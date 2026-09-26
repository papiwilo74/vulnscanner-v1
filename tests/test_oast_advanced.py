from __future__ import annotations

import socket
import struct
import time
from unittest.mock import Mock

import requests
from fastapi.testclient import TestClient

from api import app
from scanner.oast import (
    DedicatedOASTServer,
    OASTClient,
    OASTDNSServer,
    build_dns_a_response,
    check_oast_vulnerabilities,
    decode_dns_qname,
)


def test_decode_dns_qname_and_build_a_response() -> None:
    """Verifica la decodificación y empaquetado binario de paquetes DNS RFC 1035."""
    # Construir paquete de consulta DNS mínima para 'sub.target.oast.local'
    tx_id = 0xABCD
    flags = 0x0100  # Consulta estándar con RD=1
    header = struct.pack(">HHHHHH", tx_id, flags, 1, 0, 0, 0)
    qname_bytes = b"\x03sub\x06target\x04oast\x05local\x00"
    question_meta = struct.pack(">HH", 1, 1)  # QTYPE=1 (A), QCLASS=1 (IN)
    query_packet = header + qname_bytes + question_meta

    # 1. Probar decodificación de QNAME
    decoded_name, end_offset = decode_dns_qname(query_packet, offset=12)
    assert decoded_name == "sub.target.oast.local"
    assert end_offset == 12 + len(qname_bytes)

    # 2. Probar construcción de respuesta A autoritativa
    resp_packet = build_dns_a_response(query_packet, response_ip="192.168.1.50", ttl=120)
    assert len(resp_packet) >= 12 + len(qname_bytes) + 4 + 16

    resp_id, resp_flags, qd, an, ns, ar = struct.unpack(">HHHHHH", resp_packet[:12])
    assert resp_id == tx_id
    assert resp_flags == 0x8400  # Respuesta + Autoritativa (AA=1)
    assert qd == 1
    assert an == 1

    # Verificar IP resuelta al final del paquete
    resolved_ip = socket.inet_ntoa(resp_packet[-4:])
    assert resolved_ip == "192.168.1.50"


def test_oast_dns_server_lifecycle_and_query_capture() -> None:
    """Inicia el servidor DNS autoritativo (UDP), envía una consulta y verifica su captura."""
    server = OASTDNSServer(host="127.0.0.1", port=0, response_ip="127.0.0.1")
    assigned_port = server.start()
    assert assigned_port > 0
    assert server.port == assigned_port

    token = "blind-ssrf-dns-999"
    qname_str = f"{token}.corp.oast"

    # Preparar paquete de consulta UDP
    tx_id = 0x55AA
    hdr = struct.pack(">HHHHHH", tx_id, 0x0100, 1, 0, 0, 0)
    # Empaquetar etiquetas
    labels = qname_str.split(".")
    qname_raw = b"".join(bytes([len(part)]) + part.encode("ascii") for part in labels) + b"\x00"
    query_pkt = hdr + qname_raw + struct.pack(">HH", 1, 1)

    # Enviar consulta mediante socket UDP cliente
    client_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client_sock.settimeout(2.0)
    try:
        client_sock.sendto(query_pkt, ("127.0.0.1", assigned_port))
        resp_data, _ = client_sock.recvfrom(512)
        assert len(resp_data) > 12
        r_id, r_flags, _, r_an, _, _ = struct.unpack(">HHHHHH", resp_data[:12])
        assert r_id == tx_id
        assert r_an == 1
    finally:
        client_sock.close()

    time.sleep(0.05)  # Breve lapso para registro en hilo secundario

    # Verificar que el servidor registró la interacción DNS
    hits = server.get_interactions_for_token(token)
    assert len(hits) >= 1
    hit = hits[0]
    assert hit["protocol"] == "DNS"
    assert hit["type"] == "DNS-A"
    assert token in hit["qname"]
    assert hit["client_ip"] == "127.0.0.1"

    server.stop()
    assert server.sock is None


def test_dedicated_oast_server_orchestration() -> None:
    """Verifica que DedicatedOASTServer coordine simultáneamente servicios HTTP y DNS."""
    server = DedicatedOASTServer(
        host="127.0.0.1",
        domain="oast.enterprise.test",
        http_port=0,
        dns_port=0,
    )
    info = server.start()
    assert info["http_port"] > 0
    assert info["dns_port"] > 0
    assert server.is_running is True

    token = "multi-vector-777"

    # 1. Enviar interacción HTTP
    http_url = f"http://127.0.0.1:{info['http_port']}/{token}"
    r = requests.get(http_url, timeout=3)
    assert r.status_code == 200

    # 2. Enviar interacción DNS
    qname_str = f"{token}.oast.enterprise.test"
    labels = qname_str.split(".")
    qname_raw = b"".join(bytes([len(part)]) + part.encode("ascii") for part in labels) + b"\x00"
    query_pkt = struct.pack(">HHHHHH", 0x1111, 0x0100, 1, 0, 0, 0) + qname_raw + struct.pack(">HH", 1, 1)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2.0)
    try:
        sock.sendto(query_pkt, ("127.0.0.1", info["dns_port"]))
        sock.recvfrom(512)
    finally:
        sock.close()

    time.sleep(0.05)

    # 3. Comprobar correlación unificada de ambos protocolos
    interactions = server.get_interactions_for_token(token)
    assert len(interactions) == 2
    protocols = {item["protocol"] for item in interactions}
    assert "HTTP" in protocols
    assert "DNS" in protocols

    stats = server.get_stats()
    assert stats["running"] is True
    assert stats["total_http_interactions"] >= 1
    assert stats["total_dns_interactions"] >= 1
    assert stats["total_interactions"] >= 2

    server.stop()
    assert server.is_running is False


def test_oast_client_with_dedicated_server() -> None:
    """Verifica que OASTClient genere payloads avanzados y consulte al servidor dedicado."""
    server = DedicatedOASTServer(
        host="127.0.0.1",
        domain="corp.oast",
        http_port=0,
        dns_port=0,
    )
    server.start()

    client = OASTClient(dedicated_server=server)
    token = client.generate_token(prefix="rce")

    payloads = client.generate_payloads(token)
    assert "ssrf" in payloads
    assert "ssrf_dns" in payloads
    assert "rce_dns" in payloads
    assert "log4j" in payloads
    assert "sqli_mssql" in payloads
    assert "sqli_oracle" in payloads
    assert "xxe" in payloads

    # Simular callback
    server.http_server.record_interaction(
        path=f"/{token}", client_ip="10.0.0.1", method="POST"
    )

    hits = client.poll_interactions(token)
    assert len(hits) == 1
    assert hits[0]["method"] == "POST"

    server.stop()


def test_check_oast_vulnerabilities_detects_blind_ssrf() -> None:
    """Verifica que check_oast_vulnerabilities reporte un Finding confirmado si el servidor consulta el OAST."""
    client = OASTClient(mock_mode=True)
    token_captured = None

    class MockAppSession:
        def get(self, url: str, headers: dict[str, str] | None = None, timeout: float = 5.0) -> Mock:
            nonlocal token_captured
            # Si el target procesa el parámetro 'url'
            if "ssrf-" in url:
                import re
                m = re.search(r"(ssrf-[a-zA-Z0-9_-]+)", url)
                if m:
                    token_captured = m.group(1)
                    client.record_mock_interaction(
                        token_captured,
                        interaction_type="DNS-A",
                        client_ip="172.16.50.2",
                    )
            resp = Mock()
            resp.status_code = 200
            resp.text = "OK"
            return resp

    session = MockAppSession()
    findings = check_oast_vulnerabilities(
        url="https://victim.internal/api/fetch?url=https://example.com",
        session=session,  # type: ignore[arg-type]
        oast_client=client,
    )

    assert len(findings) >= 1
    f = findings[0]
    assert f.category == "ssrf"
    assert f.severity == "critical"
    assert f.confidence == "confirmed"
    assert "Blind SSRF Confirmado" in f.title
    assert "172.16.50.2" in (f.evidence.response_fragment or "")


def test_api_oast_endpoints() -> None:
    """Verifica que los endpoints REST de OAST respondan con el estado e interacciones en vivo."""
    test_client = TestClient(app)

    # 1. Endpoint status
    res = test_client.get("/api/v1/oast/status")
    assert res.status_code == 200
    data = res.json()
    assert "domain" in data

    # 2. Endpoint interacciones de token
    token = "test-token-endpoint-xyz"
    res_tok = test_client.get(f"/api/v1/oast/interactions/{token}")
    assert res_tok.status_code == 200
    data_tok = res_tok.json()
    assert data_tok["token"] == token
    assert isinstance(data_tok["interactions"], list)
