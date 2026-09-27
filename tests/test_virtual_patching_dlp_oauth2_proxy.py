"""
Suite de Pruebas Automatizadas para las 4 Nuevas Capacidades Enterprise:
1. Virtual Patching & Síntesis de Reglas WAF (ModSecurity, AWS WAF, Cloudflare, Nginx).
2. Motor DLP con Algoritmo de Luhn (Tarjetas de Crédito, SSN, Certificados PEM, Secretos).
3. Autenticación Dinámica Avanzada (OAuth2 Token Refresh proactivo/reactivo con TOTP).
4. Proxy Interceptor Pasivo Integrado (Captura de Tráfico, Endpoints y Exportación HAR).
"""
import json
import time
from unittest.mock import MagicMock, patch

import pytest
import requests
from fastapi.testclient import TestClient

from api import app
from scanner.auth_helper import AuthSessionManager, OAuth2TokenManager
from scanner.dlp import DLPEngine, luhn_checksum
from scanner.models import Finding
from scanner.proxy_capture import ProxyCaptureServer
from scanner.sensitive_data import scan_text_for_sensitive_data
from scanner.virtual_patching import VirtualPatchEngine

# =====================================================================
# 1. PRUEBAS: VIRTUAL PATCHING & WAF SYNTHESIS
# =====================================================================

def test_waf_virtual_patch_synthesis_modsecurity_and_aws() -> None:
    finding = Finding(
        category="sqli",
        title="SQL Injection vulnerable param",
        severity="critical",
        affected_url="https://app.target.com/api/v1/users",
        parameter="user_id",
        cwe_id="CWE-89",
    )
    patch = VirtualPatchEngine.synthesize_patch(finding, rule_id=100001)

    assert patch.rule_id == 100001
    assert patch.vuln_type == "sqli"
    assert "user_id" in patch.modsecurity_rule
    assert "id:100001" in patch.modsecurity_rule
    assert "SecRule ARGS:user_id" in patch.modsecurity_rule
    assert "CWE-89" in patch.modsecurity_rule

    # AWS WAF v2 JSON statement
    aws_rule = patch.aws_waf_rule
    assert aws_rule["Name"] == "OmniBreach_VP_100001_SQLI"
    assert aws_rule["Action"] == {"Block": {}}
    assert "AndStatement" in aws_rule["Statement"]

    # Cloudflare WAF Expression
    assert 'http.request.uri.path eq "/api/v1/users"' in patch.cloudflare_rule
    assert 'http.request.uri.args["user_id"][0]' in patch.cloudflare_rule

    # Nginx Native Directive
    assert "location = /api/v1/users" in patch.nginx_rule
    assert "$arg_user_id" in patch.nginx_rule


def test_waf_export_ruleset_formats() -> None:
    findings = [
        Finding(
            category="xss",
            title="Reflected XSS in search",
            severity="high",
            affected_url="https://app.target.com/search",
            parameter="q",
            cwe_id="CWE-79",
        ),
        Finding(
            category="path_traversal",
            title="LFI in file viewer",
            severity="high",
            affected_url="https://app.target.com/download",
            parameter="file",
            cwe_id="CWE-22",
        ),
    ]

    # 1. ModSecurity
    modsec_out = VirtualPatchEngine.export_ruleset(findings, format="modsecurity")
    assert "MODSECURITY (OWASP CRS)" in modsec_out
    assert "SecRule ARGS:q" in modsec_out
    assert "SecRule ARGS:file" in modsec_out

    # 2. AWS WAF
    aws_out = VirtualPatchEngine.export_ruleset(findings, format="aws_waf")
    parsed_aws = json.loads(aws_out)
    assert isinstance(parsed_aws, list)
    assert len(parsed_aws) == 2
    assert parsed_aws[0]["Action"] == {"Block": {}}

    # 3. Cloudflare
    cf_out = VirtualPatchEngine.export_ruleset(findings, format="cloudflare")
    assert "http.request.uri.args" in cf_out
    assert "Action: Block" in cf_out

    # 4. Multi-format bundle (all)
    bundle_out = VirtualPatchEngine.export_ruleset(findings, format="all")
    parsed_bundle = json.loads(bundle_out)
    assert "summary" in parsed_bundle
    assert parsed_bundle["summary"]["total_patches"] == 2
    assert "modsecurity" in parsed_bundle
    assert "aws_waf" in parsed_bundle
    assert "cloudflare" in parsed_bundle


# =====================================================================
# 2. PRUEBAS: MOTOR DLP & ALGORITMO DE LUHN
# =====================================================================

def test_luhn_algorithm_validation() -> None:
    # Tarjetas de crédito de prueba válidas (Luhn válido)
    valid_visa = "4532015112830366"
    valid_mastercard = "5425233430109903"
    valid_amex = "378282246310005"

    assert luhn_checksum(valid_visa) is True
    assert luhn_checksum(valid_mastercard) is True
    assert luhn_checksum(valid_amex) is True

    # Número con dígito de control alterado
    invalid_cc = "4532015112830367"
    assert luhn_checksum(invalid_cc) is False

    # Números triviales inválidos
    assert luhn_checksum("0000000000000000") is False
    assert luhn_checksum("1111111111111111") is False
    assert luhn_checksum("12345") is False  # Demasiado corto


def test_dlp_engine_scan_detects_card_ssn_and_secrets() -> None:
    dummy_slack = f"{'xoxb'}-{123456789012}-{123456789012}-{'abcdefghijklmnopqrstuvwx'}"
    dummy_stripe = f"{'sk_live'}_{'51Abcdefghijklmnopqrstuvwxy'}"
    content = f"""
    HTTP/1.1 200 OK
    Content-Type: application/json

    {{
        "status": "success",
        "user": {{
            "name": "John Doe",
            "ssn": "123-45-6789",
            "billing_card": "4532-0151-1283-0366",
            "slack_token": "{dummy_slack}",
            "stripe_secret": "{dummy_stripe}"
        }}
    }}
    """
    leaks = DLPEngine.scan_text(content, location_label="Respuesta API /user/profile")
    leak_categories = {leak.category for leak in leaks}

    assert "credit_card" in leak_categories
    assert "ssn" in leak_categories
    assert "secret" in leak_categories

    # Verificar enmascaramiento seguro
    card_leak = next(leak for leak in leaks if leak.category == "credit_card")
    assert "4532-****-****-0366" in card_leak.masked_value

    ssn_leak = next(leak for leak in leaks if leak.category == "ssn")
    assert ssn_leak.masked_value == "***-**-6789"

    # Conversión a Finding tipados
    findings = DLPEngine.scan_to_findings(content, target_url="https://app.target.com/profile")
    assert len(findings) >= 3
    assert any(f.cwe_id in ("CWE-359", "CWE-798") for f in findings)


def test_sensitive_data_module_integrates_dlp() -> None:
    html = """
    <html>
        <body>
            <p>Admin private key exposed:</p>
            <pre>
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Y1+abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGH
-----END RSA PRIVATE KEY-----
            </pre>
            <span>Customer card: 5425-2334-3010-9903</span>
        </body>
    </html>
    """
    findings = scan_text_for_sensitive_data(html, "HTML Admin Panel")
    vuln_names = [f["vuln"] for f in findings]

    assert any("Fuga DLP: Tarjeta de Crédito (Mastercard)" in v for v in vuln_names)
    assert any("Fuga DLP: Clave Privada Criptográfica (PEM)" in v for v in vuln_names)


# =====================================================================
# 3. PRUEBAS: AUTENTICACIÓN DINÁMICA AVANZADA (OAUTH2 + TOTP)
# =====================================================================

def test_oauth2_token_manager_refresh(monkeypatch: pytest.MonkeyPatch) -> None:
    mock_post = MagicMock()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "access_token": "new_refreshed_access_token_jwt_xyz",
        "refresh_token": "new_rotated_refresh_token_789",
        "expires_in": 3600,
    }
    mock_post.return_value = mock_resp
    monkeypatch.setattr(requests, "post", mock_post)
    monkeypatch.setattr(requests.Session, "post", mock_post)

    mgr = OAuth2TokenManager(
        token_url="https://auth.target.com/oauth/token",
        refresh_token="initial_refresh_token_123",
        client_id="my_client_id",
        client_secret="my_client_secret",
        totp_secret="JBSWY3DPEHPK3PXP",
    )

    assert mgr.is_expired() is True
    session = requests.Session()
    new_token = mgr.refresh_access_token(session)

    assert new_token == "new_refreshed_access_token_jwt_xyz"
    assert mgr.refresh_token == "new_rotated_refresh_token_789"
    assert session.headers["Authorization"] == "Bearer new_refreshed_access_token_jwt_xyz"
    assert mgr.is_expired() is False

    # Verificar que se envió TOTP en el payload de refresco
    call_kwargs = mock_post.call_args[1]
    assert "totp" in call_kwargs["data"]
    assert len(call_kwargs["data"]["totp"]) == 6


def test_auth_session_manager_intercepts_401_and_renews() -> None:
    session = requests.Session()
    session.headers["Authorization"] = "Bearer expired_token"

    token_mgr = MagicMock()
    token_mgr.is_expired.return_value = False

    def fake_refresh(s: requests.Session) -> str:
        s.headers["Authorization"] = "Bearer renewed_token"
        return "renewed_token"

    token_mgr.refresh_access_token.side_effect = fake_refresh

    auth_session = AuthSessionManager(session=session, oauth2_manager=token_mgr)

    # Simular petición que devuelve 401 en el primer intento y 200 tras renovar
    resp_401 = MagicMock(status_code=401)
    resp_200 = MagicMock(status_code=200)

    with patch.object(session, "request", side_effect=[resp_401, resp_200]) as mock_req:
        res = auth_session.get("https://app.target.com/api/protected")
        assert res.status_code == 200
        assert mock_req.call_count == 2
        token_mgr.refresh_access_token.assert_called_once()


# =====================================================================
# 4. PRUEBAS: PROXY INTERCEPTOR PASIVO INTEGRADO & HAR
# =====================================================================

def test_proxy_capture_server_lifecycle_and_har_export() -> None:
    # Usar un puerto efímero local libre para prueba
    proxy = ProxyCaptureServer(host="127.0.0.1", port=18991, forward_traffic=False)
    proxy.start()
    assert proxy.is_running is True

    try:
        # Enviar petición a través del proxy
        proxies = {"http": "http://127.0.0.1:18991"}
        r1 = requests.get(
            "http://target.internal.local/api/v1/orders?status=active",
            headers={"Authorization": "Bearer captured_jwt_test", "Cookie": "session_id=sess_12345; role=admin"},
            proxies=proxies,
            timeout=5,
        )
        assert r1.status_code == 200

        r2 = requests.post(
            "http://target.internal.local/api/v1/checkout",
            json={"amount": 99.5, "item_id": 42},
            proxies=proxies,
            timeout=5,
        )
        assert r2.status_code == 200

        time.sleep(0.1)

        # 1. Inspeccionar flujos capturados
        endpoints = proxy.get_captured_endpoints()
        assert len(endpoints) >= 2
        assert "http://target.internal.local/api/v1/orders?status=active" in endpoints
        assert "http://target.internal.local/api/v1/checkout" in endpoints

        # 2. Extracción de credenciales
        cookies = proxy.get_session_cookies()
        assert cookies.get("session_id") == "sess_12345"
        assert cookies.get("role") == "admin"

        auth_headers = proxy.get_auth_headers()
        assert auth_headers.get("Authorization") == "Bearer captured_jwt_test"

        # 3. Exportación a formato HAR 1.2
        har = proxy.export_har()
        assert har["log"]["version"] == "1.2"
        assert len(har["log"]["entries"]) >= 2
        first_entry = har["log"]["entries"][0]
        assert first_entry["request"]["method"] in ("GET", "POST")

        # 4. Creación de sesión autenticada
        built_session = proxy.create_authenticated_session()
        assert built_session.headers.get("Authorization") == "Bearer captured_jwt_test"
        assert built_session.cookies.get("session_id") == "sess_12345"

    finally:
        proxy.stop()
        assert proxy.is_running is False


# =====================================================================
# 5. PRUEBAS: ENDPOINTS FASTAPI (WAF, DLP, PROXY)
# =====================================================================

def test_api_waf_generate_endpoint() -> None:
    client = TestClient(app)
    req_body = {
        "findings": [
            {
                "category": "sqli",
                "title": "SQL Injection in login",
                "affected_url": "https://app.target.com/login",
                "parameter": "username",
                "cwe_id": "CWE-89",
            }
        ],
        "format": "modsecurity",
    }
    resp = client.post("/api/v1/waf/generate", json=req_body)
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "success"
    assert data["total_patches"] == 1
    assert "SecRule ARGS:username" in data["ruleset"]


def test_api_dlp_scan_endpoint() -> None:
    client = TestClient(app)
    dummy_slack = f"{'xoxb'}-{123456789012}-{123456789012}-{'abcdefghijklmnopqrstuvwx'}"
    req_body = {
        "text": f"Leak discovered: Card 4532015112830366 and token {dummy_slack}",
        "location": "Respuesta JSON de auditoría",
    }
    resp = client.post("/api/v1/dlp/scan", json=req_body)
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "success"
    assert data["total_leaks"] >= 2
    assert any("Tarjeta de Crédito (Visa)" in leak["leak_type"] for leak in data["leaks"])


def test_api_proxy_capture_lifecycle_endpoints() -> None:
    client = TestClient(app)

    # 1. Iniciar proxy en puerto efímero
    start_resp = client.post("/api/v1/proxy/start", json={"port": 18992, "forward_traffic": False})
    assert start_resp.status_code == 200
    assert start_resp.json()["status"] in ("started", "already_running")

    # 2. Consultar status
    status_resp = client.get("/api/v1/proxy/status")
    assert status_resp.status_code == 200
    assert status_resp.json()["is_running"] is True

    # 3. Detener proxy
    stop_resp = client.post("/api/v1/proxy/stop")
    assert stop_resp.status_code == 200
    assert stop_resp.json()["status"] == "stopped"
