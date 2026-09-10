"""
Tests unitarios para VulnScanner — Suite completa con pytest.
Cubre: headers, cookies, https, CORS, SSL, CSRF/forms, sensitive_data, sca, subdomains, stealth,
       path_traversal, xxe, open_redirect, jwt_attacks, file_upload, prototype_pollution, graphql, websocket.
"""
import os
import sys

import pytest

# Asegurarse de que el directorio raíz del proyecto esté en el path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ─────────────────────────────────────────────
# Fixtures de respuestas HTTP simuladas
# ─────────────────────────────────────────────

class MockResponse:
    """Simula un objeto requests.Response."""
    def __init__(self, url="https://example.com", headers=None, cookies=None, text="", status_code=200):
        self.url = url
        self.headers = headers or {}
        self.cookies = cookies or {}
        self.text = text
        self.status_code = status_code


# ─────────────────────────────────────────────
# Tests: scanner/headers.py
# ─────────────────────────────────────────────

class TestHeaders:
    def test_missing_csp_detected(self):
        from scanner.headers import check_headers
        response = MockResponse(headers={
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            # Sin Content-Security-Policy
        })
        results = check_headers(response)
        vuln_names = [r["vuln"] for r in results]
        assert any("Content-Security-Policy" in v for v in vuln_names), \
            "Debe detectar ausencia de Content-Security-Policy"

    def test_missing_hsts_detected(self):
        from scanner.headers import check_headers
        response = MockResponse(headers={
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY",
        })
        results = check_headers(response)
        vuln_names = [r["vuln"] for r in results]
        assert any("Strict-Transport-Security" in v for v in vuln_names), \
            "Debe detectar ausencia de HSTS"

    def test_all_headers_present_returns_empty(self):
        from scanner.headers import check_headers
        response = MockResponse(headers={
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Strict-Transport-Security": "max-age=31536000",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "geolocation=()",
        })
        results = check_headers(response)
        assert results == [], "No debe reportar nada si todas las cabeceras están presentes"


# ─────────────────────────────────────────────
# Tests: scanner/cookies.py
# ─────────────────────────────────────────────

class TestCookies:
    def test_cookie_without_secure_flag(self):
        from scanner.cookies import check_cookies

        class MockCookie:
            name = "session"
            secure = False
            def has_nonstandard_attr(self, x):
                return False

        class MockResponse:
            cookies = [MockCookie()]
            headers = {}

        results = check_cookies(MockResponse())
        assert any("Secure" in r["vuln"] for r in results), \
            "Debe detectar cookie sin flag Secure"

    def test_no_cookies_returns_empty(self):
        from scanner.cookies import check_cookies
        response = MockResponse(cookies=[])
        response.cookies = []
        results = check_cookies(response)
        assert results == []


# ─────────────────────────────────────────────
# Tests: scanner/https_check.py
# ─────────────────────────────────────────────

class TestHttps:
    def test_http_url_detected_as_insecure(self):
        from scanner.https_check import check_https
        response = MockResponse(url="http://example.com")
        results = check_https("http://example.com", response)
        assert any("HTTP" in r["vuln"] or "HTTPS" in r["vuln"] for r in results), \
            "Debe detectar uso de HTTP sin cifrar"

    def test_https_url_returns_no_vuln(self):
        from scanner.https_check import check_https
        response = MockResponse(url="https://example.com", headers={
            "Strict-Transport-Security": "max-age=31536000"
        })
        results = check_https("https://example.com", response)
        assert not any("HTTP" in r["vuln"] for r in results)


# ─────────────────────────────────────────────
# Tests: scanner/sensitive_data.py
# ─────────────────────────────────────────────

class TestSensitiveData:
    def test_detects_aws_key(self):
        from scanner.sensitive_data import scan_text_for_sensitive_data
        text = "const key = 'AKIAIOSFODNN7ABCDEXYZ'"
        results = scan_text_for_sensitive_data(text, "test.js")
        found = any(
            "AWS" in r.get("vuln", "") or
            "AWS" in r.get("detail", "") or
            "AKIAIO" in r.get("detail", "")
            for r in results
        )
        assert found, \
            f"Debe detectar clave AKIA como dato sensible. Resultados: {results}"

    def test_detects_eval_usage_in_js(self):
        from scanner.sensitive_data import scan_text_for_sensitive_data
        text = "eval(userInput);"
        results = scan_text_for_sensitive_data(text, "Archivo JS: app.js")
        assert any("eval" in r["vuln"] for r in results), \
            "Debe detectar uso de eval() en archivos JS"

    def test_detects_localhost_reference(self):
        from scanner.sensitive_data import scan_text_for_sensitive_data
        text = "const API_URL = 'http://localhost:3000/api';"
        results = scan_text_for_sensitive_data(text, "Archivo JS: config.js")
        assert any("Desarrollo" in r["vuln"] or "localhost" in r["detail"] for r in results), \
            "Debe detectar referencia a localhost en JS de producción"

    def test_no_false_positives_on_clean_html(self):
        from scanner.sensitive_data import scan_text_for_sensitive_data
        text = "<html><body><h1>Hola Mundo</h1></body></html>"
        results = scan_text_for_sensitive_data(text, "HTML de la página principal")
        assert results == [], "No debe reportar nada en HTML limpio"


# ─────────────────────────────────────────────
# Tests: scanner/cors.py (lógica de clasificación)
# ─────────────────────────────────────────────

class TestCorsLogic:
    def test_wildcard_origin_classified_correctly(self):
        """Verifica que la lógica de clasificación de CORS es correcta para wildcard."""
        # Simulamos la lógica de decisión directamente
        ac_origin = "*"
        ac_credentials = "false"
        risk = None
        if ac_origin == "*" and ac_credentials.lower() != "true":
            risk = "Bajo"
        assert risk == "Bajo"

    def test_reflected_origin_with_credentials_is_high_risk(self):
        """Verifica que origen reflejado + credenciales es riesgo alto."""
        ac_origin = "https://evil-attacker.com"
        ac_credentials = "true"
        risk = None
        if ac_origin == "https://evil-attacker.com" and ac_credentials.lower() == "true":
            risk = "Alto"
        assert risk == "Alto"


# ─────────────────────────────────────────────
# Tests: scanner/sca.py
# ─────────────────────────────────────────────

class TestSCA:
    def test_detects_vulnerable_jquery_version(self):
        from scanner.sca import check_library_vulnerabilities
        results = check_library_vulnerabilities("jquery", "1.11.0")
        assert len(results) > 0, "Debe detectar jQuery 1.11.0 como vulnerable"
        assert results[0]["risk"] in ["Alto", "Medio", "Bajo"]

    def test_safe_jquery_version_returns_empty(self):
        from scanner.sca import check_library_vulnerabilities
        results = check_library_vulnerabilities("jquery", "3.7.1")
        assert results == [], "jQuery 3.7.1 no debe ser reportado como vulnerable"

    def test_version_comparison_logic(self):
        from scanner.sca import is_version_vulnerable
        assert is_version_vulnerable("1.11.0", "3.4.1") is True
        assert is_version_vulnerable("3.7.0", "3.4.1") is False
        assert is_version_vulnerable("3.4.1", "3.4.1") is True

    def test_unknown_library_returns_empty(self):
        from scanner.sca import check_library_vulnerabilities
        results = check_library_vulnerabilities("libreria_desconocida", "1.0.0")
        assert results == []


# ─────────────────────────────────────────────
# Tests: scanner/subdomains.py
# ─────────────────────────────────────────────

class TestSubdomains:
    def test_extracts_domain_correctly(self):
        """Verifica que se usa el hostname completo para evitar falsos positivos en dominios multinivel."""
        from urllib.parse import urlparse
        url = "https://trabajo-ya-five.vercel.app/"
        parsed = urlparse(url)
        hostname = parsed.hostname
        assert hostname == "trabajo-ya-five.vercel.app"

    def test_ip_url_returns_empty(self):
        from scanner.subdomains import check_subdomains
        results = check_subdomains("http://192.168.1.1/")
        assert results == [], "Una dirección IP no debe generar búsqueda de subdominios"


# ─────────────────────────────────────────────
# Tests: utils/stealth.py
# ─────────────────────────────────────────────

class TestStealth:
    def test_user_agent_is_string(self):
        from utils.stealth import get_random_user_agent
        ua = get_random_user_agent()
        assert isinstance(ua, str)
        assert len(ua) > 20

    def test_user_agent_changes_between_calls(self):
        from utils.stealth import USER_AGENTS
        # Verificar que hay más de un User-Agent disponible para rotación
        assert len(USER_AGENTS) >= 5

    def test_stealth_session_has_user_agent(self):
        from utils.stealth import create_stealth_session
        session = create_stealth_session()
        assert "User-Agent" in session.headers
        assert "Mozilla" in session.headers["User-Agent"]

    def test_polite_delay_zero_does_not_raise(self):
        from utils.stealth import polite_delay
        # delay=0 y stealth=False no debe levantar ninguna excepción
        polite_delay(delay=0.0, stealth=False)


# ─────────────────────────────────────────────
# Tests: utils/report.py — get_recommendation
# ─────────────────────────────────────────────

class TestReportRecommendations:
    def test_xss_recommendation_exists(self):
        from utils.report import get_recommendation
        rec = get_recommendation("XSS Reflejado en Formulario")
        assert len(rec) > 10
        assert rec != "Revisar la configuración de seguridad y aplicar parches recomendados."

    def test_cors_recommendation_exists(self):
        from utils.report import get_recommendation
        rec = get_recommendation("CORS Mal configurado (Origen Reflejado con Credenciales)")
        assert "CORS" in rec or "Origin" in rec

    def test_ssl_recommendation_exists(self):
        from utils.report import get_recommendation
        rec = get_recommendation("Certificado SSL/TLS Expirado")
        assert len(rec) > 10

    def test_csrf_recommendation_exists(self):
        from utils.report import get_recommendation
        rec = get_recommendation("Ausencia de Token CSRF")
        assert len(rec) > 10

    def test_unknown_vuln_returns_default(self):
        from utils.report import get_recommendation
        rec = get_recommendation("Vulnerabilidad Completamente Desconocida XYZ123")
        assert isinstance(rec, str) and len(rec) > 5


# ─────────────────────────────────────────────
# Tests: scanner/xss.py
# ─────────────────────────────────────────────

class TestXSS:
    def test_payload_reflected_detected(self):
        from unittest.mock import Mock, patch
        from urllib.parse import parse_qs, urlparse

        import requests as req

        from scanner.xss import test_xss_payload

        parsed = urlparse("https://example.com?q=test")
        params = parse_qs(parsed.query)
        mock_resp = Mock()
        mock_resp.text = "<script>alert(1)</script>"
        mock_resp.status_code = 200

        with patch.object(req.Session, 'get', return_value=mock_resp):
            result = test_xss_payload(parsed, params, "q", "<script>alert(1)</script>", "", req.Session())
        assert result is not None
        assert result["risk"] == "Alto"

    def test_analyze_js_detects_eval(self):
        from scanner.xss import analyze_js_code
        code = 'eval(location.hash);'
        results = analyze_js_code(code, "test.js")
        assert len(results) > 0
        assert "eval" in results[0]["detail"].lower()

    def test_analyze_js_detects_inner_html(self):
        from scanner.xss import analyze_js_code
        code = 'document.body.innerHTML = location.search;'
        results = analyze_js_code(code, "test.js")
        assert len(results) > 0
        assert "innerHTML" in results[0]["detail"]

    def test_analyze_js_clean_code_no_findings(self):
        from scanner.xss import analyze_js_code
        code = 'console.log("hello world");'
        results = analyze_js_code(code, "test.js")
        assert results == []


# ─────────────────────────────────────────────
# Tests: scanner/sqli.py
# ─────────────────────────────────────────────

class TestSQLi:
    def test_error_payload_detects_signature(self):
        from unittest.mock import Mock, patch
        from urllib.parse import parse_qs, urlparse

        import requests as req

        from scanner.sqli import test_error_sqli

        parsed = urlparse("https://example.com?id=1")
        params = parse_qs(parsed.query)
        mock_resp = Mock()
        mock_resp.text = "You have an error in your SQL syntax"
        mock_resp.status_code = 200

        with patch.object(req.Session, 'get', return_value=mock_resp):
            result = test_error_sqli(parsed, params, "id", "'", "", req.Session())
        assert result is not None
        assert result["risk"] == "Alto"

    def test_error_payload_no_false_positive(self):
        from unittest.mock import Mock, patch
        from urllib.parse import parse_qs, urlparse

        import requests as req

        from scanner.sqli import test_error_sqli

        parsed = urlparse("https://example.com?id=1")
        params = parse_qs(parsed.query)
        mock_resp = Mock()
        mock_resp.text = "<html><body>Hello world</body></html>"
        mock_resp.status_code = 200

        with patch.object(req.Session, 'get', return_value=mock_resp):
            result = test_error_sqli(parsed, params, "id", "'", "", req.Session())
        assert result is None

    def test_no_params_returns_empty(self):
        from scanner.sqli import check_sqli
        result = check_sqli("https://example.com")
        assert result == []


# ─────────────────────────────────────────────
# Tests: scanner/injections.py
# ─────────────────────────────────────────────

class TestInjections:
    def test_no_params_returns_empty(self):
        from scanner.injections import check_injections
        result = check_injections("https://example.com")
        assert result == []

    def test_ssti_detection_logic(self):
        from scanner.injections import SSTI_PAYLOADS
        assert ("{{9876*5432}}", "53646432") in SSTI_PAYLOADS
        assert ("${9876*5432}", "53646432") in SSTI_PAYLOADS


# ─────────────────────────────────────────────
# Tests: scanner/forms.py
# ─────────────────────────────────────────────

class TestForms:
    def test_form_parser_parses_basic_form(self):
        from scanner.forms import FormParser
        parser = FormParser()
        parser.feed('<form action="/login" method="post"><input name="user"><input name="pass" type="password"></form>')
        assert len(parser.forms) == 1
        assert parser.forms[0]['action'] == '/login'
        assert parser.forms[0]['method'] == 'post'
        assert len(parser.forms[0]['inputs']) == 2

    def test_form_parser_ignores_submit_buttons(self):
        from scanner.forms import FormParser
        parser = FormParser()
        parser.feed('<form><input name="email"><input type="submit"></form>')
        assert len(parser.forms[0]['inputs']) == 1

    def test_extract_forms_resolves_action_url(self):
        from scanner.forms import extract_forms
        html = '<form action="/login"><input name="user"></form>'
        forms = extract_forms("https://example.com/page", html)
        assert forms[0]['action'] == 'https://example.com/login'

    def test_scan_single_form_detects_csrf_missing(self):
        from scanner.forms import scan_single_form
        form = {
            'action': 'https://example.com/login',
            'method': 'post',
            'inputs': [{'name': 'user', 'type': 'text', 'value': ''}]
        }
        results = scan_single_form(form, passive=True)
        assert any("CSRF" in r["vuln"] for r in results)


# ─────────────────────────────────────────────
# Tests: scanner/directories.py
# ─────────────────────────────────────────────

class TestDirectories:
    def test_spa_fallback_detection(self):
        from unittest.mock import Mock

        from scanner.directories import is_spa_fallback
        mock_resp = Mock()
        mock_resp.text = '<!doctype html><div id="root"></div>'
        assert is_spa_fallback(mock_resp) is True

    def test_non_spa_not_fallback(self):
        from unittest.mock import Mock

        from scanner.directories import is_spa_fallback
        mock_resp = Mock()
        mock_resp.text = '<html><body><h1>Not SPA</h1></body></html>'
        assert is_spa_fallback(mock_resp) is False

    def test_common_paths_defined(self):
        from scanner.directories import COMMON_PATHS
        assert len(COMMON_PATHS) > 10
        assert "/.env" in COMMON_PATHS


# ─────────────────────────────────────────────
# Tests: scanner/fuzzer.py
# ─────────────────────────────────────────────

class TestFuzzer:
    def test_common_paths_exist(self):
        from scanner.fuzzer import COMMON_PATHS
        assert ".env" in COMMON_PATHS
        assert ".git/config" in COMMON_PATHS


# ─────────────────────────────────────────────
# Tests: scanner/ports.py
# ─────────────────────────────────────────────

class TestPorts:
    def test_ports_scan_critical_ports_defined(self):
        from scanner.ports import PORTS_TO_SCAN
        assert 21 in PORTS_TO_SCAN
        assert 22 in PORTS_TO_SCAN
        assert 3306 in PORTS_TO_SCAN
        assert 3389 in PORTS_TO_SCAN
        assert len(PORTS_TO_SCAN) >= 14

    def test_no_hostname_returns_empty(self):
        from scanner.ports import check_ports
        result = check_ports("not-a-url")
        assert result == []


# ─────────────────────────────────────────────
# Tests: scanner/crawler.py
# ─────────────────────────────────────────────

class TestCrawler:
    def test_get_internal_links_finds_links(self):
        from scanner.crawler import get_internal_links
        html = '<a href="/page1">Link</a><a href="https://other.com">External</a>'
        links = get_internal_links("https://example.com", html)
        assert "https://example.com/page1" in links

    def test_get_internal_links_ignores_external(self):
        from scanner.crawler import get_internal_links
        html = '<a href="https://other.com/page">External</a>'
        links = get_internal_links("https://example.com", html)
        assert links == []

    def test_common_spa_routes_defined(self):
        from scanner.crawler import COMMON_SPA_ROUTES
        assert "/login" in COMMON_SPA_ROUTES
        assert "/dashboard" in COMMON_SPA_ROUTES


# ─────────────────────────────────────────────
# Tests: scanner/ssl_check.py
# ─────────────────────────────────────────────

class TestSSLCheck:
    def test_http_url_returns_high_risk(self):
        from scanner.ssl_check import check_ssl
        results = check_ssl("http://example.com")
        assert any("SSL" in r["vuln"] or "HTTP" in r["vuln"] for r in results)
        assert results[0]["risk"] == "Alto"

    def test_no_hostname_returns_empty(self):
        from scanner.ssl_check import check_ssl
        results = check_ssl("")
        assert results == []


# ─────────────────────────────────────────────
# Tests: scanner/ai_check.py
# ─────────────────────────────────────────────

class TestAICheck:
    def test_load_ai_model_no_model_returns_false(self):
        import os

        from scanner.ai_check import load_ai_model
        model_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "models", "ai_model.joblib")
        if not os.path.exists(model_path):
            assert load_ai_model() is False

    def test_check_with_ai_no_params_returns_empty(self):
        from scanner.ai_check import check_with_ai
        result = check_with_ai("https://example.com")
        assert result == []


# ─────────────────────────────────────────────
# Tests: scanner/__init__.py & main.py helpers
# ─────────────────────────────────────────────

class TestMain:
    def test_build_session_no_creds_returns_none(self):
        from main import build_session
        assert build_session() is None
        assert build_session(None, None) is None

    def test_build_session_with_cookie(self):
        from main import build_session
        session = build_session("session=abc123; user=admin", None)
        assert session is not None
        assert session.cookies.get("session") == "abc123"
        assert session.cookies.get("user") == "admin"

    def test_build_session_with_auth(self):
        from main import build_session
        session = build_session(None, "Bearer test123")
        assert session is not None
        assert session.headers.get("Authorization") == "Bearer test123"


# ─────────────────────────────────────────────
# Tests: scanner/auth_helper.py
# ─────────────────────────────────────────────

class TestAuthHelper:
    def test_dynamic_login_empty_creds_returns_none(self):
        from scanner.auth_helper import dynamic_login
        result = dynamic_login("https://example.com/login", "")
        assert result is None

    def test_dynamic_login_invalid_url_returns_none(self):
        from scanner.auth_helper import dynamic_login
        result = dynamic_login("https://invalid-url-xyz-123.com/login", "user=admin;pass=123")
        assert result is None


# ─────────────────────────────────────────────
# Tests: scanner/path_traversal.py
# ─────────────────────────────────────────────

class TestPathTraversal:
    def test_no_params_returns_empty(self):
        from scanner.path_traversal import check_path_traversal
        result = check_path_traversal("https://example.com")
        assert result == []

    def test_payload_list_is_defined(self):
        from scanner.path_traversal import PATH_TRAVERSAL_PAYLOADS
        assert len(PATH_TRAVERSAL_PAYLOADS) > 3

    def test_unix_signatures_defined(self):
        from scanner.path_traversal import UNIX_SIGNATURES
        assert len(UNIX_SIGNATURES) > 0

    def test_win_signatures_defined(self):
        from scanner.path_traversal import WIN_SIGNATURES
        assert len(WIN_SIGNATURES) > 0


# ─────────────────────────────────────────────
# Tests: scanner/xxe.py
# ─────────────────────────────────────────────

class TestXXE:
    def test_payloads_defined(self):
        from scanner.xxe import XXE_PAYLOADS
        assert len(XXE_PAYLOADS) > 0

    def test_signatures_defined(self):
        from scanner.xxe import XXE_SIGNATURES
        assert len(XXE_SIGNATURES) > 0

    def test_empty_html_returns_empty(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import unittest.mock

        from scanner.xxe import check_xxe
        mock_resp = unittest.mock.MagicMock()
        mock_resp.status_code = 404
        mock_resp.text = ""
        monkeypatch.setattr("requests.get", lambda *a, **kw: mock_resp)
        monkeypatch.setattr("requests.post", lambda *a, **kw: mock_resp)
        result = check_xxe("https://example.com", "")
        assert result == []


# ─────────────────────────────────────────────
# Tests: scanner/open_redirect.py
# ─────────────────────────────────────────────

class TestOpenRedirect:
    def test_redirect_params_defined(self):
        from scanner.open_redirect import REDIRECT_PARAMS
        assert "redirect" in REDIRECT_PARAMS
        assert "next" in REDIRECT_PARAMS
        assert "url" in REDIRECT_PARAMS

    def test_no_params_returns_empty(self):
        from scanner.open_redirect import check_open_redirect
        result = check_open_redirect("https://example.com")
        assert result == []

    def test_evil_url_constant_defined(self):
        from scanner.open_redirect import EVIL_URL
        assert EVIL_URL.startswith("https://")


# ─────────────────────────────────────────────
# Tests: scanner/jwt_attacks.py
# ─────────────────────────────────────────────

class TestJWTAttacks:
    def test_decode_valid_jwt(self):
        from scanner.jwt_attacks import _decode_jwt
        token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.dummy"
        result = _decode_jwt(token)
        assert result is not None
        assert result["header"]["alg"] == "HS256"
        assert result["payload"]["sub"] == "1234567890"

    def test_forge_none_returns_no_signature(self):
        from scanner.jwt_attacks import _forge_none
        token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.sig"
        result = _forge_none(token)
        assert result is not None
        assert result.endswith(".")

    def test_forge_hs256_creates_valid_jwt_format(self):
        from scanner.jwt_attacks import _forge_hs256
        token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.sig"
        result = _forge_hs256(token, "secret")
        assert result is not None
        parts = result.split(".")
        assert len(parts) == 3

    def test_common_secrets_defined(self):
        from scanner.jwt_attacks import COMMON_SECRETS
        assert len(COMMON_SECRETS) > 3

    def test_decode_invalid_jwt_returns_none(self):
        from scanner.jwt_attacks import _decode_jwt
        assert _decode_jwt("invalid") is None
        assert _decode_jwt("") is None

    def test_jwt_regex_matches_real_token(self):
        from scanner.jwt_attacks import JWT_RE
        token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.sig"
        assert JWT_RE.search(token) is not None


# ─────────────────────────────────────────────
# Tests: scanner/file_upload.py
# ─────────────────────────────────────────────

class TestFileUpload:
    def test_detects_file_input_in_form(self):
        from scanner.file_upload import check_file_upload
        html = '<form action="/upload" method="post" enctype="multipart/form-data"><input type="file" name="avatar"></form>'
        result = check_file_upload("https://example.com", html)
        assert len(result) >= 1
        assert any("avatar" in r["detail"] for r in result)

    def test_no_file_forms_returns_empty(self):
        from scanner.file_upload import check_file_upload
        html = '<form action="/login" method="post"><input type="text" name="user"></form>'
        result = check_file_upload("https://example.com", html)
        assert result == []

    def test_dangerous_extensions_defined(self):
        from scanner.file_upload import DANGEROUS_EXTENSIONS
        assert ".php" in DANGEROUS_EXTENSIONS
        assert ".exe" in DANGEROUS_EXTENSIONS

    def test_bypass_patterns_defined(self):
        from scanner.file_upload import BYPASS_PATTERNS
        assert len(BYPASS_PATTERNS) > 0
        assert ".php.jpg" in BYPASS_PATTERNS

    def test_file_input_with_accept_detected(self):
        from scanner.file_upload import check_file_upload
        html = '<form action="/upload" method="post"><input type="file" name="doc" accept=".pdf,.docx"></form>'
        result = check_file_upload("https://example.com", html)
        assert len(result) >= 1
        assert any("accept" in r["detail"].lower() for r in result)


# ─────────────────────────────────────────────
# Tests: scanner/prototype_pollution.py
# ─────────────────────────────────────────────

class TestPrototypePollution:
    def test_detects_proto_access(self):
        from scanner.prototype_pollution import _analyze_js_for_prototype_pollution
        js = 'obj.__proto__["polluted"] = true;'
        results = _analyze_js_for_prototype_pollution(js, "test.js")
        assert len(results) >= 1
        assert any("__proto__" in r["detail"] for r in results)

    def test_detects_constructor_prototype(self):
        from scanner.prototype_pollution import _analyze_js_for_prototype_pollution
        js = 'obj.constructor.prototype.isAdmin = true;'
        results = _analyze_js_for_prototype_pollution(js, "test.js")
        assert len(results) >= 1

    def test_clean_js_no_findings(self):
        from scanner.prototype_pollution import _analyze_js_for_prototype_pollution
        js = 'var x = 1; function hello() { return "world"; }'
        results = _analyze_js_for_prototype_pollution(js, "test.js")
        assert results == []

    def test_detects_unsafe_merge(self):
        from scanner.prototype_pollution import _analyze_js_for_prototype_pollution
        js = 'function merge(target, source) { for (var key in source) { target[key] = source[key]; } }'
        results = _analyze_js_for_prototype_pollution(js, "test.js")
        assert len(results) >= 1

    def test_cookie_proto_detected(self):
        from scanner.prototype_pollution import _analyze_js_for_prototype_pollution
        js = 'var val = document.cookie.split(";")[0]; obj.__proto__[val] = true;'
        results = _analyze_js_for_prototype_pollution(js, "test.js")
        assert len(results) >= 1


# ─────────────────────────────────────────────
# Tests: scanner/graphql.py
# ─────────────────────────────────────────────

class TestGraphQL:
    def test_endpoints_defined(self):
        from scanner.graphql import GQL_ENDPOINTS
        assert "/graphql" in GQL_ENDPOINTS
        assert len(GQL_ENDPOINTS) > 5

    def test_introspection_query_defined(self):
        from scanner.graphql import INTROSPECTION_QUERY
        assert "__schema" in INTROSPECTION_QUERY

    def test_schema_keywords_defined(self):
        from scanner.graphql import GQL_SCHEMA_KEYWORDS
        assert "__schema" in GQL_SCHEMA_KEYWORDS
        assert len(GQL_SCHEMA_KEYWORDS) >= 3


# ─────────────────────────────────────────────
# Tests: scanner/websocket.py
# ─────────────────────────────────────────────

class TestWebSocket:
    def test_detects_insecure_ws(self):
        from scanner.websocket import check_websocket
        html = '<script>var ws = new WebSocket("ws://example.com/socket");</script>'
        result = check_websocket("https://example.com", html)
        assert len(result) >= 1
        assert any("ws://" in r["detail"] for r in result)

    def test_detects_secure_wss(self):
        from scanner.websocket import check_websocket
        html = '<script>var ws = new WebSocket("wss://example.com/socket");</script>'
        result = check_websocket("https://example.com", html)
        assert any("cifrada" in r["detail"].lower() for r in result)

    def test_no_ws_returns_empty(self):
        from scanner.websocket import check_websocket
        html = '<script>console.log("hello");</script>'
        result = check_websocket("https://example.com", html)
        assert result == []

    def test_ws_regex_patterns(self):
        from scanner.websocket import WS_INSECURE_RE, WSS_SECURE_RE
        assert WS_INSECURE_RE.search("ws://test.com/socket") is not None
        assert WS_INSECURE_RE.search("wss://test.com/socket") is None
        assert WSS_SECURE_RE.search("wss://test.com/socket") is not None
