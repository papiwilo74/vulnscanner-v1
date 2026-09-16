from unittest.mock import Mock
from urllib.parse import parse_qs, urlparse

import responses

from scanner.cookies import check_cookies
from scanner.cors import check_cors
from scanner.headers import check_headers
from scanner.sqli import (
    test_boolean_sqli as _test_boolean_sqli,
)
from scanner.sqli import (
    test_error_sqli as _test_error_sqli,
)
from scanner.sqli import (
    test_json_sqli as _test_json_sqli,
)
from scanner.xss import analyze_js_code

# =====================================================================
# 1. SQLi PRECISION & DIFFERENTIAL BOOLEAN TESTS
# =====================================================================

def test_sqli_syntax_error_node_js_discarded():
    """Un error de sintaxis de JavaScript o JSON (ej: V8 SyntaxError near) NO debe disparar SQLi."""
    parsed = urlparse("https://api.test/search?q=test")
    params = parse_qs(parsed.query)

    mock_resp = Mock()
    mock_resp.text = "SyntaxError: Unexpected token '?' near 'queryParam' at line 1"
    mock_resp.status_code = 200

    class MockSession:
        def get(self, *args, **kwargs):
            return mock_resp

    result = _test_error_sqli(parsed, params, "q", "'", baseline_body="clean", session=MockSession())
    assert result is None, f"Node.js/JSON SyntaxError no debe generar falso positivo de SQLi: {result}"


def test_sqli_syntax_error_real_database_confirmed():
    """Errores explícitos de PostgreSQL o MSSQL deben confirmarse con confidence='confirmed'."""
    parsed = urlparse("https://api.test/search?q=test")
    params = parse_qs(parsed.query)

    mock_pg = Mock()
    mock_pg.text = "ERROR: syntax error at or near \"WHERE\" at character 42"
    mock_pg.status_code = 500

    class MockPgSession:
        def get(self, *args, **kwargs):
            return mock_pg

    result_pg = _test_error_sqli(parsed, params, "q", "'", baseline_body="clean", session=MockPgSession())
    assert result_pg is not None
    assert result_pg["confidence"] == "confirmed"
    assert "Error de Base de Datos" in result_pg["detail"]


def test_sqli_boolean_differential_confirmed():
    """Prueba diferencial booleana: Condición verdadera conserva respuesta base, falsa altera la respuesta."""
    parsed = urlparse("https://app.test/items?id=1")
    params = parse_qs(parsed.query)
    baseline_body = "A" * 500

    class MockSession:
        def get(self, url, *args, **kwargs):
            r = Mock()
            if "1%3D1" in url or "1=1" in url:
                # Verdadera: longitud casi idéntica a la base (500)
                r.text = "A" * 505
                r.status_code = 200
            elif "1%3D2" in url or "1=2" in url:
                # Falsa: respuesta vacía o con longitud reducida (diferencia > 60 bytes)
                r.text = "A" * 200
                r.status_code = 200
            else:
                r.text = baseline_body
                r.status_code = 200
            return r

    result = _test_boolean_sqli(
        parsed,
        params,
        "id",
        "1 AND 1=1",
        "1 AND 1=2",
        baseline_body=baseline_body,
        session=MockSession(),
    )
    assert result is not None
    assert "SQLi Booleano Confirmado" in result["vuln"]
    assert result["risk"] == "Alto"
    assert result["confidence"] == "confirmed"


def test_sqli_boolean_false_positive_same_response_discarded():
    """Si la condición verdadera y falsa devuelven exactamente la misma respuesta, no es SQLi."""
    parsed = urlparse("https://app.test/items?id=1")
    params = parse_qs(parsed.query)
    baseline_body = "A" * 500

    class MockStaticSession:
        def get(self, url, *args, **kwargs):
            r = Mock()
            r.text = baseline_body
            r.status_code = 200
            return r

    result = _test_boolean_sqli(
        parsed,
        params,
        "id",
        "1 AND 1=1",
        "1 AND 1=2",
        baseline_body=baseline_body,
        session=MockStaticSession(),
    )
    assert result is None


def test_sqli_json_confirmed_confidence():
    """SQLi en JSON debe reportarse con confidence='confirmed'."""
    class MockAuthSession:
        def post(self, url, json=None, *args, **kwargs):
            r = Mock()
            # Payload exitoso
            if json and "' OR 1=1--" in str(json.get("username", "")):
                r.status_code = 200
                r.text = '{"token": "secret_jwt_xyz", "authenticated": true}'
            else:
                r.status_code = 401
                r.text = '{"error": "Unauthorized"}'
            return r

    findings = _test_json_sqli("https://app.test/api/login", session=MockAuthSession())
    assert len(findings) >= 1
    assert findings[0]["confidence"] == "confirmed"
    assert findings[0]["risk"] == "Crítico"


# =====================================================================
# 2. CORS PRECISION & NULL ORIGIN TESTS
# =====================================================================

@responses.activate
def test_cors_static_assets_wildcard_discarded():
    """Archivos estáticos (.css, .js, .png) con CORS * no deben generar alertas de CORS abierto."""
    responses.add(
        responses.GET,
        "https://cdn.test/assets/style.css",
        headers={"Access-Control-Allow-Origin": "*"},
        body="body { margin: 0; }",
        status=200,
    )
    responses.add(
        responses.OPTIONS,
        "https://cdn.test/assets/style.css",
        headers={"Access-Control-Allow-Origin": "*"},
        body="",
        status=200,
    )
    responses.add(
        responses.GET,
        "https://cdn.test/assets/style.css",
        headers={},
        body="",
        status=200,
    )

    findings = check_cors("https://cdn.test/assets/style.css")
    assert len(findings) == 0, f"Recursos estáticos con CORS * no deben alertarse: {findings}"


@responses.activate
def test_cors_dynamic_endpoint_wildcard_reported():
    """Endpoints dinámicos (/api/data) con CORS * sí deben alertarse como Informativo/Bajo."""
    responses.add(
        responses.GET,
        "https://app.test/api/data",
        headers={"Access-Control-Allow-Origin": "*"},
        body='{"data": [1,2,3]}',
        status=200,
    )
    responses.add(
        responses.OPTIONS,
        "https://app.test/api/data",
        headers={"Access-Control-Allow-Origin": "*"},
        body="",
        status=200,
    )
    responses.add(
        responses.GET,
        "https://app.test/api/data",
        headers={},
        body="",
        status=200,
    )

    findings = check_cors("https://app.test/api/data")
    assert len(findings) == 1
    assert findings[0]["vuln"] == "CORS Abierto (Comodín)"
    assert findings[0]["confidence"] == "confirmed"


@responses.activate
def test_cors_null_origin_with_credentials_detected():
    """Confianza en Origin: null con Allow-Credentials: true debe detectarse como riesgo Alto."""
    def request_callback(request):
        origin = request.headers.get("Origin", "")
        if origin == "null":
            return (
                200,
                {
                    "Access-Control-Allow-Origin": "null",
                    "Access-Control-Allow-Credentials": "true",
                },
                "OK",
            )
        return (200, {}, "OK")

    responses.add_callback(
        responses.GET,
        "https://app.test/api/profile",
        callback=request_callback,
    )
    responses.add_callback(
        responses.OPTIONS,
        "https://app.test/api/profile",
        callback=request_callback,
    )

    findings = check_cors("https://app.test/api/profile")
    null_findings = [f for f in findings if "null" in f["vuln"].lower()]
    assert len(null_findings) == 1
    assert null_findings[0]["risk"] == "Alto"
    assert null_findings[0]["confidence"] == "confirmed"


# =====================================================================
# 3. COOKIES SESSION VS CLIENT-SIDE DISCRIMINATION TESTS
# =====================================================================

def test_cookies_client_side_ui_no_high_risk_alert():
    """Cookies de frontend/analíticas sin HttpOnly no deben generar falsos positivos de riesgo Alto."""
    class MockClientCookie:
        def __init__(self, name: str):
            self.name = name
            self.secure = True
        def has_nonstandard_attr(self, attr: str) -> bool:
            return False

    class MockResp:
        def __init__(self):
            self.headers = {}
            self.cookies = [
                MockClientCookie("theme"),
                MockClientCookie("_ga"),
                MockClientCookie("cookie_consent"),
            ]

    results = check_cookies(MockResp())
    high_risks = [r for r in results if r["risk"] == "Alto"]
    assert len(high_risks) == 0, f"Cookies de interfaz no deben tener riesgo Alto: {high_risks}"


def test_cookies_session_without_httponly_and_samesite_confirmed():
    """Cookies de sesión auténticas sin HttpOnly y sin SameSite deben alertarse apropiadamente."""
    class MockSessionCookie:
        def __init__(self, name: str):
            self.name = name
            self.secure = True
            self._rest: dict[str, str] = {}
        def has_nonstandard_attr(self, attr: str) -> bool:
            return False
        def get_nonstandard_attr(self, attr: str) -> None:
            return None

    class MockResp:
        def __init__(self):
            self.headers = {}
            self.cookies = [MockSessionCookie("sessionid")]

    results = check_cookies(MockResp())
    httponly_findings = [r for r in results if "HttpOnly" in r["vuln"]]
    samesite_findings = [r for r in results if "SameSite" in r["vuln"]]

    assert len(httponly_findings) == 1
    assert httponly_findings[0]["risk"] == "Alto"
    assert httponly_findings[0]["confidence"] == "confirmed"

    assert len(samesite_findings) == 1
    assert samesite_findings[0]["risk"] == "Medio"
    assert samesite_findings[0]["confidence"] == "confirmed"


# =====================================================================
# 4. HEADERS WEAK CSP AUDIT TESTS
# =====================================================================

def test_headers_weak_csp_unsafe_inline_eval_flagged():
    """CSP con 'unsafe-inline' o 'unsafe-eval' debe marcarse como débil/permisivo."""
    class MockDocResp:
        def __init__(self):
            self.headers = {
                "Content-Type": "text/html; charset=utf-8",
                "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'",
                "Strict-Transport-Security": "max-age=31536000",
                "X-Frame-Options": "DENY",
                "X-Content-Type-Options": "nosniff",
                "Referrer-Policy": "no-referrer",
                "Permissions-Policy": "camera=()",
            }

    findings = check_headers(MockDocResp())
    csp_findings = [f for f in findings if "Content-Security-Policy Débil" in f["vuln"]]
    assert len(csp_findings) == 1
    assert csp_findings[0]["risk"] == "Medio"
    assert csp_findings[0]["confidence"] == "confirmed"
    assert "'unsafe-inline'" in csp_findings[0]["detail"]
    assert "'unsafe-eval'" in csp_findings[0]["detail"]


def test_headers_strong_csp_not_flagged():
    """CSP estricto con nonces y sin unsafe directivas no debe generar alertas."""
    class MockStrongResp:
        def __init__(self):
            self.headers = {
                "Content-Type": "text/html; charset=utf-8",
                "Content-Security-Policy": "default-src 'self'; script-src 'self' 'nonce-rAnd0m123'",
                "Strict-Transport-Security": "max-age=31536000",
                "X-Frame-Options": "DENY",
                "X-Content-Type-Options": "nosniff",
                "Referrer-Policy": "no-referrer",
                "Permissions-Policy": "camera=()",
            }

    findings = check_headers(MockStrongResp())
    csp_findings = [f for f in findings if "Content-Security-Policy" in f["vuln"]]
    assert len(csp_findings) == 0, f"CSP robusto no debe alertarse: {findings}"


# =====================================================================
# 5. XSS JS VENDOR BUNDLE EXCLUSIONS & CONFIDENCE TESTS
# =====================================================================

def test_xss_vendor_bundle_excluded():
    """Bundles de terceros (chunk-vendors, webpack, polyfills) no deben alertar falsos DOM XSS."""
    vendor_js = "eval(location.hash); document.write(document.URL);"
    findings_chunk = analyze_js_code(vendor_js, "chunk-vendors.12345.js")
    findings_webpack = analyze_js_code(vendor_js, "webpack-runtime.min.js")
    findings_polyfills = analyze_js_code(vendor_js, "polyfills.bundle.js")

    assert len(findings_chunk) == 0
    assert len(findings_webpack) == 0
    assert len(findings_polyfills) == 0


def test_xss_custom_script_dom_flagged_with_confidence():
    """Código propio con sink peligroso debe alertarse con confidence='probable'."""
    custom_js = "document.write(document.URL);"
    findings = analyze_js_code(custom_js, "custom-search.js")

    assert len(findings) == 1
    assert "DOM" in findings[0]["vuln"]
    assert findings[0]["confidence"] == "probable"
