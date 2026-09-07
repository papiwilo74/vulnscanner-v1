"""Tests de falsos positivos y falsos negativos para cada detector clave.
Usa payloads vulnerables conocidos y contenido limpio para medir precision.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner.models import Finding

CLEAN_HTML = """<!DOCTYPE html>
<html lang="en">
<head><title>Clean Site</title>
<meta http-equiv="Content-Security-Policy" content="default-src 'self'">
</head>
<body>
<h1>Welcome</h1>
<p>This is a completely safe page with no vulnerabilities.</p>
<script>
  var x = 42;
  console.log('Hello World');
  function add(a, b) { return a + b; }
</script>
<form method="POST" action="/contact">
  <input type="hidden" name="csrf_token" value="abc123xyz"/>
  <input type="text" name="name"/>
  <input type="email" name="email"/>
  <input type="submit" value="Send"/>
</form>
</body>
</html>"""


class TestFalsePositives:
    """Verifica que el contenido limpio no genera falsos positivos."""

    def test_headers_clean_html_no_false_positive(self):
        from scanner.headers import check_headers
        class MockResp:
            def __init__(self):
                self.headers = {
                    "Content-Security-Policy": "default-src 'self'",
                    "Strict-Transport-Security": "max-age=31536000",
                    "X-Frame-Options": "DENY",
                    "X-Content-Type-Options": "nosniff",
                    "Referrer-Policy": "no-referrer",
                    "Permissions-Policy": "camera=()",
                }
        results = check_headers(MockResp())
        assert len(results) == 0, f"All headers present, should be empty: {results}"

    def test_xss_dom_clean_js_no_false_positive(self):
        from scanner.xss import analyze_js_code
        safe_js = "var x = 42; console.log('hello'); function add(a,b){return a+b;}"
        results = analyze_js_code(safe_js, "clean.js")
        assert len(results) == 0, f"No XSS in safe JS: {results}"

    def test_sqli_clean_param_no_false_positive(self):
        from urllib.parse import parse_qs, urlparse

        from scanner.sqli import test_error_sqli
        parsed = urlparse("https://example.com?page=1")
        params = parse_qs(parsed.query)
        result = test_error_sqli(parsed, params, "page", "' OR '1'='1")
        assert result is None or len(result) == 0, "Should not flag without real error signature"

    def test_sensitive_data_clean_html_no_false_positive(self):
        from scanner.sensitive_data import check_sensitive_data
        results = check_sensitive_data("https://example.com", CLEAN_HTML)
        assert len(results) == 0, f"Clean HTML should have no sensitive data: {results}"

    def test_prototype_pollution_clean_js_no_false_positive(self):
        from scanner.prototype_pollution import _analyze_js_for_prototype_pollution
        safe_js = "var obj = {}; obj.name = 'test'; obj.age = 30;"
        results = _analyze_js_for_prototype_pollution(safe_js, "safe.js")
        assert len(results) == 0, f"Safe JS should not flag prototype pollution: {results}"

    def test_forms_with_csrf_token_no_false_positive(self):
        from scanner.forms import check_forms
        html = '<form method="POST"><input type="hidden" name="csrf_token" value="abc"/><input type="text" name="q"/></form>'
        class MockSession:
            def get(self, *a, **kw):
                class R:
                    status_code = 200
                    text = html
                return R()
            def post(self, *a, **kw):
                class R:
                    status_code = 200
                    text = "OK"
                return R()
        results = check_forms("https://example.com", html, MockSession(), passive=True)
        csrf_findings = [r for r in results if 'CSRF' in r.get('vuln', '')]
        assert len(csrf_findings) == 0, f"Form with CSRF token should not flag: {results}"

    def test_cookies_secure_httponly_no_false_positive(self):
        from scanner.cookies import check_cookies
        class MockCookie:
            def __init__(self, name, secure, httponly):
                self.name = name
                self.secure = secure
                self._httponly = httponly
            def has_nonstandard_attr(self, attr):
                if attr == "HttpOnly":
                    return self._httponly
                return False
        class MockResp:
            def __init__(self):
                self.headers = {}
                self.cookies = [
                    MockCookie("session", True, True),
                    MockCookie("csrf", True, True),
                ]
        results = check_cookies(MockResp())
        assert len(results) == 0, f"All flags set, should be empty: {results}"

    def test_xss_json_content_type_no_false_positive(self):
        from unittest.mock import Mock
        from urllib.parse import parse_qs, urlparse

        from scanner.xss import test_xss_payload
        parsed = urlparse("https://api.example.com/search?q=test")
        params = parse_qs(parsed.query)
        mock_resp = Mock()
        mock_resp.text = '{"status": "ok", "query": "<script>alert(1)</script>"}'
        mock_resp.status_code = 200
        mock_resp.headers = {"Content-Type": "application/json"}
        class MockSession:
            def get(self, *a, **kw):
                return mock_resp
        result = test_xss_payload(parsed, params, "q", "<script>alert(1)</script>", "", MockSession())
        assert result is None, "JSON Content-Type should not be flagged as reflected XSS"

    def test_open_redirect_safe_domain_param_no_false_positive(self):
        from unittest.mock import Mock

        from scanner.open_redirect import check_open_redirect
        mock_resp = Mock()
        mock_resp.status_code = 302
        mock_resp.headers = {"Location": "https://example.com/login?next=https://evil-phishing-site.com"}
        mock_resp.text = ""
        class MockSession:
            def get(self, *a, **kw):
                return mock_resp
        results = check_open_redirect("https://example.com/account?redirect=test", MockSession())
        assert len(results) == 0, "Redirect keeping local domain should not flag Open Redirect"

    def test_fuzzer_spa_html_200_no_false_positive(self):
        from unittest.mock import Mock

        from scanner.fuzzer import check_exposed_files
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.headers = {"Content-Type": "text/html"}
        mock_resp.text = "<!doctype html><html><head><title>App</title></head><body><div id='root'></div></body></html>"
        mock_resp.content = mock_resp.text.encode()
        class MockSession:
            def get(self, *a, **kw):
                return mock_resp
        results = check_exposed_files("https://app.example.com", MockSession())
        assert len(results) == 0, "SPA returning 200 HTML for .env / .sql must not flag exposed files"

    def test_sensitive_data_random_base64_not_jwt_no_false_positive(self):
        from scanner.sensitive_data import scan_text_for_sensitive_data
        text = 'var hash = "eyJhbGrandomHashWithoutAlgHeader.payload123.sig456";'
        results = scan_text_for_sensitive_data(text, "bundle.js")
        jwt_findings = [r for r in results if "JWT" in r.get("vuln", "")]
        assert len(jwt_findings) == 0, "Arbitrary base64 without alg header is not a JWT"

    def test_xxe_localhost_in_error_no_false_positive(self):
        from unittest.mock import Mock

        from scanner.xxe import check_xxe
        mock_resp = Mock()
        mock_resp.status_code = 500
        mock_resp.text = "Proxy error: connection to localhost:8080 refused"
        class MockSession:
            def get(self, *a, **kw):
                return Mock(text="", status_code=200)
            def post(self, *a, **kw):
                return mock_resp
        results = check_xxe("https://example.com/api", "", MockSession())
        assert len(results) == 0, "Server error mentioning localhost should not trigger XXE finding"


class TestTruePositives:
    """Verifica que payloads vulnerables conocidos son detectados correctamente."""

    def test_headers_missing_detect_all_six(self):
        from scanner.headers import SECURITY_HEADERS, check_headers
        class MockResp:
            headers = {}
            url = "https://example.com"
        results = check_headers(MockResp())
        assert len(results) == len(SECURITY_HEADERS), \
            f"All {len(SECURITY_HEADERS)} missing headers must be detected, got {len(results)}"

    def test_xss_dom_eval_document_url_detected(self):
        from scanner.xss import analyze_js_code
        vuln_js = 'eval(document.URL.substring(1))'
        results = analyze_js_code(vuln_js, "vuln.js")
        assert len(results) >= 1, f"eval(document.URL) must be detected: {results}"
        assert any('eval' in r['vuln'].lower() or 'eval' in r['detail'].lower() for r in results)

    def test_xss_dom_innerhtml_detected(self):
        from scanner.xss import analyze_js_code
        vuln_js = "document.getElementById('x').innerHTML = location.hash;"
        results = analyze_js_code(vuln_js, "vuln.js")
        assert len(results) >= 1, f"innerHTML + location.hash must be detected: {results}"

    def test_xss_dom_document_write_detected(self):
        from scanner.xss import analyze_js_code
        vuln_js = "document.write('<h1>' + document.URL + '</h1>');"
        results = analyze_js_code(vuln_js, "vuln.js")
        assert len(results) >= 1, f"document.write + document.URL must be detected: {results}"

    def test_sensitive_data_aws_key_detected(self):
        from scanner.sensitive_data import scan_text_for_sensitive_data
        text = 'var config = { apiKey: "AKIAIOSFODNN7XYZ1234" };'
        results = scan_text_for_sensitive_data(text, "config.js")
        assert len(results) >= 1, f"AWS key should be detected: {results}"

    def test_sensitive_data_eval_detected(self):
        from scanner.sensitive_data import scan_text_for_sensitive_data
        text = 'eval("var x = " + userInput);'
        results = scan_text_for_sensitive_data(text, "script.js")
        assert any('eval' in r['vuln'].lower() for r in results), \
            f"eval() should be detected: {results}"

    def test_sensitive_data_localhost_detected(self):
        from scanner.sensitive_data import scan_text_for_sensitive_data
        text = 'const API_URL = "http://localhost:3000/api";'
        results = scan_text_for_sensitive_data(text, "config.js")
        assert any('localhost' in r.get('detail', '').lower() for r in results), \
            f"localhost reference should be detected: {results}"

    def test_prototype_pollution_proto_access(self):
        from scanner.prototype_pollution import _analyze_js_for_prototype_pollution
        vuln_js = "obj.__proto__['polluted'] = true;"
        results = _analyze_js_for_prototype_pollution(vuln_js, "vuln.js")
        assert len(results) >= 1, f"__proto__ access should be detected: {results}"

    def test_prototype_pollution_constructor_prototype(self):
        from scanner.prototype_pollution import _analyze_js_for_prototype_pollution
        vuln_js = "obj.constructor.prototype.isAdmin = true;"
        results = _analyze_js_for_prototype_pollution(vuln_js, "vuln.js")
        assert len(results) >= 1, f"constructor.prototype should be detected: {results}"

    def test_forms_csrf_missing_detected(self):
        from scanner.forms import check_forms
        html = '<form method="POST" action="/delete"><input type="text" name="id"/><input type="submit"/></form>'
        class MockSession:
            def get(self, *a, **kw):
                class R:
                    status_code = 200
                    text = html
                return R()
            def post(self, *a, **kw):
                class R:
                    status_code = 200
                    text = "OK"
                return R()
        results = check_forms("https://example.com", html, MockSession(), passive=True)
        csrf_findings = [r for r in results if 'CSRF' in r.get('vuln', '')]
        assert len(csrf_findings) >= 1, f"Missing CSRF token must be detected: {results}"

    def test_cookies_missing_flags_detected(self):
        from scanner.cookies import check_cookies
        class MockCookie:
            def __init__(self, name, secure, httponly):
                self.name = name
                self.secure = secure
                self.httponly = httponly
                self.has_nonstandard_attr = lambda x: False
        class MockResp:
            def __init__(self):
                self.headers = {}
                self.cookies = [MockCookie("session", False, False)]
        results = check_cookies(MockResp())
        assert len(results) >= 2, f"Cookie without flags should have 2 issues: {results}"

    def test_https_http_url_detected(self):
        from scanner.https_check import check_https
        class MockResp:
            url = "http://example.com"
            headers = {}
        results = check_https("http://example.com", MockResp())
        assert len(results) >= 1
        assert results[0]['risk'] == 'Alto'

    def test_cors_wildcard_detected(self):
        from scanner.cors import check_cors
        class MockResp:
            status_code = 200
            headers = {"Access-Control-Allow-Origin": "*"}
            text = ""
            history = []
        class MockSession:
            def get(self, *a, **kw):
                return MockResp()
            def options(self, *a, **kw):
                return MockResp()
        results = check_cors("https://example.com", MockSession())
        assert len(results) >= 1, f"Wildcard CORS should be detected: {results}"

    def test_ssl_http_plaintext_detected(self):
        from scanner.ssl_check import check_ssl
        class MockSession:
            headers = {}
        results = check_ssl("http://example.com", MockSession())
        assert len(results) >= 1
        assert results[0]['risk'] == 'Alto'

    def test_sca_vulnerable_jquery(self):
        from scanner.sca import check_library_vulnerabilities
        results = check_library_vulnerabilities("jquery", "1.11.0")
        assert len(results) >= 1, f"Vulnerable jQuery version should be detected: {results}"

    def test_sca_safe_jquery(self):
        from scanner.sca import check_library_vulnerabilities
        results = check_library_vulnerabilities("jquery", "3.7.0")
        assert len(results) == 0, f"Safe jQuery version should not be flagged: {results}"


class TestFindingModel:
    """Verifica el modelo Finding y su conversion."""

    def test_finding_from_legacy(self):
        legacy = {"vuln": "Header faltante: X-Frame-Options", "risk": "Alto",
                   "detail": "Protege contra clickjacking"}
        finding = Finding.from_legacy(legacy, "headers", "https://example.com")
        assert finding.category == "headers"
        assert finding.severity == "high"
        assert finding.confidence == "possible"
        assert finding.affected_url == "https://example.com"
        d = finding.to_dict()
        assert d["severity"] == "high"
        assert d["category"] == "headers"

    def test_finding_dedup_keeps_highest_severity(self):
        from scanner.models import deduplicate_findings
        f1 = Finding(category="xss", title="XSS en param q", severity="medium", confidence="possible",
                      affected_url="https://x.com", parameter="q")
        f2 = Finding(category="xss", title="XSS en param q", severity="high", confidence="confirmed",
                      affected_url="https://x.com", parameter="q")
        result = deduplicate_findings([f1, f2])
        assert len(result) == 1
        assert result[0].severity == "high"
        assert result[0].confidence == "confirmed"

    def test_finding_different_params_not_deduped(self):
        from scanner.models import deduplicate_findings
        f1 = Finding(category="xss", title="XSS Reflejado", severity="high", parameter="q")
        f2 = Finding(category="xss", title="XSS Reflejado", severity="high", parameter="search")
        result = deduplicate_findings([f1, f2])
        assert len(result) == 2

    def test_finding_to_dict_includes_all_fields(self):
        from scanner.models import Evidence
        ev = Evidence(request_method="POST", request_url="https://x.com/login",
                       payload="' OR 1=1", response_status=500,
                       response_fragment="SQL syntax error")
        f = Finding(category="sqli", title="SQLi en login", severity="critical",
                     confidence="confirmed", description="Detectado error SQL",
                     evidence=ev, remediation="Usar prepared statements",
                     affected_url="https://x.com/login", parameter="username")
        d = f.to_dict()
        assert d["severity"] == "critical"
        assert d["confidence"] == "confirmed"
        assert d["evidence"]["payload"] == "' OR 1=1"
        assert d["evidence"]["response_status"] == 500
        assert d["remediation"] == "Usar prepared statements"
        assert d["parameter"] == "username"


class TestEngineProfiles:
    """Verifica que los perfiles de escaneo se configuran correctamente."""

    def test_passive_profile_no_active_payloads(self):
        from scanner.engine import PROFILE_CONFIG, ScanProfile
        cfg = PROFILE_CONFIG[ScanProfile.PASSIVE]
        assert cfg["active_payloads"] is False
        assert cfg["max_rps"] <= 5
        assert cfg["max_crawl_pages"] <= 5

    def test_normal_profile_active_payloads(self):
        from scanner.engine import PROFILE_CONFIG, ScanProfile
        cfg = PROFILE_CONFIG[ScanProfile.NORMAL]
        assert cfg["active_payloads"] is True
        assert cfg["max_rps"] >= 5
        assert cfg["max_crawl_pages"] >= 10

    def test_aggressive_profile_higher_limits(self):
        from scanner.engine import PROFILE_CONFIG, ScanProfile
        cfg = PROFILE_CONFIG[ScanProfile.AGGRESSIVE]
        assert cfg["active_payloads"] is True
        assert cfg["max_rps"] >= 30
        assert cfg["max_total_requests"] >= 3000

    def test_from_profile_creates_scan_config(self):
        from scanner.engine import ScanConfig, ScanProfile
        config = ScanConfig.from_profile(ScanProfile.NORMAL, target="https://example.com")
        assert config.profile == ScanProfile.NORMAL
        assert config.target == "https://example.com"
        assert config.active_payloads is True

    def test_engine_url_dedup(self):
        from scanner.engine import ScanConfig, ScanEngine, ScanProfile
        config = ScanConfig.from_profile(ScanProfile.NORMAL, target="https://example.com")
        engine = ScanEngine(config)
        engine.start()
        assert not engine.is_duplicate("https://example.com/page")
        assert engine.is_duplicate("https://example.com/page")
        assert not engine.is_duplicate("https://example.com/other")


class TestSARIF:
    """Verifica la generacion de reportes SARIF."""

    def test_sarif_valid_structure(self):
        from utils.report import generate_sarif_report
        findings = [Finding(category="xss", title="XSS en param q", severity="high",
                             confidence="confirmed", description="Reflejado sin escapar",
                             affected_url="https://x.com?q=<script>")]
        sarif = generate_sarif_report("https://x.com", findings)
        assert sarif["version"] == "2.1.0"
        assert "$schema" in sarif
        assert len(sarif["runs"]) == 1
        results = sarif["runs"][0]["results"]
        assert len(results) >= 1
        assert any("xss" in r["ruleId"].lower() for r in results)
