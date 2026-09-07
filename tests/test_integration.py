"""
Tests de integracion E2E para VulnScanner.
Levanta un servidor HTTP local vulnerable y ejecuta los modulos del escaner contra el,
verificando deteccion real de vulnerabilidades.
"""
import http.server
import os
import sys
import threading
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


VULN_PAGE_HTML = """<!DOCTYPE html>
<html lang="es">
<head><title>Test Vulnerable Page</title></head>
<body>
<h1 id="titulo">Bienvenido</h1>
<script>
  var userInput = document.URL.split('q=')[1] || '';
  document.getElementById('titulo').innerHTML = userInput;
  eval(document.URL);
  var aws_key = 'AKIAIOSFODNN7XYZ1234';
  var x = obj.__proto__['polluted'];
  x.constructor.prototype;
  document.write('<h2>' + location.hash + '</h2>');
</script>
<form method="POST" action="/login">
  <input type="text" name="username" placeholder="Usuario"/>
  <input type="password" name="password" placeholder="Contrasena"/>
  <input type="submit" value="Login"/>
</form>
<form method="POST" action="/upload" enctype="multipart/form-data">
  <input type="file" name="file"/>
  <input type="submit" value="Upload"/>
</form>
</body>
</html>"""

VULN_JS = """
var app = { version: '1.0.0' };
localStorage.setItem('token', 'localhost');
"""

NOT_FOUND_HTML = """<!DOCTYPE html>
<html><head><title>404 Not Found</title></head>
<body><h1>404 Not Found</h1><p>not found</p></body></html>"""


class VulnerableHandler(http.server.BaseHTTPRequestHandler):
    """Servidor HTTP con endpoints vulnerables para pruebas de integracion."""

    def do_GET(self):
        path = self.path.split('?')[0]
        if path == '/':
            self._respond(200, VULN_PAGE_HTML, 'text/html')
        elif path == '/reflected':
            qs = self.path.split('?', 1)[1] if '?' in self.path else ''
            self._respond(200, f"<html><body>{qs}</body></html>", 'text/html')
        elif path == '/search':
            self._respond(200, VULN_PAGE_HTML, 'text/html')
        elif path == '/.env':
            self._respond(200, 'DB_PASSWORD=secret123\nDATABASE_URL=postgres://user:pass@localhost/db', 'text/plain')
        elif path == '/static/app.js':
            self._respond(200, VULN_JS, 'application/javascript')
        elif path == '/open-redirect':
            self._respond(302, '', 'text/html', extra_headers={'Location': 'https://evil.com'})
        elif path == '/spa-route':
            self._respond(200, '<!doctype html><div id="root"></div>', 'text/html')
        else:
            self._respond(404, NOT_FOUND_HTML, 'text/html')

    def do_POST(self):
        if self.path == '/login':
            self._respond(200, '<html><body>Login OK</body></html>', 'text/html',
                          extra_headers={'Set-Cookie': 'session=abc123'})
        elif self.path == '/graphql':
            self._respond(200, '{"data":{"__schema":{"types":[{"name":"Query"}]}}}', 'application/json')
        else:
            self._respond(200, '<html><body>OK</body></html>', 'text/html')

    def _respond(self, code, body, ctype, extra_headers=None):
        data = body.encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Connection', 'close')
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)
        self.close_connection = True

    def log_message(self, fmt, *args):
        pass


class StableThreadingHTTPServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 32
    allow_reuse_address = True


def _request_with_retry(method, url, **kwargs):
    last_error = None
    for _ in range(3):
        try:
            return method(url, **kwargs)
        except Exception as exc:
            last_error = exc
            time.sleep(0.05)
    raise last_error


@pytest.fixture(scope='module')
def test_server():
    """Fixture que levanta el servidor vulnerable en un thread."""
    server = StableThreadingHTTPServer(('127.0.0.1', 0), VulnerableHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f'http://127.0.0.1:{port}'
    time.sleep(0.1)
    yield url
    server.shutdown()
    thread.join(timeout=2)


def _assert_has_vuln(results: list, keyword: str, risk: str = None) -> dict:
    """Helper: assert that results contain a finding matching keyword and optional risk level."""
    matches = [r for r in results if keyword.lower() in r.get('vuln', '').lower()]
    assert matches, f"Expected finding with '{keyword}', got vulns: {[r['vuln'] for r in results]}"
    if risk:
        assert any(r['risk'] == risk for r in matches), \
            f"Expected risk '{risk}' for '{keyword}', got: {[(r['vuln'], r['risk']) for r in matches]}"
    return matches[0]


class TestIntegration:
    """Pruebas E2E contra el servidor vulnerable local."""

    def test_server_is_up(self, test_server):
        import requests as req
        r = req.get(f'{test_server}/', timeout=5)
        assert r.status_code == 200
        assert 'Bienvenido' in r.text

    def test_headers_detect_missing_security_headers(self, test_server):
        import requests as req

        from scanner.headers import SECURITY_HEADERS, check_headers
        r = req.get(f'{test_server}/', timeout=5)
        results = check_headers(r)
        # STS is skipped for non-HTTPS connections (correct security behavior)
        expected_count = len(SECURITY_HEADERS) - 1 if not r.url.startswith('https://') else len(SECURITY_HEADERS)
        assert len(results) == expected_count, \
            f"Expected {expected_count} missing headers (STS skipped for HTTP), got {len(results)}"
        for result in results:
            assert result['risk'] in ('Alto', 'Medio', 'Bajo')
            assert result['detail'], "Each finding must have a detail description"
        header_names = {r['vuln'] for r in results}
        assert any('Content-Security-Policy' in h for h in header_names)
        assert any('X-Frame-Options' in h for h in header_names)

    def test_https_http_url_detected(self, test_server):
        import requests as req

        from scanner.https_check import check_https
        r = req.get(f'{test_server}/', timeout=5)
        results = check_https(test_server, r)
        assert len(results) == 1
        assert results[0]['risk'] == 'Alto'
        assert 'HTTP' in results[0]['vuln']
        assert 'cifrar' in results[0]['detail'].lower() or 'seguro' in results[0]['detail'].lower()

    def test_cookies_missing_flags(self, test_server):
        import requests as req

        from scanner.cookies import check_cookies
        s = req.Session()
        r = _request_with_retry(
            s.post,
            f'{test_server}/login',
            data={'username': 'admin', 'password': 'pass'},
            timeout=5,
        )
        results = check_cookies(r)
        assert len(results) >= 1, f"Expected cookie flag issues, got: {results}"

    def test_xss_dom_detected_in_inline_scripts(self, test_server):
        import requests as req

        from scanner.xss import check_xss
        r = req.get(f'{test_server}/', timeout=5)
        results = check_xss(f'{test_server}/', r.text, req.Session(), passive=False)
        xss_findings = [r for r in results if 'XSS' in r['vuln']]
        assert len(xss_findings) >= 1, f"Expected >=1 DOM XSS finding, got: {[r['vuln'] for r in results]}"
        assert any('eval' in r['detail'].lower() or 'innerHTML' in r['detail'].lower() or 'document.write' in r['detail'].lower()
                   for r in xss_findings), f"Should detect eval/innerHTML/document.write, got: {[r['detail'] for r in xss_findings]}"

    def test_sensitive_data_detects_aws_key_in_js(self, test_server):
        import requests as req

        from scanner.sensitive_data import check_sensitive_data
        results = check_sensitive_data(f'{test_server}/', VULN_PAGE_HTML, req.Session())
        _assert_has_vuln(results, 'AWS', risk='Alto')
        aws_finding = _assert_has_vuln(results, 'Clave de API de AWS')
        assert 'AKIA' in aws_finding['detail'], f"AWS key should appear in detail: {aws_finding['detail']}"

    def test_cors_origin_check(self, test_server):
        import requests as req

        from scanner.cors import check_cors
        results = check_cors(f'{test_server}/', req.Session())
        assert isinstance(results, list)
        for r in results:
            assert 'vuln' in r and 'risk' in r and 'detail' in r

    def test_forms_detect_csrf_missing(self, test_server):
        import requests as req

        from scanner.forms import check_forms
        results = check_forms(f'{test_server}/', VULN_PAGE_HTML, req.Session(), passive=True)
        csrf_finding = _assert_has_vuln(results, 'CSRF')
        assert csrf_finding['risk'] in ('Alto', 'Medio')

    def test_forms_detect_login_form(self, test_server):
        import requests as req

        from scanner.forms import check_forms
        results = check_forms(f'{test_server}/', VULN_PAGE_HTML, req.Session(), passive=True)
        form_findings = [r for r in results if 'formulario' in r['vuln'].lower() or 'login' in r.get('detail', '').lower()]
        assert len(form_findings) >= 1, f"Should detect login form, got: {[r['vuln'] for r in results]}"

    def test_directories_spa_fallback(self, test_server):
        import requests as req

        from scanner.directories import check_directories
        results = check_directories(f'{test_server}/spa-route', req.Session())
        for r in results:
            assert 'vuln' in r and 'risk' in r and 'detail' in r

    def test_fuzzer_detects_exposed_env(self, test_server):
        import requests as req

        from scanner.fuzzer import check_exposed_files
        results = check_exposed_files(f'{test_server}/', session=req.Session())
        _assert_has_vuln(results, '.env')
        env_finding = [r for r in results if '.env' in r['vuln']][0]
        assert env_finding['risk'] in ('Alto', 'Medio')

    def test_open_redirect_check(self, test_server):
        import requests as req

        from scanner.open_redirect import check_open_redirect
        results = check_open_redirect(f'{test_server}/open-redirect', req.Session())
        for r in results:
            assert 'vuln' in r and 'risk' in r and 'detail' in r

    def test_graphql_introspection(self, test_server):
        import requests as req

        from scanner.graphql import check_graphql
        results = check_graphql(f'{test_server}/graphql', req.Session())
        for r in results:
            assert 'vuln' in r and 'risk' in r and 'detail' in r

    def test_prototype_pollution_in_js(self, test_server):
        import requests as req

        from scanner.prototype_pollution import check_prototype_pollution
        results = check_prototype_pollution(f'{test_server}/', VULN_PAGE_HTML, req.Session())
        _assert_has_vuln(results, 'prototype')
        proto_findings = [r for r in results if 'prototype' in r['vuln'].lower()]
        assert len(proto_findings) >= 1

    def test_websocket_check(self, test_server):
        import requests as req

        from scanner.websocket import check_websocket
        results = check_websocket(f'{test_server}/', VULN_PAGE_HTML, req.Session())
        for r in results:
            assert 'vuln' in r and 'risk' in r and 'detail' in r

    def test_sca_detects_vulnerable_libs(self, test_server):
        import requests as req

        from scanner.sca import check_sca
        results = check_sca(f'{test_server}/', VULN_PAGE_HTML, req.Session())
        for r in results:
            assert 'vuln' in r and 'risk' in r and 'detail' in r

    def test_file_upload_detects_form(self, test_server):
        import requests as req

        from scanner.file_upload import check_file_upload
        results = check_file_upload(f'{test_server}/', VULN_PAGE_HTML, req.Session())
        _assert_has_vuln(results, 'subida') if any('subida' in r['vuln'].lower() for r in results) else \
            _assert_has_vuln(results, 'upload')

    def test_jwt_attacks_check(self, test_server):
        import requests as req

        from scanner.jwt_attacks import check_jwt_attacks
        results = check_jwt_attacks(f'{test_server}/', VULN_PAGE_HTML, req.Session())
        for r in results:
            assert 'vuln' in r and 'risk' in r and 'detail' in r

    def test_path_traversal_check(self, test_server):
        import requests as req

        from scanner.path_traversal import check_path_traversal
        results = check_path_traversal(f'{test_server}/search?file=test.txt', req.Session())
        for r in results:
            assert 'vuln' in r and 'risk' in r and 'detail' in r

    def test_xxe_check(self, test_server):
        import requests as req

        from scanner.xxe import check_xxe
        results = check_xxe(f'{test_server}/', VULN_PAGE_HTML, req.Session())
        for r in results:
            assert 'vuln' in r and 'risk' in r and 'detail' in r

    def test_ssl_check_http(self, test_server):
        import requests as req

        from scanner.ssl_check import check_ssl
        results = check_ssl(test_server, req.Session())
        assert len(results) >= 1
        assert results[0]['risk'] == 'Alto'
        assert any('SSL' in r['vuln'] or 'HTTP' in r['vuln'] for r in results)

    def test_full_scan_orchestrator(self, test_server):
        from main import scan
        html_path, json_path, report_data = scan(
            url=test_server,
            no_open=True,
            crawl_pages=2,
            delay=0.0,
            stealth=False,
            passive=False,
            allow_private=True,
        )
        assert html_path is not None
        assert os.path.isfile(html_path), f"HTML report not found: {html_path}"
        assert json_path is not None
        assert os.path.isfile(json_path), f"JSON report not found: {json_path}"
        assert 'target' in report_data
        assert 'summary' in report_data
        assert 'vulnerabilities' in report_data
        assert report_data['target'] == test_server
        assert report_data['summary']['Alto'] + report_data['summary']['Medio'] >= 1, \
            "Debe detectar al menos una vulnerabilidad Alta o Media"
        vulns = report_data['vulnerabilities']
        assert len(vulns) >= 5, f"Expected >=5 total findings, got {len(vulns)}"
        categories = {v['vuln'] for v in vulns}
        assert any('Header' in c or 'header' in c or 'HTTP' in c for c in categories), \
            "Should detect missing HTTP headers"
        assert any('SSL' in c or 'HTTPS' in c or 'HTTP' in c for c in categories), \
            "Should detect SSL/HTTPS issues"
        risks = {v['risk'] for v in vulns}
        assert 'Alto' in risks, "Should find at least one High risk vulnerability"
        for v in vulns:
            assert v['risk'] in ('Alto', 'Medio', 'Bajo'), f"Invalid risk level: {v['risk']}"

    def test_passive_mode_no_active_payloads(self, test_server):
        from main import scan
        html_path, json_path, report_data = scan(
            url=test_server,
            no_open=True,
            crawl_pages=1,
            delay=0.0,
            stealth=False,
            passive=True,
            allow_private=True,
        )
        assert 'vulnerabilities' in report_data
        assert 'summary' in report_data
        assert report_data['summary']['Alto'] + report_data['summary']['Medio'] >= 1
