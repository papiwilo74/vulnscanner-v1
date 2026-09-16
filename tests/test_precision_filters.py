import re

import responses

from scanner.directories import check_directories
from scanner.open_redirect import check_open_redirect


@responses.activate
def test_soft_404_spa_returns_no_false_positives():
    """Un sitio SPA que devuelve 200 para todas las rutas no debe generar falsos positivos de directorios."""
    base_url = "https://my-spa-app.test"
    spa_html = '<!doctype html><html><body><div id="root"></div><script src="/app.js"></script></body></html>'

    def spa_callback(request):
        return (200, {"Content-Type": "text/html"}, spa_html)

    responses.add_callback(
        responses.GET,
        re.compile(r"^https://my-spa-app\.test"),
        callback=spa_callback
    )

    findings = check_directories(base_url)
    assert len(findings) == 0, f"Debe descartar todas las rutas Soft-404 de la SPA: {findings}"


@responses.activate
def test_real_exposed_directory_detected():
    """Una ruta real expuesta debe detectarse con confianza confirmada si el 404 es legítimo."""
    base_url = "https://my-real-app.test"

    def callback(request):
        if "_soft404_canary" in request.url:
            return (404, {"Content-Type": "text/html"}, "<html>Not Found</html>")
        if "/admin" in request.url:
            return (200, {"Content-Type": "text/html"}, "<html><body><h1>Admin Portal</h1></body></html>")
        return (404, {"Content-Type": "text/html"}, "<html>Not Found</html>")

    responses.add_callback(
        responses.GET,
        re.compile(r"^https://my-real-app\.test"),
        callback=callback
    )

    findings = check_directories(base_url)
    admin_findings = [f for f in findings if "/admin" in f["vuln"]]
    assert len(admin_findings) == 1
    assert admin_findings[0]["confidence"] == "confirmed"


@responses.activate
def test_open_redirect_static_redirect_discarded():
    """Si el parámetro siempre redirige a una URL estática interna, debe descartarse (falso positivo)."""
    target_url = "https://app.test/login?redirect=https://evil-phishing-site.com"

    def callback(request):
        # Siempre redirige a /home independientemente de lo que se envíe
        return (302, {"Location": "https://app.test/home"}, "")

    responses.add_callback(
        responses.GET,
        re.compile(r"^https://app\.test/login"),
        callback=callback
    )

    findings = check_open_redirect(target_url)
    assert len(findings) == 0, f"Redirección fija no debe marcarse como Open Redirect: {findings}"


@responses.activate
def test_open_redirect_arbitrary_confirmed():
    """Si redirige arbitrariamente a ambos dominios probados, debe confirmarse con confianza 'confirmed'."""
    target_url = "https://app.test/out?url=https://evil-phishing-site.com"

    def callback(request):
        url = request.url
        if "evil-phishing-site.com" in url:
            return (302, {"Location": "https://evil-phishing-site.com"}, "")
        if "control-verify-target.org" in url:
            return (302, {"Location": "https://control-verify-target.org"}, "")
        return (200, {}, "OK")

    responses.add_callback(
        responses.GET,
        re.compile(r"^https://app\.test/out"),
        callback=callback
    )

    findings = check_open_redirect(target_url)
    assert len(findings) == 1
    assert findings[0]["confidence"] == "confirmed"


@responses.activate
def test_fuzzer_nextjs_spa_soft_404_discarded():
    """Un sitio Next.js que devuelve HTML con __NEXT_DATA__ para cualquier ruta no debe reportar archivos expuestos."""
    base_url = "https://nextjs-app.test"
    next_html = '<!DOCTYPE html><html><body><div id="__next">404 Page</div><script id="__NEXT_DATA__">{}</script></body></html>'

    responses.add(
        responses.GET,
        re.compile(r"^https://nextjs-app\.test"),
        body=next_html,
        status=200,
        content_type="text/html",
    )

    from scanner.fuzzer import check_exposed_files

    findings = check_exposed_files(base_url)
    assert len(findings) == 0, f"Debe descartar respuestas de shell Next.js: {findings}"


@responses.activate
def test_fuzzer_real_exposed_file_confirmed():
    """Un archivo sensible real (.env con credenciales) debe detectarse con confianza confirmada."""
    base_url = "https://my-app.test"

    def callback(request):
        if "un_archivo_que_no_existe" in request.url:
            return (404, {"Content-Type": "text/html"}, "Not Found")
        if request.url.endswith("/.env"):
            return (200, {"Content-Type": "text/plain"}, "DB_PASSWORD=secret_12345\nSECRET_KEY=abcdef")
        return (404, {"Content-Type": "text/html"}, "Not Found")

    responses.add_callback(
        responses.GET,
        re.compile(r"^https://my-app\.test"),
        callback=callback,
    )

    from scanner.fuzzer import check_exposed_files

    findings = check_exposed_files(base_url)
    env_findings = [f for f in findings if ".env" in f["vuln"]]
    assert len(env_findings) == 1
    assert env_findings[0]["confidence"] == "confirmed"


@responses.activate
def test_path_traversal_confirmed():
    """Una inyección de Path Traversal exitosa debe reportarse con confianza confirmada."""
    target_url = "https://target.test/view?file=test"

    def callback(request):
        url = request.url
        if "etc%2Fpasswd" in url or "etc/passwd" in url:
            return (200, {"Content-Type": "text/plain"}, "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:")
        return (200, {"Content-Type": "text/html"}, "<html><body>Normal Page</body></html>")

    responses.add_callback(
        responses.GET,
        re.compile(r"^https://target\.test/view"),
        callback=callback,
    )

    from scanner.path_traversal import check_path_traversal

    findings = check_path_traversal(target_url)
    assert len(findings) == 1
    assert findings[0]["confidence"] == "confirmed"


@responses.activate
def test_xss_unescaped_reflection_confirmed():
    """Un payload XSS reflejado sin escapar en HTML debe marcarse como confirmado."""
    from urllib.parse import parse_qs, urlparse

    target_url = "https://target.test/search?q=test"
    parsed = urlparse(target_url)
    params = parse_qs(parsed.query)

    responses.add(
        responses.GET,
        re.compile(r"^https://target\.test/search"),
        body="<html><body>Resultados para: <script>alert(1)</script></body></html>",
        content_type="text/html",
        status=200,
    )

    from scanner.xss import test_xss_payload

    finding = test_xss_payload(
        parsed=parsed,
        params=params,
        param="q",
        payload="<script>alert(1)</script>",
        baseline_text="<html><body>Resultados para: test</body></html>",
    )
    assert finding is not None
    assert finding["confidence"] == "confirmed"


@responses.activate
def test_jwt_open_endpoint_no_false_positive():
    """Un endpoint público que devuelve 200 para cualquier petición no debe generar falsos positivos de JWT."""
    url = "https://my-app.test/public"
    jwt_sample = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgN_p_placeholder_sig_12345"
    html_with_jwt = f'<html><script>var t = "{jwt_sample}";</script></html>'

    # Siempre devuelve 200 (incluso para el token basura de control)
    responses.add(
        responses.GET,
        re.compile(r"^https://my-app\.test/public"),
        body=html_with_jwt,
        status=200,
    )

    from scanner.jwt_attacks import check_jwt_attacks

    findings = check_jwt_attacks(url, html_content=html_with_jwt)
    # Debe descartar "alg=none" y secreto HMAC porque el endpoint es público
    forged_findings = [f for f in findings if "Aceptado" in f["vuln"] or "Debil" in f["vuln"]]
    assert len(forged_findings) == 0, f"No debe reportar forja en endpoints públicos: {forged_findings}"


@responses.activate
def test_jwt_enforced_auth_confirmed():
    """Si el endpoint rechaza el token inválido (401) pero acepta alg=none (200), se confirma la vulnerabilidad."""
    url = "https://my-app.test/api/secure"
    jwt_sample = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgN_p_placeholder_sig_12345"
    html_with_jwt = f'<html><script>var t = "{jwt_sample}";</script></html>'

    def callback(request):
        auth = request.headers.get("Authorization", "")
        if "invalid.token" in auth:
            return (401, {}, "Unauthorized")
        if "eyJhbGciOiAibm9uZSI" in auth or "eyJhbGciOiJub25lIg" in auth:
            return (200, {}, "Welcome Admin")
        return (200, {}, html_with_jwt)

    responses.add_callback(
        responses.GET,
        re.compile(r"^https://my-app\.test/api/secure"),
        callback=callback,
    )

    from scanner.jwt_attacks import check_jwt_attacks

    findings = check_jwt_attacks(url, html_content=html_with_jwt)
    none_findings = [f for f in findings if "alg=none" in f["vuln"]]
    assert len(none_findings) == 1
    assert none_findings[0]["confidence"] == "confirmed"


def test_prototype_pollution_object_create_null_not_flagged():
    """El patrón defensivo Object.create(null) no debe alertarse como vulnerabilidad."""
    from scanner.prototype_pollution import _analyze_js_for_prototype_pollution

    safe_code = "const dictionary = Object.create(null); dictionary['key'] = 1;"
    findings = _analyze_js_for_prototype_pollution(safe_code, "safe_utils.js")
    assert len(findings) == 0, f"Object.create(null) es seguro y no debe reportarse: {findings}"


def test_prototype_pollution_vendor_library_skipped():
    """Librerías de vendor como React o chunk-vendors no deben disparar alertas de prototype pollution."""
    from scanner.prototype_pollution import _analyze_js_for_prototype_pollution

    code = "obj.__proto__['test'] = 1;"
    findings = _analyze_js_for_prototype_pollution(code, "chunk-vendors.min.js")
    assert len(findings) == 0, "Debe omitir archivos clasificados como vendor"


def test_sensitive_data_vendor_js_eval_not_flagged():
    """Un bundle de vendor con eval() o document.write() no debe generar falsos positivos."""
    from scanner.sensitive_data import scan_text_for_sensitive_data

    code = "function polyfill() { eval('void 0'); document.write(''); }"
    findings = scan_text_for_sensitive_data(code, "chunk-vendors.4812f.js")
    eval_findings = [f for f in findings if "eval" in f["vuln"] or "document.write" in f["vuln"]]
    assert len(eval_findings) == 0, f"Debe descartar eval en vendor scripts: {eval_findings}"


def test_csrf_external_action_not_flagged():
    """Formularios POST que envían a dominios externos no deben alertarse por falta de token CSRF."""
    from scanner.forms import scan_single_form

    external_form = {
        "action": "https://paypal.com/cgi-bin/webscr",
        "method": "post",
        "inputs": [{"name": "cmd", "type": "hidden", "value": "_xclick"}]
    }
    findings = scan_single_form(external_form, base_url="https://my-app.test/checkout", passive=True)
    csrf_findings = [f for f in findings if "CSRF" in f["vuln"]]

    assert len(csrf_findings) == 0, f"No debe reportar CSRF en formularios de terceros: {csrf_findings}"


def test_ports_banner_confirmed(monkeypatch):
    """Un puerto con banner protocolar verificado debe marcarse con confianza 'confirmed'."""
    from scanner.ports import check_single_port

    class MockSocket:
        def __init__(self, *a, **kw):
            pass
        def __enter__(self):
            return self
        def __exit__(self, *a):
            pass
        def settimeout(self, t):
            pass
        def connect_ex(self, addr):
            return 0
        def recv(self, n):
            return b"220 FTP Server ready\r\n"

    import socket
    monkeypatch.setattr(socket, "socket", MockSocket)

    finding = check_single_port("1.2.3.4", 21, "FTP", "Transferencia sin cifrar", "Medio")
    assert finding is not None
    assert finding["confidence"] == "confirmed"
    assert "Banner de protocolo verificado" in finding["detail"]





