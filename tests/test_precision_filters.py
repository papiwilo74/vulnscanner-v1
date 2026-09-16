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


# ---------------------------------------------------------------------------
# Phase 3 Precision Filter Tests
# ---------------------------------------------------------------------------

@responses.activate
def test_graphql_spa_keyword_query_not_flagged():
    """Un sitio web común o SPA cuyo HTML contiene la palabra 'query' no debe reportar GraphQL."""
    url = "https://my-app.test"
    html_with_query = "<html><body>Welcome! Search query here: <p>Results for query</p></body></html>"

    responses.add(
        responses.GET,
        re.compile(r"^https://my-app\.test"),
        body=html_with_query,
        status=200,
        content_type="text/html",
    )
    responses.add(
        responses.POST,
        re.compile(r"^https://my-app\.test"),
        body="Not found",
        status=404,
    )

    from scanner.graphql import check_graphql

    findings = check_graphql(url)
    assert len(findings) == 0, f"No debe reportar GraphQL por texto genérico 'query': {findings}"


@responses.activate
def test_graphql_playground_console_confirmed():
    """Una consola interactiva (GraphiQL o Playground) debe detectarse con confianza 'confirmed'."""
    url = "https://my-app.test/graphql"
    playground_html = "<html><head><title>GraphiQL</title></head><body><div id='graphiql'></div></body></html>"

    responses.add(
        responses.GET,
        "https://my-app.test/graphiql",
        body=playground_html,
        status=200,
        content_type="text/html",
    )
    responses.add(
        responses.POST,
        re.compile(r"^https://my-app\.test"),
        body="Not found",
        status=404,
    )
    responses.add(
        responses.GET,
        re.compile(r"^https://my-app\.test"),
        body="Not found",
        status=404,
    )

    from scanner.graphql import check_graphql

    findings = check_graphql(url)
    console_findings = [f for f in findings if "Consola GraphQL Interactiva" in f["vuln"]]
    assert len(console_findings) == 1
    assert console_findings[0]["confidence"] == "confirmed"


@responses.activate
def test_graphql_deduplication_prefers_introspection():
    """Si un endpoint expone introspección y también responde a GET, se prioriza el hallazgo crítico."""
    endpoint = "https://my-app.test/graphql"
    intro_json = {
        "data": {
            "__schema": {
                "queryType": {"name": "Query"},
                "mutationType": None,
                "subscriptionType": None,
                "types": [{"name": "User", "kind": "OBJECT"}],
            }
        }
    }

    responses.add(
        responses.POST,
        endpoint,
        json=intro_json,
        status=200,
        content_type="application/json",
    )
    responses.add(
        responses.GET,
        endpoint,
        json={"data": {"ok": True}},
        status=200,
        content_type="application/json",
    )
    # Todos los demás endpoints 404
    responses.add(
        responses.POST,
        re.compile(r"^https://my-app\.test/(?!graphql$)"),
        body="Not found",
        status=404,
    )
    responses.add(
        responses.GET,
        re.compile(r"^https://my-app\.test/(?!graphql$)"),
        body="Not found",
        status=404,
    )

    from scanner.graphql import check_graphql

    findings = check_graphql("https://my-app.test")
    # Solo debe haber 1 hallazgo para /graphql: el de introspección
    assert len(findings) == 1
    assert "Introspeccion" in findings[0]["vuln"]
    assert findings[0]["confidence"] == "confirmed"


def test_dom_xss_independent_sources_and_sinks_not_flagged():
    """Un script con source y sink independientes (sin flujo de datos) no debe alertarse."""
    from scanner.dom_xss import analyze_scripts_for_dom_xss

    safe_script = """
    <html><body><script>
        var theme = localStorage.getItem('theme');
        setTimeout(function() { console.log('keepalive'); }, 1000);
    </script></body></html>
    """
    findings = analyze_scripts_for_dom_xss(safe_script, "https://my-app.test")
    assert len(findings) == 0, f"Coocurrencia sin flujo no debe disparar DOM XSS: {findings}"


def test_dom_xss_direct_flow_confirmed():
    """Un flujo directo source -> sink debe marcarse con confianza 'confirmed'."""
    from scanner.dom_xss import analyze_scripts_for_dom_xss

    vuln_script = """
    <html><body><script>
        document.write(location.search);
    </script></body></html>
    """
    findings = analyze_scripts_for_dom_xss(vuln_script, "https://my-app.test")
    assert len(findings) == 1
    assert findings[0]["confidence"] == "confirmed"
    assert "location.search" in findings[0]["evidence"]


def test_dom_xss_variable_propagation_confirmed():
    """Un flujo que propaga a través de una variable debe marcarse con confianza 'confirmed'."""
    from scanner.dom_xss import analyze_scripts_for_dom_xss

    vuln_script = """
    <html><body><script>
        var untrusted = location.hash;
        document.getElementById('content').innerHTML = untrusted;
    </script></body></html>
    """
    findings = analyze_scripts_for_dom_xss(vuln_script, "https://my-app.test")
    assert len(findings) == 1
    assert findings[0]["confidence"] == "confirmed"
    assert "location.hash" in findings[0]["evidence"]


def test_sca_unparseable_version_not_vulnerable():
    """Versiones no analizables o inválidas no deben generar falsos positivos."""
    from scanner.sca import is_version_vulnerable

    assert is_version_vulnerable("invalid-ver", "2.0.0") is False
    assert is_version_vulnerable("", "2.0.0") is False
    assert is_version_vulnerable("unknown", "1.0.0") is False


def test_sca_vulnerable_library_confirmed():
    """Librerías vulnerables confirmadas deben etiquetarse con confidence='confirmed'."""
    from scanner.sca import check_library_vulnerabilities

    findings = check_library_vulnerabilities("bootstrap", "3.3.7")
    assert len(findings) >= 1
    assert findings[0]["confidence"] == "confirmed"


def test_websocket_confidence_confirmed():
    """Detecciones de websocket deben calibrarse con confidence='confirmed'."""
    from scanner.websocket import check_websocket

    html = "<script>var ws = new WebSocket('ws://chat.test/live');</script>"
    findings = check_websocket("https://chat.test", html_content=html)
    insecure = [f for f in findings if "ws://" in f["vuln"]]
    assert len(insecure) == 1
    assert insecure[0]["confidence"] == "confirmed"


def test_file_upload_confidence_calibration():
    """Inputs de archivo sin accept deben reportarse como riesgo Bajo y 'probable'."""
    from scanner.file_upload import check_file_upload

    # Formulario sin accept
    html_no_accept = '<form action="/submit" method="POST"><input type="file" name="avatar"></form>'
    f_no_accept = check_file_upload("https://my-app.test", html_content=html_no_accept)
    form_findings = [f for f in f_no_accept if "Formulario" in f["vuln"]]
    assert len(form_findings) == 1
    assert form_findings[0]["risk"] == "Bajo"
    assert form_findings[0]["confidence"] == "probable"

    # Formulario con accept
    html_with_accept = '<form action="/submit" method="POST"><input type="file" name="doc" accept=".pdf"></form>'
    f_accept = check_file_upload("https://my-app.test", html_content=html_with_accept)
    form_findings_accept = [f for f in f_accept if "Formulario" in f["vuln"]]
    assert len(form_findings_accept) == 1
    assert form_findings_accept[0]["confidence"] == "confirmed"


@responses.activate
def test_param_fuzzer_confidence_confirmed():
    """Parámetros ocultos con respuesta diferencial deben marcarse con confidence='confirmed'."""
    from scanner.param_fuzzer import ParameterFuzzer

    responses.add(
        responses.GET,
        "https://my-app.test/api",
        body="normal response",
        status=200,
    )
    responses.add(
        responses.GET,
        re.compile(r"^https://my-app\.test/api\?debug="),
        body="debug mode active - internal memory dump with substantial length difference",
        status=200,
    )

    fuzzer = ParameterFuzzer()
    _, findings = fuzzer.probe_url("https://my-app.test/api", candidate_params=["debug"])
    assert len(findings) >= 1
    assert findings[0]["confidence"] == "confirmed"






