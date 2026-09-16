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
