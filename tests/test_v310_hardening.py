"""
Pruebas de endurecimiento de seguridad (Hardening v3.10) para la API y orquestador DAST:
1. Bloqueo de bypass de autenticación cuando OMNIBREACH_ENV=production.
2. Protección Anti-SSRF en webhooks de notificación (bloqueo de loopback y AWS IMDS).
3. Validación estricta de ruta con os.path.commonpath y RBAC en GET /download.
4. Prevención de falsos positivos BOLA/IDOR ante rutas catch-all HTML de SPAs.
5. Integración de check_api_security y check_exposed_artifacts en el orquestador.
"""
from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest

from scanner.api_security import check_api_security, check_bola_idor
from scanner.exposed_artifacts import check_exposed_artifacts


def _get_client() -> Any:
    from fastapi.testclient import TestClient

    from api import app

    return TestClient(app)


def test_production_env_rejects_unauthenticated_access(monkeypatch: pytest.MonkeyPatch) -> None:
    """En modo producción, la falta de cabecera Authorization Bearer debe retornar 401 y nunca Role.ADMIN."""
    monkeypatch.setenv("OMNIBREACH_ENV", "production")
    res = _get_client().get("/scans")
    assert res.status_code == 401
    assert "obligatoria" in res.json()["detail"].lower()


def test_webhook_ssrf_guard_blocks_internal_targets() -> None:
    """El validador de webhooks debe bloquear loopback, redes privadas y metadatos cloud."""
    from api import _validate_webhook_url

    with pytest.raises(ValueError, match="SSRF Guard"):
        _validate_webhook_url("http://127.0.0.1:6379/internal", allow_private=False)

    with pytest.raises(ValueError, match="SSRF Guard"):
        _validate_webhook_url("http://169.254.169.254/latest/meta-data/", allow_private=False)

    with pytest.raises(ValueError, match="SSRF Guard"):
        _validate_webhook_url("http://localhost:8000/admin", allow_private=False)

    with pytest.raises(ValueError, match="inválida"):
        _validate_webhook_url("file:///etc/passwd", allow_private=False)


def test_scan_endpoint_rejects_ssrf_webhook() -> None:
    """POST /scan debe retornar HTTP 400 si webhook_url apunta a una IP privada sin allow_private."""
    res = _get_client().post(
        "/scan",
        json={
            "url": "https://example.com",
            "webhook_url": "http://169.254.169.254/latest/meta-data/",
            "allow_private": False,
        },
    )
    assert res.status_code == 400
    assert "SSRF Guard" in res.json()["detail"]


def test_download_endpoint_blocks_sibling_prefix_traversal() -> None:
    """GET /download debe usar os.path.commonpath y rechazar rutas fuera de reports/."""
    res = _get_client().get("/download", params={"path": "../reports_secret/leak.json"})
    assert res.status_code == 404


def test_bola_ignores_spa_html_catchall_false_positive() -> None:
    """Si el endpoint para Usuario A retorna JSON pero para ID B retorna HTML de SPA (200 OK), no es BOLA."""
    mock_session = MagicMock()

    resp_a = MagicMock()
    resp_a.status_code = 200
    resp_a.text = '{"id": 1001, "email": "alice@example.com", "role": "user"}'

    resp_b_spa = MagicMock()
    resp_b_spa.status_code = 200
    resp_b_spa.text = "<!doctype html><html><body><div id='root'>SPA Fallback</div></body></html>"

    mock_session.request.side_effect = [resp_a, resp_b_spa]

    finding = check_bola_idor(
        "https://app.example.com/api/users/1001",
        session_user_a=mock_session,
        unauth_check=False,
    )
    assert finding is None


def test_orchestrator_helpers_api_and_artifacts() -> None:
    """Verifica que los wrappers de orquestación check_api_security y check_exposed_artifacts operen sin errores."""
    mock_session = MagicMock()
    resp = MagicMock()
    resp.status_code = 404
    resp.text = "Not Found"
    mock_session.get.return_value = resp
    mock_session.request.return_value = resp

    api_findings: list[Any] = check_api_security("https://app.example.com/api/users/10", session=mock_session, passive=True)
    assert isinstance(api_findings, list)

    html_with_s3 = '<script src="https://corp-assets-prod.s3.amazonaws.com/app.js"></script>'
    art_findings = check_exposed_artifacts("https://app.example.com", html_content=html_with_s3, session=mock_session, passive=True)
    assert isinstance(art_findings, list)


def test_wildcard_dns_subdomain_suppressed(monkeypatch: pytest.MonkeyPatch) -> None:
    """Si la IP pertenece a un registro Wildcard DNS y no responde HTTP válido, no debe reportarse como subdominio."""
    import requests as req_mod
    from scanner import subdomains

    monkeypatch.setattr(subdomains, "_resolve_dns", lambda target: "216.24.57.16")

    def _raise_conn(*a: Any, **kw: Any) -> Any:
        raise req_mod.RequestException("SSL error on wildcard")

    monkeypatch.setattr(req_mod, "get", _raise_conn)

    res = subdomains._verify_subdomain(
        "shop.investpro-j91h.onrender.com",
        "https",
        0,
        wildcard_ips={"216.24.57.16"},
    )
    assert res is None


def test_port_8080_cloudflare_anycast_suppressed(monkeypatch: pytest.MonkeyPatch) -> None:
    """El puerto 8080 en un proxy Anycast de Cloudflare (HTTP 400 / Server: cloudflare) no debe reportarse."""
    import socket
    from scanner.ports import check_single_port

    class MockCFSocket:
        def __init__(self, *a: Any, **kw: Any) -> None:
            pass

        def __enter__(self) -> MockCFSocket:
            return self

        def __exit__(self, *a: Any) -> None:
            pass

        def settimeout(self, t: float) -> None:
            pass

        def connect_ex(self, addr: Any) -> int:
            return 0

        def sendall(self, data: bytes) -> None:
            pass

        def recv(self, n: int) -> bytes:
            return b"HTTP/1.1 400 Bad Request\r\nServer: cloudflare\r\nCF-RAY: 89abc\r\n\r\n"

    monkeypatch.setattr(socket, "socket", MockCFSocket)
    finding = check_single_port("216.24.57.16", 8080, "HTTP-Alt", "Panel alternativo", "Medio")
    assert finding is None


def test_rea_sourcemap_exposure_detection() -> None:
    """Detecta un Source Map v3 válido (.js.map) con SHA-256 y lista de archivos fuente e ignora Soft-404 HTML."""
    from scanner.sca import _check_js_sourcemap

    mock_session = MagicMock()
    map_resp = MagicMock()
    map_resp.status_code = 200
    map_resp.headers = {"Content-Type": "application/json"}
    map_resp.text = '{"version": 3, "sources": ["webpack:///./src/auth/token.ts", "webpack:///./src/api/client.ts"]}'
    map_resp.content = map_resp.text.encode("utf-8")
    mock_session.get.return_value = map_resp

    finding = _check_js_sourcemap(
        "https://app.example.com/static/main.bundle.js",
        "console.log(1);\n//# sourceMappingURL=main.bundle.js.map",
        session=mock_session,
    )
    assert finding is not None
    assert "Source Map JavaScript Expuesto" in finding["vuln"]
    assert "src/auth/token.ts" in finding["detail"]


def test_rea_api_surface_url_normalization() -> None:
    """Colapsa rutas paramétricas REST (/{int}, /{uuid}) y ordena claves query para evitar fuzzing redundante."""
    from scanner.engine import ScanConfig, ScanEngine

    eng = ScanEngine(ScanConfig())
    u1 = eng.normalize_url("https://api.example.com/v1/users/104/orders/550e8400-e29b-41d4-a716-446655440000?sort=asc&page=1")
    u2 = eng.normalize_url("https://api.example.com/v1/users/999/orders/123e4567-e89b-12d3-a456-426614174000?page=5&sort=desc")
    assert u1 == u2
    assert "/users/{int}/orders/{uuid}?page&sort" in u1


def test_dom_skeleton_soft404_suppression() -> None:
    """Suprime falsos positivos de directorios cuando un Soft-404 cambia de longitud y primeros 300 chars pero conserva el esqueleto DOM."""
    from scanner.directories import _dom_skeleton_sig, check_single_directory

    canary_html = (
        "<html><head><title>404 Not Found - Request 99182</title></head>"
        "<body><main><div class='err'>No existe /_soft404_canary</div><footer>v1</footer></main></body></html>"
    )
    probe_html = (
        "<html><head><title>404 Not Found - Dynamic Token 881726354411223344556677889900</title></head>"
        "<body><main><div class='err'>Ruta no encontrada: /admin con descripcion extendida</div><footer>v1</footer></main></body></html>"
    )
    skeleton = _dom_skeleton_sig(canary_html)

    mock_session = MagicMock()
    resp = MagicMock()
    resp.status_code = 200
    resp.headers = {"Content-Type": "text/html"}
    resp.text = probe_html
    mock_session.get.return_value = resp

    res = check_single_directory(
        "https://app.example.com",
        "/admin",
        session=mock_session,
        baseline_status=200,
        baseline_body_sig=canary_html[:300].lower(),
        baseline_len=len(canary_html),
        is_soft_404=True,
        baseline_skeleton_sig=skeleton,
    )
    assert res is None


def test_cors_wildcard_public_html_vs_api() -> None:
    """Suprime CORS '*' sin credenciales en landing pages HTML públicas pero lo reporta en endpoints de API."""
    from scanner.cors import check_cors

    html_session = MagicMock()
    html_resp = MagicMock()
    html_resp.status_code = 200
    html_resp.headers = {"Access-Control-Allow-Origin": "*", "Content-Type": "text/html; charset=utf-8"}
    html_session.get.return_value = html_resp
    html_session.options.return_value = html_resp

    assert check_cors("https://investpro-j91h.onrender.com/", session=html_session) == []

    api_session = MagicMock()
    api_resp = MagicMock()
    api_resp.status_code = 200
    api_resp.headers = {"Access-Control-Allow-Origin": "*", "Content-Type": "application/json"}
    api_session.get.return_value = api_resp
    api_session.options.return_value = api_resp

    api_findings = check_cors("https://investpro-j91h.onrender.com/api/v1/portfolio", session=api_session)
    assert len(api_findings) == 1
    assert api_findings[0]["vuln"] == "CORS Abierto (Comodín)"


