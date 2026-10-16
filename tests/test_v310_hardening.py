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
from fastapi.testclient import TestClient

from api import _validate_webhook_url, app
from scanner.api_security import check_api_security, check_bola_idor
from scanner.exposed_artifacts import check_exposed_artifacts

client = TestClient(app)


def test_production_env_rejects_unauthenticated_access(monkeypatch: pytest.MonkeyPatch) -> None:
    """En modo producción, la falta de cabecera Authorization Bearer debe retornar 401 y nunca Role.ADMIN."""
    monkeypatch.setenv("OMNIBREACH_ENV", "production")
    res = client.get("/scans")
    assert res.status_code == 401
    assert "obligatoria" in res.json()["detail"].lower()


def test_webhook_ssrf_guard_blocks_internal_targets() -> None:
    """El validador de webhooks debe bloquear loopback, redes privadas y metadatos cloud."""
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
    res = client.post(
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
    res = client.get("/download", params={"path": "../reports_secret/leak.json"})
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
