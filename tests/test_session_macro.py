from unittest.mock import Mock

import requests
import responses

from scanner.engine import ScanConfig, ScanEngine
from scanner.session_macro import MacroStep, SessionMacro, StateAwareSessionManager


def test_sentinel_detects_active_and_expired_session():
    """El centinela debe confirmar sesión activa si el endpoint devuelve 200 y detectar expiración ante 401 o redirect a login."""
    macro = SessionMacro(
        name="test_macro",
        sentinel_url="https://app.test/api/me",
        sentinel_expected_status=200,
        login_redirect_patterns=["/login", "/auth"],
    )
    mgr = StateAwareSessionManager(macro=macro)

    # Caso 1: Sesión viva (200 OK)
    mock_alive_session = Mock()
    mock_alive_resp = Mock()
    mock_alive_resp.status_code = 200
    mock_alive_resp.url = "https://app.test/api/me"
    mock_alive_session.get.return_value = mock_alive_resp

    assert mgr.is_session_alive(mock_alive_session) is True

    # Caso 2: Sesión caducada con 401 Unauthorized
    mock_expired_session = Mock()
    mock_401_resp = Mock()
    mock_401_resp.status_code = 401
    mock_401_resp.url = "https://app.test/api/me"
    mock_expired_session.get.return_value = mock_401_resp

    assert mgr.is_session_alive(mock_expired_session) is False

    # Caso 3: Sesión caducada con redirección a /login
    mock_redirect_session = Mock()
    mock_302_resp = Mock()
    mock_302_resp.status_code = 200  # Followed redirect
    mock_302_resp.url = "https://app.test/auth/login"
    mock_redirect_session.get.return_value = mock_302_resp

    assert mgr.is_session_alive(mock_redirect_session) is False


@responses.activate
def test_execute_http_macro_updates_cookies_and_bearer_token():
    """La ejecución del macro HTTP debe realizar el login y extraer el token Bearer hacia la sesión."""
    responses.add(
        responses.POST,
        "https://app.test/api/login",
        json={"token": "jwt_token_secret_12345", "status": "success"},
        status=200,
    )

    macro = SessionMacro(
        name="login_flow",
        steps=[
            MacroStep(
                action="http_post",
                url="https://app.test/api/login",
                json_data={"user": "admin", "pass": "secret"},
            )
        ],
        headers_to_persist={"X-Custom-Client": "OmniBreach"},
    )

    session = requests.Session()
    mgr = StateAwareSessionManager(macro=macro, session=session)

    success = mgr.execute_macro(session)
    assert success is True
    assert mgr.reauth_count == 1
    assert session.headers.get("Authorization") == "Bearer jwt_token_secret_12345"
    assert session.headers.get("X-Custom-Client") == "OmniBreach"


def test_ensure_session_alive_triggers_reauth_on_expiration():
    """ensure_session_alive debe invocar execute_macro automáticamente si la sesión caducó."""
    macro = SessionMacro(
        name="auto_reauth",
        sentinel_url="https://app.test/api/me",
        steps=[MacroStep(action="set_header", selector="Authorization", value="Bearer renewed_token")],
    )
    session = requests.Session()
    mgr = StateAwareSessionManager(macro=macro, session=session, check_interval=1)

    # Simular centinela que reporta expirado
    mgr.is_session_alive = Mock(return_value=False)

    mgr.ensure_session_alive(session)
    assert mgr.reauth_count == 1
    assert session.headers.get("Authorization") == "Bearer renewed_token"


def test_scan_engine_integrates_session_manager():
    """ScanEngine debe instanciar StateAwareSessionManager si se provee session_macro en ScanConfig."""
    macro = SessionMacro(name="engine_macro", sentinel_url="https://app.test/api/me")
    config = ScanConfig(target="https://app.test", session_macro=macro)
    engine = ScanEngine(config)

    assert engine.session_manager is not None
    assert engine.session_manager.macro.name == "engine_macro"
