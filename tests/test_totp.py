import pytest
import requests
import responses

from scanner.auth_helper import dynamic_login
from scanner.session_macro import MacroStep, SessionMacro, StateAwareSessionManager, build_smart_auth_macro
from scanner.totp import clean_base32_secret, generate_hotp, generate_totp, verify_totp

# Clave secreta RFC 6238 estándar (ASCII "12345678901234567890") en Base32
RFC_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"


def test_clean_base32_secret_valid_and_normalization():
    """Valida la normalización de secretos Base32 con espacios, guiones y minúsculas."""
    secret_dirty = "  gez-dgnb-vgy3-tqoj-qgez-dgnb-vgy3-tqoj-q  "
    cleaned = clean_base32_secret(secret_dirty)
    expected = clean_base32_secret(RFC_SECRET)
    assert cleaned == expected
    assert len(cleaned) == 20


def test_clean_base32_secret_auto_padding():
    """Comprueba que se agregue automáticamente el padding '=' necesario según RFC 4648."""
    unpadded = "JBSWY3DPEHPK3PXP"  # "Hello!\xde\xad\xbe\xef"
    cleaned = clean_base32_secret(unpadded)
    assert isinstance(cleaned, bytes)
    assert len(cleaned) > 0


def test_clean_base32_secret_errors():
    """Debe lanzar ValueError ante secretos vacíos o caracteres fuera del alfabeto Base32."""
    with pytest.raises(ValueError, match="no puede estar vacío"):
        clean_base32_secret("")

    with pytest.raises(ValueError, match="inválido o malformado"):
        clean_base32_secret("!@#$%^&*()_+")


def test_rfc6238_official_test_vectors():
    """
    Comprueba los vectores de prueba oficiales de la RFC 6238 (SHA1, intervalo 30s).
    """
    # Test vectors RFC 6238 §Appendix B
    vectors = [
        (59, "287082"),
        (1111111109, "081804"),
        (1111111111, "050471"),
        (1234567890, "005924"),
        (2000000000, "279037"),
    ]

    for timestamp, expected_totp in vectors:
        calculated = generate_totp(RFC_SECRET, digits=6, interval=30, for_time=timestamp)
        assert calculated == expected_totp, f"Fallo en TOTP para timestamp {timestamp}"


def test_rfc6238_8_digits_vector():
    """Comprueba cálculo de 8 dígitos según RFC 6238."""
    # Timestamp 59 en 8 dígitos -> 94287082
    calculated = generate_totp(RFC_SECRET, digits=8, interval=30, for_time=59)
    assert calculated == "94287082"


def test_generate_hotp_invalid_digits():
    """generate_hotp debe rechazar números de dígitos fuera del rango [6, 8]."""
    key = b"12345678901234567890"
    with pytest.raises(ValueError, match="entre 6 y 8"):
        generate_hotp(key, counter=1, digits=5)
    with pytest.raises(ValueError, match="entre 6 y 8"):
        generate_hotp(key, counter=1, digits=9)


def test_verify_totp_tolerance_window():
    """Verifica que la ventana de tolerancia de reloj funcione adecuadamente."""
    t_now = 1234567890.0  # Counter = 41152263
    valid_now = generate_totp(RFC_SECRET, for_time=t_now)
    code_past_30s = generate_totp(RFC_SECRET, for_time=t_now - 30)
    code_future_30s = generate_totp(RFC_SECRET, for_time=t_now + 30)
    code_distant = generate_totp(RFC_SECRET, for_time=t_now - 90)

    # Ventana estándar 1 (actual, -30s, +30s)
    assert verify_totp(valid_now, RFC_SECRET, window=1, for_time=t_now) is True
    assert verify_totp(code_past_30s, RFC_SECRET, window=1, for_time=t_now) is True
    assert verify_totp(code_future_30s, RFC_SECRET, window=1, for_time=t_now) is True

    # Fuera de la ventana
    assert verify_totp(code_distant, RFC_SECRET, window=1, for_time=t_now) is False

    # Ampliando la ventana a 3
    assert verify_totp(code_distant, RFC_SECRET, window=3, for_time=t_now) is True

    # Tokens inválidos
    assert verify_totp("12345", RFC_SECRET, for_time=t_now) is False  # 5 dígitos
    assert verify_totp("abcdef", RFC_SECRET, for_time=t_now) is False  # No numérico
    assert verify_totp("123456", "CLAVE_CORRUPTA_!@#", for_time=t_now) is False


def test_build_smart_auth_macro():
    """Verifica la construcción autónoma de macros para HTTP y SPAs con TOTP."""
    # 1. Macro HTTP tradicional
    http_macro = build_smart_auth_macro(
        login_url="https://app.test/login",
        username="secops",
        password="TopSecretPassword123!",
        totp_secret=RFC_SECRET,
        sentinel_url="https://app.test/api/dashboard",
        is_spa=False,
    )
    assert http_macro.name == "smart_auth_macro"
    assert http_macro.sentinel_url == "https://app.test/api/dashboard"
    assert len(http_macro.steps) == 2
    assert http_macro.steps[0].action == "goto"
    assert http_macro.steps[1].action == "http_post"
    assert http_macro.steps[1].totp_secret == RFC_SECRET
    assert http_macro.steps[1].data["username"] == "secops"
    assert http_macro.steps[1].data["totp"] == "{{TOTP}}"

    # 2. Macro SPA interactivo
    spa_macro = build_smart_auth_macro(
        login_url="https://app.test/spa/login",
        username="secops",
        password="TopSecretPassword123!",
        totp_secret=RFC_SECRET,
        sentinel_url="https://app.test/api/me",
        is_spa=True,
    )
    actions = [s.action for s in spa_macro.steps]
    assert "goto" in actions
    assert "fill" in actions
    assert "fill_totp" in actions
    assert "click" in actions
    totp_step = next(s for s in spa_macro.steps if s.action == "fill_totp")
    assert totp_step.totp_secret == RFC_SECRET


@responses.activate
def test_dynamic_login_with_totp_injection():
    """dynamic_login debe auto-generar e inyectar el código TOTP en los datos del formulario."""
    captured_body = {}

    def login_callback(request):
        # request.body es 'key=val&...'
        from urllib.parse import parse_qs
        captured_body.update(parse_qs(request.body))
        return (200, {"Set-Cookie": "session=auth_totp_ok_123"}, "")

    responses.add_callback(
        responses.POST,
        "https://app.test/api/login",
        callback=login_callback,
    )

    sess = dynamic_login(
        login_url="https://app.test/api/login",
        credentials_str="username=admin;password=secret",
        totp_secret=RFC_SECRET,
    )

    assert sess is not None
    assert sess.cookies.get("session") == "auth_totp_ok_123"
    # El body enviado debe incluir totp o otp numérico de 6 dígitos
    assert "totp" in captured_body or "code" in captured_body
    code_sent = captured_body.get("totp", [None])[0]
    assert code_sent is not None
    assert len(code_sent) == 6
    assert code_sent.isdigit()


@responses.activate
def test_session_macro_hot_reauth_with_totp():
    """StateAwareSessionManager debe re-autenticar exitosamente ejecutando macro con TOTP dinámico."""
    login_calls = []

    def mock_login(request):
        import json
        login_calls.append(request.body)
        return (200, {}, json.dumps({"token": "reauth_bearer_token_777"}))

    responses.add_callback(
        responses.POST,
        "https://app.test/auth",
        callback=mock_login,
    )

    macro = SessionMacro(
        name="totp_login",
        sentinel_url="https://app.test/status",
        steps=[
            MacroStep(
                action="http_post",
                url="https://app.test/auth",
                json_data={"user": "admin", "totp": "{{TOTP}}"},
                totp_secret=RFC_SECRET,
            )
        ],
    )

    session = requests.Session()
    mgr = StateAwareSessionManager(macro=macro, session=session)

    ok = mgr.execute_macro(session)
    assert ok is True
    assert mgr.reauth_count == 1
    assert session.headers.get("Authorization") == "Bearer reauth_bearer_token_777"
    assert len(login_calls) == 1
    import json
    payload = json.loads(login_calls[0])
    assert payload["user"] == "admin"
    assert payload["totp"].isdigit()
    assert len(payload["totp"]) == 6
