"""
Módulo de autenticación avanzada para VulnScanner.
Soporta:
1. Login dinámico HTTP (Formularios HTML, APIs REST JSON, Token Bearer)
2. Login interactivo en navegador headless (Playwright / Chromium)
3. AuthSessionManager con manejo de sesiones y soporte para auto-refresh de tokens ante 401.
"""
import contextlib
import logging
from typing import Any, Callable, Optional

import requests

from utils.renderer import is_playwright_available

logger = logging.getLogger("VulnScanner.Auth")


def parse_credentials(credentials_str: str) -> dict[str, str]:
    """Parsea una cadena de credenciales 'key=val;key2=val2' a dict."""
    credentials = {}
    for pair in credentials_str.split(';'):
        pair = pair.strip()
        if '=' in pair:
            key, value = pair.split('=', 1)
            credentials[key.strip()] = value.strip()
    return credentials


def dynamic_login(
    login_url: str,
    credentials_str: str,
    totp_secret: Optional[str] = None,
) -> Optional[requests.Session]:
    """
    Realiza un inicio de sesión automático contra un endpoint web y retorna
    una sesión autenticada lista para usar en el escáner (con soporte opcional para TOTP/2FA).
    """
    credentials = parse_credentials(credentials_str)
    if not credentials:
        logger.warning("[AUTH] No se pudieron parsear las credenciales de login.")
        return None

    if totp_secret:
        with contextlib.suppress(Exception):
            from scanner.totp import generate_totp
            totp_val = generate_totp(totp_secret)
            credentials.setdefault("totp", totp_val)
            credentials.setdefault("otp", totp_val)
            credentials.setdefault("code", totp_val)
            credentials.setdefault("mfa_code", totp_val)
            logger.info("[AUTH] Código TOTP generado e incorporado a credenciales: %s", totp_val)

    session = requests.Session()
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36'
    })

    logger.info("[AUTH] Intentando login automático en: %s", login_url)
    logger.info("[AUTH] Campos de credenciales: %s", list(credentials.keys()))

    try:
        # Intento 1: Formulario estándar HTML (application/x-www-form-urlencoded)
        r = session.post(login_url, data=credentials, timeout=10, allow_redirects=True)

        if session.cookies:
            cookie_names = [c.name for c in session.cookies]
            logger.info("[OK] Login exitoso (formulario). Cookies: %s", cookie_names)
            return session

        # Intento 2: Respuesta JSON con token Bearer
        try:
            json_response = r.json()
            token = None
            for key in ['token', 'access_token', 'accessToken', 'jwt', 'id_token', 'authToken']:
                if key in json_response:
                    token = json_response[key]
                    break

            if token:
                session.headers.update({'Authorization': f'Bearer {token}'})
                logger.info("[OK] Login exitoso (API JSON). Token Bearer configurado.")
                return session
        except (ValueError, KeyError):
            pass

        # Intento 3: Payload JSON (application/json)
        session2 = requests.Session()
        session2.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Content-Type': 'application/json'
        })
        r2 = session2.post(login_url, json=credentials, timeout=10, allow_redirects=True)

        if session2.cookies:
            cookie_names = [c.name for c in session2.cookies]
            logger.info("[OK] Login exitoso (JSON body). Cookies: %s", cookie_names)
            return session2

        try:
            json_response2 = r2.json()
            token = None
            for key in ['token', 'access_token', 'accessToken', 'jwt', 'id_token', 'authToken']:
                if key in json_response2:
                    token = json_response2[key]
                    break
            if token:
                session2.headers.update({'Authorization': f'Bearer {token}'})
                logger.info("[OK] Login exitoso (API JSON body). Token Bearer configurado.")
                return session2
        except (ValueError, KeyError):
            pass

        logger.warning("[AUTH] No se pudo detectar autenticación exitosa (Status: %s).", r.status_code)
        return None

    except requests.exceptions.ConnectionError:
        logger.warning("[FAIL] Error de conexión al intentar login en: %s", login_url)
        return None
    except requests.exceptions.Timeout:
        logger.warning("[FAIL] Tiempo de espera agotado al intentar login en: %s", login_url)
        return None


def headless_browser_login(
    login_page_url: str,
    credentials_str: str,
    username_selector: Optional[str] = None,
    password_selector: Optional[str] = None,
    submit_selector: Optional[str] = None,
    totp_secret: Optional[str] = None,
    timeout: int = 15000,
) -> Optional[requests.Session]:
    """
    Realiza un login simulando un usuario en un navegador Chromium real (Playwright).
    Rellena los inputs de usuario/contraseña, hace clic en el botón de submit,
    gestiona el segundo factor 2FA/TOTP si se especifica, y extrae cookies de sesión
    y tokens Bearer de almacenamiento local (localStorage).
    """
    if not is_playwright_available():
        logger.warning("Playwright no disponible para login headless. Intentando login HTTP clásico.")
        return dynamic_login(login_page_url, credentials_str, totp_secret=totp_secret)

    creds = parse_credentials(credentials_str)
    if not creds:
        return None

    # Identificar posibles claves de usuario y contraseña
    username_val = creds.get("username") or creds.get("user") or creds.get("email") or next(iter(creds.values()), "")
    password_val = creds.get("password") or creds.get("pass") or creds.get("pwd") or ""

    try:
        from playwright.sync_api import sync_playwright

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context()
            page = context.new_page()

            logger.info("[AUTH-HEADLESS] Navegando a formulario de login: %s", login_page_url)
            page.goto(login_page_url, timeout=timeout, wait_until="domcontentloaded")

            # Localizar input de usuario
            user_sel = username_selector or "input[type='text'], input[type='email'], input[name*='user'], input[name*='mail'], input[id*='user'], input[id*='mail']"
            page.wait_for_selector(user_sel, timeout=5000)
            page.fill(user_sel, username_val)

            # Localizar input de password
            pass_sel = password_selector or "input[type='password'], input[name*='pass'], input[id*='pass']"
            page.wait_for_selector(pass_sel, timeout=5000)
            page.fill(pass_sel, password_val)

            # Click en Submit / Botón de inicio de sesión
            sub_sel = submit_selector or "button[type='submit'], input[type='submit'], button:has-text('Log in'), button:has-text('Iniciar sesión'), button:has-text('Sign in')"
            try:
                page.click(sub_sel, timeout=3000)
            except Exception:
                page.keyboard.press("Enter")

            # Esperar navegación post-login
            with contextlib.suppress(Exception):
                page.wait_for_load_state("networkidle", timeout=5000)

            # Si se proveyó clave secreta TOTP / 2FA, verificar si la página solicita código
            if totp_secret:
                from scanner.totp import generate_totp
                totp_sel = (
                    "input[name*='totp'], input[name*='otp'], input[name*='mfa'], "
                    "input[name*='2fa'], input[name*='code'], input[placeholder*='6'], "
                    "input[autocomplete='one-time-code'], input[id*='totp'], input[id*='otp'], input[id*='code']"
                )
                with contextlib.suppress(Exception):
                    otp_el = page.wait_for_selector(totp_sel, timeout=4000)
                    if otp_el and otp_el.is_visible():
                        code = generate_totp(totp_secret)
                        logger.info("[AUTH-HEADLESS] Pantalla 2FA/TOTP detectada. Inyectando código calculado: %s", code)
                        otp_el.fill(code)
                        page.keyboard.press("Enter")
                        with contextlib.suppress(Exception):
                            page.wait_for_load_state("networkidle", timeout=5000)

            # Extraer cookies del contexto del navegador
            browser_cookies = context.cookies()

            # Extraer posibles tokens JWT / Bearer de localStorage (común en SPAs)
            bearer_token: Optional[str] = None
            with contextlib.suppress(Exception):
                tokens_dict = page.evaluate("""() => {
                    const res = {};
                    for (let i = 0; i < localStorage.length; i++) {
                        const k = localStorage.key(i);
                        if (k && /token|jwt|auth|access/i.test(k)) {
                            res[k] = localStorage.getItem(k);
                        }
                    }
                    return res;
                }""")
                if isinstance(tokens_dict, dict):
                    for val in tokens_dict.values():
                        if isinstance(val, str) and (len(val) > 20 or val.startswith("eyJ")):
                            bearer_token = val
                            break

            browser.close()

            if browser_cookies or bearer_token:
                session = requests.Session()
                for c in browser_cookies:
                    session.cookies.set(c["name"], c["value"], domain=c.get("domain", ""), path=c.get("path", "/"))
                if bearer_token:
                    session.headers["Authorization"] = f"Bearer {bearer_token}"
                    logger.info("[AUTH-HEADLESS] Token Bearer recuperado de localStorage y persistido.")
                logger.info("[AUTH-HEADLESS] Login exitoso. Extraídas %d cookies.", len(browser_cookies))
                return session

    except Exception as e:
        logger.warning("[AUTH-HEADLESS] Error durante login headless: %s", e)

    return None


class AuthSessionManager:
    """
    Gestor inteligente de sesión HTTP para el escáner.
    Mantiene el estado de autenticación, detecta tokens expirados (401 Unauthorized)
    y ejecuta callbacks de refresco de credenciales automáticamente.
    """

    def __init__(
        self,
        session: Optional[requests.Session] = None,
        refresh_callback: Optional[Callable[[], Optional[requests.Session]]] = None,
        auth_header_template: Optional[str] = None
    ):
        self.session = session or requests.Session()
        self.refresh_callback = refresh_callback
        self.auth_header_template = auth_header_template
        has_cookies = bool(getattr(self.session, 'cookies', None))
        headers = getattr(self.session, 'headers', {})
        has_auth = "Authorization" in headers if hasattr(headers, "__contains__") else False
        self.is_authenticated = has_cookies or has_auth

    def request(self, method: str, url: str, **kwargs: Any) -> requests.Response:
        """Envía una petición HTTP con manejo automático de 401 Unauthorized."""
        response = self.session.request(method, url, **kwargs)

        if response.status_code == 401 and self.refresh_callback:
            logger.info("[AUTH-MANAGER] Recibido 401 Unauthorized. Intentando refresco de sesión...")
            new_session = self.refresh_callback()
            if new_session:
                self.session = new_session
                self.is_authenticated = True
                # Reintentar la petición original con la sesión renovada
                return self.session.request(method, url, **kwargs)

        return response

    def get(self, url: str, **kwargs: Any) -> requests.Response:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> requests.Response:
        return self.request("POST", url, **kwargs)
