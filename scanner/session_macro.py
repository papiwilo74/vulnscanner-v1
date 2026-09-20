"""
Módulo de Gestión de Sesiones de Negocio y Re-autenticación en Caliente (State-Aware Session Manager).
Permite ejecutar macros de autenticación (HTTP o Playwright) y monitorear endpoints centinela
para re-autenticar la sesión automáticamente cuando expira durante un escaneo prolongado.
"""
from __future__ import annotations

import contextlib
import logging
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

import requests

from utils.renderer import is_playwright_available

logger = logging.getLogger("VulnScanner.SessionMacro")


@dataclass
class MacroStep:
    """Representa una acción individual dentro del flujo de autenticación."""
    action: str  # "goto", "fill", "click", "wait_ms", "http_post", "extract_cookies", "set_header"
    url: str | None = None
    selector: str | None = None
    value: str | None = None
    headers: dict[str, str] = field(default_factory=dict)
    data: dict[str, Any] = field(default_factory=dict)
    json_data: dict[str, Any] = field(default_factory=dict)


@dataclass
class SessionMacro:
    """Define una secuencia de pasos para autenticarse y verificar la vigencia de la sesión."""
    name: str = "default_macro"
    steps: list[MacroStep] = field(default_factory=list)
    sentinel_url: str | None = None
    sentinel_expected_status: int = 200
    login_redirect_patterns: list[str] = field(
        default_factory=lambda: ["/login", "/auth", "/signin", "/account/login"]
    )
    headers_to_persist: dict[str, str] = field(default_factory=dict)


class StateAwareSessionManager:
    """
    Supervisa la salud de la sesión durante el escaneo y ejecuta re-autenticación
    transparente si el servidor invalida el token o expira la cookie.
    """

    def __init__(
        self,
        macro: SessionMacro | None = None,
        session: requests.Session | None = None,
        check_interval: int = 20,
    ):
        self.macro = macro
        self.session = session if session is not None else requests.Session()
        self.check_interval = check_interval
        self._request_counter = 0
        self.reauth_count = 0

    def is_session_alive(self, session: requests.Session | None = None) -> bool:
        """
        Consulta el endpoint centinela (sentinel_url) para verificar si la sesión sigue activa.
        Retorna False si el servidor devuelve 401, 403 o redirige a la pantalla de login.
        """
        if not self.macro or not self.macro.sentinel_url:
            return True

        client = session if session is not None else self.session
        try:
            r = client.get(
                self.macro.sentinel_url,
                timeout=5,
                allow_redirects=True,
            )

            # 1. Comprobar código de estado HTTP
            if r.status_code != self.macro.sentinel_expected_status:
                logger.warning(
                    "Sesión caducada: Centinela devolvió HTTP %s (esperado: %s)",
                    r.status_code,
                    self.macro.sentinel_expected_status,
                )
                return False

            # 2. Comprobar redirección a pantallas de login
            final_path = urlparse(r.url).path.lower()
            if any(pattern in final_path for pattern in self.macro.login_redirect_patterns):
                logger.warning("Sesión caducada: Redirección detectada a '%s'", final_path)
                return False

            return True
        except requests.RequestException as e:
            logger.debug("Error al consultar centinela de sesión: %s", e)
            return False

    def execute_macro(self, session: requests.Session | None = None) -> bool:
        """
        Ejecuta los pasos de autenticación del macro para obtener cookies/tokens válidos.
        Soporta tanto acciones HTTP puras como automatización con Playwright para SPAs.
        """
        if not self.macro or not self.macro.steps:
            return False

        target_session = session if session is not None else self.session
        has_browser_step = any(s.action in ["fill", "click", "wait_for_selector"] for s in self.macro.steps)

        if has_browser_step and is_playwright_available():
            return self._execute_playwright_macro(target_session)

        return self._execute_http_macro(target_session)

    def _execute_http_macro(self, target_session: requests.Session) -> bool:
        """Ejecuta pasos de macro basados exclusivamente en peticiones HTTP."""
        if self.macro is None:
            return False
        try:
            for step in self.macro.steps:
                if step.action == "goto" and step.url:
                    target_session.get(step.url, headers=step.headers, timeout=8)
                elif step.action == "http_post" and step.url:
                    if step.json_data:
                        r = target_session.post(step.url, json=step.json_data, headers=step.headers, timeout=8)
                    else:
                        r = target_session.post(step.url, data=step.data, headers=step.headers, timeout=8)

                    # Si el paso de login devolvió un token Bearer en JSON
                    with contextlib.suppress(Exception):
                        data = r.json()
                        token = data.get("token") or data.get("access_token") or data.get("jwt")
                        if token:
                            target_session.headers["Authorization"] = f"Bearer {token}"
                elif step.action == "set_header" and step.selector and step.value:
                    target_session.headers[step.selector] = step.value

            # Persistir cabeceras fijas adicionales
            for k, v in self.macro.headers_to_persist.items():
                target_session.headers[k] = v

            self.reauth_count += 1
            return True
        except requests.RequestException as e:
            logger.error("Error al ejecutar macro HTTP: %s", e)
            return False

    def _execute_playwright_macro(self, target_session: requests.Session) -> bool:
        """Ejecuta pasos de macro interactuando con un navegador headless (Playwright)."""
        if self.macro is None:
            return False
        try:
            from playwright.sync_api import sync_playwright

            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                context = browser.new_context()
                page = context.new_page()

                for step in self.macro.steps:
                    if step.action == "goto" and step.url:
                        page.goto(step.url, timeout=15000, wait_until="domcontentloaded")
                    elif step.action == "fill" and step.selector and step.value is not None:
                        page.fill(step.selector, step.value)
                    elif step.action == "click" and step.selector:
                        page.click(step.selector)
                    elif step.action == "wait_ms" and step.value:
                        page.wait_for_timeout(float(step.value))

                # Extraer cookies del navegador hacia requests.Session
                cookies = context.cookies()
                for c in cookies:
                    target_session.cookies.set(
                        c["name"],
                        c["value"],
                        domain=c.get("domain", ""),
                        path=c.get("path", "/"),
                    )

                # Persistir cabeceras fijas adicionales
                for k, v in self.macro.headers_to_persist.items():
                    target_session.headers[k] = v

                browser.close()

            self.reauth_count += 1
            return True
        except Exception as e:
            logger.error("Error al ejecutar macro Playwright: %s", e)
            return False

    def ensure_session_alive(self, session: requests.Session | None = None) -> bool:
        """
        Verifica periódicamente la sesión. Si caducó, dispara la re-autenticación en caliente.
        """
        self._request_counter += 1
        if self._request_counter >= self.check_interval or self._request_counter == 1:
            self._request_counter = 1
            if not self.is_session_alive(session):
                logger.info("Detectada expiración de sesión. Iniciando re-autenticación...")
                return self.execute_macro(session)
        return True
