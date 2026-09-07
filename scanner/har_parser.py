"""
Módulo para el procesamiento y extracción de sesiones desde archivos HTTP Archive (.har).
Permite importar flujos de tráfico grabados en Chrome/Firefox DevTools para auditar
rutas autenticadas y reproducir tokens y cookies.
"""
import json
import logging
from typing import Any
from urllib.parse import urlparse

import requests

logger = logging.getLogger("VulnScanner.HAR")


class HARSessionParser:
    """
    Parsea archivos .har (HTTP Archive v1.2) para extraer:
    1. Cookies de sesión
    2. Cabeceras de autorización (Bearer tokens, API keys)
    3. Catálogo de URLs y APIs interceptadas durante la sesión de navegación.
    """

    def __init__(self, har_data: dict[str, Any]):
        self.har_data = har_data
        self.cookies: dict[str, str] = {}
        self.headers: dict[str, str] = {}
        self.discovered_urls: set[str] = set()
        self.api_endpoints: set[str] = set()
        self._parse()

    @classmethod
    def from_file(cls, filepath: str) -> "HARSessionParser":
        """Carga y parsea un archivo .har desde disco."""
        with open(filepath, encoding="utf-8", errors="ignore") as f:
            data = json.load(f)
        return cls(data)

    @classmethod
    def from_string(cls, content: str) -> "HARSessionParser":
        """Carga y parsea contenido HAR desde un string JSON."""
        data = json.loads(content)
        return cls(data)

    def _parse(self) -> None:
        """Extrae cookies, cabeceras de autorización y URLs de las entradas del HAR."""
        log = self.har_data.get("log", {})
        entries = log.get("entries", [])

        auth_headers_candidates = ["authorization", "x-auth-token", "x-api-key", "token", "apikey"]

        for entry in entries:
            req = entry.get("request", {})
            url = req.get("url")
            if not url or not url.startswith(("http://", "https://")):
                continue

            # Registrar URL descubierta
            clean_url = url.split("#")[0]
            self.discovered_urls.add(clean_url)

            # Clasificar si parece un endpoint de API
            parsed = urlparse(clean_url)
            if "/api/" in parsed.path.lower() or parsed.path.lower().startswith(("/v1/", "/v2/", "/graphql")):
                self.api_endpoints.add(clean_url)

            # Extraer Cookies de la petición
            req_cookies = req.get("cookies", [])
            for c in req_cookies:
                name = c.get("name")
                value = c.get("value")
                if name and value:
                    self.cookies[name] = value

            # Extraer Cabeceras de Autorización relevantes
            req_headers = req.get("headers", [])
            for h in req_headers:
                h_name = h.get("name", "").lower()
                h_val = h.get("value", "")
                if h_name in auth_headers_candidates and h_val:
                    if h_name == "authorization":
                        self.headers["Authorization"] = h_val
                    else:
                        self.headers[h.get("name")] = h_val

            # Extraer Cookies del Set-Cookie en la respuesta si existen
            resp = entry.get("response", {})
            resp_cookies = resp.get("cookies", [])
            for c in resp_cookies:
                name = c.get("name")
                value = c.get("value")
                if name and value:
                    self.cookies[name] = value

    def create_session(self) -> requests.Session:
        """
        Crea un objeto requests.Session preconfigurado con las cookies
        y cabeceras extraídas del HAR.
        """
        session = requests.Session()
        session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
        })

        if self.headers:
            session.headers.update(self.headers)
            logger.info("Cabeceras de autorización configuradas desde HAR: %s", list(self.headers.keys()))

        if self.cookies:
            for name, val in self.cookies.items():
                session.cookies.set(name, val)
            logger.info("Cookies de sesión configuradas desde HAR (%d cookies)", len(self.cookies))

        return session

    def get_summary(self) -> dict[str, Any]:
        """Retorna un resumen estructurado de los datos extraídos del HAR."""
        return {
            "total_urls": len(self.discovered_urls),
            "api_endpoints": list(self.api_endpoints),
            "cookies_count": len(self.cookies),
            "cookie_names": list(self.cookies.keys()),
            "auth_headers": list(self.headers.keys()),
        }
