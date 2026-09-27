"""
Proxy Interceptor Pasivo Integrado para Captura de Flujos y Mapeo de QA (ProxyCaptureServer).

Permite a OmniBreach actuar como un proxy HTTP intermedio local para interceptar el tráfico
de pruebas manuales, navegadores o suites automatizadas (Selenium, Cypress, Playwright, cURL),
extrayendo endpoints, parámetros, cookies y tokens para alimentar las auditorías de seguridad.
Exporta directamente a formato estándar HTTP Archive (HAR 1.2) o genera sesiones autenticadas.
"""
from __future__ import annotations

import json
import logging
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
from typing import Any
from urllib.parse import urlparse

import requests

logger = logging.getLogger("VulnScanner.ProxyCapture")


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Servidor HTTP multihilo para atender peticiones concurrentes del proxy."""
    daemon_threads = True
    allow_reuse_address = True
    proxy_instance: ProxyCaptureServer | None = None


class ProxyRequestHandler(BaseHTTPRequestHandler):
    """Manejador de peticiones del proxy que registra y reenvía tráfico HTTP."""

    server: ThreadedHTTPServer  # Para tipado

    def log_message(self, format: str, *args: Any) -> None:
        """Silenciar logs estándar de BaseHTTPRequestHandler en consola."""
        pass

    def _capture_and_forward(self, method: str) -> None:
        proxy_server: ProxyCaptureServer | None = getattr(self.server, "proxy_instance", None)
        start_time = time.time()

        # Determinar URL de destino
        req_url = self.path
        if not req_url.startswith(("http://", "https://")):
            host_header = self.headers.get("Host", "localhost")
            req_url = f"http://{host_header}{self.path}"

        parsed = urlparse(req_url)

        # Leer cuerpo de la petición si existe
        content_len = int(self.headers.get("Content-Length", 0))
        req_body = self.rfile.read(content_len) if content_len > 0 else b""

        headers_dict = {k: v for k, v in self.headers.items()}
        # Eliminar cabeceras hop-by-hop para reenvío limpio
        headers_to_forward = {
            k: v for k, v in headers_dict.items()
            if k.lower() not in ("proxy-connection", "proxy-authorization", "transfer-encoding")
        }

        resp_status = 200
        resp_headers: dict[str, str] = {}
        resp_body = b""

        # Reenviar petición hacia el destino real si el proxy está en modo reenvío
        if proxy_server and proxy_server.forward_traffic and parsed.netloc:
            try:
                upstream_resp = requests.request(
                    method=method,
                    url=req_url,
                    headers=headers_to_forward,
                    data=req_body,
                    timeout=10,
                    allow_redirects=False,
                )
                resp_status = upstream_resp.status_code
                resp_headers = dict(upstream_resp.headers)
                resp_body = upstream_resp.content
            except Exception as e:
                resp_status = 502
                resp_body = f"Proxy Bad Gateway: {e}".encode()
        else:
            # Modo pasivo / respuesta simulada rápida
            resp_body = b'{"status": "captured_by_omnibreach_proxy"}'
            resp_headers = {"Content-Type": "application/json"}

        duration_ms = round((time.time() - start_time) * 1000, 2)

        # Registrar la transacción capturada
        flow_entry = {
            "id": f"flow-{len(proxy_server.flows) + 1 if proxy_server else 1}",
            "timestamp": time.time(),
            "method": method,
            "url": req_url,
            "path": parsed.path or "/",
            "query": parsed.query,
            "request_headers": headers_dict,
            "request_body": req_body.decode("utf-8", errors="replace"),
            "response_status": resp_status,
            "response_headers": resp_headers,
            "response_body": resp_body.decode("utf-8", errors="replace")[:10000],
            "duration_ms": duration_ms,
        }

        if proxy_server:
            proxy_server.record_flow(flow_entry)

        # Responder al cliente HTTP local
        try:
            self.send_response(resp_status)
            for hk, hv in resp_headers.items():
                if hk.lower() not in ("content-length", "transfer-encoding", "content-encoding"):
                    self.send_header(hk, hv)
            self.send_header("Content-Length", str(len(resp_body)))
            self.end_headers()
            self.wfile.write(resp_body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_GET(self) -> None:
        self._capture_and_forward("GET")

    def do_POST(self) -> None:
        self._capture_and_forward("POST")

    def do_PUT(self) -> None:
        self._capture_and_forward("PUT")

    def do_DELETE(self) -> None:
        self._capture_and_forward("DELETE")

    def do_OPTIONS(self) -> None:
        self._capture_and_forward("OPTIONS")

    def do_PATCH(self) -> None:
        self._capture_and_forward("PATCH")

    def do_CONNECT(self) -> None:
        """Soporte básico de túnel CONNECT para HTTPS."""
        self.send_response(200, "Connection Established")
        self.end_headers()
        # En túnel CONNECT sin descifrado SSL, registrar el host y cerrar
        proxy_server: ProxyCaptureServer | None = getattr(self.server, "proxy_instance", None)
        if proxy_server:
            proxy_server.record_flow({
                "id": f"flow-{len(proxy_server.flows) + 1}",
                "timestamp": time.time(),
                "method": "CONNECT",
                "url": f"https://{self.path}",
                "path": "/",
                "query": "",
                "request_headers": dict(self.headers),
                "request_body": "",
                "response_status": 200,
                "response_headers": {},
                "response_body": "",
                "duration_ms": 0.0,
            })


class ProxyCaptureServer:
    """
    Controlador y orquestador del servidor proxy intermedio de OmniBreach.
    Captura tráfico en segundo plano, extrae activos y exporta a formato HAR 1.2.
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 8089, forward_traffic: bool = True):
        self.host = host
        self.port = port
        self.forward_traffic = forward_traffic
        self.flows: list[dict[str, Any]] = []
        self._lock = threading.Lock()
        self._server: ThreadedHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self.is_running = False

    def record_flow(self, flow: dict[str, Any]) -> None:
        """Registra un flujo capturado con exclusión mutua segura para hilos."""
        with self._lock:
            self.flows.append(flow)

    def start(self) -> None:
        """Inicia el servidor proxy en un hilo daemon en segundo plano."""
        if self.is_running:
            return

        self._server = ThreadedHTTPServer((self.host, self.port), ProxyRequestHandler)
        self._server.proxy_instance = self
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        self.is_running = True
        logger.info("[PROXY] Servidor de captura iniciado en http://%s:%d", self.host, self.port)

    def stop(self) -> None:
        """Detiene el servidor proxy y libera el puerto de red."""
        if not self.is_running or not self._server:
            return
        self._server.shutdown()
        self._server.server_close()
        self.is_running = False
        logger.info("[PROXY] Servidor de captura detenido. Total flujos: %d", len(self.flows))

    def clear(self) -> None:
        """Limpia los flujos capturados."""
        with self._lock:
            self.flows.clear()

    def get_captured_endpoints(self) -> list[str]:
        """Retorna una lista ordenada y sin duplicados de todas las URLs completas interceptadas."""
        with self._lock:
            endpoints = {
                f["url"] for f in self.flows
                if f["url"].startswith(("http://", "https://")) and f["method"] != "CONNECT"
            }
            return sorted(endpoints)

    def get_session_cookies(self) -> dict[str, str]:
        """Extrae cookies de sesión consolidadas a partir de cabeceras Cookie y Set-Cookie."""
        cookies: dict[str, str] = {}
        with self._lock:
            for f in self.flows:
                # 1. Cabeceras Cookie enviadas por el cliente
                req_cookie = f.get("request_headers", {}).get("Cookie") or f.get("request_headers", {}).get("cookie")
                if req_cookie:
                    for part in req_cookie.split(";"):
                        if "=" in part:
                            k, v = part.strip().split("=", 1)
                            cookies[k.strip()] = v.strip()
                # 2. Cabeceras Set-Cookie devueltas por el servidor
                resp_cookie = f.get("response_headers", {}).get("Set-Cookie") or f.get("response_headers", {}).get("set-cookie")
                if resp_cookie:
                    part = resp_cookie.split(";")[0]
                    if "=" in part:
                        k, v = part.strip().split("=", 1)
                        cookies[k.strip()] = v.strip()
        return cookies

    def get_auth_headers(self) -> dict[str, str]:
        """Extrae cabeceras de autorización (Authorization, API keys) observadas en el tráfico."""
        auth_headers: dict[str, str] = {}
        target_keys = ["authorization", "x-api-key", "x-auth-token", "apikey"]
        with self._lock:
            for f in self.flows:
                for k, v in f.get("request_headers", {}).items():
                    if k.lower() in target_keys:
                        auth_headers[k] = v
        return auth_headers

    def create_authenticated_session(self) -> requests.Session:
        """Construye un objeto requests.Session con las cookies y credenciales interceptadas."""
        session = requests.Session()
        session.headers.update(self.get_auth_headers())
        for k, v in self.get_session_cookies().items():
            session.cookies.set(k, v)
        return session

    def export_har(self) -> dict[str, Any]:
        """Exporta todos los flujos interceptados a formato estándar HTTP Archive (HAR 1.2)."""
        with self._lock:
            entries: list[dict[str, Any]] = []
            for f in self.flows:
                req_headers_list = [{"name": k, "value": v} for k, v in f.get("request_headers", {}).items()]
                resp_headers_list = [{"name": k, "value": v} for k, v in f.get("response_headers", {}).items()]

                entry: dict[str, Any] = {
                    "startedDateTime": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(f["timestamp"])),
                    "time": f["duration_ms"],
                    "request": {
                        "method": f["method"],
                        "url": f["url"],
                        "httpVersion": "HTTP/1.1",
                        "cookies": [],
                        "headers": req_headers_list,
                        "queryString": [],
                        "postData": {"mimeType": "application/json", "text": f.get("request_body", "")},
                        "headersSize": -1,
                        "bodySize": len(f.get("request_body", "").encode()),
                    },
                    "response": {
                        "status": f["response_status"],
                        "statusText": "OK" if f["response_status"] == 200 else "Response",
                        "httpVersion": "HTTP/1.1",
                        "cookies": [],
                        "headers": resp_headers_list,
                        "content": {
                            "size": len(f.get("response_body", "").encode()),
                            "mimeType": f.get("response_headers", {}).get("Content-Type", "text/plain"),
                            "text": f.get("response_body", ""),
                        },
                        "redirectURL": "",
                        "headersSize": -1,
                        "bodySize": len(f.get("response_body", "").encode()),
                    },
                    "cache": {},
                    "timings": {"send": 0, "wait": f["duration_ms"], "receive": 0},
                }
                entries.append(entry)

            return {
                "log": {
                    "version": "1.2",
                    "creator": {"name": "OmniBreach Proxy Capture", "version": "2.0"},
                    "pages": [],
                    "entries": entries,
                }
            }

    def save_har(self, filepath: str) -> None:
        """Guarda la sesión de captura como archivo HAR en disco."""
        har_data = self.export_har()
        with open(filepath, "w", encoding="utf-8") as file:
            json.dump(har_data, file, indent=2, ensure_ascii=False)
