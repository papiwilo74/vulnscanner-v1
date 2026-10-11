"""
Pruebas exhaustivas para el Middleware Universal IAST/RASP (ASGI & WSGI) y Correlador DAST de OmniBreach.
"""
import io
import json
import os
import sqlite3
import unittest
from typing import Any, Callable
from unittest.mock import MagicMock

from scanner.iast_agent import (
    HookManager,
    IASTCorrelator,
    IASTTelemetry,
    OmniBreachIASTMiddleware,
    VulnScannerASGI,
    VulnScannerWSGI,
)
from scanner.models import Finding


def dummy_wsgi_app(environ: dict[str, Any], start_response: Callable[..., Any]) -> list[bytes]:
    """Aplicación WSGI nativa intencionalmente vulnerable para pruebas."""
    path = environ.get("PATH_INFO", "")
    if path == "/search":
        qs = environ.get("QUERY_STRING", "")
        term = qs.split("q=")[1] if "q=" in qs else "default"
        # Llamada vulnerable a SQLite
        conn = sqlite3.connect(":memory:")
        c = conn.cursor()
        c.execute("CREATE TABLE products (name TEXT)")
        c.execute(f"SELECT * FROM products WHERE name = '{term}'")
        start_response("200 OK", [("Content-Type", "application/json")])
        return [b'{"status": "ok"}']
    elif path == "/cmd":
        # Llamada vulnerable a os.system
        os.system("whoami")  # nosec B605 B607
        start_response("200 OK", [("Content-Type", "text/plain")])
        return [b"executed"]

    start_response("404 Not Found", [("Content-Type", "text/plain")])
    return [b"Not Found"]


class TestIASTUniversalMiddleware(unittest.TestCase):
    """Pruebas de compatibilidad WSGI, detección automática ASGI/WSGI y correlación DAST."""

    def tearDown(self) -> None:
        """Desinstalar hooks del agente después de cada prueba."""
        mgr = HookManager(on_sink_event=lambda t: True)
        mgr.uninstall_hooks()

    def test_wsgi_iast_monitor_mode(self) -> None:
        """Valida que el middleware WSGI capture telemetría SQL y exponga endpoint de telemetría."""
        app = VulnScannerWSGI(dummy_wsgi_app, mode="monitor")

        # 1. Ejecutar petición con ataque SQLi
        captured_headers: dict[str, str] = {}

        def mock_start_response(status: str, headers: list[tuple[str, str]], exc_info: Any = None) -> None:
            for k, v in headers:
                captured_headers[k.lower()] = v

        environ = {
            "REQUEST_METHOD": "GET",
            "PATH_INFO": "/search",
            "QUERY_STRING": "q=test' OR '1'='1",
            "HTTP_X_VULNSCANNER_CORRELATION_ID": "wsgi-trace-999",
            "wsgi.input": io.BytesIO(),
        }

        body = app(environ, mock_start_response)
        self.assertEqual(body, [b'{"status": "ok"}'])
        self.assertEqual(captured_headers.get("x-vulnscanner-iast"), "active")
        self.assertEqual(captured_headers.get("x-vulnscanner-rasp-mode"), "monitor")

        # 2. Consultar telemetría
        telemetry_headers: dict[str, str] = {}

        def mock_telemetry_sr(status: str, headers: list[tuple[str, str]], exc_info: Any = None) -> None:
            for k, v in headers:
                telemetry_headers[k.lower()] = v

        telemetry_environ = {
            "REQUEST_METHOD": "GET",
            "PATH_INFO": "/__vulnscanner_iast__",
            "QUERY_STRING": "cid=wsgi-trace-999",
            "wsgi.input": io.BytesIO(),
        }

        resp_body = app(telemetry_environ, mock_telemetry_sr)
        data = json.loads(resp_body[0].decode("utf-8"))
        self.assertGreaterEqual(data["count"], 1)
        event = data["telemetry"][0]
        self.assertEqual(event["sink_type"], "sql")
        self.assertIn("test_iast_universal_middleware.py", event["source_file"])
        self.assertGreater(event["source_line"], 0)
        self.assertEqual(event["correlation_id"], "wsgi-trace-999")

    def test_wsgi_rasp_protect_mode_blocks(self) -> None:
        """Valida que en modo protect el middleware WSGI bloquee el ataque con HTTP 403."""
        app = VulnScannerWSGI(dummy_wsgi_app, mode="protect")

        status_code = ""
        captured_headers: dict[str, str] = {}

        def mock_start_response(status: str, headers: list[tuple[str, str]], exc_info: Any = None) -> None:
            nonlocal status_code
            status_code = status
            for k, v in headers:
                captured_headers[k.lower()] = v

        environ = {
            "REQUEST_METHOD": "GET",
            "PATH_INFO": "/search",
            "QUERY_STRING": "q=admin' OR 1=1--",
            "wsgi.input": io.BytesIO(),
        }

        body = app(environ, mock_start_response)
        self.assertIn("403", status_code)
        self.assertEqual(captured_headers.get("x-protection-by"), "VulnScanner-RASP")
        resp_data = json.loads(body[0].decode("utf-8"))
        self.assertEqual(resp_data["sink"], "sql")
        self.assertIn("Forbidden by VulnScanner RASP", resp_data["error"])

    def test_factory_autodetection(self) -> None:
        """Valida que OmniBreachIASTMiddleware detecte automáticamente apps WSGI vs ASGI."""
        # WSGI App (recibe 2 argumentos)
        wsgi_instance = OmniBreachIASTMiddleware(dummy_wsgi_app, mode="monitor")
        self.assertIsInstance(wsgi_instance, VulnScannerWSGI)

        # ASGI App dummy (recibe 3 argumentos: scope, receive, send)
        async def dummy_asgi(scope: Any, receive: Any, send: Any) -> None:
            pass

        asgi_instance = OmniBreachIASTMiddleware(dummy_asgi, mode="monitor")
        self.assertIsInstance(asgi_instance, VulnScannerASGI)

    def test_eval_code_injection_hook(self) -> None:
        """Valida que HookManager intercepte inyecciones de código hacia eval()."""
        events: list[IASTTelemetry] = []
        mgr = HookManager(on_sink_event=lambda t: (events.append(t), True)[1])
        mgr.install_hooks()

        # Invocar eval sospechoso
        eval("__import__('os').system('id')")  # nosec B307

        self.assertGreaterEqual(len(events), 1)
        eval_events = [e for e in events if e.sink_type == "eval"]
        self.assertGreaterEqual(len(eval_events), 1)
        self.assertIn("test_iast_universal_middleware.py", eval_events[0].source_file)
        self.assertGreater(eval_events[0].source_line, 0)

    def test_iast_correlator_enriches_finding(self) -> None:
        """Valida que IASTCorrelator enriquezca los hallazgos DAST con evidencia forense in-memory."""
        mock_session = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "telemetry": [
                {
                    "sink_type": "sql",
                    "source_file": "app/routes/users.py",
                    "source_line": 84,
                    "function_name": "get_user",
                }
            ]
        }
        mock_session.get.return_value = mock_resp

        correlator = IASTCorrelator(session=mock_session)

        base_finding = Finding(
            category="sqli",
            title="Posible Inyección SQL detectada en /api/users",
            severity="high",
            confidence="possible",
            description="La respuesta HTTP reflejó un error de sintaxis SQL.",
            affected_url="http://target.local/api/users?id=1'",
        )

        enriched = correlator.check_and_correlate(
            base_url="http://target.local",
            correlation_id="trace-abc-123",
            finding=base_finding,
        )

        self.assertEqual(enriched.confidence, "confirmed")
        self.assertEqual(enriched.iast_source_file, "app/routes/users.py")
        self.assertEqual(enriched.iast_source_line, 84)
        self.assertIn("[IAST CONFIRMADO EN TIEMPO DE EJECUCIÓN]", enriched.description)
        self.assertIn("app/routes/users.py", enriched.description)
        self.assertIn("84", enriched.description)


if __name__ == "__main__":
    unittest.main()
