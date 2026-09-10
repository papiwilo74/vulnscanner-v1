import sqlite3
import subprocess  # nosec B404
from typing import Any, cast

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from scanner.engine import ScanConfig, ScanEngine
from scanner.iast_agent import HookManager, IASTTelemetry, VulnScannerASGI
from scanner.models import Finding


def dummy_vuln_app() -> Starlette:
    """Aplicación web intencionalmente vulnerable para pruebas de IAST/RASP."""
    async def query_user(request: Request) -> JSONResponse:
        username = request.query_params.get("user", "")
        # Simular consulta SQL insegura
        conn = sqlite3.connect(":memory:")
        cursor = conn.cursor()
        cursor.execute("CREATE TABLE users (id INT, name TEXT)")
        # Llamada al sink vulnerable
        query = f"SELECT * FROM users WHERE name = '{username}'"
        cursor.execute(query)
        return JSONResponse({"status": "ok", "query": query})

    async def run_ping(request: Request) -> JSONResponse:
        host = request.query_params.get("host", "127.0.0.1")
        # Simular inyección de comando OS
        cmd = f"ping -c 1 {host}"
        # Se invoca Popen
        proc = subprocess.Popen(cmd, shell=True)  # nosec B602
        return JSONResponse({"status": "executed", "pid": proc.pid})

    routes = [
        Route("/user", query_user),
        Route("/ping", run_ping),
    ]
    return Starlette(routes=routes)


class TestIASTRASP:
    def teardown_method(self) -> None:
        """Asegurar que los hooks se desinstalen después de cada test."""
        manager = HookManager(on_sink_event=lambda t: True)
        manager.uninstall_hooks()

    def test_hook_manager_install_and_uninstall(self) -> None:
        events: list[IASTTelemetry] = []

        def _record_event(t: IASTTelemetry) -> bool:
            events.append(t)
            return True

        manager = HookManager(on_sink_event=_record_event)
        manager.install_hooks()

        conn = sqlite3.connect(":memory:")
        cursor = conn.cursor()
        cursor.execute("CREATE TABLE t (x INT)")
        # Ejecutar consulta con patrón SQLi
        cursor.execute("SELECT * FROM t WHERE x = 1 OR '1'='1'")

        assert len(events) >= 1
        assert events[0].sink_type == "sql"
        assert "test_iast_rasp.py" in events[0].source_file
        assert events[0].source_line > 0

        manager.uninstall_hooks()

    def test_iast_monitor_mode_telemetry_endpoint(self) -> None:
        raw_app = dummy_vuln_app()
        # Envolver en middleware ASGI en modo monitor (IAST)
        app = VulnScannerASGI(raw_app, mode="monitor")
        client = TestClient(cast(Any, app))

        # Enviar petición con inyección SQL
        resp = client.get("/user?user=admin' OR 1=1--", headers={"x-vulnscanner-correlation-id": "test-cid-123"})
        assert resp.status_code == 200
        assert resp.headers.get("x-vulnscanner-iast") == "active"
        assert resp.headers.get("x-vulnscanner-rasp-mode") == "monitor"

        # Consultar endpoint nativo de telemetría IAST
        telemetry_resp = client.get("/__vulnscanner_iast__?cid=test-cid-123")
        assert telemetry_resp.status_code == 200
        data = telemetry_resp.json()
        assert data["count"] >= 1
        event = data["telemetry"][0]
        assert event["sink_type"] == "sql"
        assert "test_iast_rasp.py" in event["source_file"]
        assert event["correlation_id"] == "test-cid-123"

        app.hook_manager.uninstall_hooks()

    def test_rasp_protect_mode_blocks_attack(self) -> None:
        raw_app = dummy_vuln_app()
        # Envolver en middleware ASGI en modo protect (RASP Activo)
        app = VulnScannerASGI(raw_app, mode="protect")
        client = TestClient(cast(Any, app))

        # Enviar ataque SQLi
        resp = client.get("/user?user=admin' OR '1'='1", headers={"x-vulnscanner-correlation-id": "attack-1"})
        # RASP debe interceptar en memoria y retornar 403 Forbidden
        assert resp.status_code == 403
        assert resp.headers.get("x-protection-by") == "VulnScanner-RASP"
        assert resp.headers.get("x-vulnscanner-rasp-mode") == "protect"

        body = resp.json()
        assert "Forbidden by VulnScanner RASP" in body["error"]
        assert body["sink"] == "sql"
        assert "test_iast_rasp.py" in body["source_file"]

        app.hook_manager.uninstall_hooks()

    def test_correlate_iast_with_engine(self, monkeypatch: Any) -> None:
        # Simular endpoint IAST en ScanEngine
        class MockResponse:
            status_code = 200
            def json(self) -> dict[str, Any]:
                return {
                    "telemetry": [
                        {
                            "sink_type": "sql",
                            "source_file": "app/views/user.py",
                            "source_line": 42,
                            "call_stack": ["app/views/user.py:42 in get_user"],
                            "blocked_by_rasp": False,
                        }
                    ]
                }

        class MockSession:
            def get(self, url: str, timeout: int = 5) -> MockResponse:
                return MockResponse()

        config = ScanConfig(target="http://testserver", iast_url="http://testserver")
        engine = ScanEngine(config)

        finding = Finding(
            category="sqli",
            title="SQL Injection en 'user'",
            severity="high",
            affected_url="http://testserver/user",
        )

        enriched = engine.correlate_iast([finding], session=cast(Any, MockSession()))
        assert enriched == 1
        assert finding.iast_source_file == "app/views/user.py"
        assert finding.iast_source_line == 42
        assert finding.confidence == "certain"
