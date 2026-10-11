"""
Pruebas exhaustivas para el motor de escaneo diferencial quirúrgico por Git Diff (CI/CD Quality Gate).
"""
import unittest
from unittest.mock import MagicMock, patch

from scanner.git_diff_scanner import (
    GitDiffAnalyzer,
    IncrementalScanResult,
    ModifiedRoute,
    SurgicalIncrementalScanner,
    format_github_pr_comment,
)
from scanner.models import Finding


class TestGitDiffScanner(unittest.TestCase):
    """Pruebas unitarias para el analizador de diff, extractor de rutas y despachador quirúrgico."""

    def test_parse_diff_text(self) -> None:
        raw_diff = """
diff --git a/app/routes/users.py b/app/routes/users.py
index 1234567..89abcdef 100644
--- a/app/routes/users.py
+++ b/app/routes/users.py
@@ -10,3 +10,4 @@
+@app.get("/api/v1/users/{user_id}")
diff --git a/services/billing.js b/services/billing.js
--- a/services/billing.js
+++ b/services/billing.js
@@ -5,2 +5,3 @@
+router.post('/checkout', ...)
"""
        files = GitDiffAnalyzer.parse_diff_text(raw_diff)
        self.assertEqual(len(files), 2)
        self.assertIn("app/routes/users.py", files)
        self.assertIn("services/billing.js", files)

    def test_extract_routes_fastapi_and_flask(self) -> None:
        sample_code = """
from fastapi import APIRouter
router = APIRouter()

@router.get("/items/{item_id}")
def read_item(item_id: int):
    return {"id": item_id}

@router.post("/items/create")
def create_item():
    pass

@app.route("/legacy/<int:user_id>", methods=["GET", "POST"])
def legacy_user(user_id):
    pass
"""
        routes = GitDiffAnalyzer.extract_routes_from_content("app/api.py", sample_code)
        self.assertGreaterEqual(len(routes), 3)

        paths = [r.path for r in routes]
        methods = [r.method for r in routes]

        self.assertIn("/items/{item_id}", paths)
        self.assertIn("/items/create", paths)
        self.assertIn("/legacy/<int:user_id>", paths)
        self.assertIn("GET", methods)
        self.assertIn("POST", methods)

    def test_extract_routes_express_and_django(self) -> None:
        express_code = """
const express = require('express');
const app = express();

app.get('/api/v2/orders/:orderId', (req, res) => {});
router.delete('/api/v2/orders/:orderId', (req, res) => {});
"""
        routes = GitDiffAnalyzer.extract_routes_from_content("server.js", express_code)
        self.assertEqual(len(routes), 2)
        paths = [r.path for r in routes]
        self.assertIn("/api/v2/orders/:orderId", paths)
        methods = [r.method for r in routes]
        self.assertIn("GET", methods)
        self.assertIn("DELETE", methods)

    def test_map_routes_from_openapi(self) -> None:
        openapi_spec = {
            "paths": {
                "/api/users": {
                    "get": {"parameters": [{"name": "limit"}]},
                    "post": {"parameters": []},
                },
                "/api/products": {
                    "get": {"parameters": [{"name": "category"}]},
                },
            }
        }
        modified_files = ["app/controllers/user_controller.py"]
        routes = GitDiffAnalyzer.map_routes_from_openapi(modified_files, openapi_spec)

        self.assertEqual(len(routes), 2)
        paths = [r.path for r in routes]
        self.assertIn("/api/users", paths)
        self.assertNotIn("/api/products", paths)

    def test_surgical_scanner_quality_gate_passed(self) -> None:
        mock_session = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "Normal Safe Response"
        mock_resp.headers = {}
        mock_session.request.return_value = mock_resp

        scanner = SurgicalIncrementalScanner(session=mock_session, max_severity_gate="high")
        test_routes = [ModifiedRoute(path="/api/health", method="GET", file_source="health.py")]

        result = scanner.run_incremental_scan(
            target_base_url="http://target.local",
            routes=test_routes,
            modified_files=["health.py"],
        )

        self.assertTrue(result.gate_passed)
        self.assertEqual(len(result.findings), 0)
        self.assertGreaterEqual(result.duration_seconds, 0.0)
        self.assertIn("APROBADO", result.summary)

    def test_surgical_scanner_quality_gate_blocked(self) -> None:
        mock_session = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        # Simular respuesta que dispara SQLi
        mock_resp.text = "You have an error in your SQL syntax; check the manual that corresponds to your MySQL"
        mock_resp.headers = {}
        mock_session.request.return_value = mock_resp
        mock_session.get.return_value = mock_resp

        scanner = SurgicalIncrementalScanner(session=mock_session, max_severity_gate="high")
        test_routes = [ModifiedRoute(path="/api/search", method="GET", file_source="search.py")]

        result = scanner.run_incremental_scan(
            target_base_url="http://target.local",
            routes=test_routes,
            modified_files=["search.py"],
        )

        # Si detectó SQLi (crítico), la puerta de calidad debe bloquear
        if result.findings:
            self.assertFalse(result.gate_passed)
            self.assertIn("BLOQUEADO", result.summary)

    def test_format_github_pr_comment(self) -> None:
        mock_finding = Finding(
            category="sqli",
            title="SQL Injection en /api/users",
            severity="critical",
            confidence="confirmed",
            affected_url="http://target.local/api/users",
            remediation="Usar consultas parametrizadas.",
        )
        result = IncrementalScanResult(
            target_url="http://target.local",
            base_ref="origin/main",
            modified_files=["users.py"],
            targeted_endpoints=[ModifiedRoute(path="/api/users", method="GET", file_source="users.py")],
            findings=[mock_finding],
            gate_passed=False,
            duration_seconds=1.45,
            summary="Escaneo completado. 1 hallazgo.",
        )

        markdown = format_github_pr_comment(result)
        self.assertIn("Quality Gate BLOQUEADO", markdown)
        self.assertIn("SQL Injection en /api/users", markdown)
        self.assertIn("CRITICAL", markdown)
        self.assertIn("users.py", markdown)

    def test_export_incremental_sarif(self) -> None:
        import tempfile
        from pathlib import Path

        from scanner.git_diff_scanner import export_incremental_sarif

        mock_finding = Finding(
            category="xss",
            title="Reflected XSS",
            severity="high",
            confidence="high",
            affected_url="http://target.local/search?q=1",
            cwe_id="CWE-79",
        )
        result = IncrementalScanResult(
            target_url="http://target.local",
            base_ref="main",
            modified_files=["app.py"],
            targeted_endpoints=[],
            findings=[mock_finding],
            gate_passed=False,
            duration_seconds=0.5,
            summary="Test",
        )
        with tempfile.NamedTemporaryFile(suffix=".sarif", delete=False) as tmp:
            tmp_path = tmp.name

        try:
            sarif_data = export_incremental_sarif(result, tmp_path)
            self.assertIn("runs", sarif_data)
            content = Path(tmp_path).read_text(encoding="utf-8")
            self.assertIn("Reflected XSS", content)
        finally:
            Path(tmp_path).unlink(missing_ok=True)

    def test_dispatch_ci_incremental_scan(self) -> None:
        from scanner.git_diff_scanner import dispatch_ci_incremental_scan
        with patch.object(SurgicalIncrementalScanner, "run_incremental_scan") as mock_scan:
            mock_scan.return_value = IncrementalScanResult(
                target_url="http://127.0.0.1:8000",
                base_ref="origin/main",
                modified_files=["routes/auth.py"],
                targeted_endpoints=[],
                findings=[],
                gate_passed=True,
                duration_seconds=0.1,
                summary="Pass",
            )
            resp = dispatch_ci_incremental_scan(
                url="http://127.0.0.1:8000",
                base_ref="origin/main",
                diff_content="+++ b/routes/auth.py\n+@router.get('/login')\n",
                gate_severity="high",
            )
            self.assertEqual(resp["status"], "success")
            self.assertTrue(resp["result"]["gate_passed"])
            self.assertIn("pr_comment_markdown", resp["result"])


if __name__ == "__main__":
    unittest.main()

