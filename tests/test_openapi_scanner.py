import json

import pytest

responses = pytest.importorskip("responses")

from scanner.openapi_scanner import OpenAPIScanner  # noqa: E402

SAMPLE_OPENAPI_SPEC = {
    "openapi": "3.0.0",
    "info": {
        "title": "Sample Enterprise API",
        "version": "1.0.0"
    },
    "servers": [
        {"url": "https://api.testservice.local/v1"}
    ],
    "paths": {
        "/users": {
            "get": {
                "summary": "List users",
                "parameters": [
                    {"name": "role", "in": "query", "schema": {"type": "string"}},
                    {"name": "limit", "in": "query", "schema": {"type": "integer"}}
                ],
                "responses": {"200": {"description": "OK"}}
            },
            "post": {
                "summary": "Create user",
                "security": [{"BearerAuth": []}],
                "requestBody": {
                    "content": {
                        "application/json": {
                            "schema": {"type": "object"}
                        }
                    }
                },
                "responses": {"201": {"description": "Created"}}
            }
        },
        "/users/{id}": {
            "delete": {
                "summary": "Delete user",
                "parameters": [
                    {"name": "id", "in": "path", "required": True, "schema": {"type": "integer"}}
                ],
                "responses": {"204": {"description": "Deleted"}}
            }
        }
    }
}


class TestOpenAPIScanner:
    """Valida la extracción de endpoints y chequeos de seguridad de APIs."""

    def test_parses_endpoints_correctly(self, tmp_path):
        spec_file = tmp_path / "openapi.json"
        spec_file.write_text(json.dumps(SAMPLE_OPENAPI_SPEC), encoding="utf-8")

        scanner = OpenAPIScanner(str(spec_file))
        assert scanner.load_spec() is True
        endpoints = scanner.get_endpoints()

        assert len(endpoints) == 3
        methods = {ep["method"] for ep in endpoints}
        assert methods == {"GET", "POST", "DELETE"}
        assert scanner.base_url == "https://api.testservice.local/v1"

    @responses.activate
    def test_detects_broken_authentication_on_sensitive_endpoint(self, tmp_path):
        spec_file = tmp_path / "openapi.json"
        spec_file.write_text(json.dumps(SAMPLE_OPENAPI_SPEC), encoding="utf-8")

        # Mock: DELETE /users/1 responde 200 sin pedir auth
        responses.add(
            responses.DELETE,
            "https://api.testservice.local/v1/users/1",
            status=200,
            json={"status": "deleted", "id": 1},
            headers={"Content-Type": "application/json"}
        )
        # Mock otros endpoints para que no fallen
        responses.add(responses.GET, "https://api.testservice.local/v1/users", status=200, json=[])
        responses.add(responses.POST, "https://api.testservice.local/v1/users", status=401)

        scanner = OpenAPIScanner(str(spec_file))
        findings = scanner.scan()

        auth_findings = [f for f in findings if "Autenticación" in f.title or "Broken Auth" in f.owasp_category]
        assert len(auth_findings) >= 1
        assert "DELETE" in auth_findings[0].description
        assert auth_findings[0].cwe_id == "CWE-306"

    @responses.activate
    def test_detects_500_stack_trace_leak(self, tmp_path):
        spec_file = tmp_path / "openapi.json"
        spec_file.write_text(json.dumps(SAMPLE_OPENAPI_SPEC), encoding="utf-8")

        # Mock: POST /users responde 500 con traceback ante json inválido
        responses.add(
            responses.POST,
            "https://api.testservice.local/v1/users",
            status=500,
            body="Internal Server Error: Traceback (most recent call last):\nFile 'app.py', line 45",
        )
        responses.add(responses.GET, "https://api.testservice.local/v1/users", status=200, json=[])
        responses.add(responses.DELETE, "https://api.testservice.local/v1/users/1", status=403)

        scanner = OpenAPIScanner(str(spec_file))
        findings = scanner.scan()

        leak_findings = [f for f in findings if f.cwe_id == "CWE-209"]
        assert len(leak_findings) >= 1
        assert "HTTP 500" in leak_findings[0].title
        assert leak_findings[0].severity == "medium"

    @responses.activate
    def test_detects_sqli_in_api_query_parameter(self, tmp_path):
        spec_file = tmp_path / "openapi.json"
        spec_file.write_text(json.dumps(SAMPLE_OPENAPI_SPEC), encoding="utf-8")

        responses.add(
            responses.GET,
            "https://api.testservice.local/v1/users",
            status=200,
            body="Warning: mysql_fetch_array() error: you have an error in your sql syntax near 'role_vuln_probe'",
        )
        responses.add(responses.POST, "https://api.testservice.local/v1/users", status=401)
        responses.add(responses.DELETE, "https://api.testservice.local/v1/users/1", status=403)

        scanner = OpenAPIScanner(str(spec_file))
        findings = scanner.scan()

        sqli_findings = [f for f in findings if f.category == "sqli"]
        assert len(sqli_findings) >= 1
        assert "role" in sqli_findings[0].parameter
        assert sqli_findings[0].cwe_id == "CWE-89"
