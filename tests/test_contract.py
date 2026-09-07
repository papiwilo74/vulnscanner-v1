"""
Tests de Contrato Formal para VulnScanner API y Modelos de Hallazgos.
Verifica que las respuestas de la API REST y las estructuras de datos
cumplan estrictamente con las especificaciones OpenAPI y los contratos de datos.
"""
import pytest
from fastapi.testclient import TestClient

from api import app
from scanner.engine import ScanConfig, ScanProfile
from scanner.models import Evidence, Finding
from utils.sarif import generate_sarif_v210

client = TestClient(app)


class TestAPIContract:
    """Valida contratos de entrada y salida de la API REST."""

    def test_root_endpoint_contract(self):
        response = client.get("/")
        assert response.status_code == 200
        data = response.json()
        assert "status" in data
        assert data["status"] == "online"
        assert "version" in data
        assert "docs_url" in data

    def test_openapi_schema_contract(self):
        response = client.get("/openapi.json")
        assert response.status_code == 200
        schema = response.json()
        assert "openapi" in schema
        assert schema["openapi"].startswith("3.")
        assert "paths" in schema
        assert "/scan" in schema["paths"]
        assert "/scan/{task_id}" in schema["paths"]
        assert "/scans" in schema["paths"]

    def test_scans_list_contract(self):
        response = client.get("/scans")
        assert response.status_code == 200
        data = response.json()
        assert "tasks" in data
        assert "total_tasks" in data
        tasks = data["tasks"]
        assert isinstance(tasks, list)
        if tasks:
            first = tasks[0]
            for field in ["task_id", "url", "status", "created_at"]:
                assert field in first, f"Falta campo requerido {field} en scan"

    def test_get_nonexistent_task_404(self):
        response = client.get("/scan/nonexistent-task-id-12345")
        assert response.status_code == 404
        assert "detail" in response.json()


class TestFindingContract:
    """Valida que el modelo Finding mantenga todos los campos del contrato enterprise."""

    def test_finding_to_dict_contract_completeness(self):
        ev = Evidence(
            request_method="GET",
            request_url="https://example.com/search?q=1",
            payload="' OR '1'='1",
            response_status=200,
            response_fragment="syntax error"
        )
        finding = Finding(
            category="sqli",
            title="SQL Injection en q",
            severity="high",
            confidence="confirmed",
            description="Inyección SQL basada en error",
            evidence=ev,
            affected_url="https://example.com/search",
            parameter="q"
        )
        d = finding.to_dict()

        mandatory_fields = [
            "id", "category", "title", "severity", "confidence",
            "description", "evidence", "remediation", "affected_url",
            "parameter", "cvss_score", "cvss_vector", "cwe_id",
            "cwe_name", "mitre_attack_id", "mitre_attack_name",
            "owasp_category", "autofix"
        ]
        for field in mandatory_fields:
            assert field in d, f"Campo obligatorio faltante: {field}"

        assert isinstance(d["cvss_score"], float)
        assert d["cvss_score"] >= 7.0  # High severity
        assert d["cwe_id"] == "CWE-89"
        assert d["mitre_attack_id"] == "T1190"
        assert d["evidence"]["request_method"] == "GET"

    def test_sarif_export_contract(self):
        finding = Finding(
            category="xss",
            title="XSS Reflejado",
            severity="medium",
            affected_url="https://example.com"
        )
        sarif = generate_sarif_v210("https://example.com", [finding])
        assert sarif["version"] == "2.1.0"
        assert "$schema" in sarif
        assert len(sarif["runs"]) == 1
        run = sarif["runs"][0]
        assert "tool" in run
        assert run["tool"]["driver"]["name"] == "VulnScanner"
        assert len(run["results"]) == 1


class TestScanEngineContract:
    """Valida contratos de configuración del motor según perfil."""

    @pytest.mark.parametrize("profile", [ScanProfile.PASSIVE, ScanProfile.NORMAL, ScanProfile.AGGRESSIVE])
    def test_scan_config_profile_contracts(self, profile):
        cfg = ScanConfig.from_profile(profile, target="https://example.com")
        assert cfg.profile == profile
        assert cfg.max_rps > 0
        assert cfg.max_total_requests > 0
        assert cfg.timeout > 0
        assert isinstance(cfg.active_payloads, bool)
