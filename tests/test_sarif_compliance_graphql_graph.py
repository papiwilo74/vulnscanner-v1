"""
Pruebas unitarias para:
1. Exportador SARIF v2.1.0 y GitHub Action (scanner/sarif.py)
2. Motor de Cumplimiento Regulatorio Automático (scanner/compliance.py)
3. Fuzzing Avanzado de APIs GraphQL: Límite de Profundidad y Batching (scanner/graphql.py)
4. Endpoints de Compliance y Grafo de Ataque Interactivo (api.py)
"""
from __future__ import annotations

import json
from typing import Any
from unittest.mock import MagicMock

from fastapi.testclient import TestClient

from api import app
from scanner.compliance import ComplianceEngine
from scanner.graphql import (
    _check_batching_abuse,
    _check_query_depth_limit,
)
from scanner.models import Finding
from scanner.sarif import export_findings_to_sarif, save_sarif_file

# ============================================================================
# 1. Pruebas: Exportador SARIF v2.1.0
# ============================================================================

def test_sarif_export_structure_and_levels() -> None:
    f_crit = Finding(
        category="sqli",
        title="SQL Injection en /api/users",
        severity="critical",
        cvss_score=9.8,
        cwe_id="CWE-89",
        affected_url="https://bank.corp/api/users",
    )
    f_med = Finding(
        category="cors",
        title="CORS Misconfiguration",
        severity="medium",
        cvss_score=5.3,
        cwe_id="CWE-942",
        affected_url="https://bank.corp/api/data",
    )

    sarif = export_findings_to_sarif([f_crit, f_med], scan_url="https://bank.corp")

    assert sarif["version"] == "2.1.0"
    assert "sarif-schema-2.1.0.json" in sarif["$schema"]
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "OmniBreach DAST"

    # Reglas
    rules = {r["id"]: r for r in run["tool"]["driver"]["rules"]}
    assert "OMNI-SQLI" in rules
    assert "OMNI-CORS" in rules

    # Resultados
    results = run["results"]
    assert len(results) == 2
    r_sqli = next(r for r in results if r["ruleId"] == "OMNI-SQLI")
    r_cors = next(r for r in results if r["ruleId"] == "OMNI-CORS")

    assert r_sqli["level"] == "error"
    assert r_cors["level"] == "warning"
    assert r_sqli["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "https://bank.corp/api/users"


def test_sarif_file_persistence(tmp_path: Any) -> None:
    out_file = str(tmp_path / "test_report.sarif")
    f = Finding(category="xss", title="XSS", severity="high", affected_url="https://app.corp/search")
    sarif = export_findings_to_sarif([f])
    save_sarif_file(sarif, out_file)

    with open(out_file, encoding="utf-8") as fp:
        loaded = json.load(fp)
    assert loaded["version"] == "2.1.0"
    assert len(loaded["runs"][0]["results"]) == 1


# ============================================================================
# 2. Pruebas: Motor de Cumplimiento Regulatorio (PCI, HIPAA, NIST, ISO)
# ============================================================================

def test_compliance_engine_clean_posture() -> None:
    engine = ComplianceEngine()
    result = engine.evaluate([])  # Cero hallazgos

    assert result["overall_compliance_score"] == 100.0
    assert "A" in result["overall_grade"]
    for fw in result["frameworks"].values():
        assert fw["compliance_score_percent"] == 100.0
        assert fw["status"] == "COMPLIANT"
        assert len(fw["violations"]) == 0


def test_compliance_engine_detects_violations_and_directives() -> None:
    engine = ComplianceEngine()
    findings = [
        Finding(category="sqli", title="SQLi en Checkout", severity="critical"),
        Finding(category="ssl", title="TLS 1.0 Débil", severity="high"),
    ]
    result = engine.evaluate(findings)

    assert result["overall_compliance_score"] < 100.0
    fws = result["frameworks"]

    # PCI-DSS debe registrar violaciones en 6.2.4 (Injection) y 4.1.2 (Cifrado)
    pci = fws["PCI-DSS v4.0"]
    assert pci["failing_controls"] >= 2
    violation_ids = [v["control_id"] for v in pci["violations"]]
    assert "PCI-6.2.4" in violation_ids
    assert "PCI-4.1.2" in violation_ids

    # Reporte Markdown
    md = engine.generate_markdown_report(result)
    assert "# Reporte de Cumplimiento Normativo" in md
    assert "PCI-DSS v4.0" in md
    assert "Directivas de Remediación Obligatorias" in md


# ============================================================================
# 3. Pruebas: Fuzzing Avanzado de APIs GraphQL
# ============================================================================

def test_graphql_query_depth_limit_vulnerable() -> None:
    client = MagicMock()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.headers = {"Content-Type": "application/json"}
    mock_resp.text = json.dumps({"data": {"__schema": {"types": [{"fields": [{"type": {"ofType": {"name": "User"}}}]}]}}})
    client.post.return_value = mock_resp

    finding = _check_query_depth_limit("https://app.corp/graphql", client)
    assert finding is not None
    assert "Sin Límite de Profundidad" in finding["vuln"]
    assert "CWE-400" in finding.get("detail", "") or "consumo de CPU" in finding.get("detail", "")


def test_graphql_query_depth_limit_safe_blocked() -> None:
    client = MagicMock()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.headers = {"Content-Type": "application/json"}
    mock_resp.text = json.dumps({"errors": [{"message": "Query depth limit of 6 exceeded"}]})
    client.post.return_value = mock_resp

    finding = _check_query_depth_limit("https://app.corp/graphql", client)
    assert finding is None


def test_graphql_batching_abuse_vulnerable() -> None:
    client = MagicMock()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.headers = {"Content-Type": "application/json"}
    mock_resp.json.return_value = [{"data": {"__typename": "Query"}} for _ in range(10)]
    client.post.return_value = mock_resp

    finding = _check_batching_abuse("https://app.corp/graphql", client)
    assert finding is not None
    assert "Ataque de Batching" in finding["vuln"]
    assert "rate-limiters" in finding["detail"]


def test_graphql_batching_abuse_safe_single() -> None:
    client = MagicMock()
    mock_resp = MagicMock()
    mock_resp.status_code = 400
    mock_resp.headers = {"Content-Type": "application/json"}
    mock_resp.json.return_value = {"error": "Batching not supported"}
    client.post.return_value = mock_resp

    finding = _check_batching_abuse("https://app.corp/graphql", client)
    assert finding is None


# ============================================================================
# 4. Pruebas: Endpoints de Compliance y Grafo de Ataque en api.py
# ============================================================================

def test_api_compliance_evaluate_endpoint() -> None:
    test_client = TestClient(app)
    payload = [
        {"category": "sqli", "title": "SQL Injection", "severity": "critical"},
        {"category": "cookies", "title": "Insecure Cookie", "severity": "low"},
    ]
    resp = test_client.post("/api/v1/compliance/evaluate", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert "overall_compliance_score" in data
    assert "frameworks" in data
    assert "PCI-DSS v4.0" in data["frameworks"]


def test_api_compliance_latest_endpoint() -> None:
    test_client = TestClient(app)
    resp = test_client.get("/api/v1/compliance/latest")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] in ("success", "not_found")


def test_api_attack_graph_latest_endpoint() -> None:
    test_client = TestClient(app)
    resp = test_client.get("/api/v1/attack-graph/latest")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] in ("success", "not_found")
