"""
Pruebas unitarias para:
1. Agente Satélite Inverso (SatelliteAgent)
2. Re-Testing Quirúrgico Bi-Direccional (retest_finding / retest_multiple_findings)
3. Registro de Auditoría Inmutable (AuditLedger)
"""
from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import requests

from scanner.audit_ledger import GENESIS_HASH, AuditLedger
from scanner.models import Evidence, Finding
from scanner.retest import retest_finding, retest_multiple_findings
from scanner.satellite import SatelliteAgent

# ============================================================================
# Pruebas: Agente Satélite Inverso
# ============================================================================

def test_satellite_initialization() -> None:
    sat = SatelliteAgent(
        coordinator_url="https://scanner.internal.corp",
        cluster_key="secret-key-123",
        satellite_id="sat_node_01",
        satellite_name="bank-dmz-agent",
        intranet_scope=["10.10.0.0/16"],
    )
    assert sat.satellite_id == "sat_node_01"
    assert sat.satellite_name == "bank-dmz-agent"
    assert "10.10.0.0/16" in sat.intranet_scope
    headers = sat._get_headers()
    assert headers["X-Worker-ID"] == "sat_node_01"
    assert headers["Authorization"] == "Bearer secret-key-123"


def test_satellite_registration_success() -> None:
    session = MagicMock(spec=requests.Session)
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    session.post.return_value = mock_resp

    sat = SatelliteAgent(coordinator_url="http://mock-coordinator", session=session)
    assert sat.register() is True
    session.post.assert_called_once()
    assert "/api/v1/cluster/workers/register" in session.post.call_args[0][0]


def test_satellite_registration_failure() -> None:
    session = MagicMock(spec=requests.Session)
    session.post.side_effect = requests.RequestException("Connection refused")

    sat = SatelliteAgent(coordinator_url="http://mock-coordinator", session=session)
    assert sat.register() is False


def test_satellite_heartbeat() -> None:
    session = MagicMock(spec=requests.Session)
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    session.post.return_value = mock_resp

    sat = SatelliteAgent(coordinator_url="http://mock-coordinator", session=session)
    assert sat.send_heartbeat() is True
    assert "/heartbeat" in session.post.call_args[0][0]


def test_satellite_claim_and_complete_job() -> None:
    session = MagicMock(spec=requests.Session)

    # Mock claim response
    mock_claim = MagicMock()
    mock_claim.status_code = 200
    mock_claim.json.return_value = {
        "task_id": "job_998",
        "url": "http://10.0.1.50/admin",
        "mode": "standard",
    }

    # Mock complete response
    mock_complete = MagicMock()
    mock_complete.status_code = 200

    session.post.side_effect = [mock_claim, mock_complete]

    sat = SatelliteAgent(coordinator_url="http://mock-coordinator", session=session)
    claimed = sat.claim_job()
    assert claimed is not None
    assert claimed["task_id"] == "job_998"

    completed = sat.complete_job("job_998", {"status": "ok"})
    assert completed is True


def test_satellite_run_single_cycle() -> None:
    session = MagicMock(spec=requests.Session)

    # 1. heartbeat response
    hb_resp = MagicMock()
    hb_resp.status_code = 200

    # 2. claim response
    claim_resp = MagicMock()
    claim_resp.status_code = 200
    claim_resp.json.return_value = {
        "task_id": "job_local_1",
        "url": "http://192.168.1.100:8080/api",
    }

    # 3. complete response
    comp_resp = MagicMock()
    comp_resp.status_code = 200

    session.post.side_effect = [hb_resp, claim_resp, comp_resp]

    sat = SatelliteAgent(coordinator_url="http://mock-coordinator", session=session)
    result = sat.run_single_cycle()
    assert result is not None
    assert result["scanned_internally"] is True
    assert result["target_url"] == "http://192.168.1.100:8080/api"


# ============================================================================
# Pruebas: Re-Testing Quirúrgico Bi-Direccional
# ============================================================================

def test_retest_sqli_still_vulnerable() -> None:
    finding = Finding(
        category="sqli",
        title="SQL Injection en login",
        severity="critical",
        affected_url="http://app.internal/login",
        parameter="user",
        evidence=Evidence(
            request_method="GET",
            request_url="http://app.internal/login?user=' OR 1=1--",
            payload="' OR 1=1--",
            response_fragment="syntax error near '1=1'",
        ),
    )

    session = MagicMock(spec=requests.Session)
    mock_resp = MagicMock()
    mock_resp.status_code = 500
    mock_resp.text = "Internal Server Error: syntax error near '1=1' in query."
    session.get.return_value = mock_resp

    result = retest_finding(finding, session=session)
    assert result["status"] == "still_vulnerable"
    assert result["vuln_type"] == "SQL Injection"
    assert "syntax error" in result["details"]


def test_retest_sqli_fixed() -> None:
    finding = Finding(
        category="sqli",
        title="SQL Injection en login",
        severity="critical",
        affected_url="http://app.internal/login",
        parameter="user",
        evidence=Evidence(
            request_method="GET",
            request_url="http://app.internal/login?user=' OR 1=1--",
            payload="' OR 1=1--",
            response_fragment="syntax error",
        ),
    )

    session = MagicMock(spec=requests.Session)
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = "Login Failed: Invalid credentials"
    session.get.return_value = mock_resp

    result = retest_finding(finding, session=session)
    assert result["status"] == "fixed"
    assert "neutralizado" in result["details"]


def test_retest_xss_fixed_and_vulnerable() -> None:
    xss_finding = Finding(
        category="xss",
        title="Reflected XSS",
        severity="high",
        affected_url="http://app.internal/search",
        parameter="q",
        evidence=Evidence(
            request_method="GET",
            request_url="http://app.internal/search?q=<script>alert(1)</script>",
            payload="<script>alert(1)</script>",
        ),
    )

    session = MagicMock(spec=requests.Session)

    # Escenario vulnerable: payload reflejado sin escape
    vuln_resp = MagicMock()
    vuln_resp.status_code = 200
    vuln_resp.text = "<div>Resultados para: <script>alert(1)</script></div>"
    session.get.return_value = vuln_resp

    res_vuln = retest_finding(xss_finding, session=session)
    assert res_vuln["status"] == "still_vulnerable"

    # Escenario corregido: payload escapado en HTML
    fixed_resp = MagicMock()
    fixed_resp.status_code = 200
    fixed_resp.text = "<div>Resultados para: &lt;script&gt;alert(1)&lt;/script&gt;</div>"
    session.get.return_value = fixed_resp

    res_fixed = retest_finding(xss_finding, session=session)
    assert res_fixed["status"] == "fixed"


def test_retest_lfi_verification() -> None:
    lfi_finding = Finding(
        category="traversal",
        title="Path Traversal /etc/passwd",
        severity="high",
        affected_url="http://app.internal/view?file=../../../../etc/passwd",
        parameter="file",
        evidence=Evidence(
            request_method="GET",
            request_url="http://app.internal/view?file=../../../../etc/passwd",
            payload="../../../../etc/passwd",
        ),
    )

    session = MagicMock(spec=requests.Session)

    # Vulnerable
    vuln_resp = MagicMock()
    vuln_resp.status_code = 200
    vuln_resp.text = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin"
    session.get.return_value = vuln_resp

    res_vuln = retest_finding(lfi_finding, session=session)
    assert res_vuln["status"] == "still_vulnerable"

    # Fixed (403 Forbidden)
    fixed_resp = MagicMock()
    fixed_resp.status_code = 403
    fixed_resp.text = "Access Denied"
    session.get.return_value = fixed_resp

    res_fixed = retest_finding(lfi_finding, session=session)
    assert res_fixed["status"] == "fixed"


def test_retest_inconclusive_missing_url_or_connection_error() -> None:
    # Sin URL
    no_url = Finding(category="generic", title="Test finding", severity="low")
    res_no_url = retest_finding(no_url)
    assert res_no_url["status"] == "inconclusive"

    # Error de conexión
    session = MagicMock(spec=requests.Session)
    session.get.side_effect = requests.ConnectionError("Host unreachable")
    valid_finding = Finding(
        category="generic",
        title="Test finding",
        severity="low",
        affected_url="http://unreachable.corp/api",
    )
    res_err = retest_finding(valid_finding, session=session)
    assert res_err["status"] == "inconclusive"
    assert "Fallo al conectar" in res_err["details"]


def test_retest_multiple_findings() -> None:
    f1 = Finding(category="xss", title="XSS", severity="high", affected_url="http://a.corp/1")
    f2 = Finding(category="sqli", title="SQLi", severity="high", affected_url="http://a.corp/2")

    session = MagicMock(spec=requests.Session)
    r1 = MagicMock(status_code=200, text="clean")
    r2 = MagicMock(status_code=500, text="syntax error near sql")
    session.get.side_effect = [r1, r2]

    summary = retest_multiple_findings([f1, f2], session=session)
    assert summary["total_retested"] == 2
    assert summary["fixed"] == 1
    assert summary["still_vulnerable"] == 1
    assert summary["inconclusive"] == 0


# ============================================================================
# Pruebas: Registro de Auditoría Inmutable (AuditLedger)
# ============================================================================

def test_audit_ledger_chain_and_integrity(tmp_path: Any) -> None:
    ledger_path = str(tmp_path / "audit_ledger.jsonl")
    ledger = AuditLedger(ledger_file=ledger_path)

    # 1. Evento Génesis
    ev0 = ledger.record_event("SCAN_STARTED", {"target": "https://company.org", "mode": "deep"}, actor="ci-runner")
    assert ev0["index"] == 0
    assert ev0["previous_hash"] == GENESIS_HASH
    assert len(ev0["current_hash"]) == 64

    # 2. Evento Hallazgo
    ev1 = ledger.record_event("FINDING_DISCOVERED", {"finding_id": "f_123", "severity": "high"}, actor="scanner-core")
    assert ev1["index"] == 1
    assert ev1["previous_hash"] == ev0["current_hash"]

    # 3. Evento Verificación
    ev2 = ledger.record_event("RETEST_VERIFIED", {"finding_id": "f_123", "status": "fixed"}, actor="sec-engineer")
    assert ev2["index"] == 2
    assert ev2["previous_hash"] == ev1["current_hash"]

    # Verificación de integridad matemática
    is_valid, msg = ledger.verify_integrity()
    assert is_valid is True
    assert "3 eventos válidos" in msg


def test_audit_ledger_detects_data_tampering() -> None:
    ledger = AuditLedger()
    ledger.record_event("SCAN_STARTED", {"target": "https://company.org"})
    ledger.record_event("FINDING_DISCOVERED", {"severity": "critical", "type": "RCE"})
    ledger.record_event("SCAN_COMPLETED", {"status": "success"})

    # Verificación inicial limpia
    assert ledger.verify_integrity()[0] is True

    # Intento malicioso de modificar retroactivamente el hallazgo para pasar auditoría
    ledger.events[1]["data"]["severity"] = "low"  # Tamper!

    is_valid, error_msg = ledger.verify_integrity()
    assert is_valid is False
    assert "Alteración de datos detectada en bloque 1" in error_msg


def test_audit_ledger_detects_broken_chain() -> None:
    ledger = AuditLedger()
    ledger.record_event("EVENT_A", {"k": 1})
    ledger.record_event("EVENT_B", {"k": 2})

    # Manipular previous_hash
    ledger.events[1]["previous_hash"] = "deadbeef" * 8

    is_valid, error_msg = ledger.verify_integrity()
    assert is_valid is False
    assert "Ruptura de cadena en bloque 1" in error_msg


def test_audit_ledger_persistence_and_report(tmp_path: Any) -> None:
    ledger_path = str(tmp_path / "persistent_ledger.jsonl")
    ledger1 = AuditLedger(ledger_file=ledger_path)
    ledger1.record_event("A1", {"msg": "first"}, actor="bot")
    ledger1.record_event("A2", {"msg": "second"}, actor="bot")

    # Cargar en una nueva instancia del ledger desde el archivo persistido
    ledger2 = AuditLedger(ledger_file=ledger_path)
    assert len(ledger2.events) == 2
    is_valid, _ = ledger2.verify_integrity()
    assert is_valid is True

    # Generar reporte forense
    report = ledger2.export_tamper_proof_report()
    assert report["integrity_verified"] is True
    assert report["total_events"] == 2
    assert report["root_head_hash"] == ledger2.events[-1]["current_hash"]
    assert report["compliance_standard"] == "SOC2-CC6.8 / ISO27001-A.12.4"
