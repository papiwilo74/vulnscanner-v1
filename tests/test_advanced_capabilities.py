"""
Suite de Pruebas Unitarias para las Nuevas Capacidades Avanzadas de OmniBreach:
1. Motor de Lógica de Negocio y Race Conditions (CWE-362 y CWE-840).
2. Programador Recurrente (Scheduler) y Cálculo de Security Drift.
3. Auditoría de Artefactos Expuestos (.git, Buckets de Nube y Dumps de Base de Datos).
"""
from __future__ import annotations

import io
from unittest.mock import Mock

import requests

from scanner.business_logic import check_race_condition, check_workflow_step_skipping
from scanner.diff import calculate_security_drift
from scanner.exposed_artifacts import (
    check_cloud_storage_leak,
    check_database_backup_exposure,
    check_exposed_git,
)
from scanner.scheduler import ScanScheduler


class TestBusinessLogicAndRaceCondition:
    """Pruebas para condiciones de carrera y salto de flujo de negocio."""

    def test_race_condition_detects_multiple_successes(self) -> None:
        mock_session = Mock(spec=requests.Session)
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.text = '{"success": true, "code": "COUPON_APPLIED"}'
        mock_resp.elapsed.total_seconds.return_value = 0.05
        mock_session.request.return_value = mock_resp

        finding = check_race_condition(
            url="https://api.target.local/api/v1/coupons/redeem",
            method="POST",
            payload={"coupon": "DESCUENTO50"},
            burst_count=4,
            session=mock_session,
        )

        assert finding is not None
        assert finding.category == "race_condition"
        assert finding.severity == "high"
        assert "Limit Overrun" in finding.title

    def test_race_condition_ignores_controlled_429(self) -> None:
        mock_session = Mock(spec=requests.Session)
        # 1er request responde 200, los demás responden 429 Too Many Requests
        responses = [Mock(status_code=200, text='{"success": true}')]
        for _ in range(3):
            m = Mock()
            m.status_code = 429
            m.text = '{"error": "Rate limit / Concurrency lock"}'
            m.elapsed.total_seconds.return_value = 0.01
            responses.append(m)
        responses[0].elapsed.total_seconds.return_value = 0.01

        mock_session.request.side_effect = responses

        finding = check_race_condition(
            url="https://api.target.local/api/v1/coupons/redeem",
            method="POST",
            burst_count=4,
            session=mock_session,
        )

        assert finding is None

    def test_workflow_step_skipping_detects_bypass(self) -> None:
        mock_session = Mock(spec=requests.Session)
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.text = '{"order_id": 999, "status": "CONFIRMED_AND_SHIPPED"}'
        mock_session.request.return_value = mock_resp

        steps = [
            {"step": 1, "url": "https://target.local/checkout/cart"},
            {"step": 2, "url": "https://target.local/checkout/payment_verify"},
            {"step": 3, "url": "https://target.local/checkout/complete_order"},
        ]

        finding = check_workflow_step_skipping(steps, session=mock_session)

        assert finding is not None
        assert finding.category == "business_logic"
        assert "Step Skipping" in finding.title

    def test_workflow_step_skipping_ignores_enforced_403(self) -> None:
        mock_session = Mock(spec=requests.Session)
        mock_resp = Mock()
        mock_resp.status_code = 403
        mock_resp.text = '{"error": "Debe completar el paso de pago previo"}'
        mock_session.request.return_value = mock_resp

        steps = [
            {"step": 1, "url": "https://target.local/checkout/cart"},
            {"step": 2, "url": "https://target.local/checkout/payment_verify"},
            {"step": 3, "url": "https://target.local/checkout/complete_order"},
        ]

        finding = check_workflow_step_skipping(steps, session=mock_session)
        assert finding is None


class TestSchedulerAndSecurityDrift:
    """Pruebas para el programador continuo y cálculo de deriva de seguridad."""

    def test_scheduler_lifecycle(self, tmp_path: object) -> None:
        import pathlib
        store_path = str(pathlib.Path(str(tmp_path)) / "schedules.json")
        scheduler = ScanScheduler(storage_file=store_path)

        task = scheduler.add_schedule(target_url="https://empresa.com", interval_hours=12)
        assert task.target_url == "https://empresa.com"
        assert task.interval_hours == 12

        # Comprobar que aparece en tareas vencidas simulando tiempo futuro (13 horas después)
        import time
        due = scheduler.get_due_tasks(current_timestamp=time.time() + (13 * 3600))
        assert len(due) == 1
        assert due[0].task_id == task.task_id

        # Marcar completada
        updated = scheduler.mark_task_completed(task.task_id, summary="0 vulnerabilidades críticas")
        assert updated is not None
        assert updated.last_run_at is not None

    def test_security_drift_calculation(self) -> None:
        # Simular 3 escaneos históricos
        scan1 = {
            "task_id": "scan_1",
            "results": {
                "security_score": 90.0,
                "vulnerabilities": [
                    {"category": "headers", "cwe_id": "CWE-693", "title": "Missing CSP"},
                ],
            },
        }
        scan2 = {
            "task_id": "scan_2",
            "results": {
                "security_score": 75.0,
                "vulnerabilities": [
                    {"category": "headers", "cwe_id": "CWE-693", "title": "Missing CSP"},
                    {"category": "sqli", "cwe_id": "CWE-89", "title": "SQLi in login"},
                    {"category": "xss", "cwe_id": "CWE-79", "title": "Reflected XSS"},
                ],
            },
        }
        drift_data = calculate_security_drift([scan1, scan2])

        assert drift_data["total_scans_analyzed"] == 2
        assert drift_data["total_new_vulnerabilities"] == 2
        assert drift_data["drift_trend"] == "deteriorating"
        assert drift_data["net_vulnerability_change"] == 2


class TestExposedArtifacts:
    """Pruebas para detección de .git, Cloud Buckets y Dumps."""

    def test_check_exposed_git_detects_real_head(self) -> None:
        mock_session = Mock(spec=requests.Session)
        mock_head = Mock()
        mock_head.status_code = 200
        mock_head.text = "ref: refs/heads/main\n"

        mock_config = Mock()
        mock_config.status_code = 200
        mock_config.text = "[core]\nrepositoryformatversion = 0\n[remote \"origin\"]\nurl = https://github.com/mycorp/app.git"

        def _side_effect(url: str, **kwargs: object) -> Mock:
            if "HEAD" in url:
                return mock_head
            return mock_config

        mock_session.get.side_effect = _side_effect

        finding = check_exposed_git("https://target.local", session=mock_session)

        assert finding is not None
        assert finding.severity == "critical"
        assert "Git Expuesto" in finding.title
        assert "mycorp/app.git" in finding.description

    def test_check_exposed_git_ignores_html_404_spa(self) -> None:
        mock_session = Mock(spec=requests.Session)
        mock_head = Mock()
        mock_head.status_code = 200
        mock_head.text = "<!DOCTYPE html><html><body>404 Not Found</body></html>"
        mock_session.get.return_value = mock_head

        finding = check_exposed_git("https://target.local", session=mock_session)
        assert finding is None

    def test_cloud_storage_leak_detects_open_bucket(self) -> None:
        html = '<img src="https://mycorp-backups.s3.amazonaws.com/logo.png">'
        mock_session = Mock(spec=requests.Session)
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.text = '<?xml version="1.0" encoding="UTF-8"?><ListBucketResult><Name>mycorp-backups</Name></ListBucketResult>'
        mock_session.get.return_value = mock_resp

        findings = check_cloud_storage_leak(html, session=mock_session)

        assert len(findings) == 1
        assert findings[0].category == "cloud_misconfiguration"
        assert "Listado Público Anónimo" in findings[0].title

    def test_database_backup_exposure_detects_sql_dump(self) -> None:
        mock_session = Mock(spec=requests.Session)
        mock_resp = Mock()
        mock_resp.status_code = 200

        # Simular lectura con context manager `with client.get(...) as resp:`
        mock_raw = io.BytesIO(b"-- MySQL dump 10.13  Distrib 8.0.28\n-- Host: localhost\nCREATE TABLE users (id int);")
        mock_resp.raw = mock_raw
        mock_resp.__enter__ = Mock(return_value=mock_resp)
        mock_resp.__exit__ = Mock(return_value=False)
        mock_session.get.return_value = mock_resp

        finding = check_database_backup_exposure("https://target.local", session=mock_session)

        assert finding is not None
        assert finding.category == "sensitive_data"
        assert finding.severity == "critical"
        assert "Respaldo de Base de Datos" in finding.title
