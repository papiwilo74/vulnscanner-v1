"""
Suite de Pruebas Unitarias para el Módulo de Seguridad en APIs (OWASP API Security Top 10).
Verifica:
1. Detección y descarte de BOLA / IDOR (API1:2023).
2. Detección y descarte de Mass Assignment / Property Tampering (API3:2023).
3. Detección y descarte de Broken Function Level Authorization - BFLA (API5:2023).
4. Detección de Consumo Abusivo de Recursos (API4:2023).
"""
from __future__ import annotations

import json
from unittest.mock import Mock

import requests

from scanner.api_security import (
    check_bfla,
    check_bola_idor,
    check_mass_assignment,
    check_resource_consumption,
)


class TestBOLAIDORDetection:
    """Pruebas para API1:2023 Broken Object Level Authorization."""

    def test_bola_idor_detects_vulnerable_endpoint(self) -> None:
        mock_session_a = Mock(spec=requests.Session)
        mock_resp_a = Mock()
        mock_resp_a.status_code = 200
        mock_resp_a.text = json.dumps({"account_id": "1001", "owner": "Alice", "balance": 500})

        mock_resp_b_hijacked = Mock()
        mock_resp_b_hijacked.status_code = 200
        mock_resp_b_hijacked.text = json.dumps({"account_id": "1002", "owner": "Bob", "balance": 15000})

        def request_side_effect(method: str, url: str, **kwargs: object) -> Mock:
            if "1001" in url:
                return mock_resp_a
            return mock_resp_b_hijacked

        mock_session_a.request.side_effect = request_side_effect

        finding = check_bola_idor(
            url="https://api.banco.local/api/v1/accounts/1001",
            method="GET",
            session_user_a=mock_session_a,
            test_entity_ids=("1001", "1002"),
            unauth_check=False,
        )

        assert finding is not None
        assert finding.category == "api_bola"
        assert finding.severity == "high"
        assert "BOLA / IDOR" in finding.title
        assert finding.confidence == "confirmed"

    def test_bola_idor_ignores_secure_endpoint_with_403(self) -> None:
        mock_session_a = Mock(spec=requests.Session)
        mock_resp_a = Mock()
        mock_resp_a.status_code = 200
        mock_resp_a.text = json.dumps({"account_id": "1001", "owner": "Alice"})

        mock_resp_b_denied = Mock()
        mock_resp_b_denied.status_code = 403
        mock_resp_b_denied.text = "Forbidden: No tienes permisos para ver este registro"

        def request_side_effect(method: str, url: str, **kwargs: object) -> Mock:
            if "1001" in url:
                return mock_resp_a
            return mock_resp_b_denied

        mock_session_a.request.side_effect = request_side_effect

        finding = check_bola_idor(
            url="https://api.banco.local/api/v1/accounts/1001",
            method="GET",
            session_user_a=mock_session_a,
            test_entity_ids=("1001", "1002"),
            unauth_check=False,
        )

        assert finding is None


class TestMassAssignmentDetection:
    """Pruebas para API3:2023 Mass Assignment / Property Tampering."""

    def test_mass_assignment_detects_compromised_role(self) -> None:
        mock_session = Mock(spec=requests.Session)
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.text = json.dumps({
            "id": 45,
            "name": "test_audit",
            "role": "admin",
            "is_admin": True,
        })
        mock_session.request.return_value = mock_resp

        finding = check_mass_assignment(
            url="https://api.target.local/api/v1/users/profile",
            method="POST",
            session=mock_session,
        )

        assert finding is not None
        assert finding.category == "api_mass_assignment"
        assert finding.severity == "high"
        assert "Mass Assignment" in finding.title
        assert finding.confidence == "confirmed"

    def test_mass_assignment_ignores_secure_filtered_response(self) -> None:
        mock_session = Mock(spec=requests.Session)
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.text = json.dumps({
            "id": 45,
            "name": "test_audit",
            "role": "user",
            "is_admin": False,
        })
        mock_session.request.return_value = mock_resp

        finding = check_mass_assignment(
            url="https://api.target.local/api/v1/users/profile",
            method="POST",
            session=mock_session,
        )

        assert finding is None


class TestBFLADetection:
    """Pruebas para API5:2023 Broken Function Level Authorization."""

    def test_bfla_detects_unauthorized_admin_access(self) -> None:
        mock_session = Mock(spec=requests.Session)
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.text = json.dumps({"total_users": 1500, "system_version": "v1.2", "env": "prod"})
        mock_session.get.return_value = mock_resp

        finding = check_bfla(
            url="https://api.target.local/api/v1/admin/metrics/raw",
            unprivileged_session=mock_session,
        )

        assert finding is not None
        assert finding.category == "api_bfla"
        assert finding.severity == "critical"
        assert "BFLA" in finding.title

    def test_bfla_ignores_protected_admin_endpoint(self) -> None:
        mock_session = Mock(spec=requests.Session)
        mock_resp = Mock()
        mock_resp.status_code = 403
        mock_resp.text = json.dumps({"detail": "Requires ADMIN role"})
        mock_session.get.return_value = mock_resp

        finding = check_bfla(
            url="https://api.target.local/api/v1/admin/metrics/raw",
            unprivileged_session=mock_session,
        )

        assert finding is None


class TestResourceConsumptionDetection:
    """Pruebas para API4:2023 Unrestricted Resource Consumption."""

    def test_resource_consumption_detects_massive_payload(self) -> None:
        mock_session = Mock(spec=requests.Session)
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.content = b"A" * 2_000_000
        mock_session.get.return_value = mock_resp

        finding = check_resource_consumption(
            url="https://api.target.local/api/v1/products?limit=10",
            session=mock_session,
            param_name="limit",
            abusive_value=1_000_000,
        )

        assert finding is not None
        assert finding.category == "api_resource_consumption"
        assert finding.severity == "medium"
        assert "Consumo de Recursos" in finding.title

    def test_resource_consumption_detects_server_error_500(self) -> None:
        mock_session = Mock(spec=requests.Session)
        mock_resp = Mock()
        mock_resp.status_code = 500
        mock_resp.content = b"Out of memory error"
        mock_resp.text = "Out of memory error"
        mock_session.get.return_value = mock_resp

        finding = check_resource_consumption(
            url="https://api.target.local/api/v1/products?limit=10",
            session=mock_session,
            param_name="limit",
            abusive_value=1_000_000,
        )

        assert finding is not None
        assert finding.category == "api_resource_consumption"
        assert "Error 500" in finding.title
