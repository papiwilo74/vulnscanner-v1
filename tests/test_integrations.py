"""
Suite de Pruebas Unitarias para el Motor de Integraciones DevSecOps.
Verifica:
1. Deduplicación determinista por fingerprinting SHA-256.
2. Despacho a Jira Cloud (ADF, mapeo de prioridad, autenticación básica).
3. Despacho a Slack (Block Kit enriquecido).
4. Despacho a Microsoft Teams (MessageCard).
5. Despacho a GitHub Issues.
6. Filtro por umbral de severidad y orquestación unificada en NotificationDispatcher.
"""
from __future__ import annotations

from unittest.mock import Mock

import requests

from scanner.integrations import (
    DeduplicationStore,
    GitHubIssuesConnector,
    JiraConnector,
    NotificationDispatcher,
    SlackConnector,
    TeamsConnector,
    calculate_finding_fingerprint,
)
from scanner.models import Evidence, Finding


def _sample_finding(severity: str = "critical", title: str = "SQL Injection en Login") -> Finding:
    return Finding(
        category="sqli",
        title=title,
        severity=severity,
        confidence="confirmed",
        description="Parámetro vulnerable a inyección SQL mediante comillas.",
        affected_url="https://target.local/api/v1/login",
        parameter="username",
        evidence=Evidence(
            request_method="POST",
            request_url="https://target.local/api/v1/login",
            payload="' OR 1=1--",
            response_status=500,
        ),
        remediation="Usar sentencias preparadas y consultas parametrizadas.",
    )


class TestDeduplication:
    """Pruebas para el motor de huella digital y deduplicación."""

    def test_fingerprint_is_deterministic(self) -> None:
        f1 = _sample_finding()
        f2 = _sample_finding()
        assert calculate_finding_fingerprint(f1) == calculate_finding_fingerprint(f2)

    def test_dedup_store_marks_and_detects_duplicates(self) -> None:
        store = DeduplicationStore()
        fp = "test_hash_123"
        assert not store.is_dispatched(fp)

        store.mark_dispatched(fp)
        assert store.is_dispatched(fp)

    def test_dedup_store_persistence(self, tmp_path: object) -> None:
        import pathlib
        p = pathlib.Path(str(tmp_path)) / "dedup.json"
        store1 = DeduplicationStore(persistence_file=str(p))
        store1.mark_dispatched("hash_abc")

        # Cargar con nueva instancia
        store2 = DeduplicationStore(persistence_file=str(p))
        assert store2.is_dispatched("hash_abc")
        assert not store2.is_dispatched("hash_xyz")


class TestJiraConnector:
    """Pruebas para integración con Jira Cloud REST API v3."""

    def test_jira_create_issue_success(self) -> None:
        mock_session = Mock(spec=requests.Session)
        mock_resp = Mock()
        mock_resp.status_code = 201
        mock_resp.json.return_value = {"id": "10001", "key": "SEC-42", "self": "https://jira.local/rest/api/3/issue/10001"}
        mock_session.post.return_value = mock_resp

        jira = JiraConnector(
            jira_url="https://mycorp.atlassian.net",
            email="sec@mycorp.com",
            api_token="token_secret_123",
            project_key="SEC",
            session=mock_session,
        )

        finding = _sample_finding(severity="critical")
        result = jira.create_issue(finding)

        assert result is not None
        assert result["key"] == "SEC-42"
        mock_session.post.assert_called_once()
        args, kwargs = mock_session.post.call_args
        assert "rest/api/3/issue" in args[0]
        json_body = kwargs["json"]
        assert json_body["fields"]["project"]["key"] == "SEC"
        assert json_body["fields"]["priority"]["name"] == "Highest"
        assert "SQL Injection" in json_body["fields"]["summary"]

    def test_jira_create_issue_failure(self) -> None:
        mock_session = Mock(spec=requests.Session)
        mock_resp = Mock()
        mock_resp.status_code = 400
        mock_resp.text = "Field 'priority' is invalid"
        mock_session.post.return_value = mock_resp

        jira = JiraConnector(
            jira_url="https://mycorp.atlassian.net",
            email="sec@mycorp.com",
            api_token="token_secret_123",
            project_key="SEC",
            session=mock_session,
        )

        finding = _sample_finding()
        result = jira.create_issue(finding)
        assert result is None


class TestSlackConnector:
    """Pruebas para notificaciones en Slack Block Kit."""

    def test_slack_send_alert_success(self) -> None:
        mock_session = Mock(spec=requests.Session)
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_session.post.return_value = mock_resp

        slack = SlackConnector(webhook_url="https://hooks.slack.com/services/T00/B00/X00", session=mock_session)
        finding = _sample_finding(severity="high")
        success = slack.send_alert(finding)

        assert success is True
        mock_session.post.assert_called_once()
        _, kwargs = mock_session.post.call_args
        payload = kwargs["json"]
        assert "blocks" in payload
        # Verificar que contiene el bloque de header
        assert payload["blocks"][0]["type"] == "header"
        assert "SQL Injection" in payload["blocks"][0]["text"]["text"]


class TestTeamsConnector:
    """Pruebas para notificaciones en Microsoft Teams."""

    def test_teams_send_alert_success(self) -> None:
        mock_session = Mock(spec=requests.Session)
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_session.post.return_value = mock_resp

        teams = TeamsConnector(webhook_url="https://outlook.office.com/webhook/test", session=mock_session)
        finding = _sample_finding(severity="medium")
        success = teams.send_alert(finding)

        assert success is True
        mock_session.post.assert_called_once()
        _, kwargs = mock_session.post.call_args
        payload = kwargs["json"]
        assert payload["@type"] == "MessageCard"
        assert "SQL Injection" in payload["summary"]


class TestGitHubIssuesConnector:
    """Pruebas para creación de issues en GitHub."""

    def test_github_create_issue_success(self) -> None:
        mock_session = Mock(spec=requests.Session)
        mock_resp = Mock()
        mock_resp.status_code = 201
        mock_resp.json.return_value = {"number": 105, "html_url": "https://github.com/mycorp/repo/issues/105"}
        mock_session.post.return_value = mock_resp

        gh = GitHubIssuesConnector(repo="mycorp/repo", token="ghp_fake123", session=mock_session)
        finding = _sample_finding(severity="critical")
        res = gh.create_issue(finding)

        assert res is not None
        assert res["number"] == 105
        mock_session.post.assert_called_once()
        _, kwargs = mock_session.post.call_args
        assert "https://api.github.com/repos/mycorp/repo/issues" in mock_session.post.call_args[0][0]
        assert "CRITICAL" in kwargs["json"]["title"]


class TestNotificationDispatcher:
    """Pruebas para el orquestador unificado y deduplicación de envíos."""

    def test_dispatcher_filters_below_severity_threshold(self) -> None:
        mock_slack = Mock(spec=SlackConnector)
        dispatcher = NotificationDispatcher(min_severity="high", slack=mock_slack)

        # Un hallazgo "low" o "medium" debe ser omitido
        finding_low = _sample_finding(severity="low")
        res = dispatcher.dispatch_finding(finding_low)

        assert res["slack"] is False
        mock_slack.send_alert.assert_not_called()

    def test_dispatcher_sends_and_deduplicates(self) -> None:
        mock_slack = Mock(spec=SlackConnector)
        mock_slack.send_alert.return_value = True

        dispatcher = NotificationDispatcher(min_severity="high", slack=mock_slack)
        finding_critical = _sample_finding(severity="critical")

        # 1er envío: debe ejecutarse
        res1 = dispatcher.dispatch_finding(finding_critical)
        assert res1["slack"] is True
        assert mock_slack.send_alert.call_count == 1

        # 2do envío idéntico: debe ser descartado por deduplicación
        res2 = dispatcher.dispatch_finding(finding_critical)
        assert res2["slack"] is False
        assert mock_slack.send_alert.call_count == 1  # No vuelve a llamar

    def test_dispatch_all_counts(self) -> None:
        mock_slack = Mock(spec=SlackConnector)
        mock_slack.send_alert.return_value = True

        dispatcher = NotificationDispatcher(min_severity="medium", slack=mock_slack)
        findings = [
            _sample_finding(severity="critical", title="Bug 1"),
            _sample_finding(severity="low", title="Bug 2"),       # Ignorado por severidad
            _sample_finding(severity="high", title="Bug 3"),
        ]

        stats = dispatcher.dispatch_all(findings)
        assert stats["total_processed"] == 3
        assert stats["slack"] == 2
