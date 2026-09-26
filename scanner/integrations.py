"""
Motor de Integraciones DevSecOps Corporativas (Jira, Slack, Microsoft Teams, GitHub Issues).
Permite despachar alertas y tickets automáticos con deduplicación por fingerprinting y filtrado por severidad.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

import requests
from requests.auth import HTTPBasicAuth

from scanner.models import Finding

logger = logging.getLogger("OmniBreach.Integrations")

SEVERITY_LEVELS: dict[str, int] = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
}

SEVERITY_COLORS: dict[str, str] = {
    "critical": "#D32F2F",  # Rojo oscuro
    "high": "#F57C00",      # Naranja intenso
    "medium": "#FBC02D",    # Amarillo
    "low": "#0288D1",       # Azul
    "info": "#757575",      # Gris
}

SEVERITY_EMOJIS: dict[str, str] = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🔵",
    "info": "⚪",
}


def calculate_finding_fingerprint(finding: Finding) -> str:
    """Calcula un hash SHA-256 determinista para deduplicación de hallazgos."""
    url_normalized = urlparse(finding.affected_url or "").path
    base_str = f"{finding.category}:{url_normalized}:{finding.parameter or ''}:{finding.title}"
    return hashlib.sha256(base_str.encode("utf-8")).hexdigest()


class DeduplicationStore:
    """Almacena fingerprints de vulnerabilidades ya despachadas para evitar spam de alertas."""

    def __init__(self, persistence_file: str | None = None) -> None:
        self.persistence_file = persistence_file
        self.seen_fingerprints: set[str] = set()
        self._load()

    def _load(self) -> None:
        if self.persistence_file and os.path.isfile(self.persistence_file):
            try:
                with open(self.persistence_file, encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, list):
                        self.seen_fingerprints = set(data)
            except Exception as exc:
                logger.debug("Error cargando store de deduplicación: %s", exc)

    def _save(self) -> None:
        if self.persistence_file:
            try:
                with open(self.persistence_file, "w", encoding="utf-8") as f:
                    json.dump(list(self.seen_fingerprints), f, indent=2)
            except Exception as exc:
                logger.debug("Error guardando store de deduplicación: %s", exc)

    def is_dispatched(self, fingerprint: str) -> bool:
        return fingerprint in self.seen_fingerprints

    def mark_dispatched(self, fingerprint: str) -> None:
        self.seen_fingerprints.add(fingerprint)
        self._save()


class JiraConnector:
    """Conector con Jira Cloud REST API v3 para generación automática de tickets/bugs."""

    def __init__(
        self,
        jira_url: str,
        email: str,
        api_token: str,
        project_key: str,
        issue_type: str = "Bug",
        session: requests.Session | None = None,
    ) -> None:
        self.jira_url = jira_url.rstrip("/")
        self.email = email
        self.api_token = api_token
        self.project_key = project_key
        self.issue_type = issue_type
        self.session = session or requests.Session()

    def create_issue(self, finding: Finding) -> dict[str, Any] | None:
        """Crea un ticket en Jira Cloud con los detalles técnicos del hallazgo."""
        api_endpoint = f"{self.jira_url}/rest/api/3/issue"

        # Mapeo de severidad a prioridad de Jira
        priority_map = {
            "critical": "Highest",
            "high": "High",
            "medium": "Medium",
            "low": "Low",
            "info": "Lowest",
        }
        priority_name = priority_map.get(finding.severity.lower(), "Medium")

        # Construir comando cURL reproducible para los ingenieros
        curl_cmd = (
            f"curl -k -i -X {finding.evidence.request_method if finding.evidence else 'GET'} "
            f"'{finding.affected_url or ''}'"
        )
        if finding.evidence and finding.evidence.payload:
            curl_cmd += f" -d '{finding.evidence.payload}'"

        # Descripción en formato Atlassian Document Format (ADF)
        description_adf = {
            "version": 1,
            "type": "doc",
            "content": [
                {
                    "type": "paragraph",
                    "content": [{"type": "text", "text": finding.description}],
                },
                {
                    "type": "heading",
                    "attrs": {"level": 3},
                    "content": [{"type": "text", "text": "Detalles del Hallazgo"}],
                },
                {
                    "type": "bulletList",
                    "content": [
                        {"type": "listItem", "content": [{"type": "paragraph", "content": [{"type": "text", "text": f"URL Afectada: {finding.affected_url or 'N/A'}"}]}]},
                        {"type": "listItem", "content": [{"type": "paragraph", "content": [{"type": "text", "text": f"Puntuación CVSS: {finding.cvss_score} ({finding.cvss_vector})"}]}]},
                        {"type": "listItem", "content": [{"type": "paragraph", "content": [{"type": "text", "text": f"Estándar: {finding.cwe_id} — {finding.cwe_name}"}]}]},
                        {"type": "listItem", "content": [{"type": "paragraph", "content": [{"type": "text", "text": f"Categoría OWASP: {finding.owasp_category}"}]}]},
                    ],
                },
                {
                    "type": "heading",
                    "attrs": {"level": 3},
                    "content": [{"type": "text", "text": "Reproducción (cURL)"}],
                },
                {
                    "type": "codeBlock",
                    "attrs": {"language": "bash"},
                    "content": [{"type": "text", "text": curl_cmd}],
                },
                {
                    "type": "heading",
                    "attrs": {"level": 3},
                    "content": [{"type": "text", "text": "Recomendación de Mitigación"}],
                },
                {
                    "type": "paragraph",
                    "content": [{"type": "text", "text": finding.remediation or "Revisar arquitectura y aplicar controles de defensa en profundidad."}],
                },
            ],
        }

        payload: dict[str, Any] = {
            "fields": {
                "project": {"key": self.project_key},
                "summary": f"[OmniBreach] {finding.severity.upper()}: {finding.title}",
                "description": description_adf,
                "issuetype": {"name": self.issue_type},
                "priority": {"name": priority_name},
                "labels": [
                    "omnibreach",
                    "security",
                    f"cwe-{finding.cwe_id.lower().replace('cwe-', '')}",
                    finding.category,
                ],
            }
        }

        try:
            resp = self.session.post(
                api_endpoint,
                json=payload,
                auth=HTTPBasicAuth(self.email, self.api_token),
                headers={"Accept": "application/json", "Content-Type": "application/json"},
                timeout=10,
            )
            if resp.status_code in (200, 201):
                data: dict[str, Any] = resp.json()
                logger.info("[Jira] Issue creado con éxito: %s", data.get("key"))
                return data
            logger.warning("[Jira] Error al crear issue (%d): %s", resp.status_code, resp.text)
        except Exception as exc:
            logger.error("[Jira] Excepción despachando ticket a Jira: %s", exc)

        return None


class SlackConnector:
    """Conector con Webhooks Entrantes de Slack con formato interactivo Block Kit."""

    def __init__(self, webhook_url: str, session: requests.Session | None = None) -> None:
        self.webhook_url = webhook_url
        self.session = session or requests.Session()

    def send_alert(self, finding: Finding) -> bool:
        """Envía una notificación enriquecida a un canal de Slack."""
        emoji = SEVERITY_EMOJIS.get(finding.severity.lower(), "⚠️")

        blocks: list[dict[str, Any]] = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{emoji} OmniBreach Alerta: {finding.title}",
                    "emoji": True,
                },
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Severidad:*\n`{finding.severity.upper()}`"},
                    {"type": "mrkdwn", "text": f"*CVSS v3.1:*\n*{finding.cvss_score}*"},
                    {"type": "mrkdwn", "text": f"*Categoría:*\n{finding.owasp_category}"},
                    {"type": "mrkdwn", "text": f"*CWE:*\n{finding.cwe_id}"},
                ],
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*URL Objetivo:*\n`{finding.affected_url or 'N/A'}`\n\n*Descripción:*\n{finding.description[:350]}",
                },
            },
        ]

        if finding.remediation:
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Mitigación Sugerida:*\n{finding.remediation[:300]}",
                },
            })

        payload = {"blocks": blocks}

        try:
            resp = self.session.post(self.webhook_url, json=payload, timeout=8)
            if resp.status_code == 200:
                logger.info("[Slack] Alerta enviada exitosamente para '%s'", finding.title)
                return True
            logger.warning("[Slack] Webhook respondió con código %d: %s", resp.status_code, resp.text)
        except Exception as exc:
            logger.error("[Slack] Error enviando alerta a Slack: %s", exc)

        return False


class TeamsConnector:
    """Conector con Webhooks Entrantes de Microsoft Teams (MessageCard / Adaptive Card)."""

    def __init__(self, webhook_url: str, session: requests.Session | None = None) -> None:
        self.webhook_url = webhook_url
        self.session = session or requests.Session()

    def send_alert(self, finding: Finding) -> bool:
        """Envía una tarjeta estructurada a Microsoft Teams."""
        color = SEVERITY_COLORS.get(finding.severity.lower(), "#757575").replace("#", "")
        emoji = SEVERITY_EMOJIS.get(finding.severity.lower(), "⚠️")

        payload = {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": color,
            "summary": f"{emoji} Alerta OmniBreach: {finding.title}",
            "sections": [
                {
                    "activityTitle": f"{emoji} OmniBreach: {finding.title}",
                    "activitySubtitle": f"Severidad: **{finding.severity.upper()}** | CVSS: **{finding.cvss_score}**",
                    "facts": [
                        {"name": "URL Afectada", "value": finding.affected_url or "N/A"},
                        {"name": "CWE / Norma", "value": f"{finding.cwe_id} — {finding.cwe_name}"},
                        {"name": "OWASP", "value": finding.owasp_category},
                        {"name": "Parámetro", "value": finding.parameter or "N/A"},
                    ],
                    "text": finding.description,
                },
                {
                    "title": "Recomendación de Seguridad",
                    "text": finding.remediation or "Implementar validación y controles defensivos.",
                },
            ],
        }

        try:
            resp = self.session.post(self.webhook_url, json=payload, timeout=8)
            if resp.status_code in (200, 201):
                logger.info("[Teams] Alerta enviada exitosamente a MS Teams para '%s'", finding.title)
                return True
            logger.warning("[Teams] Webhook respondió con código %d: %s", resp.status_code, resp.text)
        except Exception as exc:
            logger.error("[Teams] Error enviando alerta a MS Teams: %s", exc)

        return False


class GitHubIssuesConnector:
    """Conector para apertura automatizada de GitHub Issues en el repositorio corporativo."""

    def __init__(self, repo: str, token: str, session: requests.Session | None = None) -> None:
        self.repo = repo
        self.token = token
        self.session = session or requests.Session()

    def create_issue(self, finding: Finding) -> dict[str, Any] | None:
        url = f"https://api.github.com/repos/{self.repo}/issues"
        headers = {
            "Authorization": f"token {self.token}",
            "Accept": "application/vnd.github.v3+json",
        }

        body_md = (
            f"### 🛡️ Reporte Automatizado de Seguridad — OmniBreach\n\n"
            f"**Severidad:** `{finding.severity.upper()}` | **CVSS v3.1:** `{finding.cvss_score}`\n"
            f"**URL Afectada:** `{finding.affected_url or 'N/A'}`\n"
            f"**Norma / CWE:** `{finding.cwe_id} — {finding.cwe_name}`\n"
            f"**Categoría:** `{finding.owasp_category}`\n\n"
            f"#### Descripción\n{finding.description}\n\n"
        )

        if finding.evidence:
            body_md += (
                f"#### Evidencia Técnica\n"
                f"- **Método:** `{finding.evidence.request_method}`\n"
                f"- **Payload:** `{finding.evidence.payload or 'N/A'}`\n"
                f"- **Código de Respuesta:** `{finding.evidence.response_status or 'N/A'}`\n\n"
            )

        if finding.remediation:
            body_md += f"#### Remediación Sugerida\n{finding.remediation}\n"

        payload = {
            "title": f"[Security] {finding.severity.upper()}: {finding.title}",
            "body": body_md,
            "labels": ["security", f"severity:{finding.severity.lower()}", "automated-audit"],
        }

        try:
            resp = self.session.post(url, json=payload, headers=headers, timeout=10)
            if resp.status_code in (200, 201):
                data: dict[str, Any] = resp.json()
                logger.info("[GitHub] Issue #%s abierto exitosamente en %s", data.get("number"), self.repo)
                return data
            logger.warning("[GitHub] Error al crear issue (%d): %s", resp.status_code, resp.text)
        except Exception as exc:
            logger.error("[GitHub] Error conectando con API de GitHub: %s", exc)

        return None


@dataclass
class NotificationDispatcher:
    """Orquestador unificado de integraciones y despacho con deduplicación."""

    min_severity: str = "high"
    dedup_store: DeduplicationStore = field(default_factory=DeduplicationStore)
    jira: JiraConnector | None = None
    slack: SlackConnector | None = None
    teams: TeamsConnector | None = None
    github: GitHubIssuesConnector | None = None

    @classmethod
    def from_environment(
        cls,
        min_severity: str = "high",
        dedup_file: str | None = ".omnibreach_dedup.json",
        session: requests.Session | None = None,
    ) -> NotificationDispatcher:
        """Crea el despachador leyendo variables de entorno disponibles."""
        store = DeduplicationStore(dedup_file)
        sess = session or requests.Session()

        # Jira
        jira_conn: JiraConnector | None = None
        j_url = os.environ.get("JIRA_URL")
        j_email = os.environ.get("JIRA_EMAIL")
        j_token = os.environ.get("JIRA_API_TOKEN")
        j_proj = os.environ.get("JIRA_PROJECT_KEY")
        if j_url and j_email and j_token and j_proj:
            jira_conn = JiraConnector(j_url, j_email, j_token, j_proj, session=sess)

        # Slack
        slack_conn: SlackConnector | None = None
        s_url = os.environ.get("SLACK_WEBHOOK_URL")
        if s_url:
            slack_conn = SlackConnector(s_url, session=sess)

        # Teams
        teams_conn: TeamsConnector | None = None
        t_url = os.environ.get("TEAMS_WEBHOOK_URL")
        if t_url:
            teams_conn = TeamsConnector(t_url, session=sess)

        # GitHub
        gh_conn: GitHubIssuesConnector | None = None
        gh_repo = os.environ.get("GITHUB_REPOSITORY")
        gh_token = os.environ.get("GITHUB_TOKEN")
        if gh_repo and gh_token:
            gh_conn = GitHubIssuesConnector(gh_repo, gh_token, session=sess)

        return cls(
            min_severity=min_severity,
            dedup_store=store,
            jira=jira_conn,
            slack=slack_conn,
            teams=teams_conn,
            github=gh_conn,
        )

    def dispatch_finding(self, finding: Finding) -> dict[str, bool]:
        """
        Evalúa un hallazgo, aplica filtro de severidad mínima, deduplicación
        y despacha a todos los canales configurados.
        """
        results: dict[str, bool] = {"jira": False, "slack": False, "teams": False, "github": False}

        # 1. Filtro por severidad mínima
        min_level = SEVERITY_LEVELS.get(self.min_severity.lower(), 2)
        finding_level = SEVERITY_LEVELS.get(finding.severity.lower(), 0)
        if finding_level < min_level:
            logger.debug("Hallazgo '%s' omitido por severidad (%s < %s)", finding.title, finding.severity, self.min_severity)
            return results

        # 2. Comprobar deduplicación
        fingerprint = calculate_finding_fingerprint(finding)
        if self.dedup_store.is_dispatched(fingerprint):
            logger.info("[Deduplicación] Omitiendo alerta repetida para '%s' (Fingerprint: %s)", finding.title, fingerprint[:12])
            return results

        dispatched_any = False

        # 3. Despacho a Jira
        if self.jira:
            res_jira = self.jira.create_issue(finding)
            if res_jira:
                results["jira"] = True
                dispatched_any = True

        # 4. Despacho a Slack
        if self.slack:
            res_slack = self.slack.send_alert(finding)
            if res_slack:
                results["slack"] = True
                dispatched_any = True

        # 5. Despacho a Teams
        if self.teams:
            res_teams = self.teams.send_alert(finding)
            if res_teams:
                results["teams"] = True
                dispatched_any = True

        # 6. Despacho a GitHub Issues
        if self.github:
            res_gh = self.github.create_issue(finding)
            if res_gh:
                results["github"] = True
                dispatched_any = True

        # 7. Marcar como despachado si al menos un canal tuvo éxito
        if dispatched_any:
            self.dedup_store.mark_dispatched(fingerprint)

        return results

    def dispatch_all(self, findings: list[Finding]) -> dict[str, int]:
        """Despacha una lista completa de hallazgos y retorna el conteo de alertas emitidas por canal."""
        stats = {"jira": 0, "slack": 0, "teams": 0, "github": 0, "total_processed": len(findings)}
        for f in findings:
            r = self.dispatch_finding(f)
            for k in ("jira", "slack", "teams", "github"):
                if r.get(k):
                    stats[k] += 1
        return stats
