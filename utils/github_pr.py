"""Módulo de Integración DevSecOps y Auto-PR con GitHub.

Permite a VulnScanner interactuar con la API REST de GitHub para:
- Crear ramas automáticas de remediación (remediation branches).
- Aplicar parches de código seguro (headers, vercel.json, middleware, etc.).
- Abrir Pull Requests automáticos con análisis CVSS v3.1, CWE y justificación técnica.
"""
from __future__ import annotations

import base64
import logging
from typing import Any, cast

import requests

from scanner.models import Finding

logger = logging.getLogger("VulnScanner.GitHubPR")


class GitHubPRClient:
    """Cliente para la API REST de GitHub v3 orientado a auto-remediación."""

    def __init__(self, token: str, repo: str, base_url: str = "https://api.github.com"):
        """
        Args:
            token: Token de acceso personal (PAT) de GitHub con permisos repo/pull-requests.
            repo: Repositorio en formato 'owner/repo' (ej. 'papiwilo74/mi-proyecto').
            base_url: URL base de la API de GitHub (permite GitHub Enterprise).
        """
        self.token = token.strip()
        self.repo = repo.strip()
        self.base_url = base_url.rstrip("/")
        self.headers = {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "VulnScanner-Enterprise-Bot/2.3.0",
        }

    def _get(self, endpoint: str) -> dict[str, Any]:
        url = f"{self.base_url}/repos/{self.repo}/{endpoint.lstrip('/')}"
        resp = requests.get(url, headers=self.headers, timeout=15)
        if resp.status_code >= 400:
            raise RuntimeError(f"GitHub API Error {resp.status_code}: {resp.text}")
        return cast(dict[str, Any], resp.json())

    def _post(self, endpoint: str, payload: dict[str, Any]) -> dict[str, Any]:
        url = f"{self.base_url}/repos/{self.repo}/{endpoint.lstrip('/')}"
        resp = requests.post(url, headers=self.headers, json=payload, timeout=15)
        if resp.status_code >= 400:
            raise RuntimeError(f"GitHub API Error {resp.status_code}: {resp.text}")
        return cast(dict[str, Any], resp.json())

    def _put(self, endpoint: str, payload: dict[str, Any]) -> dict[str, Any]:
        url = f"{self.base_url}/repos/{self.repo}/{endpoint.lstrip('/')}"
        resp = requests.put(url, headers=self.headers, json=payload, timeout=15)
        if resp.status_code >= 400:
            raise RuntimeError(f"GitHub API Error {resp.status_code}: {resp.text}")
        return cast(dict[str, Any], resp.json())

    def get_default_branch_sha(self, branch: str = "main") -> str:
        """Obtiene el SHA del último commit de la rama base."""
        data = self._get(f"git/ref/heads/{branch}")
        return cast(str, data["object"]["sha"])

    def create_branch(self, branch_name: str, base_sha: str) -> dict[str, Any]:
        """Crea una nueva referencia de rama en el repositorio."""
        payload = {
            "ref": f"refs/heads/{branch_name}",
            "sha": base_sha,
        }
        return self._post("git/refs", payload)

    def commit_file(
        self,
        branch: str,
        path: str,
        content: str,
        commit_message: str,
    ) -> dict[str, Any]:
        """Crea o actualiza un archivo en la rama especificada."""
        # Verificar si el archivo ya existe para incluir su SHA
        file_sha: str | None = None
        try:
            existing = self._get(f"contents/{path}?ref={branch}")
            if "sha" in existing:
                file_sha = existing["sha"]
        except Exception:
            file_sha = None

        encoded_content = base64.b64encode(content.encode("utf-8")).decode("utf-8")
        payload: dict[str, Any] = {
            "message": commit_message,
            "content": encoded_content,
            "branch": branch,
        }
        if file_sha:
            payload["sha"] = file_sha

        return self._put(f"contents/{path}", payload)

    def create_pull_request(
        self,
        title: str,
        body: str,
        head_branch: str,
        base_branch: str = "main",
    ) -> dict[str, Any]:
        """Abre un Pull Request hacia la rama base."""
        payload = {
            "title": title,
            "body": body,
            "head": head_branch,
            "base": base_branch,
        }
        return self._post("pulls", payload)

    def generate_pr_body(self, findings: list[Finding], target_url: str) -> str:
        """Construye un cuerpo de Pull Request en Markdown con matriz CVSS y explicación."""
        body = [
            "## 🛡️ VulnScanner Enterprise — Auto-Remediation Patch",
            f"Este Pull Request fue generado automáticamente para resolver vulnerabilidades detectadas en: `{target_url}`.\n",
            "### 📋 Hallazgos Atendidos:",
            "| Severidad | Vulnerabilidad | CVSS v3.1 | CWE | MITRE ATT&CK |",
            "| :--- | :--- | :--- | :--- | :--- |",
        ]
        for f in findings[:15]:
            sev_badge = f"**{f.severity.upper()}**"
            cwe = f.cwe_id or "N/A"
            mitre = f.mitre_attack_id or "N/A"
            body.append(f"| {sev_badge} | {f.title} | {f.cvss_score:.1f} | {cwe} | {mitre} |")

        body.extend([
            "\n### 🔧 Cambios Realizados:",
            "- Incorporación de directivas y cabeceras de seguridad recomendadas (`Content-Security-Policy`, `Strict-Transport-Security`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`).",
            "- Mitigación contra ataques de Cross-Site Scripting (XSS), Clickjacking, MIME-Sniffing y SSL Stripping.",
            "\n### 🧪 Verificación:",
            "Se recomienda ejecutar la suite de pruebas unitarias y volver a escanear con `python main.py <url>` tras desplegar.",
            "\n---\n*Generado automáticamente por VulnScanner Enterprise v2.3.0 DevSecOps Bot.*"
        ])
        return "\n".join(body)

    def auto_remediate_and_open_pr(
        self,
        findings: list[Finding],
        target_url: str,
        base_branch: str = "main",
    ) -> dict[str, Any]:
        """Flujo completo autónomo: crea rama, aplica parches y abre el PR."""
        if not findings:
            logger.info("No hay hallazgos para auto-remediar.")
            return {"status": "skipped", "message": "Sin hallazgos"}

        import time
        import uuid
        run_id = uuid.uuid4().hex[:6]
        branch_name = f"vulnscanner/remediation-{int(time.time())}-{run_id}"

        logger.info("[Auto-PR] Obteniendo commit base de '%s'...", base_branch)
        base_sha = self.get_default_branch_sha(base_branch)

        logger.info("[Auto-PR] Creando rama '%s'...", branch_name)
        self.create_branch(branch_name, base_sha)

        # Determinar parche a aplicar según los hallazgos
        patch_file = "vercel.json"
        patch_content = """{
  "headers": [
    {
      "source": "/(.*)",
      "headers": [
        {
          "key": "Content-Security-Policy",
          "value": "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com data:; img-src 'self' data: https: blob:; connect-src 'self' https:; frame-ancestors 'none';"
        },
        {
          "key": "Strict-Transport-Security",
          "value": "max-age=31536000; includeSubDomains; preload"
        },
        {
          "key": "X-Frame-Options",
          "value": "DENY"
        },
        {
          "key": "X-Content-Type-Options",
          "value": "nosniff"
        },
        {
          "key": "Referrer-Policy",
          "value": "strict-origin-when-cross-origin"
        },
        {
          "key": "Permissions-Policy",
          "value": "camera=(), microphone=(), geolocation=()"
        }
      ]
    }
  ]
}
"""
        # Si alguno de los hallazgos tiene parche generado por autofix, lo aplicamos
        for f in findings:
            if f.autofix and isinstance(f.autofix, dict):
                patch_file = f.autofix.get("file", patch_file)
                patch_content = f.autofix.get("patch", patch_content)
                break

        logger.info("[Auto-PR] Aplicando commit a '%s' en la rama '%s'...", patch_file, branch_name)
        self.commit_file(
            branch=branch_name,
            path=patch_file,
            content=patch_content,
            commit_message="security: aplicar parches y cabeceras de defensa recomendadas por VulnScanner",
        )

        logger.info("[Auto-PR] Abriendo Pull Request hacia '%s'...", base_branch)
        pr_title = f"fix(security): remediación automática de {len(findings)} vulnerabilidades detectadas"
        pr_body = self.generate_pr_body(findings, target_url)

        pr_res = self.create_pull_request(
            title=pr_title,
            body=pr_body,
            head_branch=branch_name,
            base_branch=base_branch,
        )

        logger.info("[Auto-PR] ¡Pull Request creado exitosamente!: %s", pr_res.get("html_url"))
        return pr_res
