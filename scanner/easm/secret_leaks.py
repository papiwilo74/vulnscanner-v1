"""
Módulo de Detección de Fuga de Secretos en Repositorios Públicos (Secret Leaks OSINT).
Monitorea la exposición involuntaria de credenciales, claves de API, tokens de nube
y cadenas de conexión de bases de datos corporativas en repositorios de código abiertos.
"""
from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field
from typing import Any

import requests

logger = logging.getLogger("OmniBreach.EASM.SecretLeaks")

# Patrones de alta precisión para evitar falsos positivos
SECRET_PATTERNS: list[dict[str, Any]] = [
    {
        "type": "AWS Access Key",
        "pattern": r"AKIA[0-9A-Z]{16}",
        "severity": "CRITICAL",
        "description": "Clave de acceso de AWS Identity and Access Management (IAM).",
        "remediation": "Revocar inmediatamente la clave en la consola AWS IAM y auditar eventos en AWS CloudTrail.",
    },
    {
        "type": "GitHub Personal Access Token",
        "pattern": r"ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{82}",
        "severity": "CRITICAL",
        "description": "Token de acceso personal de GitHub con permisos sobre repositorios corporativos.",
        "remediation": "Revocar el token en GitHub Settings > Developer settings > Personal access tokens.",
    },
    {
        "type": "Stripe Live Secret Key",
        "pattern": r"sk_live_[0-9a-zA-Z]{24,32}",
        "severity": "CRITICAL",
        "description": "Clave secreta de producción de la pasarela de pagos Stripe.",
        "remediation": "Rotar la API Key de Stripe de inmediato en el dashboard y verificar transacciones recientes.",
    },
    {
        "type": "Google / Firebase API Key",
        "pattern": r"AIza[0-9A-Za-z\-_]{35}",
        "severity": "HIGH",
        "description": "Clave de API de Google Cloud Platform o Firebase expuesta públicamente.",
        "remediation": "Restringir la clave en Google Cloud Console por IP o HTTP Referrer.",
    },
    {
        "type": "Slack Incoming Webhook",
        "pattern": r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+",
        "severity": "HIGH",
        "description": "Webhook entrante de Slack. Permite publicar mensajes y suplantar canales corporativos.",
        "remediation": "Revocar el Webhook en la app de Slack y generar uno nuevo.",
    },
    {
        "type": "Database Connection String",
        "pattern": r"(?:postgres|postgresql|mysql|mongodb|redis)://[a-zA-Z0-9_]+:[^@\s]{4,}@[a-zA-Z0-9.-]+:[0-9]+",
        "severity": "CRITICAL",
        "description": "Cadena de conexión directa a base de datos con usuario y contraseña embebidos.",
        "remediation": "Cambiar la contraseña del usuario en la base de datos y migrar a variables de entorno o Secrets Manager.",
    },
    {
        "type": "Private RSA / SSH Key",
        "pattern": r"-----BEGIN (?:RSA|OPENSSH|EC|DSA) PRIVATE KEY-----",
        "severity": "CRITICAL",
        "description": "Clave criptográfica privada SSH/RSA.",
        "remediation": "Eliminar la clave autorizada en servidores (`~/.ssh/authorized_keys`) y generar un nuevo par de llaves.",
    },
]


def mask_secret(secret: str) -> str:
    """Oculta la mayor parte del secreto para no exponerlo en reportes o logs."""
    if len(secret) <= 8:
        return "****"
    prefix = secret[:4]
    suffix = secret[-4:]
    return f"{prefix}{'*' * (len(secret) - 8)}{suffix}"


@dataclass
class SecretLeakFinding:
    """Representa una credencial o secreto corporativo filtrado."""
    secret_type: str
    severity: str
    masked_value: str
    source_repository: str
    description: str
    remediation: str
    file_path: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "secret_type": self.secret_type,
            "severity": self.severity,
            "masked_value": self.masked_value,
            "source_repository": self.source_repository,
            "description": self.description,
            "remediation": self.remediation,
            "file_path": self.file_path,
        }


class SecretLeakScanner:
    """Escanea y detecta fugas de credenciales en repositorios públicos."""

    def __init__(
        self,
        github_token: str | None = None,
        patterns: list[dict[str, Any]] | None = None,
        timeout: float = 6.0,
    ):
        self.github_token = github_token or os.environ.get("GITHUB_TOKEN")
        self.patterns = patterns or SECRET_PATTERNS
        self.timeout = timeout

    def scan_content(self, text_content: str, source_ref: str = "snippet") -> list[SecretLeakFinding]:
        """Analiza un bloque de texto en busca de patrones de secretos conocidos."""
        findings: list[SecretLeakFinding] = []
        if not text_content:
            return findings

        for p in self.patterns:
            matches = re.finditer(p["pattern"], text_content)
            for m in matches:
                matched_raw = m.group(0)
                findings.append(
                    SecretLeakFinding(
                        secret_type=p["type"],
                        severity=p["severity"],
                        masked_value=mask_secret(matched_raw),
                        source_repository=source_ref,
                        description=p["description"],
                        remediation=p["remediation"],
                    )
                )

        return findings

    def search_public_leaks(self, domain: str, max_results: int = 5) -> list[SecretLeakFinding]:
        """
        Consulta la API de búsqueda de código en GitHub para identificar posibles fugas
        relacionadas con el dominio de la organización.
        """
        findings: list[SecretLeakFinding] = []
        clean_domain = domain.strip().lower()
        if not clean_domain:
            return findings

        # Si no hay token de GitHub configurado, no realizamos consultas para evitar rate-limits de 403
        if not self.github_token:
            logger.debug("[SECRET OSINT] GITHUB_TOKEN no configurado. Omitiendo consultas remotas a la API de GitHub.")
            return findings

        headers = {
            "Authorization": f"token {self.github_token}",
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "OmniBreach-SecretScout/3.5",
        }

        # Buscar menciones al dominio corporativo junto con palabras clave sensibles
        query = f'"{clean_domain}" (password OR secret OR token OR AKIA)'
        url = f"https://api.github.com/search/code?q={query}&per_page={max_results}"

        try:
            resp = requests.get(url, headers=headers, timeout=8)
            if resp.status_code == 200:
                data = resp.json()
                items = data.get("items", [])
                for item in items:
                    repo_name = item.get("repository", {}).get("full_name", "Desconocido")
                    html_url = item.get("html_url", "")
                    file_path = item.get("path", "")

                    # 1. Inspeccionar ruta o URL
                    for p in self.patterns:
                        if re.search(p["pattern"], file_path) or re.search(p["pattern"], html_url):
                            findings.append(
                                SecretLeakFinding(
                                    secret_type=p["type"],
                                    severity=p["severity"],
                                    masked_value="Detectado en ruta o URL",
                                    source_repository=repo_name,
                                    description=p["description"],
                                    remediation=p["remediation"],
                                    file_path=html_url,
                                )
                            )

                    # 2. Intentar inspeccionar contenido raw si es accesible
                    if html_url and "github.com" in html_url and "/blob/" in html_url:
                        raw_url = html_url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
                        try:
                            raw_resp = requests.get(raw_url, headers=headers, timeout=self.timeout)
                            if raw_resp.status_code == 200:
                                raw_findings = self.scan_content(raw_resp.text, source_ref=repo_name)
                                for rf in raw_findings:
                                    rf.file_path = html_url
                                findings.extend(raw_findings)
                        except Exception as raw_err:
                            logger.debug("[SECRET OSINT] No se pudo leer raw content: %s", raw_err)
            elif resp.status_code == 403:
                logger.warning("[SECRET OSINT] Límite de tasa excedido en la API de GitHub Search.")
        except Exception as err:
            logger.debug("[SECRET OSINT] No se pudo consultar GitHub Search: %s", err)

        return findings
