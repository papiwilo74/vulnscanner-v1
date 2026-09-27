"""
Generador de Reportes SARIF v2.1.0 (Static Analysis Results Interchange Format).
Permite integrar los hallazgos de OmniBreach de manera nativa con GitHub Advanced Security,
GitLab SAST/DAST y herramientas compatibles con el estándar OASIS SARIF v2.1.0.
"""
from __future__ import annotations

import json
import logging
from collections.abc import Sequence
from typing import Any

from scanner.models import Finding

logger = logging.getLogger("OmniBreach.SARIF")

SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
OMNIBREACH_VERSION = "3.9"

SEVERITY_LEVEL_MAP = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


def _finding_to_rule(finding: Finding | dict[str, Any]) -> dict[str, Any]:
    """Extrae la definición de regla SARIF desde un hallazgo."""
    if isinstance(finding, Finding):
        cat = finding.category
        title = finding.title
        desc = finding.description or finding.title
        cwe = finding.cwe_id or "CWE-693"
        cvss = finding.cvss_score
        owasp = finding.owasp_category or "Security Misconfiguration"
    else:
        cat = str(finding.get("category", "generic"))
        title = str(finding.get("title", "Vulnerabilidad detectada"))
        desc = str(finding.get("description", title))
        cwe = str(finding.get("cwe_id", "CWE-693"))
        cvss = float(finding.get("cvss_score", 0.0))
        owasp = str(finding.get("owasp_category", "Security Misconfiguration"))

    rule_id = f"OMNI-{cat.upper()}"
    return {
        "id": rule_id,
        "name": cat.replace("_", " ").title().replace(" ", ""),
        "shortDescription": {"text": title},
        "fullDescription": {"text": desc},
        "help": {
            "text": f"Vulnerabilidad {title}. Clasificación: {cwe}, {owasp}. Puntuación CVSS v3.1: {cvss}.",
            "markdown": f"### {title}\n\n{desc}\n\n* **CWE:** {cwe}\n* **OWASP:** {owasp}\n* **CVSS Score:** {cvss}",
        },
        "properties": {
            "tags": ["security", "dast", cat, cwe.lower()],
            "precision": "high",
            "security-severity": str(cvss if cvss > 0 else 5.0),
        },
    }


def _finding_to_result(finding: Finding | dict[str, Any], default_uri: str = "app/endpoint") -> dict[str, Any]:
    """Convierte un hallazgo de OmniBreach en un resultado SARIF."""
    if isinstance(finding, Finding):
        cat = finding.category
        title = finding.title
        severity = finding.severity.lower()
        desc = finding.description or finding.title
        url = finding.affected_url or (finding.evidence.request_url if finding.evidence else "") or default_uri
        line = finding.iast_source_line or 1
        source_file = finding.iast_source_file or url
    else:
        cat = str(finding.get("category", "generic"))
        title = str(finding.get("title", "Finding"))
        severity = str(finding.get("severity", "medium")).lower()
        desc = str(finding.get("description", title))
        url = str(finding.get("affected_url", default_uri))
        line = int(finding.get("iast_source_line", 1) or 1)
        source_file = str(finding.get("iast_source_file", url))

    level = SEVERITY_LEVEL_MAP.get(severity, "warning")
    rule_id = f"OMNI-{cat.upper()}"

    return {
        "ruleId": rule_id,
        "level": level,
        "message": {
            "text": f"[{severity.upper()}] {title} detectado en {url}. {desc}",
        },
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": source_file,
                        "uriBaseId": "%SRCROOT%",
                    },
                    "region": {
                        "startLine": max(line, 1),
                        "startColumn": 1,
                    },
                },
            },
        ],
    }


def export_findings_to_sarif(
    findings: Sequence[Finding | dict[str, Any]],
    scan_url: str = "",
) -> dict[str, Any]:
    """
    Convierte una lista de hallazgos en un documento SARIF v2.1.0 listo para
    GitHub Code Scanning (`github/codeql-action/upload-sarif`).
    """
    rules_dict: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    for f in findings:
        rule = _finding_to_rule(f)
        rules_dict[rule["id"]] = rule
        result = _finding_to_result(f, default_uri=scan_url or "app/web")
        results.append(result)

    sarif_doc = {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "OmniBreach DAST",
                        "semanticVersion": OMNIBREACH_VERSION,
                        "informationUri": "https://github.com/papiwilo74/vulnscanner-v1",
                        "rules": list(rules_dict.values()),
                    },
                },
                "results": results,
            },
        ],
    }
    return sarif_doc


def save_sarif_file(sarif_data: dict[str, Any], output_path: str) -> None:
    """Guarda el documento SARIF en el disco en formato JSON legible."""
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(sarif_data, f, indent=2, ensure_ascii=False)
    logger.info("[SARIF] Reporte SARIF exportado exitosamente en: %s", output_path)
