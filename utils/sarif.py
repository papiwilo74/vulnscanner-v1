"""Generador de reportes en formato OASIS SARIF v2.1.0 para VulnScanner.

SARIF (Static Analysis Results Interchange Format) es el estándar industrial adoptado por
GitHub Advanced Security, GitLab, Azure DevOps y herramientas de gestión de vulnerabilidades (ASPM).
"""
from typing import Any

from scanner.models import VULN_STANDARDS_DB


def generate_sarif_v210(url: str, findings: list, duration: float = 0.0) -> dict[str, Any]:
    """Genera un documento JSON SARIF v2.1.0 totalmente compatible con GitHub Code Scanning.

    Args:
        url: URL analizada.
        findings: Lista de objetos Finding o diccionarios normalizados.
        duration: Duración total del escaneo en segundos.

    Returns:
        Diccionario con la estructura oficial SARIF v2.1.0.
    """
    rules_dict: dict[str, dict[str, Any]] = {}
    results_list: list[dict[str, Any]] = []

    for f in findings:
        # Extraer datos ya sea de un Finding o dict legacy
        if hasattr(f, "to_dict"):
            data = f.to_dict()
        else:
            data = f

        category = data.get("category", "default").lower()
        rule_id = f"VULN-{category.upper()}"
        title = data.get("title") or data.get("vuln", "Vulnerabilidad detectada")
        severity = data.get("severity", "info")
        risk = data.get("risk", "Bajo")
        description = data.get("description") or data.get("detail", "")
        affected_url = data.get("affected_url") or url
        param = data.get("parameter")
        cvss_score = data.get("cvss_score", 0.0)
        cvss_vector = data.get("cvss_vector", "")
        cwe_id = data.get("cwe_id", "CWE-693")
        cwe_name = data.get("cwe_name", "")
        mitre_id = data.get("mitre_attack_id", "T1190")
        mitre_name = data.get("mitre_attack_name", "")
        autofix = data.get("autofix")
        confidence = data.get("confidence", "possible")

        # Nivel SARIF (error, warning, note)
        if severity in ("critical", "high") or risk == "Alto":
            sarif_level = "error"
            problem_severity = "error"
        elif severity == "medium" or risk == "Medio":
            sarif_level = "warning"
            problem_severity = "warning"
        else:
            sarif_level = "note"
            problem_severity = "recommendation"

        # Registrar la regla única en el catálogo de reglas del driver
        if rule_id not in rules_dict:
            std_info = VULN_STANDARDS_DB.get(category, VULN_STANDARDS_DB.get("default", {}))
            tags = ["security", "vulnerability", cwe_id, mitre_id]
            if std_info.get("owasp_category"):
                tags.append(std_info["owasp_category"])

            rules_dict[rule_id] = {
                "id": rule_id,
                "name": category.replace("_", " ").title() + " Rule",
                "shortDescription": {"text": title},
                "fullDescription": {"text": description or f"Regla de detección para {category}"},
                "defaultConfiguration": {
                    "level": sarif_level
                },
                "help": {
                    "text": (
                        f"Vulnerabilidad: {title}\n"
                        f"CWE: {cwe_id} - {cwe_name}\n"
                        f"MITRE ATT&CK: {mitre_id} - {mitre_name}\n"
                        f"CVSS v3.1: {cvss_score} ({cvss_vector})\n"
                        f"Solución: {data.get('remediation', 'Revisar la configuración y aplicar parches recomendados.')}"
                    ),
                    "markdown": (
                        f"### {title}\n\n"
                        f"**Estándares de Seguridad:**\n"
                        f"- **CWE**: [{cwe_id}](https://cwe.mitre.org/data/definitions/{cwe_id.replace('CWE-', '')}.html) - {cwe_name}\n"
                        f"- **MITRE ATT&CK**: [{mitre_id}](https://attack.mitre.org/techniques/{mitre_id}/) - {mitre_name}\n"
                        f"- **CVSS v3.1 Base Score**: `{cvss_score}` (`{cvss_vector}`)\n\n"
                        f"**Remediación:**\n"
                        f"{data.get('remediation', 'Revisar la configuración y aplicar parches recomendados.')}"
                    )
                },
                "properties": {
                    "tags": tags,
                    "precision": "very-high" if confidence == "confirmed" else "high",
                    "problem.severity": problem_severity,
                    "security-severity": str(cvss_score) if cvss_score > 0 else "5.0",
                }
            }

        # Construir el objeto de resultado individual
        location_uri = affected_url
        result_item: dict[str, Any] = {
            "ruleId": rule_id,
            "ruleIndex": list(rules_dict.keys()).index(rule_id),
            "level": sarif_level,
            "message": {
                "text": f"{title} detectado en {affected_url}" + (f" (parámetro '{param}')" if param else "") + f". Detalle: {description}"
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": location_uri,
                            "uriBaseId": "%SRCROOT%"
                        },
                        "region": {
                            "startLine": 1,
                            "startColumn": 1
                        }
                    }
                }
            ],
            "properties": {
                "confidence": confidence,
                "severity": severity,
                "cvssScore": cvss_score,
                "cvssVector": cvss_vector,
                "cweId": cwe_id,
                "mitreAttackId": mitre_id,
                "parameter": param,
            }
        }

        # Incorporar parche de código seguro como 'fixes' de SARIF si existe
        if autofix:
            result_item["fixes"] = [
                {
                    "description": {
                        "text": f"Parche sugerido para {autofix.get('technology', 'framework')} ({autofix.get('filename', 'config')})"
                    },
                    "fileChanges": [
                        {
                            "artifactLocation": {
                                "uri": autofix.get("filename", "config.js")
                            },
                            "replacements": [
                                {
                                    "deletedRegion": {"startLine": 1},
                                    "insertedContent": {"text": autofix.get("code_snippet", "")}
                                }
                            ]
                        }
                    ]
                }
            ]

        results_list.append(result_item)

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "VulnScanner",
                        "organization": "VulnScanner Security",
                        "semanticVersion": "2.0.0",
                        "version": "2.0.0",
                        "informationUri": "https://github.com/papiwilo74/vulnscanner-v1",
                        "rules": list(rules_dict.values())
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "endTimeUtc": None,
                    }
                ],
                "results": results_list
            }
        ]
    }
