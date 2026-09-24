"""Motor de Cumplimiento Normativo (Compliance Engine) para OmniBreach v3.8.

Mapea hallazgos de seguridad contra los principales estándares y marcos regulatorios:
- PCI-DSS v4.0 (Payment Card Industry Data Security Standard)
- OWASP Top 10 (2021)
- ISO/IEC 27001:2022
- NIST SP 800-53 Rev. 5
"""
from typing import Any

# Mapeo de categorías del escáner a controles regulatorios
COMPLIANCE_MAPPING: dict[str, dict[str, Any]] = {
    "sqli": {
        "pci_dss": ["Req-6.2.4"],
        "pci_dss_desc": "Mitigación de ataques de inyección SQL en software personalizado",
        "owasp": "A03:2021-Injection",
        "iso27001": ["A.8.26"],
        "nist": ["SI-10"],
    },
    "xss": {
        "pci_dss": ["Req-6.2.4", "Req-6.4.1", "Req-6.4.3"],
        "pci_dss_desc": "Protección contra Cross-Site Scripting (XSS) y manipulación de scripts de pago en cliente",
        "owasp": "A03:2021-Injection",
        "iso27001": ["A.8.26"],
        "nist": ["SI-10"],
    },
    "dom_xss": {
        "pci_dss": ["Req-6.4.1", "Req-6.4.3"],
        "pci_dss_desc": "Gestión y autorización de scripts en el navegador del cliente",
        "owasp": "A03:2021-Injection",
        "iso27001": ["A.8.26"],
        "nist": ["SI-10"],
    },
    "injections": {
        "pci_dss": ["Req-6.2.4"],
        "pci_dss_desc": "Prevención de Command Injection y SSTI en código de aplicación",
        "owasp": "A03:2021-Injection",
        "iso27001": ["A.8.26"],
        "nist": ["SI-10"],
    },
    "xxe": {
        "pci_dss": ["Req-6.2.4"],
        "pci_dss_desc": "Restricción de entidades externas XML en procesadores",
        "owasp": "A05:2021-Security Misconfiguration",
        "iso27001": ["A.8.26"],
        "nist": ["SI-10"],
    },
    "ssrf": {
        "pci_dss": ["Req-6.2.4", "Req-1.3.1"],
        "pci_dss_desc": "Prevención de falsificación de peticiones del lado del servidor y segmentación",
        "owasp": "A10:2021-Server-Side Request Forgery",
        "iso27001": ["A.8.20", "A.8.26"],
        "nist": ["AC-3", "SI-10"],
    },
    "oast": {
        "pci_dss": ["Req-6.2.4", "Req-1.3.1"],
        "pci_dss_desc": "Detección de interacciones fuera de banda (Blind SSRF / Blind RCE)",
        "owasp": "A10:2021-Server-Side Request Forgery",
        "iso27001": ["A.8.20", "A.8.26"],
        "nist": ["AC-3"],
    },
    "jwt": {
        "pci_dss": ["Req-8.3.1", "Req-8.3.6"],
        "pci_dss_desc": "Autenticación fuerte y protección criptográfica de tokens",
        "owasp": "A07:2021-Identification and Authentication Failures",
        "iso27001": ["A.8.24"],
        "nist": ["IA-5"],
    },
    "ssl": {
        "pci_dss": ["Req-4.1.2"],
        "pci_dss_desc": "Uso de criptografía robusta y protocolos seguros en tránsito (TLS 1.2+)",
        "owasp": "A02:2021-Cryptographic Failures",
        "iso27001": ["A.8.24"],
        "nist": ["SC-8"],
    },
    "sensitive_data": {
        "pci_dss": ["Req-3.4.1", "Req-3.5.1"],
        "pci_dss_desc": "Protección de datos de titulares de tarjetas y claves secretas",
        "owasp": "A02:2021-Cryptographic Failures",
        "iso27001": ["A.8.24"],
        "nist": ["SC-8"],
    },
    "sca": {
        "pci_dss": ["Req-6.3.1"],
        "pci_dss_desc": "Identificación y gestión de vulnerabilidades conocidas en componentes de terceros",
        "owasp": "A06:2021-Vulnerable and Outdated Components",
        "iso27001": ["A.8.8"],
        "nist": ["SI-2"],
    },
    "headers": {
        "pci_dss": ["Req-6.4.1"],
        "pci_dss_desc": "Cabeceras de protección de cliente (CSP, HSTS, X-Content-Type-Options)",
        "owasp": "A05:2021-Security Misconfiguration",
        "iso27001": ["A.8.26"],
        "nist": ["SI-10"],
    },
    "cors": {
        "pci_dss": ["Req-1.3.1", "Req-6.2.4"],
        "pci_dss_desc": "Control de acceso e intercambio de recursos de origen cruzado",
        "owasp": "A05:2021-Security Misconfiguration",
        "iso27001": ["A.8.20"],
        "nist": ["AC-3"],
    },
    "ports": {
        "pci_dss": ["Req-1.3.2"],
        "pci_dss_desc": "Restricción de puertos y servicios innecesarios en el perímetro",
        "owasp": "A05:2021-Security Misconfiguration",
        "iso27001": ["A.8.20"],
        "nist": ["CM-7"],
    },
    "prototype_pollution": {
        "pci_dss": ["Req-6.4.1"],
        "pci_dss_desc": "Integridad de prototipos y objetos en tiempo de ejecución del cliente",
        "owasp": "A08:2021-Software and Data Integrity Failures",
        "iso27001": ["A.8.26"],
        "nist": ["SI-10"],
    },
    "graphql": {
        "pci_dss": ["Req-6.2.4", "Req-6.3.1"],
        "pci_dss_desc": "Exposición no controlada de esquemas e interfaces de desarrollo",
        "owasp": "A05:2021-Security Misconfiguration",
        "iso27001": ["A.8.26"],
        "nist": ["AC-3"],
    },
    "default": {
        "pci_dss": ["Req-6.2.4"],
        "pci_dss_desc": "Protección general de seguridad de aplicaciones",
        "owasp": "A05:2021-Security Misconfiguration",
        "iso27001": ["A.8.8"],
        "nist": ["SI-10"],
    },
}


def evaluate_compliance(findings: list[Any]) -> dict[str, Any]:
    """Evalúa la lista de hallazgos contra los marcos regulatorios y genera métricas de cumplimiento.

    Args:
        findings: Lista de objetos Finding o diccionarios normalizados.

    Returns:
        Diccionario con desglose por marco (PCI-DSS v4.0, OWASP, ISO 27001, NIST) y estado global.
    """
    total_findings = len(findings)
    pci_failures: dict[str, list[dict[str, Any]]] = {}
    owasp_counts: dict[str, int] = {}
    iso_failures: dict[str, int] = {}
    nist_failures: dict[str, int] = {}

    critical_count = 0
    high_count = 0

    for f in findings:
        data = f.to_dict() if hasattr(f, "to_dict") else dict(f)
        category = str(data.get("category", "default")).lower()
        title = data.get("title") or data.get("vuln", "Vulnerabilidad detectada")
        severity = str(data.get("severity", data.get("risk", "Bajo"))).lower()

        if severity in ("critical", "alto", "crítico", "critico"):
            if "crit" in severity:
                critical_count += 1
            else:
                high_count += 1

        rule = COMPLIANCE_MAPPING.get(category, COMPLIANCE_MAPPING["default"])

        # 1. Mapeo PCI-DSS
        for req in rule["pci_dss"]:
            pci_failures.setdefault(req, []).append({
                "title": title,
                "severity": severity,
                "description": rule["pci_dss_desc"],
                "url": data.get("affected_url") or data.get("url", ""),
            })

        # 2. Mapeo OWASP
        owasp_cat = rule["owasp"]
        owasp_counts[owasp_cat] = owasp_counts.get(owasp_cat, 0) + 1

        # 3. Mapeo ISO 27001
        for ctrl in rule["iso27001"]:
            iso_failures[ctrl] = iso_failures.get(ctrl, 0) + 1

        # 4. Mapeo NIST
        for nist_ctrl in rule["nist"]:
            nist_failures[nist_ctrl] = nist_failures.get(nist_ctrl, 0) + 1

    # Cálculo de estado PCI-DSS: Falla si hay vulnerabilidades Críticas o Altas
    pci_status = "FAIL" if (critical_count > 0 or high_count > 0) else "PASS"

    # Puntuación ponderada de cumplimiento (0 a 100)
    score_deduction = (critical_count * 25) + (high_count * 10) + (max(0, total_findings - critical_count - high_count) * 2)
    compliance_score = max(0.0, min(100.0, 100.0 - score_deduction))

    return {
        "status": pci_status,
        "compliance_score": round(compliance_score, 1),
        "total_findings": total_findings,
        "critical_count": critical_count,
        "high_count": high_count,
        "frameworks": {
            "pci_dss_v40": {
                "status": pci_status,
                "impacted_requirements": pci_failures,
                "requirement_count": len(pci_failures),
            },
            "owasp_top10_2021": {
                "categories": owasp_counts,
                "category_count": len(owasp_counts),
            },
            "iso27001_2022": {
                "controls": iso_failures,
                "control_count": len(iso_failures),
            },
            "nist_sp800_53": {
                "controls": nist_failures,
                "control_count": len(nist_failures),
            },
        },
    }


def generate_compliance_markdown(compliance_data: dict[str, Any]) -> str:
    """Genera una tabla y resumen ejecutivo en Markdown para reportes formales de auditoría."""
    status = compliance_data.get("status", "FAIL")
    score = compliance_data.get("compliance_score", 0.0)
    total = compliance_data.get("total_findings", 0)
    crits = compliance_data.get("critical_count", 0)
    highs = compliance_data.get("high_count", 0)

    badge = "🔴 **NO CONFORME (FAIL)**" if status == "FAIL" else "🟢 **CONFORME (PASS)**"

    lines = [
        "## Evaluación de Cumplimiento Regulatorio Corporativo",
        "",
        f"**Estado General:** {badge} | **Puntuación de Cumplimiento:** `{score}%`",
        f"- Hallazgos Totales: **{total}** (Críticos: **{crits}**, Altos: **{highs}**)",
        "",
        "### Matriz de Cobertura Regulatoria",
        "",
        "| Estándar | Versión | Estado | Controles Impactados |",
        "| :--- | :---: | :---: | :---: |",
    ]

    pci = compliance_data["frameworks"]["pci_dss_v40"]
    lines.append(f"| **PCI-DSS** | v4.0 | {pci['status']} | {pci['requirement_count']} requisitos vulnerados |")

    owasp = compliance_data["frameworks"]["owasp_top10_2021"]
    lines.append(f"| **OWASP Top 10** | 2021 | N/A | {owasp['category_count']} categorías observadas |")

    iso = compliance_data["frameworks"]["iso27001_2022"]
    lines.append(f"| **ISO/IEC 27001** | 2022 | N/A | {iso['control_count']} controles afectados |")

    nist = compliance_data["frameworks"]["nist_sp800_53"]
    lines.append(f"| **NIST SP 800-53** | Rev 5 | N/A | {nist['control_count']} controles afectados |")

    lines.append("")
    lines.append("### Detalle de Requisitos PCI-DSS v4.0 Vulnerados")
    lines.append("")
    if pci["impacted_requirements"]:
        for req, items in pci["impacted_requirements"].items():
            desc = items[0]["description"] if items else ""
            lines.append(f"- **{req}**: {desc} ({len(items)} hallazgo(s))")
    else:
        lines.append("- *No se identificaron infracciones directas a controles obligatorios de PCI-DSS.*")

    return "\n".join(lines)
