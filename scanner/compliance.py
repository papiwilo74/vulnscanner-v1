"""
Motor de Mapeo y Evaluación de Cumplimiento Regulatorio Automático.
Mapea automáticamente los hallazgos de OmniBreach contra los principales marcos normativos
internacionales de ciberseguridad: PCI-DSS v4.0, HIPAA Security Rule, NIST SP 800-53 Rev 5 e ISO/IEC 27001:2022.
"""
from __future__ import annotations

import logging
from collections.abc import Sequence
from dataclasses import asdict, dataclass, field
from typing import Any

from scanner.models import Finding

logger = logging.getLogger("OmniBreach.Compliance")


@dataclass
class RegulatoryControl:
    """Definición de un control normativo o requisito de cumplimiento."""
    id: str
    framework: str
    section: str
    title: str
    description: str
    vulnerable_categories: list[str]
    remediation_directive: str


FRAMEWORK_CONTROLS: list[RegulatoryControl] = [
    # --- PCI-DSS v4.0 ---
    RegulatoryControl(
        id="PCI-6.2.4",
        framework="PCI-DSS v4.0",
        section="Requirement 6: Secure Systems and Software",
        title="Validación y Neutralización de Entradas (Injection Prevention)",
        description="Las aplicaciones deben mitigar ataques de inyección (SQLi, OS Command Injection, LDAP, XPath).",
        vulnerable_categories=["sqli", "injections", "xxe"],
        remediation_directive="Implementar consultas parametrizadas, ORM seguro y validación estricta por lista blanca.",
    ),
    RegulatoryControl(
        id="PCI-6.2.4.XSS",
        framework="PCI-DSS v4.0",
        section="Requirement 6: Secure Systems and Software",
        title="Prevención de Cross-Site Scripting (XSS)",
        description="Neutralizar reflejo o almacenamiento no confiable de scripts en páginas web.",
        vulnerable_categories=["xss", "dom_xss"],
        remediation_directive="Codificar salidas HTML contextualmente e implementar una directiva Content-Security-Policy (CSP) robusta.",
    ),
    RegulatoryControl(
        id="PCI-6.4.1",
        framework="PCI-DSS v4.0",
        section="Requirement 6: Secure Systems and Software",
        title="Protección de Aplicaciones Web Públicas y WAF",
        description="Detectar y bloquear ataques dirigidos a aplicaciones web mediante WAF o evaluaciones automáticas continuas.",
        vulnerable_categories=["waf", "race_condition", "business_logic"],
        remediation_directive="Desplegar un Web Application Firewall activo y controles de concurrencia y límites transaccionales.",
    ),
    RegulatoryControl(
        id="PCI-4.1.2",
        framework="PCI-DSS v4.0",
        section="Requirement 4: Protect Cardholder Data with Strong Cryptography",
        title="Cifrado Fuerte de Datos en Tránsito",
        description="Uso obligatorio de TLS 1.2+ y suites de cifrado modernas sobre redes públicas.",
        vulnerable_categories=["ssl", "websocket"],
        remediation_directive="Deshabilitar TLS 1.0/1.1 y SSLv3, forzar HTTPS mediante HSTS (Strict-Transport-Security) y WSS seguro.",
    ),
    RegulatoryControl(
        id="PCI-3.4.1",
        framework="PCI-DSS v4.0",
        section="Requirement 3: Protect Stored Cardholder Data",
        title="Protección de Secretos y Datos Sensibles Expuestos",
        description="Prevenir la exposición no autorizada de credenciales, tokens y llaves criptográficas.",
        vulnerable_categories=["sensitive_data", "fuzzer", "exposed_artifacts"],
        remediation_directive="Eliminar claves hardcodeadas en repositorios o bundles JS; rotar credenciales comprometidas.",
    ),
    RegulatoryControl(
        id="PCI-8.3.1",
        framework="PCI-DSS v4.0",
        section="Requirement 8: Identity and Access Management",
        title="Autenticación Robusta y Protección de Sesiones",
        description="Asegurar tokens de sesión, cookies de autenticación y controles contra secuestro de cuentas.",
        vulnerable_categories=["cookies", "jwt", "auth"],
        remediation_directive="Configurar cookies con banderas HttpOnly, Secure y SameSite=Strict; validar firmas HMAC/RSA en JWT.",
    ),

    # --- HIPAA Security Rule (45 CFR Part 164) ---
    RegulatoryControl(
        id="HIPAA-164.312.a.1",
        framework="HIPAA Security Rule",
        section="§ 164.312(a)(1) Technical Safeguards - Access Control",
        title="Control de Acceso y Autorización Granular a Datos de Salud (ePHI)",
        description="Prevenir acceso no autorizado o traspaso de límites entre pacientes y usuarios.",
        vulnerable_categories=["api", "open_redirect", "cors"],
        remediation_directive="Reforzar controles de autorización BOLA/IDOR a nivel de registro y restringir orígenes CORS permitidos.",
    ),
    RegulatoryControl(
        id="HIPAA-164.312.c.1",
        framework="HIPAA Security Rule",
        section="§ 164.312(c)(1) Technical Safeguards - Integrity",
        title="Integridad y No Alteración de Datos Clínicos",
        description="Proteger registros ePHI frente a modificaciones o inyecciones no autorizadas.",
        vulnerable_categories=["sqli", "prototype_pollution", "business_logic"],
        remediation_directive="Implementar validación de integridad criptográfica y parametrización de escrituras transaccionales.",
    ),
    RegulatoryControl(
        id="HIPAA-164.312.e.1",
        framework="HIPAA Security Rule",
        section="§ 164.312(e)(1) Technical Safeguards - Transmission Security",
        title="Seguridad en la Transmisión de ePHI",
        description="Garantizar canales cifrados de extremo a extremo sin fugas de datos en cabeceras o texto claro.",
        vulnerable_categories=["ssl", "headers", "sensitive_data"],
        remediation_directive="Implementar HSTS, CSP y cabeceras anti-sniffing (X-Content-Type-Options: nosniff).",
    ),

    # --- NIST SP 800-53 Rev 5 ---
    RegulatoryControl(
        id="NIST-SI-10",
        framework="NIST SP 800-53 r5",
        section="System and Information Integrity",
        title="Information Input Validation (SI-10)",
        description="Comprobar sintaxis, semántica y longitud de todas las entradas del sistema antes de procesarlas.",
        vulnerable_categories=["sqli", "injections", "xss", "xxe", "path_traversal"],
        remediation_directive="Sanitizar y validar esquemas de datos según las especificaciones de API antes del procesamiento.",
    ),
    RegulatoryControl(
        id="NIST-AC-3",
        framework="NIST SP 800-53 r5",
        section="Access Control",
        title="Access Enforcement (AC-3)",
        description="Hacer cumplir políticas de autorización aprobadas para todas las operaciones en objetos del sistema.",
        vulnerable_categories=["api", "directories", "exposed_artifacts"],
        remediation_directive="Aplicar el principio de mínimo privilegio en endpoints REST y restringir accesos a archivos internos.",
    ),
    RegulatoryControl(
        id="NIST-SC-8",
        framework="NIST SP 800-53 r5",
        section="System and Communications Protection",
        title="Transmission Confidentiality and Integrity (SC-8)",
        description="Impedir interceptación, alteración o lectura no autorizada de paquetes de red.",
        vulnerable_categories=["ssl", "websocket", "cors"],
        remediation_directive="Requerir cifrado TLS de canal completo y validar cabeceras Origin de navegadores.",
    ),

    # --- ISO/IEC 27001:2022 ---
    RegulatoryControl(
        id="ISO-A.8.28",
        framework="ISO/IEC 27001:2022",
        section="Annex A.8: Technological Controls",
        title="Secure Coding (A.8.28)",
        description="Aplicar principios de desarrollo de software seguro tanto a código propio como a dependencias.",
        vulnerable_categories=["sca", "sqli", "xss", "injections", "file_upload"],
        remediation_directive="Actualizar librerías vulnerables (SCA) y aplicar linters de seguridad en el pipeline CI/CD.",
    ),
    RegulatoryControl(
        id="ISO-A.8.24",
        framework="ISO/IEC 27001:2022",
        section="Annex A.8: Technological Controls",
        title="Use of Cryptography (A.8.24)",
        description="Definir e implementar el uso apropiado de criptografía según el valor de los activos de información.",
        vulnerable_categories=["ssl", "jwt", "sensitive_data"],
        remediation_directive="Emplear algoritmos criptográficos robustos recomendados (AES-256, RSA-2048+, SHA-256).",
    ),
]


@dataclass
class FrameworkEvaluation:
    """Resultado consolidado de cumplimiento para un marco normativo."""
    framework: str
    total_controls: int
    passing_controls: int
    failing_controls: int
    compliance_score_percent: float
    status: str
    violations: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class ComplianceEngine:
    """
    Motor evaluador de cumplimiento normativo y preparación para auditorías de seguridad.
    """

    def __init__(self, controls: list[RegulatoryControl] | None = None) -> None:
        self.controls = controls or FRAMEWORK_CONTROLS

    def evaluate(self, findings: Sequence[Finding | dict[str, Any]]) -> dict[str, Any]:
        """
        Evalúa una lista de hallazgos contra los controles regulatorios definidos.
        """
        # Extraer categorías y severidades presentes
        detected_categories: dict[str, list[dict[str, Any]]] = {}
        for f in findings:
            if isinstance(f, Finding):
                cat = f.category.lower()
                title = f.title
                sev = f.severity.lower()
                url = f.affected_url or ""
            else:
                cat = str(f.get("category", "")).lower()
                title = str(f.get("title", ""))
                sev = str(f.get("severity", "medium")).lower()
                url = str(f.get("affected_url", ""))

            detected_categories.setdefault(cat, []).append({
                "title": title,
                "severity": sev,
                "url": url,
            })

        # Agrupar controles por marco normativo
        by_framework: dict[str, list[RegulatoryControl]] = {}
        for ctrl in self.controls:
            by_framework.setdefault(ctrl.framework, []).append(ctrl)

        framework_evaluations: dict[str, FrameworkEvaluation] = {}
        total_controls_all = 0
        passing_controls_all = 0

        for fw_name, ctrls in by_framework.items():
            total = len(ctrls)
            passing = 0
            violations: list[dict[str, Any]] = []

            for c in ctrls:
                # Verificar si alguna categoría del control fue detectada
                matching_findings: list[dict[str, Any]] = []
                for vcat in c.vulnerable_categories:
                    if vcat in detected_categories:
                        matching_findings.extend(detected_categories[vcat])

                if matching_findings:
                    violations.append({
                        "control_id": c.id,
                        "title": c.title,
                        "section": c.section,
                        "findings_count": len(matching_findings),
                        "remediation": c.remediation_directive,
                        "sample_findings": matching_findings[:3],
                    })
                else:
                    passing += 1

            score = round((passing / total) * 100, 1) if total > 0 else 100.0
            status = "COMPLIANT" if score == 100.0 else ("PARTIALLY COMPLIANT" if score >= 70.0 else "NON COMPLIANT")

            framework_evaluations[fw_name] = FrameworkEvaluation(
                framework=fw_name,
                total_controls=total,
                passing_controls=passing,
                failing_controls=total - passing,
                compliance_score_percent=score,
                status=status,
                violations=violations,
            )

            total_controls_all += total
            passing_controls_all += passing

        overall_score = round((passing_controls_all / total_controls_all) * 100, 1) if total_controls_all > 0 else 100.0
        if overall_score >= 90.0:
            overall_grade = "A (Excelente postura)"
        elif overall_score >= 80.0:
            overall_grade = "B (Buena postura / Brechas menores)"
        elif overall_score >= 70.0:
            overall_grade = "C (Riesgo moderado)"
        elif overall_score >= 50.0:
            overall_grade = "D (Brechas regulatorias críticas)"
        else:
            overall_grade = "F (No apto para auditoría)"

        return {
            "overall_compliance_score": overall_score,
            "overall_grade": overall_grade,
            "total_frameworks_evaluated": len(framework_evaluations),
            "frameworks": {k: v.to_dict() for k, v in framework_evaluations.items()},
        }

    def generate_markdown_report(self, evaluation: dict[str, Any]) -> str:
        """Genera un resumen ejecutivo en formato Markdown para directores y auditores."""
        lines = [
            "# Reporte de Cumplimiento Normativo y Auditoría de Seguridad",
            f"**Calificación Global:** {evaluation.get('overall_grade')} ({evaluation.get('overall_compliance_score')}% de Controles Aprobados)\n",
            "| Estándar Normativo | Controles Evaluados | Aprobados | Fallidos | Cumplimiento (%) | Estado |",
            "|:---|:---:|:---:|:---:|:---:|:---|",
        ]

        fws: dict[str, Any] = evaluation.get("frameworks", {})
        for fw_name, fw_data in fws.items():
            lines.append(
                f"| **{fw_name}** | {fw_data['total_controls']} | {fw_data['passing_controls']} | "
                f"{fw_data['failing_controls']} | {fw_data['compliance_score_percent']}% | `{fw_data['status']}` |"
            )

        lines.append("\n## Brechas Regulatorias y Directivas de Remediación Obligatorias\n")
        for fw_name, fw_data in fws.items():
            violations = fw_data.get("violations", [])
            if violations:
                lines.append(f"### {fw_name}")
                for v in violations:
                    lines.append(f"- **[{v['control_id']}] {v['title']}** ({v['findings_count']} hallazgos asociados)")
                    lines.append(f"  * *Directiva:* {v['remediation']}")
                lines.append("")

        return "\n".join(lines)
