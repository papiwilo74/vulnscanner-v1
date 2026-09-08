"""Generador de Reportes Ejecutivos en PDF para VulnScanner Enterprise.

Produce documentos formales de auditoría para comités de riesgo y CISOs,
incluyendo matrices de cumplimiento normativo (PCI-DSS v4.0, ISO/IEC 27001, OWASP Top 10),
desglose de severidad CVSS v3.1, recomendaciones y acta de firma de auditoría.
"""
from __future__ import annotations

import os
from datetime import datetime
from typing import Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import HRFlowable, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from scanner.models import Finding


def _calculate_security_grade(findings: list[Finding]) -> tuple[str, colors.Color, str]:
    """Calcula la calificación global de seguridad (A+, A, B, C, F) y su color."""
    crit_count = sum(1 for f in findings if f.severity == "critical")
    high_count = sum(1 for f in findings if f.severity == "high")
    med_count = sum(1 for f in findings if f.severity == "medium")

    if crit_count > 0 or high_count >= 3:
        return "F", colors.HexColor("#b91c1c"), "Riesgo Crítico — Requiere remediación inmediata antes de producción"
    if high_count > 0:
        return "C", colors.HexColor("#c2410c"), "Riesgo Elevado — Se detectaron vulnerabilidades de impacto alto"
    if med_count > 0:
        return "B", colors.HexColor("#ca8a04"), "Riesgo Moderado — Cumple controles básicos con desviaciones menores"
    return "A+", colors.HexColor("#15803d"), "Excelente — Cumple estrictamente con las directivas de seguridad"


def generate_pdf_report(
    target_url: str,
    findings: list[Finding],
    output_path: str,
    duration: float = 0.0,
    scan_profile: str = "normal",
    engine_summary: dict[str, Any] | None = None,
) -> str:
    """Genera un reporte ejecutivo en PDF formal y retorna la ruta del archivo generado."""
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    doc = SimpleDocTemplate(
        output_path,
        pagesize=letter,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40,
    )

    styles = getSampleStyleSheet()
    primary_color = colors.HexColor("#0f172a")
    accent_color = colors.HexColor("#1e40af")
    text_muted = colors.HexColor("#475569")

    title_style = ParagraphStyle(
        "DocTitle",
        parent=styles["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=20,
        leading=24,
        textColor=primary_color,
        spaceAfter=4,
    )
    subtitle_style = ParagraphStyle(
        "DocSub",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=10,
        leading=14,
        textColor=text_muted,
        spaceAfter=12,
    )
    h2_style = ParagraphStyle(
        "Heading2",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=13,
        leading=16,
        textColor=accent_color,
        spaceBefore=14,
        spaceAfter=6,
    )
    body_style = ParagraphStyle(
        "DocBody",
        parent=styles["BodyText"],
        fontName="Helvetica",
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#1e293b"),
    )

    story: list[Any] = []

    # 1. Portada / Encabezado
    story.append(Paragraph("VULNSCANNER ENTERPRISE", title_style))
    story.append(Paragraph("Informe Formal de Auditoría de Seguridad & Cumplimiento Normativo", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=2, color=accent_color, spaceAfter=14))

    # 2. Resumen Metadatos & Calificación
    grade, grade_color, grade_desc = _calculate_security_grade(findings)
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    summary_data = [
        [
            Paragraph(f"<b>Objetivo Evaluado:</b> {target_url}", body_style),
            Paragraph(f"<b>Grado de Seguridad:</b> <font color='{grade_color.hexval()}'><b>{grade}</b></font>", body_style),
        ],
        [
            Paragraph(f"<b>Fecha de Emisión:</b> {now_str}", body_style),
            Paragraph(f"<b>Perfil de Escaneo:</b> {scan_profile.upper()}", body_style),
        ],
        [
            Paragraph(f"<b>Duración de Análisis:</b> {duration:.2f}s", body_style),
            Paragraph(f"<b>Total Hallazgos:</b> {len(findings)}", body_style),
        ],
    ]
    t_summary = Table(summary_data, colWidths=[270, 260])
    t_summary.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
        ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#cbd5e1")),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(t_summary)
    story.append(Spacer(1, 10))

    # Diagnóstico del Grado
    story.append(Paragraph(f"<b>Diagnóstico Ejecutivo:</b> {grade_desc}", body_style))
    story.append(Spacer(1, 12))

    # 3. Matriz de Cumplimiento Normativo
    story.append(Paragraph("1. Evaluación de Cumplimiento Normativo (Compliance)", h2_style))

    crit_count = sum(1 for f in findings if f.severity == "critical")
    high_count = sum(1 for f in findings if f.severity == "high")

    pci_status = "NO CONFORME" if (crit_count > 0 or high_count > 0) else "CONFORME"
    iso_status = "NO CONFORME" if crit_count > 0 else "CONFORME CON OBSERVACIONES" if high_count > 0 else "CONFORME"
    owasp_status = f"{len(findings)} Desviaciones Identificadas" if findings else "100% Mitigado"

    compliance_data = [
        ["Estándar / Marco Regulatorio", "Requisito de Seguridad", "Estado de Conformidad"],
        ["PCI-DSS v4.0", "Req 6.3 - 6.5 (Protección contra inyecciones y fallos web)", pci_status],
        ["ISO/IEC 27001:2022", "Control A.8.8 (Gestión de vulnerabilidades técnicas)", iso_status],
        ["OWASP Top 10:2021", "A01 a A10 (Controles de seguridad en aplicaciones)", owasp_status],
    ]
    t_comp = Table(compliance_data, colWidths=[140, 250, 140])
    t_comp.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), primary_color),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
        ("ALIGN", (2, 1), (2, -1), "CENTER"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(t_comp)
    story.append(Spacer(1, 14))

    # 4. Tabla de Severidades
    story.append(Paragraph("2. Distribución de Hallazgos por Severidad", h2_style))
    sev_counts = {
        "critical": sum(1 for f in findings if f.severity == "critical"),
        "high": sum(1 for f in findings if f.severity == "high"),
        "medium": sum(1 for f in findings if f.severity == "medium"),
        "low": sum(1 for f in findings if f.severity == "low"),
        "info": sum(1 for f in findings if f.severity == "info"),
    }
    sev_table_data = [
        ["Severidad", "Rango CVSS v3.1", "Total Detectado", "Impacto Operacional"],
        ["Crítico", "9.0 - 10.0", str(sev_counts["critical"]), "Compromiso total del servidor / RCE / SQLi"],
        ["Alto", "7.0 - 8.9", str(sev_counts["high"]), "Pérdida de confidencialidad o control de sesión"],
        ["Medio", "4.0 - 6.9", str(sev_counts["medium"]), "Falta de cabeceras de seguridad o CSRF"],
        ["Bajo", "0.1 - 3.9", str(sev_counts["low"]), "Exposición menor de información o CORS permisivo"],
    ]
    t_sev = Table(sev_table_data, colWidths=[90, 100, 100, 240])
    t_sev.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#334155")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(t_sev)
    story.append(Spacer(1, 14))

    # 5. Detalle de Hallazgos
    story.append(Paragraph("3. Catálogo Detallado de Hallazgos y Remediaciones", h2_style))
    if not findings:
        story.append(Paragraph("<i>No se identificaron vulnerabilidades durante la auditoría.</i>", body_style))
    else:
        for idx, f in enumerate(findings[:25], 1):
            sev_color = {
                "critical": "#b91c1c",
                "high": "#c2410c",
                "medium": "#ca8a04",
                "low": "#15803d",
            }.get(f.severity, "#475569")

            finding_header = f"<b>{idx}. {f.title}</b> — <font color='{sev_color}'>[{f.severity.upper()}]</font> (CVSS: {f.cvss_score:.1f})"
            story.append(Paragraph(finding_header, body_style))

            detail_text = f"<b>CWE:</b> {f.cwe_id} | <b>MITRE ATT&CK:</b> {f.mitre_attack_id} | <b>OWASP:</b> {f.owasp_category}"
            story.append(Paragraph(detail_text, ParagraphStyle("Det", parent=body_style, fontSize=8, textColor=text_muted)))

            if f.description:
                story.append(Paragraph(f"<b>Descripción:</b> {f.description}", ParagraphStyle("Desc", parent=body_style, fontSize=8)))

            if f.remediation:
                story.append(Paragraph(f"<b>Remediación Sugerida:</b> {f.remediation}", ParagraphStyle("Rem", parent=body_style, fontSize=8, textColor=colors.HexColor("#065f46"))))

            story.append(Spacer(1, 6))

    # 6. Acta Formal de Firma y Aprobación
    story.append(Spacer(1, 15))
    story.append(Paragraph("4. Acta de Cierre y Conformidad de Auditoría", h2_style))
    sig_data = [
        [
            Paragraph("<b>Emitido por:</b><br/>Auditor Líder de Ciberseguridad<br/>VulnScanner Enterprise Security Suite", body_style),
            Paragraph("<b>Recibido y Aprobado por:</b><br/>Responsable de Aplicaciones / CISO<br/>Firma: ________________________", body_style),
        ],
        [
            Paragraph(f"Fecha: {now_str[:10]}", body_style),
            Paragraph("Fecha: ____ / ____ / ________", body_style),
        ],
    ]
    t_sig = Table(sig_data, colWidths=[265, 265])
    t_sig.setStyle(TableStyle([
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#94a3b8")),
        ("LINEBEFORE", (1, 0), (1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(t_sig)

    doc.build(story)
    return output_path
