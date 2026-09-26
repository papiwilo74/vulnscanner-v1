"""
Motor de Comparación y Análisis Diferencial de Escaneos (Scan Diff Engine).

Permite comparar dos auditorías sucesivas (línea base vs escaneo actual) para:
1. Detectar nuevas vulnerabilidades introducidas (regresiones de seguridad).
2. Verificar vulnerabilidades resueltas / mitigadas exitosamente.
3. Rastrear vulnerabilidades recurrentes o persistentes.
4. Cuantificar el cambio neto de riesgo (Risk Delta).
"""
from __future__ import annotations

import logging
from dataclasses import asdict, dataclass
from typing import Any

logger = logging.getLogger("OmniBreach.ScanDiff")


@dataclass
class ScanDiffResult:
    """Resultado estructurado de la comparación diferencial entre dos escaneos."""

    scan_a_id: str
    scan_b_id: str
    new_findings: list[dict[str, Any]]
    resolved_findings: list[dict[str, Any]]
    recurring_findings: list[dict[str, Any]]
    total_new: int
    total_resolved: int
    total_recurring: int
    risk_score_delta: float
    summary: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _finding_fingerprint(finding_data: dict[str, Any]) -> str:
    """Calcula una huella digital determinista para identificar hallazgos idénticos."""
    cat = str(finding_data.get("category", "")).lower().strip()
    cwe = str(finding_data.get("cwe_id", "")).upper().strip()
    title = str(finding_data.get("title", finding_data.get("vuln", ""))).lower().strip()
    url = str(finding_data.get("affected_url", "")).strip()
    param = str(finding_data.get("parameter", "")).strip()
    return f"{cat}|{cwe}|{title}|{url}|{param}"


def compare_scans(scan_a: dict[str, Any], scan_b: dict[str, Any]) -> ScanDiffResult:
    """
    Compara dos resultados de escaneo (Scan A = Base, Scan B = Comparado).

    Retorna un ScanDiffResult con nuevas fallas, remediadas y persistentes.
    """
    scan_a_id = str(scan_a.get("task_id", "baseline_scan"))
    scan_b_id = str(scan_b.get("task_id", "target_scan"))

    # Extraer listas de vulnerabilidades
    vulns_a: list[dict[str, Any]] = []
    if "results" in scan_a and isinstance(scan_a["results"], dict):
        vulns_a = scan_a["results"].get("vulnerabilities", [])
    elif "vulnerabilities" in scan_a:
        vulns_a = scan_a["vulnerabilities"]

    vulns_b: list[dict[str, Any]] = []
    if "results" in scan_b and isinstance(scan_b["results"], dict):
        vulns_b = scan_b["results"].get("vulnerabilities", [])
    elif "vulnerabilities" in scan_b:
        vulns_b = scan_b["vulnerabilities"]

    # Mapear por fingerprint
    map_a = {_finding_fingerprint(v): v for v in vulns_a if isinstance(v, dict)}
    map_b = {_finding_fingerprint(v): v for v in vulns_b if isinstance(v, dict)}

    new_fps = set(map_b.keys()) - set(map_a.keys())
    resolved_fps = set(map_a.keys()) - set(map_b.keys())
    recurring_fps = set(map_a.keys()) & set(map_b.keys())

    new_findings = [map_b[fp] for fp in new_fps]
    resolved_findings = [map_a[fp] for fp in resolved_fps]
    recurring_findings = [map_b[fp] for fp in recurring_fps]

    # Calcular variación de score de seguridad
    def _get_score(s: dict[str, Any]) -> float:
        if "results" in s and isinstance(s["results"], dict):
            return float(s["results"].get("security_score", 100.0))
        return float(s.get("security_score", 100.0))

    score_a = _get_score(scan_a)
    score_b = _get_score(scan_b)
    risk_delta = round(score_b - score_a, 2)

    # Generar resumen ejecutivo del diferencial
    summary_parts = []
    if new_findings:
        summary_parts.append(f"Se introdujeron {len(new_findings)} nueva(s) vulnerabilidad(es).")
    if resolved_findings:
        summary_parts.append(f"Se corrigieron {len(resolved_findings)} vulnerabilidad(es) previas.")
    if recurring_findings:
        summary_parts.append(f"{len(recurring_findings)} hallazgo(s) continúan sin resolver.")
    if not summary_parts:
        summary_parts.append("No se detectaron cambios en la postura de seguridad entre ambos escaneos.")

    delta_str = f" Variación de Security Score: {score_a} -> {score_b} ({risk_delta:+0.1f} pts)."
    summary = " ".join(summary_parts) + delta_str

    return ScanDiffResult(
        scan_a_id=scan_a_id,
        scan_b_id=scan_b_id,
        new_findings=new_findings,
        resolved_findings=resolved_findings,
        recurring_findings=recurring_findings,
        total_new=len(new_findings),
        total_resolved=len(resolved_findings),
        total_recurring=len(recurring_findings),
        risk_score_delta=risk_delta,
        summary=summary,
    )


def calculate_security_drift(historical_scans: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Calcula la métrica de 'Security Drift' (deriva de seguridad y deuda técnica)
    a lo largo de una serie temporal de escaneos históricos.
    Retorna métricas como tasa de introducción de fallas, tasa de resolución y tendencia neta.
    """
    if not historical_scans or len(historical_scans) < 2:
        return {
            "total_scans_analyzed": len(historical_scans),
            "drift_trend": "insufficient_data",
            "net_vulnerability_change": 0,
            "total_new_vulnerabilities": 0,
            "total_resolved_vulnerabilities": 0,
            "drift_index_percent": 0.0,
            "summary": "Se requieren al menos 2 escaneos sucesivos para calcular la tendencia de Security Drift.",
        }

    total_new = 0
    total_resolved = 0

    for i in range(len(historical_scans) - 1):
        diff = compare_scans(historical_scans[i], historical_scans[i + 1])
        total_new += diff.total_new
        total_resolved += diff.total_resolved

    net_change = total_new - total_resolved
    drift_index = round((total_new / max(total_new + total_resolved, 1)) * 100, 1)

    if net_change < 0:
        trend = "improving"
        summary = f"Postura de seguridad en mejora: Se han resuelto {total_resolved} vulnerabilidades frente a {total_new} introducidas."
    elif net_change > 0:
        trend = "deteriorating"
        summary = f"Deriva de seguridad negativa (Drift): Se han introducido {total_new} fallas superando las {total_resolved} resueltas."
    else:
        trend = "stable"
        summary = "Postura de seguridad estable: El ritmo de resolución empata con las nuevas vulnerabilidades."

    return {
        "total_scans_analyzed": len(historical_scans),
        "total_new_vulnerabilities": total_new,
        "total_resolved_vulnerabilities": total_resolved,
        "net_vulnerability_change": net_change,
        "drift_index_percent": drift_index,
        "drift_trend": trend,
        "summary": summary,
    }

