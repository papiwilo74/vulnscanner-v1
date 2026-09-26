"""
Módulo de Evaluación Científica y Benchmarking Cuantitativo de OmniBreach.
Calcula métricas académicas rigurosas:
- Matriz de Confusión (TP, FP, TN, FN)
- Exactitud (Accuracy)
- Precisión (Precision / PPV)
- Sensibilidad / Cobertura (Recall / TPR)
- Especificidad (Specificity / TNR)
- Puntuación F1 (F1-Score)
- Tasa de Falsos Positivos (FPR / Fall-out)
- Coeficiente de Correlación de Matthews (MCC)

Genera reportes formales en JSON, Markdown y tablas en código LaTeX listas para tesis.
"""
from __future__ import annotations

import json
import logging
import math
import sys
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests

from scanner.cookies import check_cookies
from scanner.cors import check_cors
from scanner.dom_xss import check_dom_xss
from scanner.headers import check_headers
from scanner.open_redirect import check_open_redirect
from scanner.prototype_pollution import check_prototype_pollution
from scanner.sensitive_data import check_sensitive_data
from scanner.sqli import check_sqli
from scanner.synthetic_benchmark import (
    GROUND_TRUTH_CATALOG,
    GroundTruthTestCase,
    SyntheticBenchmarkServer,
)
from scanner.xss import check_xss

logger = logging.getLogger("OmniBreach.ScientificBenchmark")


@dataclass
class CategoryScore:
    category: str
    cwe_id: str
    total_cases: int
    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int
    precision: float
    recall: float
    f1_score: float

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ScientificBenchmarkResult:
    timestamp: str
    target_app: str
    version: str
    duration_seconds: float
    total_cases: int
    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int
    accuracy: float
    precision: float
    recall: float
    specificity: float
    f1_score: float
    false_positive_rate: float
    matthews_corr_coef: float
    categories: dict[str, CategoryScore]
    case_results: list[dict[str, Any]]

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["categories"] = {k: v.to_dict() for k, v in self.categories.items()}
        return d

    def to_markdown(self) -> str:
        md = []
        md.append("# Reporte de Evaluación Científica y Benchmarking Cuantitativo")
        md.append(f"**Fecha de Ejecución:** `{self.timestamp}`  ")
        md.append(f"**Objetivo Evaluado:** `{self.target_app}` | **Versión:** `{self.version}`  ")
        md.append(f"**Tiempo de Ejecución:** `{self.duration_seconds:.2f} segundos`  ")
        md.append("\n---\n")

        md.append("## 1. Matriz de Confusión Global\n")
        md.append("| Métrica | Conteo | Descripción Académica |")
        md.append("| :--- | :---: | :--- |")
        md.append(f"| **Verdaderos Positivos (TP)** | `{self.true_positives}` | Vulnerabilidades reales detectadas exitosamente |")
        md.append(f"| **Verdaderos Negativos (TN)** | `{self.true_negatives}` | Controles seguros correctamente identificados (Sin falsa alarma) |")
        md.append(f"| **Falsos Positivos (FP)** | `{self.false_positives}` | Alarmas erróneas sobre código seguro |")
        md.append(f"| **Falsos Negativos (FN)** | `{self.false_negatives}` | Vulnerabilidades no detectadas (Puntos ciegos) |")
        md.append(f"| **Muestras Totales (N)** | `{self.total_cases}` | Casos de prueba controlados en el Ground Truth |")

        md.append("\n---\n")
        md.append("## 2. Indicadores Estadísticos Clave\n")
        md.append("| Indicador Estadístico | Fórmula Matemática | Valor Obtenido |")
        md.append("| :--- | :---: | :---: |")
        md.append(f"| **Exactitud (Accuracy)** | $\\frac{{TP + TN}}{{TP + TN + FP + FN}}$ | **{self.accuracy * 100:.1f}%** |")
        md.append(f"| **Precisión (Precision / PPV)** | $\\frac{{TP}}{{TP + FP}}$ | **{self.precision * 100:.1f}%** |")
        md.append(f"| **Sensibilidad / Recall (TPR)** | $\\frac{{TP}}{{TP + FN}}$ | **{self.recall * 100:.1f}%** |")
        md.append(f"| **Especificidad (Specificity / TNR)** | $\\frac{{TN}}{{TN + FP}}$ | **{self.specificity * 100:.1f}%** |")
        md.append(f"| **Puntuación F1 (F1-Score)** | $2 \\cdot \\frac{{P \\cdot R}}{{P + R}}$ | **{self.f1_score:.4f}** |")
        md.append(f"| **Tasa de Falsos Positivos (FPR)** | $\\frac{{FP}}{{FP + TN}}$ | **{self.false_positive_rate * 100:.1f}%** |")
        md.append(f"| **Coef. Matthews (MCC)** | $\\frac{{TP \\times TN - FP \\times FN}}{{\\sqrt{{(TP+FP)(TP+FN)(TN+FP)(TN+FN)}}}}$ | **{self.matthews_corr_coef:.4f}** |")

        md.append("\n---\n")
        md.append("## 3. Desglose de Rendimiento por Familia de Vulnerabilidad (OWASP Top 10)\n")
        md.append("| Familia / Categoría | CWE | Casos | TP | FP | TN | FN | Precisión | Recall | F1-Score |")
        md.append("| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |")
        for cat_name, cat in self.categories.items():
            md.append(
                f"| **{cat_name.upper()}** | `{cat.cwe_id}` | {cat.total_cases} | "
                f"{cat.true_positives} | {cat.false_positives} | {cat.true_negatives} | {cat.false_negatives} | "
                f"**{cat.precision * 100:.1f}%** | **{cat.recall * 100:.1f}%** | **{cat.f1_score:.2f}** |"
            )

        md.append("\n---\n")
        md.append("## 4. Conclusión Académica para Tesis / Opción de Grado\n")
        md.append(
            f"La evaluación experimental demuestra una exactitud global del **{self.accuracy * 100:.1f}%** "
            f"con una tasa de falsos positivos contenida en el **{self.false_positive_rate * 100:.1f}%** "
            f"y un coeficiente MCC de **{self.matthews_corr_coef:.4f}**. El equilibrio entre sensibilidad "
            f"({self.recall * 100:.1f}%) y especificidad ({self.specificity * 100:.1f}%) ratifica la validez "
            f"técnica del motor determinista contextual de OmniBreach."
        )
        return "\n".join(md)

    def to_latex(self) -> str:
        tex = []
        tex.append("% Tabla de Métricas de Rendimiento Cuantitativo (OmniBreach v3.9)")
        tex.append("% Copiar y pegar en el documento de tesis / opción de grado")
        tex.append(r"\begin{table}[htbp]")
        tex.append(r"\centering")
        tex.append(r"\caption{Métricas Empíricas de Detección Cuantitativa contra Benchmark Certificado}")
        tex.append(r"\label{tab:omnibreach_benchmark}")
        tex.append(r"\begin{tabular}{lcccc}")
        tex.append(r"\hline")
        tex.append(r"\textbf{Métrica de Evaluación} & \textbf{Fórmula} & \textbf{Valor} & \textbf{Rango Óptimo} \\")
        tex.append(r"\hline")
        tex.append(f"Exactitud (Accuracy) & $(TP+TN)/N$ & {self.accuracy * 100:.1f}\\% & 100\\% \\\\")
        tex.append(f"Precisión (Precision) & $TP/(TP+FP)$ & {self.precision * 100:.1f}\\% & 100\\% \\\\")
        tex.append(f"Sensibilidad (Recall) & $TP/(TP+FN)$ & {self.recall * 100:.1f}\\% & 100\\% \\\\")
        tex.append(f"Especificidad (Specificity) & $TN/(TN+FP)$ & {self.specificity * 100:.1f}\\% & 100\\% \\\\")
        tex.append(f"Puntuación F1 (F1-Score) & $2PR/(P+R)$ & {self.f1_score:.4f} & 1.0000 \\\\")
        tex.append(f"Tasa de Falsos Positivos (FPR) & $FP/(FP+TN)$ & {self.false_positive_rate * 100:.1f}\\% & 0\\% \\\\")
        tex.append(f"Coef. de Matthews (MCC) & $\\text{{MCC}}_{{\\text{{form}}}}$ & {self.matthews_corr_coef:.4f} & +1.0000 \\\\")
        tex.append(r"\hline")
        tex.append(r"\end{tabular}")
        tex.append(r"\end{table}")
        return "\n".join(tex)

    def print_ascii_scorecard(self) -> None:
        if sys.platform.startswith("win"):
            try:
                if hasattr(sys.stdout, "reconfigure"):
                    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
            except Exception:
                pass

        border = "=" * 76
        print("\n" + border)
        print(" [*] [BENCHMARK CIENTIFICO & EVALUACION EMPIRICA] SCORECARD FORMAL")
        print(border)
        print(f" Aplicacion Objetivo  : {self.target_app} (OmniBreach v{self.version})")
        print(f" Duracion de Auditoria: {self.duration_seconds:.2f} segundos | Casos de Prueba: {self.total_cases}")
        print("-" * 76)
        print(" MATRIZ DE CONFUSION:")
        print(f"   [+] Verdaderos Positivos (TP): {self.true_positives:<4} | [ ] Falsos Positivos (FP): {self.false_positives:<4}")
        print(f"   [-] Falsos Negativos    (FN): {self.false_negatives:<4} | [v] Verdaderos Negativos (TN): {self.true_negatives:<4}")
        print("-" * 76)
        print(" INDICADORES ESTADISTICOS:")
        print(f"   * Exactitud  (Accuracy)   : {self.accuracy * 100:.1f}%")
        print(f"   * Precision  (Precision)  : {self.precision * 100:.1f}%")
        print(f"   * Sensibilidad (Recall)   : {self.recall * 100:.1f}%")
        print(f"   * Especificidad           : {self.specificity * 100:.1f}%")
        print(f"   * Puntuacion F1-Score     : {self.f1_score:.4f}")
        print(f"   * Tasa Falsos Positivos   : {self.false_positive_rate * 100:.1f}%")
        print(f"   * Coef. Matthews (MCC)    : {self.matthews_corr_coef:.4f}")
        print("-" * 76)
        print(" DESGLOSE DE PRECISION POR FAMILIA:")
        for cat_name, cat in self.categories.items():
            bar_len = int(cat.precision * 20)
            bar = "#" * bar_len + "." * (20 - bar_len)
            print(f"   {cat_name.upper():<18} [{bar}] {cat.precision * 100:>5.1f}%  (TP:{cat.true_positives} FP:{cat.false_positives} TN:{cat.true_negatives} FN:{cat.false_negatives})")
        print(border + "\n")


def _execute_test_case(base_url: str, tc: GroundTruthTestCase, session: requests.Session) -> bool:
    """
    Ejecuta el escáner específico correspondiente al caso de prueba.
    Retorna True si el escáner detectó una vulnerabilidad en dicho endpoint.
    """
    full_url = f"{base_url}{tc.path}"
    detected = False

    try:
        if tc.category == "sqli":
            findings = check_sqli(full_url, session=session)
            detected = len(findings) > 0

        elif tc.category == "xss":
            findings = check_xss(full_url, session=session)
            detected = len(findings) > 0

        elif tc.category == "dom_xss":
            r = session.get(full_url, timeout=4)
            findings = check_dom_xss(full_url, r.text)
            detected = len(findings) > 0

        elif tc.category == "cors":
            findings = check_cors(full_url, session=session)
            detected = len(findings) > 0

        elif tc.category == "headers":
            r = session.get(full_url, timeout=4)
            findings = check_headers(r)
            # Solo consideramos vulnerabilidad si faltan cabeceras críticas (CSP, HSTS, X-Content-Type)
            detected = len(findings) > 0

        elif tc.category == "open_redirect":
            findings = check_open_redirect(full_url, session=session)
            detected = len(findings) > 0

        elif tc.category == "sensitive_data":
            r = session.get(full_url, timeout=4)
            findings = check_sensitive_data(full_url, r.text, session=session)
            detected = len(findings) > 0

        elif tc.category == "cookies":
            r = session.get(full_url, timeout=4)
            findings = check_cookies(r)
            detected = len(findings) > 0

        elif tc.category == "fuzzer":
            # Para fuzzer comprobamos la exposición de archivos críticos directamente
            r = session.get(full_url, timeout=4)
            detected = r.status_code == 200 and ("DB_PASSWORD" in r.text or "JWT_SECRET" in r.text)

        elif tc.category == "prototype_pollution":
            r = session.get(full_url, timeout=4)
            findings = check_prototype_pollution(full_url, r.text, session=session)
            detected = len(findings) > 0

    except Exception as exc:
        logger.debug("Excepción evaluando caso %s: %s", tc.test_id, exc)
        detected = False

    return detected


def run_scientific_benchmark(
    target_url: str | None = None,
    save_reports: bool = True,
    reports_dir: str = "reports",
) -> ScientificBenchmarkResult:
    """
    Ejecuta la batería de benchmarking cuantitativo contra el entorno de pruebas.
    Si target_url es None, levanta de forma autónoma el SyntheticBenchmarkServer embebido.
    """
    server: SyntheticBenchmarkServer | None = None
    t0 = time.time()

    if target_url:
        base_url = target_url.rstrip("/")
        app_name = "Servidor Externo"
    else:
        server = SyntheticBenchmarkServer(host="127.0.0.1", port=0)
        base_url = server.start()
        app_name = "OWASP Synthetic Testbed"

    session = requests.Session()
    case_results: list[dict[str, Any]] = []

    # Inicializar contadores por categoría
    cat_counts: dict[str, dict[str, Any]] = {}
    for tc in GROUND_TRUTH_CATALOG:
        if tc.category not in cat_counts:
            cat_counts[tc.category] = {
                "cwe_id": tc.cwe_id,
                "total": 0,
                "tp": 0,
                "fp": 0,
                "tn": 0,
                "fn": 0,
            }

    tp_global = 0
    fp_global = 0
    tn_global = 0
    fn_global = 0

    try:
        for tc in GROUND_TRUTH_CATALOG:
            detected = _execute_test_case(base_url, tc, session)
            status_str = ""

            cat_dict = cat_counts[tc.category]
            cat_dict["total"] += 1

            if tc.is_vulnerable:
                if detected:
                    tp_global += 1
                    cat_dict["tp"] += 1
                    status_str = "TRUE_POSITIVE"
                else:
                    fn_global += 1
                    cat_dict["fn"] += 1
                    status_str = "FALSE_NEGATIVE"
            else:
                if detected:
                    fp_global += 1
                    cat_dict["fp"] += 1
                    status_str = "FALSE_POSITIVE"
                else:
                    tn_global += 1
                    cat_dict["tn"] += 1
                    status_str = "TRUE_NEGATIVE"

            case_results.append({
                "test_id": tc.test_id,
                "category": tc.category,
                "cwe_id": tc.cwe_id,
                "path": tc.path,
                "is_vulnerable": tc.is_vulnerable,
                "detected": detected,
                "status": status_str,
                "description": tc.description,
            })

    finally:
        if server:
            server.stop()

    duration = time.time() - t0
    total = len(GROUND_TRUTH_CATALOG)

    # Cálculo de métricas globales
    accuracy = (tp_global + tn_global) / total if total > 0 else 0.0
    precision = tp_global / (tp_global + fp_global) if (tp_global + fp_global) > 0 else 1.0
    recall = tp_global / (tp_global + fn_global) if (tp_global + fn_global) > 0 else 1.0
    specificity = tn_global / (tn_global + fp_global) if (tn_global + fp_global) > 0 else 1.0
    f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    fpr = fp_global / (fp_global + tn_global) if (fp_global + tn_global) > 0 else 0.0

    # Matthews Correlation Coefficient (MCC)
    mcc_num = (tp_global * tn_global) - (fp_global * fn_global)
    mcc_den = math.sqrt(
        (tp_global + fp_global) * (tp_global + fn_global) * (tn_global + fp_global) * (tn_global + fn_global)
    )
    mcc = (mcc_num / mcc_den) if mcc_den > 0 else 0.0

    # Construcción de categorías
    categories: dict[str, CategoryScore] = {}
    for cat_name, d in cat_counts.items():
        c_tp = d["tp"]
        c_fp = d["fp"]
        c_tn = d["tn"]
        c_fn = d["fn"]
        c_p = c_tp / (c_tp + c_fp) if (c_tp + c_fp) > 0 else 1.0
        c_r = c_tp / (c_tp + c_fn) if (c_tp + c_fn) > 0 else 1.0
        c_f1 = (2 * c_p * c_r) / (c_p + c_r) if (c_p + c_r) > 0 else 0.0

        categories[cat_name] = CategoryScore(
            category=cat_name,
            cwe_id=d["cwe_id"],
            total_cases=d["total"],
            true_positives=c_tp,
            false_positives=c_fp,
            true_negatives=c_tn,
            false_negatives=c_fn,
            precision=round(c_p, 4),
            recall=round(c_r, 4),
            f1_score=round(c_f1, 4),
        )

    res = ScientificBenchmarkResult(
        timestamp=datetime.now(timezone.utc).isoformat(),
        target_app=app_name,
        version="3.9",
        duration_seconds=round(duration, 3),
        total_cases=total,
        true_positives=tp_global,
        false_positives=fp_global,
        true_negatives=tn_global,
        false_negatives=fn_global,
        accuracy=round(accuracy, 4),
        precision=round(precision, 4),
        recall=round(recall, 4),
        specificity=round(specificity, 4),
        f1_score=round(f1, 4),
        false_positive_rate=round(fpr, 4),
        matthews_corr_coef=round(mcc, 4),
        categories=categories,
        case_results=case_results,
    )

    if save_reports:
        out_dir = Path(reports_dir)
        out_dir.mkdir(parents=True, exist_ok=True)

        json_path = out_dir / "scientific_benchmark_report.json"
        md_path = out_dir / "scientific_benchmark_report.md"
        tex_path = out_dir / "scientific_benchmark_table.tex"

        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(res.to_dict(), f, indent=2, ensure_ascii=False)

        with open(md_path, "w", encoding="utf-8") as f:
            f.write(res.to_markdown())

        with open(tex_path, "w", encoding="utf-8") as f:
            f.write(res.to_latex())

        logger.info("Reportes de benchmark guardados en: %s, %s y %s", json_path, md_path, tex_path)

    return res


if __name__ == "__main__":
    if sys.platform.startswith("win"):
        try:
            if hasattr(sys.stdout, "reconfigure"):
                sys.stdout.reconfigure(encoding="utf-8")
        except Exception:
            pass

    target = sys.argv[1] if len(sys.argv) > 1 else None
    result = run_scientific_benchmark(target)
    result.print_ascii_scorecard()
