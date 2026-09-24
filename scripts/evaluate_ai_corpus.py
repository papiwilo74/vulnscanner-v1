"""
Script ejecutor de Evaluación Cuantitativa de Precisión: Motor Solo vs. Motor + IA.

Ejecuta el benchmark contra el corpus versionado (data/ai_evaluation_corpus_v1.json),
calcula métricas comparativas y genera los reportes formalizados en reports/.
"""
from __future__ import annotations

import argparse
import logging
import os
import sys
from pathlib import Path

# Añadir raíz del proyecto al sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner.ai_evaluator import (
    DEFAULT_CORPUS_PATH,
    DEFAULT_REPORT_JSON,
    DEFAULT_REPORT_MD,
    AIEvaluator,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("OmniBreach.AIEvalCLI")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Evaluación cuantitativa del AI Copilot de OmniBreach (Motor Solo vs. Motor + IA)"
    )
    parser.add_argument(
        "--corpus",
        type=Path,
        default=DEFAULT_CORPUS_PATH,
        help="Ruta al archivo JSON del corpus versionado con ground truth.",
    )
    parser.add_argument(
        "--report-json",
        type=Path,
        default=DEFAULT_REPORT_JSON,
        help="Ruta de destino para el reporte detallado en JSON.",
    )
    parser.add_argument(
        "--report-md",
        type=Path,
        default=DEFAULT_REPORT_MD,
        help="Ruta de destino para el reporte de auditoría en Markdown.",
    )

    args = parser.parse_args()

    logger.info("Iniciando evaluación cuantitativa contra corpus: %s", args.corpus)
    evaluator = AIEvaluator(corpus_path=args.corpus)
    report = evaluator.run_and_save_reports(
        json_path=args.report_json,
        md_path=args.report_md,
    )

    base = report.baseline_engine
    hyb = report.hybrid_engine

    print("\n" + "=" * 70)
    print("      OMNIBREACH v3.8 - EVALUACIÓN CUANTITATIVA DE IA (GROUND TRUTH)")
    print("=" * 70)
    print(f" Total de Muestras Evaluadas: {report.total_samples}")
    print(f" Verdaderos Positivos Reales: {report.ground_truth_positives}")
    print(f" Falsos Positivos / Ruido:    {report.ground_truth_negatives}")
    print("-" * 70)
    print(" MÉTRICA                      MOTOR SOLO      MOTOR + IA      DELTA")
    print("-" * 70)
    print(f" Precisión (Precision)        {base.precision*100:6.1f}%         {hyb.precision*100:6.1f}%       +{report.precision_gain_percent:5.1f}%")
    print(f" Sensibilidad (Recall)        {base.recall*100:6.1f}%         {hyb.recall*100:6.1f}%        0.0%")
    print(f" F1-Score                     {base.f1_score:6.4f}          {hyb.f1_score:6.4f}       +{report.f1_gain_percent:5.1f}%")
    print(f" Falsos Positivos (Ruido)     {base.false_positives:6d}          {hyb.false_positives:6d}       -{report.false_positives_reduced_count} ({report.false_positives_reduced_percent:.1f}%)")
    print(f" Alucinaciones Bloqueadas:    {report.hallucinations_blocked_count} intentos neutralizados por guardrails")
    print("=" * 70)
    print(f" Reporte JSON guardado en:     {args.report_json}")
    print(f" Reporte Markdown guardado en: {args.report_md}")
    print("=" * 70 + "\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())
