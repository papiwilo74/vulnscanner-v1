"""
Harness de Ejecución Automatizada de Benchmarks y Detección de Regresiones.
Ejecuta baterías de prueba empíricas contra aplicaciones vulnerables estándar (OWASP Juice Shop y PyGoat),
persiste el historial de métricas y detecta regresiones en precisión o incremento de falsos positivos.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.benchmark_juiceshop import BenchmarkMetrics, run_juiceshop_benchmark
from tests.benchmark_pygoat import run_pygoat_benchmark

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("BenchmarkHarness")

HISTORY_FILE = Path("reports") / "benchmark_history.json"


class BenchmarkHarness:
    """Orquestador de benchmarks empíricos y guardián de calidad contra regresiones."""

    def __init__(self, history_path: Path = HISTORY_FILE):
        self.history_path = history_path
        self.history_path.parent.mkdir(parents=True, exist_ok=True)

    def load_history(self) -> list[dict[str, Any]]:
        if self.history_path.exists():
            try:
                with open(self.history_path, encoding="utf-8") as f:
                    return json.load(f)
            except (json.JSONDecodeError, OSError):
                return []
        return []

    def save_metrics(self, metrics: Any) -> None:
        history = self.load_history()
        entry = asdict(metrics)
        entry["timestamp"] = datetime.now(timezone.utc).isoformat()
        history.append(entry)
        with open(self.history_path, "w", encoding="utf-8") as f:
            json.dump(history, f, indent=2, ensure_ascii=False)
        logger.info("Métricas guardadas exitosamente en %s", self.history_path)

    def get_latest_metrics(self, target_app: str) -> dict[str, Any] | None:
        history = self.load_history()
        for item in reversed(history):
            if item.get("target_app", "").lower() == target_app.lower():
                return item
        return None

    def evaluate_regression(
        self, current: Any, previous: dict[str, Any] | None
    ) -> tuple[bool, list[str]]:
        """
        Evalúa si la nueva medición representa una regresión respecto a la anterior.
        Retorna: (hay_regresion: bool, motivos: list[str])
        """
        if not previous:
            return False, ["Línea base inicial registrada (no hay mediciones previas para comparar)."]

        reasons = []
        prev_prec = float(previous.get("precision", 0.0))
        prev_fp = int(previous.get("false_positives", 0))

        # Regla 1: Caída inadmisible en precisión
        if current.precision < prev_prec:
            diff = prev_prec - current.precision
            reasons.append(
                f"Regresión en Precisión: Cayó de {prev_prec:.1%} a {current.precision:.1%} (diferencia: -{diff:.1%})"
            )

        # Regla 2: Incremento en falsos positivos
        if current.false_positives > prev_fp:
            diff_fp = current.false_positives - prev_fp
            reasons.append(
                f"Regresión en Falsos Positivos: Aumentaron de {prev_fp} a {current.false_positives} (+{diff_fp} FPs)"
            )

        has_regression = len(reasons) > 0
        return has_regression, reasons

    def is_target_reachable(self, url: str) -> bool:
        try:
            r = requests.get(url, timeout=3)
            return r.status_code in [200, 301, 302, 401, 403]
        except requests.RequestException:
            return False


def main() -> None:
    parser = argparse.ArgumentParser(description="OmniBreach Automated Benchmark Harness")
    parser.add_argument("--juiceshop-url", default="http://localhost:3000", help="URL de OWASP Juice Shop")
    parser.add_argument("--pygoat-url", default="http://localhost:8000", help="URL de PyGoat")
    parser.add_argument("--fail-on-regression", action="store_true", help="Falla con código 1 si hay regresión")
    args = parser.parse_args()

    harness = BenchmarkHarness()
    any_bench_run = False
    global_regression = False

    # 1. Probar Juice Shop si está disponible
    if harness.is_target_reachable(args.juiceshop_url):
        logger.info("OWASP Juice Shop detectado en %s. Iniciando benchmark...", args.juiceshop_url)
        metrics = run_juiceshop_benchmark(args.juiceshop_url)
        prev = harness.get_latest_metrics("OWASP Juice Shop")
        has_reg, reasons = harness.evaluate_regression(metrics, prev)

        harness.save_metrics(metrics)
        any_bench_run = True

        for r in reasons:
            if has_reg:
                logger.error("[!] %s", r)
                global_regression = True
            else:
                logger.info("[*] %s", r)
    else:
        logger.warning("OWASP Juice Shop no accesible en %s. Omitiendo.", args.juiceshop_url)

    # 2. Probar PyGoat si está disponible
    if harness.is_target_reachable(args.pygoat_url):
        logger.info("PyGoat detectado en %s. Iniciando benchmark...", args.pygoat_url)
        metrics_pg = run_pygoat_benchmark(args.pygoat_url)
        prev_pg = harness.get_latest_metrics("PyGoat")
        has_reg_pg, reasons_pg = harness.evaluate_regression(metrics_pg, prev_pg)

        harness.save_metrics(metrics_pg)
        any_bench_run = True

        for r in reasons_pg:
            if has_reg_pg:
                logger.error("[!] %s", r)
                global_regression = True
            else:
                logger.info("[*] %s", r)
    else:
        logger.warning("PyGoat no accesible en %s. Omitiendo.", args.pygoat_url)

    if not any_bench_run:
        logger.info("No se detectaron servidores de prueba activos en local. Fin de ejecución.")
        sys.exit(0)

    if global_regression and args.fail_on_regression:
        logger.error("Se detectaron regresiones de calidad en los benchmarks. Abortando CI.")
        sys.exit(1)


if __name__ == "__main__":
    main()
