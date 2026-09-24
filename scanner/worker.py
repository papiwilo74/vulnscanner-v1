"""OmniBreach Enterprise — Servicio Autónomo de Worker Distribuido (Cluster Node).

Permite ejecutar nodos de escaneo independientes en diferentes regiones de red/cloud
(AWS, GCP, Azure, On-Premise) que reclaman tareas de la cola persistente del coordinador.
"""
from __future__ import annotations

import argparse
import logging
import os
import signal
import sys
import time
from typing import Any

from scanner.cluster import ScanningWorkerDaemon

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [WorkerDaemon]: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("OmniBreach.Worker")


def run_worker() -> None:
    parser = argparse.ArgumentParser(
        description="OmniBreach v5.0.0 Enterprise — Nodo Worker de Escaneo Distribuido",
        epilog="Ejemplo: python -m scanner.worker --coordinator http://api.empresa.com --region us-east-1",
    )
    parser.add_argument(
        "--coordinator",
        type=str,
        default=os.environ.get("COORDINATOR_URL", "http://localhost:8000"),
        help="URL base del Coordinador/API de OmniBreach (defecto: http://localhost:8000 o $COORDINATOR_URL)",
    )
    parser.add_argument(
        "--region",
        type=str,
        default=os.environ.get("WORKER_REGION", "local"),
        help="Región o zona de red del worker (ej. us-east-1, eu-central-1, sa-east-1, local)",
    )
    parser.add_argument(
        "--name",
        type=str,
        default=os.environ.get("WORKER_NAME", None),
        help="Nombre identificador único del worker en el cluster",
    )
    parser.add_argument(
        "--poll-interval",
        type=float,
        default=float(os.environ.get("WORKER_POLL_INTERVAL", "2.5")),
        help="Intervalo en segundos entre consultas de tareas disponibles",
    )
    args = parser.parse_args()

    daemon = ScanningWorkerDaemon(
        coordinator_url=args.coordinator,
        name=args.name,
        region=args.region,
        poll_interval=args.poll_interval,
    )

    def _sig_handler(sig: int, frame: Any) -> None:
        logger.info("[WORKER] Señal de terminación recibida. Deteniendo nodo ordenadamente...")
        daemon.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, _sig_handler)
    signal.signal(signal.SIGTERM, _sig_handler)

    logger.info("=================================================================")
    logger.info("  OmniBreach v5.0.0 Enterprise — Nodo Worker Distribuido")
    logger.info("  Coordinador: %s | Región: %s", args.coordinator, args.region)
    logger.info("=================================================================")

    daemon.start()
    try:
        while daemon.is_running:
            time.sleep(1.0)
    except KeyboardInterrupt:
        daemon.stop()


if __name__ == "__main__":
    run_worker()
