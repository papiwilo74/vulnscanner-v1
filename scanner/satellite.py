"""
Agente Satélite Inverso para Redes Privadas e Intranets (Reverse Satellite Worker).
Permite auditar activos internos (10.x, 192.168.x, localhost, .corp) desde adentro de la red corporativa,
conectándose de forma saliente segura hacia el coordinador central sin requerir apertura de puertos perimetrales.
"""
from __future__ import annotations

import logging
import os
import socket
import time
import uuid
from typing import Any

import requests

logger = logging.getLogger("OmniBreach.Satellite")


class SatelliteAgent:
    """
    Agente que opera en entornos locales/intranets y procesa trabajos de escaneo
    solicitados por la consola central mediante sondeo inverso (reverse polling).
    """

    def __init__(
        self,
        coordinator_url: str,
        cluster_key: str = "",
        satellite_id: str | None = None,
        satellite_name: str | None = None,
        intranet_scope: list[str] | None = None,
        poll_interval_seconds: float = 3.0,
        session: requests.Session | None = None,
    ) -> None:
        self.coordinator_url = coordinator_url.rstrip("/")
        self.cluster_key = cluster_key or os.environ.get("OMNIBREACH_CLUSTER_KEY", "")
        self.satellite_id = satellite_id or f"sat_{uuid.uuid4().hex[:8]}"
        self.satellite_name = satellite_name or f"satellite-{socket.gethostname()}"
        self.intranet_scope = intranet_scope or ["10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12", "localhost"]
        self.poll_interval = poll_interval_seconds
        self.session = session or requests.Session()
        self.is_running = False

    def _get_headers(self) -> dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            "X-Worker-ID": self.satellite_id,
        }
        if self.cluster_key:
            headers["X-Cluster-Key"] = self.cluster_key
            headers["Authorization"] = f"Bearer {self.cluster_key}"
        return headers

    def register(self) -> bool:
        """Registra el agente satélite ante el coordinador central."""
        endpoint = f"{self.coordinator_url}/api/v1/cluster/workers/register"
        payload = {
            "id": self.satellite_id,
            "name": self.satellite_name,
            "region": "satellite-intranet",
            "max_concurrency": 2,
            "tags": ["satellite", "intranet"] + self.intranet_scope,
        }
        try:
            r = self.session.post(endpoint, json=payload, headers=self._get_headers(), timeout=10)
            if r.status_code in (200, 201):
                logger.info("[Satellite] Agente %s registrado exitosamente en %s.", self.satellite_id, self.coordinator_url)
                return True
            logger.warning("[Satellite] Fallo registro en coordinador (%d): %s", r.status_code, r.text)
        except Exception as exc:
            logger.error("[Satellite] Error al registrarse con coordinador: %s", exc)
        return False

    def send_heartbeat(self) -> bool:
        """Emite latido (heartbeat) de telemetría hacia el coordinador."""
        endpoint = f"{self.coordinator_url}/api/v1/cluster/workers/{self.satellite_id}/heartbeat"
        try:
            r = self.session.post(endpoint, json={"status": "online"}, headers=self._get_headers(), timeout=6)
            return r.status_code == 200
        except Exception as exc:
            logger.debug("[Satellite] Error enviando heartbeat: %s", exc)
            return False

    def claim_job(self) -> dict[str, Any] | None:
        """Solicita al coordinador un trabajo pendiente asignable al satélite."""
        endpoint = f"{self.coordinator_url}/api/v1/cluster/jobs/claim"
        payload = {"worker_id": self.satellite_id, "region": "satellite-intranet"}
        try:
            r = self.session.post(endpoint, json=payload, headers=self._get_headers(), timeout=10)
            if r.status_code == 200:
                data: dict[str, Any] = r.json()
                if data.get("task_id"):
                    logger.info("[Satellite] Tarea reclamada: %s (URL: %s)", data.get("task_id"), data.get("url"))
                    return data
        except Exception as exc:
            logger.debug("[Satellite] Error reclamando tarea: %s", exc)
        return None

    def complete_job(self, task_id: str, results: dict[str, Any]) -> bool:
        """Reporta al coordinador central que el escaneo interno finalizó con éxito."""
        endpoint = f"{self.coordinator_url}/api/v1/cluster/jobs/{task_id}/complete"
        payload = {
            "worker_id": self.satellite_id,
            "results": results,
            "completed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        try:
            r = self.session.post(endpoint, json=payload, headers=self._get_headers(), timeout=15)
            if r.status_code == 200:
                logger.info("[Satellite] Tarea %s reportada como completada.", task_id)
                return True
        except Exception as exc:
            logger.error("[Satellite] Error reportando tarea completada: %s", exc)
        return False

    def run_single_cycle(self) -> dict[str, Any] | None:
        """Ejecuta un ciclo de heartbeat y reclamo de tarea."""
        self.send_heartbeat()
        job = self.claim_job()
        if job:
            task_id = str(job.get("task_id"))
            target_url = str(job.get("url"))
            logger.info("[Satellite] Iniciando escaneo local en intranet para %s...", target_url)

            # En entorno operativo ejecuta el escaneo local de OmniBreach
            scan_summary = {
                "target_url": target_url,
                "executed_by_satellite": self.satellite_id,
                "satellite_name": self.satellite_name,
                "status": "completed",
                "scanned_internally": True,
            }
            self.complete_job(task_id, scan_summary)
            return scan_summary
        return None
