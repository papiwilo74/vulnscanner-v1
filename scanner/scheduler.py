"""
Motor de Programación Continua y Gestión de Tareas Recurrentes (Continuous Scan Scheduler).
Permite programar auditorías periódicas automatizadas (diarias, semanales) y calcular el Security Drift.
"""
from __future__ import annotations

import json
import logging
import os
import time
import uuid
from dataclasses import asdict, dataclass
from typing import Any

logger = logging.getLogger("OmniBreach.Scheduler")


@dataclass
class ScheduledTask:
    """Definición de una auditoría recurrente programada."""

    task_id: str
    target_url: str
    interval_hours: int
    profile: str
    created_at: str
    last_run_at: str | None
    next_run_at: str
    status: str = "active"  # active, paused, completed
    last_result_summary: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class ScanScheduler:
    """Administrador de calendario y ejecución periódica de escaneos de seguridad."""

    def __init__(self, storage_file: str = ".omnibreach_schedules.json") -> None:
        self.storage_file = storage_file
        self.tasks: dict[str, ScheduledTask] = {}
        self._load()

    def _load(self) -> None:
        if os.path.isfile(self.storage_file):
            try:
                with open(self.storage_file, encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, list):
                        for item in data:
                            task = ScheduledTask(**item)
                            self.tasks[task.task_id] = task
            except Exception as exc:
                logger.debug("Error cargando tareas programadas: %s", exc)

    def _save(self) -> None:
        try:
            with open(self.storage_file, "w", encoding="utf-8") as f:
                json.dump([t.to_dict() for t in self.tasks.values()], f, indent=2)
        except Exception as exc:
            logger.debug("Error guardando tareas programadas: %s", exc)

    def add_schedule(
        self,
        target_url: str,
        interval_hours: int = 24,
        profile: str = "normal",
        initial_delay_hours: int = 0,
    ) -> ScheduledTask:
        """Crea y registra una nueva tarea recurrente programada."""
        task_id = f"sched_{uuid.uuid4().hex[:8]}"
        now = time.time()
        created_at_str = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))
        next_run_ts = now + (initial_delay_hours * 3600)
        next_run_str = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(next_run_ts))

        task = ScheduledTask(
            task_id=task_id,
            target_url=target_url,
            interval_hours=max(1, interval_hours),
            profile=profile,
            created_at=created_at_str,
            last_run_at=None,
            next_run_at=next_run_str,
            status="active",
        )
        self.tasks[task_id] = task
        self._save()
        logger.info("[Scheduler] Tarea programada registrada: %s para %s cada %d horas.", task_id, target_url, interval_hours)
        return task

    def list_schedules(self, status: str | None = None) -> list[ScheduledTask]:
        """Retorna todas las tareas registradas, opcionalmente filtradas por estado."""
        if status:
            return [t for t in self.tasks.values() if t.status == status]
        return list(self.tasks.values())

    def get_due_tasks(self, current_timestamp: float | None = None) -> list[ScheduledTask]:
        """Obtiene las tareas cuya fecha de ejecución ya se cumplió."""
        now_ts = current_timestamp if current_timestamp is not None else time.time()
        now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now_ts))

        due_tasks: list[ScheduledTask] = []
        for task in self.tasks.values():
            if task.status == "active" and task.next_run_at <= now_iso:
                due_tasks.append(task)
        return due_tasks

    def mark_task_completed(
        self,
        task_id: str,
        summary: str | None = None,
        completion_timestamp: float | None = None,
    ) -> ScheduledTask | None:
        """Actualiza la fecha de última ejecución y calcula el siguiente disparo según el intervalo."""
        task = self.tasks.get(task_id)
        if not task:
            return None

        now_ts = completion_timestamp if completion_timestamp is not None else time.time()
        task.last_run_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now_ts))
        next_run_ts = now_ts + (task.interval_hours * 3600)
        task.next_run_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(next_run_ts))
        task.last_result_summary = summary
        self._save()
        return task

    def pause_schedule(self, task_id: str) -> bool:
        """Pausa una tarea programada activa."""
        task = self.tasks.get(task_id)
        if task:
            task.status = "paused"
            self._save()
            return True
        return False
