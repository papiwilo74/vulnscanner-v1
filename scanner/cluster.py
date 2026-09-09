"""
Motor de Cluster de Escaneo Distribuido y Orquestador de Workers Multi-Región.
Permite coordinar nodos de escaneo distribuidos en AWS, GCP o redes privadas
con balanceo de carga, heartbeats y failover automático.
"""
import contextlib
import datetime
import json
import logging
import os
import secrets
import sqlite3
import threading
import time
from collections.abc import Generator
from dataclasses import asdict, dataclass, field
from typing import Any, Optional

import requests

logger = logging.getLogger("VulnScanner.Cluster")


@dataclass
class WorkerNode:
    """Representa un nodo worker de escaneo registrado en el cluster."""

    id: str
    name: str
    region: str  # ej. "us-east-1", "eu-central-1", "sa-east-1", "local"
    status: str = "online"  # "online", "busy", "offline"
    max_concurrency: int = 2
    active_jobs: int = 0
    tags: list[str] = field(default_factory=list)
    last_heartbeat: str = field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())
    registered_at: str = field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ClusterJob:
    """Representa una tarea de escaneo distribuida asignada o encolada."""

    task_id: str
    tenant_id: str
    url: str
    profile: str
    status: str  # "queued", "claimed", "running", "completed", "failed"
    config_json: str = "{}"
    assigned_worker_id: Optional[str] = None
    region_preference: Optional[str] = None
    results_json: Optional[str] = None
    created_at: str = field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())
    started_at: Optional[str] = None
    completed_at: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        if self.results_json:
            with contextlib.suppress(Exception):
                d["results"] = json.loads(self.results_json)
        return d


class ClusterCoordinator:
    """Orquestador maestro del cluster: administra workers, heartbeats y despacha tareas."""

    def __init__(self, db_path: Optional[str] = None) -> None:
        if db_path is None:
            reports_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "reports")
            os.makedirs(reports_dir, exist_ok=True)
            self.db_path = os.path.join(reports_dir, "cluster.db")
        else:
            self.db_path = db_path
            os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)

        self._lock = threading.Lock()
        self._init_db()

    @contextlib.contextmanager
    def _connection(self) -> Generator[sqlite3.Connection, None, None]:
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        try:
            yield conn
        finally:
            conn.close()

    def _init_db(self) -> None:
        with self._lock, self._connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS cluster_workers (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    region TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'online',
                    max_concurrency INTEGER NOT NULL DEFAULT 2,
                    active_jobs INTEGER NOT NULL DEFAULT 0,
                    tags TEXT NOT NULL DEFAULT '[]',
                    last_heartbeat TEXT NOT NULL,
                    registered_at TEXT NOT NULL
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS cluster_jobs (
                    task_id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    url TEXT NOT NULL,
                    profile TEXT NOT NULL DEFAULT 'normal',
                    status TEXT NOT NULL DEFAULT 'queued',
                    config_json TEXT NOT NULL DEFAULT '{}',
                    assigned_worker_id TEXT,
                    region_preference TEXT,
                    results_json TEXT,
                    created_at TEXT NOT NULL,
                    started_at TEXT,
                    completed_at TEXT,
                    FOREIGN KEY (assigned_worker_id) REFERENCES cluster_workers (id)
                )
            """)
            conn.commit()

    def register_worker(
        self,
        name: str,
        region: str = "local",
        max_concurrency: int = 2,
        tags: Optional[list[str]] = None,
        worker_id: Optional[str] = None,
    ) -> WorkerNode:
        w_id = worker_id or f"worker_{secrets.token_hex(6)}"
        now_str = datetime.datetime.now(datetime.timezone.utc).isoformat()
        tags_list = tags or []

        node = WorkerNode(
            id=w_id,
            name=name,
            region=region,
            status="online",
            max_concurrency=max_concurrency,
            active_jobs=0,
            tags=tags_list,
            last_heartbeat=now_str,
            registered_at=now_str,
        )

        with self._lock, self._connection() as conn:
            conn.execute(
                """
                INSERT INTO cluster_workers (
                    id, name, region, status, max_concurrency, active_jobs, tags, last_heartbeat, registered_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    name = excluded.name,
                    region = excluded.region,
                    status = excluded.status,
                    max_concurrency = excluded.max_concurrency,
                    tags = excluded.tags,
                    last_heartbeat = excluded.last_heartbeat
                """,
                (
                    node.id,
                    node.name,
                    node.region,
                    node.status,
                    node.max_concurrency,
                    node.active_jobs,
                    json.dumps(node.tags),
                    node.last_heartbeat,
                    node.registered_at,
                ),
            )
            conn.commit()

        logger.info("[CLUSTER] Worker registrado: %s (%s) en región %s", node.name, node.id, node.region)
        return node

    def heartbeat(self, worker_id: str, active_jobs: int = 0, status: str = "online") -> bool:
        now_str = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with self._lock, self._connection() as conn:
            cursor = conn.execute(
                "UPDATE cluster_workers SET last_heartbeat = ?, active_jobs = ?, status = ? WHERE id = ?",
                (now_str, active_jobs, status, worker_id),
            )
            conn.commit()
            return cursor.rowcount > 0

    def list_workers(self, include_offline: bool = True) -> list[WorkerNode]:
        self.reap_stale_workers(timeout_seconds=45)
        with self._lock, self._connection() as conn:
            query = "SELECT * FROM cluster_workers"
            if not include_offline:
                query += " WHERE status != 'offline'"
            query += " ORDER BY registered_at DESC"
            rows = conn.execute(query).fetchall()
            workers: list[WorkerNode] = []
            for r in rows:
                try:
                    t_list = json.loads(r["tags"])
                except Exception:
                    t_list = []
                workers.append(
                    WorkerNode(
                        id=r["id"],
                        name=r["name"],
                        region=r["region"],
                        status=r["status"],
                        max_concurrency=r["max_concurrency"],
                        active_jobs=r["active_jobs"],
                        tags=t_list,
                        last_heartbeat=r["last_heartbeat"],
                        registered_at=r["registered_at"],
                    )
                )
            return workers

    def enqueue_job(
        self,
        task_id: str,
        tenant_id: str,
        url: str,
        profile: str = "normal",
        config: Optional[dict[str, Any]] = None,
        region_preference: Optional[str] = None,
    ) -> ClusterJob:
        now_str = datetime.datetime.now(datetime.timezone.utc).isoformat()
        cfg_str = json.dumps(config or {}, ensure_ascii=False)

        job = ClusterJob(
            task_id=task_id,
            tenant_id=tenant_id,
            url=url,
            profile=profile,
            status="queued",
            config_json=cfg_str,
            region_preference=region_preference,
            created_at=now_str,
        )

        with self._lock, self._connection() as conn:
            conn.execute(
                """
                INSERT INTO cluster_jobs (
                    task_id, tenant_id, url, profile, status, config_json, region_preference, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (job.task_id, job.tenant_id, job.url, job.profile, job.status, job.config_json, job.region_preference, job.created_at),
            )
            conn.commit()

        logger.info("[CLUSTER] Tarea encolada en cluster: %s (Tenant: %s) -> Región: %s", task_id, tenant_id, region_preference or "Cualquiera")
        return job

    def claim_job(self, worker_id: str, worker_region: str = "local") -> Optional[ClusterJob]:
        """Un worker reclama la siguiente tarea disponible compatible con su región."""
        now_str = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with self._lock, self._connection() as conn:
            # Buscar primero tareas específicas para la región del worker o globales (region_preference IS NULL)
            row = conn.execute(
                """
                SELECT * FROM cluster_jobs
                WHERE status = 'queued'
                  AND (region_preference IS NULL OR region_preference = ? OR region_preference = '')
                ORDER BY created_at ASC LIMIT 1
                """,
                (worker_region,),
            ).fetchone()

            if not row:
                return None

            task_id = row["task_id"]
            conn.execute(
                """
                UPDATE cluster_jobs
                SET status = 'claimed', assigned_worker_id = ?, started_at = ?
                WHERE task_id = ?
                """,
                (worker_id, now_str, task_id),
            )
            conn.execute(
                "UPDATE cluster_workers SET active_jobs = active_jobs + 1, status = 'busy' WHERE id = ?",
                (worker_id,),
            )
            conn.commit()

            return ClusterJob(
                task_id=row["task_id"],
                tenant_id=row["tenant_id"],
                url=row["url"],
                profile=row["profile"],
                status="claimed",
                config_json=row["config_json"],
                assigned_worker_id=worker_id,
                region_preference=row["region_preference"],
                created_at=row["created_at"],
                started_at=now_str,
            )

    def complete_job(self, task_id: str, worker_id: str, results: dict[str, Any]) -> None:
        now_str = datetime.datetime.now(datetime.timezone.utc).isoformat()
        res_str = json.dumps(results, ensure_ascii=False)
        with self._lock, self._connection() as conn:
            conn.execute(
                "UPDATE cluster_jobs SET status = 'completed', results_json = ?, completed_at = ? WHERE task_id = ?",
                (res_str, now_str, task_id),
            )
            conn.execute(
                "UPDATE cluster_workers SET active_jobs = MAX(0, active_jobs - 1) WHERE id = ?",
                (worker_id,),
            )
            # Si no quedan tareas, marcar online
            conn.execute(
                "UPDATE cluster_workers SET status = 'online' WHERE id = ? AND active_jobs = 0",
                (worker_id,),
            )
            conn.commit()
        logger.info("[CLUSTER] Tarea completada por worker %s: %s", worker_id, task_id)

    def fail_job(self, task_id: str, worker_id: str, error_message: str) -> None:
        now_str = datetime.datetime.now(datetime.timezone.utc).isoformat()
        err_dict = {"error": error_message}
        with self._lock, self._connection() as conn:
            conn.execute(
                "UPDATE cluster_jobs SET status = 'failed', results_json = ?, completed_at = ? WHERE task_id = ?",
                (json.dumps(err_dict), now_str, task_id),
            )
            conn.execute(
                "UPDATE cluster_workers SET active_jobs = MAX(0, active_jobs - 1) WHERE id = ?",
                (worker_id,),
            )
            conn.commit()
        logger.warning("[CLUSTER] Tarea fallida en worker %s: %s - Error: %s", worker_id, task_id, error_message)

    def reap_stale_workers(self, timeout_seconds: int = 45) -> list[str]:
        """Failover: Detecta workers sin heartbeat reciente, los marca offline y reencola sus tareas activas."""
        now = datetime.datetime.now(datetime.timezone.utc)
        reaped_workers: list[str] = []

        with self._lock, self._connection() as conn:
            workers = conn.execute("SELECT id, last_heartbeat FROM cluster_workers WHERE status != 'offline'").fetchall()
            for w in workers:
                try:
                    last_hb = datetime.datetime.fromisoformat(w["last_heartbeat"])
                    if (now - last_hb).total_seconds() > timeout_seconds:
                        conn.execute("UPDATE cluster_workers SET status = 'offline' WHERE id = ?", (w["id"],))
                        # Reencolar tareas que estaban asignadas a este worker y no finalizaron
                        conn.execute(
                            "UPDATE cluster_jobs SET status = 'queued', assigned_worker_id = NULL WHERE assigned_worker_id = ? AND status IN ('claimed', 'running')",
                            (w["id"],),
                        )
                        reaped_workers.append(w["id"])
                except Exception:
                    pass
            if reaped_workers:
                conn.commit()
                logger.info("[CLUSTER FAILOVER] Workers desconectados detectados: %s. Tareas reencoladas.", reaped_workers)

        return reaped_workers

    def get_stats(self) -> dict[str, Any]:
        self.reap_stale_workers(timeout_seconds=45)
        with self._lock, self._connection() as conn:
            total_w = conn.execute("SELECT COUNT(*) FROM cluster_workers").fetchone()[0]
            online_w = conn.execute("SELECT COUNT(*) FROM cluster_workers WHERE status = 'online'").fetchone()[0]
            busy_w = conn.execute("SELECT COUNT(*) FROM cluster_workers WHERE status = 'busy'").fetchone()[0]
            total_j = conn.execute("SELECT COUNT(*) FROM cluster_jobs").fetchone()[0]
            queued_j = conn.execute("SELECT COUNT(*) FROM cluster_jobs WHERE status = 'queued'").fetchone()[0]
            running_j = conn.execute("SELECT COUNT(*) FROM cluster_jobs WHERE status IN ('claimed', 'running')").fetchone()[0]
            completed_j = conn.execute("SELECT COUNT(*) FROM cluster_jobs WHERE status = 'completed'").fetchone()[0]

            return {
                "total_workers": total_w,
                "online_workers": online_w,
                "busy_workers": busy_w,
                "total_jobs": total_j,
                "queued_jobs": queued_j,
                "running_jobs": running_j,
                "completed_jobs": completed_j,
            }


class ScanningWorkerDaemon:
    """Cliente Worker autónomo: sondea tareas desde el coordinador, ejecuta escaneos y reporta estado."""

    def __init__(
        self,
        coordinator_url: str = "http://localhost:8000",
        name: Optional[str] = None,
        region: str = "local",
        poll_interval: float = 2.5,
    ) -> None:
        self.coordinator_url = coordinator_url.rstrip("/")
        self.region = region
        self.name = name or f"Worker-{region}-{secrets.token_hex(3)}"
        self.poll_interval = poll_interval
        self.worker_id = f"w_{secrets.token_hex(6)}"
        self.is_running = False
        self._thread: Optional[threading.Thread] = None

    def register(self) -> bool:
        try:
            resp = requests.post(
                f"{self.coordinator_url}/api/cluster/workers/register",
                json={
                    "worker_id": self.worker_id,
                    "name": self.name,
                    "region": self.region,
                    "max_concurrency": 2,
                    "tags": ["distributed-scanner", self.region],
                },
                timeout=5,
            )
            return resp.status_code == 200
        except Exception as e:
            logger.warning("[WORKER] No se pudo registrar ante el coordinador (%s): %s", self.coordinator_url, e)
            return False

    def send_heartbeat(self, active_jobs: int = 0) -> None:
        with contextlib.suppress(Exception):
            requests.post(
                f"{self.coordinator_url}/api/cluster/workers/{self.worker_id}/heartbeat",
                json={"active_jobs": active_jobs, "status": "busy" if active_jobs > 0 else "online"},
                timeout=3,
            )

    def start(self) -> None:
        self.is_running = True
        self.register()
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()
        logger.info("[WORKER] Worker %s iniciado en región %s (Conectado a %s)", self.name, self.region, self.coordinator_url)

    def stop(self) -> None:
        self.is_running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2)
        logger.info("[WORKER] Worker %s detenido.", self.name)

    def _run_loop(self) -> None:
        from main import scan

        last_hb = 0.0
        while self.is_running:
            now = time.time()
            if now - last_hb > 10.0:
                self.send_heartbeat(active_jobs=0)
                last_hb = now

            job_data: Optional[dict[str, Any]] = None
            try:
                resp = requests.post(
                    f"{self.coordinator_url}/api/cluster/jobs/claim",
                    json={"worker_id": self.worker_id, "region": self.region},
                    timeout=5,
                )
                if resp.status_code == 200:
                    body = resp.json()
                    if body.get("claimed") and body.get("job"):
                        job_data = body["job"]
            except Exception:
                pass

            if not job_data:
                time.sleep(self.poll_interval)
                continue

            task_id = job_data["task_id"]
            target_url = job_data["url"]
            profile = job_data.get("profile", "normal")
            logger.info("[WORKER] Ejecutando tarea reclamada: %s -> %s (Perfil: %s)", task_id, target_url, profile)

            self.send_heartbeat(active_jobs=1)
            try:
                html_path, json_path, report_data = scan(
                    url=target_url,
                    profile=profile,
                    no_open=True,
                    generate_pdf=True,
                )
                # Enviar resultados al coordinador
                requests.post(
                    f"{self.coordinator_url}/api/cluster/jobs/{task_id}/complete",
                    json={
                        "worker_id": self.worker_id,
                        "results": report_data,
                        "html_path": html_path,
                        "json_path": json_path,
                    },
                    timeout=15,
                )
                logger.info("[WORKER] Tarea %s completada exitosamente.", task_id)
            except Exception as e:
                logger.error("[WORKER] Error ejecutando tarea %s: %s", task_id, e)
                with contextlib.suppress(Exception):
                    requests.post(
                        f"{self.coordinator_url}/api/cluster/jobs/{task_id}/fail",
                        json={"worker_id": self.worker_id, "error": str(e)},
                        timeout=5,
                    )
            finally:
                self.send_heartbeat(active_jobs=0)

            time.sleep(1.0)
