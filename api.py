import contextlib
import json
import logging
import os
import sqlite3
import uuid
from threading import Lock
from typing import Any, Optional

import requests
from fastapi import BackgroundTasks, FastAPI, HTTPException
from pydantic import BaseModel

from main import scan

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("VulnScannerAPI")

app = FastAPI(
    title="VulnScanner Enterprise API",
    description="Microservicio web para automatización de auditorías de seguridad, OAST, SARIF, Headless Crawling y Auto-Fix.",
    version="2.0.0"
)


_db_path = os.environ.get("VULNSCANNER_DB", os.path.join("reports", "tasks.db"))
_db_lock = Lock()


def _get_db() -> sqlite3.Connection:
    os.makedirs(os.path.dirname(_db_path), exist_ok=True)
    conn = sqlite3.connect(_db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    _init_db(conn)
    return conn


def _init_db(conn: sqlite3.Connection) -> None:
    conn.execute("""
        CREATE TABLE IF NOT EXISTS tasks (
            task_id TEXT PRIMARY KEY,
            url TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'queued',
            html_report_path TEXT,
            json_report_path TEXT,
            sarif_report_path TEXT,
            results TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    _ensure_column(conn, "tasks", "sarif_report_path", "TEXT")
    conn.commit()


def _ensure_column(conn: sqlite3.Connection, table: str, column: str, declaration: str) -> None:
    existing_columns = {
        row["name"] if isinstance(row, sqlite3.Row) else row[1]
        for row in conn.execute(f"PRAGMA table_info({table})").fetchall()
    }
    if column not in existing_columns:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {declaration}")


def _save_task(conn: sqlite3.Connection, task_id: str, **fields) -> None:
    valid = {"task_id", "url", "status", "html_report_path", "json_report_path", "sarif_report_path", "results"}
    updates = {k: fields[k] for k in fields if k in valid}
    if "results" in updates and not isinstance(updates["results"], str):
        updates["results"] = json.dumps(updates["results"], ensure_ascii=False)
    set_clause = ", ".join(f"{k} = ?" for k in updates)
    values = list(updates.values()) + [task_id]
    conn.execute(
        f"UPDATE tasks SET {set_clause}, updated_at = CURRENT_TIMESTAMP WHERE task_id = ?",
        values
    )
    conn.commit()


def _get_task(conn: sqlite3.Connection, task_id: str) -> Optional[dict[str, Any]]:
    row = conn.execute("SELECT * FROM tasks WHERE task_id = ?", (task_id,)).fetchone()
    if row is None:
        return None
    data = dict(row)
    if data.get("results") and isinstance(data["results"], str):
        with contextlib.suppress(json.JSONDecodeError, TypeError):
            data["results"] = json.loads(data["results"])
    return data


def _list_tasks(conn: sqlite3.Connection) -> list:
    rows = conn.execute("SELECT task_id, url, status, created_at FROM tasks ORDER BY created_at DESC").fetchall()
    return [{"task_id": r["task_id"], "url": r["url"], "status": r["status"], "created_at": r["created_at"]} for r in rows]


class ScanRequest(BaseModel):
    url: str
    stealth: bool = True
    delay: float = 0.0
    crawl: int = 1
    subdomains: bool = False
    cookie: Optional[str] = None
    auth: Optional[str] = None
    webhook_url: Optional[str] = None
    passive: bool = False
    enable_oast: bool = True
    profile: str = "normal"
    allow_private: bool = False
    har_file: Optional[str] = None
    headless_crawl: bool = False
    headless_login: bool = False
    openapi_spec: Optional[str] = None
    use_async_engine: bool = False
    no_waf_detect: bool = False


def run_scan_in_background(task_id: str, req: ScanRequest):
    """
    Ejecuta el escaneo en segundo plano, actualiza el estado de la tarea
    y envía la notificación por Webhook al finalizar si está configurada.
    """
    with _db_lock:
        conn = _get_db()
        _init_db(conn)
        _save_task(conn, task_id, status="running")
        conn.close()

    logger.info(f"Iniciando escaneo para la tarea {task_id} - URL: {req.url}")

    try:
        html_path, json_path, report_data = scan(
            url=req.url,
            no_open=True,
            cookie_str=req.cookie,
            auth_header=req.auth,
            crawl_pages=req.crawl,
            run_subdomains=req.subdomains,
            delay=req.delay,
            stealth=req.stealth,
            passive=req.passive,
            enable_oast=req.enable_oast,
            profile=req.profile,
            allow_private=req.allow_private,
            har_file=req.har_file,
            headless_crawl=req.headless_crawl,
            headless_login=req.headless_login,
            openapi_spec=req.openapi_spec,
            use_async_engine=req.use_async_engine,
            no_waf_detect=req.no_waf_detect,
        )
        if report_data and "error" in report_data:
            raise RuntimeError(report_data["error"])

        sarif_path = report_data.get("sarif_report_path") if isinstance(report_data, dict) else None

        with _db_lock:
            conn = _get_db()
            _save_task(conn, task_id, status="completed",
                       html_report_path=html_path,
                       json_report_path=json_path,
                       sarif_report_path=sarif_path,
                       results=report_data)
            conn.close()

        logger.info(f"Escaneo completado exitosamente para la tarea {task_id}")

        if req.webhook_url:
            send_webhook_notification(task_id, req.webhook_url, "completed", report_data)

    except Exception as e:
        logger.error(f"Error durante el escaneo de la tarea {task_id}: {str(e)}")
        error_info = {"error": str(e)}
        with _db_lock:
            conn = _get_db()
            _save_task(conn, task_id, status="failed", results=error_info)
            conn.close()

        if req.webhook_url:
            send_webhook_notification(task_id, req.webhook_url, "failed", error_info)


def send_webhook_notification(task_id: str, webhook_url: str, status: str, payload: Any):
    """Envía una petición POST con los resultados al Webhook especificado."""
    logger.info(f"Enviando notificación webhook para la tarea {task_id} a: {webhook_url}")
    try:
        response = requests.post(
            webhook_url,
            json={
                "task_id": task_id,
                "status": status,
                "data": payload
            },
            timeout=10
        )
        logger.info(f"Respuesta del Webhook recibida (Código {response.status_code})")
    except Exception as e:
        logger.warning(f"No se pudo enviar la notificación Webhook para la tarea {task_id}: {e}")


@app.get("/")
def read_root():
    return {
        "message": "Bienvenido a VulnScanner Enterprise API",
        "version": "2.0.0",
        "standards": ["OASIS SARIF v2.1.0", "CVSS v3.1", "MITRE ATT&CK", "OAST", "Playwright Headless", "HAR v1.2"],
        "docs_url": "/docs",
        "status": "online"
    }


@app.post("/scan", status_code=202)
def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    """
    Inicia un escaneo web en segundo plano y responde inmediatamente con un ID de tarea.
    """
    task_id = str(uuid.uuid4())
    with _db_lock:
        conn = _get_db()
        _init_db(conn)
        _save_task(conn, task_id, url=request.url, status="queued")
        conn.close()

    background_tasks.add_task(run_scan_in_background, task_id, request)

    return {
        "message": "Escaneo encolado correctamente",
        "task_id": task_id,
        "status_url": f"/scan/{task_id}"
    }


@app.get("/scan/{task_id}")
def get_scan_status(task_id: str):
    """
    Retorna el estado actual de una tarea de escaneo específica y sus resultados si terminó.
    """
    with _db_lock:
        conn = _get_db()
        task = _get_task(conn, task_id)
        conn.close()

    if task is None:
        raise HTTPException(status_code=404, detail="Tarea de escaneo no encontrada")
    return task


@app.get("/scans")
def list_scans():
    """
    Lista el historial de escaneos y sus estados correspondientes.
    """
    with _db_lock:
        conn = _get_db()
        tasks = _list_tasks(conn)
        conn.close()

    return {
        "total_tasks": len(tasks),
        "tasks": tasks
    }
