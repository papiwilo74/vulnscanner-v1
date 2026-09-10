import asyncio
import contextlib
import json
import logging
import os
import sqlite3
import uuid
from threading import Lock
from typing import Any, Optional

import requests
import yaml
from fastapi import BackgroundTasks, FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse
from pydantic import BaseModel

from main import scan
from scanner.cluster import ClusterCoordinator
from scanner.deception import DeceptionManager, SnippetGenerator
from scanner.tenancy import ROLE_PERMISSIONS, Role, TenancyManager, User

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("OmniBreachAPI")

app = FastAPI(
    title="OmniBreach v3.0 API",
    description="Plataforma de Ciberdefensa Ofensiva & EASM (External Attack Surface Management): Cartografía de Subdominios, Detección de Puertos de Ransomware, Correlación CISA KEV, DAST, SAST, IAST/RASP, Grafos de Ataque, Cluster Distribuido y Multi-Tenancy con RBAC.",
    version="3.0"
)

# Soporte CORS para despliegue distribuido (Frontend Vercel <-> Backend Render)
_allowed_origins_raw = os.environ.get("CORS_ORIGINS", "*")
_allowed_origins = [orig.strip() for orig in _allowed_origins_raw.split(",") if orig.strip()] or ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins if "*" not in _allowed_origins else ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

deception_mgr = DeceptionManager()
tenancy_mgr = TenancyManager()
cluster_mgr = ClusterCoordinator()

_db_path = os.environ.get("OMNIBREACH_DB", os.environ.get("VULNSCANNER_DB", os.path.join("reports", "tasks.db")))
_db_lock = Lock()


class EventBroadcaster:
    """Administra conexiones WebSocket activas y retransmite eventos en vivo."""

    def __init__(self) -> None:
        self.active_connections: dict[str, list[WebSocket]] = {}
        self.event_history: dict[str, list[dict[str, Any]]] = {}
        self.lock = Lock()

    def connect(self, task_id: str, websocket: WebSocket) -> list[dict[str, Any]]:
        with self.lock:
            self.active_connections.setdefault(task_id, []).append(websocket)
            return list(self.event_history.get(task_id, []))

    def disconnect(self, task_id: str, websocket: WebSocket) -> None:
        with self.lock:
            if task_id in self.active_connections:
                if websocket in self.active_connections[task_id]:
                    self.active_connections[task_id].remove(websocket)
                if not self.active_connections[task_id]:
                    del self.active_connections[task_id]

    def record_and_get_targets(self, task_id: str, event_data: dict[str, Any]) -> list[WebSocket]:
        with self.lock:
            self.event_history.setdefault(task_id, []).append(event_data)
            return list(self.active_connections.get(task_id, []))

    def get_all_targets(self) -> list[WebSocket]:
        with self.lock:
            targets: list[WebSocket] = []
            for sockets in self.active_connections.values():
                targets.extend(sockets)
            return targets


broadcaster = EventBroadcaster()


def broadcast_deception_alert(event_data: dict[str, Any]) -> None:
    """Envía alerta de canario detonado a todas las conexiones activas y al canal 'deception'."""
    sockets = broadcaster.record_and_get_targets("deception", event_data)
    all_targets = set(sockets).union(broadcaster.get_all_targets())
    if not all_targets:
        return

    msg = json.dumps(event_data, ensure_ascii=False)

    async def _send_all() -> None:
        for ws in all_targets:
            with contextlib.suppress(Exception):
                await ws.send_text(msg)

    try:
        loop = asyncio.get_running_loop()
        asyncio.run_coroutine_threadsafe(_send_all(), loop)
    except RuntimeError:
        new_loop = asyncio.new_event_loop()
        try:
            new_loop.run_until_complete(_send_all())
        finally:
            new_loop.close()


def broadcast_event_sync(task_id: str, event_data: dict[str, Any]) -> None:
    """Envía un evento a todos los clientes WebSocket suscritos a la tarea."""
    sockets = broadcaster.record_and_get_targets(task_id, event_data)
    if not sockets:
        return

    msg = json.dumps(event_data, ensure_ascii=False)

    async def _send_all() -> None:
        for ws in sockets:
            with contextlib.suppress(Exception):
                await ws.send_text(msg)

    try:
        loop = asyncio.get_running_loop()
        asyncio.run_coroutine_threadsafe(_send_all(), loop)
    except RuntimeError:
        new_loop = asyncio.new_event_loop()
        try:
            new_loop.run_until_complete(_send_all())
        finally:
            new_loop.close()


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
            pdf_report_path TEXT,
            results TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    _ensure_column(conn, "tasks", "sarif_report_path", "TEXT")
    _ensure_column(conn, "tasks", "pdf_report_path", "TEXT")
    _ensure_column(conn, "tasks", "tenant_id", "TEXT DEFAULT 'org_default'")
    _ensure_column(conn, "tasks", "region", "TEXT DEFAULT 'local'")
    conn.commit()


def _ensure_column(conn: sqlite3.Connection, table: str, column: str, declaration: str) -> None:
    existing_columns = {
        row["name"] if isinstance(row, sqlite3.Row) else row[1]
        for row in conn.execute(f"PRAGMA table_info({table})").fetchall()
    }
    if column not in existing_columns:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {declaration}")


def _save_task(conn: sqlite3.Connection, task_id: str, **fields: Any) -> None:
    valid = {"task_id", "url", "status", "html_report_path", "json_report_path", "sarif_report_path", "pdf_report_path", "results", "tenant_id", "region"}
    updates = {k: fields[k] for k in fields if k in valid}
    if "results" in updates and not isinstance(updates["results"], str):
        updates["results"] = json.dumps(updates["results"], ensure_ascii=False)

    existing = conn.execute("SELECT task_id FROM tasks WHERE task_id = ?", (task_id,)).fetchone()
    if existing:
        conn.execute(
            """
            UPDATE tasks SET
                url = COALESCE(?, url),
                status = COALESCE(?, status),
                html_report_path = COALESCE(?, html_report_path),
                json_report_path = COALESCE(?, json_report_path),
                sarif_report_path = COALESCE(?, sarif_report_path),
                pdf_report_path = COALESCE(?, pdf_report_path),
                results = COALESCE(?, results),
                tenant_id = COALESCE(?, tenant_id),
                region = COALESCE(?, region),
                updated_at = CURRENT_TIMESTAMP
            WHERE task_id = ?
            """,
            (
                updates.get("url"),
                updates.get("status"),
                updates.get("html_report_path"),
                updates.get("json_report_path"),
                updates.get("sarif_report_path"),
                updates.get("pdf_report_path"),
                updates.get("results"),
                updates.get("tenant_id"),
                updates.get("region"),
                task_id,
            ),
        )
    else:
        conn.execute(
            """
            INSERT INTO tasks (
                task_id, url, status, html_report_path, json_report_path,
                sarif_report_path, pdf_report_path, results, tenant_id, region
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                task_id,
                updates.get("url", ""),
                updates.get("status", "queued"),
                updates.get("html_report_path"),
                updates.get("json_report_path"),
                updates.get("sarif_report_path"),
                updates.get("pdf_report_path"),
                updates.get("results"),
                updates.get("tenant_id", "org_default"),
                updates.get("region", "local"),
            ),
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


def _list_tasks(conn: sqlite3.Connection, tenant_id: Optional[str] = None) -> list[dict[str, Any]]:
    if tenant_id:
        rows = conn.execute("SELECT task_id, url, status, created_at, tenant_id, region FROM tasks WHERE tenant_id = ? ORDER BY created_at DESC", (tenant_id,)).fetchall()
    else:
        rows = conn.execute("SELECT task_id, url, status, created_at, tenant_id, region FROM tasks ORDER BY created_at DESC").fetchall()
    result: list[dict[str, Any]] = []
    for r in rows:
        r_dict = dict(r)
        result.append({
            "task_id": r_dict.get("task_id"),
            "url": r_dict.get("url"),
            "status": r_dict.get("status"),
            "created_at": r_dict.get("created_at"),
            "tenant_id": r_dict.get("tenant_id", "org_default"),
            "region": r_dict.get("region", "local"),
        })
    return result


def get_current_user_optional(request: Request) -> User:
    """Extrae el usuario autenticado desde la cabecera Authorization Bearer token, o retorna el usuario default."""
    auth_header = request.headers.get("authorization") or request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header[7:].strip()
        user = tenancy_mgr.get_user_from_token(token)
        if user:
            return user
    return tenancy_mgr.get_default_user()


def require_role(allowed_roles: list[Role]) -> Any:
    def _dependency(request: Request) -> User:
        user = get_current_user_optional(request)
        if user.role not in allowed_roles and user.role != Role.ADMIN:
            raise HTTPException(
                status_code=403,
                detail=f"Acceso denegado: El rol '{user.role.value}' no tiene permisos para esta acción."
            )
        return user
    return _dependency


OAUTH2_BEARER_TYPE: str = "bearer"


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
    iast_url: Optional[str] = None
    enable_attack_chain: bool = True
    generate_pdf: bool = True
    auto_pr: bool = False
    github_repo: Optional[str] = None
    github_token: Optional[str] = None
    base_branch: str = "main"
    region: Optional[str] = None
    dispatch_to_cluster: bool = False


def run_scan_in_background(task_id: str, req: ScanRequest) -> None:
    """
    Ejecuta el escaneo en segundo plano, transmite telemetría por WebSockets,
    actualiza el estado de la tarea y envía notificación por Webhook si está configurada.
    """
    with _db_lock:
        conn = _get_db()
        _init_db(conn)
        _save_task(conn, task_id, status="running")
        conn.close()

    logger.info(f"Iniciando escaneo para la tarea {task_id} - URL: {req.url}")
    broadcast_event_sync(task_id, {
        "event": "progress",
        "step": "Iniciando motor de auditoría y análisis de entorno...",
        "percent": 10,
        "current_rps": 10.0,
        "total_requests": 1,
        "circuit_state": "CLOSED",
        "waf_detected": False,
    })

    def _progress_cb(evt: dict[str, Any]) -> None:
        broadcast_event_sync(task_id, evt)

    try:
        broadcast_event_sync(task_id, {
            "event": "progress",
            "step": "Ejecutando pruebas de seguridad DAST & correlación...",
            "percent": 35,
            "current_rps": 12.0,
            "total_requests": 5,
            "circuit_state": "CLOSED",
        })

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
            iast_url=req.iast_url,
            attack_chain=req.enable_attack_chain,
            generate_pdf=req.generate_pdf,
            auto_pr=req.auto_pr,
            github_repo=req.github_repo,
            github_token=req.github_token,
            base_branch=req.base_branch,
            progress_callback=_progress_cb,
        )
        if report_data and "error" in report_data:
            raise RuntimeError(report_data["error"])

        sarif_path = report_data.get("sarif_report_path") if isinstance(report_data, dict) else None
        pdf_path = report_data.get("pdf_report_path") if isinstance(report_data, dict) else None

        # Transmitir todos los hallazgos al cliente WS
        if isinstance(report_data, dict) and "vulnerabilities" in report_data:
            for v in report_data["vulnerabilities"]:
                broadcast_event_sync(task_id, {
                    "event": "finding",
                    "finding": v,
                })

        with _db_lock:
            conn = _get_db()
            _save_task(conn, task_id, status="completed",
                       html_report_path=html_path,
                       json_report_path=json_path,
                       sarif_report_path=sarif_path,
                       pdf_report_path=pdf_path,
                       results=report_data)
            conn.close()

        logger.info(f"Escaneo completado exitosamente para la tarea {task_id}")

        # Enviar evento de finalización
        attack_graph_info = report_data.get("engine", {}).get("attack_graph") if isinstance(report_data, dict) else None
        broadcast_event_sync(task_id, {
            "event": "completed",
            "percent": 100,
            "step": "¡Auditoría completada exitosamente!",
            "html_path": html_path,
            "json_path": json_path,
            "sarif_path": sarif_path,
            "pdf_path": pdf_path,
            "attack_graph": attack_graph_info,
        })

        if req.webhook_url:
            send_webhook_notification(task_id, req.webhook_url, "completed", report_data)

    except Exception as e:
        logger.error(f"Error durante el escaneo de la tarea {task_id}: {str(e)}")
        error_info = {"error": str(e)}
        with _db_lock:
            conn = _get_db()
            _save_task(conn, task_id, status="failed", results=error_info)
            conn.close()

        broadcast_event_sync(task_id, {
            "event": "failed",
            "error": str(e),
            "step": f"Fallo de escaneo: {e}",
        })

        if req.webhook_url:
            send_webhook_notification(task_id, req.webhook_url, "failed", error_info)


def send_webhook_notification(task_id: str, webhook_url: str, status: str, payload: Any) -> None:
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


class EASMScanRequest(BaseModel):
    domain: str
    include_bruteforce: bool = True
    max_workers: int = 20


@app.post("/api/v1/easm/scan", tags=["EASM"])
def trigger_easm_scan(req: EASMScanRequest, request: Request) -> dict[str, Any]:
    """Ejecuta una auditoría completa de superficie externa (EASM) para el dominio especificado."""
    _ = get_current_user_optional(request)
    from scanner.easm.engine import EASMEngine
    engine = EASMEngine()
    report = engine.run_full_surface_assessment(
        req.domain,
        include_bruteforce=req.include_bruteforce,
        max_workers=min(req.max_workers, 30)
    )
    return {
        "status": "completed",
        "domain": req.domain,
        "report": report.to_dict()
    }


@app.get("/health", tags=["System"])
def health_check() -> dict[str, Any]:
    """Endpoint de estado para Render Blueprints, monitores UptimeRobot y verificación de latencia."""
    is_postgres = bool(os.environ.get("DATABASE_URL", "").startswith(("postgres://", "postgresql://")))
    return {
        "status": "healthy",
        "service": "OmniBreach API",
        "version": "3.0",
        "database": "neon-postgresql" if is_postgres else "sqlite",
        "lightweight_mode": os.environ.get("OMNIBREACH_LIGHTWEIGHT", "").lower() in ("1", "true", "yes"),
    }


@app.get("/")
def read_root() -> dict[str, Any]:
    return {
        "message": "Bienvenido a OmniBreach v3.0 API",
        "version": "3.0",
        "standards": ["OASIS SARIF v2.1.0", "CVSS v3.1", "Executive PDF Audit", "GitHub Auto-PR", "Real-Time SOC Dashboard", "MITRE ATT&CK", "OAST", "EASM CISA KEV"],
        "dashboard_url": "/dashboard",
        "health_url": "/health",
        "docs_url": "/docs",
        "status": "online"
    }


@app.get("/dashboard", response_class=HTMLResponse)
def get_dashboard() -> HTMLResponse:
    """Sirve la consola interactiva en tiempo real del SOC Dashboard."""
    dashboard_path = os.path.join(os.path.dirname(__file__), "templates", "dashboard.html")
    if not os.path.exists(dashboard_path):
        raise HTTPException(status_code=404, detail="Plantilla de dashboard no encontrada")
    with open(dashboard_path, encoding="utf-8") as f:
        content = f.read()
    return HTMLResponse(content=content)


@app.websocket("/ws/scan/{task_id}")
async def websocket_scan_stream(websocket: WebSocket, task_id: str) -> None:
    """Canal WebSocket para transmisión reactiva de telemetría, hallazgos y estado del escaneo."""
    await websocket.accept()
    past_events = broadcaster.connect(task_id, websocket)

    # Reenviar historial previo si el cliente se conectó tarde o refrescó
    for evt in past_events:
        try:
            await websocket.send_text(json.dumps(evt, ensure_ascii=False))
        except Exception:
            break

    try:
        while True:
            # Mantener la conexión abierta recibiendo pings o mensajes del cliente
            await websocket.receive_text()
    except WebSocketDisconnect:
        broadcaster.disconnect(task_id, websocket)


@app.get("/download")
def download_report(path: str) -> FileResponse:
    """Permite la descarga segura de reportes generados (HTML, JSON, SARIF, PDF)."""
    normalized = os.path.abspath(path)
    reports_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "reports"))

    # Validar que el archivo resida en la carpeta de reportes por seguridad
    if not normalized.startswith(reports_dir) or not os.path.exists(normalized):
        raise HTTPException(status_code=404, detail="Archivo no encontrado o acceso denegado")

    filename = os.path.basename(normalized)
    return FileResponse(normalized, filename=filename)


@app.post("/scan", status_code=202)
def start_scan(request: ScanRequest, background_tasks: BackgroundTasks, req_http: Request) -> dict[str, Any]:
    """
    Inicia un escaneo web (localmente o despachado al cluster distribuido de workers).
    """
    user = get_current_user_optional(req_http)
    task_id = str(uuid.uuid4())
    region_val = request.region or "local"

    with _db_lock:
        conn = _get_db()
        _init_db(conn)
        _save_task(conn, task_id, url=request.url, status="queued", tenant_id=user.org_id, region=region_val)
        conn.close()

    if request.dispatch_to_cluster:
        req_cfg = request.model_dump() if hasattr(request, "model_dump") else (request.dict() if hasattr(request, "dict") else dict(request))
        cluster_mgr.enqueue_job(
            task_id=task_id,
            tenant_id=user.org_id,
            url=request.url,
            profile=request.profile,
            config=req_cfg,
            region_preference=request.region,
        )
        mode = "cluster"
    else:
        background_tasks.add_task(run_scan_in_background, task_id, request)
        mode = "local"

    return {
        "message": "Escaneo encolado correctamente",
        "task_id": task_id,
        "execution_mode": mode,
        "region": region_val,
        "tenant_id": user.org_id,
        "status_url": f"/scan/{task_id}",
        "websocket_url": f"/ws/scan/{task_id}"
    }


@app.get("/scan/{task_id}")
def get_scan_status(task_id: str, request: Request) -> dict[str, Any]:
    """
    Retorna el estado actual de una tarea de escaneo específica y sus resultados si terminó.
    """
    user = get_current_user_optional(request)
    with _db_lock:
        conn = _get_db()
        task = _get_task(conn, task_id)
        conn.close()

    if task is None:
        raise HTTPException(status_code=404, detail="Tarea de escaneo no encontrada")

    task_tenant = task.get("tenant_id", "org_default")
    if user.role != Role.ADMIN and task_tenant != user.org_id:
        raise HTTPException(status_code=403, detail="Acceso denegado: Esta auditoría pertenece a otra organización.")

    return task


@app.get("/scans")
def list_scans(request: Request) -> dict[str, Any]:
    """
    Lista el historial de escaneos y sus estados correspondientes con aislamiento de organización.
    """
    user = get_current_user_optional(request)
    filter_tenant = None if user.role == Role.ADMIN else user.org_id
    with _db_lock:
        conn = _get_db()
        tasks = _list_tasks(conn, tenant_id=filter_tenant)
        conn.close()

    return {
        "total_tasks": len(tasks),
        "tasks": tasks,
        "tenant_id": user.org_id,
    }


@app.get("/openapi.yaml", response_class=PlainTextResponse)
def get_openapi_yaml() -> PlainTextResponse:
    """Retorna el esquema contractual oficial OpenAPI 3.1 en formato YAML."""
    openapi_schema = app.openapi()
    yaml_content = yaml.safe_dump(openapi_schema, sort_keys=False, allow_unicode=True)
    return PlainTextResponse(content=yaml_content, media_type="text/yaml")


# =====================================================================
# CIBERDEFENSA ACTIVA & TECNOLOGÍA DE SEÑUELOS (DECEPTION ENGINE)
# =====================================================================

class DeceptionGenerateRequest(BaseModel):
    trap_type: str = "url"
    label: str = "Señuelo de Detección"
    target_url: str = ""


@app.websocket("/ws/deception")
async def websocket_deception_stream(websocket: WebSocket) -> None:
    """Canal WebSocket para transmisión en tiempo real de alertas de intrusión HoneyTokens."""
    await websocket.accept()
    past_events = broadcaster.connect("deception", websocket)
    for evt in past_events[-25:]:
        try:
            await websocket.send_text(json.dumps(evt, ensure_ascii=False))
        except Exception:
            break
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        broadcaster.disconnect("deception", websocket)


@app.post("/api/deception/generate")
def generate_honey_trap(req: DeceptionGenerateRequest, request: Request) -> dict[str, Any]:
    """Genera un nuevo HoneyToken / Señuelo (URL, API Key, JWT, Cookie) con snippet de integración."""
    trap = deception_mgr.create_trap(
        trap_type=req.trap_type,
        label=req.label,
        target_url=req.target_url
    )
    base_url = str(request.base_url).rstrip("/")
    snippet = SnippetGenerator.generate_snippet(trap, server_base_url=base_url)
    return {
        "trap": trap.to_dict(),
        "snippet": snippet,
        "stats": deception_mgr.get_stats(),
    }


@app.get("/api/deception/traps")
def list_honey_traps() -> dict[str, Any]:
    """Lista todas las trampas señuelo configuradas y estadísticas agregadas."""
    traps = deception_mgr.list_traps()
    stats = deception_mgr.get_stats()
    return {
        "total": len(traps),
        "traps": [t.to_dict() for t in traps],
        "stats": stats,
    }


@app.get("/api/deception/events")
def list_canary_events(limit: int = 50) -> dict[str, Any]:
    """Lista el historial de detonaciones e intrusiones detectadas por los señuelos."""
    events = deception_mgr.list_events(limit=limit)
    return {
        "total": len(events),
        "events": [e.to_dict() for e in events],
    }


@app.get("/api/deception/stats")
def get_deception_stats() -> dict[str, Any]:
    """Retorna métricas cuantitativas del motor de deception."""
    return deception_mgr.get_stats()


@app.get("/api/deception/snippet/{trap_id}")
def get_trap_snippet(trap_id: str, request: Request) -> dict[str, Any]:
    """Genera el snippet de código específico para insertar una trampa en producción."""
    trap = deception_mgr.get_trap(trap_id)
    if not trap:
        raise HTTPException(status_code=404, detail="Trampa señuelo no encontrada")
    base_url = str(request.base_url).rstrip("/")
    return {
        "trap": trap.to_dict(),
        "snippet": SnippetGenerator.generate_snippet(trap, server_base_url=base_url),
    }


@app.api_route("/deception/trap/{trap_id}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"], include_in_schema=False)
async def trigger_honey_trap(trap_id: str, request: Request) -> JSONResponse:
    """
    Receptor trampa (HoneyTrap Sink). Captura la intrusión del atacante o bot malicioso,
    registra telemetría completa, alerta al SOC por WebSocket y responde con un error decepcionante (401).
    """
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        attacker_ip = forwarded.split(",")[0].strip()
    elif request.client:
        attacker_ip = request.client.host
    else:
        attacker_ip = "127.0.0.1"

    user_agent = request.headers.get("user-agent", "Unknown")
    headers_dict = dict(request.headers)

    payload_sample: Optional[str] = None
    if request.method in ["POST", "PUT", "PATCH"]:
        with contextlib.suppress(Exception):
            body_bytes = await request.body()
            if body_bytes:
                payload_sample = body_bytes[:1024].decode(errors="replace")

    trap = deception_mgr.get_trap(trap_id)
    if not trap:
        trap = deception_mgr.find_trap_by_token(trap_id)

    if not trap:
        trap = deception_mgr.create_trap(
            trap_type="url",
            label=f"Exploración Señuelo /deception/trap/{trap_id}",
            target_url=str(request.url)
        )

    event = deception_mgr.record_event(
        trap=trap,
        attacker_ip=attacker_ip,
        user_agent=user_agent,
        http_method=request.method,
        requested_path=str(request.url.path),
        headers=headers_dict,
        payload_sample=payload_sample
    )

    broadcast_deception_alert({
        "event": "deception_alert",
        "data": event.to_dict(),
        "stats": deception_mgr.get_stats(),
    })

    return JSONResponse(
        status_code=401,
        content={
            "error": "Unauthorized",
            "message": "Invalid authentication credentials or expired canary token.",
            "code": "AUTH_TOKEN_EXPIRED",
            "timestamp": event.timestamp,
        },
        headers={"WWW-Authenticate": 'Bearer error="invalid_token"'}
    )


# =====================================================================
# GESTOR MULTI-TENANT & CONTROL DE ACCESO RBAC
# =====================================================================

class RegisterRequest(BaseModel):
    email: str
    password: str
    full_name: str
    org_name: str = "Mi Organización"
    role: str = "developer"


class LoginRequest(BaseModel):
    email: str
    password: str


@app.post("/api/auth/register")
def register_account(req: RegisterRequest) -> dict[str, Any]:
    """Registra una nueva cuenta de usuario y crea o enlaza su organización tenant."""
    org = tenancy_mgr.create_organization(name=req.org_name)
    try:
        user_role = Role(req.role.lower())
    except Exception:
        user_role = Role.DEVELOPER

    user = tenancy_mgr.register_user(
        org_id=org.id,
        email=req.email,
        password=req.password,
        full_name=req.full_name,
        role=user_role,
    )
    token = tenancy_mgr.jwt.create_token(user)
    return {
        "message": "Usuario y organización registrados exitosamente",
        "user": user.to_dict(),
        "organization": org.to_dict(),
        "access_token": token,
        "token_type": OAUTH2_BEARER_TYPE,
    }


@app.post("/api/auth/login")
def login_account(req: LoginRequest) -> dict[str, Any]:
    """Autentica a un usuario y genera un token JWT de acceso para su tenant."""
    result = tenancy_mgr.authenticate_user(req.email, req.password)
    if not result:
        raise HTTPException(status_code=401, detail="Credenciales incorrectas o usuario inactivo")
    user, token = result
    org = tenancy_mgr.get_organization(user.org_id)
    return {
        "message": "Inicio de sesión exitoso",
        "user": user.to_dict(),
        "organization": org.to_dict() if org else None,
        "access_token": token,
        "token_type": OAUTH2_BEARER_TYPE,
    }


@app.get("/api/auth/me")
def get_my_profile(request: Request) -> dict[str, Any]:
    """Retorna el perfil del usuario autenticado, su organización y permisos RBAC."""
    user = get_current_user_optional(request)
    org = tenancy_mgr.get_organization(user.org_id)
    perms = list(ROLE_PERMISSIONS.get(user.role, set()))
    return {
        "user": user.to_dict(),
        "organization": org.to_dict() if org else None,
        "permissions": perms,
    }


# =====================================================================
# CLUSTER DE ESCANEO DISTRIBUIDO & COORDINACIÓN DE WORKERS
# =====================================================================

class WorkerRegisterRequest(BaseModel):
    name: str
    worker_id: Optional[str] = None
    region: str = "local"
    max_concurrency: int = 2
    tags: list[str] = []


class WorkerHeartbeatRequest(BaseModel):
    active_jobs: int = 0
    status: str = "online"


class JobClaimRequest(BaseModel):
    worker_id: str
    region: str = "local"


class JobCompleteRequest(BaseModel):
    worker_id: str
    results: dict[str, Any] = {}
    html_path: Optional[str] = None
    json_path: Optional[str] = None
    sarif_path: Optional[str] = None
    pdf_path: Optional[str] = None


class JobFailRequest(BaseModel):
    worker_id: str
    error: str


@app.post("/api/cluster/workers/register")
def register_cluster_worker(req: WorkerRegisterRequest) -> dict[str, Any]:
    """Registra un nodo worker en el cluster distribuido."""
    worker = cluster_mgr.register_worker(
        name=req.name,
        region=req.region,
        max_concurrency=req.max_concurrency,
        tags=req.tags,
        worker_id=req.worker_id,
    )
    return {"message": "Worker registrado exitosamente", "worker": worker.to_dict()}


@app.post("/api/cluster/workers/{worker_id}/heartbeat")
def worker_heartbeat(worker_id: str, req: WorkerHeartbeatRequest) -> dict[str, Any]:
    """Actualiza el heartbeat y telemetría de salud de un worker."""
    ok = cluster_mgr.heartbeat(worker_id, active_jobs=req.active_jobs, status=req.status)
    return {"status": "ok" if ok else "unknown_worker"}


@app.get("/api/cluster/workers")
def list_cluster_workers() -> dict[str, Any]:
    """Lista los workers del cluster, sus regiones cloud y estadísticas agregadas."""
    workers = cluster_mgr.list_workers()
    stats = cluster_mgr.get_stats()
    return {
        "total_workers": len(workers),
        "workers": [w.to_dict() for w in workers],
        "stats": stats,
    }


@app.post("/api/cluster/jobs/claim")
def claim_cluster_job(req: JobClaimRequest) -> dict[str, Any]:
    """Un worker reclama la siguiente tarea de escaneo pendiente compatible con su región."""
    job = cluster_mgr.claim_job(worker_id=req.worker_id, worker_region=req.region)
    if not job:
        return {"claimed": False, "job": None}
    return {"claimed": True, "job": job.to_dict()}


@app.post("/api/cluster/jobs/{task_id}/complete")
def complete_cluster_job(task_id: str, req: JobCompleteRequest) -> dict[str, Any]:
    """Registra la finalización de una tarea ejecutada por un worker remoto y actualiza reportes."""
    cluster_mgr.complete_job(task_id=task_id, worker_id=req.worker_id, results=req.results)
    with _db_lock:
        conn = _get_db()
        _save_task(
            conn,
            task_id,
            status="completed",
            html_report_path=req.html_path,
            json_report_path=req.json_path,
            sarif_report_path=req.sarif_path,
            pdf_report_path=req.pdf_path,
            results=req.results,
        )
        conn.close()

    broadcast_event_sync(task_id, {
        "event": "completed",
        "percent": 100,
        "step": "¡Auditoría distribuida completada exitosamente!",
        "html_path": req.html_path,
        "json_path": req.json_path,
        "sarif_path": req.sarif_path,
        "pdf_path": req.pdf_path,
    })
    return {"message": "Trabajo completado registrado correctamente"}


@app.post("/api/cluster/jobs/{task_id}/fail")
def fail_cluster_job(task_id: str, req: JobFailRequest) -> dict[str, Any]:
    """Registra el fallo de una tarea en el cluster distribuido."""
    cluster_mgr.fail_job(task_id=task_id, worker_id=req.worker_id, error_message=req.error)
    with _db_lock:
        conn = _get_db()
        _save_task(conn, task_id, status="failed", results={"error": req.error})
        conn.close()

    broadcast_event_sync(task_id, {
        "event": "failed",
        "error": req.error,
        "step": f"Fallo en worker {req.worker_id}: {req.error}",
    })
    return {"message": "Fallo registrado correctamente"}



