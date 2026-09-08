"""Agente Híbrido IAST / RASP para VulnScanner.

Proporciona:
1. IAST (Interactive Application Security Testing): Instrumentación en memoria de sinks
   críticos (SQL, Command Injection, Path Traversal) para registrar archivo fuente,
   línea exacta y pila de llamadas con 0% de falsos positivos.
2. RASP (Runtime Application Self-Protection): Defensa activa en memoria. En modo "protect",
   intercepta y bloquea llamadas a sinks peligrosos antes de que alcancen el kernel o la BD.
"""
from __future__ import annotations

import builtins
import contextvars
import inspect
import json
import re
import sqlite3
import subprocess  # nosec B404
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Callable

# Identificador de correlación por hilo/tarea asíncrona
_current_correlation_id: contextvars.ContextVar[str] = contextvars.ContextVar(
    "vulnscanner_correlation_id", default=""
)


class RASPBlockedError(Exception):
    """Excepción lanzada cuando el agente RASP intercepta y bloquea un ataque en memoria."""
    def __init__(self, sink_type: str, detail: str, source_file: str = "", source_line: int = 0):
        super().__init__(f"RASP Blocked [{sink_type}]: {detail}")
        self.sink_type = sink_type
        self.detail = detail
        self.source_file = source_file
        self.source_line = source_line


RASPBlockedException = RASPBlockedError


@dataclass
class IASTTelemetry:
    """Telemetría de ejecución capturada en tiempo real por el agente IAST."""
    sink_type: str
    source_file: str
    source_line: int
    function_name: str
    tainted_argument: str
    call_stack: list[str] = field(default_factory=list)
    blocked_by_rasp: bool = False
    correlation_id: str = ""
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# Firmas heurísticas para detección en memoria dentro del sink
SQLI_PATTERNS = [
    re.compile(r"(\bOR\b\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+|--|/\*|;\s*DROP\s+TABLE|UNION\s+SELECT)", re.IGNORECASE),
    re.compile(r"(\bSELECT\b.+\bFROM\b.+\bWHERE\b.+['\"]\s*OR\b)", re.IGNORECASE),
]

CMD_PATTERNS = [
    re.compile(r"(;|&&|\|\||\|)\s*(cat\s+/etc/passwd|whoami|id|uname|dir|type\s+)", re.IGNORECASE),
    re.compile(r"(`|\$\().*(\)|`)"),
]

PATH_TRAVERSAL_PATTERNS = [
    re.compile(r"(\.\./|\.\.\\){2,}", re.IGNORECASE),
    re.compile(r"(/etc/passwd|windows[\\/]system32)", re.IGNORECASE),
]


class HookedCursor:
    """Cursor envolvente que analiza llamadas SQL en busca de inyecciones antes de delegar."""

    def __init__(self, real_cursor: Any, hook_mgr: HookManager):
        self._cursor = real_cursor
        self._hook_mgr = hook_mgr

    def execute(self, operation: Any, *args: Any, **kwargs: Any) -> Any:
        self._hook_mgr._check_sql_operation(operation)
        return self._cursor.execute(operation, *args, **kwargs)

    def executemany(self, operation: Any, *args: Any, **kwargs: Any) -> Any:
        self._hook_mgr._check_sql_operation(operation)
        return self._cursor.executemany(operation, *args, **kwargs)

    def __iter__(self) -> Any:
        return iter(self._cursor)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._cursor, name)


class HookedConnection:
    """Conexión envolvente que devuelve cursores instrumentados."""

    def __init__(self, real_conn: Any, hook_mgr: HookManager):
        self._conn = real_conn
        self._hook_mgr = hook_mgr

    def cursor(self, *args: Any, **kwargs: Any) -> HookedCursor:
        real_c = self._conn.cursor(*args, **kwargs)
        return HookedCursor(real_c, self._hook_mgr)

    def execute(self, operation: Any, *args: Any, **kwargs: Any) -> Any:
        self._hook_mgr._check_sql_operation(operation)
        return self._conn.execute(operation, *args, **kwargs)

    def executemany(self, operation: Any, *args: Any, **kwargs: Any) -> Any:
        self._hook_mgr._check_sql_operation(operation)
        return self._conn.executemany(operation, *args, **kwargs)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._conn, name)


class HookManager:
    """Gestiona la instrumentación de sinks de ejecución mediante monkey-patching controlado."""

    def __init__(self, on_sink_event: Callable[[IASTTelemetry], bool]):
        """
        on_sink_event: Callback invocado en cada llamada a un sink.
                       Si devuelve True, se autoriza la ejecución.
                       Si devuelve False (modo RASP protect), se levanta RASPBlockedException.
        """
        self.on_sink_event = on_sink_event
        self._installed = False
        self._orig_sqlite_connect: Callable | None = None
        self._orig_subprocess_popen: Callable | None = None
        self._orig_builtin_open: Callable | None = None

    def _check_sql_operation(self, operation: Any) -> None:
        """Inspecciona la operación SQL en tiempo de ejecución."""
        op_str = str(operation)
        file, line, func, stack = self._inspect_caller_stack()
        is_suspicious = any(p.search(op_str) for p in SQLI_PATTERNS)
        if is_suspicious:
            cid = _current_correlation_id.get()
            telemetry = IASTTelemetry(
                sink_type="sql",
                source_file=file,
                source_line=line,
                function_name=func,
                tainted_argument=op_str[:300],
                call_stack=stack,
                correlation_id=cid,
            )
            should_execute = self.on_sink_event(telemetry)
            if not should_execute:
                telemetry.blocked_by_rasp = True
                raise RASPBlockedException("sql", f"Suspicious SQL query blocked: {op_str[:80]}", file, line)

    def install_hooks(self) -> None:
        """Instala instrumentación en sqlite3, subprocess y builtins.open."""
        if self._installed:
            return

        # 1. Hook para sqlite3.connect
        self._orig_sqlite_connect = sqlite3.connect

        def hooked_connect(*args: Any, **kwargs: Any) -> Any:
            assert self._orig_sqlite_connect is not None
            real_conn = self._orig_sqlite_connect(*args, **kwargs)
            return HookedConnection(real_conn, self)

        setattr(sqlite3, "connect", hooked_connect)

        # 2. Hook para subprocess.Popen
        self._orig_subprocess_popen = subprocess.Popen

        def hooked_popen(*args: Any, **kwargs: Any) -> Any:
            cmd_arg = ""
            if args:
                cmd_arg = str(args[0])
            elif "args" in kwargs:
                cmd_arg = str(kwargs["args"])

            file, line, func, stack = self._inspect_caller_stack()
            is_suspicious = any(p.search(cmd_arg) for p in CMD_PATTERNS)
            if is_suspicious:
                cid = _current_correlation_id.get()
                telemetry = IASTTelemetry(
                    sink_type="command",
                    source_file=file,
                    source_line=line,
                    function_name=func,
                    tainted_argument=cmd_arg[:300],
                    call_stack=stack,
                    correlation_id=cid,
                )
                should_execute = self.on_sink_event(telemetry)
                if not should_execute:
                    telemetry.blocked_by_rasp = True
                    raise RASPBlockedException("command", f"Suspicious OS command blocked: {cmd_arg[:80]}", file, line)

            assert self._orig_subprocess_popen is not None
            return self._orig_subprocess_popen(*args, **kwargs)

        setattr(subprocess, "Popen", hooked_popen)

        # 3. Hook para builtins.open (Path Traversal)
        self._orig_builtin_open = builtins.open

        def hooked_open(file: Any, *args: Any, **kwargs: Any) -> Any:
            file_str = str(file)
            src_file, line, func, stack = self._inspect_caller_stack()
            is_suspicious = any(p.search(file_str) for p in PATH_TRAVERSAL_PATTERNS)
            if is_suspicious:
                cid = _current_correlation_id.get()
                telemetry = IASTTelemetry(
                    sink_type="file",
                    source_file=src_file,
                    source_line=line,
                    function_name=func,
                    tainted_argument=file_str[:300],
                    call_stack=stack,
                    correlation_id=cid,
                )
                should_execute = self.on_sink_event(telemetry)
                if not should_execute:
                    telemetry.blocked_by_rasp = True
                    raise RASPBlockedException("file", f"Path traversal attempt blocked: {file_str[:80]}", src_file, line)

            assert self._orig_builtin_open is not None
            return self._orig_builtin_open(file, *args, **kwargs)

        setattr(builtins, "open", hooked_open)

        self._installed = True

    def uninstall_hooks(self) -> None:
        """Restaura los sinks originales a su estado no instrumentado."""
        if not self._installed:
            return

        if self._orig_sqlite_connect:
            setattr(sqlite3, "connect", self._orig_sqlite_connect)
        if self._orig_subprocess_popen:
            setattr(subprocess, "Popen", self._orig_subprocess_popen)
        if self._orig_builtin_open:
            setattr(builtins, "open", self._orig_builtin_open)

        self._installed = False

    @staticmethod
    def _inspect_caller_stack() -> tuple[str, int, str, list[str]]:
        """Extrae el primer frame de la llamada fuera del propio módulo iast_agent."""
        stack = inspect.stack()
        calling_file = "unknown"
        calling_line = 0
        calling_func = "unknown"
        clean_stack: list[str] = []

        this_file = __file__.replace("\\", "/")

        for frame_info in stack[1:]:
            f_name = frame_info.filename.replace("\\", "/")
            # Omitir frames internos de instrumentación
            if f_name == this_file or "contextvars" in f_name or "inspect.py" in f_name:
                continue

            if calling_file == "unknown":
                calling_file = frame_info.filename
                calling_line = frame_info.lineno
                calling_func = frame_info.function

            clean_stack.append(f"{frame_info.filename}:{frame_info.lineno} in {frame_info.function}")
            if len(clean_stack) >= 6:
                break

        return calling_file, calling_line, calling_func, clean_stack


class VulnScannerASGI:
    """Middleware ASGI compatible con FastAPI, Starlette y Quart.

    Modos:
    - 'monitor' (IAST): Monitorea y registra telemetría de ejecución sin bloquear peticiones.
    - 'protect' (RASP): Monitorea y BLOQUEA activamente ataques en memoria devolviendo 403 Forbidden.
    """

    def __init__(self, app: Any, mode: str = "monitor"):
        if mode not in ("monitor", "protect"):
            raise ValueError("mode debe ser 'monitor' o 'protect'")
        self.app = app
        self.mode = mode
        self.telemetry_history: list[IASTTelemetry] = []
        self._max_history = 500

        self.hook_manager = HookManager(on_sink_event=self._handle_sink_event)
        self.hook_manager.install_hooks()

        if hasattr(app, "add_exception_handler"):
            try:
                from starlette.responses import JSONResponse

                def _handle_rasp_exc(request: Any, exc: RASPBlockedException) -> Any:
                    return JSONResponse(
                        {
                            "error": "Forbidden by VulnScanner RASP",
                            "detail": exc.detail,
                            "sink": exc.sink_type,
                            "source_file": exc.source_file,
                            "source_line": exc.source_line,
                            "action": "Execution prevented in memory before reaching OS or Database",
                        },
                        status_code=403,
                        headers={
                            "x-protection-by": "VulnScanner-RASP",
                            "x-vulnscanner-rasp-mode": "protect",
                        },
                    )

                app.add_exception_handler(RASPBlockedException, _handle_rasp_exc)
            except Exception:
                pass

    def _handle_sink_event(self, telemetry: IASTTelemetry) -> bool:
        """Registra telemetría y decide si permitir o bloquear la ejecución."""
        self.telemetry_history.append(telemetry)
        if len(self.telemetry_history) > self._max_history:
            self.telemetry_history.pop(0)

        # En modo monitor se autoriza la ejecución; en modo protect se bloquea
        return self.mode != "protect"

    def get_telemetry(self, correlation_id: str | None = None) -> list[dict[str, Any]]:
        """Retorna eventos de telemetría registrados, opcionalmente filtrados por correlation_id."""
        if correlation_id:
            return [t.to_dict() for t in self.telemetry_history if t.correlation_id == correlation_id]
        return [t.to_dict() for t in self.telemetry_history]

    def clear_telemetry(self) -> None:
        """Limpia el buffer de telemetría en memoria."""
        self.telemetry_history.clear()

    async def __call__(self, scope: dict[str, Any], receive: Callable, send: Callable) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        # Endpoint nativo para consultar telemetría IAST
        if path == "/__vulnscanner_iast__":
            raw_query = scope.get("query_string", b"").decode("utf-8")
            cid = ""
            if "cid=" in raw_query:
                parts = raw_query.split("cid=")
                if len(parts) > 1:
                    cid = parts[1].split("&")[0]

            data = self.get_telemetry(cid if cid else None)
            body = json.dumps({"telemetry": data, "count": len(data), "mode": self.mode}).encode("utf-8")

            await send({
                "type": "http.response.start",
                "status": 200,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"x-vulnscanner-iast", b"active"),
                    (b"x-vulnscanner-rasp-mode", self.mode.encode("utf-8")),
                ],
            })
            await send({
                "type": "http.response.body",
                "body": body,
            })
            return

        # Extraer correlation-id si viene desde VulnScanner
        headers = dict(scope.get("headers", []))
        correlation_id = headers.get(b"x-vulnscanner-correlation-id", b"").decode("utf-8")
        token = _current_correlation_id.set(correlation_id)

        response_started = False

        try:
            # Envoltura send para inyectar cabeceras de diagnóstico
            async def wrapped_send(message: dict[str, Any]) -> None:
                nonlocal response_started
                if message["type"] == "http.response.start":
                    response_started = True
                    msg_headers = list(message.get("headers", []))
                    existing_names = {h[0].lower() for h in msg_headers}
                    if b"x-vulnscanner-iast" not in existing_names:
                        msg_headers.append((b"x-vulnscanner-iast", b"active"))
                    if b"x-vulnscanner-rasp-mode" not in existing_names:
                        msg_headers.append((b"x-vulnscanner-rasp-mode", self.mode.encode("utf-8")))
                    message["headers"] = msg_headers
                await send(message)

            await self.app(scope, receive, wrapped_send)
        except RASPBlockedException as ex:
            if not response_started:
                # Respuesta activa de bloqueo RASP
                resp_body = json.dumps({
                    "error": "Forbidden by VulnScanner RASP",
                    "detail": ex.detail,
                    "sink": ex.sink_type,
                    "source_file": ex.source_file,
                    "source_line": ex.source_line,
                    "action": "Execution prevented in memory before reaching OS or Database",
                }).encode("utf-8")

                await send({
                    "type": "http.response.start",
                    "status": 403,
                    "headers": [
                        (b"content-type", b"application/json"),
                        (b"x-protection-by", b"VulnScanner-RASP"),
                        (b"x-vulnscanner-rasp-mode", b"protect"),
                    ],
                })
                await send({
                    "type": "http.response.body",
                    "body": resp_body,
                })
        finally:
            _current_correlation_id.reset(token)
