"""
Módulo de Limitación de Tasa (Rate Limiting) y Protección contra Ataques DoS / Fuerza Bruta.

Implementa un limitador por ventana deslizante (Sliding Window) en memoria y thread-safe,
con políticas diferenciadas por criticidad de endpoint (autenticación, escaneos, telemetría).
"""
from __future__ import annotations

import logging
import os
import threading
import time
from collections import defaultdict
from typing import Any, Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

logger = logging.getLogger("OmniBreach.RateLimiter")


class InMemorySlidingWindowLimiter:
    """Limitador de tasa por ventana deslizante thread-safe en memoria."""

    def __init__(self, window_seconds: float = 60.0) -> None:
        self.window_seconds = window_seconds
        self._records: dict[str, list[float]] = defaultdict(list)
        self._lock = threading.Lock()

    def is_allowed(self, key: str, max_requests: int) -> tuple[bool, int, float]:
        """
        Verifica si la clave (ej. IP del cliente) tiene permitido realizar la solicitud.
        Retorna: (permitido, solicitudes_restantes, segundos_para_reintento).
        """
        now = time.time()
        cutoff = now - self.window_seconds

        with self._lock:
            # Purgar timestamps expirados
            timestamps = self._records[key]
            valid_timestamps = [ts for ts in timestamps if ts > cutoff]
            self._records[key] = valid_timestamps

            count = len(valid_timestamps)
            if count >= max_requests:
                earliest = valid_timestamps[0]
                retry_after = max(1.0, round(self.window_seconds - (now - earliest), 1))
                return False, 0, retry_after

            # Registrar la nueva solicitud
            self._records[key].append(now)
            remaining = max_requests - (count + 1)
            return True, remaining, 0.0

    def reset(self) -> None:
        """Limpia los registros de tasa acumulados."""
        with self._lock:
            self._records.clear()


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Middleware ASGI de FastAPI para enforcement de límites de tasa."""

    # Reglas específicas por prefijo de ruta (solicitudes permitidas por minuto)
    ENDPOINT_LIMITS: dict[str, int] = {
        "/api/auth/login": 20,
        "/api/auth/register": 15,
        "/scan": 30,
        "/api/cluster/jobs/claim": 60,
    }
    DEFAULT_LIMIT: int = 300

    def __init__(self, app: Any, enabled: bool = True) -> None:
        super().__init__(app)
        self.enabled = enabled
        self.limiter = InMemorySlidingWindowLimiter(window_seconds=60.0)

    def _get_client_identifier(self, request: Request) -> str:
        # Priorizar cabecera X-Forwarded-For si está detrás de un reverse proxy (Cloudflare/Nginx)
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
        client = request.client
        return client.host if client else "unknown_client"

    def _get_limit_for_path(self, path: str) -> int:
        for prefix, limit in self.ENDPOINT_LIMITS.items():
            if path.startswith(prefix):
                return limit
        return self.DEFAULT_LIMIT

    async def dispatch(self, request: Request, call_next: Callable[[Request], Any]) -> Response:
        # Modo desactivado por configuración o variable de entorno (útil para pruebas unitarias)
        env_disabled = os.environ.get("OMNIBREACH_RATE_LIMIT", "true").lower() in ("false", "0", "no")
        if not self.enabled or env_disabled:
            return await call_next(request)  # type: ignore[no-any-return]

        path = request.url.path
        # Eximir rutas estáticas, websockets, health check y documentación Swagger
        if (
            path.startswith("/docs")
            or path.startswith("/redoc")
            or path.startswith("/openapi")
            or path == "/api/health"
            or path == "/"
            or path.startswith("/ws")
            or path.startswith("/static")
        ):
            return await call_next(request)  # type: ignore[no-any-return]

        client_ip = self._get_client_identifier(request)
        max_reqs = self._get_limit_for_path(path)
        key = f"{client_ip}:{path if max_reqs != self.DEFAULT_LIMIT else 'global'}"

        allowed, remaining, retry_after = self.limiter.is_allowed(key, max_requests=max_reqs)
        if not allowed:
            logger.warning("[RATE LIMIT] IP %s excedió límite en %s (%d req/min)", client_ip, path, max_reqs)
            return JSONResponse(
                status_code=429,
                content={
                    "error": "Too Many Requests",
                    "message": f"Ha excedido el límite de velocidad permitido ({max_reqs} solicitudes/minuto).",
                    "retry_after_seconds": retry_after,
                },
                headers={"Retry-After": str(int(retry_after))},
            )

        response: Response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(max_reqs)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        return response
