"""
Módulo de Limitación de Tasa (Rate Limiting) y Protección contra Ataques DoS / Fuerza Bruta.

Implementa un limitador por ventana deslizante (Sliding Window) en memoria y thread-safe,
con políticas diferenciadas por criticidad de endpoint (autenticación, escaneos, telemetría).
"""
from __future__ import annotations

import ipaddress
import logging
import os
import threading
import time
from collections import defaultdict
from collections.abc import Iterable
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

    def __init__(
        self,
        app: Any,
        enabled: bool = True,
        trusted_proxies: Iterable[str] | None = None,
    ) -> None:
        super().__init__(app)
        self.enabled = enabled
        self.limiter = InMemorySlidingWindowLimiter(window_seconds=60.0)

        # Configurar proxies de confianza para evitar evasión por spoofing de X-Forwarded-For
        self._trust_all_proxies: bool = False
        self._trusted_addresses: set[ipaddress.IPv4Address | ipaddress.IPv6Address] = set()
        self._trusted_networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self._trusted_raw_strings: set[str] = set()

        raw_list: list[str] = []
        if trusted_proxies is not None:
            raw_list = [p.strip() for p in trusted_proxies if p.strip()]
        else:
            env_proxies = os.environ.get("OMNIBREACH_TRUSTED_PROXIES", "127.0.0.1,::1,localhost")
            raw_list = [p.strip() for p in env_proxies.split(",") if p.strip()]

        for item in raw_list:
            if item == "*":
                self._trust_all_proxies = True
                continue
            self._trusted_raw_strings.add(item)
            try:
                if "/" in item:
                    self._trusted_networks.append(ipaddress.ip_network(item, strict=False))
                else:
                    self._trusted_addresses.add(ipaddress.ip_address(item))
            except ValueError:
                # Hostname como 'localhost' o entrada no IP
                pass

    def _is_trusted_proxy(self, ip_str: str) -> bool:
        """Verifica si la IP inmediata de conexión pertenece a un reverse proxy confiable."""
        if not ip_str:
            return False
        if self._trust_all_proxies:
            return True
        if ip_str in self._trusted_raw_strings:
            return True
        try:
            addr = ipaddress.ip_address(ip_str)
            if addr in self._trusted_addresses:
                return True
            for net in self._trusted_networks:
                if addr in net:
                    return True
        except ValueError:
            pass
        return False

    def _get_client_identifier(self, request: Request) -> str:
        """
        Determina la dirección IP del cliente de forma segura.
        Solo se confía en la cabecera 'X-Forwarded-For' si la conexión peer proviene
        de un reverse proxy previamente autorizado (ej: Nginx, Cloudflare, Loopback).
        """
        client = request.client
        peer_ip = client.host if client else "unknown_client"

        # Si el socket peer es un proxy confiable, evaluamos la cabecera X-Forwarded-For
        if self._is_trusted_proxy(peer_ip):
            forwarded = request.headers.get("X-Forwarded-For")
            if forwarded:
                client_candidate = forwarded.split(",")[0].strip()
                if client_candidate:
                    return client_candidate

        # Si la conexión no viene de un proxy confiable, usar peer_ip para impedir spoofing
        return peer_ip

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
