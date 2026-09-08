"""Motor de escaneo asíncrono de alto rendimiento basado en httpx y asyncio."""
import asyncio
import logging
import time
from collections.abc import Coroutine
from typing import Any, Callable, Optional

import httpx

from scanner.engine import ScanConfig
from scanner.models import Finding

log = logging.getLogger("VulnScanner.AsyncEngine")


class AsyncScanEngine:
    """Motor asíncrono con control de concurrencia, rate limiting no bloqueante y circuit breaker."""

    def __init__(self, config: ScanConfig, max_concurrency: int = 15):
        self.config = config
        self.max_concurrency = max_concurrency
        self.semaphore = asyncio.Semaphore(max_concurrency)
        self._request_count = 0
        self._start_time = 0.0
        self._current_rps = float(config.max_rps)
        self._circuit_state = "CLOSED"
        self._circuit_open_until = 0.0
        self._consecutive_throttles = 0
        self._seen_urls: set[str] = set()
        self._lock = asyncio.Lock()
        self.client: Optional[httpx.AsyncClient] = None

    @property
    def circuit_state(self) -> str:
        return self._circuit_state

    @property
    def current_rps(self) -> float:
        return self._current_rps

    @property
    def elapsed(self) -> float:
        return time.time() - self._start_time if self._start_time > 0 else 0.0

    @property
    def request_count(self) -> int:
        return self._request_count

    async def __aenter__(self) -> "AsyncScanEngine":
        limits = httpx.Limits(max_keepalive_connections=20, max_connections=50)
        timeout = httpx.Timeout(self.config.timeout)
        headers = {}
        if self.config.auth_header:
            headers["Authorization"] = self.config.auth_header
        if self.config.cookie:
            headers["Cookie"] = self.config.cookie

        self.client = httpx.AsyncClient(
            limits=limits,
            timeout=timeout,
            headers=headers,
            follow_redirects=True,
            verify=False,  # nosec B501
        )
        self._start_time = time.time()
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        if self.client:
            await self.client.aclose()

    async def _handle_response(self, status: int) -> None:
        """Ajusta dinámicamente el ritmo y estado del circuit breaker de forma asíncrona."""
        now = time.monotonic()
        async with self._lock:
            self._request_count += 1
            if status in (429, 503):
                self._consecutive_throttles += 1
                backoff = min(10.0, 1.5 * (2 ** (self._consecutive_throttles - 1)))
                self._circuit_state = "OPEN"
                self._circuit_open_until = now + backoff
                self._current_rps = max(1.0, self._current_rps * 0.5)
                log.warning("[AsyncEngine] Throttling HTTP %d. Circuito ABIERTO por %.1fs. RPS: %.1f", status, backoff, self._current_rps)
            elif 200 <= status < 400:
                if self._circuit_state == "OPEN" and now >= self._circuit_open_until:
                    self._circuit_state = "HALF-OPEN"
                elif self._circuit_state == "HALF-OPEN":
                    self._circuit_state = "CLOSED"
                    self._consecutive_throttles = 0
                    self._current_rps = min(float(self.config.max_rps), self._current_rps + 1.0)

    async def fetch(self, url: str, method: str = "GET", **kwargs: Any) -> Optional[httpx.Response]:
        """Ejecuta una petición asíncrona respetando el semáforo y el rate limiter."""
        if not self.client:
            raise RuntimeError("AsyncScanEngine debe usarse dentro de un bloque async with")

        # Rate limiting y Circuit Breaker asíncrono
        now = time.monotonic()
        if self._circuit_state == "OPEN":
            if now < self._circuit_open_until:
                await asyncio.sleep(self._circuit_open_until - now)
            self._circuit_state = "HALF-OPEN"

        # Espaciamiento de peticiones
        delay = (1.0 / self._current_rps) if self._current_rps > 0 else 0.05
        await asyncio.sleep(delay)

        async with self.semaphore:
            try:
                resp = await self.client.request(method, url, **kwargs)
                await self._handle_response(resp.status_code)
                return resp
            except httpx.RequestError as e:
                log.debug("Error asíncrono en %s: %s", url, e)
                return None

    async def run_batch(
        self,
        urls: list[str],
        worker_fn: Callable[[str, "AsyncScanEngine"], Coroutine[Any, Any, list[Finding]]]
    ) -> list[Finding]:
        """Ejecuta un lote de URLs concurrentemente distribuyéndolas entre corutinas."""
        tasks = [worker_fn(u, self) for u in urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        all_findings: list[Finding] = []
        for r in results:
            if isinstance(r, list):
                all_findings.extend(r)
            elif isinstance(r, Exception):
                log.warning("Excepción durante escaneo asíncrono: %s", r)

        return all_findings
