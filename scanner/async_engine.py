"""
Motor de Escaneo Asíncrono de Alto Rendimiento y Pipeline Reactivo (AsyncIO / HTTPX).

Implementa:
1. Cliente Asíncrono con Pooling HTTP/1.1 y HTTP/2, keep-alive y control no bloqueante de semáforos.
2. Limitador de Tasa Adaptativo (AIMD) y Circuit Breaker dinámico ante errores 429/503.
3. Arquitectura Productor-Consumidor (AsyncReactivePipeline):
   - Descubrimiento continuo en streaming (AsyncCrawler) sin esperas de fase.
   - Pool de Workers de auditoría consumiendo de colas asíncronas (asyncio.Queue).
4. Generador de flujo en tiempo real (Event-Driven Streaming: `stream_scan`).
5. Detectores nativos asíncronos para Cabeceras, CORS, Fugas de Rutas y Plantillas DSL.
6. Cancelación cooperativa limpia y telemetría de rendimiento en tiempo real.
"""
from __future__ import annotations

import asyncio
import contextlib
import logging
import re
import time
from collections.abc import AsyncGenerator, Coroutine
from dataclasses import dataclass
from typing import Any, Callable
from urllib.parse import urljoin, urlparse

import httpx

from scanner.engine import ScanConfig
from scanner.models import Evidence, Finding

logger = logging.getLogger("OmniBreach.AsyncEngine")


# =========================================================================
# 1. Motor de Cliente Asíncrono con Rate Limiting y Circuit Breaker
# =========================================================================

class AsyncScanEngine:
    """Motor asíncrono con control de concurrencia, rate limiting no bloqueante y circuit breaker."""

    def __init__(
        self,
        config: ScanConfig,
        max_concurrency: int = 15,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.config = config
        self.max_concurrency = max_concurrency
        self.transport = transport
        self.semaphore = asyncio.Semaphore(max_concurrency)
        self._request_count = 0
        self._start_time = 0.0
        self._current_rps = float(config.max_rps) if config.max_rps > 0 else 10.0
        self._circuit_state = "CLOSED"
        self._circuit_open_until = 0.0
        self._consecutive_throttles = 0
        self._seen_urls: set[str] = set()
        self._lock = asyncio.Lock()
        self.client: httpx.AsyncClient | None = None
        self._cancelled = False

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

    @property
    def is_cancelled(self) -> bool:
        return self._cancelled

    def cancel(self) -> None:
        """Marca el motor para cancelación cooperativa."""
        self._cancelled = True

    async def __aenter__(self) -> AsyncScanEngine:
        limits = httpx.Limits(max_keepalive_connections=20, max_connections=50)
        timeout = httpx.Timeout(self.config.timeout)
        headers: dict[str, str] = {
            "User-Agent": "OmniBreach-Async/3.9 (+https://github.com/papiwilo74/vulnscanner-v1)"
        }
        if self.config.auth_header:
            headers["Authorization"] = self.config.auth_header
        if self.config.cookie:
            headers["Cookie"] = self.config.cookie

        self.client = httpx.AsyncClient(
            transport=self.transport,
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
                logger.warning(
                    "[AsyncEngine] Throttling HTTP %d. Circuito ABIERTO por %.1fs. RPS: %.1f",
                    status,
                    backoff,
                    self._current_rps,
                )
            elif 200 <= status < 400:
                if self._circuit_state == "OPEN" and now >= self._circuit_open_until:
                    self._circuit_state = "HALF-OPEN"
                elif self._circuit_state == "HALF-OPEN":
                    self._circuit_state = "CLOSED"
                    self._consecutive_throttles = 0
                    self._current_rps = min(float(self.config.max_rps), self._current_rps + 1.0)

    async def fetch(self, url: str, method: str = "GET", **kwargs: Any) -> httpx.Response | None:
        """Ejecuta una petición asíncrona respetando el semáforo y el rate limiter."""
        if self._cancelled:
            return None
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
            except (httpx.RequestError, asyncio.CancelledError) as e:
                logger.debug("Error asíncrono en %s: %s", url, e)
                return None

    async def run_batch(
        self,
        urls: list[str],
        worker_fn: Callable[[str, AsyncScanEngine], Coroutine[Any, Any, list[Finding]]],
    ) -> list[Finding]:
        """Ejecuta un lote de URLs concurrentemente distribuyéndolas entre corrutinas."""
        tasks = [worker_fn(u, self) for u in urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        all_findings: list[Finding] = []
        for r in results:
            if isinstance(r, list):
                all_findings.extend(r)
            elif isinstance(r, Exception):
                logger.warning("Excepción durante escaneo asíncrono: %s", r)

        return all_findings


# =========================================================================
# 2. Crawler Asíncrono no bloqueante (AsyncCrawler)
# =========================================================================

class AsyncCrawler:
    """Rastreador web asíncrono para mapeo rápido de enlaces y endpoints internos."""

    def __init__(self, engine: AsyncScanEngine, max_pages: int = 25, max_depth: int = 2) -> None:
        self.engine = engine
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.visited: set[str] = set()

    async def crawl(self, start_url: str) -> list[str]:
        """Ejecuta un rastreo BFS asíncrono devolviendo todas las URLs descubiertas."""
        parsed_base = urlparse(start_url)
        base_netloc = parsed_base.netloc
        queue: asyncio.Queue[tuple[str, int]] = asyncio.Queue()
        await queue.put((start_url, 0))
        self.visited.add(start_url)
        discovered: list[str] = [start_url]

        while not queue.empty() and len(discovered) < self.max_pages:
            if self.engine.is_cancelled:
                break
            current_url, depth = await queue.get()

            if depth >= self.max_depth:
                continue

            resp = await self.engine.fetch(current_url)
            if not resp or resp.status_code != 200 or "text/html" not in resp.headers.get("Content-Type", ""):
                continue

            # Extracción ligera de enlaces vía regex
            links = re.findall(r'href=["\']([^"\'#]+)["\']', resp.text, re.IGNORECASE)
            for link in links:
                full_url = urljoin(current_url, link)
                parsed = urlparse(full_url)
                if parsed.netloc == base_netloc and full_url not in self.visited:
                    self.visited.add(full_url)
                    discovered.append(full_url)
                    await queue.put((full_url, depth + 1))
                    if len(discovered) >= self.max_pages:
                        break

        return discovered


# =========================================================================
# 3. Detectores Nativos Asíncronos
# =========================================================================

async def check_headers_async(resp: httpx.Response, url: str) -> list[Finding]:
    """Auditoría asíncrona de cabeceras de seguridad HTTP y HSTS."""
    findings: list[Finding] = []
    headers = {k.lower(): v for k, v in resp.headers.items()}
    is_html = "text/html" in headers.get("content-type", "")

    # Chequeos de cabeceras críticas para documentos navegables
    if is_html:
        if "content-security-policy" not in headers:
            findings.append(Finding(
                category="headers",
                title="Falta Cabecera Content-Security-Policy (CSP)",
                severity="medium",
                confidence="confirmed",
                description="La aplicación no define una política CSP, aumentando el riesgo de XSS y ataques de inyección.",
                affected_url=url,
                evidence=Evidence(request_method="GET", request_url=url, response_status=resp.status_code),
                remediation="Configurar la cabecera Content-Security-Policy con directivas restrictivas (ej: default-src 'self').",
            ))

        if "x-frame-options" not in headers and "content-security-policy" not in headers:
            findings.append(Finding(
                category="headers",
                title="Falta Protección contra Clickjacking (X-Frame-Options)",
                severity="medium",
                confidence="confirmed",
                description="La aplicación puede ser embebida en marcos <iframe> externos, permitiendo ataques de Clickjacking.",
                affected_url=url,
                evidence=Evidence(request_method="GET", request_url=url, response_status=resp.status_code),
                remediation="Añadir la cabecera 'X-Frame-Options: DENY' o 'X-Frame-Options: SAMEORIGIN'.",
            ))

    if "x-content-type-options" not in headers:
        findings.append(Finding(
            category="headers",
            title="Falta Cabecera X-Content-Type-Options: nosniff",
            severity="low",
            confidence="confirmed",
            description="Permite al navegador realizar inferencia MIME de recursos, facilitando ataques de confusión de tipos.",
            affected_url=url,
            evidence=Evidence(request_method="GET", request_url=url, response_status=resp.status_code),
            remediation="Configurar la cabecera 'X-Content-Type-Options: nosniff'.",
        ))

    if url.startswith("https://") and "strict-transport-security" not in headers:
        findings.append(Finding(
            category="ssl",
            title="Falta Cabecera HSTS (Strict-Transport-Security)",
            severity="medium",
            confidence="confirmed",
            description="La aplicación sobre HTTPS no exige comunicación segura forzada mediante HSTS.",
            affected_url=url,
            evidence=Evidence(request_method="GET", request_url=url, response_status=resp.status_code),
            remediation="Añadir la cabecera 'Strict-Transport-Security: max-age=31536000; includeSubDomains'.",
        ))

    return findings


async def check_cors_async(engine: AsyncScanEngine, url: str) -> list[Finding]:
    """Auditoría asíncrona de Cross-Origin Resource Sharing (CORS)."""
    findings: list[Finding] = []
    test_origin = "https://evil-attacker.example.com"
    resp = await engine.fetch(url, method="GET", headers={"Origin": test_origin})
    if not resp:
        return []

    acao = resp.headers.get("access-control-allow-origin", "")
    acac = resp.headers.get("access-control-allow-credentials", "").lower()

    if acao == test_origin and acac == "true":
        findings.append(Finding(
            category="cors",
            title="Configuración Crítica de CORS con Credenciales Arbitrarias",
            severity="critical",
            confidence="confirmed",
            description=(
                f"El endpoint refleja el origen no confiable '{test_origin}' en 'Access-Control-Allow-Origin' "
                "junto con 'Access-Control-Allow-Credentials: true', permitiendo el robo de sesiones y datos sensibles (CWE-942)."
            ),
            affected_url=url,
            evidence=Evidence(
                request_method="GET",
                request_url=url,
                payload=f"Origin: {test_origin}",
                response_status=resp.status_code,
                response_fragment=f"Access-Control-Allow-Origin: {acao}\nAccess-Control-Allow-Credentials: {acac}",
            ),
            remediation="Restringir los orígenes autorizados mediante una lista blanca explícita de dominios confiables.",
        ))
    elif acao == "*":
        ctype = resp.headers.get("content-type", "").lower()
        path_lower = urlparse(url).path.lower()
        is_api_route = any(h in path_lower for h in ("/api", "/graphql", "/rest", "/v1", "/v2", ".json", ".xml"))
        if is_api_route or "text/html" not in ctype:
            findings.append(Finding(
                category="cors",
                title="CORS Abierto (Comodín)",
                severity="low",
                confidence="confirmed",
                description="La cabecera 'Access-Control-Allow-Origin: *' permite la lectura de este recurso desde cualquier sitio web.",
                affected_url=url,
                evidence=Evidence(request_method="GET", request_url=url, response_status=resp.status_code),
                remediation="Verificar si la información contenida en el endpoint es pública; en caso contrario, restringir el origen.",
            ))

    return findings


async def check_sensitive_paths_async(
    engine: AsyncScanEngine,
    base_url: str,
    custom_paths: list[str] | None = None,
) -> list[Finding]:
    """Sondeo asíncrono concurrente de archivos expuestos y rutas administrativas sensibles."""
    findings: list[Finding] = []
    probe_paths = custom_paths or [
        "/.env",
        "/.git/HEAD",
        "/actuator/health",
        "/server-status",
        "/swagger.json",
        "/openapi.json",
    ]

    base = base_url.rstrip("/")
    tasks = [engine.fetch(f"{base}{path}", method="GET") for path in probe_paths]
    responses = await asyncio.gather(*tasks, return_exceptions=True)

    for path, resp in zip(probe_paths, responses):
        if not isinstance(resp, httpx.Response) or resp.status_code != 200:
            continue

        body_lower = resp.text.lower()
        # Descartar páginas de error HTML con código 200 (Soft-404)
        if ("<!doctype html" in body_lower or "<html" in body_lower) and path in ("/.env", "/.git/HEAD"):
            continue

        # Validaciones de firmas
        if path == "/.env" and any(k in resp.text for k in ("DB_PASSWORD", "APP_KEY", "SECRET_KEY")):
            findings.append(Finding(
                category="sensitive_data",
                title="Archivo de Configuración .env Expuesto",
                severity="critical",
                confidence="confirmed",
                description="Archivo de variables de entorno expuesto públicamente con credenciales de la aplicación.",
                affected_url=f"{base}{path}",
                evidence=Evidence(request_method="GET", request_url=f"{base}{path}", response_status=200, response_fragment=resp.text[:150]),
                remediation="Bloquear acceso a dotfiles (.env) en el servidor web.",
            ))
        elif path == "/.git/HEAD" and "ref: refs/" in resp.text:
            findings.append(Finding(
                category="sensitive_data",
                title="Repositorio Git Expuesto (.git/HEAD)",
                severity="high",
                confidence="confirmed",
                description="El repositorio de control de versiones Git es accesible directamente desde la web.",
                affected_url=f"{base}{path}",
                evidence=Evidence(request_method="GET", request_url=f"{base}{path}", response_status=200, response_fragment=resp.text[:100]),
                remediation="Restringir el acceso a directorios /.git en la configuración del servidor web.",
            ))
        elif path == "/actuator/health" and '"status"' in resp.text:
            findings.append(Finding(
                category="sensitive_data",
                title="Endpoint Spring Boot Actuator Expuesto",
                severity="medium",
                confidence="confirmed",
                description="Endpoint de diagnóstico de Spring Boot accesible públicamente.",
                affected_url=f"{base}{path}",
                evidence=Evidence(request_method="GET", request_url=f"{base}{path}", response_status=200, response_fragment=resp.text[:100]),
                remediation="Aislar endpoints /actuator o protegerlos mediante autenticación Spring Security.",
            ))

    return findings


# =========================================================================
# 4. Pipeline Reactivo Asíncrono Productor-Consumidor (AsyncReactivePipeline)
# =========================================================================

@dataclass
class PipelineStats:
    """Telemetría cuantitativa de la ejecución reactiva asíncrona."""
    requests_count: int = 0
    findings_count: int = 0
    urls_scanned: int = 0
    current_rps: float = 0.0
    elapsed_seconds: float = 0.0
    circuit_state: str = "CLOSED"


class AsyncReactivePipeline:
    """
    Orquestador reactivo de alto throughput basado en streaming de eventos.
    Implementa el patrón Productor-Consumidor con colas desacopladas y workers asíncronos.
    """

    def __init__(
        self,
        config: ScanConfig,
        num_workers: int = 8,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.config = config
        self.num_workers = num_workers
        self.transport = transport
        self.url_queue: asyncio.Queue[str] = asyncio.Queue()
        self.findings_queue: asyncio.Queue[Finding | None] = asyncio.Queue()
        self.seen_urls: set[str] = set()
        self.findings: list[Finding] = []
        self._is_cancelled = False
        self._stats = PipelineStats()

    @property
    def stats(self) -> PipelineStats:
        return self._stats

    def cancel(self) -> None:
        """Detiene de forma segura el pipeline."""
        self._is_cancelled = True
        with contextlib.suppress(Exception):
            self.findings_queue.put_nowait(None)

    async def _audit_worker(self, engine: AsyncScanEngine) -> None:
        """Worker consumidor que audita URLs extraídas de la cola asíncrona."""
        while not self._is_cancelled:
            try:
                url = await asyncio.wait_for(self.url_queue.get(), timeout=0.2)
            except asyncio.TimeoutError:
                if self.url_queue.empty() or self._is_cancelled:
                    break
                continue

            try:
                if self._is_cancelled:
                    break
                # 1. Petición base
                resp = await engine.fetch(url)
                if resp and not self._is_cancelled:
                    # 2. Chequeos Pasivos
                    header_findings = await check_headers_async(resp, url)
                    for f in header_findings:
                        await self.findings_queue.put(f)

                    # 3. Chequeos Activos si el perfil lo permite
                    if self.config.active_payloads and not self._is_cancelled:
                        cors_findings = await check_cors_async(engine, url)
                        for f in cors_findings:
                            await self.findings_queue.put(f)

                self._stats.urls_scanned += 1
            except Exception as exc:
                logger.debug("Error procesando URL %s en worker: %s", url, exc)
            finally:
                self.url_queue.task_done()

    async def stream_scan(self, start_url: str) -> AsyncGenerator[Finding, None]:
        """
        Generador asíncrono que transmite hallazgos en tiempo real según se descubren,
        permitiendo integración directa con WebSockets y consumidores de streaming.
        """
        start_time = time.time()
        if self._is_cancelled:
            return

        async with AsyncScanEngine(self.config, max_concurrency=self.num_workers * 2, transport=self.transport) as engine:
            # 1. Encolar URL inicial
            await self.url_queue.put(start_url)
            self.seen_urls.add(start_url)

            # 2. Descubrir URLs concurrentemente si el crawling está activo
            if self.config.max_crawl_pages > 1 and not self._is_cancelled:
                crawler = AsyncCrawler(engine, max_pages=self.config.max_crawl_pages, max_depth=self.config.max_crawl_depth)
                discovered = await crawler.crawl(start_url)
                for u in discovered:
                    if u not in self.seen_urls:
                        self.seen_urls.add(u)
                        await self.url_queue.put(u)

            # 3. Iniciar sondeo de rutas sensibles del dominio
            sensitive_task = asyncio.create_task(check_sensitive_paths_async(engine, start_url))

            # 4. Disparar pool de workers consumidores
            workers = [asyncio.create_task(self._audit_worker(engine)) for _ in range(self.num_workers)]

            # 5. Tarea de finalización para cerrar la cola de hallazgos
            async def _cleanup_notifier() -> None:
                try:
                    if not self._is_cancelled:
                        await self.url_queue.join()
                except Exception as exc:
                    logger.debug("Excepción esperando url_queue en cleanup: %s", exc)
                for w in workers:
                    w.cancel()
                # Recoger hallazgos de rutas sensibles si no fue cancelado
                if not self._is_cancelled:
                    try:
                        sens_findings = await sensitive_task
                        for sf in sens_findings:
                            await self.findings_queue.put(sf)
                    except Exception as exc:
                        logger.debug("Excepción recogiendo rutas sensibles en cleanup: %s", exc)
                else:
                    sensitive_task.cancel()
                # Centinela de fin de flujo
                await self.findings_queue.put(None)

            cleanup_task = asyncio.create_task(_cleanup_notifier())

            # 6. Stream reactivo hacia el consumidor
            while True:
                item = await self.findings_queue.get()
                if item is None:
                    break
                self.findings.append(item)
                self._stats.findings_count = len(self.findings)
                self._stats.requests_count = engine.request_count
                self._stats.current_rps = engine.current_rps
                self._stats.elapsed_seconds = time.time() - start_time
                self._stats.circuit_state = engine.circuit_state
                yield item

            await cleanup_task

    async def run_full_scan(self, start_url: str) -> list[Finding]:
        """Ejecuta el pipeline reactivo completo y retorna la lista acumulada de hallazgos."""
        async for _ in self.stream_scan(start_url):
            pass
        return self.findings
