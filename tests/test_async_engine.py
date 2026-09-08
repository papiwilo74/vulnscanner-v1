"""Pruebas unitarias para el motor de escaneo asíncrono httpx/asyncio."""
import httpx
import pytest

from scanner.async_engine import AsyncScanEngine
from scanner.engine import ScanConfig, ScanProfile
from scanner.models import Finding


@pytest.mark.anyio
async def test_async_engine_fetch_and_limits():
    """Valida que AsyncScanEngine ejecute peticiones asíncronas con pooling y límites."""
    config = ScanConfig(profile=ScanProfile.NORMAL, max_rps=20)

    # Mock transport para httpx sin depender de red externa
    def handler(request: httpx.Request) -> httpx.Response:
        if "rate-limit" in str(request.url):
            return httpx.Response(429, json={"error": "Too Many Requests"})
        return httpx.Response(200, json={"status": "ok", "url": str(request.url)})

    transport = httpx.MockTransport(handler)

    async with AsyncScanEngine(config, max_concurrency=5) as engine:
        engine.client._transport = transport  # Inyectar mock transport

        resp = await engine.fetch("https://api.mock.local/status")
        assert resp is not None
        assert resp.status_code == 200
        assert engine.request_count == 1
        assert engine.circuit_state == "CLOSED"

        # Simular petición que desata 429
        resp_429 = await engine.fetch("https://api.mock.local/rate-limit")
        assert resp_429 is not None
        assert resp_429.status_code == 429
        assert engine.circuit_state == "OPEN"
        assert engine.current_rps < 20.0


@pytest.mark.anyio
async def test_async_engine_run_batch():
    """Valida que run_batch distribuya corutinas concurrentemente y agrupe hallazgos."""
    config = ScanConfig(profile=ScanProfile.NORMAL)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="Mock Page")

    transport = httpx.MockTransport(handler)

    async def mock_worker(url: str, eng: AsyncScanEngine) -> list[Finding]:
        r = await eng.fetch(url)
        if r and r.status_code == 200:
            return [Finding(
                category="test",
                title=f"Test Async Finding on {url}",
                severity="info",
                confidence="high",
                description="Async probe verified",
                affected_url=url,
            )]
        return []

    test_urls = [f"https://mock.local/page{i}" for i in range(5)]

    async with AsyncScanEngine(config, max_concurrency=4) as engine:
        engine.client._transport = transport
        findings = await engine.run_batch(test_urls, mock_worker)

        assert len(findings) == 5
        assert all(f.category == "test" for f in findings)
