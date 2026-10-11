"""
Pruebas exhaustivas para el Pipeline Reactivo Asíncrono de OmniBreach (AsyncReactivePipeline).
"""
import httpx
import pytest

from scanner.async_engine import (
    AsyncCrawler,
    AsyncReactivePipeline,
    AsyncScanEngine,
    check_cors_async,
    check_headers_async,
    check_sensitive_paths_async,
)
from scanner.engine import ScanConfig, ScanProfile
from scanner.models import Finding


@pytest.mark.anyio
async def test_async_crawler_domain_scoping():
    """Valida que AsyncCrawler descubra enlaces internos respetando el dominio y límites."""
    config = ScanConfig(profile=ScanProfile.NORMAL, max_crawl_pages=5)

    def handler(request: httpx.Request) -> httpx.Response:
        url_str = str(request.url)
        if url_str == "https://app.local/":
            html = """
            <html>
                <a href="/about">About</a>
                <a href="/products">Products</a>
                <a href="https://external-site.com/evil">External</a>
            </html>
            """
            return httpx.Response(200, text=html, headers={"Content-Type": "text/html"})
        elif url_str == "https://app.local/about":
            html = '<html><a href="/contact">Contact</a></html>'
            return httpx.Response(200, text=html, headers={"Content-Type": "text/html"})
        return httpx.Response(200, text="<html>Page</html>", headers={"Content-Type": "text/html"})

    transport = httpx.MockTransport(handler)

    async with AsyncScanEngine(config, transport=transport) as engine:
        crawler = AsyncCrawler(engine, max_pages=10, max_depth=2)
        discovered = await crawler.crawl("https://app.local/")

        assert "https://app.local/" in discovered
        assert "https://app.local/about" in discovered
        assert "https://app.local/products" in discovered
        assert "https://app.local/contact" in discovered
        # No debe incluir dominios externos
        assert not any("external-site.com" in u for u in discovered)


@pytest.mark.anyio
async def test_async_security_headers_and_hsts():
    """Valida la detección de cabeceras de seguridad faltantes en respuestas HTML."""
    req = httpx.Request("GET", "https://app.local/page")
    resp_insecure = httpx.Response(
        200,
        text="<html>Secure Portal</html>",
        headers={"Content-Type": "text/html"},
        request=req,
    )

    findings = await check_headers_async(resp_insecure, "https://app.local/page")
    categories = [f.category for f in findings]
    titles = [f.title for f in findings]

    assert "headers" in categories
    assert any("Content-Security-Policy" in t for t in titles)
    assert any("Clickjacking" in t for t in titles)
    assert any("HSTS" in t for t in titles)


@pytest.mark.anyio
async def test_async_cors_arbitrary_origin_with_credentials():
    """Valida la detección de origen arbitrario reflejado con credenciales en CORS."""
    config = ScanConfig(profile=ScanProfile.NORMAL)

    def handler(request: httpx.Request) -> httpx.Response:
        origin = request.headers.get("Origin", "")
        if "evil-attacker.example.com" in origin:
            return httpx.Response(
                200,
                headers={
                    "Access-Control-Allow-Origin": origin,
                    "Access-Control-Allow-Credentials": "true",
                },
            )
        return httpx.Response(200)

    transport = httpx.MockTransport(handler)

    async with AsyncScanEngine(config, transport=transport) as engine:
        findings = await check_cors_async(engine, "https://api.local/user/data")
        assert len(findings) == 1
        f = findings[0]
        assert f.category == "cors"
        assert f.severity == "critical"
        assert "Credenciales Arbitrarias" in f.title


@pytest.mark.anyio
async def test_async_sensitive_paths_and_soft_404():
    """Valida detección de fuga de .env y filtrado estricto de falsos positivos Soft-404."""
    config = ScanConfig(profile=ScanProfile.NORMAL)

    def handler(request: httpx.Request) -> httpx.Response:
        url_str = str(request.url)
        if url_str.endswith("/.env"):
            return httpx.Response(200, text="DB_PASSWORD=SecretProd999\nAPP_KEY=123")
        elif url_str.endswith("/.git/HEAD"):
            # Simular Soft-404 con HTML genérico (debe descartarse)
            return httpx.Response(200, text="<!DOCTYPE html><html><body>Error 404</body></html>")
        return httpx.Response(404)

    transport = httpx.MockTransport(handler)

    async with AsyncScanEngine(config, transport=transport) as engine:
        findings = await check_sensitive_paths_async(engine, "https://app.local")

        assert len(findings) == 1
        f = findings[0]
        assert f.category == "sensitive_data"
        assert ".env" in f.title
        assert f.severity == "critical"


@pytest.mark.anyio
async def test_reactive_pipeline_streaming_execution():
    """Valida la ejecución reactiva en streaming productor-consumidor con telemetría en tiempo real."""
    config = ScanConfig(
        profile=ScanProfile.NORMAL,
        max_crawl_pages=3,
        active_payloads=True,
    )

    def handler(request: httpx.Request) -> httpx.Response:
        url_str = str(request.url)
        if url_str == "https://demo.local/":
            html = '<html><a href="/profile">Profile</a></html>'
            return httpx.Response(200, text=html, headers={"Content-Type": "text/html"})
        elif url_str.endswith("/.env"):
            return httpx.Response(200, text="DB_PASSWORD=RootPassword123!")
        return httpx.Response(200, text="OK", headers={"Content-Type": "text/plain"})

    transport = httpx.MockTransport(handler)
    pipeline = AsyncReactivePipeline(config, num_workers=4, transport=transport)

    streamed_findings: list[Finding] = []
    async for finding in pipeline.stream_scan("https://demo.local/"):
        assert isinstance(finding, Finding)
        streamed_findings.append(finding)

    # Validar que los hallazgos se acumularon y las estadísticas se actualizaron
    assert len(streamed_findings) > 0
    stats = pipeline.stats
    assert stats.findings_count == len(streamed_findings)
    assert stats.requests_count > 0
    assert stats.urls_scanned >= 1
    assert stats.elapsed_seconds >= 0.0


@pytest.mark.anyio
async def test_reactive_pipeline_cooperative_cancellation():
    """Valida que la cancelación cooperativa interrumpa de inmediato las tareas sin excepciones no controladas."""
    config = ScanConfig(profile=ScanProfile.NORMAL)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="Delayed response")

    transport = httpx.MockTransport(handler)
    pipeline = AsyncReactivePipeline(config, num_workers=2, transport=transport)

    # Iniciar y cancelar inmediatamente
    pipeline.cancel()
    findings = await pipeline.run_full_scan("https://cancel-test.local/")
    assert isinstance(findings, list)
