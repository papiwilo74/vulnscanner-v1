"""
Router de FastAPI para el Rastreador Dinámico Avanzado (Active Crawler & Monkey Testing).
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter(tags=["Active Crawler & Monkey Testing"])


class ActiveCrawlAPIRequest(BaseModel):
    url: str
    max_monkey_actions: int | None = 25
    timeout_ms: int | None = 15000
    force_fallback: bool | None = False


@router.post("/api/v1/crawl/active")
def run_active_crawl_endpoint(req: ActiveCrawlAPIRequest) -> dict[str, Any]:
    """
    Ejecuta el rastreador dinámico avanzado con Monkey Testing y CDP Network Interception.
    Descubre rutas SPA (React/Vue/Angular), mutaciones DOM y flujos de API ocultos.
    """
    from scanner.active_crawler import ActiveCrawler
    crawler = ActiveCrawler(
        timeout_ms=req.timeout_ms or 15000,
        max_monkey_actions=req.max_monkey_actions or 25,
    )
    result = crawler.crawl(req.url, force_fallback=bool(req.force_fallback))
    return {
        "status": "success",
        "result": result.to_dict(),
    }
