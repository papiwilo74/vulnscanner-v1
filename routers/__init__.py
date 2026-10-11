"""
Paquete de Routers Modulares de OmniBreach FastAPI.
"""
from routers.ci_cd import IncrementalScanAPIRequest
from routers.ci_cd import router as ci_cd_router
from routers.crawler import ActiveCrawlAPIRequest
from routers.crawler import router as crawler_router
from routers.proxy import HARImportRequest, ProxyStartRequest
from routers.proxy import router as proxy_router
from routers.templates import TemplateScanRequest
from routers.templates import router as templates_router

__all__ = [
    "ci_cd_router",
    "templates_router",
    "crawler_router",
    "proxy_router",
    "IncrementalScanAPIRequest",
    "TemplateScanRequest",
    "ActiveCrawlAPIRequest",
    "ProxyStartRequest",
    "HARImportRequest",
]
