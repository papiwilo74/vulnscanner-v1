"""
Router de FastAPI para el Servidor Proxy Interceptor y Captura de Flujos QA / HAR.
"""
from __future__ import annotations

import threading
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

router = APIRouter(tags=["Proxy Interceptor"])

_proxy_lock = threading.Lock()
_active_proxy: Any = None


class ProxyStartRequest(BaseModel):
    port: int = 8089
    forward_traffic: bool = True


class HARImportRequest(BaseModel):
    har_data: dict[str, Any] | None = None
    har_content: str | None = None


@router.post("/api/v1/proxy/start")
def start_proxy_capture(req: ProxyStartRequest) -> dict[str, Any]:
    """Inicia el servidor proxy interceptor pasivo local para capturar tráfico de QA."""
    global _active_proxy
    from scanner.proxy_capture import ProxyCaptureServer

    with _proxy_lock:
        if _active_proxy and _active_proxy.is_running:
            return {
                "status": "already_running",
                "port": _active_proxy.port,
                "flows_count": len(_active_proxy.flows),
                "message": f"Proxy ya activo en http://{_active_proxy.host}:{_active_proxy.port}",
            }
        _active_proxy = ProxyCaptureServer(port=req.port, forward_traffic=req.forward_traffic)
        _active_proxy.start()

    return {
        "status": "started",
        "port": req.port,
        "message": f"Proxy interceptor activo en http://127.0.0.1:{req.port}",
    }


@router.post("/api/v1/proxy/stop")
def stop_proxy_capture() -> dict[str, Any]:
    """Detiene el servidor proxy interceptor y conserva los flujos en memoria."""
    global _active_proxy
    with _proxy_lock:
        if not _active_proxy or not _active_proxy.is_running:
            return {"status": "not_running", "message": "El servidor proxy no está en ejecución."}
        flows_count = len(_active_proxy.flows)
        endpoints = _active_proxy.get_captured_endpoints()
        _active_proxy.stop()

    return {
        "status": "stopped",
        "flows_captured": flows_count,
        "endpoints_count": len(endpoints),
        "endpoints": endpoints,
    }


@router.get("/api/v1/proxy/status")
def get_proxy_status() -> dict[str, Any]:
    """Consulta el estado del proxy interceptor y métricas de captura."""
    global _active_proxy
    with _proxy_lock:
        if not _active_proxy:
            return {"is_running": False, "flows_count": 0, "endpoints_count": 0}
        return {
            "is_running": _active_proxy.is_running,
            "port": _active_proxy.port,
            "flows_count": len(_active_proxy.flows),
            "endpoints_count": len(_active_proxy.get_captured_endpoints()),
        }


@router.get("/api/v1/proxy/flows")
def get_proxy_flows() -> dict[str, Any]:
    """Retorna la lista de transacciones HTTP interceptadas por el proxy."""
    global _active_proxy
    with _proxy_lock:
        if not _active_proxy:
            return {"total": 0, "flows": [], "endpoints": []}
        return {
            "total": len(_active_proxy.flows),
            "endpoints": _active_proxy.get_captured_endpoints(),
            "cookies": _active_proxy.get_session_cookies(),
            "auth_headers": _active_proxy.get_auth_headers(),
            "flows": _active_proxy.flows,
        }


@router.get("/api/v1/proxy/export-har")
def export_proxy_har() -> dict[str, Any]:
    """Exporta todas las transacciones interceptadas en formato estándar HTTP Archive (HAR 1.2)."""
    global _active_proxy
    with _proxy_lock:
        if not _active_proxy:
            raise HTTPException(status_code=404, detail="No hay proxy interceptor inicializado.")
        return _active_proxy.export_har()


@router.post("/api/v1/proxy/import-har")
def import_har_session(req: HARImportRequest) -> dict[str, Any]:
    """Importa un archivo HAR y extrae cookies, tokens Bearer y catálogo de endpoints."""
    from scanner.har_parser import HARSessionParser
    try:
        if req.har_data:
            parser = HARSessionParser(req.har_data)
        elif req.har_content:
            parser = HARSessionParser.from_string(req.har_content)
        else:
            raise HTTPException(status_code=400, detail="Debe suministrar 'har_data' o 'har_content'.")
        return {
            "status": "success",
            "summary": parser.get_summary(),
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error al procesar archivo HAR: {e}") from e
