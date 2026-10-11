"""
Router de FastAPI para endpoints de CI/CD DevSecOps y Escaneo Incremental Quirúrgico.
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter(tags=["CI/CD DevSecOps"])


class IncrementalScanAPIRequest(BaseModel):
    url: str
    base_ref: str | None = "origin/main"
    diff_content: str | None = None
    modified_files: list[str] | None = None
    repo_dir: str | None = "."
    gate_severity: str | None = "high"


@router.post("/api/v1/ci/incremental-scan")
def run_ci_incremental_scan(req: IncrementalScanAPIRequest) -> dict[str, Any]:
    """
    Ejecuta una auditoría diferencial quirúrgica en CI/CD (<60s) sobre endpoints modificados.
    Evalúa Quality Gate, genera comentario para PR y retorna resultados estructurados.
    """
    from scanner.git_diff_scanner import dispatch_ci_incremental_scan
    return dispatch_ci_incremental_scan(
        url=req.url,
        base_ref=req.base_ref or "origin/main",
        diff_content=req.diff_content,
        modified_files=req.modified_files,
        repo_dir=req.repo_dir or ".",
        gate_severity=req.gate_severity or "high",
    )
