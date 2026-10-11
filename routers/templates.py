"""
Router de FastAPI para Catálogo y Ejecución de Plantillas Declarativas YAML/JSON (DSL).
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

router = APIRouter(tags=["Template Engine"])


class TemplateScanRequest(BaseModel):
    url: str
    template_ids: list[str] | None = None
    custom_template_yaml: str | None = None


@router.get("/api/v1/templates")
def list_declarative_templates() -> dict[str, Any]:
    """Lista las plantillas declarativas YAML/JSON disponibles en el catálogo."""
    from scanner.template_engine import TemplateEngine
    templates_dir = Path(__file__).resolve().parent.parent / "templates_dsl"
    templates = TemplateEngine.load_from_dir(templates_dir)
    return {
        "status": "success",
        "total": len(templates),
        "templates": [
            {
                "id": t.id,
                "name": t.info.name,
                "author": t.info.author,
                "severity": t.info.severity,
                "description": t.info.description,
                "cwe_id": t.info.cwe_id,
                "cvss_score": t.info.cvss_score,
                "tags": t.info.tags,
            }
            for t in templates
        ],
    }


@router.post("/api/v1/templates/scan")
def run_template_scan(req: TemplateScanRequest) -> dict[str, Any]:
    """Ejecuta plantillas declarativas contra un objetivo HTTP."""
    from scanner.template_engine import TemplateEngine
    engine = TemplateEngine()
    templates_dir = Path(__file__).resolve().parent.parent / "templates_dsl"
    all_templates = TemplateEngine.load_from_dir(templates_dir)

    selected = all_templates
    if req.template_ids:
        selected = [t for t in all_templates if t.id in req.template_ids]

    if req.custom_template_yaml:
        try:
            custom_tmpl = TemplateEngine.load_from_string(req.custom_template_yaml)
            selected.append(custom_tmpl)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Error parseando plantilla personalizada: {e}") from e

    if not selected:
        raise HTTPException(status_code=404, detail="No se encontraron plantillas coincidentes para ejecutar.")

    findings = engine.execute_all(selected, req.url)
    return {
        "status": "success",
        "target": req.url,
        "templates_executed": len(selected),
        "findings_count": len(findings),
        "findings": [f.to_dict() for f in findings],
    }
