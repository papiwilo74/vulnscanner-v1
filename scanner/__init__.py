"""
OmniBreach v3.10 — Enterprise Security Engine.
Exporta el motor de escaneo DAST, modelos de hallazgos y el middleware universal IAST/RASP.
"""
from scanner.engine import ScanConfig, ScanEngine
from scanner.git_diff_scanner import dispatch_ci_incremental_scan
from scanner.iast_agent import OmniBreachIASTMiddleware
from scanner.models import Finding
from scanner.template_engine import TemplateEngine

__all__ = [
    "Finding",
    "OmniBreachIASTMiddleware",
    "ScanConfig",
    "ScanEngine",
    "TemplateEngine",
    "dispatch_ci_incremental_scan",
]
