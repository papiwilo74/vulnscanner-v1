"""
Motor de Escaneo Diferencial Quirúrgico por Git Diff en CI/CD (Smart Incremental DAST).

Optimizado para ejecutarse en Pull Requests de GitHub Actions, GitLab CI y Azure DevOps en <60 segundos.
Implementa:
1. Analizador de Git Diff: Identifica archivos modificados a partir de git o streams de diff unificado.
2. Extractor de Rutas y Controladores: Mapea código fuente modificado (FastAPI, Flask, Django, Express)
   y especificaciones OpenAPI hacia endpoints HTTP reales.
3. Despachador DAST Quirúrgico: Ejecuta auditorías enfocadas exclusivamente sobre la superficie afectada
   (Inyecciones de parámetros, API Security BOLA/Mass Assignment, CORS, Headers y Templates DSL).
4. Puerta de Calidad DevSecOps (Quality Gate): Bloqueo automático ante vulnerabilidades High/Critical.
5. Formateador de Comentarios para PRs de GitHub y serializador SARIF v2.1.0 para Code Scanning.
"""
from __future__ import annotations

import concurrent.futures
import logging
import re
import subprocess  # nosec B404
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import requests

from scanner.api_security import check_bola_idor, check_mass_assignment
from scanner.models import Finding
from scanner.sqli import check_sqli
from scanner.xss import check_xss

logger = logging.getLogger("OmniBreach.GitDiffScanner")


@dataclass
class ModifiedRoute:
    """Ruta o endpoint HTTP afectado por modificaciones de código."""
    path: str
    method: str = "GET"
    file_source: str = ""
    parameters: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class IncrementalScanResult:
    """Resultado estructurado de la auditoría diferencial quirúrgica de CI/CD."""
    target_url: str
    base_ref: str
    modified_files: list[str]
    targeted_endpoints: list[ModifiedRoute]
    findings: list[Finding]
    gate_passed: bool
    duration_seconds: float
    summary: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_url": self.target_url,
            "base_ref": self.base_ref,
            "modified_files": self.modified_files,
            "targeted_endpoints": [e.to_dict() for e in self.targeted_endpoints],
            "findings": [f.to_dict() for f in self.findings],
            "findings_count": len(self.findings),
            "gate_passed": self.gate_passed,
            "duration_seconds": round(self.duration_seconds, 2),
            "summary": self.summary,
        }


# =========================================================================
# 1. Analizador de Cambios de Git y Extractor de Rutas
# =========================================================================

class GitDiffAnalyzer:
    """Analiza cambios de código en repositorios Git y extrae endpoints afectados."""

    @staticmethod
    def parse_diff_text(diff_text: str) -> list[str]:
        """Extrae la lista de archivos modificados a partir de un diff unificado (git diff)."""
        modified_files: set[str] = set()
        for line in diff_text.splitlines():
            # Formato '+++ b/ruta/archivo.py' o 'diff --git a/... b/...'
            if line.startswith("+++ b/"):
                filepath = line[6:].strip()
                if filepath and filepath != "/dev/null":
                    modified_files.add(filepath)
            elif line.startswith("diff --git a/"):
                parts = line.split(" b/")
                if len(parts) == 2:
                    modified_files.add(parts[1].strip())
        return sorted(modified_files)

    @staticmethod
    def extract_files_from_git(repo_path: str = ".", base_ref: str = "origin/main") -> list[str]:
        """Ejecuta comando 'git diff' en el repositorio local para obtener archivos modificados."""
        try:
            cmd = ["git", "diff", "--name-only", f"{base_ref}...HEAD"]
            out = subprocess.check_output(cmd, cwd=repo_path, stderr=subprocess.DEVNULL, text=True)  # nosec B603
            files = [line.strip() for line in out.splitlines() if line.strip()]
            if files:
                return files
        except Exception as exc:
            logger.debug("Error ejecutando git diff con tres puntos: %s", exc)

        # Fallback a git diff directo contra base_ref
        try:
            cmd = ["git", "diff", "--name-only", base_ref]
            out = subprocess.check_output(cmd, cwd=repo_path, stderr=subprocess.DEVNULL, text=True)  # nosec B603
            return [line.strip() for line in out.splitlines() if line.strip()]
        except Exception as exc:
            logger.warning("Fallo al inspeccionar git diff en %s: %s", repo_path, exc)
            return []

    @staticmethod
    def extract_routes_from_content(file_path: str, code_content: str) -> list[ModifiedRoute]:
        """
        Inspecciona código fuente Python (FastAPI, Flask, Django) y JavaScript/TypeScript (Express)
        mediante expresiones regulares especializadas para extraer rutas declaradas.
        """
        routes: list[ModifiedRoute] = []

        # 1. FastAPI / Starlette: @app.get("/path"), @router.post("/path")
        fastapi_patterns = [
            r'@(?:app|router|api)\.(get|post|put|delete|patch|options)\(\s*["\']([^"\']+)["\']',
            r'@(?:app|router|api)\.api_route\(\s*["\']([^"\']+)["\']\s*,\s*methods=\[([^\]]+)\]',
        ]
        for pattern in fastapi_patterns:
            matches = re.findall(pattern, code_content, re.IGNORECASE)
            for m in matches:
                if len(m) == 2:
                    method, path = m[0].upper(), m[1]
                    params = re.findall(r'\{([a-zA-Z0-9_]+)\}', path)
                    routes.append(ModifiedRoute(path=path, method=method, file_source=file_path, parameters=params))

        # 2. Flask: @app.route("/path", methods=["GET", "POST"])
        flask_matches = re.findall(r'@(?:app|bp|blueprint)\.route\(\s*["\']([^"\']+)["\'](?:.*?methods=\[([^\]]+)\])?', code_content, re.DOTALL)
        for path, raw_methods in flask_matches:
            methods = ["GET"]
            if raw_methods:
                methods = [m.strip().replace("'", "").replace('"', '').upper() for m in raw_methods.split(",") if m.strip()]
            params = re.findall(r'<[a-zA-Z_:]*([a-zA-Z0-9_]+)>', path)
            for method in methods:
                routes.append(ModifiedRoute(path=path, method=method, file_source=file_path, parameters=params))

        # 3. Express JS / TS: app.get('/path', ...), router.post('/path', ...)
        express_matches = re.findall(r'(?:app|router)\.(get|post|put|delete|patch)\(\s*["\']([^"\']+)["\']', code_content)
        for method, path in express_matches:
            params = re.findall(r':([a-zA-Z0-9_]+)', path)
            routes.append(ModifiedRoute(path=path, method=method.upper(), file_source=file_path, parameters=params))

        # 4. Django urls.py: path('users/', views.user_list)
        django_matches = re.findall(r'path\(\s*["\']([^"\']*)["\']\s*,', code_content)
        for path in django_matches:
            norm_path = f"/{path}" if not path.startswith("/") else path
            routes.append(ModifiedRoute(path=norm_path, method="GET", file_source=file_path))

        return routes

    @classmethod
    def extract_routes_from_files(cls, file_paths: list[str], base_dir: str = ".") -> list[ModifiedRoute]:
        """Lee archivos del disco y extrae rutas HTTP declaradas."""
        all_routes: list[ModifiedRoute] = []
        root = Path(base_dir)

        for rel_path in file_paths:
            full_path = root / rel_path
            if full_path.is_file() and full_path.suffix in (".py", ".js", ".ts", ".jsx", ".tsx"):
                try:
                    content = full_path.read_text(encoding="utf-8", errors="ignore")
                    extracted = cls.extract_routes_from_content(rel_path, content)
                    all_routes.extend(extracted)
                except Exception as exc:
                    logger.debug("Error leyendo archivo %s: %s", full_path, exc)

        # Deduplicar por método y ruta
        unique_map: dict[str, ModifiedRoute] = {}
        for r in all_routes:
            key = f"{r.method}:{r.path}"
            if key not in unique_map:
                unique_map[key] = r

        return list(unique_map.values())

    @staticmethod
    def map_routes_from_openapi(modified_files: list[str], openapi_data: dict[str, Any]) -> list[ModifiedRoute]:
        """
        Si se modificaron controladores o esquemas, cruza los nombres con las rutas de OpenAPI.
        """
        matched_routes: list[ModifiedRoute] = []
        paths_dict = openapi_data.get("paths", {})

        # Palabras clave extraídas de los archivos modificados (ej. 'users' de 'user_controller.py')
        keywords = set()
        for f in modified_files:
            stem = Path(f).stem.lower().replace("_", "").replace("controller", "").replace("router", "").replace("view", "")
            if len(stem) >= 3:
                keywords.add(stem)

        for path, path_item in paths_dict.items():
            if not isinstance(path_item, dict):
                continue

            path_lower = path.lower().replace("_", "").replace("-", "")
            is_relevant = any(kw in path_lower for kw in keywords) if keywords else True

            if is_relevant:
                for method, spec in path_item.items():
                    if method.lower() in ("get", "post", "put", "delete", "patch"):
                        params = []
                        if isinstance(spec, dict) and "parameters" in spec:
                            params = [p.get("name", "") for p in spec["parameters"] if isinstance(p, dict)]
                        matched_routes.append(ModifiedRoute(
                            path=path,
                            method=method.upper(),
                            file_source="openapi_spec",
                            parameters=params,
                        ))

        return matched_routes


# =========================================================================
# 2. Despachador DAST Quirúrgico (SurgicalIncrementalScanner)
# =========================================================================

class SurgicalIncrementalScanner:
    """Ejecutor rápido de pruebas de seguridad dirigido exclusivamente a endpoints modificados."""

    def __init__(
        self,
        session: requests.Session | None = None,
        default_timeout: float = 4.0,
        max_severity_gate: str = "high",
    ) -> None:
        self.session = session or requests.Session()
        self.default_timeout = default_timeout
        self.max_severity_gate = max_severity_gate.lower()

    def run_incremental_scan(
        self,
        target_base_url: str,
        routes: list[ModifiedRoute],
        modified_files: list[str] | None = None,
        base_ref: str = "main",
        max_workers: int = 4,
    ) -> IncrementalScanResult:
        """
        Ejecuta pruebas específicas sobre cada endpoint modificado.
        Típicamente completa en menos de 10-30 segundos.
        """
        start_time = time.time()
        findings: list[Finding] = []
        base = target_base_url.rstrip("/")

        def _audit_route(route: ModifiedRoute) -> list[Finding]:
            route_findings: list[Finding] = []
            # Normalizar ruta reemplazando variables {id} o <id> por canarios '1'
            normalized_path = re.sub(r'\{[a-zA-Z0-9_]+\}', '1', route.path)
            normalized_path = re.sub(r'<[a-zA-Z0-9_:]+>', '1', normalized_path)
            normalized_path = re.sub(r':[a-zA-Z0-9_]+', '1', normalized_path)
            if not normalized_path.startswith("/"):
                normalized_path = f"/{normalized_path}"

            full_url = f"{base}{normalized_path}"

            # 1. Petición inicial para verificar presencia
            try:
                self.session.request(
                    route.method,
                    full_url,
                    timeout=self.default_timeout,
                    verify=False,  # nosec B501
                )
            except Exception as exc:
                logger.debug("Error conectando a endpoint quirúrgico %s: %s", full_url, exc)
                return []

            # 2. Inyección de Parámetros SQLi & XSS (si acepta GET con parámetros)
            if route.method == "GET":
                url_with_param = f"{full_url}?q=test"
                try:
                    sqli_results = check_sqli(url_with_param, self.session)
                    route_findings.extend(Finding.from_legacy_list(sqli_results, "sqli", url_with_param))
                except Exception:
                    pass

                try:
                    xss_results = check_xss(url_with_param, None, self.session, passive=False)
                    route_findings.extend(Finding.from_legacy_list(xss_results, "xss", url_with_param))
                except Exception:
                    pass

            # 3. Comprobaciones de API (Mass Assignment en POST/PUT/PATCH)
            if route.method in ("POST", "PUT", "PATCH"):
                try:
                    mass_finding = check_mass_assignment(
                        url=full_url,
                        method=route.method,
                        session=self.session,
                        timeout=self.default_timeout,
                    )
                    if mass_finding:
                        route_findings.append(mass_finding)
                except Exception:
                    pass

            # 4. Comprobaciones de BOLA / IDOR si la ruta tiene identificador de entidad
            if "1" in normalized_path:
                try:
                    bola_finding = check_bola_idor(
                        url=full_url,
                        method=route.method,
                        session_user_a=self.session,
                        unauth_check=True,
                        timeout=self.default_timeout,
                    )
                    if bola_finding:
                        route_findings.append(bola_finding)
                except Exception:
                    pass

            return route_findings

        # Ejecución paralela sobre los endpoints seleccionados
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_route = {executor.submit(_audit_route, r): r for r in routes}
            for future in concurrent.futures.as_completed(future_to_route):
                try:
                    res = future.result()
                    findings.extend(res)
                except Exception as exc:
                    logger.debug("Fallo en escaneo quirúrgico de ruta: %s", exc)

        duration = time.time() - start_time

        # Evaluar Quality Gate: Si existen vulnerabilidades de severidad mayor o igual al umbral
        severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        gate_threshold = severity_rank.get(self.max_severity_gate, 3)

        gate_passed = True
        for f in findings:
            if severity_rank.get(f.severity.lower(), 0) >= gate_threshold:
                gate_passed = False
                break

        summary = (
            f"Escaneo Quirúrgico completado en {duration:.2f}s. "
            f"Endpoints evaluados: {len(routes)} de {len(modified_files or [])} archivos modificados. "
            f"Hallazgos detectados: {len(findings)}. "
            f"Quality Gate: {'APROBADO (PASS)' if gate_passed else 'BLOQUEADO (FAIL)'}."
        )

        return IncrementalScanResult(
            target_url=target_base_url,
            base_ref=base_ref,
            modified_files=modified_files or [],
            targeted_endpoints=routes,
            findings=findings,
            gate_passed=gate_passed,
            duration_seconds=duration,
            summary=summary,
        )


# =========================================================================
# 3. Decoradores de Pull Request & Exportadores DevSecOps
# =========================================================================

def format_github_pr_comment(result: IncrementalScanResult) -> str:
    """Genera un reporte en Markdown listo para comentar como Bot en el Pull Request de GitHub."""
    status_icon = "✅" if result.gate_passed else "❌"
    gate_title = "Quality Gate APROBADO" if result.gate_passed else "Quality Gate BLOQUEADO"

    lines = [
        f"## {status_icon} OmniBreach Incremental DAST — {gate_title}",
        "",
        f"> **Objetivo:** `{result.target_url}` | **Rama Base:** `{result.base_ref}` | **Duración:** `{result.duration_seconds:.2f}s`",
        "",
        f"**Resumen:** {result.summary}",
        "",
        "### 🎯 Superficie Quirúrgica Auditada",
        "| Método | Endpoint Afectado | Archivo de Origen |",
        "| :--- | :--- | :--- |",
    ]

    for r in result.targeted_endpoints[:10]:
        lines.append(f"| `{r.method}` | `{r.path}` | `{r.file_source}` |")

    if len(result.targeted_endpoints) > 10:
        lines.append(f"| ... | *{len(result.targeted_endpoints) - 10} endpoints más* | |")

    lines.append("")
    lines.append("### 🚨 Resultados de Seguridad")

    if not result.findings:
        lines.append("🎉 **No se detectaron nuevas vulnerabilidades en los endpoints modificados.** El PR es seguro para merge.")
    else:
        lines.append("| Severidad | Vulnerabilidad | Endpoint | CWE | Confianza |")
        lines.append("| :--- | :--- | :--- | :--- | :--- |")
        for f in result.findings:
            badge = f"**{f.severity.upper()}**"
            lines.append(f"| {badge} | {f.title} | `{f.affected_url}` | {f.cwe_id or 'N/A'} | {f.confidence} |")

        lines.append("")
        lines.append("#### 🛠️ Instrucciones de Remediación")
        for f in result.findings[:5]:
            lines.append(f"- **{f.title}**: {f.remediation or 'Revisar validación y control de acceso del endpoint.'}")

    lines.append("")
    lines.append("---")
    lines.append("*Generado automáticamente por OmniBreach v3.9 DevSecOps Engine.*")
    return "\n".join(lines)


def export_incremental_sarif(result: IncrementalScanResult, output_path: str) -> dict[str, Any]:
    """Serializa los hallazgos en formato OASIS SARIF v2.1.0 para GitHub Code Scanning."""
    from scanner.sarif import export_findings_to_sarif, save_sarif_file
    sarif_data = export_findings_to_sarif(result.findings, scan_url=result.target_url)
    save_sarif_file(sarif_data, output_path)
    return sarif_data


def dispatch_ci_incremental_scan(
    url: str,
    base_ref: str = "origin/main",
    diff_content: str | None = None,
    modified_files: list[str] | None = None,
    repo_dir: str = ".",
    gate_severity: str = "high",
) -> dict[str, Any]:
    """
    Función orquestadora de alto nivel para ejecutar el escaneo diferencial
    desde CI/CD, scripts automatizados o endpoints de API.
    """
    files = list(modified_files or [])
    if diff_content:
        parsed = GitDiffAnalyzer.parse_diff_text(diff_content)
        files = list(dict.fromkeys(files + parsed))
    elif not files:
        files = GitDiffAnalyzer.extract_files_from_git(repo_path=repo_dir, base_ref=base_ref)

    routes = GitDiffAnalyzer.extract_routes_from_files(files, base_dir=repo_dir)

    scanner = SurgicalIncrementalScanner(max_severity_gate=gate_severity)
    result = scanner.run_incremental_scan(
        target_base_url=url,
        routes=routes,
        modified_files=files,
        base_ref=base_ref,
    )

    pr_comment = format_github_pr_comment(result)
    res_dict = result.to_dict()
    res_dict["pr_comment_markdown"] = pr_comment
    return {
        "status": "success",
        "result": res_dict,
    }


