"""Escáner de APIs REST guiado por especificaciones OpenAPI 3.x y Swagger 2.0."""
import json
import logging
import re
from typing import Any, Optional

import requests

from scanner.engine import ScanEngine
from scanner.models import Finding

log = logging.getLogger("VulnScanner.OpenAPI")


class OpenAPIScanner:
    """Parsea especificaciones OpenAPI/Swagger y ejecuta auditorias de seguridad en sus endpoints."""

    def __init__(
        self,
        spec_source: str,
        base_url: Optional[str] = None,
        session: Optional[requests.Session] = None,
        engine: Optional[ScanEngine] = None,
    ):
        self.spec_source = spec_source
        self.session = session or requests.Session()
        self.engine = engine
        self.spec: dict[str, Any] = {}
        self.base_url = base_url or ""

    def load_spec(self) -> bool:
        """Carga la especificacion desde una URL remota o un archivo local."""
        try:
            if self.spec_source.startswith(("http://", "https://")):
                r = self.session.get(self.spec_source, timeout=10)
                if r.status_code == 200:
                    self.spec = r.json()
                else:
                    log.error("No se pudo descargar OpenAPI spec de %s (HTTP %d)", self.spec_source, r.status_code)
                    return False
            else:
                with open(self.spec_source, encoding="utf-8") as f:
                    self.spec = json.load(f)

            # Determinar base_url si no fue explicitamente proporcionada
            if not self.base_url:
                if "servers" in self.spec and self.spec["servers"]:
                    raw_server = self.spec["servers"][0].get("url", "")
                    if raw_server.startswith("http"):
                        self.base_url = raw_server
                elif "host" in self.spec:
                    scheme = self.spec.get("schemes", ["http"])[0]
                    base_path = self.spec.get("basePath", "")
                    self.base_url = f"{scheme}://{self.spec['host']}{base_path}"

            log.info("[OpenAPI] Especificacion cargada exitosamente: %s (Base: %s)", self.spec.get("info", {}).get("title", "API"), self.base_url)
            return True
        except Exception as e:
            log.error("[OpenAPI] Error al cargar especificacion: %s", e)
            return False

    def get_endpoints(self) -> list[dict[str, Any]]:
        """Extrae todas las rutas, metodos y parametros de la especificacion."""
        endpoints = []
        paths = self.spec.get("paths", {})

        for path, path_item in paths.items():
            for method in ["get", "post", "put", "delete", "patch"]:
                if method in path_item:
                    op = path_item[method]
                    endpoints.append({
                        "path": path,
                        "method": method.upper(),
                        "operation_id": op.get("operationId", f"{method}_{path}"),
                        "summary": op.get("summary", ""),
                        "parameters": op.get("parameters", []) + path_item.get("parameters", []),
                        "request_body": op.get("requestBody", {}),
                        "security": op.get("security", self.spec.get("security", [])),
                    })
        return endpoints

    def scan(self) -> list[Finding]:
        """Ejecuta la suite de auditoria de seguridad sobre los endpoints de la API."""
        if not self.spec and not self.load_spec():
            return []

        findings: list[Finding] = []
        endpoints = self.get_endpoints()
        log.info("[OpenAPI] Auditando %d endpoints descubiertos...", len(endpoints))

        for ep in endpoints:
            if self.engine and not self.engine.check_limits():
                break

            target_path = ep["path"]
            method = ep["method"]
            has_security = bool(ep["security"])

            # 1. Resolver parametros de ruta para pruebas
            sample_path = re.sub(r"\{([^}]+)\}", "1", target_path)
            full_url = f"{self.base_url.rstrip('/')}/{sample_path.lstrip('/')}" if self.base_url else sample_path

            # 2. Chequeo API2:2023 - Broken Authentication en endpoints sensibles
            if has_security or method in ["POST", "PUT", "DELETE"]:
                auth_finding = self._check_broken_auth(full_url, method, ep)
                if auth_finding:
                    findings.append(auth_finding)

            # 3. Chequeo API8:2023 - Security Misconfiguration (Manejo de errores 500 ante entrada malformada)
            if method in ["POST", "PUT", "PATCH"]:
                error_finding = self._check_error_handling(full_url, method)
                if error_finding:
                    findings.append(error_finding)

            # 4. Fuzzing de Inyecciones en Parametros Query de la API
            query_params = [p for p in ep["parameters"] if p.get("in") == "query"]
            for qp in query_params:
                pname = qp.get("name")
                if pname:
                    sqli_finding = self._check_parameter_sqli(full_url, pname)
                    if sqli_finding:
                        findings.append(sqli_finding)

        return findings

    def _check_broken_auth(self, url: str, method: str, ep: dict[str, Any]) -> Optional[Finding]:
        """Verifica si un endpoint que declara seguridad o mutacion responde 200/201 sin cabecera de autenticacion."""
        try:
            if self.engine:
                self.engine.ratelimit()

            # Peticion sin credenciales
            unauth_session = requests.Session()
            resp = unauth_session.request(method, url, timeout=8)
            if self.engine:
                self.engine.record_request(url, method, resp.status_code)

            if resp.status_code in [200, 201] and not any(p in url.lower() for p in ["login", "token", "public", "health", "docs", "openapi"]):
                # Comprobar si devolvio datos reales
                ct = resp.headers.get("Content-Type", "").lower()
                if "json" in ct and len(resp.content) > 10:
                    from scanner.models import Evidence
                    return Finding(
                        category="api",
                        title="API Endpoint Sensible sin Autenticación Obligatoria",
                        severity="high",
                        confidence="high",
                        description=(
                            f"El endpoint {method} {url} respondió con código HTTP {resp.status_code} "
                            "a una petición no autenticada, a pesar de operar con métodos de mutación o declarar esquemas de seguridad."
                        ),
                        affected_url=url,
                        evidence=Evidence(
                            request_method=method,
                            request_url=url,
                            response_status=resp.status_code,
                            response_fragment=resp.text[:120],
                        ),
                        cwe_id="CWE-306",
                        cwe_name="Missing Authentication for Critical Function",
                        mitre_attack_id="T1078",
                        mitre_attack_name="Valid Accounts",
                        owasp_category="API2:2023 - Broken Authentication",
                        remediation="Implementar verificación estricta de tokens de autorización (Bearer JWT / API Keys) antes de procesar la solicitud.",
                    )
        except requests.RequestException:
            pass
        return None

    def _check_error_handling(self, url: str, method: str) -> Optional[Finding]:
        """Prueba si enviar un cuerpo JSON malformado o de tipo incorrecto desencadena un 500 con fuga de trazas."""
        try:
            if self.engine:
                self.engine.ratelimit()

            malformed_body = '{"invalid_json": true,'  # JSON roto deliberadamente
            headers = {"Content-Type": "application/json"}
            resp = self.session.request(method, url, data=malformed_body, headers=headers, timeout=8)
            if self.engine:
                self.engine.record_request(url, method, resp.status_code)

            if resp.status_code == 500:
                text_lower = resp.text.lower()
                has_stacktrace = any(
                    sig in text_lower for sig in [
                        "traceback (most recent call last)",
                        "syntaxerror:",
                        "at json.parse",
                        "internal server error",
                        "exception in thread",
                        "system.exception",
                    ]
                )
                if has_stacktrace:
                    from scanner.models import Evidence
                    return Finding(
                        category="api",
                        title="Fuga de Información y Traza de Error en API (HTTP 500)",
                        severity="medium",
                        confidence="high",
                        description=f"El endpoint {method} {url} devolvió un error interno HTTP 500 exponiendo trazas o excepciones internas ante entrada malformada.",
                        affected_url=url,
                        evidence=Evidence(
                            request_method=method,
                            request_url=url,
                            payload=malformed_body,
                            response_status=resp.status_code,
                            response_fragment=resp.text[:150],
                        ),
                        cwe_id="CWE-209",
                        cwe_name="Generation of Error Message Containing Sensitive Information",
                        mitre_attack_id="T1005",
                        mitre_attack_name="Data from Local System",
                        owasp_category="API8:2023 - Security Misconfiguration",
                        remediation="Configurar un manejador de excepciones global que capture errores y devuelva un código HTTP 400 Bad Request estructurado sin volcar detalles internos.",
                    )
        except requests.RequestException:
            pass
        return None

    def _check_parameter_sqli(self, url: str, param_name: str) -> Optional[Finding]:
        """Prueba una inyección SQL benigna en un parámetro de query especificado en OpenAPI."""
        probe = f"'{param_name}_vuln_probe"
        test_url = f"{url}{'&' if '?' in url else '?'}{param_name}={probe}"
        try:
            if self.engine:
                self.engine.ratelimit()

            resp = self.session.get(test_url, timeout=8)
            if self.engine:
                self.engine.record_request(test_url, "GET", resp.status_code)

            text_lower = resp.text.lower()
            from scanner.sqli import ERROR_SIGNATURES
            matched_error = next((sig for sig in ERROR_SIGNATURES if re.search(sig, text_lower, re.IGNORECASE)), None)

            if matched_error:
                from scanner.models import Evidence
                return Finding(
                    category="sqli",
                    title=f"Inyección SQL en Parámetro de API ({param_name})",
                    severity="critical",
                    confidence="high",
                    description=f"El parámetro '{param_name}' documentado en la API es vulnerable a Inyección SQL.",
                    affected_url=test_url,
                    parameter=param_name,
                    evidence=Evidence(
                        request_method="GET",
                        request_url=test_url,
                        payload=probe,
                        response_status=resp.status_code,
                        response_fragment=f"Firma detectada: {matched_error}",
                    ),
                    cwe_id="CWE-89",
                    cwe_name="Improper Neutralization of Special Elements used in an SQL Command",
                    mitre_attack_id="T1190",
                    mitre_attack_name="Exploit Public-Facing Application",
                    owasp_category="A03:2021-Injection",
                    remediation="Utilizar consultas parametrizadas u ORM seguro para validar el tipo de dato del parámetro.",
                )
        except requests.RequestException:
            pass
        return None
