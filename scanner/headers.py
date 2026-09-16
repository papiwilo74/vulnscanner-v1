import re
from collections.abc import Mapping
from typing import Any

import requests

SECURITY_HEADERS: dict[str, tuple[str, str]] = {
    "X-Frame-Options": ("Alto", "Protege contra clickjacking"),
    "Content-Security-Policy": ("Alto", "Previene XSS y code injection"),
    "Strict-Transport-Security": ("Alto", "Fuerza HTTPS (HSTS)"),
    "X-Content-Type-Options": ("Medio", "Previene MIME sniffing"),
    "Referrer-Policy": ("Bajo", "Controla info en cabecera Referer"),
    "Permissions-Policy": ("Bajo", "Controla APIs del navegador"),
}

BROWSER_DOCUMENT_HEADERS: set[str] = {
    "X-Frame-Options",
    "Content-Security-Policy",
    "Referrer-Policy",
    "Permissions-Policy",
}

HTML_CONTENT_TYPES: tuple[str, ...] = (
    "text/html",
    "application/xhtml+xml",
    "image/svg+xml",
)

def _get_header_case_insensitive(headers: Mapping[str, Any], name: str) -> str | None:
    target = name.lower()
    for key, value in headers.items():
        if str(key).lower() == target:
            return str(value)
    return None

def _is_https_response(response: requests.Response | Any) -> bool:
    url = getattr(response, "url", "") or ""
    return str(url).lower().startswith("https://")

def _is_browser_document_response(response: requests.Response | Any) -> bool:
    headers = getattr(response, "headers", {})
    content_type = _get_header_case_insensitive(headers, "Content-Type")

    if not content_type:
        return True

    content_type = content_type.lower()
    return any(expected in content_type for expected in HTML_CONTENT_TYPES)

def check_headers(response: requests.Response | Any) -> list[dict[str, str]]:
    results: list[dict[str, str]] = []
    is_https = _is_https_response(response)
    is_browser_document = _is_browser_document_response(response)

    # 1. Cabeceras de seguridad faltantes
    for header, (risk, desc) in SECURITY_HEADERS.items():
        if header == "Strict-Transport-Security" and not is_https:
            continue

        if header in BROWSER_DOCUMENT_HEADERS and not is_browser_document:
            continue

        if _get_header_case_insensitive(response.headers, header) is None:
            results.append({
                "vuln": f"Header faltante: {header}",
                "risk": risk,
                "detail": desc,
                "confidence": "confirmed",
            })

    # 2. Auditoría de Content-Security-Policy Débil / Permisivo
    if is_browser_document:
        csp = _get_header_case_insensitive(response.headers, "Content-Security-Policy")
        if csp:
            csp_lower = csp.lower()
            weaknesses: list[str] = []
            if "'unsafe-inline'" in csp_lower and "nonce-" not in csp_lower and "sha256-" not in csp_lower:
                weaknesses.append("'unsafe-inline' sin nonce/hash")
            if "'unsafe-eval'" in csp_lower:
                weaknesses.append("'unsafe-eval' permitido")
            if re.search(r"(?:script-src|default-src)[^;]*\*", csp_lower):
                weaknesses.append("comodín '*' en script-src/default-src")
            if re.search(r"(?:script-src|default-src)[^;]*\bhttp:", csp_lower):
                weaknesses.append("inclusión de scripts sobre HTTP inseguro")

            if weaknesses:
                results.append({
                    "vuln": "Content-Security-Policy Débil o Permisivo",
                    "risk": "Medio",
                    "detail": f"La política CSP contiene directivas inseguras que facilitan XSS: {', '.join(weaknesses)}.",
                    "confidence": "confirmed",
                })

    return results
