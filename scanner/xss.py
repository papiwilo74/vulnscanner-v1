import html
import os
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse

import requests

XSS_PAYLOADS: list[str] = [
    "<script>alert(1)</script>",
    '"><img src=x onerror=alert(1)>',
    "javascript:alert(1)",
]

def test_xss_payload(
    parsed, params, param: str, payload: str, baseline_text: str = "", session: Optional[requests.Session] = None
) -> Optional[dict[str, str]]:
    test_params = params.copy()
    test_params[param] = [payload]
    new_query = urlencode(test_params, doseq=True)
    test_url = urlunparse(parsed._replace(query=new_query))
    try:
        client = session if session is not None else requests
        r = client.get(test_url, timeout=5)
        response_text = r.text

        # Evitar falsos positivos:
        # 1. Si el Content-Type no es HTML ni XML, el navegador no ejecuta scripts (ej. APIs JSON o texto plano)
        headers = getattr(r, "headers", {})
        content_type = headers.get("Content-Type", "") if hasattr(headers, "get") else ""
        if isinstance(content_type, str) and content_type:
            ct_lower = content_type.lower()
            if not any(t in ct_lower for t in ["text/html", "application/xhtml+xml", "image/svg+xml"]):
                return None

        # 2. Verificar que el payload esté presente y que los caracteres clave HTML NO hayan sido escapados.
        if payload in response_text and payload not in baseline_text:
            escaped_payload = html.escape(payload)
            # Si el payload aparece unívocamente codificado (ej. &lt;script&gt;), no es ejecutable -> Falso positivo
            if payload != escaped_payload and escaped_payload in response_text and response_text.count(payload) == response_text.count(escaped_payload):
                return None

            return {
                "vuln": f"XSS reflejado en parámetro '{param}'",
                "risk": "Alto",
                "detail": f"Payload reflejado sin escapar en la respuesta HTTP: {payload}",
            }
    except requests.RequestException:
        pass
    return None

def analyze_js_code(code: str, script_name: str) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []

    # Excluir bundles minificados comunes de librerías para evitar falsos positivos masivos en JS cliente
    if any(lib in script_name.lower() for lib in ["jquery", "react", "vue", "angular", "bootstrap"]):
        return findings

    # Patrones de concordancia directa en código propio
    direct_patterns = [
        (
            r"eval\s*\([^)]*(location\.|document\.URL|document\.referrer|window\.name)",
            "Uso de eval() con entrada directa del DOM",
        ),
        (
            r"document\.write(?:ln)?\s*\([^)]*(location\.|document\.URL|document\.referrer|window\.name)",
            "Uso de document.write() con entrada directa del DOM",
        ),
        (
            r"\.(?:inner|outer)HTML\s*=\s*[^;]*(location\.|document\.URL|document\.referrer|window\.name)",
            "Asignación a innerHTML/outerHTML con entrada directa del DOM",
        ),
    ]

    for pattern, desc in direct_patterns:
        match = re.search(pattern, code, re.IGNORECASE)
        if match:
            snippet = match.group(0)[:150].strip()
            findings.append(
                {
                    "vuln": "Posible XSS basado en DOM (Directo)",
                    "risk": "Medio",
                    "detail": f"{desc} en {script_name}. Código sospechoso: {snippet}",
                }
            )
            return findings

    return findings

def check_dom_xss(url: str, html_content: Optional[str] = None, session: Optional[requests.Session] = None) -> list[dict[str, str]]:
    results: list[dict[str, str]] = []
    if not html_content:
        return results

    parsed_base = urlparse(url)
    base_domain = parsed_base.netloc

    # Analizar scripts embebidos en el HTML
    inline_scripts = re.findall(r"<script\b[^>]*>(.*?)</script>", html_content, re.DOTALL | re.IGNORECASE)
    for idx, code in enumerate(inline_scripts):
        if code.strip():
            findings = analyze_js_code(code, f"Script Embebido #{idx + 1}")
            results.extend(findings)

    # Descargar y analizar archivos JavaScript propios del mismo dominio
    src_scripts = re.findall(r'<script\b[^>]*\bsrc=["\'\s]([^"\'\s>]+)["\'\s]', html_content, re.IGNORECASE)

    js_urls = []
    for src in src_scripts:
        abs_url = urljoin(url, src)
        parsed_js = urlparse(abs_url)
        if parsed_js.netloc == base_domain:
            js_urls.append(abs_url)

    def fetch_and_analyze_js(js_url: str) -> list[dict[str, str]]:
        try:
            client = session if session is not None else requests
            r = client.get(js_url, timeout=5)
            if r.status_code == 200:
                js_name = os.path.basename(urlparse(js_url).path) or js_url
                return analyze_js_code(r.text, f"Archivo JS: {js_name}")
        except requests.RequestException:
            pass
        return []

    if js_urls:
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = {executor.submit(fetch_and_analyze_js, js_url): js_url for js_url in js_urls}
            for future in as_completed(futures):
                res = future.result()
                if res:
                    results.extend(res)

    return results

def check_xss(url: str, html_content: Optional[str] = None, session: Optional[requests.Session] = None, passive: bool = False) -> list[dict[str, str]]:
    results: list[dict[str, str]] = []

    if html_content:
        results.extend(check_dom_xss(url, html_content, session=session))

    if passive:
        return results

    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    if not params:
        return results

    client = session if session is not None else requests
    baselines = {}
    for param in params:
        try:
            r_base = client.get(urlunparse(parsed._replace(query=urlencode(params, doseq=True))), timeout=5)
            baselines[param] = r_base.text
        except requests.RequestException:
            baselines[param] = ""

    tasks = []
    for param in params:
        for payload in XSS_PAYLOADS:
            tasks.append((param, payload))

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {
            executor.submit(test_xss_payload, parsed, params, t[0], t[1], baselines.get(t[0], ""), session): t
            for t in tasks
        }
        flagged_params = set()
        for future in as_completed(futures):
            param, payload = futures[future]
            if param in flagged_params:
                continue
            res = future.result()
            if res:
                results.append(res)
                flagged_params.add(param)

    return results
