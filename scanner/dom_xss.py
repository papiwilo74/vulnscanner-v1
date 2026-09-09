"""
Módulo para la detección de Cross-Site Scripting basado en DOM (DOM-based XSS).
Analiza flujos de fuentes no confiables (Sources: location.search, location.hash, document.referrer)
hacia sumideros peligrosos (Sinks: innerHTML, eval, document.write, setTimeout) tanto
en código JavaScript estático como dinámicamente en navegador.
"""
import contextlib
import re
from typing import Any, Optional

from utils.renderer import is_playwright_available

# Expresiones regulares para fuentes (sources) y sumideros (sinks) de DOM XSS
DOM_SOURCES_REGEX = re.compile(
    r"(location\.(search|hash|href|pathname)|document\.(URL|documentURI|referrer)|window\.name|localStorage|sessionStorage)",
    re.IGNORECASE
)

DOM_SINKS_REGEX = re.compile(
    r"(\.innerHTML\s*=|\.outerHTML\s*=|document\.write\s*\(|document\.writeln\s*\(|eval\s*\(|setTimeout\s*\([^,]+|setInterval\s*\([^,]+|new\s+Function\s*\(|\.src\s*=|\.href\s*=)",
    re.IGNORECASE
)


def analyze_scripts_for_dom_xss(html_content: str, target_url: str) -> list[dict[str, Any]]:
    """
    Analiza bloques <script> en el HTML en busca de patrones de código JavaScript
    vulnerables a DOM-based XSS.
    """
    findings: list[dict[str, Any]] = []
    if not html_content:
        return findings

    # Extraer contenido de todos los bloques <script>
    script_blocks = re.findall(r"<script[^>]*>(.*?)</script>", html_content, re.DOTALL | re.IGNORECASE)

    for i, script in enumerate(script_blocks):
        # 1. Comprobar si el script contiene una fuente y un sumidero
        source_match = DOM_SOURCES_REGEX.search(script)
        sink_match = DOM_SINKS_REGEX.search(script)

        if source_match and sink_match:
            source_snippet = source_match.group(0).strip()
            sink_snippet = sink_match.group(0).strip()
            evidence = f"Source: {source_snippet} | Sink: {sink_snippet}"
            findings.append({
                "vuln": "DOM-Based Cross-Site Scripting (DOM XSS)",
                "risk": "Alto",
                "detail": f"Se detectó flujo de entrada no confiable en script #{i+1} ({source_snippet}) hacia sumidero ({sink_snippet}).",
                "type": "DOM-Based Cross-Site Scripting (DOM XSS)",
                "severity": "Alto",
                "url": target_url,
                "description": f"Se detectó un flujo peligroso de DOM XSS en bloque <script> #{i+1}: Source ({source_snippet}) -> Sink ({sink_snippet}).",
                "evidence": evidence,
                "solution": "Evita asignar variables del DOM (location.hash, location.search) a innerHTML o eval(). Utiliza textContent o librerías de sanitización como DOMPurify."
            })

    return findings


def dynamic_check_dom_xss(target_url: str, timeout: int = 8000) -> list[dict[str, Any]]:
    """
    Prueba dinámicamente si el navegador evalúa payloads inyectados en fragmentos
    (#) o parámetros de búsqueda (?) mediante Playwright.
    """
    if not is_playwright_available():
        return []

    findings = []
    canary = "vuln_dom_test_99"
    test_urls = [
        f"{target_url}#{canary}",
        f"{target_url}?search={canary}&q={canary}"
    ]

    with contextlib.suppress(Exception):
        from playwright.sync_api import sync_playwright

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()

            for test_url in test_urls:
                with contextlib.suppress(Exception):
                    page.goto(test_url, timeout=timeout, wait_until="domcontentloaded")
                    page.wait_for_timeout(1000)

                    # Verificar si el canary terminó renderizado dentro de un elemento sensible
                    injected = page.evaluate(f"""() => {{
                        const innerHTMLMatches = document.body ? document.body.innerHTML.includes('{canary}') : false;
                        const scripts = Array.from(document.querySelectorAll('script')).map(s => s.innerText);
                        const scriptMatch = scripts.some(s => s.includes('{canary}'));
                        return innerHTMLMatches && !scriptMatch;
                    }}""")

                    if injected:
                        findings.append({
                            "vuln": "DOM-Based Cross-Site Scripting (Dinámico)",
                            "risk": "Alto",
                            "detail": f"El valor inyectado en la URL ({canary}) fue reflejado en el DOM del navegador.",
                            "type": "DOM-Based XSS (Dinámico)",
                            "severity": "Alto",
                            "url": test_url,
                            "description": f"El valor inyectado en la URL ({canary}) fue reflejado dinámicamente en el DOM tras la ejecución del JavaScript de la página.",
                            "evidence": f"Payload reflejado en DOM desde URL: {test_url}",
                            "solution": "Sanitiza las variables obtenidas de window.location antes de insertarlas en el árbol DOM con DOMPurify.sanitize()."
                        })
                        break

            browser.close()

    return findings


def check_dom_xss(url: str, html_content: Optional[str] = None) -> list[dict[str, Any]]:
    """
    Función principal de verificación de DOM XSS que combina
    análisis estático de scripts y comprobación dinámica en navegador.
    """
    results: list[dict[str, Any]] = []
    if html_content:
        results.extend(analyze_scripts_for_dom_xss(html_content, url))

    if is_playwright_available():
        results.extend(dynamic_check_dom_xss(url))

    return results
