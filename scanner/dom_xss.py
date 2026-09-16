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
    re.IGNORECASE,
)
DOM_DIRECT_FLOW = re.compile(
    r"(\.innerHTML|\.outerHTML|document\.write|document\.writeln|eval|setTimeout|setInterval|new\s+Function|\.src|\.href)\s*(\(|=)[^;]*\b(location\.(?:search|hash|href|pathname)|document\.(?:URL|documentURI|referrer)|window\.name)\b",
    re.IGNORECASE
)

ASSIGNMENT_RE = re.compile(
    r"(?:var|let|const)\s+([a-zA-Z0-9_$]+)\s*=\s*[^;]*\b(location\.(?:search|hash|href|pathname)|document\.(?:URL|documentURI|referrer)|window\.name)\b",
    re.IGNORECASE
)


def analyze_scripts_for_dom_xss(html_content: str, target_url: str) -> list[dict[str, Any]]:
    """
    Analiza bloques <script> en el HTML en busca de patrones de código JavaScript
    vulnerables a DOM-based XSS verificando correlación de flujo de datos.
    """
    findings: list[dict[str, Any]] = []
    if not html_content:
        return findings

    # Extraer contenido de todos los bloques <script>
    script_blocks = re.findall(r"<script[^>]*>(.*?)</script>", html_content, re.DOTALL | re.IGNORECASE)

    for i, script in enumerate(script_blocks):
        # 1. Comprobación de flujo directo (Source inyectado directamente en Sink)
        direct_match = DOM_DIRECT_FLOW.search(script)
        if direct_match:
            sink_kw = direct_match.group(1).strip()
            source_kw = direct_match.group(3).strip()
            findings.append({
                "vuln": "DOM-Based Cross-Site Scripting (DOM XSS)",
                "risk": "Alto",
                "detail": f"Se detectó flujo directo de entrada no confiable en script #{i+1} ({source_kw}) hacia sumidero ({sink_kw}).",
                "type": "DOM-Based Cross-Site Scripting (DOM XSS)",
                "severity": "Alto",
                "url": target_url,
                "description": f"Se detectó un flujo peligroso de DOM XSS en bloque <script> #{i+1}: Source ({source_kw}) -> Sink ({sink_kw}).",
                "evidence": f"Source: {source_kw} | Sink: {sink_kw}",
                "confidence": "confirmed",
                "solution": "Evita asignar variables del DOM (location.hash, location.search) a innerHTML o eval(). Utiliza textContent o librerías de sanitización como DOMPurify."
            })
            continue

        # 2. Comprobación de propagación de variables (var x = source; ... sink = x)
        var_assignments = ASSIGNMENT_RE.findall(script)
        has_flow = False
        for var_name, source_expr in var_assignments:
            sink_var_pattern = re.compile(
                rf"(\.innerHTML|\.outerHTML|document\.write|document\.writeln|eval|setTimeout|setInterval|new\s+Function|\.src|\.href)\s*(\(|=)[^;]*\b{re.escape(var_name)}\b",
                re.IGNORECASE
            )
            sink_match = sink_var_pattern.search(script)
            if sink_match:
                sink_kw = sink_match.group(1).strip()
                findings.append({
                    "vuln": "DOM-Based Cross-Site Scripting (DOM XSS)",
                    "risk": "Alto",
                    "detail": f"Se detectó flujo de entrada no confiable en script #{i+1} ({source_expr} -> {var_name}) hacia sumidero ({sink_kw}).",
                    "type": "DOM-Based Cross-Site Scripting (DOM XSS)",
                    "severity": "Alto",
                    "url": target_url,
                    "description": f"Se detectó un flujo peligroso de DOM XSS en bloque <script> #{i+1}: Source ({source_expr} -> {var_name}) -> Sink ({sink_kw}).",
                    "evidence": f"Source: {source_expr} | Sink: {sink_kw}",
                    "confidence": "confirmed",
                    "solution": "Evita asignar variables del DOM a innerHTML o eval(). Utiliza textContent o librerías de sanitización como DOMPurify."
                })
                has_flow = True
                break

        if has_flow:
            continue

    return findings



def dynamic_check_dom_xss(target_url: str, timeout: int = 8000) -> list[dict[str, Any]]:
    """
    Prueba dinámicamente si el navegador evalúa payloads inyectados en fragmentos
    (#) o parámetros de búsqueda (?) mediante instrumentación y taint tracking en Playwright.
    """
    if not is_playwright_available():
        return []

    findings: list[dict[str, Any]] = []
    canary = "vuln_dom_test_99"
    test_urls = [
        f"{target_url}#{canary}",
        f"{target_url}?search={canary}&q={canary}"
    ]

    taint_harness = f"""(() => {{
        window.__omni_taint_findings = [];
        const canary = "{canary}";

        function recordTaint(sinkName, val) {{
            try {{
                if (typeof val === 'string' && val.includes(canary)) {{
                    const err = new Error();
                    const stack = err.stack ? err.stack.toString() : '';
                    window.__omni_taint_findings.push({{
                        sink: sinkName,
                        value: val.length > 200 ? val.substring(0, 200) + '...' : val,
                        stack: stack,
                        timestamp: Date.now()
                    }});
                }}
            }} catch (e) {{}}
        }}

        try {{
            const origEval = window.eval;
            window.eval = function(code) {{
                recordTaint('window.eval', code);
                return origEval.apply(this, arguments);
            }};
        }} catch (e) {{}}

        try {{
            const origSetTimeout = window.setTimeout;
            window.setTimeout = function(handler, timeout, ...args) {{
                if (typeof handler === 'string') {{
                    recordTaint('window.setTimeout(string)', handler);
                }}
                return origSetTimeout.apply(this, [handler, timeout, ...args]);
            }};
            const origSetInterval = window.setInterval;
            window.setInterval = function(handler, timeout, ...args) {{
                if (typeof handler === 'string') {{
                    recordTaint('window.setInterval(string)', handler);
                }}
                return origSetInterval.apply(this, [handler, timeout, ...args]);
            }};
        }} catch (e) {{}}

        try {{
            const origWrite = Document.prototype.write;
            Document.prototype.write = function(...args) {{
                for (const a of args) {{
                    recordTaint('document.write', a);
                }}
                return origWrite.apply(this, args);
            }};
            const origWriteln = Document.prototype.writeln;
            Document.prototype.writeln = function(...args) {{
                for (const a of args) {{
                    recordTaint('document.writeln', a);
                }}
                return origWriteln.apply(this, args);
            }};
        }} catch (e) {{}}

        try {{
            const innerDesc = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
            if (innerDesc && innerDesc.set) {{
                const origSet = innerDesc.set;
                innerDesc.set = function(val) {{
                    recordTaint('Element.innerHTML', val);
                    return origSet.call(this, val);
                }};
                Object.defineProperty(Element.prototype, 'innerHTML', innerDesc);
            }}
        }} catch (e) {{}}

        try {{
            const outerDesc = Object.getOwnPropertyDescriptor(Element.prototype, 'outerHTML');
            if (outerDesc && outerDesc.set) {{
                const origSet = outerDesc.set;
                outerDesc.set = function(val) {{
                    recordTaint('Element.outerHTML', val);
                    return origSet.call(this, val);
                }};
                Object.defineProperty(Element.prototype, 'outerHTML', outerDesc);
            }}
        }} catch (e) {{}}
    }})();"""

    with contextlib.suppress(Exception):
        from playwright.sync_api import sync_playwright

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()

            # Pre-cargar script de instrumentación antes de que se ejecute el JavaScript de la página
            page.add_init_script(taint_harness)

            for test_url in test_urls:
                with contextlib.suppress(Exception):
                    page.goto(test_url, timeout=timeout, wait_until="domcontentloaded")
                    page.wait_for_timeout(1000)

                    # 1. Comprobar si los hooks de Taint interceptaron llamadas a sumideros
                    taint_events = page.evaluate("() => window.__omni_taint_findings || []")
                    if isinstance(taint_events, list) and taint_events:
                        for ev in taint_events:
                            sink = ev.get("sink", "DOM Sink")
                            stack = ev.get("stack", "")
                            stack_lines = [line.strip() for line in stack.split("\n") if line.strip()][:4]
                            stack_snippet = "\n".join(stack_lines) if stack_lines else "Traza en motor V8"

                            findings.append({
                                "vuln": f"DOM-Based XSS Confirmado vía Taint Analysis ({sink})",
                                "risk": "Alto",
                                "detail": f"Flujo peligroso hacia el sumidero '{sink}' interceptado dinámicamente en tiempo de ejecución.",
                                "confidence": "confirmed",
                                "type": "DOM-Based XSS (Dynamic Taint)",
                                "severity": "Alto",
                                "url": test_url,
                                "description": (
                                    f"El valor inyectado en la URL ({canary}) fue consumido directamente por '{sink}'.\n"
                                    f"Traza de pila JavaScript:\n{stack_snippet}"
                                ),
                                "evidence": f"Sink: {sink} | Stack:\n{stack_snippet}",
                                "solution": "Sanitiza las variables obtenidas de window.location antes de insertarlas en el árbol DOM con DOMPurify.sanitize()."
                            })
                        break

                    # 2. Comprobación de respaldo: reflexión en el árbol DOM
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
                            "confidence": "confirmed",
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
