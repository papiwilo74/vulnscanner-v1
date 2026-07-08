import requests
import re
import os
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    '"><img src=x onerror=alert(1)>',
    "javascript:alert(1)",
]

def test_xss_payload(parsed, params, param, payload, baseline_text="", session=None):
    test_params = params.copy()
    test_params[param] = [payload]
    new_query = urlencode(test_params, doseq=True)
    test_url = urlunparse(parsed._replace(query=new_query))
    try:
        client = session if session is not None else requests
        r = client.get(test_url, timeout=5)
        if payload in r.text and payload not in baseline_text:
            return {
                "vuln": f"XSS reflejado en parámetro '{param}'",
                "risk": "Alto",
                "detail": f"Payload reflejado sin escapar: {payload}"
            }
    except:
        pass
    return None

def analyze_js_code(code, script_name):
    findings = []
    
    # 1. Patrones de concordancia directa
    direct_patterns = [
        (r"eval\s*\([^)]*(location\.|document\.URL|document\.referrer|window\.name)", "Uso de eval() con entrada directa del DOM"),
        (r"document\.write(?:ln)?\s*\([^)]*(location\.|document\.URL|document\.referrer|window\.name)", "Uso de document.write() con entrada directa del DOM"),
        (r"\.(?:inner|outer)HTML\s*=\s*[^;]*(location\.|document\.URL|document\.referrer|window\.name)", "Asignación a innerHTML/outerHTML con entrada directa del DOM"),
        (r"setTimeout\s*\([^,)]*(location\.|document\.URL|document\.referrer|window\.name)", "Uso de setTimeout() con entrada directa del DOM"),
        (r"\$\s*\([^)]*\)\.(?:html|append)\s*\([^)]*(location\.|document\.URL|document\.referrer|window\.name)", "Uso de .html()/.append() de jQuery con entrada directa del DOM")
    ]
    
    for pattern, desc in direct_patterns:
        match = re.search(pattern, code, re.IGNORECASE)
        if match:
            snippet = match.group(0)[:150].strip()
            findings.append({
                "vuln": "Posible XSS basado en DOM (Directo)",
                "risk": "Medio",
                "detail": f"{desc} en {script_name}. Código sospechoso: {snippet}"
            })
            return findings
            
    # 2. Simulación simple de análisis de flujo de variables (Taint Analysis)
    lines = code.split("\n")
    tainted_vars = set()
    
    # Expresión regular para detectar asignación de fuentes DOM a variables
    var_assign_pattern = re.compile(
        r"(?:var|let|const|window\.)\s*([a-zA-Z0-9_$]+)\s*=\s*.*(location\.search|location\.hash|location\.href|document\.URL|document\.referrer|window\.name|URLSearchParams)",
        re.IGNORECASE
    )
    
    for idx, line in enumerate(lines):
        m_assign = var_assign_pattern.search(line)
        if m_assign:
            var_name = m_assign.group(1)
            tainted_vars.add(var_name)
            
        for var in tainted_vars:
            sink_patterns = [
                (rf"eval\s*\([^)]*\b{re.escape(var)}\b", "Uso de eval() con variable contaminada"),
                (rf"document\.write(?:ln)?\s*\([^)]*\b{re.escape(var)}\b", "Uso de document.write() con variable contaminada"),
                (rf"\.(?:inner|outer)HTML\s*=\s*[^;]*\b{re.escape(var)}\b", "Asignación a innerHTML/outerHTML con variable contaminada"),
                (rf"setTimeout\s*\([^,)]*\b{re.escape(var)}\b", "Uso de setTimeout() con variable contaminada"),
                (rf"\$\s*\([^)]*\)\.(?:html|append)\s*\([^)]*\b{re.escape(var)}\b", "Uso de .html()/.append() de jQuery con variable contaminada"),
                (rf"location\.href\s*=\s*[^;]*\b{re.escape(var)}\b", "Redirección abierta/XSS asignando variable contaminada a location.href")
            ]
            
            for pat, desc in sink_patterns:
                match = re.search(pat, line, re.IGNORECASE)
                if match:
                    snippet = line[:150].strip()
                    findings.append({
                        "vuln": "Posible XSS basado en DOM (Flujo)",
                        "risk": "Medio",
                        "detail": f"{desc} ('{var}') en {script_name} (línea {idx+1}). Código sospechoso: {snippet}"
                    })
                    return findings
                    
    return findings

def check_dom_xss(url, html_content, session=None):
    results = []
    if not html_content:
        return results
        
    parsed_base = urlparse(url)
    base_domain = parsed_base.netloc
    
    # 1. Analizar scripts embebidos en el HTML
    inline_scripts = re.findall(r'<script\b[^>]*>(.*?)</script>', html_content, re.DOTALL | re.IGNORECASE)
    for idx, code in enumerate(inline_scripts):
        if code.strip():
            findings = analyze_js_code(code, f"Script Embebido #{idx+1}")
            results.extend(findings)
            
    # 2. Descargar y analizar archivos JavaScript locales
    src_scripts = re.findall(r'<script\b[^>]*\bsrc=["\'\s]([^"\'\s>]+)["\'\s]', html_content, re.IGNORECASE)
    
    js_urls = []
    for src in src_scripts:
        abs_url = urljoin(url, src)
        parsed_js = urlparse(abs_url)
        if parsed_js.netloc == base_domain:
            js_urls.append(abs_url)
            
    def fetch_and_analyze_js(js_url):
        try:
            client = session if session is not None else requests
            r = client.get(js_url, timeout=5)
            if r.status_code == 200:
                js_name = os.path.basename(urlparse(js_url).path) or js_url
                return analyze_js_code(r.text, f"Archivo JS: {js_name}")
        except:
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

def check_xss(url, html_content=None, session=None, passive=False):
    results = []

    # 1. Comprobación pasiva de DOM XSS si se provee HTML (análisis estático, sin payloads)
    if html_content:
        results.extend(check_dom_xss(url, html_content, session=session))

    # En modo pasivo, omitir las pruebas activas con payloads reflejados
    if passive:
        return results

    # 2. Comprobación de XSS Reflejado en parámetros URL
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
        except:
            baselines[param] = ""

    tasks = []
    for param in params:
        for payload in XSS_PAYLOADS:
            tasks.append((param, payload))

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(test_xss_payload, parsed, params, t[0], t[1], baselines.get(t[0], ""), session): t for t in tasks}
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