import re
from typing import Optional
from urllib.parse import urljoin, urlparse

import requests

PROTO_POLLUTION_PATTERNS = [
    r"\.__proto__\s*\[",
    r"\b__proto__\s*:\s*",
    r"\.constructor\.prototype",
    r"constructor\.prototype\s*:\s*",
    r"Object\.assign\s*\(.*__proto__",
    r"\.hasOwnProperty\s*\(.*__proto__",
    r"merge\s*\(.*__proto__",
    r"extend\s*\(.*__proto__",
    r"deepMerge\s*\(.*__proto__",
    r"lodash\.merge\s*\([^)]*true",
    r"jQuery\.extend\s*\([^)]*true",
    r"Object\.create\s*\(\s*null\s*\)",
]

UNSAFE_MERGE_PATTERNS = [
    r"function\s+merge\s*\([^)]*\)\s*{",
    r"function\s+extend\s*\([^)]*\)\s*{",
    r"function\s+deep\s*Merge\s*\([^)]*\)\s*{",
    r"function\s+deep\s*Extend\s*\([^)]*\)\s*{",
    r"Object\.keys\s*\([^)]*\)\.forEach",
]

COOKIE_PROTO_RE = re.compile(
    r"document\.cookie\s*.*__proto__|__proto__\s*.*document\.cookie",
    re.IGNORECASE,
)


def _analyze_js_for_prototype_pollution(js_code: str, source: str) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []

    for pat in PROTO_POLLUTION_PATTERNS:
        matches = re.findall(pat, js_code, re.IGNORECASE)
        if matches:
            findings.append({
                "vuln": "Posible Prototype Pollution (JS)",
                "risk": "Medio",
                "detail": f"Acceso/manipulacion de __proto__ o prototype detectado en '{source}': {matches[0][:80]}"
            })
            break

    for pat in UNSAFE_MERGE_PATTERNS:
        matches = re.findall(pat, js_code, re.IGNORECASE)
        if matches and "__proto__" not in js_code.lower():
            findings.append({
                "vuln": "Funcion Merge/Extend Potencialmente Insegura",
                "risk": "Bajo",
                "detail": f"Funcion de merge sin proteccion contra prototype pollution detectada en '{source}'. Implementar sanitizacion de claves '__proto__' y 'constructor.prototype'."
            })
            break

    if COOKIE_PROTO_RE.search(js_code):
        findings.append({
            "vuln": "Manipulacion de Prototipo via Cookies",
            "risk": "Medio",
            "detail": f"Manipulacion de prototype pollution detectada via cookies en '{source}'. Esto puede permitir la contaminacion del prototipo via el header Cookie."
        })

    return findings


def check_prototype_pollution(url: str, html_content: str = "",
                               session: Optional[requests.Session] = None) -> list[dict[str, str]]:
    results: list[dict[str, str]] = []
    client = session if session is not None else requests

    if not html_content:
        try:
            r = client.get(url, timeout=8)
            html_content = r.text
        except requests.RequestException:
            return results

    inline_scripts = re.findall(
        r"<script[^>]*>(.*?)</script>",
        html_content, re.DOTALL | re.IGNORECASE,
    )
    for i, script in enumerate(inline_scripts):
        if script.strip():
            results.extend(_analyze_js_for_prototype_pollution(script, f"script inline #{i+1}"))

    script_srcs = re.findall(
        r'<script\s+[^>]*src=["\']([^"\']+)["\']',
        html_content, re.IGNORECASE,
    )

    parsed_base = urlparse(url)
    base_domain = parsed_base.netloc
    scanned = set()

    for src in script_srcs[:10]:
        abs_src = urljoin(url, src)
        parsed_src = urlparse(abs_src)
        if parsed_src.netloc == base_domain and abs_src not in scanned:
            scanned.add(abs_src)
            try:
                r = client.get(abs_src, timeout=5)
                if r.status_code == 200:
                    results.extend(_analyze_js_for_prototype_pollution(r.text, f"JS: {src}"))
            except requests.RequestException:
                pass

    return results
