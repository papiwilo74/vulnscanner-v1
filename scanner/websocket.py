import re
from typing import Optional

import requests

WS_INSECURE_RE = re.compile(r"ws://[^\s\"'<>]+", re.IGNORECASE)
WSS_SECURE_RE = re.compile(r"wss://[^\s\"'<>]+", re.IGNORECASE)

WS_NO_AUTH_PATTERNS = [
    r'new\s+WebSocket\s*\(\s*["\'](ws://|wss://)["\']\s*\)',
    r'new\s+WebSocket\s*\(\s*[^)]*\)\s*(?!.*authenticate|.*token|.*auth|.*header)',
]

WS_PLAINTEXT_RE = re.compile(
    r'(?:password|token|secret|apikey|passwd)\s*=\s*["\'][^"\']+["\'].*(?:WebSocket|ws://)',
    re.IGNORECASE,
)


def check_websocket(url: str, html_content: str = "",
                    session: Optional[requests.Session] = None) -> list[dict[str, str]]:
    results: list[dict[str, str]] = []
    client = session if session is not None else requests

    if not html_content:
        try:
            r = client.get(url, timeout=8)
            html_content = r.text
        except requests.RequestException:
            return results

    ws_urls = WS_INSECURE_RE.findall(html_content)
    for ws_url in set(ws_urls):
        results.append({
            "vuln": "WebSocket Inseguro (ws:// sin TLS)",
            "risk": "Alto",
            "detail": f"Conexion WebSocket sin cifrar detectada: {ws_url}. Usar 'wss://' (WebSocket sobre TLS) para proteger datos en transito."
        })

    wss_urls = WSS_SECURE_RE.findall(html_content)
    if wss_urls:
        results.append({
            "vuln": "WebSocket Seguro Detectado (wss://)",
            "risk": "Bajo",
            "detail": f"Se detectaron {len(set(wss_urls))} conexion(es) WebSocket cifradas en la pagina."
        })

    inline_scripts = re.findall(
        r"<script[^>]*>(.*?)</script>",
        html_content, re.DOTALL | re.IGNORECASE,
    )
    combined_js = " ".join(s for s in inline_scripts if s.strip())

    for pat in WS_NO_AUTH_PATTERNS:
        matches = re.findall(pat, combined_js, re.IGNORECASE)
        if matches:
            results.append({
                "vuln": "WebSocket sin Autenticacion Aparente",
                "risk": "Medio",
                "detail": "Se crea una conexion WebSocket sin enviar token o credenciales de autenticacion visibles en el codigo. Verificar que el handshake incluya autenticacion via header o query param."
            })
            break

    if WS_PLAINTEXT_RE.search(html_content):
        results.append({
            "vuln": "Credenciales Cerca de WebSocket",
            "risk": "Medio",
            "detail": "Se detectaron credenciales o tokens en proximidad a codigo de WebSocket. Posible exposicion accidental de secretos en el cliente."
        })

    return results
