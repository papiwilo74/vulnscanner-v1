from typing import Optional
from urllib.parse import urlparse

import requests

STATIC_EXTENSIONS = (
    ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg",
    ".ico", ".woff", ".woff2", ".ttf", ".eot", ".map", ".webp", ".mp4"
)


def check_cors(url: str, session: Optional[requests.Session] = None) -> list[dict[str, str]]:
    """
    Analiza si el servidor tiene una mala configuración de CORS.
    Envía peticiones con cabeceras Origin externas y nulas para evaluar las respuestas.

    Args:
        url: La URL a probar.
        session: Instancia opcional de requests.Session para escaneo autenticado.

    Returns:
        Una lista de diccionarios con vulnerabilidades detectadas.
    """
    results: list[dict[str, str]] = []
    attacker_origin = "https://evil-attacker.com"
    client = session if session is not None else requests

    is_static = urlparse(url).path.lower().endswith(STATIC_EXTENSIONS)

    try:
        # 1. Enviar petición con Origin malicioso
        headers = {
            'Origin': attacker_origin,
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        for method in ['GET', 'OPTIONS']:
            try:
                if method == 'GET':
                    r = client.get(url, headers=headers, timeout=8)
                else:
                    r = client.options(url, headers=headers, timeout=8)
            except requests.RequestException:
                continue

            ac_origin = r.headers.get('Access-Control-Allow-Origin')
            ac_credentials = r.headers.get('Access-Control-Allow-Credentials')

            if not ac_origin:
                continue

            # Caso 1: Origen reflejado (refleja cualquier Origin malicioso enviado)
            if ac_origin == attacker_origin:
                if ac_credentials and ac_credentials.lower() == 'true':
                    results.append({
                        "vuln": "CORS Mal configurado (Origen Reflejado con Credenciales)",
                        "risk": "Alto",
                        "detail": f"El servidor ({method}) acepta cualquier origen de forma dinámica y permite el envío de credenciales (Access-Control-Allow-Credentials: true) para el origen: {attacker_origin}.",
                        "confidence": "confirmed",
                    })
                    break
                else:
                    results.append({
                        "vuln": "CORS Permisivo (Origen Reflejado)",
                        "risk": "Bajo",
                        "detail": f"El servidor ({method}) refleja el origen de la petición en Access-Control-Allow-Origin: {ac_origin}, aunque no permite credenciales explícitamente.",
                        "confidence": "confirmed",
                    })
                    break

            # Caso 2: Wildcard (*)
            elif ac_origin == '*':
                if ac_credentials and ac_credentials.lower() == 'true':
                    results.append({
                        "vuln": "CORS Inseguro (Comodín con Credenciales)",
                        "risk": "Medio",
                        "detail": f"El servidor ({method}) expone Access-Control-Allow-Origin: * y Access-Control-Allow-Credentials: true, lo cual es una configuración contradictoria e insegura.",
                        "confidence": "confirmed",
                    })
                    break
                elif not is_static:
                    # Omitir alerta en recursos estáticos públicos donde '*' es el estándar de CDNs
                    results.append({
                        "vuln": "CORS Abierto (Comodín)",
                        "risk": "Bajo",
                        "detail": f"El servidor ({method}) expone Access-Control-Allow-Origin: * permitiendo peticiones desde cualquier origen sin credenciales en endpoints dinámicos.",
                        "confidence": "confirmed",
                    })
                    break

        # 2. Enviar prueba con Origin: null (explotable mediante sandbox iframes)
        try:
            r_null = client.get(url, headers={'Origin': 'null'}, timeout=5)
            ac_origin_null = r_null.headers.get('Access-Control-Allow-Origin', '')
            ac_cred_null = r_null.headers.get('Access-Control-Allow-Credentials', '')
            if ac_origin_null.lower() == 'null' and ac_cred_null.lower() == 'true':
                results.append({
                    "vuln": "CORS Inseguro (Origen 'null' Confiado con Credenciales)",
                    "risk": "Alto",
                    "detail": "El servidor confía en el origen 'null' y permite credenciales. Permite a atacantes robar datos mediante iframes sandboxed locales o redirecciones.",
                    "confidence": "confirmed",
                })
        except requests.RequestException:
            pass

    except requests.RequestException:
        pass

    return results
