from typing import Optional

import requests


def check_cors(url: str, session: Optional[requests.Session] = None) -> list[dict[str, str]]:
    """
    Analiza si el servidor tiene una mala configuración de CORS.
    Envía una petición con una cabecera Origin maliciosa/externa y evalúa las respuestas.

    Args:
        url: La URL a probar.
        session: Instancia opcional de requests.Session para escaneo autenticado.

    Returns:
        Una lista de diccionarios con vulnerabilidades detectadas.
    """
    results: list[dict[str, str]] = []
    attacker_origin = "https://evil-attacker.com"
    client = session if session is not None else requests

    try:
        # Enviar petición con Origin malicioso
        headers = {
            'Origin': attacker_origin,
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        # Hacemos una petición OPTIONS y una GET para cubrir diferentes flujos
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
                        "detail": f"El servidor ({method}) acepta cualquier origen de forma dinámica y permite el envío de credenciales (Access-Control-Allow-Credentials: true) para el origen: {attacker_origin}."
                    })
                    break  # Evitar duplicar si se detecta en GET y OPTIONS
                else:
                    results.append({
                        "vuln": "CORS Permisivo (Origen Reflejado)",
                        "risk": "Bajo",
                        "detail": f"El servidor ({method}) refleja el origen de la petición en Access-Control-Allow-Origin: {ac_origin}, aunque no permite credenciales explícitamente."
                    })
                    break

            # Caso 2: Wildcard (*)
            elif ac_origin == '*':
                if ac_credentials and ac_credentials.lower() == 'true':
                    # Aunque la mayoría de los navegadores bloquean esto, se considera una configuración contradictoria/insegura.
                    results.append({
                        "vuln": "CORS Inseguro (Comodín con Credenciales)",
                        "risk": "Medio",
                        "detail": f"El servidor ({method}) expone Access-Control-Allow-Origin: * y Access-Control-Allow-Credentials: true, lo cual es una configuración contradictoria e insegura."
                    })
                    break
                else:
                    # CORS abierto, no necesariamente malo a menos que sea un recurso privado, pero vale la pena reportarlo a nivel Informativo/Bajo
                    results.append({
                        "vuln": "CORS Abierto (Comodín)",
                        "risk": "Bajo",
                        "detail": f"El servidor ({method}) expone Access-Control-Allow-Origin: * permitiendo peticiones desde cualquier origen sin credenciales."
                    })
                    break
    except Exception:
        # Silenciar excepciones de conexión general
        pass

    return results
