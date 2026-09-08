

import requests


def check_https(url: str, response: requests.Response) -> list[dict[str, str]]:
    results: list[dict[str, str]] = []

    if not url.startswith("https://"):
        results.append({
            "vuln": "El sitio no usa HTTPS",
            "risk": "Alto",
            "detail": "El tráfico viaja sin cifrar"
        })

    if url.startswith("http://") and response.url.startswith("https://"):
        results.append({
            "vuln": "Redirige a HTTPS pero URL inicial es HTTP",
            "risk": "Medio",
            "detail": "Hay una ventana de ataque en el primer request"
        })

    return results
