def check_https(url, response):
    results = []

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