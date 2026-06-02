import requests

COMMON_PATHS = [
    "/admin", "/login", "/backup", "/config",
    "/wp-admin", "/.env", "/api/v1", "/phpmyadmin",
    "/dashboard", "/test", "/old", "/debug"
]

# Si la respuesta contiene esto, probablemente es un SPA redirigiendo al index
SPA_SIGNATURES = [
    "<!doctype html>",
    "<div id=\"root\">",
    "<div id=\"app\">",
    "window.__NUXT__",
    "window.__NEXT_DATA__",
]

def is_spa_fallback(response):
    """Detecta si la respuesta es el index.html de un SPA (React, Vue, Next...)"""
    body = response.text.lower()
    return any(sig.lower() in body for sig in SPA_SIGNATURES)

def check_directories(base_url):
    results = []

    for path in COMMON_PATHS:
        try:
            url = base_url.rstrip("/") + path
            r = requests.get(url, timeout=5, allow_redirects=False)

            if r.status_code == 200:
                # Si parece un SPA redirigiendo, ignorar
                if is_spa_fallback(r):
                    continue

            if r.status_code in [200, 301, 302, 403]:
                results.append({
                    "vuln": f"Directorio expuesto: {path}",
                    "risk": "Medio" if r.status_code == 403 else "Alto",
                    "detail": f"Responde con HTTP {r.status_code}"
                })
        except:
            pass

    return results