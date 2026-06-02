from concurrent.futures import ThreadPoolExecutor, as_completed
import requests

COMMON_PATHS = [
    "/admin", "/login", "/backup", "/config",
    "/wp-admin", "/.env", "/api/v1", "/phpmyadmin",
    "/dashboard", "/test", "/old", "/debug",
    "/.env.local", "/.git/config", "/.git/HEAD",
    "/docker-compose.yml", "/package.json", "/requirements.txt",
    "/backup.zip", "/db.sql", "/database.sql", "/config.php",
    "/wp-config.php"
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

def check_single_directory(base_url, path):
    try:
        url = base_url.rstrip("/") + path
        r = requests.get(url, timeout=5, allow_redirects=False)

        if r.status_code == 200:
            # Si parece un SPA redirigiendo, ignorar
            if is_spa_fallback(r):
                return None

        if r.status_code in [200, 301, 302, 403]:
            return {
                "vuln": f"Archivo o directorio expuesto: {path}",
                "risk": "Medio" if r.status_code == 403 else "Alto",
                "detail": f"Responde con HTTP {r.status_code}"
            }
    except:
        pass
    return None

def check_directories(base_url):
    results = []
    
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(check_single_directory, base_url, path): path for path in COMMON_PATHS}
        for future in as_completed(futures):
            res = future.result()
            if res:
                results.append(res)

    return results