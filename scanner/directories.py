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

def check_single_directory(base_url, path, session=None, baseline_status=None, baseline_location="", baseline_body_sig=""):
    try:
        url = base_url.rstrip("/") + path
        client = session if session is not None else requests
        r = client.get(url, timeout=5, allow_redirects=False)
        status = r.status_code

        if baseline_status is not None and status == baseline_status:
            if status == 200:
                if r.text[:300].lower() == baseline_body_sig or is_spa_fallback(r):
                    return None
            elif status in (301, 302):
                if r.headers.get("Location", "") == baseline_location:
                    return None
            else:
                return None

        if status == 200 and is_spa_fallback(r):
            return None

        if status in [200, 301, 302, 403]:
            if status == 403:
                return {
                    "vuln": f"Ruta existente protegida (403): {path}",
                    "risk": "Bajo",
                    "detail": f"El recurso existe pero devuelve HTTP 403 (Forbidden). Solo revela la existencia del recurso."
                }
            if status in (301, 302):
                return {
                    "vuln": f"Directorio expuesto con redirección: {path}",
                    "risk": "Medio",
                    "detail": f"Responde con HTTP {status} -> {r.headers.get('Location', '?')}"
                }
            return {
                "vuln": f"Archivo o directorio expuesto: {path}",
                "risk": "Alto",
                "detail": f"Responde con HTTP {status}"
            }
    except:
        pass
    return None

def check_directories(base_url, session=None):
    results = []
    client = session if session is not None else requests

    baseline_status = None
    baseline_location = ""
    baseline_body_sig = ""
    try:
        r_fake = client.get(base_url.rstrip("/") + "/no_existe_12345_zzz.html", timeout=5, allow_redirects=False)
        baseline_status = r_fake.status_code
        baseline_location = r_fake.headers.get("Location", "")
        baseline_body_sig = r_fake.text[:300].lower()
    except:
        pass

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(check_single_directory, base_url, path, session, baseline_status, baseline_location, baseline_body_sig): path for path in COMMON_PATHS}
        for future in as_completed(futures):
            res = future.result()
            if res:
                results.append(res)

    return results