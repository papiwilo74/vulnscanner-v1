from typing import Optional
from urllib.parse import urljoin, urlparse

import requests

# Archivos y carpetas sensibles comunes
COMMON_PATHS: list[str] = [
    # Variables de entorno y config
    ".env",
    ".env.local",
    ".env.production",
    ".env.development",
    "wp-config.php",
    "config.php.bak",
    "web.config",
    "docker-compose.yml",
    "package.json",
    # Control de versiones
    ".git/config",
    ".git/HEAD",
    ".git/index",
    # Bases de datos y respaldos
    "backup.sql",
    "db.sql",
    "dump.sql",
    "database.sql",
    "mysql.sql",
    # Archivos comprimidos y código
    "backup.zip",
    "project.zip",
    "html.zip",
    "www.zip",
    "site.zip",
    "project.tar.gz",
    "backup.tar.gz",
]

def _is_valid_exposed_file(path: str, response: requests.Response) -> bool:
    """Valida que el contenido corresponda realmente al tipo de archivo y no a un HTML genérico / SPA / 404."""
    content_type = response.headers.get("Content-Type", "").lower()
    text = response.text
    text_sample = text[:500].lower()

    # Si parece claramente una página web HTML completa
    is_html_content = (
        "text/html" in content_type
        or "<!doctype html" in text_sample
        or "<html" in text_sample
        or "<body" in text_sample
        or '<div id="root">' in text_sample
        or '<div id="app">' in text_sample
    )

    p_lower = path.lower()

    # 1. Variables de entorno (.env)
    if ".env" in p_lower:
        if is_html_content:
            return False
        lines = [line.strip() for line in text.splitlines() if line.strip() and not line.strip().startswith("#")]
        if not lines:
            return False
        return any("=" in line for line in lines[:10])

    # 2. Control de versiones (.git/config, .git/HEAD, .git/index)
    if ".git" in p_lower:
        if is_html_content:
            return False
        if p_lower.endswith("/config"):
            return "[core]" in text_sample or "[remote" in text_sample or "repositoryformatversion" in text_sample
        if p_lower.endswith("/head"):
            return "ref: refs/" in text_sample or len(text.strip()) == 40
        if p_lower.endswith("/index"):
            return bool(response.content.startswith(b"DIRC"))
        return True

    # 3. Bases de datos (.sql)
    if p_lower.endswith(".sql"):
        if is_html_content:
            return False
        sql_sigs = ["create table", "insert into", "-- mysql dump", "postgresql database dump", "sqlite format", "/*!40"]
        return any(sig in text_sample for sig in sql_sigs) or not is_html_content

    # 4. Archivos comprimidos (.zip, .tar.gz, etc.)
    if any(p_lower.endswith(ext) for ext in [".zip", ".tar.gz", ".gz"]):
        if is_html_content:
            return False
        if p_lower.endswith(".zip") and not response.content.startswith(b"PK\x03\x04"):
            return False
        return bool(not (p_lower.endswith(".gz") or p_lower.endswith(".tar.gz")) or response.content.startswith(b"\x1f\x8b"))

    # 5. Configuración JSON / YML
    if p_lower.endswith(".json"):
        if is_html_content:
            return False
        if p_lower == "package.json":
            return '"name"' in text or '"dependencies"' in text or '"version"' in text
        return bool(text.strip().startswith("{") or text.strip().startswith("["))

    if p_lower.endswith(".yml") or p_lower.endswith(".yaml"):
        if is_html_content:
            return False
        return ":" in text and not ("<" in text_sample and ">" in text_sample)

    # 6. PHP / Web config
    if p_lower.endswith(".php") or p_lower.endswith(".config"):
        if "<?php" in text or "configuration" in text_sample:
            return True
        if is_html_content:
            return False

    return not is_html_content


def check_exposed_files(base_url: str, session: Optional[requests.Session] = None) -> list[dict[str, str]]:
    """
    Realiza fuzzing sobre rutas sensibles comunes en el servidor web.
    Usa detección inteligente para evitar falsas respuestas 200 (como páginas de error 404 personalizadas).

    Args:
        base_url: URL base del sitio web.
        session: Instancia opcional de requests.Session.

    Returns:
        Lista de vulnerabilidades encontradas.
    """
    results: list[dict[str, str]] = []
    client = session if session is not None else requests

    # Obtener el origen / raíz del servidor para hacer la comprobación
    parsed = urlparse(base_url)
    root_url = f"{parsed.scheme}://{parsed.netloc}/"

    # Intentamos obtener un archivo inexistente para establecer una línea base de "No Encontrado" (404 falsa)
    fake_path = urljoin(root_url, "un_archivo_que_no_existe_seguro_12345.html")
    baseline_text = ""
    baseline_len = 0
    try:
        r_fake = client.get(fake_path, timeout=5)
        if r_fake.status_code == 200:
            baseline_text = r_fake.text
            baseline_len = len(r_fake.text)
    except requests.RequestException:
        pass

    for path in COMMON_PATHS:
        target_url = urljoin(root_url, path)
        try:
            r = client.get(target_url, timeout=5, allow_redirects=False)

            # Si responde 200 OK
            if r.status_code == 200:
                content_len = len(r.text)
                if content_len == 0:
                    continue

                # Si la longitud o el contenido es idéntico a la respuesta del archivo inexistente, es un falso positivo
                if baseline_len > 0 and abs(content_len - baseline_len) < 50 and r.text[:200] == baseline_text[:200]:
                    continue

                # Validación profunda del contenido para evitar falsos positivos con SPAs o 404 personalizados
                if not _is_valid_exposed_file(path, r):
                    continue

                results.append({
                    "vuln": f"Archivo Sensible Expuesto ({path})",
                    "risk": "Alto" if not path.endswith('.json') else "Medio",
                    "detail": f"Se puede acceder públicamente al archivo en: {target_url} (Código: 200, Tamaño: {content_len} bytes)."
                })
        except requests.RequestException:
            pass

    return results
