import requests
from urllib.parse import urljoin, urlparse

# Archivos y carpetas sensibles comunes
COMMON_PATHS = [
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

def check_exposed_files(base_url, session=None):
    """
    Realiza fuzzing sobre rutas sensibles comunes en el servidor web.
    Usa detección inteligente para evitar falsas respuestas 200 (como páginas de error 404 personalizadas).
    
    Args:
        base_url: URL base del sitio web.
        session: Instancia opcional de requests.Session.
        
    Returns:
        Lista de vulnerabilidades encontradas.
    """
    results = []
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
    except:
        pass

    for path in COMMON_PATHS:
        target_url = urljoin(root_url, path)
        try:
            r = client.get(target_url, timeout=5, allow_redirects=False)
            
            # Si responde 200 OK
            if r.status_code == 200:
                # Comprobar que no coincida exactamente con la página de error 404 simulada
                content_len = len(r.text)
                if content_len == 0:
                    continue
                    
                # Si la longitud o el contenido es idéntico a la respuesta del archivo inexistente, es un falso positivo
                if baseline_len > 0 and abs(content_len - baseline_len) < 50:
                    # Comprobación de firma en caso de que sea el mismo HTML
                    if r.text[:200] == baseline_text[:200]:
                        continue
                
                # Excluir respuestas que son obviamente páginas HTML (a menos que busquemos configuraciones específicas de PHP/web.config)
                # La mayoría de los archivos de base de datos o env no son HTML.
                is_html = 'text/html' in r.headers.get('Content-Type', '').lower()
                if is_html and not any(path.endswith(ext) for ext in ['.php', '.config', '.json', '.yml']):
                    # Si es HTML y el usuario esperaba un .sql o .env, probablemente sea un redireccionamiento camuflado
                    if any(path.endswith(ext) for ext in ['.sql', '.zip', '.gz', '.env']):
                        continue

                results.append({
                    "vuln": f"Archivo Sensible Expuesto ({path})",
                    "risk": "Alto" if not path.endswith('.json') else "Medio",
                    "detail": f"Se puede acceder públicamente al archivo en: {target_url} (Código: 200, Tamaño: {content_len} bytes)."
                })
        except:
            pass
            
    return results
