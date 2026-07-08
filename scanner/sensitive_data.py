import re
import requests
from urllib.parse import urljoin, urlparse

# Expresiones regulares para detectar datos sensibles
SENSITIVE_PATTERNS = {
    "Clave de API de AWS": r"AKIA[0-9A-Z]{16}",
    "Clave de API de Google/Firebase": r"AIza[0-9A-Za-z\-_]{35}",
    "Clave Privada de Stripe": r"sk_live_[0-9a-zA-Z]{24}",
    "Token JWT": r"\beyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]*",
    "Cadena de Conexión de Base de Datos": r"(mongodb(?:\+srv)?|postgres|mysql|sqlite|oracle):\/\/[^\s'\"@]+:[^\s'\"@]+@[^\s'\"]+",
    "Clave Secreta Genérica en Código": r"(?:key|api_key|token|secret|password|aws_secret|db_password|private_key)\s*[:=]\s*['\"]([a-zA-Z0-9_\-\.\/]{16,})['\"]"
}

PLACEHOLDER_VALUES = {
    "your-key-here", "your_api_key", "your-api-key", "yourkey", "changeme",
    "placeholder", "example", "test", "demo", "xxx", "xxxx", "abcdef",
    "your_secret_key", "your-secret-key", "your-password", "yourpassword",
    "string", "none", "null", "true", "false", "undefined", "lorem",
    "your-token-here", "your_access_key", "replace_me", "replaceme",
    "your_value_here", "your_value", "yourvalue", "dummy", "sample",
}

def _is_placeholder(val):
    lv = val.lower()
    if lv in PLACEHOLDER_VALUES:
        return True
    if any(p in lv for p in ["your", "placeholder", "example", "changeme", "xxx", "replace", "dummy", "sample", "default"]):
        return True
    return False

def scan_text_for_sensitive_data(text, source_name):
    """
    Escanea un texto (HTML, JS, comentarios) en busca de patrones sensibles.
    """
    findings = []
    
    # 1. Comprobar patrones definidos
    for name, pattern in SENSITIVE_PATTERNS.items():
        matches = re.findall(pattern, text, re.IGNORECASE)
        if matches:
            # Eliminar duplicados para no inundar el reporte
            unique_matches = list(set(matches))
            # Si el patrón tiene un grupo de captura (ej. Clave Secreta Genérica), tomamos el valor capturado
            display_matches = [m[0] if isinstance(m, tuple) else m for m in unique_matches]
            display_matches = [m for m in display_matches if not _is_placeholder(m)]
            if not display_matches:
                continue
            # Ocultar la mayor parte del secreto por seguridad
            censored_matches = [f"{m[:6]}...{m[-4:]}" if len(m) > 10 else "..." for m in display_matches]
            
            findings.append({
                "vuln": f"Exposición de Datos Sensibles ({name})",
                "risk": "Alto",
                "detail": f"Se detectó un patrón coincidente con '{name}' en '{source_name}'. Valores truncados: {', '.join(censored_matches)}"
            })
            
    # 2. Comprobar comentarios sospechosos/sensibles (ej. TODOs con credenciales)
    comments = re.findall(r"<!--(.*?)-->", text, re.DOTALL)
    for comment in comments:
        comment_lower = comment.lower()
        if any(keyword in comment_lower for keyword in ["password", "clave", "usuario", "creds", "token", "secret", "contraseña"]):
            findings.append({
                "vuln": "Comentario Informativo/Sensible Expuesto",
                "risk": "Bajo",
                "detail": f"Se encontró un comentario HTML potencialmente sensible o pendiente de desarrollo en '{source_name}': {comment.strip()[:100]}..."
            })
            
    # 3. Comprobar malas prácticas de funciones o entornos de prueba (Análisis Estático)
    # Buscar llamadas a eval() o document.write()
    if source_name.endswith('.js') or "Archivo JS" in source_name:
        eval_matches = re.findall(r"\beval\s*\([^\)]*\)", text)
        if eval_matches:
            findings.append({
                "vuln": "Uso de Funciones Inseguras en JavaScript (eval)",
                "risk": "Bajo",
                "detail": f"Se detectó el uso de la función 'eval()' en '{source_name}', lo cual puede facilitar la ejecución de inyecciones de script de forma insegura."
            })
            
        docwrite_matches = re.findall(r"\bdocument\.write\s*\(", text)
        if docwrite_matches:
            findings.append({
                "vuln": "Uso de Funciones Inseguras en JavaScript (document.write)",
                "risk": "Bajo",
                "detail": f"Se detectó la escritura directa con 'document.write()' en '{source_name}', considerada una práctica propensa a inyecciones DOM-XSS."
            })
            
        # Buscar referencias a entornos locales o de desarrollo expuestos
        dev_envs = re.findall(r"\b(localhost|127\.0\.0\.1|test-env|staging-api|dev-db)\b", text, re.IGNORECASE)
        if dev_envs:
            unique_envs = list(set(dev_envs))
            findings.append({
                "vuln": "Referencia a Entorno de Desarrollo en Código de Producción",
                "risk": "Bajo",
                "detail": f"Se detectaron referencias a servidores de prueba/desarrollo en '{source_name}': {', '.join(unique_envs)}."
            })
            
    return findings

def check_sensitive_data(url, html_content=None, session=None):
    """
    Analiza la página e identifica si expone datos sensibles.
    También intenta descargar e inspeccionar archivos JS locales/internos enlazados.
    
    Args:
        url: La URL de la página.
        html_content: El contenido HTML de la página (si ya está disponible).
        session: Instancia opcional de requests.Session.
        
    Returns:
        Una lista de diccionarios con vulnerabilidades detectadas.
    """
    results = []
    client = session if session is not None else requests
    
    # Si no se nos da el HTML, lo descargamos
    if not html_content:
        try:
            r = client.get(url, timeout=8)
            html_content = r.text
        except:
            return results

    # 1. Escanear el HTML principal
    results.extend(scan_text_for_sensitive_data(html_content, "HTML de la página principal"))
    
    # 2. Extraer scripts JS locales/del mismo host y escanearlos
    parsed_base = urlparse(url)
    base_domain = parsed_base.netloc
    
    # Buscar etiquetas <script src="...">
    script_sources = re.findall(r'<script\s+[^>]*src=["\']([^"\']+)["\']', html_content, re.IGNORECASE)
    
    scanned_scripts = set()
    for src in script_sources:
        # Resolver ruta absoluta
        abs_src = urljoin(url, src)
        parsed_src = urlparse(abs_src)
        
        # Solo escanear si pertenece al mismo dominio/host para evitar peticiones a terceros (ej. Google Analytics, CDN de Bootstrap)
        if parsed_src.netloc == base_domain and abs_src not in scanned_scripts:
            scanned_scripts.add(abs_src)
            try:
                # Descargar script JS
                js_res = client.get(abs_src, timeout=5)
                if js_res.status_code == 200:
                    results.extend(scan_text_for_sensitive_data(js_res.text, f"Archivo JS: {src}"))
            except:
                pass
                
    return results
