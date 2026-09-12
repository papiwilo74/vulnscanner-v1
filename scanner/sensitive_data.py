import base64
import json
import re
from typing import Optional
from urllib.parse import urljoin, urlparse

import requests

# Expresiones regulares para detectar datos sensibles
SENSITIVE_PATTERNS: dict[str, str] = {
    "Clave de API de AWS": r"AKIA[0-9A-Z]{16}",
    "Clave Privada de Stripe": r"sk_live_[0-9a-zA-Z]{24}",
    "Token JWT": r"\beyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]*",
    "Cadena de Conexion de Base de Datos": r"(mongodb(?:\+srv)?|postgres|mysql|sqlite|oracle):\/\/[^\s'\"@]+:[^\s'\"@]+@[^\s'\"]+",
}

PLACEHOLDER_VALUES = {
    "your-key-here", "your_api_key", "your-api-key", "yourkey", "changeme",
    "placeholder", "example", "test", "demo", "xxx", "xxxx", "abcdef",
    "your_secret_key", "your-secret-key", "your-password", "yourpassword",
    "string", "none", "null", "true", "false", "undefined", "lorem",
    "your-token-here", "your_access_key", "replace_me", "replaceme",
    "your_value_here", "your_value", "yourvalue", "dummy", "sample",
}

def _is_placeholder(val: str) -> bool:
    lv = val.lower()
    if lv in PLACEHOLDER_VALUES:
        return True
    return bool(any(p in lv for p in ["your", "placeholder", "example", "changeme", "xxx", "replace", "dummy", "sample", "default"]))

def _is_valid_jwt(token_str: str) -> bool:
    """Verifica que un token candidato sea un JWT bien formado y no un hash base64 arbitrario."""
    parts = token_str.split(".")
    if len(parts) < 2:
        return False
    header_b64 = parts[0]
    rem = len(header_b64) % 4
    if rem > 0:
        header_b64 += "=" * (4 - rem)
    try:
        header_bytes = base64.urlsafe_b64decode(header_b64.encode("ascii"))
        header_obj = json.loads(header_bytes.decode("utf-8", errors="ignore"))
        if isinstance(header_obj, dict) and ("alg" in header_obj or header_obj.get("typ") == "JWT"):
            return True
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
        pass
    return False

def scan_text_for_sensitive_data(text: str, source_name: str, target_url: str = "") -> list[dict[str, str]]:
    """
    Escanea un texto (HTML, JS, comentarios) en busca de patrones sensibles.
    """
    findings: list[dict[str, str]] = []

    # 1. Comprobar patrones definidos
    for name, pattern in SENSITIVE_PATTERNS.items():
        matches = re.findall(pattern, text, re.IGNORECASE)
        if matches:
            # Eliminar duplicados para no inundar el reporte
            unique_matches = list(set(matches))
            # Si el patrón tiene un grupo de captura (ej. Clave Secreta Genérica), tomamos el valor capturado
            display_matches = [m[0] if isinstance(m, tuple) else m for m in unique_matches]
            display_matches = [m for m in display_matches if not _is_placeholder(m)]
            if name == "Token JWT":
                display_matches = [m for m in display_matches if _is_valid_jwt(m)]
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
        target_host = urlparse(target_url).hostname or ""
        is_local_target = target_host.lower() in ("localhost", "127.0.0.1", "::1")
        dev_envs = re.findall(r"\b(localhost|127\.0\.0\.1|test-env|staging-api|dev-db)\b", text, re.IGNORECASE)
        if dev_envs:
            unique_envs = {env.lower() for env in dev_envs}
            if is_local_target:
                unique_envs.discard("localhost")
                unique_envs.discard("127.0.0.1")
            if unique_envs:
                findings.append({
                    "vuln": "Referencia a Entorno de Desarrollo en Código de Producción",
                    "risk": "Bajo",
                    "detail": f"Se detectaron referencias a servidores de prueba/desarrollo en '{source_name}': {', '.join(sorted(unique_envs))}."
                })

    return findings

def check_sensitive_data(url: str, html_content: Optional[str] = None, session: Optional[requests.Session] = None) -> list[dict[str, str]]:
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
    results: list[dict[str, str]] = []
    client = session if session is not None else requests

    # Si no se nos da el HTML, lo descargamos
    if not html_content:
        try:
            r = client.get(url, timeout=8)
            html_content = r.text
        except requests.RequestException:
            return results

    # 1. Escanear el HTML principal
    results.extend(scan_text_for_sensitive_data(html_content, "HTML de la página principal", target_url=url))

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
                    results.extend(scan_text_for_sensitive_data(js_res.text, f"Archivo JS: {src}", target_url=url))
            except requests.RequestException:
                pass

    return results
