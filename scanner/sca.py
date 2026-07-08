import re
import requests
from urllib.parse import urljoin, urlparse

# Base de datos local de versiones vulnerables de librerías comunes de frontend.
# Formato: { "nombre_libreria": [ (version_maxima_vulnerable, "CVE/descripcion", "riesgo") ] }
VULNERABLE_LIBS = {
    "jquery": [
        ("1.12.4", "Múltiples CVEs de XSS (CVE-2020-11022, CVE-2020-11023)", "Medio"),
        ("2.2.4", "Vulnerabilidades de XSS en métodos .html() y .append() (CVE-2020-11022)", "Medio"),
        ("3.4.1", "Prototype Pollution (CVE-2019-11358)", "Medio"),
    ],
    "bootstrap": [
        ("3.4.1", "Cross-Site Scripting via data-template attribute (CVE-2019-8331)", "Bajo"),
        ("4.3.1", "XSS vía tooltip/popover data-template (CVE-2019-8331)", "Bajo"),
    ],
    "lodash": [
        ("4.17.20", "Prototype Pollution (CVE-2020-8203, CVE-2021-23337)", "Alto"),
        ("4.17.15", "Prototype Pollution y Command Injection (CVE-2019-10744)", "Alto"),
    ],
    "angular": [
        ("1.8.2", "Bypass de Sandbox que permite ejecución de código arbitrario (GHSA)", "Medio"),
    ],
    "vue": [
        ("2.6.12", "Vulnerabilidades de tipo ReDoS en versiones antiguas (GHSA)", "Bajo"),
    ],
    "moment": [
        ("2.29.1", "Path Traversal (CVE-2022-24785), ReDoS (CVE-2022-31129)", "Medio"),
    ],
    "handlebars": [
        ("4.7.6", "Prototype Pollution (CVE-2021-23369, CVE-2021-23383)", "Alto"),
    ],
}

# Patrones para detectar librerías y versiones en atributos src o contenido JS
LIB_PATTERNS = {
    "jquery": r"jquery[.-]?v?(\d+\.\d+[\.\d]*)(\.min)?\.js",
    "bootstrap": r"bootstrap[.-]?v?(\d+\.\d+[\.\d]*)(\.min)?\.js",
    "lodash": r"lodash[.-]?v?(\d+\.\d+[\.\d]*)(\.min)?\.js",
    "angular": r"angular[.-]?v?(\d+\.\d+[\.\d]*)(\.min)?\.js",
    "vue": r"vue[.-]?v?(\d+\.\d+[\.\d]*)(\.min)?\.js",
    "moment": r"moment[.-]?v?(\d+\.\d+[\.\d]*)(\.min)?\.js",
    "handlebars": r"handlebars[.-]?v?(\d+\.\d+[\.\d]*)(\.min)?\.js",
}

# Patrones de versión dentro del contenido del archivo JS
CONTENT_VERSION_PATTERNS = {
    "jquery": r"jQuery\s+v?(\d+\.\d+[\.\d]*)",
    "lodash": r"lodash\s+(\d+\.\d+[\.\d]*)",
    "moment": r"moment\.js\s+v?(\d+\.\d+[\.\d]*)",
    "handlebars": r"Handlebars\s+v?(\d+\.\d+[\.\d]*)",
}

def parse_version(version_str):
    """Convierte una cadena de versión a una tupla de enteros para comparación."""
    try:
        return tuple(int(x) for x in version_str.split('.'))
    except ValueError:
        return (0,)

def is_version_vulnerable(detected_version, max_vulnerable_version):
    """Comprueba si la versión detectada es <= la versión máxima vulnerable."""
    return parse_version(detected_version) <= parse_version(max_vulnerable_version)

def check_library_vulnerabilities(lib_name, detected_version):
    """Devuelve hallazgos si la versión detectada es vulnerable."""
    findings = []
    lib_key = lib_name.lower()
    if lib_key not in VULNERABLE_LIBS:
        return findings

    for (max_vuln_version, description, risk) in VULNERABLE_LIBS[lib_key]:
        if is_version_vulnerable(detected_version, max_vuln_version):
            findings.append({
                "vuln": f"Componente Vulnerable Detectado ({lib_name} v{detected_version})",
                "risk": risk,
                "detail": f"Se detectó {lib_name} versión {detected_version}. "
                          f"Esta versión es vulnerable a: {description}. "
                          f"Se recomienda actualizar a la última versión estable."
            })
            break  # Reportar solo el hallazgo más crítico por librería
    return findings

def check_sca(url, html_content=None, session=None):
    """
    Analiza el HTML y los archivos JS de la página para detectar librerías
    de terceros con versiones vulnerables conocidas.
    
    Args:
        url: URL de la página analizada.
        html_content: Contenido HTML de la página.
        session: Instancia opcional de requests.Session.
        
    Returns:
        Lista de vulnerabilidades encontradas en componentes de software.
    """
    results = []
    client = session if session is not None else requests

    if not html_content:
        try:
            r = client.get(url, timeout=8)
            html_content = r.text
        except Exception:
            return results

    detected_libs = {}  # { "nombre": "version" }

    # 1. Detectar librerías por la ruta de los archivos script src
    script_sources = re.findall(
        r'<script\s+[^>]*src=["\']([^"\']+)["\']',
        html_content, re.IGNORECASE
    )

    for src in script_sources:
        src_lower = src.lower()
        for lib_name, pattern in LIB_PATTERNS.items():
            match = re.search(pattern, src_lower)
            if match:
                version = match.group(1)
                if lib_name not in detected_libs:
                    detected_libs[lib_name] = version

    # 2. Detectar versiones analizando el contenido interno de los scripts
    parsed_base = urlparse(url)
    base_domain = parsed_base.netloc
    scanned = set()

    for src in script_sources:
        abs_src = urljoin(url, src)
        parsed_src = urlparse(abs_src)

        # Solo analizar scripts del mismo dominio
        if parsed_src.netloc == base_domain and abs_src not in scanned:
            scanned.add(abs_src)
            try:
                js_res = client.get(abs_src, timeout=5)
                if js_res.status_code == 200:
                    js_text = js_res.text
                    for lib_name, content_pattern in CONTENT_VERSION_PATTERNS.items():
                        if lib_name not in detected_libs:
                            m = re.search(content_pattern, js_text, re.IGNORECASE)
                            if m:
                                detected_libs[lib_name] = m.group(1)
            except Exception:
                pass

    # 3. Evaluar versiones detectadas contra la base de datos de vulnerabilidades
    for lib_name, version in detected_libs.items():
        findings = check_library_vulnerabilities(lib_name, version)
        results.extend(findings)

    return results
