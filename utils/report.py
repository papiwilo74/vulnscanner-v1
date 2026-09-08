import json
import logging
import os
import re
import time
from typing import Any, Optional
from urllib.parse import urlparse

from colorama import Fore, init

from scanner.models import VULN_STANDARDS_DB
from utils.pdf_report import generate_pdf_report
from utils.sarif import generate_sarif_v210

init(autoreset=True)

_logger = logging.getLogger("VulnScanner.Report")

COLORS = {
    "Alto":  Fore.RED,
    "Medio": Fore.YELLOW,
    "Bajo":  Fore.CYAN,
}

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reporte VulnScanner - {domain}</title>
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
    <style>
        :root {{
            --bg-body: #090d16;
            --bg-card: #111827;
            --bg-card-header: #1a2234;
            --text-main: #f3f4f6;
            --text-muted: #9ca3af;
            --border: #1f2937;
            --accent: #6366f1;
            --accent-hover: #4f46e5;

            --high-color: #ef4444;
            --high-bg: rgba(239, 68, 68, 0.12);
            --medium-color: #f59e0b;
            --medium-bg: rgba(245, 158, 11, 0.12);
            --low-color: #06b6d4;
            --low-bg: rgba(6, 182, 212, 0.12);
            --safe-color: #10b981;
            --safe-bg: rgba(16, 185, 129, 0.12);

            --shadow-sm: 0 1px 2px 0 rgba(0, 0, 0, 0.3);
            --shadow-md: 0 4px 6px -1px rgba(0, 0, 0, 0.3), 0 2px 4px -1px rgba(0, 0, 0, 0.2);
            --shadow-lg: 0 10px 15px -3px rgba(0, 0, 0, 0.4), 0 4px 6px -2px rgba(0, 0, 0, 0.3);
            --font: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            --font-mono: 'JetBrains Mono', monospace;
        }}

        [data-theme="light"] {{
            --bg-body: #f8fafc;
            --bg-card: #ffffff;
            --bg-card-header: #f1f5f9;
            --text-main: #0f172a;
            --text-muted: #64748b;
            --border: #e2e8f0;
            --accent: #4f46e5;
            --accent-hover: #4338ca;
            --shadow-sm: 0 1px 2px 0 rgba(0, 0, 0, 0.05);
            --shadow-md: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
            --shadow-lg: 0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -2px rgba(0, 0, 0, 0.05);
        }}

        * {{
            box-sizing: border-box;
            margin: 0;
            padding: 0;
            transition: background-color 0.2s ease, border-color 0.2s ease, color 0.2s ease;
        }}

        body {{
            background-color: var(--bg-body);
            color: var(--text-main);
            font-family: var(--font);
            line-height: 1.5;
            padding-bottom: 80px;
        }}

        header {{
            position: sticky;
            top: 0;
            z-index: 100;
            background-color: rgba(9, 13, 22, 0.85);
            backdrop-filter: blur(12px);
            -webkit-backdrop-filter: blur(12px);
            border-bottom: 1px solid var(--border);
            padding: 16px 24px;
        }}

        [data-theme="light"] header {{
            background-color: rgba(248, 250, 252, 0.85);
        }}

        .nav-container {{
            max-width: 1200px;
            margin: 0 auto;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}

        .brand-group {{
            display: flex;
            align-items: center;
            gap: 12px;
        }}

        .brand-logo {{
            width: 38px;
            height: 38px;
            border-radius: 10px;
            background: linear-gradient(135deg, #6366f1, #a855f7);
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 800;
            color: white;
            font-size: 18px;
            box-shadow: 0 4px 12px rgba(99, 102, 241, 0.35);
        }}

        .brand-name {{
            font-size: 20px;
            font-weight: 800;
            letter-spacing: -0.5px;
            background: linear-gradient(135deg, #818cf8, #c084fc);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }}

        .header-actions {{
            display: flex;
            align-items: center;
            gap: 12px;
        }}

        .theme-toggle {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            color: var(--text-main);
            padding: 8px 14px;
            border-radius: 8px;
            cursor: pointer;
            font-size: 13px;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 8px;
        }}

        .theme-toggle:hover {{
            background: var(--border);
        }}

        .main-container {{
            max-width: 1200px;
            margin: 32px auto 0 auto;
            padding: 0 24px;
        }}

        .hero-panel {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 24px 32px;
            box-shadow: var(--shadow-md);
            margin-bottom: 32px;
            display: flex;
            flex-wrap: wrap;
            justify-content: space-between;
            align-items: center;
            gap: 20px;
        }}

        .target-info h1 {{
            font-size: 24px;
            font-weight: 700;
            margin-bottom: 6px;
            word-break: break-all;
        }}

        .target-meta {{
            display: flex;
            flex-wrap: wrap;
            gap: 16px;
            font-size: 13px;
            color: var(--text-muted);
        }}

        .target-meta span {{
            display: flex;
            align-items: center;
            gap: 6px;
        }}

        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 16px;
            margin-bottom: 32px;
        }}

        .stat-card {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 14px;
            padding: 20px;
            box-shadow: var(--shadow-sm);
            display: flex;
            align-items: center;
            justify-content: space-between;
        }}

        .stat-val {{
            font-size: 32px;
            font-weight: 800;
            line-height: 1;
        }}

        .stat-label {{
            font-size: 13px;
            font-weight: 600;
            color: var(--text-muted);
            margin-top: 4px;
        }}

        .stat-icon {{
            width: 44px;
            height: 44px;
            border-radius: 12px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 18px;
            font-weight: 700;
        }}

        .stat-high .stat-val {{ color: var(--high-color); }}
        .stat-high .stat-icon {{ background: var(--high-bg); color: var(--high-color); }}

        .stat-medium .stat-val {{ color: var(--medium-color); }}
        .stat-medium .stat-icon {{ background: var(--medium-bg); color: var(--medium-color); }}

        .stat-low .stat-val {{ color: var(--low-color); }}
        .stat-low .stat-icon {{ background: var(--low-bg); color: var(--low-color); }}

        .stat-total .stat-val {{ color: var(--accent); }}
        .stat-total .stat-icon {{ background: rgba(99, 102, 241, 0.12); color: var(--accent); }}

        .filter-section {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
            flex-wrap: wrap;
            gap: 12px;
        }}

        .filter-title {{
            font-size: 18px;
            font-weight: 700;
        }}

        .chips {{
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
        }}

        .chip {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            color: var(--text-muted);
            padding: 6px 14px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
            cursor: pointer;
        }}

        .chip:hover {{
            background: var(--border);
            color: var(--text-main);
        }}

        .chip.active-all {{ background: var(--accent); color: white; border-color: var(--accent); }}
        .chip.active-alto {{ background: var(--high-color); color: white; border-color: var(--high-color); }}
        .chip.active-medio {{ background: var(--medium-color); color: white; border-color: var(--medium-color); }}
        .chip.active-bajo {{ background: var(--low-color); color: white; border-color: var(--low-color); }}

        .findings-list {{
            display: flex;
            flex-direction: column;
            gap: 16px;
        }}

        .finding-card {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 14px;
            overflow: hidden;
            box-shadow: var(--shadow-sm);
        }}

        .finding-header {{
            padding: 18px 24px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            cursor: pointer;
            user-select: none;
            background: var(--bg-card);
        }}

        .finding-header:hover {{
            background: var(--bg-card-header);
        }}

        .finding-title-group {{
            display: flex;
            align-items: center;
            gap: 12px;
            flex-wrap: wrap;
        }}

        .finding-badge {{
            font-size: 11px;
            font-weight: 800;
            text-transform: uppercase;
            padding: 4px 10px;
            border-radius: 6px;
            letter-spacing: 0.5px;
        }}

        .badge-alto, .badge-high, .badge-critical {{ background: var(--high-bg); color: var(--high-color); border: 1px solid var(--high-color); }}
        .badge-medio, .badge-medium {{ background: var(--medium-bg); color: var(--medium-color); border: 1px solid var(--medium-color); }}
        .badge-bajo, .badge-low, .badge-info {{ background: var(--low-bg); color: var(--low-color); border: 1px solid var(--low-color); }}

        .cvss-badge {{
            background: rgba(99, 102, 241, 0.15);
            color: #a5b4fc;
            border: 1px solid rgba(99, 102, 241, 0.4);
            font-size: 11px;
            font-weight: 700;
            padding: 3px 8px;
            border-radius: 6px;
            font-family: var(--font-mono);
        }}

        .cwe-pill, .mitre-pill {{
            font-size: 11px;
            font-weight: 600;
            padding: 3px 8px;
            border-radius: 6px;
            background: var(--border);
            color: var(--text-muted);
            text-decoration: none;
        }}

        .cwe-pill:hover, .mitre-pill:hover {{
            color: var(--text-main);
            background: var(--accent);
        }}

        .finding-title {{
            font-size: 15px;
            font-weight: 700;
        }}

        .finding-arrow {{
            color: var(--text-muted);
            font-size: 14px;
            transform: rotate(0deg);
            transition: transform 0.2s ease;
        }}

        .finding-card.expanded .finding-arrow {{
            transform: rotate(90deg);
        }}

        .finding-details {{
            display: none;
            padding: 0 24px 24px 24px;
            border-top: 1px solid var(--border);
            background: rgba(0, 0, 0, 0.1);
        }}

        .finding-card.expanded .finding-details {{
            display: block;
        }}

        .detail-row {{
            margin-top: 16px;
        }}

        .detail-label {{
            font-size: 12px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            color: var(--text-muted);
            margin-bottom: 6px;
        }}

        .detail-content {{
            font-size: 14px;
            color: var(--text-main);
            line-height: 1.6;
        }}

        .detail-code {{
            background: #000000;
            color: #10b981;
            font-family: var(--font-mono);
            padding: 12px 16px;
            border-radius: 8px;
            font-size: 13px;
            overflow-x: auto;
            border: 1px solid var(--border);
            margin-top: 6px;
        }}

        .standards-bar {{
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            margin-top: 12px;
            align-items: center;
        }}

        .remediation-box {{
            margin-top: 18px;
            background: rgba(99, 102, 241, 0.08);
            border-left: 4px solid var(--accent);
            padding: 14px 18px;
            border-radius: 0 8px 8px 0;
        }}

        .remediation-title {{
            font-size: 13px;
            font-weight: 700;
            color: #818cf8;
            margin-bottom: 4px;
        }}

        /* Auto-Fix Code Patch Widget */
        .autofix-box {{
            margin-top: 18px;
            background: #0d1117;
            border: 1px solid #30363d;
            border-radius: 10px;
            overflow: hidden;
        }}

        .autofix-header {{
            background: #161b22;
            padding: 10px 16px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid #30363d;
        }}

        .autofix-meta {{
            display: flex;
            align-items: center;
            gap: 10px;
            font-size: 12px;
            font-weight: 600;
            color: #58a6ff;
        }}

        .autofix-tech-tag {{
            background: rgba(88, 166, 255, 0.15);
            color: #58a6ff;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 11px;
        }}

        .copy-btn {{
            background: #238636;
            color: white;
            border: none;
            padding: 5px 12px;
            border-radius: 6px;
            font-size: 12px;
            font-weight: 600;
            cursor: pointer;
            display: flex;
            align-items: center;
            gap: 6px;
        }}

        .copy-btn:hover {{
            background: #2ea043;
        }}

        .copy-btn.copied {{
            background: #1f6feb;
        }}

        .autofix-code {{
            padding: 14px 16px;
            font-family: var(--font-mono);
            font-size: 12px;
            color: #e6edf3;
            overflow-x: auto;
            line-height: 1.5;
            white-space: pre;
        }}

        .autofix-explanation {{
            padding: 8px 16px;
            font-size: 12px;
            color: #8b949e;
            background: #161b22;
            border-top: 1px solid #30363d;
        }}

        .no-vulns-card {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 48px 24px;
            text-align: center;
        }}

        .no-vulns-icon {{
            font-size: 48px;
            color: var(--safe-color);
            margin-bottom: 16px;
        }}

        .no-vulns-title {{
            font-size: 20px;
            font-weight: 800;
            margin-bottom: 8px;
        }}

        .no-vulns-desc {{
            color: var(--text-muted);
            max-width: 500px;
            margin: 0 auto;
            font-size: 14px;
        }}

        footer {{
            text-align: center;
            margin-top: 48px;
            color: var(--text-muted);
            font-size: 13px;
        }}
    </style>
</head>
<body>
    <header>
        <div class="nav-container">
            <div class="brand-group">
                <div class="brand-logo">VS</div>
                <div class="brand-name">VulnScanner Enterprise</div>
            </div>
            <div class="header-actions">
                <button class="theme-toggle" id="themeBtn" onclick="toggleTheme()">
                    <span id="themeIcon">Sun</span>
                    <span id="themeText">Tema Claro</span>
                </button>
            </div>
        </div>
    </header>

    <div class="main-container">
        <div class="hero-panel">
            <div class="target-info">
                <h1>Reporte de Auditoría: {domain}</h1>
                <div class="target-meta">
                    <span><strong>URL:</strong> {target_url}</span>
                    <span><strong>Fecha:</strong> {scan_date}</span>
                    <span><strong>Duración:</strong> {duration}s</span>
                    <span><strong>Estándar:</strong> SARIF v2.1.0 / CVSS v3.1</span>
                </div>
            </div>
        </div>

        <div class="stats-grid">
            <div class="stat-card stat-total">
                <div>
                    <div class="stat-val">{total_count}</div>
                    <div class="stat-label">Total Hallazgos</div>
                </div>
                <div class="stat-icon">#</div>
            </div>
            <div class="stat-card stat-high">
                <div>
                    <div class="stat-val">{high_count}</div>
                    <div class="stat-label">Riesgo Alto / Crítico</div>
                </div>
                <div class="stat-icon">!</div>
            </div>
            <div class="stat-card stat-medium">
                <div>
                    <div class="stat-val">{medium_count}</div>
                    <div class="stat-label">Riesgo Medio</div>
                </div>
                <div class="stat-icon">~</div>
            </div>
            <div class="stat-card stat-low">
                <div>
                    <div class="stat-val">{low_count}</div>
                    <div class="stat-label">Riesgo Bajo / Info</div>
                </div>
                <div class="stat-icon">i</div>
            </div>
        </div>

        {content_section}
    </div>

    <footer>
        Generado automáticamente por <strong>VulnScanner</strong> &bull; Compatible con OASIS SARIF v2.1.0 &bull; MITRE ATT&CK
    </footer>

    <script>
        function toggleTheme() {{
            const html = document.documentElement;
            const currentTheme = html.getAttribute('data-theme');
            const themeIcon = document.getElementById('themeIcon');
            const themeText = document.getElementById('themeText');

            if (currentTheme === 'light') {{
                html.removeAttribute('data-theme');
                themeIcon.innerText = 'Sun';
                themeText.innerText = 'Tema Claro';
            }} else {{
                html.setAttribute('data-theme', 'light');
                themeIcon.innerText = 'Moon';
                themeText.innerText = 'Tema Oscuro';
            }}
        }}

        function toggleCard(cardId) {{
            const card = document.getElementById(cardId);
            card.classList.toggle('expanded');
        }}

        function filterSeverity(severity) {{
            const chips = document.querySelectorAll('.chip');
            chips.forEach(chip => {{
                chip.className = 'chip';
            }});

            const clickedBtn = document.getElementById('chip-' + severity.toLowerCase());
            if (clickedBtn) {{
                clickedBtn.className = 'chip active-' + severity.toLowerCase();
            }}

            const cards = document.querySelectorAll('.finding-card');
            cards.forEach(card => {{
                if (severity === 'All') {{
                    card.style.display = 'block';
                }} else {{
                    const risk = card.getAttribute('data-risk').toLowerCase();
                    if (risk === severity.toLowerCase()) {{
                        card.style.display = 'block';
                    }} else {{
                        card.style.display = 'none';
                    }}
                }}
            }});
        }}

        function copyCode(btn, codeId) {{
            const codeElem = document.getElementById(codeId);
            if (!codeElem) return;
            const textToCopy = codeElem.innerText;
            navigator.clipboard.writeText(textToCopy).then(() => {{
                const originalText = btn.innerHTML;
                btn.innerHTML = '&#10003; ¡Copiado!';
                btn.classList.add('copied');
                setTimeout(() => {{
                    btn.innerHTML = originalText;
                    btn.classList.remove('copied');
                }}, 2000);
            }}).catch(err => {{
                console.error('Error al copiar: ', err);
            }});
        }}
    </script>
</body>
</html>
"""

def get_recommendation(vuln_name: str) -> str:
    vn = vuln_name.lower()
    if "x-frame-options" in vn:
        return "Configurar cabecera 'X-Frame-Options: DENY' o 'SAMEORIGIN' para mitigar Clickjacking."
    elif "content-security-policy" in vn:
        return "Definir una política de seguridad de contenido (CSP) robusta para evitar inyecciones XSS y de código."
    elif "strict-transport-security" in vn:
        return "Habilitar HSTS mediante la cabecera 'Strict-Transport-Security: max-age=31536000; includeSubDomains' para forzar conexiones HTTPS seguras."
    elif "x-content-type-options" in vn:
        return "Configurar la cabecera 'X-Content-Type-Options: nosniff' para evitar que el navegador adivine el tipo MIME de los archivos."
    elif "referrer-policy" in vn:
        return "Establecer una cabecera 'Referrer-Policy' segura (ej. 'strict-origin-when-cross-origin') para evitar la filtración de URLs en la navegación externa."
    elif "permissions-policy" in vn:
        return "Definir la cabecera 'Permissions-Policy' para limitar el uso de APIs del navegador (geolocalización, cámara, etc.) únicamente a orígenes autorizados."
    elif "secure" in vn:
        return "Asegurar que la cookie se emita con el flag 'Secure' para evitar su transmisión sobre canales HTTP sin cifrar."
    elif "httponly" in vn:
        return "Asegurar que la cookie se emita con el flag 'HttpOnly' para que no sea accesible desde scripts de JavaScript, reduciendo el riesgo de secuestro de sesión vía XSS."
    elif "https" in vn:
        return "Migrar todo el tráfico a HTTPS e implementar redirecciones automáticas 301 desde HTTP a HTTPS."
    elif "directorio" in vn:
        return "Deshabilitar el listado de directorios en el servidor web (Apache, Nginx, IIS) y restringir el acceso a rutas administrativas mediante autenticación robusta o reglas de IP."
    elif "xss" in vn:
        return "Sanitizar y escapar adecuadamente todas las entradas del usuario antes de renderizarlas en el HTML de la página (por ejemplo, usar plantillas con auto-escaping)."
    elif "sqli" in vn:
        return "Implementar consultas preparadas (Prepared Statements) o consultas parametrizadas al interactuar con la base de datos para evitar la inyección de comandos SQL."
    elif "formulario" in vn:
        return "Se detectaron entradas inseguras en el formulario. Implementa validación estricta de tipos de datos en el servidor, usa consultas parametrizadas para base de datos (evitando SQLi), escapa todas las salidas en el HTML para evitar XSS y configura tokens anti-CSRF."
    elif "alerta ia" in vn:
        return "La Inteligencia Artificial ha detectado un comportamiento o estructura sospechosa en los parámetros. Se recomienda validar estrictamente la entrada del usuario, usar consultas parametrizadas para interactuar con la base de datos y sanitizar el HTML de salida."
    elif "cors" in vn:
        return "Configurar las cabeceras CORS de forma restrictiva. No reflejar dinámicamente la cabecera 'Origin' recibida y evitar el uso de 'Access-Control-Allow-Origin: *' si la respuesta requiere cookies o credenciales ('Access-Control-Allow-Credentials: true')."
    elif "csrf" in vn:
        return "Implementar tokens anti-CSRF únicos, criptográficamente seguros y asociados a la sesión del usuario (ej. Double Submit Cookie o fichas sincronizadas) en todos los formularios y endpoints que realicen acciones de modificación del estado (POST, PUT, DELETE)."
    elif "ssl" in vn or "tls" in vn or "certificado" in vn:
        return "Configurar un certificado SSL/TLS válido emitido por una Autoridad de Certificación reconocida, forzar HTTPS y deshabilitar soporte para protocolos obsoletos (TLS 1.0 y TLS 1.1) y cifrados débiles en el servidor web."
    elif "exposición de datos" in vn or "datos sensibles" in vn:
        return "Remover secretos, claves de API, tokens JWT o credenciales del código fuente HTML y de los archivos JavaScript expuestos públicamente. Utilizar variables de entorno en el backend y almacenar credenciales de forma segura en un gestor de secretos."
    elif "inyección de comandos" in vn:
        return "Evitar pasar entradas del usuario directamente a comandos del sistema operativo. Sanitizar las entradas y preferir APIs seguras del lenguaje (ej. usar listas con subprocess en lugar de shell=True en Python)."
    elif "ssti" in vn or "inyección de plantillas" in vn:
        return "Evitar pasar la entrada del usuario directamente a la renderización de plantillas. Sanitizar adecuadamente o usar mecanismos nativos de escape del motor de plantillas."
    elif "archivo sensible" in vn:
        return "Asegurar que los archivos de configuración, respaldos, base de datos (.sql) o control de versiones (.git) estén fuera de la raíz pública del servidor web o restringidos a través de reglas de acceso del servidor (Nginx, Apache)."
    elif "subdominio activo" in vn:
        return "Se identificó un subdominio activo. Asegúrate de que todos los puertos y servicios expuestos en este subdominio estén correctamente protegidos y actualizados."
    elif "path traversal" in vn or "directory traversal" in vn:
        return "Sanitizar y validar las rutas de archivos ingresadas por el usuario. Usar whitelists de rutas permitidas y evitar pasar directamente la entrada del usuario a funciones de lectura de archivos del sistema operativo."
    elif "xxe" in vn or "xml external entity" in vn:
        return "Deshabilitar el procesamiento de entidades externas (DTD/DOCTYPE) en el parser XML del servidor. Configurar el parser con features como 'external-general-entities=false' y 'external-parameter-entities=false'."
    elif "open redirect" in vn:
        return "Validar la URL de redirección contra una whitelist de dominios permitidos. No aceptar URLs completas de usuario; usar tokens o IDs internos que mapeen a destinos predefinidos."
    elif "jwt" in vn.lower() and ("none" in vn or "algoritmo" in vn or "debil" in vn or "expuesto" in vn):
        return "Forzar explícitamente el algoritmo de firma en el servidor (no aceptar 'none'). Usar secretos HMAC robustos (mínimo 256 bits) o claves RSA/ECDSA asimétricas. Almacenar JWTs en cookies HttpOnly/Secure en lugar de localStorage/sessionStorage."
    elif "subida de archivos" in vn or "file upload" in vn.lower():
        return "Validar el tipo MIME real del archivo en el servidor (no confiar en la extensión). Usar whitelist de extensiones permitidas. Almacenar archivos fuera del directorio público. Implementar escaneo antivirus y límite estricto de tamaño."
    elif "prototype pollution" in vn.lower():
        return "Sanitizar todas las claves de objetos en funciones merge/extend para bloquear '__proto__', 'constructor' y 'prototype'. Usar Object.create(null) para objetos planos y considerar Object.freeze() en prototipos críticos."
    elif "graphql" in vn.lower():
        return "Deshabilitar la introspección GraphQL en entornos de producción. Implementar rate limiting, limitar la profundidad de consultas (query depth limit) y usar persisted queries para endpoints públicos."
    elif "websocket" in vn.lower():
        return "Usar exclusivamente 'wss://' (WebSocket sobre TLS) para cifrar las comunicaciones. Implementar autenticación en el handshake vía token en query param o cabeceras. Validar el origen de las conexiones (Origin header)."
    elif "oast" in vn.lower() or "blind" in vn.lower() or "ssrf" in vn.lower():
        return "Validar y sanitizar URLs antes de realizar peticiones HTTP salientes desde el backend. Restringir el acceso a direcciones IP privadas (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.1) y configurar reglas de egress en el firewall."
    return "Revisar la configuración de seguridad y aplicar parches recomendados."


SEVERITY_RISK_MAP = {"critical": "Alto", "high": "Alto", "medium": "Medio", "low": "Bajo", "info": "Bajo"}


def _normalize_finding(r: Any) -> dict[str, Any]:
    """Convierte un Finding o dict legacy a un dict unificado con estándares de seguridad."""
    if hasattr(r, 'to_dict'):
        d = r.to_dict()
        return {
            "vuln": d["title"],
            "risk": SEVERITY_RISK_MAP.get(d["severity"], "Bajo"),
            "detail": d["description"],
            "severity": d["severity"],
            "confidence": d["confidence"],
            "category": d["category"],
            "evidence": d.get("evidence"),
            "remediation": d.get("remediation"),
            "affected_url": d.get("affected_url"),
            "parameter": d.get("parameter"),
            "cvss_score": d.get("cvss_score", 0.0),
            "cvss_vector": d.get("cvss_vector", ""),
            "cwe_id": d.get("cwe_id", "CWE-693"),
            "cwe_name": d.get("cwe_name", ""),
            "mitre_attack_id": d.get("mitre_attack_id", "T1190"),
            "mitre_attack_name": d.get("mitre_attack_name", ""),
            "owasp_category": d.get("owasp_category", ""),
            "autofix": d.get("autofix"),
        }

    category = r.get("category", "default")
    std = VULN_STANDARDS_DB.get(category, VULN_STANDARDS_DB.get("default", {}))
    return {
        "vuln": r.get("vuln", ""),
        "risk": r.get("risk", "Bajo"),
        "detail": r.get("detail", ""),
        "severity": "high" if r.get("risk") == "Alto" else "medium" if r.get("risk") == "Medio" else "low",
        "confidence": r.get("confidence", "possible"),
        "category": category,
        "evidence": r.get("evidence"),
        "remediation": r.get("remediation"),
        "affected_url": r.get("affected_url"),
        "parameter": r.get("parameter"),
        "cvss_score": r.get("cvss_score", std.get("default_cvss_score", 4.0)),
        "cvss_vector": r.get("cvss_vector", std.get("default_cvss_vector", "")),
        "cwe_id": r.get("cwe_id", std.get("cwe_id", "CWE-693")),
        "cwe_name": r.get("cwe_name", std.get("cwe_name", "")),
        "mitre_attack_id": r.get("mitre_attack_id", std.get("mitre_attack_id", "T1190")),
        "mitre_attack_name": r.get("mitre_attack_name", std.get("mitre_attack_name", "")),
        "owasp_category": r.get("owasp_category", std.get("owasp_category", "")),
        "autofix": r.get("autofix"),
    }


def generate_html_report(url: str, all_results: list[Any], duration: float) -> str:
    parsed_url = urlparse(url)
    domain = parsed_url.netloc or "localhost"

    normalized = [_normalize_finding(r) for r in all_results]

    high_count = sum(1 for r in normalized if r["risk"] == "Alto")
    medium_count = sum(1 for r in normalized if r["risk"] == "Medio")
    low_count = sum(1 for r in normalized if r["risk"] == "Bajo")
    total_count = len(normalized)

    scan_date = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

    if not normalized:
        content_section = """
        <div class="no-vulns-card">
            <div class="no-vulns-icon">[OK]</div>
            <div class="no-vulns-title">¡Sitio Seguro!</div>
            <div class="no-vulns-desc">
                No se detectaron vulnerabilidades conocidas. Tu aplicación parece seguir las directivas básicas de configuración segura, HTTPS y cookies.
            </div>
        </div>
        """
    else:
        cards_html = []
        for i, r in enumerate(normalized):
            risk = r["risk"]
            vuln = r["vuln"]
            detail = r["detail"]
            recommendation = r.get("remediation") or get_recommendation(vuln)
            cvss_score = r.get("cvss_score", 0.0)
            cvss_vector = r.get("cvss_vector", "")
            cwe_id = r.get("cwe_id", "CWE-693")
            mitre_id = r.get("mitre_attack_id", "T1190")
            autofix = r.get("autofix")

            badge_class = f"badge-{risk.lower()}"
            card_id = f"card-{i}"
            code_id = f"autofix-code-{i}"

            detail_formatted = detail
            if "payload:" in detail.lower() or "responde" in detail.lower() or "error" in detail.lower():
                detail_formatted = f'<div class="detail-code">{detail}</div>'

            # Auto-Fix Widget HTML si existe parche disponible
            autofix_html = ""
            if autofix:
                tech = autofix.get("technology", "Framework")
                filename = autofix.get("filename", "config")
                code_snippet = autofix.get("code_snippet", "")
                explanation = autofix.get("explanation", "")

                autofix_html = f"""
                <div class="autofix-box">
                    <div class="autofix-header">
                        <div class="autofix-meta">
                            <span>🤖 <strong>Parche Auto-Fix:</strong></span>
                            <span class="autofix-tech-tag">{tech}</span>
                            <span><code>{filename}</code></span>
                        </div>
                        <button class="copy-btn" onclick="copyCode(this, '{code_id}')">
                            📋 Copiar Parche
                        </button>
                    </div>
                    <div class="autofix-code" id="{code_id}">{code_snippet}</div>
                    <div class="autofix-explanation">💡 <em>{explanation}</em></div>
                </div>
                """

            card_html = f"""
            <div class="finding-card" id="{card_id}" data-risk="{risk}">
                <div class="finding-header" onclick="toggleCard('{card_id}')">
                    <div class="finding-title-group">
                        <span class="finding-badge {badge_class}">{risk}</span>
                        <span class="cvss-badge" title="{cvss_vector}">CVSS {cvss_score}</span>
                        <a href="https://cwe.mitre.org/data/definitions/{cwe_id.replace('CWE-', '')}.html" target="_blank" class="cwe-pill" onclick="event.stopPropagation()">{cwe_id}</a>
                        <a href="https://attack.mitre.org/techniques/{mitre_id}/" target="_blank" class="mitre-pill" onclick="event.stopPropagation()">MITRE {mitre_id}</a>
                        <span class="finding-title">{vuln}</span>
                    </div>
                    <span class="finding-arrow">&gt;</span>
                </div>
                <div class="finding-details">
                    <div class="detail-row">
                        <div class="detail-label">Detalle Detectado</div>
                        <div class="detail-content">{detail_formatted}</div>
                    </div>
                    <div class="remediation-box">
                        <div class="remediation-title">🛡️ Recomendación de Remediación</div>
                        <div class="detail-content">{recommendation}</div>
                    </div>
                    {autofix_html}
                </div>
            </div>
            """
            cards_html.append(card_html)

        findings_html = "\n".join(cards_html)

        content_section = f"""
        <div class="filter-section">
            <div class="filter-title">Hallazgos Encontrados ({total_count})</div>
            <div class="chips">
                <button class="chip active-all" id="chip-all" onclick="filterSeverity('All')">Todos ({total_count})</button>
                <button class="chip" id="chip-alto" onclick="filterSeverity('Alto')">Alto ({high_count})</button>
                <button class="chip" id="chip-medio" onclick="filterSeverity('Medio')">Medio ({medium_count})</button>
                <button class="chip" id="chip-bajo" onclick="filterSeverity('Bajo')">Bajo ({low_count})</button>
            </div>
        </div>
        <div class="findings-list">
            {findings_html}
        </div>
        """

    html_content = HTML_TEMPLATE.format(
        domain=domain,
        target_url=url,
        scan_date=scan_date,
        duration=f"{duration:.2f}",
        total_count=total_count,
        high_count=high_count,
        medium_count=medium_count,
        low_count=low_count,
        content_section=content_section
    )

    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    reports_dir = os.path.join(project_root, "reports")
    os.makedirs(reports_dir, exist_ok=True)

    domain_clean = re.sub(r'[^a-zA-Z0-9]', '_', domain)
    filename = f"reporte_{domain_clean}_{int(time.time())}.html"
    filepath = os.path.join(reports_dir, filename)

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(html_content)

    return filepath


def generate_sarif_report(url: str, findings: list[Any], duration: float = 0.0) -> dict[str, Any]:
    """Genera reporte en formato estándar OASIS SARIF v2.1.0."""
    return generate_sarif_v210(url, findings, duration)


def print_report(
    url: str,
    all_results: list[Any],
    duration: float = 0.0,
    no_open: bool = False,
    engine_summary: Optional[dict[str, Any]] = None,
    generate_pdf: bool = False,
) -> tuple[str, Optional[str], dict[str, Any]]:
    from scanner.models import deduplicate_findings

    is_finding_list = all_results and hasattr(all_results[0], 'to_dict')
    if is_finding_list:
        all_results = deduplicate_findings(all_results)
    else:
        seen = set()
        deduped = []
        for r in all_results:
            key = (r.get("vuln", ""), r.get("detail", ""))
            if key not in seen:
                seen.add(key)
                deduped.append(r)
        if len(deduped) != len(all_results):
            _logger.info("%d hallazgo(s) duplicado(s) consolidado(s).", len(all_results) - len(deduped))
        all_results = deduped

    normalized = [_normalize_finding(r) for r in all_results]

    severity_count = {"high": 0, "medium": 0, "low": 0, "info": 0, "critical": 0}
    confidence_count = {"confirmed": 0, "probable": 0, "possible": 0}
    for n in normalized:
        sev = n.get("severity", "info")
        severity_count[sev] = severity_count.get(sev, 0) + 1
        conf = n.get("confidence", "possible")
        confidence_count[conf] = confidence_count.get(conf, 0) + 1

    risk_counts = {
        "Alto": severity_count["critical"] + severity_count["high"],
        "Medio": severity_count["medium"],
        "Bajo": severity_count["low"] + severity_count["info"]
    }

    print(f"\n{'='*60}")
    print(f"  VulnScanner Enterprise -- Reporte para: {url}")
    print(f"{'='*60}")
    if engine_summary:
        print(f"  Perfil: {engine_summary.get('profile', 'N/A')} | "
              f"Requests: {engine_summary.get('total_requests', 0)} | "
              f"Duracion: {engine_summary.get('duration_seconds', 0)}s")
    if confidence_count["confirmed"] + confidence_count["probable"] > 0:
        print(f"  Confianza: {confidence_count['confirmed']} confirmados, "
              f"{confidence_count['probable']} probables, {confidence_count['possible']} posibles")

    if not all_results:
        _logger.info("No se detectaron vulnerabilidades.")
        html_path = generate_html_report(url, all_results, duration)
        _logger.info("Reporte HTML generado: %s", html_path)
        sarif_path = _save_sarif_report(url, all_results, duration)
        pdf_path = _save_pdf_report(url, all_results, duration, engine_summary) if generate_pdf else None
        json_path, report_data = _save_json_report(
            url,
            risk_counts,
            normalized,
            duration,
            engine_summary,
            sarif_path=sarif_path,
            pdf_path=pdf_path,
        )
        if not no_open:
            _open_report(html_path)
        return html_path, json_path, report_data

    for n in normalized:
        risk = n.get("risk", "Bajo")
        color = COLORS.get(risk, "")
        conf_badge = f" [{n.get('confidence', '').upper()}]" if n.get('confidence') not in ('possible', '') else ""
        cvss_str = f" [CVSS {n.get('cvss_score', 0.0)}]" if n.get('cvss_score') else ""
        cwe_str = f" [{n.get('cwe_id')}]" if n.get('cwe_id') else ""
        print(f"\n{color}[{risk}]{cvss_str}{cwe_str} {n['vuln']}{conf_badge}")
        print(f"       -> {n['detail']}")
        if n.get("evidence") and n["evidence"].get("response_fragment"):
            frag = n["evidence"]["response_fragment"]
            if len(frag) > 120:
                frag = frag[:120] + "..."
            print(f"         Evidencia: {frag}")
        if n.get("remediation"):
            print(f"         Solución: {n['remediation']}")

    print(f"\n{'─'*60}")
    print(f"  Resumen: "
          f"{Fore.RED}{risk_counts['Alto']} Alto  "
          f"{Fore.YELLOW}{risk_counts['Medio']} Medio  "
          f"{Fore.CYAN}{risk_counts['Bajo']} Bajo")
    print(f"{'='*60}\n")

    html_path = generate_html_report(url, all_results, duration)
    _logger.info("Reporte HTML generado: %s", html_path)

    sarif_path = _save_sarif_report(url, all_results, duration)
    pdf_path = _save_pdf_report(url, all_results, duration, engine_summary) if generate_pdf else None
    json_path, report_data = _save_json_report(
        url,
        risk_counts,
        normalized,
        duration,
        engine_summary,
        sarif_path=sarif_path,
        pdf_path=pdf_path,
    )

    if not no_open:
        _open_report(html_path)

    return html_path, json_path, report_data


def _save_pdf_report(url: str, findings: list[Any], duration: float, engine_summary: Optional[dict[str, Any]] = None) -> str:
    try:
        from scanner.models import Finding
        parsed_url = urlparse(url)
        safe_domain = (parsed_url.netloc or "localhost").replace(":", "_").replace(".", "_")
        pdf_filename = f"reporte_{safe_domain}_{int(time.time())}.pdf"
        reports_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "reports")
        os.makedirs(reports_dir, exist_ok=True)
        pdf_path = os.path.join(reports_dir, pdf_filename)

        # Convertir a objetos Finding si son diccionarios legados
        finding_objs: list[Finding] = []
        for f in findings:
            if isinstance(f, Finding):
                finding_objs.append(f)
            elif isinstance(f, dict):
                finding_objs.append(Finding(
                    title=f.get("vuln") or f.get("title") or "Vulnerabilidad",
                    severity=f.get("severity") or "info",
                    category=f.get("category") or "general",
                    affected_url=f.get("url") or url,
                    description=f.get("detail") or f.get("description") or "",
                    remediation=f.get("remediation") or "",
                    cwe_id=f.get("cwe_id") or "",
                    mitre_attack_id=f.get("mitre_attack_id") or "",
                    cvss_score=f.get("cvss_score", 0.0),
                ))

        profile_val = engine_summary.get("profile", "normal") if engine_summary else "normal"
        generate_pdf_report(
            target_url=url,
            findings=finding_objs,
            output_path=pdf_path,
            duration=duration,
            scan_profile=profile_val,
            engine_summary=engine_summary,
        )
        _logger.info("Reporte Ejecutivo PDF generado: %s", pdf_path)
        return pdf_path
    except Exception as e:
        _logger.warning("No se pudo generar el reporte PDF: %s", e)
        return ""


def _save_json_report(
    url: str,
    counts: dict[str, int],
    normalized: list[dict[str, Any]],
    duration: float,
    engine_summary: Optional[dict[str, Any]] = None,
    sarif_path: str = "",
    pdf_path: str | None = None,
) -> tuple[Optional[str], dict[str, Any]]:
    json_path = None
    report_data: dict[str, Any] = {
        "target": url,
        "date": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
        "duration_seconds": round(duration, 2),
        "engine": engine_summary or {},
        "sarif_report_path": sarif_path,
        "pdf_report_path": pdf_path or "",
        "summary": {
            "Alto": counts.get("Alto", 0),
            "Medio": counts.get("Medio", 0),
            "Bajo": counts.get("Bajo", 0),
        },
        "vulnerabilities": normalized
    }
    try:
        parsed_url = urlparse(url)
        safe_domain = (parsed_url.netloc or "localhost").replace(":", "_").replace(".", "_")
        json_filename = f"reporte_{safe_domain}_{int(time.time())}.json"
        reports_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "reports")
        os.makedirs(reports_dir, exist_ok=True)
        json_path = os.path.join(reports_dir, json_filename)
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, ensure_ascii=False, indent=2)
        _logger.info("Reporte JSON generado: %s", json_path)
    except Exception as e:
        _logger.warning("No se pudo generar el reporte JSON: %s", e)
    return json_path, report_data


def _save_sarif_report(url: str, findings: list[Any], duration: float) -> str:
    try:
        sarif = generate_sarif_v210(url, findings, duration)
        parsed_url = urlparse(url)
        safe_domain = (parsed_url.netloc or "localhost").replace(":", "_").replace(".", "_")
        sarif_filename = f"reporte_{safe_domain}_{int(time.time())}.sarif"
        reports_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "reports")
        os.makedirs(reports_dir, exist_ok=True)
        sarif_path = os.path.join(reports_dir, sarif_filename)
        with open(sarif_path, 'w', encoding='utf-8') as f:
            json.dump(sarif, f, ensure_ascii=False, indent=2)
        _logger.info("Reporte SARIF v2.1.0 generado: %s", sarif_path)
        return sarif_path
    except Exception as e:
        _logger.warning("No se pudo generar reporte SARIF: %s", e)
        return ""


def _open_report(html_path: str) -> None:
    try:
        import webbrowser
        webbrowser.open("file://" + os.path.abspath(html_path).replace("\\", "/"))
        _logger.info("Reporte abierto automáticamente en tu navegador.")
    except Exception as e:
        _logger.warning("No se pudo abrir el navegador: %s", e)
