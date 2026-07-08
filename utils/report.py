import os
import re
import time
import json
from urllib.parse import urlparse
from colorama import Fore, Style, init

init(autoreset=True)

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
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
    <style>
        :root {{
            --bg-body: #090d16;
            --bg-card: #111827;
            --text-main: #f3f4f6;
            --text-muted: #9ca3af;
            --border: #1f2937;
            --accent: #6366f1;
            
            --high-color: #ef4444;
            --high-bg: rgba(239, 68, 68, 0.1);
            --medium-color: #f59e0b;
            --medium-bg: rgba(245, 158, 11, 0.1);
            --low-color: #06b6d4;
            --low-bg: rgba(6, 182, 212, 0.1);
            --safe-color: #10b981;
            --safe-bg: rgba(16, 185, 129, 0.1);
            
            --shadow-sm: 0 1px 2px 0 rgba(0, 0, 0, 0.3);
            --shadow-md: 0 4px 6px -1px rgba(0, 0, 0, 0.3), 0 2px 4px -1px rgba(0, 0, 0, 0.2);
            --shadow-lg: 0 10px 15px -3px rgba(0, 0, 0, 0.4), 0 4px 6px -2px rgba(0, 0, 0, 0.3);
            --font: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
        }}

        [data-theme="light"] {{
            --bg-body: #f8fafc;
            --bg-card: #ffffff;
            --text-main: #0f172a;
            --text-muted: #64748b;
            --border: #e2e8f0;
            --accent: #4f46e5;
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
            background-color: rgba(9, 13, 22, 0.8);
            backdrop-filter: blur(12px);
            -webkit-backdrop-filter: blur(12px);
            border-bottom: 1px solid var(--border);
            padding: 16px 24px;
        }}

        [data-theme="light"] header {{
            background-color: rgba(248, 250, 252, 0.8);
        }}

        .nav-container {{
            max-width: 1200px;
            margin: 0 auto;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}

        .logo {{
            font-size: 1.25rem;
            font-weight: 800;
            letter-spacing: -0.5px;
            display: flex;
            align-items: center;
            gap: 8px;
            background: linear-gradient(135deg, var(--accent), #a855f7);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }}

        .theme-toggle {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            color: var(--text-main);
            padding: 8px 16px;
            border-radius: 9999px;
            cursor: pointer;
            font-size: 0.875rem;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 6px;
            box-shadow: var(--shadow-sm);
        }}

        .theme-toggle:hover {{
            background-color: var(--border);
        }}

        .container {{
            max-width: 1200px;
            margin: 40px auto 0 auto;
            padding: 0 24px;
        }}

        .summary-card {{
            background-color: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 24px;
            padding: 32px;
            margin-bottom: 32px;
            box-shadow: var(--shadow-lg);
            position: relative;
            overflow: hidden;
        }}

        .summary-card::before {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 4px;
            background: linear-gradient(90deg, var(--high-color), var(--medium-color), var(--low-color));
        }}

        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 24px;
            margin-top: 24px;
        }}

        .stat-box {{
            padding: 20px;
            border-radius: 16px;
            background-color: var(--bg-body);
            border: 1px solid var(--border);
            text-align: center;
        }}

        .stat-value {{
            font-size: 2.25rem;
            font-weight: 800;
            margin-bottom: 4px;
            line-height: 1;
        }}

        .stat-label {{
            font-size: 0.875rem;
            color: var(--text-muted);
            font-weight: 600;
        }}

        .stat-high {{ color: var(--high-color); }}
        .stat-medium {{ color: var(--medium-color); }}
        .stat-low {{ color: var(--low-color); }}
        .stat-total {{ color: var(--accent); }}

        .meta-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 16px;
            font-size: 0.875rem;
            color: var(--text-muted);
            margin-top: 16px;
            border-top: 1px solid var(--border);
            padding-top: 16px;
        }}

        .meta-item strong {{
            color: var(--text-main);
        }}

        .filter-section {{
            display: flex;
            align-items: center;
            justify-content: space-between;
            flex-wrap: wrap;
            gap: 16px;
            margin-bottom: 24px;
        }}

        .filter-title {{
            font-size: 1.25rem;
            font-weight: 700;
            letter-spacing: -0.3px;
        }}

        .chips {{
            display: flex;
            gap: 8px;
        }}

        .chip {{
            padding: 8px 18px;
            border-radius: 9999px;
            border: 1px solid var(--border);
            background-color: var(--bg-card);
            color: var(--text-main);
            font-size: 0.875rem;
            font-weight: 600;
            cursor: pointer;
            box-shadow: var(--shadow-sm);
        }}

        .chip:hover {{
            background-color: var(--border);
        }}

        .chip.active-all {{ background-color: var(--text-main); color: var(--bg-body); border-color: var(--text-main); }}
        .chip.active-high {{ background-color: var(--high-color); color: white; border-color: var(--high-color); box-shadow: 0 4px 10px rgba(239, 68, 68, 0.3); }}
        .chip.active-medium {{ background-color: var(--medium-color); color: white; border-color: var(--medium-color); box-shadow: 0 4px 10px rgba(245, 158, 11, 0.3); }}
        .chip.active-low {{ background-color: var(--low-color); color: white; border-color: var(--low-color); box-shadow: 0 4px 10px rgba(6, 182, 212, 0.3); }}

        .findings-list {{
            display: flex;
            flex-direction: column;
            gap: 16px;
        }}

        .finding-card {{
            background-color: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 16px;
            overflow: hidden;
            box-shadow: var(--shadow-sm);
        }}

        .finding-card:hover {{
            transform: translateY(-2px);
            box-shadow: var(--shadow-md);
        }}

        .finding-header {{
            padding: 20px 24px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            cursor: pointer;
            user-select: none;
        }}

        .finding-title-group {{
            display: flex;
            align-items: center;
            gap: 12px;
        }}

        .finding-badge {{
            font-size: 0.75rem;
            font-weight: 700;
            text-transform: uppercase;
            padding: 4px 10px;
            border-radius: 6px;
            letter-spacing: 0.5px;
        }}

        .badge-alto {{ background-color: var(--high-bg); color: var(--high-color); border: 1px solid rgba(239, 68, 68, 0.2); }}
        .badge-medio {{ background-color: var(--medium-bg); color: var(--medium-color); border: 1px solid rgba(245, 158, 11, 0.2); }}
        .badge-bajo {{ background-color: var(--low-bg); color: var(--low-color); border: 1px solid rgba(6, 182, 212, 0.2); }}

        .finding-title {{
            font-weight: 600;
            font-size: 1rem;
        }}

        .finding-arrow {{
            color: var(--text-muted);
            font-size: 1.25rem;
            font-weight: 300;
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
            background-color: rgba(255, 255, 255, 0.01);
        }}

        .finding-card.expanded .finding-details {{
            display: block;
        }}

        .detail-row {{
            margin-top: 16px;
        }}

        .detail-label {{
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: var(--text-muted);
            font-weight: 700;
            margin-bottom: 4px;
        }}

        .detail-content {{
            font-size: 0.95rem;
        }}

        .detail-code {{
            font-family: 'Courier New', Courier, monospace;
            background-color: var(--bg-body);
            border: 1px solid var(--border);
            padding: 8px 12px;
            border-radius: 8px;
            margin-top: 4px;
            overflow-x: auto;
            font-size: 0.85rem;
            color: var(--text-main);
        }}

        .remediation-box {{
            background-color: rgba(99, 102, 241, 0.05);
            border-left: 4px solid var(--accent);
            padding: 16px;
            border-radius: 0 12px 12px 0;
            margin-top: 20px;
        }}

        .remediation-title {{
            font-weight: 700;
            font-size: 0.875rem;
            color: var(--accent);
            margin-bottom: 4px;
            display: flex;
            align-items: center;
            gap: 6px;
        }}

        .no-vulns-card {{
            background-color: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 24px;
            padding: 48px;
            text-align: center;
            box-shadow: var(--shadow-md);
        }}

        .no-vulns-icon {{
            font-size: 3rem;
            color: var(--safe-color);
            margin-bottom: 16px;
        }}

        .no-vulns-title {{
            font-size: 1.5rem;
            font-weight: 700;
            margin-bottom: 8px;
        }}

        .no-vulns-desc {{
            color: var(--text-muted);
            max-width: 500px;
            margin: 0 auto;
        }}

        footer {{
            text-align: center;
            margin-top: 60px;
            color: var(--text-muted);
            font-size: 0.875rem;
        }}

        footer strong {{
            color: var(--text-main);
        }}
    </style>
</head>
<body>
    <header>
        <div class="nav-container">
            <div class="logo">
                <span>🛡️</span> VulnScanner Report
            </div>
            <button class="theme-toggle" id="themeBtn" onclick="toggleTheme()">
                <span id="themeIcon">☀️</span> <span id="themeText">Tema Claro</span>
            </button>
        </div>
    </header>

    <div class="container">
        <div class="summary-card">
            <h2>Resumen del Escaneo</h2>
            <div class="meta-grid">
                <div class="meta-item">Objetivo: <strong style="word-break: break-all;">{target_url}</strong></div>
                <div class="meta-item">Fecha: <strong>{scan_date}</strong></div>
                <div class="meta-item">Duración: <strong>{duration}s</strong></div>
            </div>
            <div class="summary-grid">
                <div class="stat-box">
                    <div class="stat-value stat-total">{total_count}</div>
                    <div class="stat-label">Encontradas</div>
                </div>
                <div class="stat-box">
                    <div class="stat-value stat-high">{high_count}</div>
                    <div class="stat-label">Alto Riesgo</div>
                </div>
                <div class="stat-box">
                    <div class="stat-value stat-medium">{medium_count}</div>
                    <div class="stat-label">Medio Riesgo</div>
                </div>
                <div class="stat-box">
                    <div class="stat-value stat-low">{low_count}</div>
                    <div class="stat-label">Bajo Riesgo</div>
                </div>
            </div>
        </div>

        {content_section}
    </div>

    <footer>
        Generado automáticamente por <strong>VulnScanner</strong>
    </footer>

    <script>
        function toggleTheme() {{
            const html = document.documentElement;
            const currentTheme = html.getAttribute('data-theme');
            const themeBtn = document.getElementById('themeBtn');
            const themeIcon = document.getElementById('themeIcon');
            const themeText = document.getElementById('themeText');
            
            if (currentTheme === 'light') {{
                html.removeAttribute('data-theme');
                themeIcon.innerText = '☀️';
                themeText.innerText = 'Tema Claro';
            }} else {{
                html.setAttribute('data-theme', 'light');
                themeIcon.innerText = '🌙';
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
            clickedBtn.className = 'chip active-' + severity.toLowerCase();

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
    </script>
</body>
</html>
"""

def get_recommendation(vuln_name):
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
    elif "3306" in vn or "mysql" in vn.lower():
        return "El puerto de MySQL/MariaDB está expuesto públicamente. Configura el firewall para restringir el acceso únicamente a IPs de confianza (ej. solo desde tu servidor de aplicaciones)."
    elif "5432" in vn or "postgresql" in vn.lower():
        return "El puerto de PostgreSQL está expuesto públicamente. Restringe el acceso en el firewall y utiliza túneles SSH si necesitas administrarlo de forma remota."
    elif "27017" in vn or "mongodb" in vn.lower():
        return "MongoDB está accesible públicamente. Habilita la autenticación obligatoria y restringe el acceso al puerto 27017 mediante reglas de firewall."
    elif "1433" in vn or "mssql" in vn.lower():
        return "El servidor SQL Server de Microsoft está expuesto. Cierra el puerto 1433 en el firewall para conexiones externas y usa VPN o salto SSH para la administración."
    elif "22" in vn or "ssh" in vn.lower():
        return "El servicio SSH está expuesto. Considera deshabilitar la autenticación por contraseña y usar únicamente claves SSH públicas/privadas. También puedes cambiar el puerto a uno no estándar."
    elif "3389" in vn or "rdp" in vn.lower():
        return "El Escritorio Remoto de Windows (RDP) está expuesto. Es un vector de ataque crítico. Restringe el acceso con reglas de firewall o usa una VPN. Habilita la autenticación NLA (Network Level Authentication)."
    elif "21" in vn or "ftp" in vn.lower():
        return "El protocolo FTP está expuesto. FTP no cifra las transferencias. Migra a SFTP (SSH File Transfer Protocol) o FTPS para garantizar la seguridad de los datos en tránsito."
    elif "445" in vn or "smb" in vn.lower():
        return "El puerto SMB está expuesto públicamente. Es vector de ataques críticos como WannaCry/EternalBlue. Bloquea inmediatamente este puerto en el firewall para conexiones externas."
    elif "8080" in vn or "http-alt" in vn.lower():
        return "Hay un servidor web alternativo expuesto en el puerto 8080. Podría ser un panel de administración o servidor de desarrollo. Verifica si debe ser accesible públicamente."
    elif "23" in vn or "telnet" in vn.lower():
        return "Telnet está expuesto. Es un protocolo completamente inseguro que transmite todo sin cifrar. Elimina el servicio Telnet y usa SSH como alternativa segura."
    elif "cors" in vn:
        return "Configurar las cabeceras CORS de forma restrictiva. No reflejar dinámicamente la cabecera 'Origin' recibida y evitar el uso de 'Access-Control-Allow-Origin: *' si la respuesta requiere cookies o credenciales ('Access-Control-Allow-Credentials: true')."
    elif "csrf" in vn:
        return "Implementar tokens anti-CSRF únicos, criptográficamente seguros y asociados a la sesión del usuario (ej. Double Submit Cookie o fichas sincronizadas) en todos los formularios y endpoints que realicen acciones de modificación del estado (POST, PUT, DELETE)."
    elif "ssl" in vn or "tls" in vn or "certificado" in vn:
        return "Configurar un certificado SSL/TLS válido emitido por una Autoridad de Certificación reconocida, forzar HTTPS y deshabilitar soporte para protocolos obsoletos (TLS 1.0 y TLS 1.1) y cifrados débiles en el servidor web."
    elif "exposición de datos" in vn or "datos sensibles" in vn:
        return "Remover secretos, claves de API, tokens JWT o credenciales del código fuente HTML y de los archivos JavaScript expuestos públicamente. Utilizar variables de entorno en el backend y almacenar credenciales de forma segura en un gestor de secretos."
    elif "comentario" in vn:
        return "Remover comentarios de desarrollo (TODOs, notas de depuración, credenciales provisionales o rutas internas) de la producción HTML y de archivos JavaScript expuestos antes del despliegue."
    elif "inyección de comandos" in vn:
        return "Evitar pasar entradas del usuario directamente a comandos del sistema operativo. Sanitizar las entradas y preferir APIs seguras del lenguaje (ej. usar listas con subprocess en lugar de shell=True en Python)."
    elif "ssti" in vn or "inyección de plantillas" in vn:
        return "Evitar pasar la entrada del usuario directamente a la renderización de plantillas. Sanitizar adecuadamente o usar mecanismos nativos de escape del motor de plantillas."
    elif "archivo sensible" in vn:
        return "Asegurar que los archivos de configuración, respaldos, base de datos (.sql) o control de versiones (.git) estén fuera de la raíz pública del servidor web o restringidos a través de reglas de acceso del servidor (Nginx, Apache)."
    elif "subdominio activo" in vn:
        return "Se identificó un subdominio activo. Asegúrate de que todos los puertos y servicios expuestos en este subdominio estén correctamente protegidos y actualizados."
    elif "puerto" in vn:
        return "Hay un puerto de servicio expuesto públicamente. Revisa las reglas de firewall y restringe el acceso solo a las IPs y servicios que realmente necesiten conectarse a este puerto."
    return "Revisar la configuración de seguridad y aplicar parches recomendados."

def generate_html_report(url, all_results, duration):
    parsed_url = urlparse(url)
    domain = parsed_url.netloc or "localhost"
    
    high_count = sum(1 for r in all_results if r["risk"] == "Alto")
    medium_count = sum(1 for r in all_results if r["risk"] == "Medio")
    low_count = sum(1 for r in all_results if r["risk"] == "Bajo")
    total_count = len(all_results)
    
    scan_date = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    
    if not all_results:
        content_section = """
        <div class="no-vulns-card">
            <div class="no-vulns-icon">🎉</div>
            <div class="no-vulns-title">¡Sitio Seguro!</div>
            <div class="no-vulns-desc">
                No se detectaron vulnerabilidades comunes de seguridad. Tu sitio parece seguir las directrices básicas de configuración segura, HTTPS y cookies.
            </div>
        </div>
        """
    else:
        cards_html = []
        for i, r in enumerate(all_results):
            risk = r["risk"]
            vuln = r["vuln"]
            detail = r["detail"]
            recommendation = get_recommendation(vuln)
            
            badge_class = f"badge-{risk.lower()}"
            card_id = f"card-{i}"
            
            detail_formatted = detail
            if "payload:" in detail.lower() or "responde" in detail.lower() or "error" in detail.lower():
                detail_formatted = f'<div class="detail-code">{detail}</div>'
                
            card_html = f"""
            <div class="finding-card" id="{card_id}" data-risk="{risk}">
                <div class="finding-header" onclick="toggleCard('{card_id}')">
                    <div class="finding-title-group">
                        <span class="finding-badge {badge_class}">{risk}</span>
                        <span class="finding-title">{vuln}</span>
                    </div>
                    <span class="finding-arrow">❯</span>
                </div>
                <div class="finding-details">
                    <div class="detail-row">
                        <div class="detail-label">Detalle Detectado</div>
                        <div class="detail-content">{detail_formatted}</div>
                    </div>
                    <div class="remediation-box">
                        <div class="remediation-title">💡 Recomendación de Remediación</div>
                        <div class="detail-content">{recommendation}</div>
                    </div>
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

def print_report(url, all_results, duration=0.0, no_open=False):
    print(f"\n{'='*60}")
    print(f"  VulnScanner — Reporte para: {url}")
    print(f"{'='*60}")

    import webbrowser

    # Deduplicar hallazgos idénticos (mismo vuln + detail) que aparecen en múltiples páginas.
    # Los hallazgos específicos por página incluyen la URL/parámetro en el detail, por lo que se conservan.
    seen = set()
    deduped = []
    for r in all_results:
        key = (r.get("vuln", ""), r.get("detail", ""))
        if key not in seen:
            seen.add(key)
            deduped.append(r)
    if len(deduped) != len(all_results):
        removed = len(all_results) - len(deduped)
        print(f"  ℹ️  {removed} hallazgo(s) duplicado(s) consolidado(s) de varias páginas.")
    all_results = deduped

    if not all_results:
        print(Fore.GREEN + "\n No se detectaron vulnerabilidades obvias.\n")
        # Generar reporte HTML aunque no haya vulnerabilidades
        html_path = generate_html_report(url, all_results, duration)
        print(f"🌐 Reporte HTML generado: {html_path}\n")
        
        if not no_open:
            try:
                webbrowser.open("file://" + os.path.abspath(html_path).replace("\\", "/"))
                print(" Reporte abierto automáticamente en tu navegador.\n")
            except Exception as e:
                print(f"⚠️ No se pudo abrir el navegador automáticamente: {e}\n")
        return

    counts = {"Alto": 0, "Medio": 0, "Bajo": 0}

    for r in all_results:
        risk = r["risk"]
        color = COLORS.get(risk, "")
        counts[risk] += 1
        print(f"\n{color}[{risk}] {r['vuln']}")
        print(f"       → {r['detail']}")

    print(f"\n{'─'*60}")
    print(f"  Resumen: "
          f"{Fore.RED}{counts['Alto']} Alto  "
          f"{Fore.YELLOW}{counts['Medio']} Medio  "
          f"{Fore.CYAN}{counts['Bajo']} Bajo")
    print(f"{'='*60}\n")
    
    # Generar el reporte HTML e informar la ruta en consola
    html_path = generate_html_report(url, all_results, duration)
    print(Fore.GREEN + f"🌐 Reporte HTML generado: {html_path}")
    
    # Generar reporte JSON
    try:
        report_data = {
            "target": url,
            "date": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
            "duration_seconds": round(duration, 2),
            "summary": counts,
            "vulnerabilities": all_results
        }
        parsed_url = urlparse(url)
        safe_domain = (parsed_url.netloc or "localhost").replace(":", "_").replace(".", "_")
        json_filename = f"reporte_{safe_domain}_{int(time.time())}.json"
        
        # Guardar en el mismo directorio 'reports' que el reporte HTML
        reports_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "reports")
        os.makedirs(reports_dir, exist_ok=True)
        json_path = os.path.join(reports_dir, json_filename)
        
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, ensure_ascii=False, indent=4)
        print(Fore.GREEN + f"📁 Reporte JSON generado: {json_path}\n")
    except Exception as e:
        print(Fore.YELLOW + f"⚠️ No se pudo generar el reporte JSON: {e}\n")
    
    if not no_open:
        try:
            import webbrowser
            webbrowser.open("file://" + os.path.abspath(html_path).replace("\\", "/"))
            print(" Reporte abierto automáticamente en tu navegador.\n")
        except Exception as e:
            print(f"⚠️ No se pudo abrir el navegador automáticamente: {e}\n")
