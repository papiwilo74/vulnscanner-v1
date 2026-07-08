import sys
if sys.platform.startswith('win'):
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except:
        pass

import requests
import time
from scanner.headers import check_headers
from scanner.https_check import check_https
from scanner.cookies import check_cookies
from scanner.directories import check_directories
from scanner.xss import check_xss
from scanner.sqli import check_sqli
from scanner.ai_check import check_with_ai
from scanner.ports import check_ports
from scanner.forms import check_forms
from scanner.cors import check_cors
from scanner.ssl_check import check_ssl
from scanner.sensitive_data import check_sensitive_data
from scanner.crawler import crawl_site
from scanner.fuzzer import check_exposed_files
from scanner.injections import check_injections
from scanner.subdomains import check_subdomains
from utils.report import print_report
from utils.stealth import apply_stealth_headers, polite_delay, create_stealth_session
from utils.renderer import render_page, is_playwright_available

import argparse


def build_session(cookie_str=None, auth_header=None):
    """Crea y configura un requests.Session con credenciales opcionales.
    
    Args:
        cookie_str: Cadena de cookies en formato "nombre=valor; nombre2=valor2"
        auth_header: Valor de la cabecera Authorization (ej. "Bearer token123")
    
    Returns:
        requests.Session configurado, o None si no hay credenciales.
    """
    if not cookie_str and not auth_header:
        return None

    session = requests.Session()

    if cookie_str:
        # Parsear "nombre=valor; nombre2=valor2" a un dict de cookies
        for pair in cookie_str.split(';'):
            pair = pair.strip()
            if '=' in pair:
                name, value = pair.split('=', 1)
                session.cookies.set(name.strip(), value.strip())
        print(f"  🔑 Sesión configurada con {len(session.cookies)} cookie(s)")

    if auth_header:
        session.headers.update({'Authorization': auth_header})
        print(f"  🔑 Sesión configurada con cabecera Authorization")

    return session


def scan(url, no_open=False, cookie_str=None, auth_header=None, crawl_pages=1, run_subdomains=False, delay=0.0, stealth=False, passive=False):
    print(f"\n Escaneando: {url}\n")
    if passive:
        print("  🛡️  Modo Pasivo (No Intrusivo) ACTIVADO — Solo análisis pasivo, SIN envío de payloads de ataque (XSS/SQLi/Inyecciones omitidos).\n")
    if stealth:
        print("  🥷 Modo Sigiloso (Stealth) ACTIVADO — Retardos aleatorios + cabeceras de navegador real.\n")
    elif delay > 0:
        print(f"  ⏱️  Rate Limiting: {delay}s de retardo entre peticiones.\n")

    if is_playwright_available():
        print("  🎭 Renderizado JS (Playwright) disponible — se extraerán formularios y rutas de SPAs.\n")
    else:
        print("  💡 Tip: instala Playwright para detectar formularios/rutas generados por JS en SPAs.\n      pip install playwright && playwright install chromium\n")

    all_results = []

    # Configurar sesión con perfil de navegador real
    if stealth:
        # En modo stealth, siempre usamos una sesión con cabeceras realistas
        session = build_session(cookie_str, auth_header)
        if session is None:
            import requests as req_module
            session = req_module.Session()
        apply_stealth_headers(session)
    else:
        session = build_session(cookie_str, auth_header)

    client = session if session is not None else requests

    start_time = time.time()

    # 1. Escaneo de Subdominios (Si está habilitado)
    if run_subdomains:
        all_results += check_subdomains(url)

    # 2. Rastreo de Páginas (Crawler)
    target_urls = [url]
    if crawl_pages > 1:
        target_urls = crawl_site(url, max_pages=crawl_pages, session=session)

    # 3. Fuzzing de Archivos Sensibles (Una vez por host)
    print("   Búsqueda de archivos sensibles expuestos...")
    all_results += check_exposed_files(url, session=session)

    # 4. Certificados y Configuración de SSL/TLS (Una vez por host)
    print("   Certificado SSL/TLS...")
    all_results += check_ssl(url, session=session)

    # 5. Puertos expuestos (Una vez por host)
    print("   Escaneando puertos y servicios expuestos...")
    all_results += check_ports(url)

    # 6. Escanear cada página descubierta
    for page_url in target_urls:
        # Aplicar retardo antes de cada página para no parecer un bot agresivo
        polite_delay(delay=delay, stealth=stealth)
        print(f"\n 📄 Analizando página: {page_url}")
        try:
            response = client.get(page_url, timeout=10)
        except Exception as e:
            print(f"   ⚠️ Error conectando a {page_url}: {e}")
            continue

        print("   Headers...")
        all_results += check_headers(response)

        print("   HTTPS...")
        all_results += check_https(page_url, response)

        print("   Cookies...")
        all_results += check_cookies(response)

        print("   Directorios expuestos...")
        all_results += check_directories(page_url, session=session)

        # Renderizado JS opcional (Playwright) para ver formularios y DOM de SPAs
        rendered_html, rendered_links = render_page(page_url)
        if rendered_html is not None:
            print("   🎭 Usando HTML renderizado (Playwright) para análisis DOM")
            dom_html = rendered_html
        else:
            dom_html = response.text

        print("   XSS reflejado y DOM...")
        all_results += check_xss(page_url, html_content=dom_html, session=session, passive=passive)

        if not passive:
            print("   SQL Injection...")
            all_results += check_sqli(page_url, session=session)

        print("   Formularios y CSRF...")
        all_results += check_forms(page_url, dom_html, session=session, passive=passive)

        print("   Configuración de CORS...")
        all_results += check_cors(page_url, session=session)

        if not passive:
            print("   Inyecciones avanzadas (Comandos / SSTI)...")
            all_results += check_injections(page_url, session=session)

        print("   Exposición de datos sensibles...")
        all_results += check_sensitive_data(page_url, html_content=dom_html, session=session)

        print("   Análisis de IA en parámetros...")
        all_results += check_with_ai(page_url)

    duration = time.time() - start_time
    print_report(url, all_results, duration, no_open=no_open)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="VulnScanner — Escáner de vulnerabilidades web",
        epilog="Ejemplo: python main.py https://ejemplo.com --cookie 'session=abc123' --crawl 5 --subdomains"
    )
    parser.add_argument("url", help="URL del sitio web a escanear")
    parser.add_argument("--no-open", action="store_true",
                        help="Evita abrir el reporte HTML automáticamente en el navegador")
    parser.add_argument("--cookie", type=str, default=None,
                        help="Cookies de sesión en formato 'nombre=valor; nombre2=valor2'")
    parser.add_argument("--auth", type=str, default=None,
                        help="Cabecera Authorization (ej. 'Bearer mi_token' o 'Basic dXN...')")
    parser.add_argument("--crawl", type=int, default=1,
                        help="Número de páginas máximas a rastrear y escanear (por defecto 1)")
    parser.add_argument("--subdomains", action="store_true",
                        help="Habilita la búsqueda y descubrimiento de subdominios activos")
    parser.add_argument("--delay", type=float, default=0.0,
                        help="Retardo en segundos entre peticiones para evitar ser bloqueado (ej. --delay 1.5)")
    parser.add_argument("--stealth", action="store_true",
                        help="Activa el modo sigiloso: retardos aleatorios + cabeceras de navegador real para no parecer un bot")
    parser.add_argument("--passive", action="store_true",
                        help="Modo pasivo (no intrusivo): omite el envío de payloads de ataque (XSS/SQLi/Inyecciones). Solo analiza cabeceras, HTML/JS, certificados y configuración sin atacar el sitio")

    args = parser.parse_args()
    scan(
        args.url,
        no_open=args.no_open,
        cookie_str=args.cookie,
        auth_header=args.auth,
        crawl_pages=args.crawl,
        run_subdomains=args.subdomains,
        delay=args.delay,
        stealth=args.stealth,
        passive=args.passive
    )