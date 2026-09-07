import argparse
import contextlib
import logging
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import partial
from typing import Any, Optional

import requests

from scanner.ai_check import check_with_ai
from scanner.auth_helper import dynamic_login, headless_browser_login
from scanner.autofix import TechFingerprinter, enrich_findings_with_autofix
from scanner.cookies import check_cookies
from scanner.cors import check_cors
from scanner.crawler import crawl_site
from scanner.directories import check_directories
from scanner.dom_xss import check_dom_xss
from scanner.engine import ScanConfig, ScanEngine, ScanProfile
from scanner.file_upload import check_file_upload
from scanner.forms import check_forms
from scanner.fuzzer import check_exposed_files
from scanner.graphql import check_graphql
from scanner.har_parser import HARSessionParser
from scanner.headers import check_headers
from scanner.https_check import check_https
from scanner.injections import check_injections
from scanner.jwt_attacks import check_jwt_attacks
from scanner.models import Finding, deduplicate_findings
from scanner.oast import check_oast_vulnerabilities
from scanner.open_redirect import check_open_redirect
from scanner.path_traversal import check_path_traversal
from scanner.ports import check_ports
from scanner.prototype_pollution import check_prototype_pollution
from scanner.sca import check_sca
from scanner.sensitive_data import check_sensitive_data
from scanner.sqli import check_sqli
from scanner.ssl_check import check_ssl
from scanner.subdomains import check_subdomains
from scanner.websocket import check_websocket
from scanner.xss import check_xss
from scanner.xxe import check_xxe
from utils.renderer import is_playwright_available, render_page
from utils.report import print_report
from utils.stealth import apply_stealth_headers, polite_delay, stealth_check_delay

if sys.platform.startswith('win'):
    with contextlib.suppress(Exception):
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding='utf-8')

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S"
)
logger = logging.getLogger("VulnScanner")

CATEGORY_MAP: dict[str, str] = {
    "headers": "headers",
    "https": "ssl",
    "cookies": "cookies",
    "directories": "directories",
    "xss": "xss",
    "dom_xss": "dom_xss",
    "forms": "csrf",
    "cors": "cors",
    "sensitive_data": "sensitive_data",
    "sca": "sca",
    "path_traversal": "path_traversal",
    "xxe": "xxe",
    "open_redirect": "open_redirect",
    "jwt": "jwt",
    "file_upload": "file_upload",
    "prototype_pollution": "prototype_pollution",
    "graphql": "graphql",
    "websocket": "websocket",
    "ai": "ai",
    "sqli": "sqli",
    "injections": "injections",
    "subdomains": "subdomains",
    "fuzzer": "sensitive_data",
    "ssl": "ssl",
    "ports": "ports",
    "oast": "oast",
}

def _legacy_to_findings(legacy_list: list[dict], category: str, url: str) -> list[Finding]:
    return Finding.from_legacy_list(legacy_list, category, url)

def build_session(cookie_str: Optional[str] = None, auth_header: Optional[str] = None) -> Optional[requests.Session]:
    if not cookie_str and not auth_header:
        return None
    session = requests.Session()
    if cookie_str:
        for pair in cookie_str.split(';'):
            pair = pair.strip()
            if '=' in pair:
                name, value = pair.split('=', 1)
                session.cookies.set(name.strip(), value.strip())
        logger.info("Sesión configurada con %d cookie(s)", len(session.cookies))
    if auth_header:
        session.headers.update({'Authorization': auth_header})
        logger.info("Sesión configurada con cabecera Authorization")
    return session

def _scan_single_page(page_url: str, cookie_str: Optional[str] = None, auth_header: Optional[str] = None,
                       stealth: bool = False, delay: float = 0.0, passive: bool = False,
                       enable_oast: bool = True, engine: Optional[ScanEngine] = None,
                       active_session: Optional[requests.Session] = None) -> tuple[list[Finding], dict, str]:
    session: requests.Session
    if active_session is not None:
        session = active_session
    else:
        built = build_session(cookie_str, auth_header)
        session = built if built is not None else requests.Session()

    if stealth:
        apply_stealth_headers(session)

    polite_delay(delay=delay, stealth=stealth)
    if engine and engine.is_cancelled:
        return [], {}, ""
    if engine and engine.is_duplicate(page_url):
        logger.info("URL duplicada, omitiendo: %s", page_url)
        return [], {}, ""

    if engine:
        engine.ratelimit()
    engine.record_request(page_url, "GET") if engine else None

    logger.info("Analizando página: %s", page_url)
    try:
        response = session.get(page_url, timeout=10)
        resp_headers = dict(response.headers)
    except Exception as e:
        logger.warning("Error conectando a %s: %s", page_url, e)
        return [], {}, ""

    if engine:
        engine.record_request(page_url, "GET", response.status_code)

    rendered_html, rendered_links = render_page(page_url)
    dom_html = rendered_html if rendered_html is not None else response.text

    # Detección de Stack Tecnológico para Auto-Fix
    detected_tech = TechFingerprinter.detect_stack(resp_headers, dom_html, dict(response.cookies))

    def _task(name, category, fn, *args, **kwargs):
        if engine and not engine.check_limits():
            return []
        if engine:
            engine.ratelimit()
        try:
            logger.info("  %s...", name)
            raw = fn(*args, **kwargs)
            if raw and isinstance(raw[0], Finding):
                return raw
            return _legacy_to_findings(raw, category, page_url)
        except Exception as e:
            logger.warning("  Error en %s: %s", name, e)
            return []

    tasks: list[tuple[Any, ...]] = [
        ("Headers", "headers", check_headers, response),
        ("HTTPS", "ssl", check_https, page_url, response),
        ("Cookies", "cookies", check_cookies, response),
        ("Directorios expuestos", "directories", check_directories, page_url, session),
        ("XSS reflejado", "xss", check_xss, page_url, None, session, passive),
        ("DOM-based XSS", "dom_xss", check_dom_xss, page_url, dom_html),
        ("Formularios y CSRF", "forms", check_forms, page_url, dom_html, session, passive),
        ("CORS", "cors", check_cors, page_url, session),
        ("Datos sensibles", "sensitive_data", check_sensitive_data, page_url, dom_html, session),
        ("SCA", "sca", check_sca, page_url, dom_html, session),
        ("Path Traversal", "path_traversal", check_path_traversal, page_url, session),
        ("XXE", "xxe", check_xxe, page_url, dom_html, session),
        ("Open Redirect", "open_redirect", check_open_redirect, page_url, session),
        ("JWT Attacks", "jwt", check_jwt_attacks, page_url, dom_html, session),
        ("File Upload", "file_upload", check_file_upload, page_url, dom_html, session),
        ("Prototype Pollution", "prototype_pollution", check_prototype_pollution, page_url, dom_html, session),
        ("GraphQL", "graphql", check_graphql, page_url, session),
        ("WebSocket", "websocket", check_websocket, page_url, dom_html, session),
        ("IA en parámetros", "ai", check_with_ai, page_url),
    ]

    if not passive:
        tasks.append(("SQL Injection", "sqli", check_sqli, page_url, session))
        tasks.append(("Inyecciones (Comandos/SSTI)", "injections", check_injections, page_url, session))
        if enable_oast:
            tasks.append(("OAST (Blind SSRF / RCE / Log4j)", "oast", check_oast_vulnerabilities, page_url, session))

    results: list[Finding] = []

    if stealth:
        for name, category, fn, *args in tasks:
            stealth_check_delay(stealth=True)
            results += _task(name, category, fn, *args)
    else:
        max_workers = engine.config.max_workers if engine else len(tasks)
        with ThreadPoolExecutor(max_workers=min(max_workers, len(tasks))) as executor:
            futures = {
                executor.submit(_task, name, category, fn, *args): name
                for name, category, fn, *args in tasks
            }
            for future in as_completed(futures):
                results += future.result()

    # Enriquecer con parches automáticos según el stack tecnológico detectado
    results = enrich_findings_with_autofix(results, detected_tech)

    return results, resp_headers, dom_html

SCAN_STATS = {"total_requests": 0}

def scan(url: str, no_open: bool = False, cookie_str: Optional[str] = None,
         auth_header: Optional[str] = None, crawl_pages: int = 1, run_subdomains: bool = False,
         delay: float = 0.0, stealth: bool = False, passive: bool = False,
         enable_oast: bool = True, login_url: Optional[str] = None, login_creds: Optional[str] = None,
         profile: str = "normal", allow_private: bool = False,
         har_file: Optional[str] = None, headless_crawl: bool = False,
         headless_login: bool = False) -> tuple:
    profile_enum = ScanProfile(profile)
    config = ScanConfig.from_profile(
        profile_enum, target=url,
        cookie=cookie_str, auth_header=auth_header,
        stealth=stealth,
        login_url=login_url,
        login_creds=login_creds,
        allow_private=allow_private,
    )
    if delay > 0:
        config.delay = delay
        config.max_rps = int(1.0 / delay)
    if passive:
        config.active_payloads = False

    engine = ScanEngine(config)
    try:
        engine.start()
    except ValueError as e:
        logger.error("Error de configuración: %s", e)
        return None, None, {"error": str(e)}

    logger.info("Escaneando: %s [perfil: %s]", url, profile_enum.value)
    if passive:
        logger.info("[PASSIVE] Modo Pasivo (No Intrusivo) - Solo análisis pasivo.")
    if stealth:
        logger.info("[STEALTH] Rate-limiting activado - Retardos aleatorios + cabeceras reales.")
    elif delay > 0:
        logger.info("[RATE] Rate Limiting: %.1fs de retardo entre peticiones.", delay)
    if enable_oast and not passive:
        logger.info("[OAST] Detección Fuera de Banda (Out-of-Band AST) ACTIVADA.")

    if is_playwright_available():
        logger.info("[JS] Renderizado JS y Headless Crawler (Playwright) DISPONIBLE.")
    else:
        logger.info("[TIP] Instala Playwright para crawling de SPAs: pip install playwright && playwright install chromium")

    all_findings: list[Finding] = []
    global_tech_stack: set[str] = set()

    session = None

    # 1. Autenticación desde archivo HAR si se especifica
    har_discovered_urls: set[str] = set()
    if har_file:
        logger.info("[HAR] Cargando sesión grabada desde archivo: %s", har_file)
        try:
            har_parser = HARSessionParser.from_file(har_file)
            session = har_parser.create_session()
            har_discovered_urls = har_parser.discovered_urls
            logger.info("[HAR] Importación exitosa. %d URLs y APIs recuperadas del HAR.", len(har_discovered_urls))
        except Exception as e:
            logger.warning("[HAR] Error al procesar archivo HAR: %s", e)

    # 2. Login dinámico o headless si se especifica
    if session is None and login_url and login_creds:
        if headless_login:
            auth_session = headless_browser_login(login_url, login_creds)
        else:
            auth_session = dynamic_login(login_url, login_creds)
        if auth_session is not None:
            session = auth_session

    if stealth:
        if session is None:
            session = build_session(cookie_str, auth_header)
        if session is None:
            import requests as req_module
            session = req_module.Session()
        apply_stealth_headers(session)
    elif session is None:
        session = build_session(cookie_str, auth_header)

    if run_subdomains and not engine.is_cancelled:
        raw = check_subdomains(url)
        all_findings += _legacy_to_findings(raw, "subdomains", url)

    target_urls = [url]
    if har_discovered_urls:
        # Priorizar URLs del mismo host encontradas en el HAR
        from urllib.parse import urlparse
        base_domain = urlparse(url).netloc
        har_matching = [u for u in har_discovered_urls if urlparse(u).netloc == base_domain]
        if har_matching:
            target_urls = har_matching[:min(crawl_pages * 2, config.max_crawl_pages)]

    if crawl_pages > 1 and not engine.is_cancelled and not har_discovered_urls:
        target_urls = crawl_site(
            url,
            max_pages=min(crawl_pages, config.max_crawl_pages),
            session=session,
            use_headless=headless_crawl
        )

    if not engine.is_cancelled:
        logger.info("Búsqueda de archivos sensibles expuestos...")
        raw = check_exposed_files(url, session=session)
        all_findings += _legacy_to_findings(raw, "fuzzer", url)

    if not engine.is_cancelled:
        logger.info("Certificado SSL/TLS...")
        raw = check_ssl(url, session=session)
        all_findings += _legacy_to_findings(raw, "ssl", url)

    if not engine.is_cancelled:
        logger.info("Escaneando puertos y servicios expuestos...")
        raw = check_ports(url)
        all_findings += _legacy_to_findings(raw, "ports", url)

    if target_urls and not engine.is_cancelled:
        logger.info("Escaneando %d página(s) en paralelo...", len(target_urls))
        scan_func = partial(
            _scan_single_page,
            cookie_str=cookie_str,
            auth_header=auth_header,
            stealth=stealth,
            delay=delay,
            passive=passive,
            enable_oast=enable_oast,
            engine=engine,
            active_session=session
        )
        max_workers = min(len(target_urls), config.max_workers)
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(scan_func, u): u for u in target_urls}
            for future in as_completed(futures):
                try:
                    page_findings, p_headers, p_html = future.result()
                    all_findings += page_findings
                    stack = TechFingerprinter.detect_stack(p_headers, p_html)
                    global_tech_stack.update(stack)
                except Exception as e:
                    logger.warning("Error escaneando %s: %s", futures[future], e)
                if engine.is_cancelled:
                    break

    # Consolidación y Auto-Fix final
    all_findings = deduplicate_findings(all_findings)
    all_findings = enrich_findings_with_autofix(all_findings, list(global_tech_stack))

    engine_summary = engine.get_summary()
    SCAN_STATS["total_requests"] = engine.request_count

    return print_report(url, all_findings, engine.elapsed, no_open=no_open, engine_summary=engine_summary)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="VulnScanner Enterprise — Escáner de vulnerabilidades web con OAST, SARIF, Auto-Fix y Headless Crawling",
        epilog="Ejemplo: python main.py https://ejemplo.com --profile normal --crawl 5 --headless-crawl"
    )
    parser.add_argument("url", help="URL del sitio web a escanear")
    parser.add_argument("--no-open", action="store_true",
                        help="Evita abrir el reporte HTML automáticamente")
    parser.add_argument("--cookie", type=str, default=None,
                        help="Cookies de sesión en formato 'nombre=valor; nombre2=valor2'")
    parser.add_argument("--auth", type=str, default=None,
                        help="Cabecera Authorization (ej. 'Bearer mi_token')")
    parser.add_argument("--crawl", type=int, default=1,
                        help="Número máximo de páginas a rastrear")
    parser.add_argument("--subdomains", action="store_true",
                        help="Habilita búsqueda de subdominios activos")
    parser.add_argument("--delay", type=float, default=0.0,
                        help="Retardo fijo en segundos entre peticiones")
    parser.add_argument("--stealth", action="store_true",
                        help="Rate-limiting con User-Agent rotativo y retardos aleatorios")
    parser.add_argument("--passive", action="store_true",
                        help="Modo pasivo: solo análisis sin envío de payloads")
    parser.add_argument("--no-oast", action="store_true",
                        help="Deshabilita las pruebas Out-of-Band (OAST)")
    parser.add_argument("--profile", type=str, default="normal",
                        choices=["passive", "normal", "aggressive"],
                        help="Perfil de escaneo: passive, normal, aggressive (defecto: normal)")
    parser.add_argument("--allow-private", action="store_true",
                        help="Permite escanear IPs privadas (10.x, 192.168.x, etc.)")
    parser.add_argument("--login-url", type=str, default=None,
                        help="URL del endpoint de login para autenticación dinámica")
    parser.add_argument("--login-creds", type=str, default=None,
                        help="Credenciales en formato 'campo=valor;campo2=valor2'")
    parser.add_argument("--har", type=str, default=None,
                        help="Ruta a archivo .har (HTTP Archive) para reproducir sesión autenticada")
    parser.add_argument("--headless-crawl", action="store_true",
                        help="Habilita rastreador headless dinámico con Playwright para SPAs")
    parser.add_argument("--headless-login", action="store_true",
                        help="Usa navegador headless interactivo para resolver el login")

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
        passive=args.passive,
        enable_oast=not args.no_oast,
        login_url=args.login_url,
        login_creds=args.login_creds,
        profile=args.profile,
        allow_private=args.allow_private,
        har_file=args.har,
        headless_crawl=args.headless_crawl,
        headless_login=args.headless_login,
    )
