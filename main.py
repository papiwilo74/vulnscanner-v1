import argparse
import contextlib
import logging
import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import partial
from typing import Any, Callable, Optional

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
from utils.github_pr import GitHubPRClient
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
logger = logging.getLogger("OmniBreach")

OMNIBREACH_BANNER = (
    "\n"
    r"   ____                  _ ____                       _    " + "\n"
    r"  / __ \____ ___  ____  (_) __ )________  ____ ______/ /_  " + "\n"
    r" / / / / __ `__ \/ __ \/ / __  / ___/ _ \/ __ `/ ___/ __ \ " + "\n"
    r"/ /_/ / / / / / / / / / / /_/ / /  /  __/ /_/ / /__/ / / / " + "\n"
    r"\____/_/ /_/ /_/_/ /_/_/_____/_/   \___/\__,_/\___/_/ /_/  " + "\n"
    "                      v3.0 EASM\n"
)

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

def _legacy_to_findings(legacy_list: list[dict[str, Any]], category: str, url: str) -> list[Finding]:
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
                       active_session: Optional[requests.Session] = None) -> tuple[list[Finding], dict[str, Any], str]:
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

    resp_headers: dict[str, Any] = {}
    try:
        response = session.get(page_url, timeout=10)
        resp_headers = dict(response.headers)
    except Exception as e:
        logger.warning("Error accediendo a %s: %s", page_url, e)
        return [], {}, ""

    if engine:
        engine.record_request(page_url, "GET", response.status_code)

    rendered_html, rendered_links = render_page(page_url)
    dom_html = rendered_html if rendered_html is not None else response.text

    # Detección de Stack Tecnológico para Auto-Fix
    detected_tech = TechFingerprinter.detect_stack(resp_headers, dom_html, dict(response.cookies))

    def _task(name: str, category: str, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> list[Finding]:
        if engine and not engine.check_limits():
            return []
        if engine:
            engine.ratelimit()
        try:
            logger.info("  %s...", name)
            raw = fn(*args, **kwargs)
            if raw and isinstance(raw[0], Finding):
                return [r for r in raw if isinstance(r, Finding)]
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
         headless_login: bool = False, openapi_spec: Optional[str] = None,
         use_async_engine: bool = False, no_waf_detect: bool = False,
         iast_url: Optional[str] = None, attack_chain: bool = True,
         generate_pdf: bool = False, auto_pr: bool = False,
         github_repo: Optional[str] = None, github_token: Optional[str] = None,
         base_branch: str = "main",
         progress_callback: Optional[Any] = None) -> tuple[Optional[str], Optional[str], dict[str, Any]]:
    profile_enum = ScanProfile(profile)
    config = ScanConfig.from_profile(
        profile_enum, target=url,
        cookie=cookie_str, auth_header=auth_header,
        stealth=stealth,
        login_url=login_url,
        login_creds=login_creds,
        allow_private=allow_private,
        iast_url=iast_url,
        enable_attack_chain=attack_chain,
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

    # 3. Detección Inteligente de WAF y adaptación perimetral
    if not no_waf_detect and not engine.is_cancelled:
        logger.info("Detectando presencia de WAF o protección perimetral...")
        try:
            from scanner.waf_detector import WAFDetector
            waf_detector = WAFDetector(session=session)
            waf_res = waf_detector.detect(url)
            if waf_res.detected:
                engine.waf_detected = True
                waf_finding = waf_detector.to_finding(url, waf_res)
                if waf_finding:
                    all_findings.append(waf_finding)
                logger.info("[WAF] %s detectado (%s). Activando rate limiting adaptativo.", waf_res.waf_name, waf_res.evidence)
        except Exception as e:
            logger.debug("Error detectando WAF: %s", e)

    # 4. Auditoría guiada por especificación OpenAPI / Swagger
    if openapi_spec and not engine.is_cancelled:
        logger.info("[OpenAPI] Iniciando auditoría guiada por especificación: %s", openapi_spec)
        try:
            from scanner.openapi_scanner import OpenAPIScanner
            oa_scanner = OpenAPIScanner(spec_source=openapi_spec, base_url=url, session=session, engine=engine)
            oa_findings = oa_scanner.scan()
            all_findings.extend(oa_findings)
            logger.info("[OpenAPI] Auditoría de API completada. %d hallazgo(s) detectado(s).", len(oa_findings))
        except Exception as e:
            logger.warning("[OpenAPI] Error auditando especificación OpenAPI: %s", e)

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
        logger.info("Escaneando %d página(s)...", len(target_urls))
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
        if use_async_engine:
            logger.info("[ASYNC] Despachando escaneo concurrente con httpx/asyncio...")
            import asyncio

            async def _run_async_batch() -> list[Any]:
                loop = asyncio.get_running_loop()
                tasks = [loop.run_in_executor(None, scan_func, u) for u in target_urls]
                res = await asyncio.gather(*tasks, return_exceptions=True)
                return list(res)

            try:
                batch_res = asyncio.run(_run_async_batch())
                for res in batch_res:
                    if isinstance(res, tuple):
                        page_findings, p_headers, p_html = res
                        all_findings += page_findings
                        stack = TechFingerprinter.detect_stack(p_headers, p_html)
                        global_tech_stack.update(stack)
            except Exception as e:
                logger.warning("Error en despachador asíncrono: %s", e)
        else:
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

    # 5. Correlación de telemetría IAST en tiempo de ejecución
    if iast_url:
        enriched_count = engine.correlate_iast(all_findings, session=session)
        if enriched_count > 0:
            logger.info("[IAST] Correlación exitosa: %d hallazgo(s) enriquecido(s) con archivo y línea de código exacta.", enriched_count)

    # 6. Orquestador de Grafos de Ataque y Análisis de Choke Points Defensivos
    attack_graph_dict = None
    if attack_chain and all_findings:
        attack_graph = engine.build_attack_graph(all_findings)
        choke_points = attack_graph.calculate_choke_points()
        if choke_points:
            top_cp = choke_points[0]
            logger.info("[DEFENSA] Choke Point Crítico: '%s' corta %d ruta(s) de ataque hacia impacto final.",
                        top_cp.node_title, top_cp.severed_paths_count)
            logger.info("[DEFENSA] Contramedida recomendada: %s", top_cp.recommended_defense)
        attack_graph_dict = attack_graph.to_dict()

    # 7. Auto-Remediación DevSecOps con GitHub Pull Request
    pr_result = None
    if auto_pr and github_repo and github_token and all_findings:
        try:
            logger.info("[DevSecOps] Iniciando bot de auto-remediación para repositorio '%s'...", github_repo)
            gh_client = GitHubPRClient(token=github_token, repo=github_repo)
            pr_result = gh_client.auto_remediate_and_open_pr(
                findings=all_findings,
                target_url=url,
                base_branch=base_branch,
            )
            if pr_result and "html_url" in pr_result:
                logger.info("[DevSecOps] ✅ Pull Request de seguridad generado: %s", pr_result["html_url"])
        except Exception as e:
            logger.error("[DevSecOps] Error al crear Pull Request en GitHub: %s", e)

    engine_summary = engine.get_summary()
    if attack_graph_dict:
        engine_summary["attack_graph"] = attack_graph_dict
    if pr_result:
        engine_summary["github_pr"] = pr_result
    SCAN_STATS["total_requests"] = engine.request_count

    return print_report(
        url,
        all_findings,
        engine.elapsed,
        no_open=no_open,
        engine_summary=engine_summary,
        generate_pdf=generate_pdf,
    )

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="OmniBreach v3.0 — Suite Defensiva & Ofensiva con EASM (External Attack Surface Management), Telemetría en Vivo, Reportes Ejecutivos PDF, Auto-PR GitHub DevSecOps, IAST/RASP, Grafos de Ataque, Cluster Distribuido y Modo Lab",
        epilog="Ejemplo: python main.py --easm empresa.com.co"
    )
    parser.add_argument("--version", "-V", action="version", version="OmniBreach v3.0")
    parser.add_argument("url", nargs="?", default=None, help="URL del sitio web a escanear")
    parser.add_argument("--easm", type=str, default=None, metavar="DOMINIO",
                        help="Auditoría de Superficie Externa (EASM): Cartografía de subdominios, puertos de ransomware y CISA KEV")
    parser.add_argument("--no-bruteforce", action="store_true",
                        help="Omite la fuerza bruta DNS en el modo EASM (solo consultas pasivas CT logs)")
    parser.add_argument("--runbook", action="store_true",
                        help="Exporta el Runbook Técnico de Remediación a Medida generado por el Asesor de IA")
    parser.add_argument("--web", "--dashboard", "--gui", dest="web_mode", action="store_true",
                        help="Inicia la interfaz web interactiva en tiempo real (SOC Dashboard) en el navegador")
    parser.add_argument("--lab", "--offline", dest="lab_mode", action="store_true",
                        help="Modo Laboratorio Aislado: ejecuta un servidor de prueba local hermético para escaneo sin conexión")
    parser.add_argument("--no-open", action="store_true",
                        help="Evita abrir el reporte HTML automáticamente")
    parser.add_argument("--pdf", action="store_true",
                        help="Genera un Reporte Ejecutivo formal en PDF para comités CISO/Dirección")
    parser.add_argument("--auto-pr", action="store_true",
                        help="Genera automáticamente un Pull Request de remediación en GitHub con los parches aplicados")
    parser.add_argument("--github-repo", type=str, default=os.environ.get("GITHUB_REPOSITORY"),
                        help="Repositorio de GitHub en formato 'owner/repo' para Auto-PR")
    parser.add_argument("--github-token", type=str, default=os.environ.get("GITHUB_TOKEN"),
                        help="Token de acceso personal (PAT) de GitHub para Auto-PR")
    parser.add_argument("--base-branch", type=str, default="main",
                        help="Rama base en GitHub sobre la cual abrir el Pull Request (defecto: main)")
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
    parser.add_argument("--openapi", type=str, default=None,
                        help="Ruta o URL a especificación OpenAPI/Swagger para auditar endpoints de API")
    parser.add_argument("--async-engine", action="store_true",
                        help="Habilita motor asíncrono httpx/asyncio de ultra alto rendimiento")
    parser.add_argument("--no-waf-detect", action="store_true",
                        help="Deshabilita la detección automática de WAF")
    parser.add_argument("--iast-url", type=str, default=None,
                        help="URL base del servidor instrumentado con agente IAST/RASP para correlación en memoria")
    parser.add_argument("--no-attack-chain", action="store_true",
                        help="Deshabilita el modelado de Grafos de Ataque y análisis de Choke Points defensivos")
    parser.add_argument("--full", "--all", dest="full", action="store_true",
                        help="Modo Todo-en-Uno: activa crawling (10 páginas), subdominios, stealth, detección WAF, grafos de ataque y auto-detección de OpenAPI e IAST")
    parser.add_argument("--deception-generate", action="store_true",
                        help="Genera un pack de señuelos HoneyTokens / Canaries activos (URLs, API Keys, JWT)")
    parser.add_argument("--deception-alerts", action="store_true",
                        help="Consulta y lista las alertas de intrusión y detonaciones de trampas activas")
    parser.add_argument("--worker", action="store_true",
                        help="Inicia la instancia como un nodo worker de escaneo distribuido")
    parser.add_argument("--coordinator", type=str, default="http://localhost:8000",
                        help="URL del servidor API coordinador para workers (defecto: http://localhost:8000)")
    parser.add_argument("--region", type=str, default="local",
                        help="Identificador geográfico o cloud de la región del worker (ej. us-east-1, eu-central-1, local)")
    parser.add_argument("--tenant", type=str, default="org_default",
                        help="ID de organización tenant para el escaneo (defecto: org_default)")

    args = parser.parse_args()
    if not args.worker:
        print(OMNIBREACH_BANNER)

    if args.worker:
        from scanner.cluster import ScanningWorkerDaemon
        worker = ScanningWorkerDaemon(
            coordinator_url=args.coordinator,
            region=args.region,
        )
        print("\n" + "=" * 70)
        print(" [🌐 CLUSTER DISTRIBUIDO] INICIANDO NODO WORKER DE ESCANEO")
        print("=" * 70)
        print(f" ID Worker: {worker.worker_id} | Región: {worker.region}")
        print(f" Coordinador: {worker.coordinator_url}")
        print(" Esperando y procesando tareas de escaneo en segundo plano (Ctrl+C para salir)...")
        print("=" * 70 + "\n")
        worker.start()
        try:
            import time
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            worker.stop()
            print("\n[WORKER] Nodo detenido limpiamente.")
            sys.exit(0)

    if args.easm:
        clean_target = args.easm.strip()
        if not clean_target or " " in clean_target:
            print("\n[EASM ERROR] Debes proporcionar un dominio corporativo válido (ej: python main.py --easm empresa.com.co)")
            sys.exit(1)

        try:
            from scanner.easm.engine import EASMEngine
            easm_engine = EASMEngine()
            print("\n" + "=" * 75)
            print(f" [🌐 EASM SCOUT] CARTOGRAFÍA & SUPERFICIE DE ATAQUE EXTERNA: {clean_target}")
            print("=" * 75)
            report = easm_engine.run_full_surface_assessment(
                clean_target,
                include_bruteforce=not args.no_bruteforce
            )
            print(f"\n Calificación de Exposición: {report.exposure_grade} ({report.exposure_score}/100)")
            print(f" Activos Totales Descubiertos: {report.total_assets}")
            print(f" Servicios Expuestos: {report.total_exposed_services}")
            print(f" Vectores de Ransomware (RDP, SMB, DBs): {report.critical_ransomware_vectors}")
            print(f" Alertas CISA KEV (Exploits Activos): {report.cisa_kev_alerts}")
            print(f" Secuestros de Subdominio (Takeover): {len(report.takeovers)}")
            print(f" Fugas de Secretos en Repositorios (OSINT): {len(report.secret_leaks)}")
            print("-" * 75)
            if report.services:
                print(" SERVICIOS Y PUERTOS CRÍTICOS EXPUESTOS:")
                for s in report.services:
                    crit_flag = "🚨 [CRÍTICO]" if s["severity"] == "CRITICAL" else f"[{s['severity']}]"
                    print(f"   * {crit_flag} {s['host']} ({s['ip']}) -> Puerto {s['port']} ({s['service_name']})")
                    if s["unauthenticated_access"]:
                        print(f"     ⚠️ ACCESO NO AUTENTICADO DETECTADO: {s['evidence']}")
                    elif s["banner"]:
                        print(f"     Banner: {s['banner'][:80]}")
                print("-" * 75)
            if report.takeovers:
                print(" 🚨 ALERTA: SUBDOMAIN TAKEOVER CONFIRMADOS:")
                for to_item in report.takeovers:
                    print(f"   * 💥 {to_item['subdomain']} -> CNAME: {to_item['cname']} ({to_item['service_name']})")
                    print(f"     Firma detectada: {to_item['fingerprint_detected']}")
                    print(f"     Mitigación: {to_item['remediation']}")
                print("-" * 75)
            if report.secret_leaks:
                print(" 🔑 ALERTA: FUGAS DE SECRETOS EN REPOSITORIOS PÚBLICOS:")
                for sec in report.secret_leaks:
                    print(f"   * ⚠️ {sec['secret_type']} ({sec['masked_value']}) en {sec['source_repository']}")
                    print(f"     Acción: {sec['remediation']}")
                print("-" * 75)
            if report.cves:
                print(" ALERTA CISA KEV — VULNERABILIDADES ACTIVAMENTE EXPLOTADAS:")
                for c in report.cves:
                    print(f"   * 💥 {c['cve_id']} - {c['vulnerability_name']}")
                    print(f"     Afecta: {c['affected_product']} (Campaña: {c['ransomware_campaign']})")
                    print(f"     Remediación: {c['remediation_steps']}")
                print("-" * 75)
            if report.identity_risk.get("typosquatting_detected"):
                print(" RIESGO DE IDENTIDAD & TYPOSQUATTING (Phishing):")
                for typo in report.identity_risk["typosquatting_detected"]:
                    print(f"   * ⚠️ Dominio suplantador activo: {typo['domain']} ({typo['ip']})")
                print("-" * 75)

            if args.runbook or report.critical_ransomware_vectors > 0 or report.takeovers:
                rb = report.remediation_runbook
                print(" 🛡️ ASESOR DE IA: RUNBOOK TÉCNICO DE REMEDIACIÓN A MEDIDA:")
                print(f"   Motor: {rb.get('generated_by', 'OmniBreach AI')}")
                print(f"   Resumen: {rb.get('executive_summary', '')}")
                if rb.get("immediate_actions"):
                    print("   Acciones Inmediatas (P0):")
                    for act in rb["immediate_actions"]:
                        print(f"     - [!] {act}")
                if rb.get("executable_scripts"):
                    print("   Comandos de Mitigación Listos para Ejecutar:")
                    for sname, scode in rb["executable_scripts"].items():
                        print(f"     [{sname}]:\n       " + scode.replace("\n", "\n       "))
                print("-" * 75)
            print()
            sys.exit(0)
        except KeyboardInterrupt:
            print("\n\n[EASM] Auditoría cancelada por el usuario.")
            sys.exit(130)
        except Exception as err:
            print(f"\n[EASM ERROR] Fallo inesperado durante la auditoría: {err}")
            sys.exit(1)

    if args.deception_generate:
        from scanner.deception import DeceptionManager, SnippetGenerator
        mgr = DeceptionManager()
        t1 = mgr.create_trap("url", "Ruta Secreta Admin Vault")
        t2 = mgr.create_trap("api_key", "Stripe Production Live Secret")
        t3 = mgr.create_trap("jwt_token", "JWT Superadmin Token")
        print("\n" + "=" * 70)
        print(" [🛡️ DECEPTION ENGINE] PACK DE SEÑUELOS GENERADO EXITOSAMENTE")
        print("=" * 70)
        for t in [t1, t2, t3]:
            s = SnippetGenerator.generate_snippet(t)
            print(f"\n📌 Tipo: {t.trap_type.upper()} | Etiqueta: {t.label}")
            print(f"   ID Trampa: {t.id}")
            print(f"   Valor Señuelo: {t.token_value}")
            print(f"   Dónde colocar: {s['placement']}")
            print(f"   Código a insertar:\n{s['code']}")
            print("-" * 70)
        print("\n💡 Cualquier acceso a estos señuelos generará alertas inmediatas en tiempo real.")
        print(f"   Base de datos de trampas: {mgr.db_path}\n")
        sys.exit(0)

    if args.deception_alerts:
        from scanner.deception import DeceptionManager
        mgr = DeceptionManager()
        events = mgr.list_events(limit=50)
        stats = mgr.get_stats()
        print("\n" + "=" * 70)
        print(" [🚨 DECEPTION ENGINE] HISTORIAL DE INTRUSIONES & CANARIOS DETONADOS")
        print("=" * 70)
        print(f" Trampas Activas: {stats['active_traps']}/{stats['total_traps']} | Intrusiones Totales: {stats['total_intrusions_detected']} | IPs Únicas: {stats['unique_attackers']}")
        print("-" * 70)
        if not events:
            print(" ✅ No se han detectado intrusiones ni accesos a señuelos todavía.")
        else:
            for ev in events:
                print(f" [!] {ev.timestamp} | {ev.http_method} {ev.requested_path}")
                print(f"     IP Atacante: {ev.attacker_ip} | Trampa: {ev.trap_label} ({ev.trap_type})")
                print(f"     User-Agent: {ev.user_agent}")
                if ev.payload_sample:
                    print(f"     Payload: {ev.payload_sample[:120]}")
                print("-" * 70)
        print()
        sys.exit(0)

    if args.web_mode:
        import webbrowser

        import uvicorn
        web_url = "http://localhost:8000/dashboard"
        logger.info("[WEB] Iniciando Servidor Web y Panel SOC en %s ...", web_url)
        with contextlib.suppress(Exception):
            webbrowser.open(web_url)
        uvicorn.run("api:app", host="127.0.0.1", port=8000, reload=False)
        sys.exit(0)

    lab_server = None
    if args.lab_mode:
        from scanner.lab_server import LabServer
        lab_server = LabServer()
        args.url = lab_server.start()
        args.allow_private = True
        logger.info("[LAB MODE] Servidor de pruebas hermético iniciado en %s", args.url)

    if not args.url:
        parser.print_help()
        sys.exit(1)

    if args.full:
        logger.info("[TODO-EN-UNO] Modo --full activado: Ejecutando suite completa de auditoría empresarial...")
        if args.crawl == 1:
            args.crawl = 10
        args.subdomains = True
        args.stealth = True
        # Auto-descubrir OpenAPI si el servidor expone contrato
        if not args.openapi:
            session_check = build_session(args.cookie, args.auth) or requests.Session()
            for cand in ["/openapi.json", "/swagger.json", "/api/openapi.json"]:
                cand_url = f"{args.url.rstrip('/')}{cand}"
                try:
                    r = session_check.get(cand_url, timeout=3)
                    if r.status_code == 200 and ("openapi" in r.text.lower() or "swagger" in r.text.lower()):
                        args.openapi = cand_url
                        logger.info("[AUTO-DISCOVERY] Especificación OpenAPI encontrada en: %s", cand_url)
                        break
                except requests.RequestException:
                    continue
        # Auto-descubrir si el servidor tiene agente IAST/RASP activo
        if not args.iast_url:
            session_check = build_session(args.cookie, args.auth) or requests.Session()
            try:
                r = session_check.get(f"{args.url.rstrip('/')}/__vulnscanner_iast__", timeout=2)
                if r.status_code == 200 and "telemetry" in r.text:
                    args.iast_url = args.url
                    logger.info("[AUTO-DISCOVERY] Agente IAST/RASP en memoria detectado en el objetivo.")
            except requests.RequestException:
                pass

    try:
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
            openapi_spec=args.openapi,
            use_async_engine=args.async_engine,
            no_waf_detect=args.no_waf_detect,
            iast_url=args.iast_url,
            attack_chain=not args.no_attack_chain,
            generate_pdf=args.pdf or args.full,
            auto_pr=args.auto_pr,
            github_repo=args.github_repo,
            github_token=args.github_token,
            base_branch=args.base_branch,
        )
    finally:
        if lab_server:
            lab_server.stop()
            logger.info("[LAB MODE] Servidor de pruebas hermético detenido.")
