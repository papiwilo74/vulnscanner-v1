import contextlib
import logging
import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import partial
from pathlib import Path
from typing import Any, Callable, Optional

import requests

from cli import build_cli_parser, dispatch_cli
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
from scanner.param_fuzzer import check_param_fuzzer, discover_parameters
from scanner.path_traversal import check_path_traversal
from scanner.ports import check_ports
from scanner.prototype_pollution import check_prototype_pollution
from scanner.sca import check_sca
from scanner.sensitive_data import check_sensitive_data
from scanner.sqli import check_sqli
from scanner.ssl_check import check_ssl
from scanner.subdomains import check_subdomains
from scanner.template_engine import TemplateEngine
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
    "                             v3.10\n"
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
    "param_fuzzer": "sensitive_data",
    "template_dsl": "sensitive_data",
}

def check_declarative_templates(target_url: str, session: Optional[requests.Session] = None, templates_dir: Optional[str] = None) -> list[Finding]:
    """Ejecuta plantillas declarativas YAML/JSON contra el objetivo."""
    engine = TemplateEngine(session=session)
    tdir = Path(templates_dir) if templates_dir else (Path(__file__).resolve().parent / "templates_dsl")
    if tdir.is_dir():
        templates = TemplateEngine.load_from_dir(tdir)
        return engine.execute_all(templates, target_url)
    return []

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
        ("XXE", "xxe", check_xxe, page_url, dom_html, session, getattr(engine, "oast_client", None)),
        ("Open Redirect", "open_redirect", check_open_redirect, page_url, session),
        ("JWT Attacks", "jwt", check_jwt_attacks, page_url, dom_html, session),
        ("File Upload", "file_upload", check_file_upload, page_url, dom_html, session),
        ("Prototype Pollution", "prototype_pollution", check_prototype_pollution, page_url, dom_html, session),
        ("GraphQL", "graphql", check_graphql, page_url, session),
        ("WebSocket", "websocket", check_websocket, page_url, dom_html, session),
        ("Plantillas Declarativas DSL", "template_dsl", check_declarative_templates, page_url, session),
        ("IA en parámetros", "ai", check_with_ai, page_url),
    ]

    if not passive:
        tasks.append(("SQL Injection", "sqli", check_sqli, page_url, session))
        tasks.append(("Inyecciones (Comandos/SSTI)", "injections", check_injections, page_url, session))
        tasks.append(("Fuzzing de Parámetros Ocultos", "param_fuzzer", check_param_fuzzer, page_url, session))
        if enable_oast:
            oast_cl = getattr(engine, "oast_client", None)
            tasks.append(("OAST (Blind SSRF / RCE / Log4j)", "oast", check_oast_vulnerabilities, page_url, session, oast_cl))

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
         active_crawl: bool = False, monkey_actions: int = 25,
         headless_login: bool = False, openapi_spec: Optional[str] = None,
         use_async_engine: bool = False, no_waf_detect: bool = False,
         iast_url: Optional[str] = None, attack_chain: bool = True,
         generate_pdf: bool = False, auto_pr: bool = False,
         github_repo: Optional[str] = None, github_token: Optional[str] = None,
         base_branch: str = "main",
         what_if_nodes: Optional[list[str]] = None,
         param_fuzz: bool = False,
         session_macro_file: Optional[str] = None,
         sentinel_url: Optional[str] = None,
         totp_secret: Optional[str] = None,
         oast_server: Optional[str] = None,
         oast_dns_port: Optional[int] = None,
         oast_http_port: Optional[int] = None,
         copilot: bool = False,
         autofix: bool = False,
         source_dir: Optional[str] = None,
         dry_run: bool = False,
         prefer_local_ai: bool = False,
         sarif_output: Optional[str] = None,
         eval_compliance: bool = False,
         export_waf: Optional[str] = None,
         waf_output: Optional[str] = None,
         oauth2_token_url: Optional[str] = None,
         oauth2_refresh_token: Optional[str] = None,
         oauth2_client_id: Optional[str] = None,
         oauth2_client_secret: Optional[str] = None,
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
        totp_secret=totp_secret,
        sentinel_url=sentinel_url,
        enable_oast=enable_oast,
        oast_server=oast_server,
        oast_dns_port=oast_dns_port,
        oast_http_port=oast_http_port,
    )
    if delay > 0:
        config.delay = delay
        config.max_rps = int(1.0 / delay)
    if passive:
        config.active_payloads = False

    if session_macro_file and os.path.exists(session_macro_file):
        try:
            import json

            from scanner.session_macro import MacroStep, SessionMacro
            with open(session_macro_file, encoding="utf-8") as f:
                macro_data = json.load(f)
                steps = [MacroStep(**s) for s in macro_data.get("steps", [])]
                config.session_macro = SessionMacro(
                    name=macro_data.get("name", "cli_macro"),
                    steps=steps,
                    sentinel_url=sentinel_url or macro_data.get("sentinel_url"),
                    sentinel_expected_status=macro_data.get("sentinel_expected_status", 200),
                    login_redirect_patterns=macro_data.get("login_redirect_patterns", ["/login", "/auth"]),
                    headers_to_persist=macro_data.get("headers_to_persist", {}),
                )
                logger.info("[SESSION MACRO] Macro de sesión cargado: %s", config.session_macro.name)
        except Exception as err:
            logger.error("Error al cargar macro de sesión '%s': %s", session_macro_file, err)
    elif not config.session_macro and login_url and (totp_secret or sentinel_url):
        from scanner.auth_helper import parse_credentials
        from scanner.session_macro import build_smart_auth_macro
        parsed = parse_credentials(login_creds or "")
        username = parsed.get("username") or parsed.get("user") or parsed.get("email") or ""
        password = parsed.get("password") or parsed.get("pass") or ""
        config.session_macro = build_smart_auth_macro(
            login_url=login_url,
            username=username,
            password=password,
            totp_secret=totp_secret,
            sentinel_url=sentinel_url,
            is_spa=headless_login,
            extra_data=parsed,
        )
        logger.info("[SESSION MACRO] Macro inteligente auto-configurado para login con MFA/TOTP: %s", config.session_macro.name)

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

    def _notify(pct: int, step_desc: str) -> None:
        if progress_callback:
            with contextlib.suppress(Exception):
                progress_callback({
                    "event": "progress",
                    "step": step_desc,
                    "percent": pct,
                    "current_rps": getattr(engine, "current_rps", 10.0) or 10.0,
                    "total_requests": getattr(engine, "total_requests", 0),
                    "circuit_state": getattr(getattr(engine, "circuit_breaker", None), "state", "CLOSED"),
                    "waf_detected": getattr(engine, "waf_detected", False),
                })

    _notify(15, "Iniciando motor de auditoría y análisis de entorno...")

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

    # 1.1 Autenticación dinámica OAuth2 con auto-refresh y soporte TOTP
    if session is None and oauth2_token_url and oauth2_refresh_token:
        try:
            from scanner.auth_helper import create_oauth2_refreshing_session
            logger.info("[OAUTH2] Configurando sesión con auto-renovación de tokens OAuth2...")
            auth_mgr = create_oauth2_refreshing_session(
                token_url=oauth2_token_url,
                refresh_token=oauth2_refresh_token,
                client_id=oauth2_client_id,
                client_secret=oauth2_client_secret,
                totp_secret=totp_secret,
            )
            session = auth_mgr.session
            session_mgr = getattr(engine, "session_manager", None)
            if session_mgr is not None:
                session_mgr.session = session
        except Exception as e:
            logger.warning("[OAUTH2] Error configurando sesión OAuth2: %s", e)

    # 2. Login dinámico o headless si se especifica
    if session is None and login_url and login_creds:
        if headless_login:
            auth_session = headless_browser_login(login_url, login_creds, totp_secret=totp_secret)
        else:
            auth_session = dynamic_login(login_url, login_creds, totp_secret=totp_secret)
        if auth_session is not None:
            session = auth_session
            session_mgr = getattr(engine, "session_manager", None)
            if session_mgr is not None:
                session_mgr.session = session


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
        _notify(20, "Detectando presencia de WAF o protección perimetral...")
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

    if (crawl_pages > 1 or active_crawl) and not engine.is_cancelled and not har_discovered_urls:
        _notify(30, f"Rastreando estructura web y formularios ({min(crawl_pages, config.max_crawl_pages)} páginas máx)...")
        if active_crawl:
            from scanner.active_crawler import ActiveCrawler, extract_active_crawl_targets
            logger.info("[ACTIVE-CRAWL] Ejecutando Active Crawler con Monkey Testing y CDP Network Interception...")
            ac = ActiveCrawler(max_monkey_actions=monkey_actions)
            ac_res = ac.crawl(url, session=session)
            active_targets = extract_active_crawl_targets(ac_res)
            target_urls = list(dict.fromkeys(target_urls + active_targets))[:min(crawl_pages * 2, config.max_crawl_pages)]
            logger.info("[ACTIVE-CRAWL] %d URLs y endpoints descubiertos vía Monkey Testing", len(target_urls))
        else:
            target_urls = crawl_site(
                url,
                max_pages=min(crawl_pages, config.max_crawl_pages),
                session=session,
                use_headless=headless_crawl
            )

    if target_urls and not engine.is_cancelled and (param_fuzz or profile == "aggressive"):
        _notify(40, f"Descubriendo parámetros ocultos en {len(target_urls)} URL(s)...")
        logger.info("[PARAM-FUZZ] Ejecutando descubrimiento diferencial de parámetros en %d URL(s)...", len(target_urls))
        new_param_urls: list[str] = []
        for u in target_urls[:5]:
            if "?" not in u:
                try:
                    disc = discover_parameters(u, session=session, max_params=20)
                    new_param_urls.extend(disc)
                except Exception as e:
                    logger.debug("Error en descubrimiento de parámetros de %s: %s", u, e)
        if new_param_urls:
            logger.info("[PARAM-FUZZ] %d URL(s) parametrizadas incorporadas para auditoría activa.", len(new_param_urls))
            target_urls = list(dict.fromkeys(target_urls + new_param_urls))

    if not engine.is_cancelled:
        _notify(50, "Buscando archivos sensibles expuestos (.env, .git, backups)...")
        logger.info("Búsqueda de archivos sensibles expuestos...")
        raw = check_exposed_files(url, session=session)
        all_findings += _legacy_to_findings(raw, "fuzzer", url)

    if not engine.is_cancelled:
        _notify(60, "Auditando cifrado SSL/TLS y certificados digitales...")
        logger.info("Certificado SSL/TLS...")
        raw = check_ssl(url, session=session)
        all_findings += _legacy_to_findings(raw, "ssl", url)

    if not engine.is_cancelled:
        _notify(65, "Escaneando puertos y servicios perimetrales expuestos...")
        logger.info("Escaneando puertos y servicios expuestos...")
        raw = check_ports(url)
        all_findings += _legacy_to_findings(raw, "ports", url)

    if target_urls and not engine.is_cancelled:
        _notify(75, f"Ejecutando pruebas de seguridad DAST en {len(target_urls)} página(s)...")
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
    _notify(90, "Correlacionando hallazgos y construyendo grafos de ataque...")
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
        if what_if_nodes:
            what_if_res = attack_graph.simulate_remediation(what_if_nodes)
            attack_graph_dict["what_if_simulation"] = what_if_res.to_dict()
            logger.info("[WHAT-IF] Simulación completada: Reducción de riesgo del %.1f%% (%d rutas cortadas).",
                        what_if_res.risk_reduction_percent, what_if_res.severed_attack_paths)

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

    # 8. Copiloto de Seguridad IA Híbrido (Triaje, Auto-Fix y Resumen Ejecutivo)
    copilot_summary: Optional[dict[str, Any]] = None
    if (copilot or autofix) and all_findings:
        from scanner.ai_copilot import AIConfig, AICopilot
        copilot_inst = AICopilot(AIConfig(prefer_local=prefer_local_ai))

        if autofix and source_dir:
            logger.info("[Auto-Fix] 🛠️ Analizando código fuente en '%s' para aplicar auto-remediación...", source_dir)
            for finding_item in all_findings:
                candidates: list[str] = []
                if finding_item.iast_source_file and os.path.isfile(finding_item.iast_source_file):
                    candidates.append(finding_item.iast_source_file)
                if finding_item.autofix and finding_item.autofix.get("filename"):
                    hint_path = os.path.join(source_dir, str(finding_item.autofix["filename"]))
                    if os.path.isfile(hint_path):
                        candidates.append(hint_path)

                for c_file in candidates:
                    p_res = copilot_inst.autofix_file(c_file, finding_item, dry_run=dry_run)
                    if p_res.applied:
                        logger.info("[Auto-Fix] ✅ Código parcheado con éxito en: %s (Backup: %s)", c_file, p_res.backup_path)
                    elif p_res.diff:
                        logger.info("[Auto-Fix] [DRY-RUN] Simulación de parche para %s:\n%s", c_file, p_res.diff)

        if copilot:
            logger.info("[Copilot] 🧠 Generando Resumen Ejecutivo y Evaluación de Compliance CISO...")
            copilot_summary = copilot_inst.executive_summary(all_findings, url)
            logger.info("[Copilot] Postura General: %s | Acciones prioritarias: %d",
                        copilot_summary.get("overall_posture"), len(copilot_summary.get("top_immediate_actions", [])))

    engine_summary = engine.get_summary()
    if attack_graph_dict:
        engine_summary["attack_graph"] = attack_graph_dict
    if pr_result:
        engine_summary["github_pr"] = pr_result
    if copilot_summary:
        engine_summary["ai_copilot"] = copilot_summary
    SCAN_STATS["total_requests"] = engine.request_count

    # 8.1. Verificación Forense Basada en Pruebas (Proof-Based Verification)
    if all_findings:
        try:
            from scanner.proof_verifier import ProofVerifier
            verifier = ProofVerifier(session=session)
            verifier.verify_all(all_findings)
        except Exception as e:
            logger.debug("[ProofVerifier] Error durante verificación forense: %s", e)

    # 9. Despacho automatizado a Jira, Slack, Teams o GitHub Issues
    if all_findings:
        try:
            from scanner.integrations import NotificationDispatcher
            dispatcher = NotificationDispatcher.from_environment()
            if dispatcher.jira or dispatcher.slack or dispatcher.teams or dispatcher.github:
                dispatch_stats = dispatcher.dispatch_all(all_findings)
                logger.info(
                    "[DevSecOps] Alertas despachadas: %d Jira, %d Slack, %d Teams, %d GitHub",
                    dispatch_stats["jira"], dispatch_stats["slack"], dispatch_stats["teams"], dispatch_stats["github"]
                )
                engine_summary["integrations_dispatched"] = dispatch_stats
        except Exception as e:
            logger.debug("[DevSecOps] Error al despachar alertas: %s", e)

    # 10. Exportador SARIF v2.1.0 para GitHub Code Scanning
    if sarif_output and all_findings:
        try:
            from scanner.sarif import export_findings_to_sarif, save_sarif_file
            sarif_doc = export_findings_to_sarif(all_findings, scan_url=url)
            save_sarif_file(sarif_doc, sarif_output)
            engine_summary["sarif_report_path"] = sarif_output
            logger.info("[SARIF] Reporte estándar exportado exitosamente a: %s", sarif_output)
        except Exception as e:
            logger.debug("[SARIF] Error generando reporte SARIF: %s", e)

    # 11. Mapeo y evaluación de cumplimiento normativo (PCI-DSS, HIPAA, NIST, ISO)
    if eval_compliance and all_findings:
        try:
            from scanner.compliance import ComplianceEngine
            c_engine = ComplianceEngine()
            c_eval = c_engine.evaluate(all_findings)
            engine_summary["compliance"] = c_eval
            print("\n" + c_engine.generate_markdown_report(c_eval) + "\n")
        except Exception as e:
            logger.debug("[Compliance] Error evaluando cumplimiento: %s", e)

    # 12. Síntesis y exportación de reglas WAF (Virtual Patching)
    if export_waf and all_findings:
        try:
            from scanner.virtual_patching import VirtualPatchEngine
            waf_ruleset = VirtualPatchEngine.export_ruleset(all_findings, format=export_waf)
            if waf_output:
                with open(waf_output, "w", encoding="utf-8") as f:
                    f.write(waf_ruleset)
                logger.info("[WAF] Reglas de parcheo virtual (%s) exportadas en: %s", export_waf, waf_output)
            else:
                print("\n" + "=" * 75)
                print(f" [🛡️ REGLAS DE PARCHEO VIRTUAL WAF - FORMATO: {export_waf.upper()}]")
                print("=" * 75)
                print(waf_ruleset)
                print("=" * 75 + "\n")
            engine_summary["waf_virtual_patches"] = {"format": export_waf, "ruleset": waf_ruleset}
        except Exception as e:
            logger.debug("[WAF] Error generando reglas de parcheo virtual: %s", e)

    return print_report(
        url,
        all_findings,
        engine.elapsed,
        no_open=no_open,
        engine_summary=engine_summary,
        generate_pdf=generate_pdf,
    )

def main() -> None:
    parser = build_cli_parser()
    args = parser.parse_args()
    dispatch_cli(args, scan_runner=scan)


if __name__ == "__main__":
    main()
