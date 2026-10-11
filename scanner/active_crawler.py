"""
Motor de Rastreo Activo con Monkey Testing & CDP Network Interception (Active SPA Crawler).

Diseñado para Single Page Applications (React, Angular, Vue, Next.js, Svelte) y APIs dinámicas.
Implementa:
1. Interceptación profunda de red (CDP / Playwright):
   - Captura de peticiones XHR, Fetch, GraphQL y WebSockets.
   - Extracción de cabeceras de autorización, tokens CSRF y cuerpos (JSON / FormData).
   - Descubrimiento de endpoints en respuestas JSON anidadas.
2. Monkey Testing & Event Fuzzing Autónomo:
   - Disparo de eventos estocásticos y deterministas (click, fill, select, toggle).
   - Inyección de canarios válidos en formularios (email, text, number).
   - Lista negra de seguridad (Safe Navigation) para evitar desautenticación (logout / signout).
   - Observador de mutaciones del DOM (MutationObserver) y rastreo de History API (pushState/replaceState).
3. Degradación heurística elegante (Offline/Lightweight):
   - Extractor regex/AST de rutas de API en bundles JavaScript y scripts en línea.
"""
from __future__ import annotations

import contextlib
import logging
import re
import time
from dataclasses import asdict, dataclass, field
from typing import Any
from urllib.parse import urljoin, urlparse

import requests

from utils.renderer import is_playwright_available

logger = logging.getLogger("OmniBreach.ActiveCrawler")

# Patrones para evitar acciones destructivas o de desautenticación durante el Monkey Testing
DANGEROUS_ACTION_PATTERNS = re.compile(
    r"(logout|signout|cerrar[-_ ]?sesi[oó]n|salir|disconnect|desconectar|delete[-_ ]?account|"
    r"cancel[-_ ]?subscription|eliminar[-_ ]?cuenta|destroy|drop[-_ ]?database|purge)",
    re.IGNORECASE,
)

# Script de instrumentación inyectado en el cliente antes de la ejecución de scripts de la app
CLIENT_MONKEY_BOOTSTRAP_JS = """
(() => {
    if (window.__omnibreach_bootstrapped) return;
    window.__omnibreach_bootstrapped = true;
    window.__omnibreach_routes = [];
    window.__omnibreach_mutations = 0;
    window.__omnibreach_events = [];

    // 1. Interceptar History API para detectar navegación SPA sin recarga
    const origPush = history.pushState;
    history.pushState = function(state, title, url) {
        if (url) {
            window.__omnibreach_routes.push({ type: 'pushState', url: String(url), ts: Date.now() });
        }
        return origPush.apply(this, arguments);
    };

    const origReplace = history.replaceState;
    history.replaceState = function(state, title, url) {
        if (url) {
            window.__omnibreach_routes.push({ type: 'replaceState', url: String(url), ts: Date.now() });
        }
        return origReplace.apply(this, arguments);
    };

    window.addEventListener('hashchange', (ev) => {
        window.__omnibreach_routes.push({ type: 'hashchange', url: window.location.href, ts: Date.now() });
    });

    // 2. Observador de mutaciones DOM para contabilizar renderizado dinámico
    try {
        const observer = new MutationObserver((mutations) => {
            window.__omnibreach_mutations += mutations.length;
        });
        observer.observe(document.documentElement, { childList: true, subtree: true });
    } catch(e) {}
})();
"""


@dataclass
class HTTPTransaction:
    """Representa una transacción HTTP interceptada a nivel de red."""
    url: str
    method: str = "GET"
    headers: dict[str, str] = field(default_factory=dict)
    post_data: str | None = None
    resource_type: str = "fetch"  # "fetch", "xhr", "websocket", "document", "script", "form"
    response_status: int | None = None
    response_headers: dict[str, str] = field(default_factory=dict)
    source_event: str = "initial"  # "initial", "monkey_click", "form_fill", "history_pushState"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class MonkeyAction:
    """Registro de una acción interactiva ejecutada por el Monkey Tester."""
    action_type: str  # "click", "fill", "select", "toggle", "hover"
    selector: str
    tag_name: str
    text_snippet: str = ""
    value_entered: str | None = None
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ActiveCrawlResult:
    """Resultado consolidado del rastreo dinámico y monkey testing."""
    target_url: str
    discovered_pages: list[str] = field(default_factory=list)
    api_transactions: list[HTTPTransaction] = field(default_factory=list)
    spa_routes: list[str] = field(default_factory=list)
    websocket_endpoints: list[str] = field(default_factory=list)
    monkey_actions: list[MonkeyAction] = field(default_factory=list)
    dom_mutations: int = 0
    duration_seconds: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_url": self.target_url,
            "discovered_pages": self.discovered_pages,
            "api_transactions": [t.to_dict() for t in self.api_transactions],
            "api_endpoints_count": len(self.api_transactions),
            "spa_routes": self.spa_routes,
            "websocket_endpoints": self.websocket_endpoints,
            "monkey_actions": [a.to_dict() for a in self.monkey_actions],
            "monkey_actions_count": len(self.monkey_actions),
            "dom_mutations": self.dom_mutations,
            "duration_seconds": round(self.duration_seconds, 2),
        }


class StaticBundleExtractor:
    """Extractor heurístico de endpoints desde archivos JavaScript y Webpack bundles."""

    # Patrones para endpoints de API y rutas relativas en código fuente
    API_ROUTE_REGEX = re.compile(
        r"""(?:["'`])((?:/api/|/v[0-9]+/|/graphql|/rest/|/auth/|/oauth/|/users/|/items/)[a-zA-Z0-9_\-\./\?=&%]*)["'`]""",
        re.IGNORECASE,
    )

    # Patrones de llamadas cliente tipo axios/fetch
    CLIENT_HTTP_REGEX = re.compile(
        r"""(?:axios|client)\s*\.\s*(?:get|post|put|delete|patch)\s*\(\s*["'`]([^"'`]+)["'`]""",
        re.IGNORECASE,
    )
    FETCH_CALL_REGEX = re.compile(
        r"""(?:fetch)\s*\(\s*["'`]([^"'`]+)["'`]""",
        re.IGNORECASE,
    )

    # Endpoints de WebSockets
    WS_REGEX = re.compile(r"""(?:["'`])((?:ws|wss)://[a-zA-Z0-9_\-\.:/]+)(?:["'`])""", re.IGNORECASE)

    @classmethod
    def extract_from_text(cls, content: str, base_url: str) -> tuple[set[str], set[str]]:
        """Extrae rutas de API y WebSockets a partir de texto o bundle JS."""
        endpoints: set[str] = set()
        websockets: set[str] = set()

        # 1. Búsqueda de rutas de API
        for match in cls.API_ROUTE_REGEX.findall(content):
            clean = match.strip()
            if not clean.endswith((".js", ".css", ".png", ".jpg", ".svg", ".map")):
                abs_url = urljoin(base_url, clean)
                endpoints.add(abs_url)

        # 2. Búsqueda de llamadas Axios / Fetch
        for path in cls.CLIENT_HTTP_REGEX.findall(content) + cls.FETCH_CALL_REGEX.findall(content):
            clean = path.strip()
            if not clean.startswith(("http://", "https://")):
                clean = urljoin(base_url, clean)
            endpoints.add(clean)

        # 3. WebSockets
        for ws in cls.WS_REGEX.findall(content):
            websockets.add(ws.strip())

        return endpoints, websockets


class ActiveCrawler:
    """
    Rastreador dinámico con Monkey Testing y CDP Network Interception.
    Capaz de navegar SPAs, simular interacciones de usuario y capturar flujos de API.
    """

    def __init__(
        self,
        timeout_ms: int = 15000,
        max_monkey_actions: int = 25,
        allowed_domains: list[str] | None = None,
    ) -> None:
        self.timeout_ms = timeout_ms
        self.max_monkey_actions = max_monkey_actions
        self.allowed_domains = allowed_domains

    def is_safe_action(self, element_meta: dict[str, Any]) -> bool:
        """Determina si un elemento interactivo es seguro para ser presionado sin desautenticar."""
        text = str(element_meta.get("text", ""))
        aria = str(element_meta.get("aria", ""))
        elem_id = str(element_meta.get("id", ""))
        name = str(element_meta.get("name", ""))
        combined = f"{text} {aria} {elem_id} {name}".lower()

        return not bool(DANGEROUS_ACTION_PATTERNS.search(combined))

    def _crawl_with_playwright(self, target_url: str) -> ActiveCrawlResult:
        """Ejecuta rastreo interactivo y Monkey Testing con Chromium headless."""
        from playwright.sync_api import sync_playwright

        start_time = time.time()
        discovered_pages: set[str] = {target_url}
        api_transactions: list[HTTPTransaction] = []
        websocket_endpoints: set[str] = set()
        spa_routes: set[str] = set()
        monkey_actions: list[MonkeyAction] = []
        dom_mutations_count = 0

        parsed_base = urlparse(target_url)
        base_domain = parsed_base.netloc

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(
                user_agent=(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 (OmniBreach ActiveCrawler/3.9)"
                ),
                viewport={"width": 1280, "height": 800},
            )

            # Inyectar script de instrumentación SPA antes de que se cargue la página
            context.add_init_script(CLIENT_MONKEY_BOOTSTRAP_JS)
            page = context.new_page()

            current_event_context = ["initial_load"]

            # Listener de red para peticiones salientes
            def on_request(req: Any) -> None:
                with contextlib.suppress(Exception):
                    r_url = req.url
                    r_type = req.resource_type
                    r_method = req.method.upper()
                    req_netloc = urlparse(r_url).netloc

                    # Interceptar XHR, Fetch o rutas con /api/ del mismo dominio
                    if (r_type in ("fetch", "xhr", "websocket") or "/api/" in r_url.lower()) and req_netloc == base_domain:
                        post_data = None
                        with contextlib.suppress(Exception):
                            post_data = req.post_data

                        tx = HTTPTransaction(
                            url=r_url,
                            method=r_method,
                            headers=dict(req.headers),
                            post_data=post_data,
                            resource_type=r_type,
                            source_event=current_event_context[0],
                        )
                        api_transactions.append(tx)

            # Listener de respuestas de red
            def on_response(resp: Any) -> None:
                with contextlib.suppress(Exception):
                    resp_url = resp.url
                    for tx in reversed(api_transactions):
                        if tx.url == resp_url and tx.response_status is None:
                            tx.response_status = resp.status
                            tx.response_headers = dict(resp.headers)
                            # Extraer rutas de API anidadas si la respuesta es JSON
                            c_type = resp.headers.get("content-type", "").lower()
                            if "application/json" in c_type:
                                with contextlib.suppress(Exception):
                                    text_body = resp.text()
                                    sub_apis, _ = StaticBundleExtractor.extract_from_text(text_body, target_url)
                                    for sub in sub_apis:
                                        if urlparse(sub).netloc == base_domain:
                                            discovered_pages.add(sub)
                            break

            # Listener de WebSockets
            def on_websocket(ws: Any) -> None:
                with contextlib.suppress(Exception):
                    websocket_endpoints.add(ws.url)

            page.on("request", on_request)
            page.on("response", on_response)
            page.on("websocket", on_websocket)

            # Navegación inicial
            try:
                page.goto(target_url, wait_until="domcontentloaded", timeout=self.timeout_ms)
                with contextlib.suppress(Exception):
                    page.wait_for_load_state("networkidle", timeout=3000)
            except Exception as exc:
                logger.warning("Fallo en carga inicial de %s: %s", target_url, exc)

            # Extraer enlaces estáticos iniciales
            with contextlib.suppress(Exception):
                raw_hrefs = page.eval_on_selector_all(
                    "a[href]",
                    "elements => elements.map(el => el.getAttribute('href'))",
                )
                for h in raw_hrefs:
                    if h and not h.startswith(("javascript:", "mailto:", "tel:")):
                        abs_h = urljoin(target_url, h).split("#")[0]
                        if urlparse(abs_h).netloc == base_domain:
                            discovered_pages.add(abs_h)

            # =============================================================
            # MONKEY TESTING & DOM EVENT FUZZING ENGINE
            # =============================================================
            logger.info("[MONKEY] Iniciando exploración estocástica y fuzzing de eventos (máx %d acciones)...", self.max_monkey_actions)
            actions_executed = 0

            # 1. Fuzzing de formularios interactivos
            forms_selector = "form"
            form_count = page.locator(forms_selector).count()
            for f_idx in range(min(form_count, 3)):
                if actions_executed >= self.max_monkey_actions:
                    break
                with contextlib.suppress(Exception):
                    form_loc = page.locator(forms_selector).nth(f_idx)
                    # Llenar inputs de texto / email
                    text_inputs = form_loc.locator("input[type='text'], input[type='email'], input[type='search'], input:not([type])")
                    for in_idx in range(min(text_inputs.count(), 3)):
                        inp = text_inputs.nth(in_idx)
                        in_type = inp.get_attribute("type") or "text"
                        val = "test@example.com" if in_type == "email" else "fuzz_canary"
                        current_event_context[0] = "monkey_form_fill"
                        inp.fill(val)
                        monkey_actions.append(MonkeyAction(
                            action_type="fill",
                            selector=f"form:nth({f_idx}) input:nth({in_idx})",
                            tag_name="input",
                            value_entered=val,
                        ))
                        actions_executed += 1

                    # Click en botón de envío (si no es peligroso)
                    sub_btn = form_loc.locator("button[type='submit'], input[type='submit'], button:not([type])").first
                    if sub_btn.count() > 0:
                        btn_text = sub_btn.inner_text() or ""
                        if self.is_safe_action({"text": btn_text}):
                            current_event_context[0] = "monkey_form_submit"
                            sub_btn.click(timeout=1000)
                            monkey_actions.append(MonkeyAction(
                                action_type="click",
                                selector=f"form:nth({f_idx}) submit",
                                tag_name="button",
                                text_snippet=btn_text[:30],
                            ))
                            actions_executed += 1
                            page.wait_for_timeout(400)

            # 2. Monkey Clicks sobre botones, tabs y selectores interactivos
            clickables = page.locator("button, [role='button'], [data-toggle], [aria-expanded], summary, div[onclick]")
            total_clickables = clickables.count()
            for c_idx in range(min(total_clickables, self.max_monkey_actions - actions_executed)):
                if actions_executed >= self.max_monkey_actions:
                    break
                with contextlib.suppress(Exception):
                    elem = clickables.nth(c_idx)
                    if not elem.is_visible():
                        continue

                    e_text = elem.inner_text() or ""
                    e_id = elem.get_attribute("id") or ""
                    e_aria = elem.get_attribute("aria-label") or ""

                    if not self.is_safe_action({"text": e_text, "id": e_id, "aria": e_aria}):
                        continue

                    current_event_context[0] = f"monkey_click_{c_idx}"
                    elem.click(timeout=1000)
                    monkey_actions.append(MonkeyAction(
                        action_type="click",
                        selector=f"clickable:nth({c_idx})",
                        tag_name="button",
                        text_snippet=e_text[:30],
                    ))
                    actions_executed += 1
                    page.wait_for_timeout(300)

            # 3. Recopilar telemetría de instrumentación SPA inyectada
            with contextlib.suppress(Exception):
                instrumentation_data = page.evaluate("""() => ({
                    routes: window.__omnibreach_routes || [],
                    mutations: window.__omnibreach_mutations || 0,
                    current_url: window.location.href,
                })""")
                dom_mutations_count = instrumentation_data.get("mutations", 0)
                for r in instrumentation_data.get("routes", []):
                    route_url = r.get("url", "")
                    if route_url:
                        abs_r = urljoin(target_url, route_url).split("#")[0]
                        if urlparse(abs_r).netloc == base_domain:
                            spa_routes.add(abs_r)
                            discovered_pages.add(abs_r)

                final_url = instrumentation_data.get("current_url")
                if final_url and urlparse(final_url).netloc == base_domain:
                    discovered_pages.add(final_url.split("#")[0])

            browser.close()

        duration = time.time() - start_time
        return ActiveCrawlResult(
            target_url=target_url,
            discovered_pages=sorted(discovered_pages),
            api_transactions=api_transactions,
            spa_routes=sorted(spa_routes),
            websocket_endpoints=sorted(websocket_endpoints),
            monkey_actions=monkey_actions,
            dom_mutations=dom_mutations_count,
            duration_seconds=duration,
        )

    def _crawl_with_fallback(self, target_url: str, session: requests.Session | None = None) -> ActiveCrawlResult:
        """
        Degradación elegante sin navegador: extrae endpoints mediante análisis estático
        de JavaScript, formularios HTML y scripts embebidos.
        """
        start_time = time.time()
        client = session or requests.Session()
        discovered_pages: set[str] = {target_url}
        api_transactions: list[HTTPTransaction] = []
        websocket_endpoints: set[str] = set()
        monkey_actions: list[MonkeyAction] = []

        parsed_base = urlparse(target_url)
        base_domain = parsed_base.netloc

        try:
            resp = client.get(target_url, timeout=self.timeout_ms / 1000)
            html_text = resp.text

            # 1. Extracción desde el propio HTML
            found_apis, found_ws = StaticBundleExtractor.extract_from_text(html_text, target_url)
            websocket_endpoints.update(found_ws)

            # 2. Descubrir y parsear scripts JS vinculados
            script_srcs = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html_text, re.IGNORECASE)
            for src in script_srcs[:5]:
                js_url = urljoin(target_url, src)
                if urlparse(js_url).netloc == base_domain:
                    try:
                        js_resp = client.get(js_url, timeout=4)
                        if js_resp.status_code == 200:
                            s_apis, s_ws = StaticBundleExtractor.extract_from_text(js_resp.text, target_url)
                            found_apis.update(s_apis)
                            websocket_endpoints.update(s_ws)
                    except Exception:
                        pass

            # 3. Descubrir formularios en el HTML
            forms = re.findall(r'<form[^>]*action=["\']([^"\']*)["\'][^>]*method=["\']?([a-zA-Z]+)?["\']?', html_text, re.IGNORECASE)
            for action, method in forms:
                form_url = urljoin(target_url, action or "")
                if urlparse(form_url).netloc == base_domain:
                    api_transactions.append(HTTPTransaction(
                        url=form_url,
                        method=method.upper() if method else "GET",
                        resource_type="form",
                        source_event="static_form_discovery",
                    ))
                    discovered_pages.add(form_url)
                    monkey_actions.append(MonkeyAction(
                        action_type="fill",
                        selector=f"form[action='{action}']",
                        tag_name="form",
                        text_snippet="Simulated fallback form fill",
                    ))

            for api in found_apis:
                if urlparse(api).netloc == base_domain:
                    api_transactions.append(HTTPTransaction(
                        url=api,
                        method="GET",
                        resource_type="fetch",
                        source_event="bundle_ast_analysis",
                    ))
                    discovered_pages.add(api)

        except Exception as exc:
            logger.warning("Fallo en fallback crawler para %s: %s", target_url, exc)

        duration = time.time() - start_time
        return ActiveCrawlResult(
            target_url=target_url,
            discovered_pages=sorted(discovered_pages),
            api_transactions=api_transactions,
            spa_routes=[],
            websocket_endpoints=sorted(websocket_endpoints),
            monkey_actions=monkey_actions,
            dom_mutations=0,
            duration_seconds=duration,
        )

    def crawl(
        self,
        target_url: str,
        session: requests.Session | None = None,
        force_fallback: bool = False,
    ) -> ActiveCrawlResult:
        """
        Ejecuta el rastreo dinámico completo seleccionando el mejor motor disponible:
        Playwright Headless + CDP si está soportado, o Heuristic AST Fallback en caso contrario.
        """
        if not force_fallback and is_playwright_available():
            try:
                logger.info("[ACTIVE-CRAWL] Lanzando motor Chromium Headless con CDP y Monkey Testing...")
                return self._crawl_with_playwright(target_url)
            except Exception as exc:
                logger.warning("[ACTIVE-CRAWL] Fallo en Chromium, degradando a fallback heurístico: %s", exc)

        logger.info("[ACTIVE-CRAWL] Ejecutando análisis heurístico estático de bundles y DOM...")
        return self._crawl_with_fallback(target_url, session=session)


def extract_active_crawl_targets(result: ActiveCrawlResult) -> list[str]:
    """
    Convierte el resultado del rastreo activo en una lista ordenada de URLs listas
    para alimentar el motor de auditoría de vulnerabilidades DAST de OmniBreach.
    """
    targets: set[str] = {p.split("#")[0] for p in result.discovered_pages if p}
    for tx in result.api_transactions:
        clean_url = tx.url.split("#")[0]
        if clean_url:
            targets.add(clean_url)
    for r in result.spa_routes:
        clean_url = r.split("#")[0]
        if clean_url:
            targets.add(clean_url)
    return sorted(targets)
