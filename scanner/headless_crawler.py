"""
Rastreador dinámico avanzado con navegador headless (Playwright / Chromium).
Permite renderizar aplicaciones de página única (SPAs), interceptar tráfico de red
asíncrono (XHR/Fetch) y descubrir endpoints de API ocultos para auditorías profundas.
"""
import contextlib
import logging
from urllib.parse import urljoin, urlparse

from utils.renderer import is_playwright_available

logger = logging.getLogger("VulnScanner.HeadlessCrawler")


class HeadlessCrawler:
    """
    Rastreador dinámico con soporte de renderizado JavaScript,
    scroll automático e interceptación de tráfico de red para SPAs.
    """

    def __init__(self, timeout: int = 15000):
        self.timeout = timeout

    def crawl_dynamic_page(self, url: str) -> tuple[list[str], set[str], str]:
        """
        Renderiza la URL en un navegador Chromium headless, intercepta peticiones
        asíncronas (XHR/Fetch) y extrae todos los enlaces y rutas dinámicas.

        Returns:
            tuple: (enlaces_internos, api_endpoints_interceptados, html_renderizado)
        """
        if not is_playwright_available():
            logger.debug("Playwright no disponible. Omitiendo rastreo dinámico.")
            return [], set(), ""

        discovered_links: set[str] = set()
        intercepted_apis: set[str] = set()
        rendered_html = ""

        try:
            from playwright.sync_api import sync_playwright

            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                context = browser.new_context(
                    user_agent=(
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
                    ),
                    viewport={"width": 1280, "height": 800},
                )
                page = context.new_page()

                parsed_base = urlparse(url)
                base_domain = parsed_base.netloc

                # Interceptar peticiones de red salientes (XHR / Fetch)
                def on_request(req):
                    try:
                        req_url = req.url
                        r_type = req.resource_type
                        if r_type in ["fetch", "xhr", "websocket"] or "/api/" in req_url.lower():
                            intercepted_apis.add(req_url.split("#")[0])
                    except Exception:
                        pass

                page.on("request", on_request)

                # Navegar al sitio
                page.goto(url, wait_until="domcontentloaded", timeout=self.timeout)

                # Esperar a que la red se estabilice
                with contextlib.suppress(Exception):
                    page.wait_for_load_state("networkidle", timeout=5000)

                # Simular scroll suave para disparar listeners / lazy loading
                with contextlib.suppress(Exception):
                    page.evaluate("window.scrollTo(0, document.body.scrollHeight / 2)")
                    page.wait_for_timeout(500)
                    page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
                    page.wait_for_timeout(500)

                rendered_html = page.content()

                # Extraer enlaces <a href>
                raw_hrefs = page.eval_on_selector_all(
                    "a[href]",
                    "elements => elements.map(el => el.getAttribute('href'))"
                )

                # Extraer posibles botones/enlaces de frameworks SPA (React Router, Angular, Vue)
                spa_routes = page.eval_on_selector_all(
                    "[data-href], [routerlink], [to], button[onclick]",
                    """elements => elements.map(el => {
                        return el.getAttribute('data-href') ||
                               el.getAttribute('routerlink') ||
                               el.getAttribute('to') ||
                               '';
                    })"""
                )

                all_candidates = list(raw_hrefs) + [r for r in spa_routes if r]

                for link in all_candidates:
                    if not link or link.startswith(("javascript:", "mailto:", "tel:")):
                        continue
                    abs_url = urljoin(url, link).split("#")[0]
                    parsed_link = urlparse(abs_url)
                    if parsed_link.netloc == base_domain and not any(
                        abs_url.lower().endswith(ext)
                        for ext in [".png", ".jpg", ".jpeg", ".gif", ".pdf", ".zip", ".css", ".js", ".svg"]
                    ):
                        discovered_links.add(abs_url)

                browser.close()

        except Exception as e:
            logger.warning("Error en rastreo dinámico headless de %s: %s", url, e)

        return list(discovered_links), intercepted_apis, rendered_html


def crawl_site_dynamic(start_url: str, max_pages: int = 10) -> tuple[list[str], set[str]]:
    """
    Rastrea un sitio web completo combinando análisis estático y renderizado headless.
    Descubre tanto páginas HTML como endpoints de API ocultos.
    """
    crawler = HeadlessCrawler()
    visited: set[str] = set()
    all_apis: set[str] = set()
    to_visit = [start_url]

    while to_visit and len(visited) < max_pages:
        curr = to_visit.pop(0)
        if curr in visited:
            continue

        links, apis, _ = crawler.crawl_dynamic_page(curr)
        visited.add(curr)
        all_apis.update(apis)

        for lk in links:
            if lk not in visited and lk not in to_visit:
                to_visit.append(lk)

    return list(visited), all_apis
