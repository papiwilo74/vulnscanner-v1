import importlib

_playwright_available = None
_playwright_checked = False

def is_playwright_available():
    """Comprueba una sola vez si Playwright está instalado."""
    global _playwright_available, _playwright_checked
    if not _playwright_checked:
        try:
            importlib.import_module("playwright")
            _playwright_available = True
        except ImportError:
            _playwright_available = False
        _playwright_checked = True
    return _playwright_available

def render_page(url, wait_until="networkidle", timeout=15000, nav_timeout=20000):
    """
    Renderiza una página con Playwright (Chromium headless) y devuelve el HTML
    ya ejecutado (JavaScript incluido) junto con la lista de enlaces <a href>.

    Si Playwright no está instalado o falla, devuelve (None, []) para que el
    llamador pueda degradar con elegancia al HTML estático de requests.

    Args:
        url: URL a renderizar.
        wait_until: Evento de carga ('networkidle', 'domcontentloaded', 'load').
        timeout: Tiempo máximo de espera de red (ms).
        nav_timeout: Tiempo máximo de navegación (ms).

    Returns:
        (html_renderizado, [enlaces]) o (None, []) si no disponible/falló.
    """
    if not is_playwright_available():
        return None, []

    try:
        from playwright.sync_api import sync_playwright

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(
                user_agent=("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                            "AppleWebKit/537.36 (KHTML, like Gecko) "
                            "Chrome/124.0.0.0 Safari/537.36"),
                viewport={"width": 1280, "height": 800},
            )
            page = context.new_page()
            page.goto(url, wait_until=wait_until, timeout=nav_timeout)
            # Esperar un poco más para que el JS de la SPA pinte formularios
            try:
                page.wait_for_load_state("networkidle", timeout=timeout)
            except Exception:
                pass

            html = page.content()
            # Extraer enlaces del DOM ya renderizado
            links = page.eval_on_selector_all(
                "a[href]",
                "els => els.map(e => e.href)"
            )
            browser.close()
            return html, [ln for ln in links if ln]
    except Exception:
        return None, []
