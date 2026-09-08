import contextlib
from html.parser import HTMLParser
from typing import Optional
from urllib.parse import urljoin, urlparse

try:
    import defusedxml.ElementTree as DefusedElementTree
    xml_parser = DefusedElementTree
except ImportError:
    import xml.etree.ElementTree as StandardElementTree  # nosec B405
    xml_parser = StandardElementTree

import requests

from utils.renderer import is_playwright_available

# Rutas SPA comunes a probar como semillas adicionales
COMMON_SPA_ROUTES: list[str] = [
    "/login", "/signin", "/signup", "/register", "/dashboard",
    "/admin", "/panel", "/account", "/profile", "/settings",
    "/home", "/about", "/contact", "/api", "/docs", "/help",
    "/cart", "/checkout", "/orders", "/products", "/search",
]


class LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, Optional[str]]]) -> None:
        if tag == 'a':
            attr_dict = dict(attrs)
            href = attr_dict.get('href')
            if href:
                self.links.append(href)


def get_internal_links(url: str, html_content: str) -> list[str]:
    """
    Extrae todos los enlaces del HTML que pertenezcan al mismo dominio/host.
    """
    parser = LinkParser()
    with contextlib.suppress(Exception):
        parser.feed(html_content)

    parsed_base = urlparse(url)
    base_domain = parsed_base.netloc
    internal_links = set()

    for link in parser.links:
        # Resolver URLs relativas a absolutas
        abs_url = urljoin(url, link)

        # Eliminar fragmentos/anclas (ej. #contacto)
        abs_url_clean = abs_url.split('#')[0]
        parsed_clean = urlparse(abs_url_clean)

        # Validar que pertenezca al mismo dominio
        if parsed_clean.netloc == base_domain and not any(
            abs_url_clean.lower().endswith(ext)
            for ext in ['.png', '.jpg', '.jpeg', '.gif', '.pdf', '.zip', '.css', '.js', '.svg']
        ):
            internal_links.add(abs_url_clean)

    return list(internal_links)


def fetch_sitemap(root_url: str, session: Optional[requests.Session] = None) -> set[str]:
    """Descarga y parsea sitemap.xml buscando URLs del mismo dominio."""
    client = session if session is not None else requests
    urls: set[str] = set()
    for sitemap_path in ["/sitemap.xml", "/sitemap_index.xml"]:
        sitemap_url = urljoin(root_url, sitemap_path)
        try:
            r = client.get(sitemap_url, timeout=8)
            if r.status_code == 200 and 'xml' in r.headers.get('Content-Type', '').lower():
                root = xml_parser.fromstring(r.content)  # nosec B314
                for loc in root.iter():
                    tag = loc.tag.split('}')[-1]
                    if tag == 'loc':
                        loc_text = (loc.text or '').strip()
                        if loc_text:
                            parsed_loc = urlparse(loc_text)
                            parsed_base = urlparse(root_url)
                            if parsed_loc.netloc == parsed_base.netloc:
                                urls.add(loc_text.split('#')[0])
        except (xml_parser.ParseError, requests.RequestException):
            pass
    return urls


def fetch_robots_paths(root_url: str, session: Optional[requests.Session] = None) -> tuple[set[str], set[str]]:
    """Lee robots.txt y extrae rutas Disallow/Allow/Sitemap."""
    client = session if session is not None else requests
    paths: set[str] = set()
    sitemap_urls: set[str] = set()
    robots_url = urljoin(root_url, "/robots.txt")
    try:
        r = client.get(robots_url, timeout=8)
        if r.status_code == 200:
            for line in r.text.splitlines():
                line = line.strip()
                if line.lower().startswith('disallow:') or line.lower().startswith('allow:'):
                    _, _, path = line.partition(':')
                    path = path.strip()
                    if path and path != '/' and not path.endswith('*'):
                        paths.add(path.split('#')[0])
                elif line.lower().startswith('sitemap:'):
                    _, _, sm = line.partition(':')
                    sm = sm.strip()
                    if sm:
                        sitemap_urls.add(sm)
    except requests.RequestException:
        pass
    return paths, sitemap_urls


def crawl_site(
    start_url: str,
    max_pages: int = 10,
    session: Optional[requests.Session] = None,
    use_headless: bool = False
) -> list[str]:
    """
    Rastrea el sitio web descubriendo URLs mediante:
      1. Enlaces <a href> del HTML (método clásico)
      2. sitemap.xml / sitemap_index.xml
      3. robots.txt (rutas Disallow/Allow)
      4. Rutas SPA comunes (/login, /dashboard, /register, ...)
      5. Navegador headless dinámico con Playwright (si use_headless=True y disponible)
    Hasta alcanzar max_pages páginas únicas.
    """
    if use_headless and is_playwright_available():
        from scanner.headless_crawler import crawl_site_dynamic
        print(f"  [CRAWL-HEADLESS] Iniciando rastreo SPA con navegador headless (limite: {max_pages} paginas)...")
        pages, apis = crawl_site_dynamic(start_url, max_pages=max_pages)
        if apis:
            print(f"  [API-DISCOVERY] Interceptados {len(apis)} endpoints de API dinámicos")
        return pages

    visited: set[str] = set()
    client = session if session is not None else requests

    parsed_start = urlparse(start_url)
    root_url = f"{parsed_start.scheme}://{parsed_start.netloc}/"

    print(f"  [CRAWL] Iniciando rastreo web (limite: {max_pages} paginas)...")

    # Conjunto de semillas inicial: la URL de inicio
    to_visit = [start_url]

    # 1. Añadir URLs de sitemap.xml
    sitemap_urls = fetch_sitemap(root_url, session=session)
    if sitemap_urls:
        print(f"  [SITEMAP] sitemap.xml: {len(sitemap_urls)} URL(s) descubiertas")
        to_visit.extend(sitemap_urls)

    # 2. Añadir rutas de robots.txt
    robots_paths, robots_sitemaps = fetch_robots_paths(root_url, session=session)
    for sm in robots_sitemaps:
        sitemap_urls |= fetch_sitemap(sm, session=session)
    for path in robots_paths:
        to_visit.append(urljoin(root_url, path))
    if robots_paths:
        print(f"  [ROBOTS] robots.txt: {len(robots_paths)} ruta(s) descubiertas")

    # 3. Añadir rutas SPA comunes
    for route in COMMON_SPA_ROUTES:
        candidate = urljoin(root_url, route)
        if candidate not in to_visit:
            to_visit.append(candidate)

    # Deduplicar semillas preservando orden
    seen_seeds = set()
    deduped = []
    for u in to_visit:
        if u not in seen_seeds:
            seen_seeds.add(u)
            deduped.append(u)
    to_visit = deduped

    while to_visit and len(visited) < max_pages:
        current_url = to_visit.pop(0)
        if current_url in visited:
            continue

        try:
            r = client.get(current_url, timeout=8)
            visited.add(current_url)

            if 'text/html' in r.headers.get('Content-Type', '').lower():
                links = get_internal_links(current_url, r.text)
                for link in links:
                    if link not in visited and link not in to_visit:
                        to_visit.append(link)
        except Exception:
            visited.add(current_url)

    print(f"  [CRAWL] Rastreo finalizado. Paginas encontradas: {len(visited)}")
    return list(visited)
