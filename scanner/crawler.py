import re
import requests
from urllib.parse import urljoin, urlparse
from html.parser import HTMLParser
import xml.etree.ElementTree as ET

# Rutas SPA comunes a probar como semillas adicionales
COMMON_SPA_ROUTES = [
    "/login", "/signin", "/signup", "/register", "/dashboard",
    "/admin", "/panel", "/account", "/profile", "/settings",
    "/home", "/about", "/contact", "/api", "/docs", "/help",
    "/cart", "/checkout", "/orders", "/products", "/search",
]

class LinkParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []

    def handle_starttag(self, tag, attrs):
        if tag == 'a':
            attr_dict = dict(attrs)
            href = attr_dict.get('href')
            if href:
                self.links.append(href)

def get_internal_links(url, html_content):
    """
    Extrae todos los enlaces del HTML que pertenezcan al mismo dominio/host.
    """
    parser = LinkParser()
    try:
        parser.feed(html_content)
    except Exception as e:
        pass

    parsed_base = urlparse(url)
    base_domain = parsed_base.netloc
    internal_links = set()

    for link in parser.links:
        # Resolver URLs relativas a absolutas
        abs_url = urljoin(url, link)
        parsed_link = urlparse(abs_url)
        
        # Eliminar fragmentos/anclas (ej. #contacto)
        abs_url_clean = abs_url.split('#')[0]
        parsed_clean = urlparse(abs_url_clean)

        # Validar que pertenezca al mismo dominio
        if parsed_clean.netloc == base_domain:
            # Evitar enlaces a archivos no HTML obvios (imágenes, pdfs, etc.)
            if not any(abs_url_clean.lower().endswith(ext) for ext in ['.png', '.jpg', '.jpeg', '.gif', '.pdf', '.zip', '.css', '.js']):
                internal_links.add(abs_url_clean)

    return list(internal_links)

def fetch_sitemap(root_url, session=None):
    """Descarga y parsea sitemap.xml buscando URLs del mismo dominio."""
    client = session if session is not None else requests
    urls = set()
    for sitemap_path in ["/sitemap.xml", "/sitemap_index.xml"]:
        sitemap_url = urljoin(root_url, sitemap_path)
        try:
            r = client.get(sitemap_url, timeout=8)
            if r.status_code == 200 and 'xml' in r.headers.get('Content-Type', '').lower():
                root = ET.fromstring(r.content)
                # Namespace común de sitemaps
                ns = {'sm': 'http://www.sitemaps.org/schemas/sitemap/0.9'}
                # <loc> puede estar en raíz (sitemap) o dentro de <sitemap> (índice)
                for loc in root.iter():
                    tag = loc.tag.split('}')[-1]  # quitar namespace
                    if tag == 'loc':
                        loc_text = (loc.text or '').strip()
                        if loc_text:
                            parsed_loc = urlparse(loc_text)
                            parsed_base = urlparse(root_url)
                            if parsed_loc.netloc == parsed_base.netloc:
                                urls.add(loc_text.split('#')[0])
        except (ET.ParseError, requests.RequestException, Exception):
            pass
    return urls

def fetch_robots_paths(root_url, session=None):
    """Lee robots.txt y extrae rutas Disallow/Allow/Sitemap."""
    client = session if session is not None else requests
    paths = set()
    sitemap_urls = set()
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

def crawl_site(start_url, max_pages=10, session=None):
    """
    Rastrea el sitio web descubriendo URLs mediante:
      1. Enlaces <a href> del HTML (método clásico)
      2. sitemap.xml / sitemap_index.xml
      3. robots.txt (rutas Disallow/Allow)
      4. Rutas SPA comunes (/login, /dashboard, /register, ...)
    Hasta alcanzar max_pages páginas únicas.
    """
    visited = set()
    client = session if session is not None else requests

    parsed_start = urlparse(start_url)
    root_url = f"{parsed_start.scheme}://{parsed_start.netloc}/"

    print(f"  🕸️ Iniciando rastreo web (límite: {max_pages} páginas)...")

    # Conjunto de semillas inicial: la URL de inicio
    to_visit = [start_url]

    # 1. Añadir URLs de sitemap.xml
    sitemap_urls = fetch_sitemap(root_url, session=session)
    if sitemap_urls:
        print(f"  🗺️  sitemap.xml: {len(sitemap_urls)} URL(s) descubiertas")
        to_visit.extend(sitemap_urls)

    # 2. Añadir rutas de robots.txt
    robots_paths, robots_sitemaps = fetch_robots_paths(root_url, session=session)
    for sm in robots_sitemaps:
        sitemap_urls |= fetch_sitemap(sm, session=session)
    for path in robots_paths:
        to_visit.append(urljoin(root_url, path))
    if robots_paths:
        print(f"  🤖 robots.txt: {len(robots_paths)} ruta(s) descubiertas")

    # 3. Añadir rutas SPA comunes (solo si no superan ampliamente el límite)
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
        except Exception as e:
            # En caso de error de conexión de una subpágina, la marcamos como visitada para no reintentar
            visited.add(current_url)

    print(f"  🕸️ Rastreo finalizado. Páginas encontradas: {len(visited)}")
    return list(visited)
