import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Optional
from urllib.parse import urlparse

import requests

COMMON_SUBDOMAINS: list[str] = [
    "www", "admin", "api", "dev", "stage", "staging", "blog",
    "mail", "test", "shop", "portal", "vpn", "db", "database",
    "secure", "demo", "docs", "app", "git"
]

PLATFORM_ERROR_SIGNATURES = [
    "DEPLOYMENT_NOT_FOUND",
    "DEPLOYMENT_DISABLED",
    "This deployment could not be found",
    "There isn't a GitHub Pages site here",
    "Heroku | No such app",
    "Netlify",
    "project is not deployed",
    "Application Error",
    "This page is reserved",
    "This site is not configured",
]


def _resolve_dns(target: str) -> Optional[str]:
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return None


def _is_platform_error_page(text: str) -> bool:
    lower = text.lower()
    for sig in PLATFORM_ERROR_SIGNATURES:
        if sig.lower() in lower:
            return True
    stripped = text.strip().lower()
    return stripped in ("not found", "404: not_found", "404 not found")


def _verify_subdomain(target: str, scheme: str, main_html_hash: int) -> Optional[dict[str, str]]:
    ip = _resolve_dns(target)
    if ip is None:
        return None

    schemes = [scheme] if scheme == "https" else [scheme, "https"]
    for try_scheme in schemes:
        candidate = f"{try_scheme}://{target}"
        try:
            r = requests.get(candidate, timeout=6, allow_redirects=True)
            if r.status_code in (200, 301, 302, 401, 403):
                if _is_platform_error_page(r.text):
                    continue
                if hash(r.text[:2000]) == main_html_hash:
                    continue
                return {
                    "vuln": "Subdominio Activo Descubierto",
                    "risk": "Bajo",
                    "detail": f"Subdominio activo verificado: {target} -> IP: {ip} (HTTP {r.status_code})"
                }
        except requests.RequestException:
            continue

    return {
        "vuln": "Subdominio Activo Descubierto (DNS)",
        "risk": "Bajo",
        "detail": f"Subdominio resuelto por DNS: {target} -> IP: {ip}"
    }


def check_subdomains(url: str) -> list[dict[str, str]]:
    results: list[dict[str, str]] = []
    parsed = urlparse(url)
    hostname = parsed.hostname

    if not hostname:
        return results

    scheme = parsed.scheme
    parts = hostname.split('.')
    if parts[-1].isdigit():
        return results

    domain = hostname
    print(f"  Buscando subdominios activos para el dominio base: {domain}...")

    main_html_hash = 0
    try:
        r = requests.get(url, timeout=8)
        main_html_hash = hash(r.text[:2000])
    except requests.RequestException:
        pass

    subdomains_to_check = [s for s in COMMON_SUBDOMAINS if f"{s}.{domain}" != hostname]

    dns_found: list[tuple[str, str]] = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures: dict[Any, str] = {}
        for sub in subdomains_to_check:
            target = f"{sub}.{domain}"
            futures[executor.submit(_resolve_dns, target)] = sub
        for future in as_completed(futures):
            ip = future.result()
            if ip is not None:
                sub = futures[future]
                dns_found.append((sub, ip))

    if dns_found:
        print(f"    {len(dns_found)} subdominio(s) resuelven DNS - verificando HTTP...")
        with ThreadPoolExecutor(max_workers=6) as executor:
            http_futures: dict[Any, str] = {}
            for sub, _ in dns_found:
                target = f"{sub}.{domain}"
                http_futures[executor.submit(_verify_subdomain, target, scheme, main_html_hash)] = target
            for future in as_completed(http_futures):
                res = future.result()
                if res and isinstance(res, dict):
                    results.append(res)

    return results
