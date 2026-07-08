import socket
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

# Lista optimizada y común de subdominios a comprobar
COMMON_SUBDOMAINS = [
    "www",
    "admin",
    "api",
    "dev",
    "stage",
    "staging",
    "blog",
    "mail",
    "test",
    "shop",
    "portal",
    "vpn",
    "db",
    "database",
    "secure",
    "demo",
    "docs",
    "app",
    "git"
]

def resolve_subdomain(subdomain, domain):
    """
    Intenta resolver un subdominio. Retorna la IP si es exitoso.
    """
    target = f"{subdomain}.{domain}"
    try:
        ip = socket.gethostbyname(target)
        return {
            "vuln": "Subdominio Activo Descubierto",
            "risk": "Bajo",
            "detail": f"Subdominio activo mapeado: {target} → IP: {ip}"
        }
    except socket.gaierror:
        # No se pudo resolver, el subdominio no existe o no es público
        return None

def check_subdomains(url):
    """
    Extrae el dominio de la URL y realiza fuerza bruta de subdominios comunes de forma concurrente.
    
    Args:
        url: URL del sitio web.
        
    Returns:
        Lista de subdominios activos encontrados con sus respectivas IPs.
    """
    results = []
    parsed = urlparse(url)
    hostname = parsed.hostname
    
    if not hostname:
        return results

    # Extraer el dominio base (ej. 'ejemplo.com' desde 'www.ejemplo.com' o 'sub.dev.ejemplo.com')
    # Dividir y tomar las últimas dos partes si no es una dirección IP
    parts = hostname.split('.')
    if len(parts) >= 2:
        # Validar que no sea una IP literal (ej. 192.168.1.1)
        if not parts[-1].isdigit():
            domain = ".".join(parts[-2:])
        else:
            return results
    else:
        return results

    print(f"  🔍 Buscando subdominios activos para el dominio base: {domain}...")
    
    # Resolver en paralelo utilizando un ThreadPoolExecutor
    subdomains_to_check = [s for s in COMMON_SUBDOMAINS if f"{s}.{domain}" != hostname]
    
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(resolve_subdomain, sub, domain): sub for sub in subdomains_to_check}
        for future in as_completed(futures):
            res = future.result()
            if res:
                results.append(res)
                
    return results
