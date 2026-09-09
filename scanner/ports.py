import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional
from urllib.parse import urlparse

# Puertos críticos a analizar
PORTS_TO_SCAN: dict[int, tuple[str, str, str]] = {
    21: ("FTP", "Transferencia de archivos sin cifrar", "Medio"),
    22: ("SSH", "Acceso remoto seguro (consola de comandos)", "Medio"),
    23: ("Telnet", "Acceso remoto obsoleto e inseguro sin cifrar", "Medio"),
    25: ("SMTP", "Envío de correos electrónicos", "Medio"),
    53: ("DNS", "Resolución de nombres de dominio", "Bajo"),
    110: ("POP3", "Recuperación de correo sin cifrar", "Medio"),
    143: ("IMAP", "Acceso a correos sin cifrar", "Medio"),
    445: ("SMB", "Compartición de archivos en red (Riesgo de exploits como EternalBlue)", "Alto"),
    1433: ("MSSQL", "Base de datos Microsoft SQL Server", "Alto"),
    3306: ("MySQL", "Base de datos MySQL/MariaDB", "Alto"),
    3389: ("RDP", "Escritorio remoto de Windows", "Medio"),
    5432: ("PostgreSQL", "Base de datos PostgreSQL", "Alto"),
    8080: ("HTTP-Alt", "Servidor web alternativo o panel de administración", "Medio"),
    27017: ("MongoDB", "Base de datos NoSQL MongoDB", "Alto")
}

def check_single_port(ip: str, port: int, name: str, service: str, risk: str) -> Optional[dict[str, str]]:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1.2)
            res = s.connect_ex((ip, port))
            if res == 0:
                return {
                    "vuln": f"Puerto expuesto públicamente: {port} ({name})",
                    "risk": risk,
                    "detail": f"El puerto está abierto en la IP {ip} ({service})."
                }
    except (OSError, socket.timeout):
        pass
    return None

def check_ports(url: str) -> list[dict[str, str]]:
    results: list[dict[str, str]] = []

    parsed = urlparse(url)
    hostname = parsed.hostname

    if not hostname:
        return results

    try:
        # Intentar resolver DNS con timeout controlado de sistema
        ip = socket.gethostbyname(hostname)
        print(f"  [IP] {hostname} resolvió a: {ip}")
    except socket.gaierror:
        print(f"  [WARN] No se pudo resolver la IP para {hostname}. Omitiendo escaneo de puertos.")
        return results

    print(f"   Escaneando {len(PORTS_TO_SCAN)} puertos críticos concurrentemente...")

    # Limitar de forma segura max_workers según los elementos a escanear
    workers = min(len(PORTS_TO_SCAN), 10)
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(check_single_port, ip, port, data[0], data[1], data[2]): port
            for port, data in PORTS_TO_SCAN.items()
        }
        for future in as_completed(futures):
            try:
                res = future.result()
                if res:
                    results.append(res)
            except (OSError, TimeoutError):
                pass

    return results
