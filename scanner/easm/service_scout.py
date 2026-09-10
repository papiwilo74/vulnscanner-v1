"""
Módulo de Detección de Puertos y Servicios de Alto Riesgo (EASM Service Scout).
Identifica servicios expuestos directamente a internet propensos a ataques de Ransomware,
movimiento lateral y filtración de datos (RDP, SMB, Redis sin clave, MongoDB, Docker API).
"""
from __future__ import annotations

import contextlib
import logging
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger("OmniBreach.EASM.ServiceScout")

# Puertos críticos con perfil de riesgo empresarial
CRITICAL_EASM_PORTS: dict[int, dict[str, Any]] = {
    # 🚨 Vectores de Ransomware y Acceso Remoto
    3389: {
        "name": "RDP",
        "category": "Remote Access",
        "severity": "CRITICAL",
        "ransomware_vector": True,
        "description": "Escritorio remoto de Windows expuesto a internet. Vector #1 de intrusión para ransomware corporativo.",
    },
    445: {
        "name": "SMB",
        "category": "File Sharing",
        "severity": "CRITICAL",
        "ransomware_vector": True,
        "description": "Server Message Block (SMB). Riesgo crítico de explotación remota (EternalBlue, WannaCry) y robo de hashes NTLM.",
    },
    22: {
        "name": "SSH",
        "category": "Remote Access",
        "severity": "MEDIUM",
        "ransomware_vector": False,
        "description": "Terminal remota segura. Expuesto a ataques de fuerza bruta de credenciales.",
    },
    23: {
        "name": "Telnet",
        "category": "Remote Access",
        "severity": "HIGH",
        "ransomware_vector": True,
        "description": "Protocolo de terminal obsoleto y sin cifrado. Contraseñas transmitidas en texto plano.",
    },
    5900: {
        "name": "VNC",
        "category": "Remote Access",
        "severity": "HIGH",
        "ransomware_vector": True,
        "description": "Consola gráfica VNC expuesta a internet. Alto riesgo de acceso no autorizado.",
    },
    # 🗄️ Bases de Datos Expuestas
    6379: {
        "name": "Redis",
        "category": "NoSQL Database",
        "severity": "CRITICAL",
        "ransomware_vector": True,
        "description": "Base de datos / caché Redis. Si carece de autenticación, permite ejecución remota de código (RCE) y vaciado de datos.",
    },
    27017: {
        "name": "MongoDB",
        "category": "NoSQL Database",
        "severity": "CRITICAL",
        "ransomware_vector": True,
        "description": "Base de datos NoSQL MongoDB. Riesgo crítico de secuestro de base de datos si no requiere autenticación.",
    },
    9200: {
        "name": "Elasticsearch",
        "category": "Search / DB",
        "severity": "HIGH",
        "ransomware_vector": False,
        "description": "Cluster de Elasticsearch expuesto. Frecuente filtración masiva de registros y datos sensibles.",
    },
    1433: {
        "name": "MSSQL",
        "category": "SQL Database",
        "severity": "HIGH",
        "ransomware_vector": False,
        "description": "Servidor de base de datos Microsoft SQL Server accesible desde internet.",
    },
    3306: {
        "name": "MySQL",
        "category": "SQL Database",
        "severity": "HIGH",
        "ransomware_vector": False,
        "description": "Servidor de base de datos MySQL/MariaDB expuesto directamente al exterior.",
    },
    5432: {
        "name": "PostgreSQL",
        "category": "SQL Database",
        "severity": "HIGH",
        "ransomware_vector": False,
        "description": "Servidor de base de datos relacional PostgreSQL expuesto.",
    },
    # 🐳 DevOps / Orquestación
    2375: {
        "name": "Docker Daemon",
        "category": "Containerization",
        "severity": "CRITICAL",
        "ransomware_vector": True,
        "description": "API de Docker sin TLS. Permite a cualquier atacante tomar control total del servidor anfitrión.",
    },
    6443: {
        "name": "Kubernetes API",
        "category": "Orchestration",
        "severity": "HIGH",
        "ransomware_vector": False,
        "description": "API Server de Kubernetes expuesto a internet.",
    },
    8080: {
        "name": "HTTP-Alt / Jenkins",
        "category": "Web Management",
        "severity": "MEDIUM",
        "ransomware_vector": False,
        "description": "Puerto web alternativo, paneles Tomcat o servidores CI/CD Jenkins.",
    },
}


@dataclass
class ExposedService:
    """Representa un puerto o servicio de alto riesgo descubierto en el escaneo."""
    host: str
    ip: str
    port: int
    service_name: str
    severity: str
    description: str
    ransomware_vector: bool = False
    unauthenticated_access: bool = False
    banner: str = ""
    evidence: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "ip": self.ip,
            "port": self.port,
            "service_name": self.service_name,
            "severity": self.severity,
            "description": self.description,
            "ransomware_vector": self.ransomware_vector,
            "unauthenticated_access": self.unauthenticated_access,
            "banner": self.banner,
            "evidence": self.evidence,
        }


class ServiceScout:
    """Escanea y valida servicios críticos en el perímetro con rate-limiting y banner grabbing."""

    def __init__(self, timeout: float = 1.5):
        self.timeout = timeout

    def grab_banner(self, ip: str, port: int) -> tuple[str, bool, str]:
        """
        Conecta al servicio para capturar su banner e inspeccionar si permite
        acceso no autenticado sin romper ni alterar nada (sondeo inocuo).
        """
        banner = ""
        unauth = False
        evidence = ""

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                s.connect((ip, port))

                # Sondeo especializado para Redis (Puerto 6379)
                if port == 6379:
                    s.sendall(b"PING\r\n")
                    resp = s.recv(128).decode("latin-1", errors="ignore")
                    if "+PONG" in resp:
                        unauth = True
                        evidence = "Respuesta de Redis sin autenticación: +PONG"
                        banner = "Redis (Unauthenticated)"

                # Sondeo especializado para Elasticsearch (Puerto 9200)
                elif port == 9200:
                    s.sendall(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
                    resp = s.recv(512).decode("latin-1", errors="ignore")
                    if "cluster_name" in resp or "tagline" in resp:
                        unauth = True
                        evidence = "API de Elasticsearch respondió JSON sin requerir credenciales"
                        banner = "Elasticsearch API (Publicly Accessible)"

                # Sondeo estándar de banner de bienvenida (SSH, FTP, SMTP, etc.)
                else:
                    # Enviar salto de línea si no habla primero
                    s.settimeout(1.0)
                    with contextlib.suppress(Exception):
                        data = s.recv(256)
                        if data:
                            banner = data.decode("latin-1", errors="ignore").strip()

        except (OSError, socket.timeout):
            pass

        return banner[:200], unauth, evidence

    def scan_host_services(self, host: str, ip: str, ports: list[int] | None = None) -> list[ExposedService]:
        """Escanea concurrentemente los puertos críticos para una IP / host específico."""
        target_ports = ports or list(CRITICAL_EASM_PORTS.keys())
        findings: list[ExposedService] = []

        def _probe_port(p: int) -> ExposedService | None:
            spec = CRITICAL_EASM_PORTS.get(p, {
                "name": f"Port-{p}",
                "severity": "LOW",
                "ransomware_vector": False,
                "description": f"Puerto TCP {p} expuesto a internet."
            })

            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(self.timeout)
                    if s.connect_ex((ip, p)) == 0:
                        banner, unauth, evidence = self.grab_banner(ip, p)
                        severity = spec.get("severity", "MEDIUM")
                        if unauth:
                            severity = "CRITICAL"

                        return ExposedService(
                            host=host,
                            ip=ip,
                            port=p,
                            service_name=spec.get("name", "Desconocido"),
                            severity=severity,
                            description=spec.get("description", ""),
                            ransomware_vector=spec.get("ransomware_vector", False),
                            unauthenticated_access=unauth,
                            banner=banner,
                            evidence=evidence,
                        )
            except (OSError, socket.timeout):
                pass
            return None

        # Concurrencia controlada para no saturar enlaces
        with ThreadPoolExecutor(max_workers=min(len(target_ports), 15)) as executor:
            futures = [executor.submit(_probe_port, p) for p in target_ports]
            for fut in as_completed(futures):
                with contextlib.suppress(Exception):
                    res = fut.result()
                    if res:
                        findings.append(res)

        findings.sort(key=lambda x: (0 if x.severity == "CRITICAL" else 1 if x.severity == "HIGH" else 2))
        return findings

    def scout_perimeter(
        self,
        assets: list[Any],
        ports: list[int] | None = None,
        max_workers: int = 10
    ) -> list[ExposedService]:
        """
        Escanea la lista completa de activos descubiertos en el perímetro digital.
        """
        all_exposed: list[ExposedService] = []
        if not assets:
            return all_exposed

        # Deduplicar por dirección IP previamente para evitar carreras entre hilos y trabajo duplicado
        unique_targets: dict[str, str] = {}
        for asset in assets:
            raw_ip = getattr(asset, "ip_address", None) or (asset if isinstance(asset, str) else None)
            if raw_ip and isinstance(raw_ip, str) and raw_ip not in unique_targets:
                raw_host = getattr(asset, "subdomain", None) or raw_ip
                unique_targets[raw_ip] = str(raw_host)

        if not unique_targets:
            return all_exposed

        def _scan_target(target: tuple[str, str]) -> list[ExposedService]:
            ip_str, host_str = target
            return self.scan_host_services(host_str, ip_str, ports=ports)

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(_scan_target, (ip, host)) for ip, host in unique_targets.items()]
            for fut in as_completed(futures):
                try:
                    res = fut.result()
                    all_exposed.extend(res)
                except Exception as err:
                    logger.debug("Error analizando activo en scout: %s", err)

        return all_exposed
