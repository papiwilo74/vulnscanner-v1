"""
Módulo de Reconocimiento y Cartografía de Superficie Externa (EASM).
Descubre el perímetro digital completo de una organización a través de:
1. Registros de Certificate Transparency (CT Logs vía crt.sh).
2. Resolución y enumeración DNS concurrente con mutaciones de infraestructura.
3. Detección de activos en la nube (AWS, Azure, GCP, Cloudflare) y Shadow IT.
"""
from __future__ import annotations

import contextlib
import logging
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

import requests

logger = logging.getLogger("OmniBreach.EASM.Recon")

# Prefijos corporativos críticos para fuerza bruta y descubrimiento
CORPORATE_PREFIXES: list[str] = [
    "www", "mail", "remote", "vpn", "portal", "admin", "api", "auth", "login",
    "sso", "citrix", "rdp", "ssh", "dev", "stage", "staging", "test", "qa",
    "lab", "db", "database", "sql", "redis", "mongo", "elastic", "billing",
    "salud", "pago", "pagos", "clientes", "intranet", "cloud", "git", "gitlab",
    "jira", "confluence", "backup", "backups", "monitor", "grafana", "kibana",
    "prometheus", "app", "mobile", "gateway", "proxy", "services", "internal"
]

CLOUD_SIGNATURES: dict[str, str] = {
    "amazonaws.com": "Amazon Web Services (AWS)",
    "awsglobalaccelerator.com": "AWS Global Accelerator",
    "azure.com": "Microsoft Azure",
    "azurewebsites.net": "Microsoft Azure App Service",
    "cloudapp.azure.com": "Microsoft Azure VM",
    "trafficmanager.net": "Azure Traffic Manager",
    "google.com": "Google Cloud Platform",
    "1e100.net": "Google Infrastructure",
    "appspot.com": "Google App Engine",
    "cloudflare.net": "Cloudflare CDN/WAF",
    "digitaloceanspaces.com": "DigitalOcean Spaces",
    "digitalocean.com": "DigitalOcean",
    "oraclecloud.com": "Oracle Cloud",
    "herokuapp.com": "Heroku",
}


@dataclass
class AssetDiscovery:
    """Representa un activo digital descubierto en el perímetro externo."""
    subdomain: str
    ip_address: str | None = None
    source: str = "DNS"
    is_live: bool = False
    cname: str | None = None
    cloud_provider: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "subdomain": self.subdomain,
            "ip_address": self.ip_address,
            "source": self.source,
            "is_live": self.is_live,
            "cname": self.cname,
            "cloud_provider": self.cloud_provider,
            "metadata": self.metadata,
        }


class DigitalPerimeterMapper:
    """Mapea la cartografía externa completa de un dominio corporativo."""

    def __init__(self, timeout: float = 6.0):
        self.timeout = timeout

    def sanitize_domain(self, target: str) -> str:
        """Limpia el dominio eliminando esquemas http/https, puertos o rutas."""
        clean = target.strip().lower()
        if "://" in clean:
            parsed = urlparse(clean)
            clean = parsed.hostname or clean
        clean = clean.split("/")[0].split(":")[0]
        return clean.lstrip(".")

    def fetch_ct_logs(self, domain: str) -> set[str]:
        """
        Consulta registros públicos de Certificate Transparency (crt.sh)
        para descubrir certificados emitidos históricamente para el dominio.
        """
        discovered: set[str] = set()
        clean_domain = self.sanitize_domain(domain)
        url = f"https://crt.sh/?q=%.{clean_domain}&output=json"

        try:
            headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) OmniBreach-EASM/3.0"}
            resp = requests.get(url, headers=headers, timeout=12)
            if resp.status_code == 200:
                try:
                    entries = resp.json()
                    if isinstance(entries, list):
                        for entry in entries:
                            name_val = entry.get("name_value", "")
                            # Los certificados pueden contener múltiples nombres separados por saltos de línea
                            for sub in name_val.split("\n"):
                                sub_clean = sub.strip().lower()
                                if sub_clean.startswith("*."):
                                    sub_clean = sub_clean[2:]
                                if sub_clean.endswith(clean_domain) and sub_clean != clean_domain:
                                    discovered.add(sub_clean)
                except Exception as json_err:
                    logger.debug("Error procesando JSON de crt.sh: %s", json_err)
        except Exception as err:
            logger.warning("[EASM] No se pudo consultar crt.sh para %s (%s). Continuando con reconocimiento DNS...", domain, err)

        return discovered

    def resolve_subdomain(self, subdomain: str) -> tuple[str | None, str | None]:
        """Resuelve la dirección IP y el registro CNAME (si existe)."""
        ip: str | None = None
        cname: str | None = None

        with contextlib.suppress(socket.gaierror, socket.herror, TimeoutError):
            ip = socket.gethostbyname(subdomain)

        with contextlib.suppress(Exception):
            canonical, _, _ = socket.gethostbyname_ex(subdomain)
            if canonical and canonical.lower() != subdomain.lower():
                cname = canonical

        return ip, cname

    def identify_cloud_provider(self, hostname: str, ip: str | None, cname: str | None) -> str | None:
        """Detecta si el activo está alojado en un proveedor cloud o CDN."""
        checks = [hostname.lower()]
        if cname:
            checks.append(cname.lower())

        for target in checks:
            for sig, provider_name in CLOUD_SIGNATURES.items():
                if sig in target:
                    return provider_name

        if ip:
            # Detección por rangos conocidos básicos o reversos
            with contextlib.suppress(Exception):
                rev_dns = socket.gethostbyaddr(ip)[0].lower()
                for sig, provider_name in CLOUD_SIGNATURES.items():
                    if sig in rev_dns:
                        return provider_name

        return None

    def map_perimeter(
        self,
        domain: str,
        include_bruteforce: bool = True,
        custom_prefixes: list[str] | None = None,
        max_workers: int = 20
    ) -> list[AssetDiscovery]:
        """
        Ejecuta la cartografía completa del dominio corporativo combinando
        fuentes pasivas (Certificate Transparency) y activas (DNS Recursivo).
        """
        clean_domain = self.sanitize_domain(domain)
        logger.info("[EASM] Iniciando cartografía de superficie para: %s", clean_domain)

        candidates: set[str] = set()

        # 1. CT Logs (Pasivo)
        ct_subdomains = self.fetch_ct_logs(clean_domain)
        candidates.update(ct_subdomains)
        logger.info("[EASM] %d subdominios descubiertos vía Certificate Transparency (crt.sh)", len(ct_subdomains))

        # 2. Generación de prefijos para fuerza bruta (Activo)
        if include_bruteforce:
            prefixes = custom_prefixes or CORPORATE_PREFIXES
            for p in prefixes:
                candidates.add(f"{p}.{clean_domain}")

        # Incluir también el dominio raíz
        candidates.add(clean_domain)

        results: list[AssetDiscovery] = []

        # 3. Resolución concurrente
        def _check_candidate(sub: str) -> AssetDiscovery | None:
            ip, cname = self.resolve_subdomain(sub)
            if ip is None:
                return None

            source = "Certificate Transparency" if sub in ct_subdomains else "DNS Active Scout"
            cloud = self.identify_cloud_provider(sub, ip, cname)

            return AssetDiscovery(
                subdomain=sub,
                ip_address=ip,
                source=source,
                is_live=True,
                cname=cname,
                cloud_provider=cloud,
            )

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(_check_candidate, cand) for cand in candidates]
            for fut in as_completed(futures):
                try:
                    res = fut.result()
                    if res:
                        results.append(res)
                except Exception as err:
                    logger.debug("Error analizando candidato EASM: %s", err)

        # Ordenar por nombre de subdominio
        results.sort(key=lambda x: x.subdomain)
        logger.info("[EASM] Cartografía finalizada. Total activos activos identificados: %d", len(results))
        return results
