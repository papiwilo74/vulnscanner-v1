"""
Módulo de Detección de Secuestro de Subdominios (Subdomain Takeover Scanner).
Identifica registros CNAME perimetrales que apuntan a servicios en la nube desprovisionados
u olvidados (AWS S3, GitHub Pages, Heroku, Azure Web Apps, Zendesk, etc.), permitiendo
a un atacante registrar el recurso y tomar control total del subdominio institucional.
"""
from __future__ import annotations

import contextlib
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Any

import requests

logger = logging.getLogger("OmniBreach.EASM.Takeover")

# Firmas de servicios en la nube propensos a Subdomain Takeover
TAKEOVER_SIGNATURES: list[dict[str, Any]] = [
    {
        "service": "AWS S3 Bucket",
        "cname_pattern": "s3.amazonaws.com",
        "fingerprints": [
            "The specified bucket does not exist",
            "<Code>NoSuchBucket</Code>",
        ],
        "remediation": "Eliminar el registro CNAME huérfano en el DNS corporativo o reclamar el Bucket en AWS S3.",
    },
    {
        "service": "GitHub Pages",
        "cname_pattern": "github.io",
        "fingerprints": [
            "There isn't a GitHub Pages site here",
            "For root URLs (like http://example.com/) you must provide an index.html file",
        ],
        "remediation": "Eliminar el CNAME que apunta a GitHub Pages o vincular el repositorio en la organización.",
    },
    {
        "service": "Heroku App",
        "cname_pattern": "herokuapp.com",
        "fingerprints": [
            "No such app",
            "<title>No such app</title>",
            "Heroku | No such app",
        ],
        "remediation": "Eliminar el CNAME hacia herokuapp.com o desplegar una aplicación con dicho nombre.",
    },
    {
        "service": "Microsoft Azure Web App",
        "cname_pattern": "azurewebsites.net",
        "fingerprints": [
            "404 Web Site not found",
            "This web app is stopped",
        ],
        "remediation": "Eliminar el registro CNAME hacia Azure o aprovisionar la Web App correspondiente.",
    },
    {
        "service": "Zendesk Help Center",
        "cname_pattern": "zendesk.com",
        "fingerprints": [
            "Help Center Closed",
            "this help center does not exist",
        ],
        "remediation": "Reconfigurar el mapeo de host en Zendesk o borrar el registro DNS.",
    },
    {
        "service": "Fastly CDN",
        "cname_pattern": "fastly.net",
        "fingerprints": [
            "Fastly error: unknown domain",
        ],
        "remediation": "Eliminar la delegación a Fastly o dar de alta el dominio en la cuenta corporativa.",
    },
    {
        "service": "Shopify Store",
        "cname_pattern": "myshopify.com",
        "fingerprints": [
            "Sorry, this shop is currently unavailable",
            "There is no page here",
        ],
        "remediation": "Eliminar el registro CNAME que apunta a la tienda de Shopify inactiva.",
    },
    {
        "service": "Surge.sh",
        "cname_pattern": "surge.sh",
        "fingerprints": [
            "project not found",
        ],
        "remediation": "Eliminar el CNAME hacia Surge o desplegar el proyecto correspondiente.",
    },
    {
        "service": "Ghost Blog",
        "cname_pattern": "ghost.io",
        "fingerprints": [
            "The thing you were looking for is no longer here",
        ],
        "remediation": "Eliminar el CNAME hacia Ghost(Pro) o activar el blog.",
    },
    {
        "service": "Bitbucket Cloud",
        "cname_pattern": "bitbucket.io",
        "fingerprints": [
            "Repository not found",
        ],
        "remediation": "Eliminar el registro DNS o recrear el repositorio en Bitbucket.",
    },
    {
        "service": "Pantheon Hosting",
        "cname_pattern": "pantheonsite.io",
        "fingerprints": [
            "404 error unknown site!",
        ],
        "remediation": "Eliminar el CNAME que delega el sitio hacia Pantheon.",
    },
]


@dataclass
class TakeoverVulnerability:
    """Representa una vulnerabilidad de secuestro de subdominio confirmada."""
    subdomain: str
    cname: str
    service_name: str
    severity: str = "CRITICAL"
    fingerprint_detected: str = ""
    remediation: str = ""
    evidence: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "subdomain": self.subdomain,
            "cname": self.cname,
            "service_name": self.service_name,
            "severity": self.severity,
            "fingerprint_detected": self.fingerprint_detected,
            "remediation": self.remediation,
            "evidence": self.evidence,
        }


class SubdomainTakeoverScanner:
    """Escáner de seguridad perimetral para identificar secuestro de subdominios."""

    def __init__(self, timeout: float = 4.0, signatures: list[dict[str, Any]] | None = None):
        self.timeout = timeout
        self.signatures = signatures or TAKEOVER_SIGNATURES

    def inspect_subdomain(self, subdomain: str, cname: str | None) -> TakeoverVulnerability | None:
        """
        Inspecciona si el registro CNAME coincide con algún servicio vulnerable
        y verifica si el contenido HTTP contiene la huella de desprovisionamiento.
        """
        if not cname:
            return None

        cname_lower = cname.lower().strip(".")
        matched_sig: dict[str, Any] | None = None

        for sig in self.signatures:
            pattern = sig["cname_pattern"].lower()
            if pattern in cname_lower:
                matched_sig = sig
                break

        if not matched_sig:
            return None

        # Realizar prueba HTTP/HTTPS para validar si el servicio responde con el mensaje huérfano
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) OmniBreach-EASM-Takeover/3.5"}
        urls_to_try = [f"https://{subdomain}", f"http://{subdomain}"]

        for url in urls_to_try:
            try:
                resp = requests.get(url, headers=headers, timeout=self.timeout, verify=False, allow_redirects=True)  # nosec B501
                body = resp.text

                for fp in matched_sig["fingerprints"]:
                    if fp.lower() in body.lower():
                        logger.critical(
                            "[TAKEOVER ALERT] ¡Subdomain Takeover Detectado! %s (CNAME: %s) en %s",
                            subdomain, cname, matched_sig["service"]
                        )
                        return TakeoverVulnerability(
                            subdomain=subdomain,
                            cname=cname,
                            service_name=matched_sig["service"],
                            severity="CRITICAL",
                            fingerprint_detected=fp,
                            remediation=matched_sig["remediation"],
                            evidence=f"Respuesta HTTP {resp.status_code} contiene firma huérfana '{fp}'",
                        )
            except (requests.RequestException, OSError):
                continue

        return None

    def scan_assets(
        self,
        assets: list[Any],
        max_workers: int = 10
    ) -> list[TakeoverVulnerability]:
        """
        Escanea concurrentemente la lista de activos del perímetro en busca de CNAMEs huérfanos.
        """
        vulnerable: list[TakeoverVulnerability] = []
        if not assets:
            return vulnerable

        candidates: list[tuple[str, str]] = []
        for asset in assets:
            sub = getattr(asset, "subdomain", None) or (asset.get("subdomain") if isinstance(asset, dict) else (asset if isinstance(asset, str) else None))
            cname = getattr(asset, "cname", None) or (asset.get("cname") if isinstance(asset, dict) else None)
            if sub and cname:
                candidates.append((str(sub), str(cname)))

        if not candidates:
            return vulnerable

        def _worker(target: tuple[str, str]) -> TakeoverVulnerability | None:
            sub, cname = target
            with contextlib.suppress(Exception):
                return self.inspect_subdomain(sub, cname)
            return None

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(_worker, c) for c in candidates]
            for fut in as_completed(futures):
                try:
                    res = fut.result()
                    if res:
                        vulnerable.append(res)
                except Exception as err:
                    logger.debug("Error analizando takeover en candidato: %s", err)

        return vulnerable
