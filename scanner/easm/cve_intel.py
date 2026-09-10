"""
Módulo de Inteligencia de Vulnerabilidades y Correlación CISA KEV (EASM CVE Intel).
Cruza tecnologías y versiones detectadas en el perímetro contra el catálogo de
Known Exploited Vulnerabilities (CISA KEV) e identifica exploits públicos (PoCs).
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger("OmniBreach.EASM.CVEIntel")


@dataclass
class CVEFinding:
    """Representa una vulnerabilidad correlacionada en un activo del perímetro."""
    cve_id: str
    vulnerability_name: str
    severity: str
    affected_product: str
    detected_version: str
    cisa_kev_listed: bool = True
    has_public_exploit: bool = True
    ransomware_campaign: str = "General Threat Actors"
    remediation_steps: str = ""
    evidence: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "vulnerability_name": self.vulnerability_name,
            "severity": self.severity,
            "affected_product": self.affected_product,
            "detected_version": self.detected_version,
            "cisa_kev_listed": self.cisa_kev_listed,
            "has_public_exploit": self.has_public_exploit,
            "ransomware_campaign": self.ransomware_campaign,
            "remediation_steps": self.remediation_steps,
            "evidence": self.evidence,
        }


# Base de firmas críticas CISA KEV observadas frecuentemente en intrusiones corporativas
CISA_KEV_DATABASE: list[dict[str, Any]] = [
    {
        "cve_id": "CVE-2021-41773",
        "name": "Apache HTTP Server Path Traversal & Remote Code Execution",
        "product": "Apache HTTP Server",
        "pattern": r"apache/(?:2\.4\.49|2\.4\.50)",
        "severity": "CRITICAL",
        "ransomware": "BlackCat / ALPHV",
        "has_poc": True,
        "remediation": "Actualizar de inmediato a Apache HTTP Server 2.4.51 o superior."
    },
    {
        "cve_id": "CVE-2024-6387",
        "name": "OpenSSH 'regreSSHion' Remote Code Execution",
        "product": "OpenSSH",
        "pattern": r"openssh_(?:8\.[5-9]|9\.[0-7])p1",
        "severity": "CRITICAL",
        "ransomware": "Botnets & Ransomware Pre-intrusions",
        "has_poc": True,
        "remediation": "Actualizar OpenSSH a versión 9.8p1 o posterior, o restringir puerto SSH mediante firewall/VPN."
    },
    {
        "cve_id": "CVE-2023-4966",
        "name": "Citrix Bleed - Session Token Hijacking",
        "product": "Citrix NetScaler Gateway",
        "pattern": r"(?:citrix|netscaler)",
        "severity": "CRITICAL",
        "ransomware": "LockBit 3.0 / Medusa",
        "has_poc": True,
        "remediation": "Aplicar parches oficiales de Citrix y cerrar todas las sesiones activas en Gateway."
    },
    {
        "cve_id": "CVE-2022-26134",
        "name": "Atlassian Confluence OGNL Injection Remote Code Execution",
        "product": "Atlassian Confluence",
        "pattern": r"confluence",
        "severity": "CRITICAL",
        "ransomware": "Akira / LockBit",
        "has_poc": True,
        "remediation": "Actualizar Atlassian Confluence a versiones 7.4.17, 7.13.7, 7.14.3, o superiores."
    },
    {
        "cve_id": "CVE-2021-26855",
        "name": "Microsoft Exchange Server SSRF (ProxyLogon)",
        "product": "Microsoft Exchange Server",
        "pattern": r"(?:owa|exchange)",
        "severity": "CRITICAL",
        "ransomware": "Hafnium / BlackByte",
        "has_poc": True,
        "remediation": "Aplicar las actualizaciones de seguridad de emergencia de Microsoft Exchange acumuladas."
    },
    {
        "cve_id": "CVE-2021-44228",
        "name": "Apache Log4j JNDI Remote Code Execution (Log4Shell)",
        "product": "Apache Log4j",
        "pattern": r"(?:log4j|spring-boot)",
        "severity": "CRITICAL",
        "ransomware": "Widespread Ransomware Campaigns",
        "has_poc": True,
        "remediation": "Actualizar dependencias log4j a versión 2.17.1 o superior, o deshabilitar JNDI lookup."
    },
    {
        "cve_id": "CVE-2018-13379",
        "name": "Fortinet FortiOS SSL-VPN Credential Disclosure",
        "product": "Fortinet FortiOS",
        "pattern": r"(?:fortinet|fortigate|fortios)",
        "severity": "CRITICAL",
        "ransomware": "Conti / LockBit / Cuba Ransomware",
        "has_poc": True,
        "remediation": "Actualizar firmware FortiOS de forma inmediata y forzar cambio de credenciales VPN."
    }
]


class CISAExploitIntel:
    """Motor de correlación para evaluar exposición a vulnerabilidades de alto impacto."""

    def __init__(self, custom_rules: list[dict[str, Any]] | None = None):
        self.rules = custom_rules or CISA_KEV_DATABASE

    def correlate_text(self, text_sample: str, context_label: str = "banner") -> list[CVEFinding]:
        """
        Analiza cadenas de texto (cabeceras HTTP, banners de servicios, títulos HTML)
        buscando patrones de versiones de software afectadas por vulnerabilidades CISA KEV.
        """
        findings: list[CVEFinding] = []
        if not text_sample:
            return findings

        normalized = text_sample.lower().replace(" ", "")

        for rule in self.rules:
            pattern = rule["pattern"]
            match = re.search(pattern, normalized, flags=re.IGNORECASE)
            if match:
                findings.append(
                    CVEFinding(
                        cve_id=rule["cve_id"],
                        vulnerability_name=rule["name"],
                        severity=rule["severity"],
                        affected_product=rule["product"],
                        detected_version=match.group(0),
                        cisa_kev_listed=True,
                        has_public_exploit=rule.get("has_poc", True),
                        ransomware_campaign=rule.get("ransomware", "Actores de Amenazas"),
                        remediation_steps=rule.get("remediation", "Actualizar el servicio de inmediato."),
                        evidence=f"Detectado en {context_label}: '{text_sample[:100]}'",
                    )
                )

        return findings

    def analyze_services(self, services: list[Any]) -> list[CVEFinding]:
        """Analiza la lista de servicios expuestos descubiertos en el perímetro."""
        all_cves: list[CVEFinding] = []
        seen_cves: set[str] = set()

        for svc in services:
            banner = getattr(svc, "banner", "") or ""
            service_name = getattr(svc, "service_name", "") or ""
            host = getattr(svc, "host", "") or getattr(svc, "ip", "")
            port = getattr(svc, "port", "")

            combined_text = f"{service_name} {banner}"
            cve_matches = self.correlate_text(combined_text, context_label=f"{host}:{port}")

            for c in cve_matches:
                dedup_key = f"{c.cve_id}:{host}:{port}"
                if dedup_key not in seen_cves:
                    seen_cves.add(dedup_key)
                    all_cves.append(c)

        return all_cves
