"""
Orquestador Principal de External Attack Surface Management (EASM Engine).
Consolida la cartografía perimetral, el escaneo de puertos de alto riesgo,
la correlación CISA KEV y la inteligencia de amenazas en un reporte integral con calificación de riesgo.
"""
from __future__ import annotations

import datetime
import logging
from dataclasses import dataclass, field
from typing import Any

from scanner.easm.cve_intel import CISAExploitIntel, CVEFinding
from scanner.easm.darkweb_intel import DarkWebIntel, IdentityExposure
from scanner.easm.recon import AssetDiscovery, DigitalPerimeterMapper
from scanner.easm.service_scout import ExposedService, ServiceScout

logger = logging.getLogger("OmniBreach.EASM.Engine")


@dataclass
class EASMReport:
    """Informe ejecutivo y técnico de Gestión de Superficie de Ataque Externa."""
    root_domain: str
    scan_timestamp: str
    exposure_score: int
    exposure_grade: str
    total_assets: int
    total_exposed_services: int
    critical_ransomware_vectors: int
    cisa_kev_alerts: int
    assets: list[dict[str, Any]] = field(default_factory=list)
    services: list[dict[str, Any]] = field(default_factory=list)
    cves: list[dict[str, Any]] = field(default_factory=list)
    identity_risk: dict[str, Any] = field(default_factory=dict)
    summary: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "root_domain": self.root_domain,
            "scan_timestamp": self.scan_timestamp,
            "exposure_score": self.exposure_score,
            "exposure_grade": self.exposure_grade,
            "total_assets": self.total_assets,
            "total_exposed_services": self.total_exposed_services,
            "critical_ransomware_vectors": self.critical_ransomware_vectors,
            "cisa_kev_alerts": self.cisa_kev_alerts,
            "assets": self.assets,
            "services": self.services,
            "cves": self.cves,
            "identity_risk": self.identity_risk,
            "summary": self.summary,
        }


class EASMEngine:
    """Motor central de evaluación de superficie externa para OmniBreach v3.0."""

    def __init__(
        self,
        recon_mapper: DigitalPerimeterMapper | None = None,
        service_scout: ServiceScout | None = None,
        cve_intel: CISAExploitIntel | None = None,
        darkweb_intel: DarkWebIntel | None = None,
    ):
        self.recon = recon_mapper or DigitalPerimeterMapper()
        self.scout = service_scout or ServiceScout()
        self.cve_intel = cve_intel or CISAExploitIntel()
        self.darkweb = darkweb_intel or DarkWebIntel()

    def calculate_score(
        self,
        services: list[ExposedService],
        cves: list[CVEFinding],
        identity: IdentityExposure
    ) -> tuple[int, str]:
        """
        Calcula el Score de Exposición Externa (0 a 100) y su grado (A+ a F).
        100 representa una superficie hermética y segura sin servicios riesgosos expuestos.
        """
        score = 100

        # Penalización por servicios expuestos
        for s in services:
            if s.severity == "CRITICAL" or s.unauthenticated_access:
                score -= 25
            elif s.ransomware_vector:
                score -= 20
            elif s.severity == "HIGH":
                score -= 15
            elif s.severity == "MEDIUM":
                score -= 5

        # Penalización grave por CVEs en el catálogo CISA KEV (activamente explotados)
        score -= (len(cves) * 25)

        # Penalización por suplantación activa
        if identity.risk_level == "HIGH":
            score -= 10

        final_score = max(0, min(100, score))

        if final_score >= 95:
            grade = "A+"
        elif final_score >= 85:
            grade = "A"
        elif final_score >= 70:
            grade = "B"
        elif final_score >= 50:
            grade = "C"
        elif final_score >= 35:
            grade = "D"
        else:
            grade = "F"

        return final_score, grade

    def run_full_surface_assessment(
        self,
        domain: str,
        include_bruteforce: bool = True,
        max_workers: int = 20
    ) -> EASMReport:
        """
        Ejecuta la auditoría integral de superficie de ataque externa de punta a punta.
        """
        clean_domain = self.recon.sanitize_domain(domain)
        logger.info("[EASM] Iniciando auditoría perimetral completa para: %s", clean_domain)

        # 1. Cartografía perimetral y activos
        assets: list[AssetDiscovery] = self.recon.map_perimeter(
            clean_domain,
            include_bruteforce=include_bruteforce,
            max_workers=max_workers
        )

        # 2. Escaneo de servicios críticos y vectores de ransomware
        exposed_services: list[ExposedService] = self.scout.scout_perimeter(
            assets,
            max_workers=min(max_workers, 15)
        )

        # 3. Correlación CISA KEV y exploits públicos
        cve_alerts: list[CVEFinding] = self.cve_intel.analyze_services(exposed_services)

        # 4. Inteligencia de identidad y typosquatting
        identity_exp: IdentityExposure = self.darkweb.inspect_identity_risk(clean_domain)

        # 5. Cálculo de métricas y Score
        score, grade = self.calculate_score(exposed_services, cve_alerts, identity_exp)

        ransomware_vectors = sum(1 for s in exposed_services if s.ransomware_vector or s.unauthenticated_access)

        summary = {
            "critical_services_count": sum(1 for s in exposed_services if s.severity == "CRITICAL"),
            "high_services_count": sum(1 for s in exposed_services if s.severity == "HIGH"),
            "unauthenticated_databases": sum(1 for s in exposed_services if s.unauthenticated_access),
            "top_cloud_providers": list({a.cloud_provider for a in assets if a.cloud_provider}),
        }

        report = EASMReport(
            root_domain=clean_domain,
            scan_timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            exposure_score=score,
            exposure_grade=grade,
            total_assets=len(assets),
            total_exposed_services=len(exposed_services),
            critical_ransomware_vectors=ransomware_vectors,
            cisa_kev_alerts=len(cve_alerts),
            assets=[a.to_dict() for a in assets],
            services=[s.to_dict() for s in exposed_services],
            cves=[c.to_dict() for c in cve_alerts],
            identity_risk=identity_exp.to_dict(),
            summary=summary,
        )

        logger.info(
            "[EASM] Auditoría completada para %s. Score: %d (%s) | Activos: %d | Servicios Expuestos: %d",
            clean_domain, score, grade, len(assets), len(exposed_services)
        )
        return report
