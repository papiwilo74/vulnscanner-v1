"""
OmniBreach v3.0 — External Attack Surface Management (EASM) Engine.
Mapeo de perímetro digital, descubrimiento de activos en la nube, detección de puertos
críticos para Ransomware y correlación de vulnerabilidades explotadas activamente (CISA KEV).
"""
from scanner.easm.advisor import AIRemediationAdvisor, RemediationRunbook
from scanner.easm.cve_intel import CISAExploitIntel, CVEFinding
from scanner.easm.darkweb_intel import DarkWebIntel, IdentityExposure
from scanner.easm.engine import EASMEngine, EASMReport
from scanner.easm.recon import AssetDiscovery, DigitalPerimeterMapper
from scanner.easm.secret_leaks import SecretLeakFinding, SecretLeakScanner
from scanner.easm.service_scout import ExposedService, ServiceScout
from scanner.easm.takeover import SubdomainTakeoverScanner, TakeoverVulnerability

__all__ = [
    "DigitalPerimeterMapper",
    "AssetDiscovery",
    "ServiceScout",
    "ExposedService",
    "CISAExploitIntel",
    "CVEFinding",
    "DarkWebIntel",
    "IdentityExposure",
    "SubdomainTakeoverScanner",
    "TakeoverVulnerability",
    "SecretLeakScanner",
    "SecretLeakFinding",
    "AIRemediationAdvisor",
    "RemediationRunbook",
    "EASMEngine",
    "EASMReport",
]
