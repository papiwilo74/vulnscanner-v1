"""Detector inteligente de WAF (Web Application Firewall) y firmas de seguridad."""
import logging
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urljoin

import requests

from scanner.models import Finding

log = logging.getLogger("VulnScanner.WAF")

# Firmas de WAFs conocidos en cabeceras, cookies y cuerpos de respuesta
WAF_SIGNATURES: dict[str, dict] = {
    "Cloudflare": {
        "headers": ["cf-ray", "cf-cache-status", "cf-request-id"],
        "cookies": ["__cfduid", "cf_clearance"],
        "server": ["cloudflare"],
        "blocked_status": [403, 503],
    },
    "AWS WAF / CloudFront": {
        "headers": ["x-amzn-requestid", "x-amz-cf-id", "x-amzn-waf-action"],
        "cookies": ["awselb", "awsalb"],
        "server": ["awselb", "cloudfront"],
        "blocked_status": [403],
    },
    "Akamai": {
        "headers": ["x-akamai-transformed", "x-akamai-request-id", "akamai-origin-hop"],
        "cookies": ["ak_bmsc", "bm_sz"],
        "server": ["akamai"],
        "blocked_status": [403],
    },
    "Imperva / Incapsula": {
        "headers": ["x-iinfo", "x-cdn"],
        "cookies": ["incap_ses", "visid_incap"],
        "server": ["incapsula"],
        "blocked_status": [403],
    },
    "F5 BIG-IP / ASM": {
        "headers": ["x-wa-info", "x-cnection"],
        "cookies": ["bigipserver", "ts01", "f5_cspm"],
        "server": ["big-ip", "f5"],
        "blocked_status": [403],
    },
    "ModSecurity / OWASP CRS": {
        "headers": ["x-mod-security"],
        "cookies": [],
        "server": ["mod_security", "modsecurity"],
        "blocked_status": [403, 406],
    },
    "Sucuri Cloudproxy": {
        "headers": ["x-sucuri-id", "x-sucuri-cache"],
        "cookies": ["sucuri_cloudproxy"],
        "server": ["sucuri"],
        "blocked_status": [403],
    },
}


@dataclass
class WAFDetectionResult:
    detected: bool
    waf_name: Optional[str] = None
    confidence: float = 0.0
    evidence: str = ""


class WAFDetector:
    """Inspecciona respuestas y comportamiento ante sondeos para identificar WAFs."""

    def __init__(self, session: Optional[requests.Session] = None):
        self.session = session or requests.Session()

    def detect(self, target_url: str) -> WAFDetectionResult:
        """Realiza peticion inicial pasiva y un sondeo no destructivo para identificar WAFs."""
        headers_lower: dict[str, str] = {}
        cookies_lower: list[str] = []
        server_header: str = ""
        status_code: int = 200

        try:
            r = self.session.get(target_url, timeout=10, allow_redirects=True)
            status_code = r.status_code
            headers_lower = {k.lower(): v.lower() for k, v in r.headers.items()}
            cookies_lower = [c.name.lower() for c in r.cookies]
            server_header = headers_lower.get("server", "")
        except requests.RequestException as e:
            log.warning("Error al conectar con %s para deteccion de WAF: %s", target_url, e)
            return WAFDetectionResult(detected=False)

        # 1. Comprobacion de firmas pasivas
        for waf_name, sigs in WAF_SIGNATURES.items():
            matched_headers = [h for h in sigs["headers"] if h in headers_lower]
            matched_cookies = [c for c in sigs["cookies"] if any(c in ck for ck in cookies_lower)]
            matched_server = any(s in server_header for s in sigs["server"])

            if matched_headers or matched_cookies or matched_server:
                evidence_parts = []
                if matched_headers:
                    evidence_parts.append(f"Cabeceras: {', '.join(matched_headers)}")
                if matched_cookies:
                    evidence_parts.append(f"Cookies: {', '.join(matched_cookies)}")
                if matched_server:
                    evidence_parts.append(f"Server: {server_header}")

                evidence = " | ".join(evidence_parts)
                log.info("[WAF] Detectado %s en %s (%s)", waf_name, target_url, evidence)
                return WAFDetectionResult(
                    detected=True,
                    waf_name=waf_name,
                    confidence=0.95 if (matched_headers or matched_cookies) else 0.80,
                    evidence=evidence,
                )

        # 2. Sondeo no destructivo (payload sospechoso sintético para provocar bloqueo)
        try:
            probe_url = urljoin(target_url, "?__waf_probe__=%3Cscript%3Ealert(1)%3C/script%3E")
            probe_res = self.session.get(probe_url, timeout=10, allow_redirects=False)
            probe_headers = {k.lower(): v.lower() for k, v in probe_res.headers.items()}
            probe_cookies = [c.name.lower() for c in probe_res.cookies]
            probe_server = probe_headers.get("server", "")

            if probe_res.status_code in [403, 406, 429, 503] and status_code < 400:
                # Comprobar si el sondeo reactivó firmas específicas
                for waf_name, sigs in WAF_SIGNATURES.items():
                    if (
                        any(h in probe_headers for h in sigs["headers"])
                        or any(c in probe_cookies for c in sigs["cookies"])
                        or any(s in probe_server for s in sigs["server"])
                    ):
                        evidence = f"Bloqueo HTTP {probe_res.status_code} con firmas de {waf_name}"
                        return WAFDetectionResult(
                            detected=True,
                            waf_name=waf_name,
                            confidence=0.90,
                            evidence=evidence,
                        )

                return WAFDetectionResult(
                    detected=True,
                    waf_name="WAF Genérico / Filtro de Aplicación",
                    confidence=0.75,
                    evidence=f"El servidor respondió {status_code} a tráfico legítimo pero bloqueó con HTTP {probe_res.status_code} un sondeo de prueba.",
                )
        except requests.RequestException:
            pass

        return WAFDetectionResult(detected=False)

    def to_finding(self, target_url: str, result: WAFDetectionResult) -> Optional[Finding]:
        """Convierte un resultado positivo en un hallazgo informativo."""
        if not result.detected or not result.waf_name:
            return None

        from scanner.models import Evidence

        return Finding(
            category="waf",
            title=f"WAF Detectado: {result.waf_name}",
            severity="info",
            confidence="high" if result.confidence >= 0.85 else "medium",
            description=f"Se identificó la presencia activa de un Web Application Firewall ({result.waf_name}).",
            affected_url=target_url,
            evidence=Evidence(request_url=target_url, response_fragment=result.evidence),
            cwe_id="CWE-693",
            cwe_name="Protection Mechanism Failure",
            mitre_attack_id="T1562.001",
            mitre_attack_name="Disable or Modify Tools",
            owasp_category="A05:2021-Security Misconfiguration",
            remediation=(
                "Configuración informativa: Se recomienda utilizar el modo --stealth con rate limiting adaptativo "
                "para evitar que el WAF bloquee escaneos de seguridad legítimos autorizados."
            ),
        )
