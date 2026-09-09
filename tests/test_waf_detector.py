"""Pruebas unitarias para el detector de WAF y el Circuit Breaker de ScanEngine."""
import time

import pytest

responses = pytest.importorskip("responses")

from scanner.engine import ScanConfig, ScanEngine, ScanProfile  # noqa: E402
from scanner.waf_detector import WAFDetector  # noqa: E402


class TestWAFDetector:
    """Valida la detección de firmas de WAFs en cabeceras y respuestas."""

    @responses.activate
    def test_detects_cloudflare(self):
        url = "https://example-cloudflare.com"
        responses.add(
            responses.GET,
            url,
            status=200,
            headers={"cf-ray": "84a123456789-MIA", "server": "cloudflare", "cf-cache-status": "DYNAMIC"},
        )
        detector = WAFDetector()
        result = detector.detect(url)

        assert result.detected is True
        assert result.waf_name == "Cloudflare"
        assert result.confidence >= 0.85
        assert "cf-ray" in result.evidence

        finding = detector.to_finding(url, result)
        assert finding is not None
        assert "Cloudflare" in finding.title
        assert finding.category == "waf"
        assert finding.severity == "info"

    @responses.activate
    def test_detects_aws_waf_cloudfront(self):
        url = "https://example-aws.com"
        responses.add(
            responses.GET,
            url,
            status=200,
            headers={"x-amzn-requestid": "12345-abcde", "x-amz-cf-id": "cloudfront-token-xyz"},
        )
        detector = WAFDetector()
        result = detector.detect(url)

        assert result.detected is True
        assert result.waf_name == "AWS WAF / CloudFront"
        assert "x-amzn-requestid" in result.evidence

    @responses.activate
    def test_detects_modsecurity_on_probe_block(self):
        url = "https://example-modsec.com"
        # Tráfico normal pasa
        responses.add(responses.GET, url, status=200, headers={"server": "Apache/2.4.52"})
        # Sondeo de prueba es bloqueado por ModSecurity
        probe_url = f"{url}/?__waf_probe__=%3Cscript%3Ealert(1)%3C/script%3E"
        responses.add(
            responses.GET,
            probe_url,
            status=403,
            headers={"x-mod-security": "OWASP CRS active"},
        )

        detector = WAFDetector()
        result = detector.detect(url)
        assert result.detected is True
        assert "ModSecurity" in (result.waf_name or "")

    @responses.activate
    def test_clean_site_returns_not_detected(self):
        url = "https://clean-example.com"
        responses.add(responses.GET, url, status=200, headers={"server": "nginx", "content-type": "text/html"})
        probe_url = f"{url}/?__waf_probe__=%3Cscript%3Ealert(1)%3C/script%3E"
        responses.add(responses.GET, probe_url, status=200, headers={"server": "nginx"})

        detector = WAFDetector()
        result = detector.detect(url)
        assert result.detected is False
        assert result.waf_name is None


class TestCircuitBreakerAndAdaptiveThrottling:
    """Valida que ScanEngine adapte la velocidad y abra el circuito ante HTTP 429/503."""

    def test_circuit_trips_to_open_on_throttles(self):
        config = ScanConfig(profile=ScanProfile.NORMAL, max_rps=10)
        engine = ScanEngine(config)
        engine.start()

        assert engine.circuit_state == "CLOSED"
        assert engine.current_rps == 10.0

        # Simular respuestas 429 Too Many Requests
        engine.handle_response(429)
        assert engine.circuit_state == "OPEN"
        assert engine.current_rps < 10.0  # RPS reducido a la mitad

        # Segunda respuesta 429
        engine.handle_response(429)
        assert engine.current_rps <= 2.5

    def test_circuit_recovers_to_closed_on_success(self):
        config = ScanConfig(profile=ScanProfile.NORMAL, max_rps=10)
        engine = ScanEngine(config)
        engine.start()

        engine.handle_response(503)
        assert engine.circuit_state == "OPEN"

        # Simular expiración de la ventana de backoff
        engine._circuit_open_until = time.monotonic() - 1.0

        # Respuesta 200 de prueba pasa a HALF-OPEN
        engine.handle_response(200)
        assert engine.circuit_state == "HALF-OPEN"

        # Siguiente 200 restablece el circuito a CLOSED
        engine.handle_response(200)
        assert engine.circuit_state == "CLOSED"
