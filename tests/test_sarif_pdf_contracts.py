"""
Pruebas de Contrato Estricto para SARIF v2.1.0, Reportes PDF, Scan Diff y Rate Limiting.

Valida que las salidas estructuradas cumplan rigurosamente con los estándares
de la industria (OASIS SARIF v2.1.0, especificación PDF ISO 32000-1) y los contratos
de integración del analista.
"""
from unittest.mock import MagicMock

from starlette.requests import Request

from scanner.diff import ScanDiffResult, compare_scans
from scanner.models import Evidence, Finding
from scanner.rate_limiter import InMemorySlidingWindowLimiter, RateLimitMiddleware
from utils.pdf_report import generate_pdf_report
from utils.sarif import generate_sarif_v210


class TestSarifOasisContract:
    """Valida el cumplimiento estricto del estándar OASIS SARIF v2.1.0."""

    def test_sarif_oasis_v210_full_schema_contract(self) -> None:
        ev = Evidence(
            request_method="POST",
            request_url="https://app.target.com/api/v1/transfer",
            payload="account=' OR '1'='1",
            response_status=500,
            response_fragment="SQL Syntax Error"
        )
        finding = Finding(
            category="sqli",
            title="SQL Injection en transfer",
            severity="critical",
            confidence="confirmed",
            description="Vulnerabilidad de inyección SQL en endpoint de transferencia bancaria.",
            evidence=ev,
            affected_url="https://app.target.com/api/v1/transfer",
            parameter="account",
            cwe_id="CWE-89",
            cwe_name="Improper Neutralization of Special Elements used in an SQL Command",
            mitre_attack_id="T1190",
            mitre_attack_name="Exploit Public-Facing Application"
        )

        sarif = generate_sarif_v210("https://app.target.com", [finding], duration=4.25)

        # 1. Metadatos de nivel raíz
        assert sarif["version"] == "2.1.0"
        assert sarif["$schema"] == "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
        assert isinstance(sarif["runs"], list)
        assert len(sarif["runs"]) == 1

        run = sarif["runs"][0]
        # 2. Driver del escáner
        driver = run["tool"]["driver"]
        assert driver["name"] == "OmniBreach"
        assert driver["version"] == "3.8.0"
        assert driver["semanticVersion"] == "3.8.0"
        assert len(driver["rules"]) >= 1

        rule = driver["rules"][0]
        assert rule["id"] == "VULN-SQLI"
        assert "shortDescription" in rule
        assert "defaultConfiguration" in rule
        assert rule["defaultConfiguration"]["level"] == "error"

        # 3. Resultados y ubicaciones
        assert len(run["results"]) == 1
        result = run["results"][0]
        assert result["ruleId"] == "VULN-SQLI"
        assert result["level"] == "error"
        assert "message" in result
        assert "locations" in result
        assert len(result["locations"]) == 1

        loc = result["locations"][0]
        phys = loc["physicalLocation"]
        assert phys["artifactLocation"]["uri"] == "https://app.target.com/api/v1/transfer"
        assert phys["region"]["startLine"] == 1

        # 4. Propiedades extendidas del hallazgo
        props = result["properties"]
        assert props["cweId"] == "CWE-89"
        assert props["mitreAttackId"] == "T1190"
        assert props["severity"] == "critical"
        assert props["confidence"] == "confirmed"


class TestPdfReportBinaryContract:
    """Valida que el generador de reportes PDF emita archivos binarios conformes."""

    def test_pdf_binary_header_and_structure(self) -> None:
        import os
        import tempfile

        findings = [
            Finding(
                category="xss",
                title="Cross-Site Scripting Reflejado",
                severity="high",
                affected_url="https://example.com/search",
                parameter="q",
                cwe_id="CWE-79"
            )
        ]
        target_url = "https://example.com"
        with tempfile.TemporaryDirectory() as tmpdir:
            out_pdf = os.path.join(tmpdir, "audit_report.pdf")
            result_path = generate_pdf_report(target_url, findings, output_path=out_pdf)

            assert os.path.exists(result_path)
            with open(result_path, "rb") as f:
                pdf_bytes = f.read()

            assert isinstance(pdf_bytes, bytes)
            assert len(pdf_bytes) > 500  # Tamaño mínimo para un PDF válido con contenido
            # Cabecera estándar del formato PDF según ISO 32000-1
            assert pdf_bytes.startswith(b"%PDF-")
            # Final estándar de archivo PDF
            assert b"%%EOF" in pdf_bytes[-1024:]


class TestScanDiffContract:
    """Valida el contrato formal del motor de análisis diferencial."""

    def test_scan_diff_identifies_new_and_resolved_findings(self) -> None:
        scan_a = {
            "task_id": "scan_baseline_01",
            "security_score": 75.0,
            "results": {
                "security_score": 75.0,
                "vulnerabilities": [
                    {
                        "category": "headers",
                        "title": "Falta X-Frame-Options",
                        "cwe_id": "CWE-1021",
                        "affected_url": "https://example.com",
                        "parameter": "",
                    },
                    {
                        "category": "sqli",
                        "title": "SQL Injection en login",
                        "cwe_id": "CWE-89",
                        "affected_url": "https://example.com/login",
                        "parameter": "user",
                    },
                ]
            }
        }

        # En el Scan B, se resolvió SQLi pero apareció XSS nuevo
        scan_b = {
            "task_id": "scan_current_02",
            "security_score": 85.0,
            "results": {
                "security_score": 85.0,
                "vulnerabilities": [
                    {
                        "category": "headers",
                        "title": "Falta X-Frame-Options",
                        "cwe_id": "CWE-1021",
                        "affected_url": "https://example.com",
                        "parameter": "",
                    },
                    {
                        "category": "xss",
                        "title": "Reflected XSS",
                        "cwe_id": "CWE-79",
                        "affected_url": "https://example.com/search",
                        "parameter": "q",
                    },
                ]
            }
        }

        diff: ScanDiffResult = compare_scans(scan_a, scan_b)

        assert diff.scan_a_id == "scan_baseline_01"
        assert diff.scan_b_id == "scan_current_02"
        assert diff.total_new == 1
        assert diff.new_findings[0]["cwe_id"] == "CWE-79"

        assert diff.total_resolved == 1
        assert diff.resolved_findings[0]["cwe_id"] == "CWE-89"

        assert diff.total_recurring == 1
        assert diff.recurring_findings[0]["cwe_id"] == "CWE-1021"

        assert diff.risk_score_delta == 10.0
        assert "Se introdujeron 1 nueva(s)" in diff.summary
        assert "Se corrigieron 1 vulnerabilidad(es)" in diff.summary


class TestRateLimiterContract:
    """Valida el limitador por ventana deslizante thread-safe."""

    def test_rate_limiter_allows_under_limit_and_blocks_over(self) -> None:
        limiter = InMemorySlidingWindowLimiter(window_seconds=10.0)
        client_key = "192.168.1.10:test_endpoint"

        # Permitir 3 solicitudes
        for i in range(3):
            allowed, remaining, _ = limiter.is_allowed(client_key, max_requests=3)
            assert allowed is True
            assert remaining == 2 - i

        # La 4ta solicitud debe ser bloqueada
        allowed, remaining, retry_after = limiter.is_allowed(client_key, max_requests=3)
        assert allowed is False
        assert remaining == 0
        assert retry_after > 0.0

    def test_rate_limiter_rejects_spoofed_x_forwarded_for_from_untrusted_peer(self) -> None:
        # Configurar middleware con proxy de confianza exclusivo en 127.0.0.1
        middleware = RateLimitMiddleware(app=MagicMock(), trusted_proxies=["127.0.0.1"])

        # Petición proveniente de atacante directo (IP pública 203.0.113.195)
        # El atacante intenta engañar al rate limiter inyectando X-Forwarded-For: 10.0.0.1
        mock_request = MagicMock(spec=Request)
        mock_request.client = MagicMock()
        mock_request.client.host = "203.0.113.195"
        mock_request.headers = {"X-Forwarded-For": "10.0.0.1, 10.0.0.2"}

        client_id = middleware._get_client_identifier(mock_request)
        # La cabecera X-Forwarded-For DEBE ser ignorada porque 203.0.113.195 NO es un proxy confiable
        assert client_id == "203.0.113.195"
        assert client_id != "10.0.0.1"

    def test_rate_limiter_accepts_x_forwarded_for_from_trusted_proxy(self) -> None:
        # Configurar middleware confiando en la red interna 10.0.0.0/8
        middleware = RateLimitMiddleware(app=MagicMock(), trusted_proxies=["10.0.0.0/8"])

        # Petición enviada a través del reverse proxy interno Nginx (10.0.1.5)
        mock_request = MagicMock(spec=Request)
        mock_request.client = MagicMock()
        mock_request.client.host = "10.0.1.5"
        mock_request.headers = {"X-Forwarded-For": "198.51.100.42, 10.0.1.5"}

        client_id = middleware._get_client_identifier(mock_request)
        # Como 10.0.1.5 está en la red de confianza 10.0.0.0/8, se extrae la IP real del cliente
        assert client_id == "198.51.100.42"
