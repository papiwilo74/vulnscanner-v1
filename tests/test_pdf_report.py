import os
import tempfile

from scanner.models import Finding
from utils.pdf_report import generate_pdf_report


def test_generate_pdf_report():
    findings = [
        Finding(
            title="Header faltante: Content-Security-Policy",
            severity="high",
            category="headers",
            affected_url="https://ejemplo.com",
            description="Falta cabecera CSP contra XSS.",
            remediation="Configurar directiva default-src 'self'",
            cwe_id="CWE-693",
            mitre_attack_id="T1190",
            cvss_score=7.5,
        ),
        Finding(
            title="Cookie sin flag Secure",
            severity="medium",
            category="cookies",
            affected_url="https://ejemplo.com/login",
            description="Cookie de sesión sin atributo Secure.",
            remediation="Añadir flag Secure en Set-Cookie",
            cwe_id="CWE-614",
            mitre_attack_id="T1539",
            cvss_score=5.3,
        ),
    ]

    with tempfile.TemporaryDirectory() as tmpdir:
        out_pdf = os.path.join(tmpdir, "test_audit.pdf")
        res_path = generate_pdf_report(
            target_url="https://ejemplo.com",
            findings=findings,
            output_path=out_pdf,
            duration=12.4,
            scan_profile="normal",
            engine_summary={"profile": "normal", "total_requests": 45, "waf_detected": False},
        )

        assert os.path.exists(res_path)
        file_size = os.path.getsize(res_path)
        assert file_size > 1500  # Un PDF generado válido con tablas debe tener más de 1.5KB
