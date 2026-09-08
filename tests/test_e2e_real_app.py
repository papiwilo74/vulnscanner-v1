"""
Pruebas End-to-End (E2E) Reales contra un Entorno Web Vulnerable Simulado.
Verifica que el ciclo completo de auditoría (Crawling, DAST, Fingerprinting,
Auto-Fix, Correlación MITRE ATT&CK, y Generación de Reportes SARIF/HTML/JSON)
opera de forma hermética y detecta vulnerabilidades reales con precisión.
"""
import json
import os

import pytest

from main import scan
from scanner.lab_server import LabServer


@pytest.fixture(scope="module")
def lab_target():
    """Inicia el servidor de prueba vulnerable y lo destruye al finalizar."""
    server = LabServer()
    target_url = server.start()
    yield target_url
    server.stop()


def test_e2e_scan_real_vulnerabilities(lab_target):
    """
    Ejecuta un escaneo E2E real contra la aplicación vulnerable local y valida los hallazgos.
    """
    html_path, json_path, report_data = scan(
        url=lab_target,
        no_open=True,
        allow_private=True,
        passive=False,
        profile="normal",
        crawl_pages=1,
    )

    assert html_path is not None and os.path.exists(html_path), "El reporte HTML debe existir"
    assert json_path is not None and os.path.exists(json_path), "El reporte JSON debe existir"
    assert isinstance(report_data, dict), "El reporte retornado debe ser un diccionario"

    # 1. Validar que se detectaron hallazgos
    vulns = report_data.get("vulnerabilities", [])
    assert len(vulns) >= 5, f"Se esperaban al menos 5 hallazgos, encontrados: {len(vulns)}"

    categories_detected = {v.get("category") for v in vulns}

    # 2. Validar detección de categorías clave
    assert "headers" in categories_detected, "Debe detectar headers de seguridad faltantes"
    assert "cookies" in categories_detected, "Debe detectar cookies sin flag Secure"
    assert "forms" in categories_detected, "Debe detectar formulario sin token CSRF"

    # 3. Validar estándares de seguridad: MITRE ATT&CK y CWE en cada hallazgo
    for v in vulns:
        assert v.get("cwe_id", "").startswith("CWE-"), f"Hallazgo {v.get('vuln')} sin CWE válido"
        assert v.get("mitre_attack_id", "").startswith("T"), f"Hallazgo {v.get('vuln')} sin MITRE ATT&CK ID válido"
        assert "cvss_score" in v, f"Hallazgo {v.get('vuln')} sin CVSS score"

    # 4. Validar reporte SARIF v2.1.0 generado
    sarif_path = report_data.get("sarif_report_path")
    assert sarif_path and os.path.exists(sarif_path), "El archivo SARIF debe existir en disco"

    with open(sarif_path, encoding="utf-8") as f:
        sarif_json = json.load(f)

    assert sarif_json.get("version") == "2.1.0"
    assert "sarif-schema-2.1.0.json" in sarif_json.get("$schema", "")
    runs = sarif_json.get("runs", [])
    assert len(runs) > 0
    driver = runs[0].get("tool", {}).get("driver", {})
    assert "VulnScanner" in driver.get("name", "")
    assert len(runs[0].get("results", [])) == len(vulns)
