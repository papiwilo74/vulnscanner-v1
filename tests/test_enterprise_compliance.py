from utils.compliance import evaluate_compliance, generate_compliance_markdown
from utils.sarif import generate_sarif_v210


def test_compliance_evaluation_fail_on_critical_or_high():
    """Verifica que una vulnerabilidad crítica o alta marque el estado PCI-DSS como FAIL."""
    mock_findings = [
        {
            "category": "sqli",
            "vuln": "SQL Injection (Boolean)",
            "severity": "critical",
            "risk": "Alto",
            "confidence": "confirmed",
            "affected_url": "https://victim.test/items?id=1",
        },
        {
            "category": "headers",
            "vuln": "Cabecera CSP Faltante",
            "severity": "low",
            "risk": "Bajo",
            "confidence": "confirmed",
            "affected_url": "https://victim.test/",
        },
    ]

    report = evaluate_compliance(mock_findings)
    assert report["status"] == "FAIL"
    assert report["critical_count"] == 1
    assert report["compliance_score"] < 100.0

    pci = report["frameworks"]["pci_dss_v40"]
    assert pci["status"] == "FAIL"
    assert "Req-6.2.4" in pci["impacted_requirements"]

    owasp = report["frameworks"]["owasp_top10_2021"]
    assert "A03:2021-Injection" in owasp["categories"]

    md = generate_compliance_markdown(report)
    assert "NO CONFORME (FAIL)" in md
    assert "PCI-DSS" in md
    assert "Req-6.2.4" in md


def test_compliance_evaluation_pass_on_low_findings():
    """Verifica que solo hallazgos de severidad baja mantengan el cumplimiento PCI-DSS como PASS."""
    mock_findings = [
        {
            "category": "headers",
            "vuln": "Cabecera X-Frame-Options Faltante",
            "severity": "low",
            "risk": "Bajo",
            "confidence": "probable",
            "affected_url": "https://victim.test/",
        }
    ]

    report = evaluate_compliance(mock_findings)
    assert report["status"] == "PASS"
    assert report["critical_count"] == 0
    assert report["high_count"] == 0
    assert report["compliance_score"] >= 95.0

    md = generate_compliance_markdown(report)
    assert "CONFORME (PASS)" in md


def test_sarif_taxonomies_and_compliance_tags():
    """Verifica que el reporte SARIF v2.1.0 incluya taxonomías oficiales de PCI-DSS y OWASP."""
    mock_findings = [
        {
            "category": "sqli",
            "vuln": "SQL Injection",
            "severity": "critical",
            "confidence": "confirmed",
            "affected_url": "https://victim.test/api/login",
            "cvss_score": 9.8,
        }
    ]

    sarif_doc = generate_sarif_v210("https://victim.test", mock_findings)
    assert sarif_doc["version"] == "2.1.0"
    run = sarif_doc["runs"][0]

    # Verificar taxonomías
    taxonomies = run["tool"]["taxonomies"]
    tax_names = [t["name"] for t in taxonomies]
    assert "PCI-DSS" in tax_names
    assert "OWASP-Top-10" in tax_names

    # Verificar reglas y tags de cumplimiento
    rule = run["tool"]["driver"]["rules"][0]
    tags = rule["properties"]["tags"]
    assert any("PCI-DSS-v4.0:Req-6.2.4" in t for t in tags)
    assert rule["properties"]["pciDssRequirements"] == ["Req-6.2.4"]
