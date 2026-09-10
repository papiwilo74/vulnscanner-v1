"""Unit tests for AI Remediation Advisor."""
from scanner.easm.advisor import AIRemediationAdvisor, RemediationRunbook
from scanner.easm.cve_intel import CVEFinding
from scanner.easm.secret_leaks import SecretLeakFinding
from scanner.easm.takeover import TakeoverVulnerability


def test_advisor_clean_surface() -> None:
    advisor = AIRemediationAdvisor()
    runbook = advisor.generate_runbook(
        domain="clean-company.com",
        services=[],
        cves=[],
        takeovers=[],
        secret_leaks=[],
        identity_risk=None
    )
    assert isinstance(runbook, RemediationRunbook)
    assert runbook.target_domain == "clean-company.com"
    assert len(runbook.immediate_actions) == 0
    assert "hermético" in runbook.executive_summary or "hermetico" in runbook.executive_summary

def test_advisor_with_takeover_and_secret() -> None:
    advisor = AIRemediationAdvisor()
    takeover = TakeoverVulnerability(
        subdomain="blog.target.com",
        cname="target.herokuapp.com",
        service_name="Heroku App",
        severity="CRITICAL",
        fingerprint_detected="Heroku | No such app",
        remediation="Liberar CNAME"
    )
    secret = SecretLeakFinding(
        secret_type="AWS Access Key",
        severity="CRITICAL",
        masked_value="AKIA************1234",
        source_repository="target/repo",
        description="AWS IAM Key",
        remediation="Revocar clave"
    )
    service_mock = {
        "host": "vpn.target.com",
        "port": 3389,
        "service_name": "RDP",
        "unauthenticated_access": False,
        "ransomware_vector": True
    }

    runbook = advisor.generate_runbook(
        domain="target.com",
        services=[service_mock],
        cves=[],
        takeovers=[takeover],
        secret_leaks=[secret],
        identity_risk={"high_risk_exposure": True}
    )

    assert len(runbook.immediate_actions) >= 3
    assert any("blog.target.com" in a for a in runbook.immediate_actions)
    assert any("AWS Access Key" in a for a in runbook.immediate_actions)
    assert any("3389" in a for a in runbook.immediate_actions)

    scripts = runbook.executable_scripts
    assert any("Firewall" in k or "iptables" in k for k in scripts)
    assert any("DNS" in k or "Takeover" in k for k in scripts)
    assert any("Revocación" in k or "Secret" in k for k in scripts)
    assert len(runbook.strategic_recommendations) >= 3


def test_advisor_with_cve() -> None:
    advisor = AIRemediationAdvisor()
    cve = CVEFinding(
        cve_id="CVE-2023-38606",
        vulnerability_name="Remote Code Execution",
        severity="CRITICAL",
        affected_product="Apache HTTP Server",
        detected_version="2.4.49",
        cisa_kev_listed=True,
        has_public_exploit=True,
        remediation_steps="Actualizar a 2.4.51+"
    )

    runbook = advisor.generate_runbook(
        domain="target.com",
        services=[],
        cves=[cve],
        takeovers=[],
        secret_leaks=[]
    )

    assert len(runbook.short_term_actions) >= 1
    assert any("CVE-2023-38606" in a for a in runbook.short_term_actions)
    assert any("Actualización" in k for k in runbook.executable_scripts)
