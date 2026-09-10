"""
Suite de pruebas unitarias y de integración para OmniBreach v3.0 EASM Engine.
Valida cartografía perimetral, escaneo de puertos de alto riesgo,
correlación CISA KEV, inteligencia de amenazas y el API REST.
"""
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient

from api import app
from scanner.easm.cve_intel import CISAExploitIntel, CVEFinding
from scanner.easm.darkweb_intel import DarkWebIntel, IdentityExposure
from scanner.easm.engine import EASMEngine, EASMReport
from scanner.easm.recon import AssetDiscovery, DigitalPerimeterMapper
from scanner.easm.service_scout import ExposedService, ServiceScout

client = TestClient(app)


def test_perimeter_mapper_domain_sanitization() -> None:
    mapper = DigitalPerimeterMapper()
    assert mapper.sanitize_domain("https://empresa.com.co/login") == "empresa.com.co"
    assert mapper.sanitize_domain("HTTP://SUB.EMPRESA.COM.CO:8443/") == "sub.empresa.com.co"
    assert mapper.sanitize_domain("  .banco.com.co  ") == "banco.com.co"


def test_identify_cloud_provider() -> None:
    mapper = DigitalPerimeterMapper()
    assert "AWS" in (mapper.identify_cloud_provider("s3.amazonaws.com", None, None) or "")
    assert "Azure" in (mapper.identify_cloud_provider("portal.azure.com", None, None) or "")
    assert "Cloudflare" in (mapper.identify_cloud_provider("cdn.empresa.com", None, "custom.cloudflare.net") or "")
    assert mapper.identify_cloud_provider("local.test", None, None) is None


@patch("requests.get")
def test_fetch_ct_logs(mock_get: MagicMock) -> None:
    mapper = DigitalPerimeterMapper()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = [
        {"name_value": "api.empresa.com.co\nvpn.empresa.com.co"},
        {"name_value": "*.dev.empresa.com.co"},
        {"name_value": "otherdomain.com"}
    ]
    mock_get.return_value = mock_resp

    discovered = mapper.fetch_ct_logs("empresa.com.co")
    assert "api.empresa.com.co" in discovered
    assert "vpn.empresa.com.co" in discovered
    assert "dev.empresa.com.co" in discovered
    assert "otherdomain.com" not in discovered


def test_cisa_kev_correlation() -> None:
    intel = CISAExploitIntel()

    # 1. Apache 2.4.49 (CVE-2021-41773)
    findings = intel.correlate_text("Apache/2.4.49 (Unix) OpenSSL/1.1.1", context_label="192.168.1.5:80")
    assert len(findings) == 1
    assert findings[0].cve_id == "CVE-2021-41773"
    assert findings[0].cisa_kev_listed is True
    assert findings[0].has_public_exploit is True

    # 2. OpenSSH regreSSHion (CVE-2024-6387)
    ssh_findings = intel.correlate_text("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10", context_label="192.168.1.5:22")
    assert any(f.cve_id == "CVE-2024-6387" for f in ssh_findings)

    # 3. Clean banner
    clean_findings = intel.correlate_text("nginx/1.24.0", context_label="web")
    assert len(clean_findings) == 0


def test_cve_analyze_services() -> None:
    intel = CISAExploitIntel()
    svc = ExposedService(
        host="vpn.empresa.com.co",
        ip="200.1.2.3",
        port=443,
        service_name="Citrix Gateway",
        severity="CRITICAL",
        description="Citrix NetScaler",
        banner="Citrix NetScaler Gateway",
    )
    alerts = intel.analyze_services([svc])
    assert any(a.cve_id == "CVE-2023-4966" for a in alerts)


def test_darkweb_typosquatting_generation() -> None:
    dw = DarkWebIntel()
    perms = dw.generate_typosquatting_permutations("banco.com.co")
    assert any("banco-seguro" in p for p in perms)
    assert any("bancoo" in p or "baanco" in p for p in perms)


def test_easm_engine_scoring() -> None:
    engine = EASMEngine()

    # Caso 1: Sin servicios críticos ni CVEs -> Score A+
    services_clean: list[ExposedService] = []
    cves_clean: list[CVEFinding] = []
    id_clean = IdentityExposure(domain="clean.com", risk_level="LOW", breach_indicators=0, threat_description="Ninguna")
    score_clean, grade_clean = engine.calculate_score(services_clean, cves_clean, id_clean)
    assert score_clean == 100
    assert grade_clean == "A+"

    # Caso 2: Con RDP abierto + Redis sin clave + CVE KEV -> Score F
    bad_services = [
        ExposedService(host="rdp.test", ip="1.1.1.1", port=3389, service_name="RDP", severity="CRITICAL", description="RDP", ransomware_vector=True),
        ExposedService(host="redis.test", ip="1.1.1.2", port=6379, service_name="Redis", severity="CRITICAL", description="Redis", unauthenticated_access=True),
    ]
    bad_cves = [
        CVEFinding(cve_id="CVE-2021-41773", vulnerability_name="Apache RCE", severity="CRITICAL", affected_product="Apache", detected_version="2.4.49")
    ]
    id_bad = IdentityExposure(domain="bad.com", risk_level="HIGH", breach_indicators=2, threat_description="Typosquatting")
    score_bad, grade_bad = engine.calculate_score(bad_services, bad_cves, id_bad)
    assert score_bad < 50
    assert grade_bad in ("D", "F")


@patch.object(DigitalPerimeterMapper, "map_perimeter")
@patch.object(ServiceScout, "scout_perimeter")
@patch.object(CISAExploitIntel, "analyze_services")
@patch.object(DarkWebIntel, "inspect_identity_risk")
def test_easm_engine_full_run(
    mock_id: MagicMock,
    mock_cve: MagicMock,
    mock_scout: MagicMock,
    mock_recon: MagicMock,
) -> None:
    mock_recon.return_value = [
        AssetDiscovery(subdomain="empresa.com.co", ip_address="190.1.2.3", source="DNS", is_live=True),
        AssetDiscovery(subdomain="mail.empresa.com.co", ip_address="190.1.2.4", source="CT", is_live=True),
    ]
    mock_scout.return_value = [
        ExposedService(
            host="empresa.com.co",
            ip="190.1.2.3",
            port=22,
            service_name="SSH",
            severity="MEDIUM",
            description="Terminal remota",
            banner="SSH-2.0-OpenSSH_8.9p1",
        )
    ]
    mock_cve.return_value = [
        CVEFinding(
            cve_id="CVE-2024-6387",
            vulnerability_name="OpenSSH regreSSHion",
            severity="CRITICAL",
            affected_product="OpenSSH",
            detected_version="8.9p1",
        )
    ]
    mock_id.return_value = IdentityExposure(
        domain="empresa.com.co",
        risk_level="LOW",
        breach_indicators=0,
        threat_description="Sin anomalías",
    )

    engine = EASMEngine()
    report = engine.run_full_surface_assessment("empresa.com.co", include_bruteforce=False)

    assert isinstance(report, EASMReport)
    assert report.root_domain == "empresa.com.co"
    assert report.total_assets == 2
    assert report.total_exposed_services == 1
    assert report.cisa_kev_alerts == 1
    rep_dict = report.to_dict()
    assert rep_dict["root_domain"] == "empresa.com.co"


@patch.object(EASMEngine, "run_full_surface_assessment")
def test_api_easm_scan_endpoint(mock_assess: MagicMock) -> None:
    mock_assess.return_value = EASMReport(
        root_domain="testbank.com.co",
        scan_timestamp="2026-09-10T15:00:00Z",
        exposure_score=95,
        exposure_grade="A+",
        total_assets=5,
        total_exposed_services=0,
        critical_ransomware_vectors=0,
        cisa_kev_alerts=0,
        summary={"status": "clean"},
    )

    res = client.post("/api/v1/easm/scan", json={"domain": "testbank.com.co", "include_bruteforce": False})
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "completed"
    assert data["domain"] == "testbank.com.co"
    assert data["report"]["exposure_grade"] == "A+"


def test_api_easm_scan_invalid_domain() -> None:
    # 1. Dominio vacío
    res_empty = client.post("/api/v1/easm/scan", json={"domain": "   "})
    assert res_empty.status_code == 400
    assert "Debe especificar un dominio corporativo válido" in res_empty.json()["detail"]

    # 2. Dominio con espacios internos
    res_spaces = client.post("/api/v1/easm/scan", json={"domain": "empresa invalida.com"})
    assert res_spaces.status_code == 400


@patch.object(EASMEngine, "run_full_surface_assessment")
def test_api_easm_scan_internal_error(mock_assess: MagicMock) -> None:
    mock_assess.side_effect = RuntimeError("Conexión DNS rota")
    res = client.post("/api/v1/easm/scan", json={"domain": "errorbank.com.co"})
    assert res.status_code == 500
    assert "Error durante la auditoría EASM" in res.json()["detail"]


def test_recon_and_scout_empty_inputs() -> None:
    mapper = DigitalPerimeterMapper()
    assert mapper.sanitize_domain("") == ""
    assert mapper.map_perimeter("") == []
    assert mapper.fetch_ct_logs("") == set()

    scout = ServiceScout()
    assert scout.scout_perimeter([]) == []
