"""Unit tests for Subdomain Takeover Scanner."""
from unittest.mock import MagicMock, patch

from scanner.easm.takeover import SubdomainTakeoverScanner


def test_takeover_fingerprint_match() -> None:
    scanner = SubdomainTakeoverScanner(timeout=2)
    mock_resp = MagicMock()
    mock_resp.status_code = 404
    mock_resp.text = "NoSuchBucket: The specified bucket does not exist"

    with patch("requests.get", return_value=mock_resp):
        vuln = scanner.inspect_subdomain("assets.empresa.com", "my-bucket.s3.amazonaws.com")
        assert vuln is not None
        assert vuln.service_name == "AWS S3 Bucket"
        assert vuln.severity == "CRITICAL"
        assert "The specified bucket does not exist" in vuln.fingerprint_detected

def test_takeover_no_vulnerability() -> None:
    scanner = SubdomainTakeoverScanner(timeout=2)
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = "OK - Company Asset Portal"

    with patch("requests.get", return_value=mock_resp):
        vuln = scanner.inspect_subdomain("portal.empresa.com", "active.s3.amazonaws.com")
        assert vuln is None

def test_takeover_unknown_cname() -> None:
    scanner = SubdomainTakeoverScanner(timeout=2)
    vuln = scanner.inspect_subdomain("mail.empresa.com", "internal-dc.empresa.local")
    assert vuln is None

def test_takeover_scan_assets() -> None:
    scanner = SubdomainTakeoverScanner(timeout=2)
    assets = [
        {"subdomain": "docs.empresa.com", "cname": "empresa.github.io"},
        {"subdomain": "app.empresa.com", "cname": "empresa.herokuapp.com"},
    ]

    def fake_get(url: str, **kwargs: object) -> MagicMock:
        mock = MagicMock()
        mock.status_code = 404
        if "docs.empresa.com" in url:
            mock.text = "There isn't a GitHub Pages site here."
        else:
            mock.text = "Normal Heroku App running"
        return mock

    with patch("requests.get", side_effect=fake_get):
        vulns = scanner.scan_assets(assets)
        assert len(vulns) == 1
        assert vulns[0].service_name == "GitHub Pages"
        assert vulns[0].subdomain == "docs.empresa.com"
