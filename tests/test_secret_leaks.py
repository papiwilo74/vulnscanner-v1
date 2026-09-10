"""Unit tests for Public Secret Leaks Scanner."""
from unittest.mock import MagicMock, patch

from scanner.easm.secret_leaks import SecretLeakScanner, mask_secret


def test_mask_secret() -> None:
    assert mask_secret("AKIA1234567890ABCDEF") == "AKIA************CDEF"
    assert mask_secret("12345678") == "****"
    assert mask_secret("abc") == "****"

def test_scan_content_finds_patterns() -> None:
    scanner = SecretLeakScanner()
    # Construir tokens de prueba sintéticos sin exponer cadenas literales completas
    fake_aws = "AKIA" + "IOSFODNN7EXAMPL" + "E"
    fake_gh = "ghp_" + ("x" * 36)
    fake_stripe = "sk_" + "live_" + ("1234567890abcdef" * 2)
    fake_db = "postgres://admin:SuperSecretPass123@db.prod.local:5432/app"

    code_sample = (
        f"AWS_KEY = '{fake_aws}'\n"
        f"GITHUB_PAT = '{fake_gh}'\n"
        f"STRIPE_KEY = '{fake_stripe}'\n"
        f"DB_URL = '{fake_db}'\n"
    )
    findings = scanner.scan_content(code_sample, "config.py")
    types_found = {f.secret_type for f in findings}

    assert "AWS Access Key" in types_found
    assert "GitHub Personal Access Token" in types_found
    assert "Stripe Live Secret Key" in types_found
    assert "Database Connection String" in types_found

    for f in findings:
        assert not f.masked_value.startswith(fake_stripe)
        assert f.severity in ["CRITICAL", "HIGH"]

def test_scan_github_unauthenticated() -> None:
    scanner = SecretLeakScanner(github_token="")
    findings = scanner.search_public_leaks("empresa.com")
    assert findings == []

def test_scan_github_mocked_results() -> None:
    scanner = SecretLeakScanner(github_token="fake_token")
    mock_search_resp = MagicMock()
    mock_search_resp.status_code = 200
    mock_search_resp.json.return_value = {
        "items": [
            {
                "html_url": "https://github.com/empresa/repo/blob/main/.env",
                "repository": {"full_name": "empresa/repo"},
                "path": ".env"
            }
        ]
    }

    dummy_aws = "AKIA" + "TESTDUMMYKEY12345"
    raw_resp = MagicMock()
    raw_resp.status_code = 200
    raw_resp.text = f"AWS_ACCESS_KEY_ID={dummy_aws}\n"

    def fake_get(url: str, **kwargs: object) -> MagicMock:
        if "raw.githubusercontent.com" in url:
            return raw_resp
        return mock_search_resp

    with patch("requests.get", side_effect=fake_get):
        findings = scanner.search_public_leaks("empresa.com", max_results=5)
        assert len(findings) >= 1
        assert findings[0].secret_type == "AWS Access Key"
        assert findings[0].source_repository == "empresa/repo"
