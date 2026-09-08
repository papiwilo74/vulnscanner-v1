from unittest.mock import patch

import pytest

from scanner.models import Finding
from utils.github_pr import GitHubPRClient


@pytest.fixture
def sample_findings():
    return [
        Finding(
            title="Header faltante: X-Frame-Options",
            severity="high",
            category="headers",
            affected_url="https://ejemplo.com",
            description="Protege contra clickjacking",
            remediation="Configurar X-Frame-Options DENY",
            cwe_id="CWE-693",
            mitre_attack_id="T1190",
            cvss_score=7.0,
            autofix={"file": "vercel.json", "patch": '{"headers": []}'},
        )
    ]


def test_github_pr_client_methods(sample_findings):
    client = GitHubPRClient(token="ghp_fake_test_token_12345", repo="owner/test-repo")

    # 1. Test generate_pr_body
    body = client.generate_pr_body(sample_findings, "https://ejemplo.com")
    assert "VulnScanner Enterprise" in body
    assert "X-Frame-Options" in body
    assert "CVSS v3.1" in body
    assert "CWE-693" in body

    # 2. Test auto_remediate_and_open_pr con mocks de llamadas HTTP
    with patch.object(client, "_get") as mock_get, \
         patch.object(client, "_post") as mock_post, \
         patch.object(client, "_put") as mock_put:

        mock_get.side_effect = [
            {"object": {"sha": "base_sha_abc123"}},  # get_default_branch_sha
            {"sha": "existing_file_sha_xyz999"},      # commit_file check existing
        ]
        mock_post.side_effect = [
            {"ref": "refs/heads/vulnscanner/remediation-test"},  # create_branch
            {"html_url": "https://github.com/owner/test-repo/pull/42", "number": 42},  # create_pr
        ]
        mock_put.return_value = {"content": {"sha": "new_commit_sha"}}

        res = client.auto_remediate_and_open_pr(
            findings=sample_findings,
            target_url="https://ejemplo.com",
            base_branch="main",
        )

        assert res["html_url"] == "https://github.com/owner/test-repo/pull/42"
        assert res["number"] == 42
        assert mock_post.call_count == 2
        assert mock_put.call_count == 1
