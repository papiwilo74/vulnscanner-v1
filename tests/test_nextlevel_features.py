"""Tests unitarios para las 3 características de nueva generación:
1. Motor OAST (Out-of-Band AST)
2. Motor de Auto-Fix y Remediación Contextual
3. Exportador OASIS SARIF v2.1.0, Puntuación CVSS v3.1 y Mapeo MITRE ATT&CK
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner.autofix import AutoFixEngine, TechFingerprinter, enrich_findings_with_autofix
from scanner.models import Finding
from scanner.oast import OASTClient, check_oast_vulnerabilities
from utils.sarif import generate_sarif_v210

# ─────────────────────────────────────────────
# 1. Tests: Motor OAST (Out-of-Band AST)
# ─────────────────────────────────────────────

class TestOASTEngine:
    def test_oast_token_and_payload_generation(self):
        client = OASTClient(server_domain="oast.vulnscanner.test", mock_mode=True)
        token = client.generate_token(prefix="test-ssrf")

        assert token.startswith("test-ssrf-")
        assert len(token) > 15

        cb_url = client.get_callback_url(token)
        cb_host = client.get_callback_host(token)
        assert cb_url == f"http://{token}.oast.vulnscanner.test"
        assert cb_host == f"{token}.oast.vulnscanner.test"

        payloads = client.generate_payloads(token)
        assert "ssrf" in payloads
        assert "xxe" in payloads
        assert "rce" in payloads
        assert "log4j" in payloads
        assert f"jndi:ldap://{cb_host}" in payloads["log4j"]
        assert f"http://{token}" in payloads["ssrf"]

    def test_oast_mock_interaction_recording_and_polling(self):
        client = OASTClient(server_domain="oast.test", mock_mode=True)
        token = client.generate_token()

        # Antes de interacción
        assert client.poll_interactions(token) == []

        # Simular callback DNS y HTTP
        client.record_mock_interaction(token, interaction_type="DNS", client_ip="198.51.100.25")
        client.record_mock_interaction(token, interaction_type="HTTP", client_ip="198.51.100.25")

        interactions = client.poll_interactions(token)
        assert len(interactions) == 2
        assert interactions[0]["type"] == "DNS"
        assert interactions[1]["type"] == "HTTP"

    def test_check_oast_detects_blind_ssrf_on_interaction(self, monkeypatch):
        client = OASTClient(server_domain="oast.test", mock_mode=True)

        class FakeResponse:
            status_code = 200
            text = "<html>OK</html>"
            headers = {}
            cookies = {}

        class FakeSession:
            def get(self, url, headers=None, timeout=5):
                # Simular que al recibir el payload remoto, el servidor vulnerable hace callback OAST
                for token in list(client._registered_interactions.keys()):
                    if token in url:
                        client.record_mock_interaction(token, interaction_type="HTTP", client_ip="10.0.0.99")
                return FakeResponse()

        fake_session = FakeSession()
        findings = check_oast_vulnerabilities("https://example.com/fetch?url=https://target.com", session=fake_session, oast_client=client)

        assert len(findings) >= 1
        ssrf_finding = next((f for f in findings if f.category == "ssrf"), None)
        assert ssrf_finding is not None
        assert ssrf_finding.severity == "critical"
        assert ssrf_finding.confidence == "confirmed"
        assert "Blind SSRF" in ssrf_finding.title
        assert ssrf_finding.evidence is not None


# ─────────────────────────────────────────────
# 2. Tests: Auto-Fix y Tech Fingerprinting
# ─────────────────────────────────────────────

class TestAutoFixEngine:
    def test_fingerprint_express_stack(self):
        headers = {"X-Powered-By": "Express", "Server": "Node.js"}
        cookies = {"connect.sid": "s%3Aabc123"}
        stack = TechFingerprinter.detect_stack(headers=headers, cookies=cookies)
        assert "Express.js" in stack

    def test_fingerprint_django_stack(self):
        headers = {"Server": "WSGIServer/0.2 CPython/3.10"}
        cookies = {"csrftoken": "xyz987", "sessionid": "sess123"}
        stack = TechFingerprinter.detect_stack(headers=headers, cookies=cookies)
        assert "Django" in stack

    def test_fingerprint_nextjs_react_stack(self):
        html = '<div id="__next"><script id="__NEXT_DATA__">{}</script></div>'
        stack = TechFingerprinter.detect_stack(headers={}, html=html)
        assert "Next.js" in stack

    def test_fingerprint_nginx_fastapi_stack(self):
        headers = {"Server": "nginx/1.24.0", "X-Process-Time": "0.002"}
        html = '{"docs_url": "/openapi.json"}'
        stack = TechFingerprinter.detect_stack(headers=headers, html=html)
        assert "Nginx" in stack
        assert "FastAPI" in stack

    def test_generate_patch_for_cors_express(self):
        patch = AutoFixEngine.generate_patch("cors", ["Express.js"])
        assert patch is not None
        assert patch["technology"] == "Express.js"
        assert "npm install cors" in patch["code_snippet"]
        assert "allowedOrigins" in patch["code_snippet"]

    def test_generate_patch_for_headers_nginx(self):
        patch = AutoFixEngine.generate_patch("headers", ["Nginx"])
        assert patch is not None
        assert patch["technology"] == "Nginx"
        assert "add_header Content-Security-Policy" in patch["code_snippet"]
        assert "add_header X-Frame-Options" in patch["code_snippet"]

    def test_generate_patch_for_sqli_python(self):
        patch = AutoFixEngine.generate_patch("sqli", ["Django", "Python"])
        assert patch is not None
        assert "Prepared Statements" in patch["code_snippet"] or "%s" in patch["code_snippet"] or "SQLAlchemy" in patch["code_snippet"]

    def test_enrich_findings_with_autofix(self):
        finding = Finding(category="cors", title="CORS Abierto", severity="medium")
        assert finding.autofix is None

        enrich_findings_with_autofix([finding], tech_stack=["FastAPI"])
        assert finding.autofix is not None
        assert finding.autofix["technology"] == "FastAPI"
        assert "CORSMiddleware" in finding.autofix["code_snippet"]


# ─────────────────────────────────────────────
# 3. Tests: SARIF v2.1.0, CVSS v3.1 y MITRE ATT&CK
# ─────────────────────────────────────────────

class TestSARIFAndStandards:
    def test_finding_cvss_and_mitre_auto_enrichment(self):
        # 1. SQLi debe auto-asignar CWE-89, MITRE T1190 y CVSS Crítico
        sqli = Finding(category="sqli", title="SQL Injection en id", severity="critical")
        assert sqli.cwe_id == "CWE-89"
        assert sqli.mitre_attack_id == "T1190"
        assert sqli.cvss_score >= 9.0
        assert "CVSS:3.1" in sqli.cvss_vector

        # 2. XSS debe auto-asignar CWE-79, MITRE T1189 y CVSS Alto
        xss = Finding(category="xss", title="XSS Reflejado en q", severity="high")
        assert xss.cwe_id == "CWE-79"
        assert xss.mitre_attack_id == "T1189"
        assert 7.0 <= xss.cvss_score <= 8.9

        # 3. Cookies debe asignar CWE-614, MITRE T1539 y CVSS Bajo
        cookies = Finding(category="cookies", title="Cookie sin Secure flag", severity="low")
        assert cookies.cwe_id == "CWE-614"
        assert cookies.mitre_attack_id == "T1539"
        assert 0.1 <= cookies.cvss_score <= 3.9

    def test_sarif_v210_structure_and_schema_compliance(self):
        findings = [
            Finding(
                category="sqli",
                title="Inyección SQL detectada",
                severity="critical",
                affected_url="https://example.com/api/user?id=1",
                parameter="id",
                autofix={
                    "technology": "Python",
                    "filename": "db.py",
                    "code_snippet": "cursor.execute('SELECT * FROM users WHERE id = %s', (uid,))"
                }
            ),
            Finding(
                category="headers",
                title="Ausencia de CSP",
                severity="low",
                affected_url="https://example.com/"
            )
        ]

        sarif = generate_sarif_v210("https://example.com", findings, duration=5.4)

        # Validar raíz de SARIF
        assert sarif["version"] == "2.1.0"
        assert "sarif-schema-2.1.0.json" in sarif["$schema"]
        assert len(sarif["runs"]) == 1

        run = sarif["runs"][0]
        assert run["tool"]["driver"]["name"] == "VulnScanner"
        assert run["tool"]["driver"]["version"] == "2.0.0"

        # Validar reglas definidas
        rules = run["tool"]["driver"]["rules"]
        rule_ids = [r["id"] for r in rules]
        assert "VULN-SQLI" in rule_ids
        assert "VULN-HEADERS" in rule_ids

        # Validar regla SQLi con tags de seguridad
        sqli_rule = next(r for r in rules if r["id"] == "VULN-SQLI")
        assert "CWE-89" in sqli_rule["properties"]["tags"]
        assert "T1190" in sqli_rule["properties"]["tags"]

        # Validar resultados reportados
        results = run["results"]
        assert len(results) == 2
        assert results[0]["ruleId"] == "VULN-SQLI"
        assert results[0]["level"] == "error"
        assert results[0]["properties"]["cweId"] == "CWE-89"
        assert results[0]["properties"]["mitreAttackId"] == "T1190"
        assert results[0]["properties"]["cvssScore"] >= 9.0

        # Validar inclusión de objeto 'fixes' en SARIF
        assert "fixes" in results[0]
        assert len(results[0]["fixes"]) == 1
        assert "db.py" in results[0]["fixes"][0]["fileChanges"][0]["artifactLocation"]["uri"]

    def test_print_report_persists_json_and_sarif_paths(self):
        from pathlib import Path

        from utils.report import print_report

        finding = Finding(
            category="headers",
            title="Ausencia de Content-Security-Policy",
            severity="low",
            affected_url="https://example.com/",
        )

        html_path, json_path, report_data = print_report(
            "https://example.com/",
            [finding],
            duration=0.1,
            no_open=True,
        )

        sarif_path = report_data["sarif_report_path"]
        assert Path(html_path).exists()
        assert Path(json_path).exists()
        assert sarif_path
        assert Path(sarif_path).exists()
        assert report_data["vulnerabilities"][0]["cwe_id"] == "CWE-693"

    def test_print_report_clean_scan_still_persists_sarif_path(self):
        from pathlib import Path

        from utils.report import print_report

        html_path, json_path, report_data = print_report(
            "https://clean.example/",
            [],
            duration=0.1,
            no_open=True,
        )

        sarif_path = report_data["sarif_report_path"]
        assert Path(html_path).exists()
        assert Path(json_path).exists()
        assert Path(sarif_path).exists()
        assert report_data["summary"] == {"Alto": 0, "Medio": 0, "Bajo": 0}
        assert report_data["vulnerabilities"] == []


class TestAPIDatabaseContracts:
    def test_init_db_migrates_existing_tasks_table_with_sarif_path(self):
        import sqlite3

        from api import _init_db

        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        conn.execute(
            """
            CREATE TABLE tasks (
                task_id TEXT PRIMARY KEY,
                url TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'queued',
                html_report_path TEXT,
                json_report_path TEXT,
                results TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )

        _init_db(conn)

        columns = {row["name"] for row in conn.execute("PRAGMA table_info(tasks)").fetchall()}
        assert "sarif_report_path" in columns
