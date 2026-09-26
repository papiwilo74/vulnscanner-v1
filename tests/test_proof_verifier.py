"""
Suite de Pruebas Unitarias para el Motor de Verificación Basado en Pruebas (Proof-Based Verification).
Verifica:
1. Extracción y certificación forense de banners de base de datos para SQLi.
2. Reconocimiento forense y hash de firmas de sistema para Path Traversal / LFI.
3. Certificación de interacciones fuera de banda (OAST).
4. Certificación de acceso cruzado entre entidades para BOLA / IDOR.
5. Certificación de mutación de propiedades para Mass Assignment.
"""
from __future__ import annotations

from unittest.mock import Mock

import requests

from scanner.models import Evidence, Finding
from scanner.proof_verifier import ProofVerifier


class TestSQLiProofVerification:
    """Pruebas de verificación de pruebas para SQL Injection."""

    def test_sqli_verifies_with_extracted_sqlite_banner(self) -> None:
        mock_session = Mock(spec=requests.Session)
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.text = "Resultados de búsqueda: SQLite 3.39.4 instalado en el servidor."
        mock_session.get.return_value = mock_resp

        finding = Finding(
            category="sqli",
            title="SQLi en parámetro 'q'",
            severity="high",
            affected_url="https://target.local/search?q=test",
            parameter="q",
            evidence=Evidence(request_method="GET", request_url="https://target.local/search?q=test"),
        )

        verifier = ProofVerifier(session=mock_session)
        verified_finding = verifier.verify_finding(finding)

        assert verified_finding.is_proof_verified is True
        assert verified_finding.proof_evidence is not None
        assert verified_finding.proof_evidence["proof_type"] == "safe_db_banner_extraction"
        assert "SQLite 3.39.4" in verified_finding.proof_evidence["extracted_banner"]
        assert len(verified_finding.proof_evidence["evidence_hash"]) == 64

    def test_sqli_verifies_with_native_syntax_exception_fallback(self) -> None:
        mock_session = Mock(spec=requests.Session)
        mock_resp = Mock()
        mock_resp.status_code = 500
        mock_resp.text = "Sin coincidencia"
        mock_session.get.return_value = mock_resp

        finding = Finding(
            category="sqli",
            title="SQLi en login",
            severity="critical",
            affected_url="https://target.local/api/v1/auth",
            evidence=Evidence(
                request_method="POST",
                request_url="https://target.local/api/v1/auth",
                response_fragment="pg_query(): syntax error in SQL query at or near ''",
            ),
        )

        verifier = ProofVerifier(session=mock_session)
        verified_finding = verifier.verify_finding(finding)

        assert verified_finding.is_proof_verified is True
        assert verified_finding.proof_evidence is not None
        assert verified_finding.proof_evidence["proof_type"] == "db_native_syntax_exception"


class TestLFISystemProofVerification:
    """Pruebas de verificación de pruebas para Path Traversal / LFI."""

    def test_lfi_verifies_linux_passwd_marker(self) -> None:
        finding = Finding(
            category="path_traversal",
            title="Path Traversal en file",
            severity="high",
            affected_url="https://target.local/view?file=../../../../etc/passwd",
            evidence=Evidence(
                request_method="GET",
                request_url="https://target.local/view?file=../../../../etc/passwd",
                response_fragment="root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
            ),
        )

        verifier = ProofVerifier()
        verified = verifier.verify_finding(finding)

        assert verified.is_proof_verified is True
        assert verified.proof_evidence is not None
        assert verified.proof_evidence["proof_type"] == "safe_file_marker_signature"
        assert "Linux /etc/passwd" in verified.proof_evidence["marker_identified"]

    def test_lfi_verifies_windows_win_ini_marker(self) -> None:
        finding = Finding(
            category="path_traversal",
            title="Path Traversal en file",
            severity="high",
            affected_url="https://target.local/view?file=..\\..\\win.ini",
            evidence=Evidence(
                request_method="GET",
                request_url="https://target.local/view?file=..\\..\\win.ini",
                response_fragment="; for 16-bit app support\n[fonts]\nArial (TrueType)=ARIAL.TTF",
            ),
        )

        verifier = ProofVerifier()
        verified = verifier.verify_finding(finding)

        assert verified.is_proof_verified is True
        assert verified.proof_evidence is not None
        assert "win.ini" in verified.proof_evidence["marker_identified"]


class TestOASTAndAPIProofVerification:
    """Pruebas de verificación para OAST y APIs."""

    def test_oast_interaction_certified(self) -> None:
        finding = Finding(
            category="oast",
            title="Blind SSRF confirmado por interacción OAST",
            severity="critical",
            affected_url="https://target.local/import?url=http://oast.local/uuid123",
            evidence=Evidence(
                request_method="POST",
                request_url="https://target.local/import",
                response_fragment="DNS Query A de 192.168.1.50 para oast-token-42.oast.local",
            ),
        )

        verifier = ProofVerifier()
        verified = verifier.verify_finding(finding)

        assert verified.is_proof_verified is True
        assert verified.proof_evidence is not None
        assert verified.proof_evidence["proof_type"] == "oast_network_interaction"

    def test_bola_cross_tenant_access_certified(self) -> None:
        finding = Finding(
            category="api_bola",
            title="BOLA en /accounts/1002",
            severity="high",
            affected_url="https://api.target.local/accounts/1002",
            evidence=Evidence(
                request_method="GET",
                request_url="https://api.target.local/accounts/1002",
                response_status=200,
                response_fragment='{"account_id": "1002", "owner": "Bob", "balance": 15000}',
            ),
        )

        verifier = ProofVerifier()
        verified = verifier.verify_finding(finding)

        assert verified.is_proof_verified is True
        assert verified.proof_evidence is not None
        assert verified.proof_evidence["proof_type"] == "cross_tenant_object_access"

    def test_verify_all_batch_pipeline(self) -> None:
        findings = [
            Finding(
                category="path_traversal",
                title="LFI",
                severity="high",
                evidence=Evidence(response_fragment="[extensions]\nfoo=bar"),
            ),
            Finding(
                category="headers",
                title="Missing HSTS",
                severity="low",
            ),
        ]

        verifier = ProofVerifier()
        results = verifier.verify_all(findings)

        assert len(results) == 2
        assert results[0].is_proof_verified is True
        assert results[1].is_proof_verified is False
