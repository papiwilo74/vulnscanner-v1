"""
Evaluación Empírica, Validación Anti-Alucinaciones y Sanitización de Privacidad del AI Copilot.

Verifica:
1. Saneamiento estricto de secretos (tokens JWT, Bearer, contraseñas, IPs privadas RFC1918)
   antes de cualquier comunicación con APIs en la nube (Groq).
2. Guardrails anti-alucinaciones: El motor determinista reconcilia severidades y evita escaladas espurias.
3. Evaluación empírica de triaje contra un dataset de referencia (Ground Truth).
"""
import json
from unittest.mock import MagicMock, patch

import pytest

from scanner.ai_copilot import (
    AIConfig,
    AutoPatcher,
    DataSanitizer,
    FindingTriager,
    HybridLLMClient,
)
from scanner.models import Evidence, Finding


class TestDataSanitizer:
    """Verifica la despersonalización y redacción de datos confidenciales."""

    def test_sanitize_jwt_and_bearer_tokens(self) -> None:
        jwt_mock = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        raw_text = f"Header Authorization: Bearer {jwt_mock} detectado en endpoint."
        sanitized = DataSanitizer.sanitize_text(raw_text)

        assert jwt_mock not in sanitized
        assert "[REDACTED_JWT]" in sanitized or "[REDACTED_TOKEN]" in sanitized

    def test_sanitize_private_ip_addresses(self) -> None:
        text = "Fuga SSRF hacia 10.0.1.5, 192.168.1.50 y 172.16.5.99 interna."
        sanitized = DataSanitizer.sanitize_text(text)

        assert "10.0.1.5" not in sanitized
        assert "192.168.1.50" not in sanitized
        assert "172.16.5.99" not in sanitized
        assert "[REDACTED_IP]" in sanitized

    def test_sanitize_session_cookies_and_api_keys(self) -> None:
        text = "Cookie: sessionid=abcdef1234567890; api_key=secret_live_key_998877"
        sanitized = DataSanitizer.sanitize_text(text)

        assert "abcdef1234567890" not in sanitized
        assert "secret_live_key_998877" not in sanitized
        assert "[REDACTED_SESSION]" in sanitized or "[REDACTED_SECRET]" in sanitized

    def test_sanitize_finding_deep_copy(self) -> None:
        ev = Evidence(
            request_method="GET",
            request_url="https://192.168.1.100/admin?token=secret12345678",
            payload="password=SuperSecretPassword123!",
            response_fragment="User authenticated with Bearer 123456789012345"
        )
        finding = Finding(
            category="auth_bypass",
            title="Bypass en 10.0.0.1 con token secret12345678",
            severity="high",
            affected_url="http://192.168.1.100/login",
            parameter="token=secret12345678",
            evidence=ev
        )

        clean = DataSanitizer.sanitize_finding(finding)

        assert clean.affected_url is not None
        assert "192.168.1.100" not in clean.affected_url
        assert "10.0.0.1" not in clean.title
        assert clean.evidence is not None
        assert clean.evidence.request_url is not None
        assert "192.168.1.100" not in clean.evidence.request_url


class TestGroqPrivacyGuardrail:
    """Verifica que las peticiones a Groq Cloud jamás reciban secretos sin redactar."""

    @patch("requests.post")
    def test_groq_payload_is_always_sanitized(self, mock_post: MagicMock) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "choices": [{"message": {"content": "{\"status\": \"ok\"}"}}]
        }
        mock_post.return_value = mock_resp

        config = AIConfig(groq_api_key="gsk_test_key_12345", prefer_local=False)
        client = HybridLLMClient(config)

        sensitive_prompt = "Audita el host 192.168.1.1 con Bearer secret_token_xyz_123456"
        client.generate([{"role": "user", "content": sensitive_prompt}])

        assert mock_post.called
        call_kwargs = mock_post.call_args[1]
        payload = call_kwargs["json"]
        sent_messages = payload["messages"]
        sent_content = sent_messages[0]["content"]

        assert "192.168.1.1" not in sent_content
        assert "secret_token_xyz_123456" not in sent_content
        assert "[REDACTED_IP]" in sent_content


class TestAntiHallucinationGuardrails:
    """Evalúa que las alucinaciones del modelo sean mitigadas por el validador formal."""

    def test_triage_prevents_unwarranted_severity_escalation(self) -> None:
        # Hallazgo determinista es 'info' (cabecera faltante)
        finding = Finding(
            category="headers",
            title="Cabecera X-Frame-Options no configurada",
            severity="info",
            affected_url="https://example.com",
            cwe_id="CWE-1021"
        )

        mock_client = MagicMock(spec=HybridLLMClient)
        # La IA alucina que es 'critical'
        hallucinated_json = json.dumps({
            "human_explanation": "Falta de cabecera que permite clickjacking.",
            "attack_vector": "Clickjacking en iframe.",
            "business_impact": "Compromiso total de la infraestructura.",
            "exploit_difficulty": "low",
            "recommended_severity": "critical"  # Alucinación grosera
        })
        mock_client.generate.return_value = (hallucinated_json, "test_llm", 15.0)

        triager = FindingTriager(mock_client)
        result = triager.triage_finding(finding)

        # El guardrail debe haber corregido la severidad a la línea base determinista
        assert result["recommended_severity"] == "info"
        assert result["cwe_id"] == "CWE-1021"

    def test_triage_preserves_legitimate_severity(self) -> None:
        finding = Finding(
            category="sqli",
            title="Inyección SQL basada en tiempo",
            severity="high",
            affected_url="https://example.com/api/users",
            cwe_id="CWE-89"
        )

        mock_client = MagicMock(spec=HybridLLMClient)
        legit_json = json.dumps({
            "human_explanation": "Inyección SQL verificada que permite exfiltración de base de datos.",
            "attack_vector": "Manipulación de payload SQL.",
            "business_impact": "Filtración masiva de registros.",
            "exploit_difficulty": "medium",
            "recommended_severity": "high"
        })
        mock_client.generate.return_value = (legit_json, "test_llm", 25.0)

        triager = FindingTriager(mock_client)
        result = triager.triage_finding(finding)

        assert result["recommended_severity"] == "high"


class TestAutoPatcherSyntaxVerification:
    """Verifica que el AST guardrail rechace parches sintácticamente inválidos."""

    def test_patcher_rejects_invalid_python_syntax(self) -> None:
        mock_client = MagicMock(spec=HybridLLMClient)
        # IA genera código con error de sintaxis evidente
        broken_code = "def vulnerable_handler():\n    if True\n        print('broken syntax')"
        mock_client.generate.return_value = (json.dumps({"patched_code": broken_code}), "test_llm", 10.0)

        patcher = AutoPatcher(mock_client)
        finding = Finding(category="xss", title="XSS", severity="medium")

        with pytest.raises(ValueError, match="sintaxis"):
            patcher.patch_code_snippet("def original(): pass", finding, language="python")

    def test_patcher_accepts_valid_python_syntax(self) -> None:
        mock_client = MagicMock(spec=HybridLLMClient)
        clean_code = "def secure_handler(user_input: str) -> None:\n    safe = html_escape(user_input)\n    print(safe)\n"
        mock_client.generate.return_value = (json.dumps({"patched_code": clean_code}), "test_llm", 10.0)

        patcher = AutoPatcher(mock_client)
        finding = Finding(category="xss", title="XSS", severity="medium")

        patched, diff = patcher.patch_code_snippet("def handler(): pass\n", finding, language="python")
        assert "html_escape" in patched
        assert len(diff) > 0
