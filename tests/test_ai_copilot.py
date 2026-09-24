"""Pruebas automatizadas para el Copiloto de Seguridad IA Híbrido (Groq + Ollama) y Auto-Fixer.
Verifica los 5 modos operativos, conmutación por fallas, guardrails de AST, backups y endpoints API.
"""
import json
import os
import tempfile
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from api import app
from scanner.ai_copilot import (
    AIConfig,
    AutoPatcher,
    ExecutiveSummaryGenerator,
    FindingTriager,
    HybridLLMClient,
    InteractiveCopilot,
    RemediationGenerator,
)
from scanner.models import Evidence, Finding


@pytest.fixture
def sample_finding() -> Finding:
    return Finding(
        category="sqli",
        title="SQL Injection en parámetro id",
        severity="critical",
        confidence="confirmed",
        affected_url="https://api.empresa.com/users",
        parameter="id",
        evidence=Evidence(
            request_method="GET",
            request_url="https://api.empresa.com/users?id=1'%20OR%20'1'='1",
            payload="1' OR '1'='1",
            response_status=200,
        ),
    )


# ─────────────────────────────────────────────────────────────
# 1. Pruebas del Cliente Híbrido (Groq Cloud + Ollama Local + Fallback)
# ─────────────────────────────────────────────────────────────

def test_hybrid_client_groq_success() -> None:
    config = AIConfig(groq_api_key="gsk_test_key_12345", prefer_local=False)
    client = HybridLLMClient(config)

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "choices": [{"message": {"content": "Respuesta desde Groq LPU"}}]
    }

    with patch("requests.post", return_value=mock_resp):
        res, provider, latency = client.generate([{"role": "user", "content": "test"}])
        assert res == "Respuesta desde Groq LPU"
        assert provider == "groq_cloud"
        assert latency >= 0.0


def test_hybrid_client_fallback_to_ollama() -> None:
    config = AIConfig(groq_api_key="gsk_test_key_12345", prefer_local=False)
    client = HybridLLMClient(config)

    # Groq falla con 500, Ollama responde con éxito
    mock_groq_fail = MagicMock()
    mock_groq_fail.status_code = 500

    mock_ollama_ok = MagicMock()
    mock_ollama_ok.status_code = 200
    mock_ollama_ok.json.return_value = {
        "message": {"content": "Respuesta desde Ollama Local en RTX 4060"}
    }

    with patch("requests.post", side_effect=[mock_groq_fail, mock_ollama_ok]):
        res, provider, latency = client.generate([{"role": "user", "content": "test"}])
        assert res == "Respuesta desde Ollama Local en RTX 4060"
        assert provider == "ollama_local"


def test_hybrid_client_offline_rule_fallback() -> None:
    config = AIConfig(groq_api_key="", prefer_local=False)
    client = HybridLLMClient(config)

    # Ollama falla (conexión rechazada / offline)
    with patch("requests.post", side_effect=ConnectionError("Ollama offline")):
        res, provider, _ = client.generate([{"role": "user", "content": "test"}], json_mode=True)
        assert provider == "rule_engine_fallback"
        data = json.loads(res)
        assert "explanation" in data
        assert "top_immediate_actions" in data


# ─────────────────────────────────────────────────────────────
# 2. Modo 1: Triage de Vulnerabilidades
# ─────────────────────────────────────────────────────────────

def test_finding_triage_mode(sample_finding: Finding) -> None:
    client = HybridLLMClient(AIConfig(groq_api_key=""))
    triager = FindingTriager(client)

    # Probando con el fallback determinista
    triage_data = triager.triage_finding(sample_finding)
    assert "human_explanation" in triage_data or "explanation" in triage_data
    assert "attack_vector" in triage_data
    assert "business_impact" in triage_data
    assert triage_data["provider_used"] == "rule_engine_fallback"


# ─────────────────────────────────────────────────────────────
# 3. Modo 2: Generador de Parches de Remediación
# ─────────────────────────────────────────────────────────────

def test_remediation_patch_generator(sample_finding: Finding) -> None:
    client = HybridLLMClient(AIConfig(groq_api_key=""))
    remediator = RemediationGenerator(client)

    patch_data = remediator.generate_patch(sample_finding, tech_stack=["FastAPI", "Python"])
    assert "after_code" in patch_data
    assert "language" in patch_data
    assert "defense_in_depth" in patch_data or "top_immediate_actions" in patch_data


# ─────────────────────────────────────────────────────────────
# 4. Modo 3: Auto-Patcher Local con Guardrails y Backups
# ─────────────────────────────────────────────────────────────

def test_auto_patcher_dry_run_and_real_apply(sample_finding: Finding) -> None:
    client = HybridLLMClient(AIConfig(groq_api_key=""))
    patcher = AutoPatcher(client)

    vulnerable_py_code = """def get_user(db, user_id):
    query = f"SELECT * FROM users WHERE id = '{user_id}'"
    return db.execute(query).fetchall()
"""

    with tempfile.TemporaryDirectory() as tmpdir:
        test_file = os.path.join(tmpdir, "routes.py")
        with open(test_file, "w", encoding="utf-8") as f:
            f.write(vulnerable_py_code)

        # 1. Simulación Dry-Run (no modifica el archivo original)
        with patch.object(
            patcher,
            "patch_code_snippet",
            return_value=("def get_user(db, user_id):\n    return db.execute('SELECT * FROM users WHERE id = :id', {'id': user_id})\n", "--- diff mock")
        ):
            res_dry = patcher.patch_file(test_file, sample_finding, dry_run=True)
            assert res_dry.success is True
            assert res_dry.applied is False
            assert res_dry.backup_path is None
            assert res_dry.diff == "--- diff mock"

            # El archivo sigue teniendo el código original
            with open(test_file, encoding="utf-8") as f:
                assert f.read() == vulnerable_py_code

            # 2. Aplicación Real (applied=True, crea .bak y sobreescribe con código seguro)
            res_real = patcher.patch_file(test_file, sample_finding, dry_run=False)
            assert res_real.success is True
            assert res_real.applied is True
            assert res_real.backup_path is not None
            assert os.path.exists(res_real.backup_path)

            # Verificar que el backup contiene el código original
            with open(res_real.backup_path, encoding="utf-8") as f_bak:
                assert f_bak.read() == vulnerable_py_code

            # Verificar que el archivo principal fue actualizado
            with open(test_file, encoding="utf-8") as f_new:
                assert "SELECT * FROM users WHERE id = :id" in f_new.read()


def test_auto_patcher_syntax_guardrail(sample_finding: Finding) -> None:
    client = HybridLLMClient(AIConfig(groq_api_key=""))
    patcher = AutoPatcher(client)

    # Simular que el LLM devolvió código Python con sintaxis rota
    broken_code = "def syntax_error_func( \n invalid syntax ::::"

    with (
        patch.object(client, "generate", return_value=(json.dumps({"patched_code": broken_code}), "mock", 10.0)),
        pytest.raises(ValueError, match="sintaxis Python")
    ):
        patcher.patch_code_snippet("def original(): pass", sample_finding, language="python")


# ─────────────────────────────────────────────────────────────
# 5. Modo 4: Resumen Ejecutivo CISO y Compliance
# ─────────────────────────────────────────────────────────────

def test_executive_summary_mode(sample_finding: Finding) -> None:
    client = HybridLLMClient(AIConfig(groq_api_key=""))
    exec_gen = ExecutiveSummaryGenerator(client)

    summary = exec_gen.generate_summary([sample_finding], "https://empresa.com")
    assert "overall_posture" in summary
    assert "top_immediate_actions" in summary
    assert "compliance_status" in summary
    assert summary["counts"]["critical"] == 1


# ─────────────────────────────────────────────────────────────
# 6. Modo 5: Chat Interactivo de Auditoría
# ─────────────────────────────────────────────────────────────

def test_interactive_copilot_chat(sample_finding: Finding) -> None:
    client = HybridLLMClient(AIConfig(groq_api_key=""))
    chat_bot = InteractiveCopilot(client)

    res = chat_bot.chat("¿Cómo genero un comando cURL para reproducir este SQLi?", [sample_finding], "https://empresa.com")
    assert "answer" in res
    assert "suggested_actions" in res
    assert len(res["suggested_actions"]) > 0


# ─────────────────────────────────────────────────────────────
# 7. Endpoints API REST en FastAPI
# ─────────────────────────────────────────────────────────────

def test_api_copilot_endpoints(sample_finding: Finding) -> None:
    test_client = TestClient(app)

    finding_dict = sample_finding.to_dict()

    # 1. Endpoint Triage
    triage_res = test_client.post("/api/v1/copilot/triage", json={"finding": finding_dict})
    assert triage_res.status_code == 200
    assert "attack_vector" in triage_res.json()

    # 2. Endpoint Remediation
    rem_res = test_client.post(
        "/api/v1/copilot/remediation",
        json={"finding": finding_dict, "tech_stack": ["FastAPI", "Python"]}
    )
    assert rem_res.status_code == 200
    assert "after_code" in rem_res.json()

    # 3. Endpoint Chat
    chat_res = test_client.post(
        "/api/v1/copilot/chat",
        json={"query": "¿Cuál es el hallazgo más crítico?", "findings": [finding_dict]}
    )
    assert chat_res.status_code == 200
    assert "answer" in chat_res.json()

    # 4. Endpoint Executive Summary
    summary_res = test_client.post(
        "/api/v1/copilot/executive-summary",
        json={"findings": [finding_dict], "target_url": "https://api.empresa.com"}
    )
    assert summary_res.status_code == 200
    assert "overall_posture" in summary_res.json()

    # 5. Endpoint Autofix (Dry Run)
    with tempfile.NamedTemporaryFile(suffix=".py", delete=False) as tf:
        tf.write(b"def check(): pass\n")
        tf_name = tf.name

    try:
        autofix_res = test_client.post(
            "/api/v1/copilot/autofix",
            json={"file_path": tf_name, "finding": finding_dict, "dry_run": True}
        )
        assert autofix_res.status_code == 200
        assert autofix_res.json()["success"] is True
        assert autofix_res.json()["applied"] is False
    finally:
        if os.path.exists(tf_name):
            os.remove(tf_name)
