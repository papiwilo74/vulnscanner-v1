"""
Pruebas automatizadas para el Motor de Deception (Ciberdefensa Activa y HoneyTokens).
"""
import os
import tempfile
from collections.abc import Generator

import pytest
from fastapi.testclient import TestClient

from api import app
from scanner.deception import DeceptionManager, HoneyTrap, SnippetGenerator


@pytest.fixture
def temp_deception_mgr() -> Generator[DeceptionManager, None, None]:
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test_deception.db")
        mgr = DeceptionManager(db_path=db_path)
        yield mgr


def test_create_and_get_traps(temp_deception_mgr: DeceptionManager) -> None:
    # 1. URL trap
    t_url = temp_deception_mgr.create_trap("url", "Ruta Secreta Admin", "http://test.local")
    assert t_url.id is not None
    assert t_url.trap_type == "url"
    assert "/_internal/vault" in t_url.token_value
    assert t_url.trigger_count == 0

    # 2. API Key trap
    t_key = temp_deception_mgr.create_trap("api_key", "Stripe Fake Key")
    assert t_key.trap_type == "api_key"
    assert t_key.token_value.startswith("sk_live_")

    # 3. JWT trap
    t_jwt = temp_deception_mgr.create_trap("jwt_token", "JWT Superadmin")
    assert t_jwt.trap_type == "jwt_token"
    assert len(t_jwt.token_value.split(".")) == 3

    # 4. Cookie trap
    t_cookie = temp_deception_mgr.create_trap("cookie", "Session Cookie")
    assert t_cookie.trap_type == "cookie"
    assert t_cookie.token_value.startswith("debug_session_")

    # Recuperación por ID
    fetched = temp_deception_mgr.get_trap(t_url.id)
    assert fetched is not None
    assert fetched.id == t_url.id
    assert fetched.label == "Ruta Secreta Admin"

    # Recuperación por token
    found_by_token = temp_deception_mgr.find_trap_by_token(t_key.token_value)
    assert found_by_token is not None
    assert found_by_token.id == t_key.id

    # Listado de trampas
    all_traps = temp_deception_mgr.list_traps()
    assert len(all_traps) == 4


def test_record_canary_event_and_stats(temp_deception_mgr: DeceptionManager) -> None:
    trap = temp_deception_mgr.create_trap("api_key", "Fake Stripe Key")
    assert trap.trigger_count == 0

    event = temp_deception_mgr.record_event(
        trap=trap,
        attacker_ip="198.51.100.42",
        user_agent="sqlmap/1.7#dev",
        http_method="POST",
        requested_path="/deception/trap/" + trap.id,
        headers={"Content-Type": "application/json", "Authorization": "Bearer " + trap.token_value},
        payload_sample='{"query": "SELECT * FROM users"}',
    )

    assert event.attacker_ip == "198.51.100.42"
    assert event.trap_id == trap.id
    assert event.payload_sample == '{"query": "SELECT * FROM users"}'

    # Verificar actualización de disparos en trampa
    updated_trap = temp_deception_mgr.get_trap(trap.id)
    assert updated_trap is not None
    assert updated_trap.trigger_count == 1

    # Verificar listado de eventos
    events = temp_deception_mgr.list_events()
    assert len(events) == 1
    assert events[0].id == event.id
    assert events[0].headers.get("Content-Type") == "application/json"

    # Estadísticas
    stats = temp_deception_mgr.get_stats()
    assert stats["total_traps"] == 1
    assert stats["active_traps"] == 1
    assert stats["total_intrusions_detected"] == 1
    assert stats["unique_attackers"] == 1


def test_snippet_generator() -> None:
    dummy_trap = HoneyTrap(
        id="canary123",
        trap_type="url",
        label="Vault",
        token_value="/_internal/vault_abc",
        target_url="http://localhost:8000",
    )
    snippet_url = SnippetGenerator.generate_snippet(dummy_trap, "http://localhost:8000")
    assert "Disallow: /_internal/vault_abc" in snippet_url["code"]
    assert "/deception/trap/canary123" in snippet_url["code"]

    dummy_trap.trap_type = "api_key"
    dummy_trap.token_value = "sk_live_12345"
    snippet_key = SnippetGenerator.generate_snippet(dummy_trap, "http://localhost:8000")
    assert "sk_live_12345" in snippet_key["code"]

    dummy_trap.trap_type = "jwt_token"
    dummy_trap.token_value = "header.payload.sig"
    snippet_jwt = SnippetGenerator.generate_snippet(dummy_trap, "http://localhost:8000")
    assert "localStorage.setItem" in snippet_jwt["code"]

    dummy_trap.trap_type = "cookie"
    dummy_trap.token_value = "debug_session_789"
    snippet_cookie = SnippetGenerator.generate_snippet(dummy_trap, "http://localhost:8000")
    assert "Set-Cookie: debug_session_789" in snippet_cookie["code"]


def test_deception_api_endpoints() -> None:
    client = TestClient(app)

    # 1. Crear trampa vía API
    gen_res = client.post(
        "/api/deception/generate",
        json={"trap_type": "url", "label": "API Honey Route", "target_url": "http://test.local"},
    )
    assert gen_res.status_code == 200
    gen_data = gen_res.json()
    assert "trap" in gen_data
    assert "snippet" in gen_data
    trap_id = gen_data["trap"]["id"]

    # 2. Listar trampas
    traps_res = client.get("/api/deception/traps")
    assert traps_res.status_code == 200
    traps_data = traps_res.json()
    assert traps_data["total"] >= 1

    # 3. Obtener snippet de trampa
    snip_res = client.get(f"/api/deception/snippet/{trap_id}")
    assert snip_res.status_code == 200
    assert "code" in snip_res.json()["snippet"]

    # 4. Detonar trampa (Atacante accede al endpoint trampa)
    trigger_res = client.get(
        f"/deception/trap/{trap_id}",
        headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) BadBot/2.0"},
    )
    assert trigger_res.status_code == 401
    trigger_json = trigger_res.json()
    assert trigger_json["code"] == "AUTH_TOKEN_EXPIRED"

    # 5. Detonar trampa con POST y payload
    post_res = client.post(
        f"/deception/trap/{trap_id}",
        headers={"User-Agent": "Nikto/2.1.6"},
        content=b"probe_exploit_payload=1",
    )
    assert post_res.status_code == 401

    # 6. Consultar eventos de intrusión
    events_res = client.get("/api/deception/events")
    assert events_res.status_code == 200
    events_data = events_res.json()
    assert events_data["total"] >= 2

    # 7. Consultar estadísticas
    stats_res = client.get("/api/deception/stats")
    assert stats_res.status_code == 200
    stats_data = stats_res.json()
    assert stats_data["total_intrusions_detected"] >= 2
