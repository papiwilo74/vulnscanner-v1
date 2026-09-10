import json

from fastapi.testclient import TestClient

from api import app, broadcast_event_sync

client = TestClient(app)


def test_api_root_and_dashboard():
    # 1. Test Root
    res_root = client.get("/")
    assert res_root.status_code == 200
    data = res_root.json()
    assert data["version"] == "2.5"
    assert data["dashboard_url"] == "/dashboard"

    # 1.1 Test Health
    res_health = client.get("/health")
    assert res_health.status_code == 200
    health_data = res_health.json()
    assert health_data["status"] == "healthy"
    assert "OmniBreach" in health_data["service"]

    # 2. Test Dashboard HTML
    res_dash = client.get("/dashboard")
    assert res_dash.status_code == 200
    assert "Real-Time SOC Dashboard" in res_dash.text
    assert "severityChart" in res_dash.text
    assert "WebSocket: Conectado" in res_dash.text


def test_websocket_scan_stream():
    task_id = "test-task-uuid-1234"
    with client.websocket_connect(f"/ws/scan/{task_id}") as websocket:
        # Enviar evento de progreso vía broadcaster
        broadcast_event_sync(task_id, {
            "event": "progress",
            "step": "Prueba de WebSocket",
            "percent": 50,
            "current_rps": 15.2,
        })

        data = websocket.receive_text()
        parsed = json.loads(data)
        assert parsed["event"] == "progress"
        assert parsed["percent"] == 50
        assert parsed["current_rps"] == 15.2
