"""
Pruebas automatizadas para el Cluster de Escaneo Distribuido y Nodos Workers.
"""
import os
import tempfile
from collections.abc import Generator

import pytest
from fastapi.testclient import TestClient

from api import app
from scanner.cluster import ClusterCoordinator


@pytest.fixture
def temp_cluster() -> Generator[ClusterCoordinator, None, None]:
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test_cluster.db")
        mgr = ClusterCoordinator(db_path=db_path)
        yield mgr


def test_worker_registration_and_heartbeat(temp_cluster: ClusterCoordinator) -> None:
    # 1. Registrar Worker en us-east-1
    w1 = temp_cluster.register_worker(
        name="AWS-Worker-01",
        region="us-east-1",
        max_concurrency=4,
        tags=["aws", "gpu-accelerated"],
    )
    assert w1.name == "AWS-Worker-01"
    assert w1.region == "us-east-1"
    assert w1.status == "online"

    # 2. Registrar Worker en eu-central-1
    w2 = temp_cluster.register_worker(
        name="EU-Worker-01",
        region="eu-central-1",
        max_concurrency=2,
    )
    assert w2.region == "eu-central-1"

    # 3. Listar workers
    workers = temp_cluster.list_workers()
    assert len(workers) == 2

    # 4. Enviar heartbeat
    hb_ok = temp_cluster.heartbeat(w1.id, active_jobs=1, status="busy")
    assert hb_ok is True
    updated_workers = temp_cluster.list_workers()
    w1_updated = next(w for w in updated_workers if w.id == w1.id)
    assert w1_updated.active_jobs == 1
    assert w1_updated.status == "busy"


def test_cluster_job_dispatch_and_claim(temp_cluster: ClusterCoordinator) -> None:
    worker = temp_cluster.register_worker(name="Local-Worker", region="local")

    # 1. Encolar tarea para región local
    job = temp_cluster.enqueue_job(
        task_id="task_test_001",
        tenant_id="org_default",
        url="http://target.local",
        profile="normal",
        region_preference="local",
    )
    assert job.status == "queued"

    # 2. Reclamar tarea por worker
    claimed = temp_cluster.claim_job(worker_id=worker.id, worker_region="local")
    assert claimed is not None
    assert claimed.task_id == "task_test_001"
    assert claimed.status == "claimed"
    assert claimed.assigned_worker_id == worker.id

    # 3. Completar tarea
    temp_cluster.complete_job(
        task_id="task_test_001",
        worker_id=worker.id,
        results={"findings_count": 0, "status": "clean"},
    )

    stats = temp_cluster.get_stats()
    assert stats["completed_jobs"] == 1
    assert stats["queued_jobs"] == 0


def test_cluster_failover_reaping(temp_cluster: ClusterCoordinator) -> None:
    # Registrar un worker con heartbeat viejo simulado
    worker = temp_cluster.register_worker(name="Unstable-Worker", region="us-east-1")
    temp_cluster.enqueue_job(
        task_id="task_failover_01",
        tenant_id="org_default",
        url="http://target.local",
        region_preference="us-east-1",
    )
    claimed = temp_cluster.claim_job(worker_id=worker.id, worker_region="us-east-1")
    assert claimed is not None

    # Simular que pasaron más de 45 segundos (timeout de failover)
    reaped = temp_cluster.reap_stale_workers(timeout_seconds=0)
    assert worker.id in reaped

    # Verificar que la tarea fue reencolada
    reclaimed = temp_cluster.claim_job(worker_id="backup_worker", worker_region="us-east-1")
    assert reclaimed is not None
    assert reclaimed.task_id == "task_failover_01"


def test_api_cluster_endpoints(monkeypatch: pytest.MonkeyPatch, temp_cluster: ClusterCoordinator) -> None:
    monkeypatch.setattr("api.cluster_mgr", temp_cluster)
    client = TestClient(app)

    # 1. Registrar Worker vía API
    reg_res = client.post(
        "/api/cluster/workers/register",
        json={
            "name": "API-Worker-Test",
            "region": "sa-east-1",
            "max_concurrency": 2,
            "tags": ["cloud", "sa"],
        },
    )
    assert reg_res.status_code == 200
    w_data = reg_res.json()["worker"]
    w_id = w_data["id"]

    # 2. Heartbeat vía API
    hb_res = client.post(f"/api/cluster/workers/{w_id}/heartbeat", json={"active_jobs": 0, "status": "online"})
    assert hb_res.status_code == 200
    assert hb_res.json()["status"] == "ok"

    # 3. Listar workers vía API
    list_res = client.get("/api/cluster/workers")
    assert list_res.status_code == 200
    assert list_res.json()["total_workers"] >= 1

    # 4. Encolar tarea y reclamar vía API
    scan_res = client.post(
        "/scan",
        json={
            "url": "http://cluster-target.local",
            "region": "sa-east-1",
            "dispatch_to_cluster": True,
        },
    )
    assert scan_res.status_code == 202
    task_id = scan_res.json()["task_id"]

    claim_res = client.post(
        "/api/cluster/jobs/claim",
        json={"worker_id": w_id, "region": "sa-east-1"},
    )
    assert claim_res.status_code == 200
    claim_data = claim_res.json()
    assert claim_data["claimed"] is True
    assert claim_data["job"]["task_id"] == task_id

    # 5. Completar tarea vía API
    comp_res = client.post(
        f"/api/cluster/jobs/{task_id}/complete",
        json={
            "worker_id": w_id,
            "results": {"score": 100, "vulnerabilities": []},
            "html_path": None,
            "json_path": None,
        },
    )
    assert comp_res.status_code == 200


def test_cluster_job_retries_and_exhaustion(temp_cluster: ClusterCoordinator) -> None:
    worker = temp_cluster.register_worker(name="Retry-Worker", region="local")
    _ = temp_cluster.enqueue_job(
        task_id="task_retry_test",
        tenant_id="org_default",
        url="http://target.local",
    )

    # 1. Fallo 1 (retry_count: 0 -> 1, reencolado)
    temp_cluster.claim_job(worker_id=worker.id, worker_region="local")
    ok1 = temp_cluster.fail_job("task_retry_test", worker.id, "Timeout de red en etapa 1", allow_retry=True)
    assert ok1 is True
    j1 = temp_cluster.get_job("task_retry_test")
    assert j1 is not None
    assert j1.status == "queued"
    assert j1.retry_count == 1

    # 2. Fallo 2 (retry_count: 1 -> 2, reencolado)
    temp_cluster.claim_job(worker_id=worker.id, worker_region="local")
    temp_cluster.fail_job("task_retry_test", worker.id, "Timeout de red en etapa 2", allow_retry=True)
    j2 = temp_cluster.get_job("task_retry_test")
    assert j2 is not None
    assert j2.retry_count == 2
    assert j2.status == "queued"

    # 3. Fallo 3 (retry_count: 2 -> 3, reencolado)
    temp_cluster.claim_job(worker_id=worker.id, worker_region="local")
    temp_cluster.fail_job("task_retry_test", worker.id, "Timeout de red en etapa 3", allow_retry=True)
    j3 = temp_cluster.get_job("task_retry_test")
    assert j3 is not None
    assert j3.retry_count == 3
    assert j3.status == "queued"

    # 4. Fallo 4 (excede max_retries=3 -> estado failed definitivo)
    temp_cluster.claim_job(worker_id=worker.id, worker_region="local")
    temp_cluster.fail_job("task_retry_test", worker.id, "Fallo irrecuperable", allow_retry=True)
    j_final = temp_cluster.get_job("task_retry_test")
    assert j_final is not None
    assert j_final.status == "failed"
    assert j_final.current_stage == "failed"


def test_cluster_progress_and_cancellation(temp_cluster: ClusterCoordinator) -> None:
    worker = temp_cluster.register_worker(name="Prog-Worker", region="local")
    temp_cluster.enqueue_job(task_id="task_prog_test", tenant_id="org_default", url="http://target.local")
    temp_cluster.claim_job(worker_id=worker.id, worker_region="local")

    # Actualizar progreso
    ok_prog = temp_cluster.update_job_progress("task_prog_test", worker.id, 45, "crawling_deep")
    assert ok_prog is True
    job = temp_cluster.get_job("task_prog_test")
    assert job is not None
    assert job.progress_percent == 45
    assert job.current_stage == "crawling_deep"

    # Cancelar tarea
    assert temp_cluster.is_job_cancelled("task_prog_test") is False
    ok_cancel = temp_cluster.cancel_job("task_prog_test")
    assert ok_cancel is True
    assert temp_cluster.is_job_cancelled("task_prog_test") is True

    job_cancelled = temp_cluster.get_job("task_prog_test")
    assert job_cancelled is not None
    assert job_cancelled.status == "cancelled"


def test_cluster_authentication_enforcement(monkeypatch: pytest.MonkeyPatch, temp_cluster: ClusterCoordinator) -> None:
    monkeypatch.setattr("api.cluster_mgr", temp_cluster)
    monkeypatch.setattr("api._OMNIBREACH_CLUSTER_KEY", "super_secret_cluster_key_12345")
    client = TestClient(app)

    # 1. Petición sin cabecera X-Cluster-Key -> 401 Unauthorized
    resp_unauth = client.post(
        "/api/cluster/workers/register",
        json={"name": "Attacker-Node", "region": "local"},
    )
    assert resp_unauth.status_code == 401

    # 2. Petición con clave errónea -> 401 Unauthorized
    resp_wrong = client.post(
        "/api/cluster/workers/register",
        json={"name": "Attacker-Node", "region": "local"},
        headers={"X-Cluster-Key": "wrong_key"},
    )
    assert resp_wrong.status_code == 401

    # 3. Petición con clave legítima -> 200 OK
    resp_ok = client.post(
        "/api/cluster/workers/register",
        json={"name": "Legit-Node", "region": "local"},
        headers={"X-Cluster-Key": "super_secret_cluster_key_12345"},
    )
    assert resp_ok.status_code == 200


def test_human_in_the_loop_autofix_guardrail() -> None:
    client = TestClient(app)
    # Intentar aplicar cambios a disco con dry_run=False sin confirm=True
    resp = client.post(
        "/api/v1/copilot/autofix",
        json={
            "file_path": "test.py",
            "finding": {"title": "XSS", "category": "xss", "severity": "medium"},
            "dry_run": False,
            "confirm": False,
        }
    )
    assert resp.status_code == 400
    assert "Human-in-the-loop" in resp.json()["detail"]


def test_jwt_logout_and_revocation() -> None:
    client = TestClient(app)
    # Registrar e iniciar sesión
    login_res = client.post("/api/auth/register", json={
        "email": "logout_test@example.com",
        "password": "Password123!",
        "full_name": "Logout Tester",
        "org_name": "Test Org"
    })
    assert login_res.status_code == 200
    token = login_res.json()["access_token"]

    # Acceso a /api/auth/me exitoso con token activo
    me_res = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me_res.status_code == 200

    # Cerrar sesión (Logout)
    logout_res = client.post("/api/auth/logout", headers={"Authorization": f"Bearer {token}"})
    assert logout_res.status_code == 200

    # Acceso posterior a /api/auth/me debe ser rechazado con 401
    me_revoked_res = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me_revoked_res.status_code == 401


def test_scan_compare_endpoint() -> None:
    client = TestClient(app)
    res = client.post("/api/scans/compare", json={
        "scan_a": {
            "task_id": "scan_1",
            "security_score": 70.0,
            "results": {"security_score": 70.0, "vulnerabilities": [{"category": "xss", "cwe_id": "CWE-79"}]}
        },
        "scan_b": {
            "task_id": "scan_2",
            "security_score": 90.0,
            "results": {"security_score": 90.0, "vulnerabilities": []}
        }
    })
    assert res.status_code == 200
    data = res.json()
    assert data["total_resolved"] == 1
    assert data["risk_score_delta"] == 20.0

