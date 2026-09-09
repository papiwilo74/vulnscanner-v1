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


def test_api_cluster_endpoints() -> None:
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
