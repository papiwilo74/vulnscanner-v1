"""
Pruebas automatizadas para el Gestor Multi-Tenant y Control de Acceso RBAC.
"""
import os
import tempfile
from collections.abc import Generator

import pytest
from fastapi.testclient import TestClient

from api import app
from scanner.tenancy import PasswordHasher, Role, TenancyManager


@pytest.fixture
def temp_tenancy() -> Generator[TenancyManager, None, None]:
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test_tenancy.db")
        mgr = TenancyManager(db_path=db_path)
        yield mgr


def test_password_hasher() -> None:
    pw = "SuperSecret_2026!"
    hashed = PasswordHasher.hash_password(pw)
    assert hashed != pw
    assert PasswordHasher.verify_password(pw, hashed) is True
    assert PasswordHasher.verify_password("wrong_password", hashed) is False


def test_tenancy_organization_and_user_creation(temp_tenancy: TenancyManager) -> None:
    # 1. Crear Organización
    org = temp_tenancy.create_organization(name="Acme Corp", slug="acme-corp")
    assert org.id.startswith("org_")
    assert org.name == "Acme Corp"

    # 2. Registrar usuarios con distintos roles
    admin_usr = temp_tenancy.register_user(
        org_id=org.id,
        email="admin@acme.corp",
        password="Password123!",
        full_name="Alice Admin",
        role=Role.ADMIN,
    )
    assert admin_usr.role == Role.ADMIN
    assert admin_usr.has_permission("scan:launch") is True
    assert admin_usr.has_permission("users:manage") is True

    auditor_usr = temp_tenancy.register_user(
        org_id=org.id,
        email="auditor@acme.corp",
        password="Password123!",
        full_name="Bob Auditor",
        role=Role.AUDITOR,
    )
    assert auditor_usr.role == Role.AUDITOR
    assert auditor_usr.has_permission("scan:launch") is True
    assert auditor_usr.has_permission("users:manage") is False

    dev_usr = temp_tenancy.register_user(
        org_id=org.id,
        email="dev@acme.corp",
        password="Password123!",
        full_name="Charlie Dev",
        role=Role.DEVELOPER,
    )
    assert dev_usr.role == Role.DEVELOPER
    assert dev_usr.has_permission("findings:read") is True
    assert dev_usr.has_permission("scan:profile:aggressive") is False

    # 3. Autenticación exitosa
    auth_res = temp_tenancy.authenticate_user("admin@acme.corp", "Password123!")
    assert auth_res is not None
    user_auth, token = auth_res
    assert user_auth.email == "admin@acme.corp"
    assert token is not None

    # 4. Decodificación de JWT
    decoded_user = temp_tenancy.get_user_from_token(token)
    assert decoded_user is not None
    assert decoded_user.id == admin_usr.id


def test_api_auth_and_tenant_isolation() -> None:
    client = TestClient(app)

    # 1. Registrar Organización A y Usuario A
    reg_a = client.post(
        "/api/auth/register",
        json={
            "email": "ciso@cybercorp.com",
            "password": "SecurePasswordA!",
            "full_name": "CISO CyberCorp",
            "org_name": "CyberCorp Global",
            "role": "admin",
        },
    )
    assert reg_a.status_code == 200
    data_a = reg_a.json()
    token_a = data_a["access_token"]
    assert token_a is not None
    org_a_id = data_a["organization"]["id"]

    # 2. Registrar Organización B y Usuario B (Auditor)
    reg_b = client.post(
        "/api/auth/register",
        json={
            "email": "sec@fintech.com",
            "password": "SecurePasswordB!",
            "full_name": "Sec Auditor FinTech",
            "org_name": "FinTech Secure",
            "role": "auditor",
        },
    )
    assert reg_b.status_code == 200
    data_b = reg_b.json()
    token_b = data_b["access_token"]
    org_b_id = data_b["organization"]["id"]
    assert org_a_id != org_b_id

    # 3. Login de Usuario A
    login_res = client.post(
        "/api/auth/login",
        json={"email": "ciso@cybercorp.com", "password": "SecurePasswordA!"},
    )
    assert login_res.status_code == 200
    assert "access_token" in login_res.json()

    # 4. Consultar /api/auth/me con Token B
    me_res = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token_b}"})
    assert me_res.status_code == 200
    me_data = me_res.json()
    assert me_data["user"]["email"] == "sec@fintech.com"
    assert me_data["organization"]["id"] == org_b_id

    # 5. Lanzar escaneo como Organización B
    scan_b_res = client.post(
        "/scan",
        headers={"Authorization": f"Bearer {token_b}"},
        json={"url": "http://fintech.internal.local", "passive": True},
    )
    assert scan_b_res.status_code == 202
    task_b_id = scan_b_res.json()["task_id"]

    # 6. Validar que Usuario B puede ver su tarea
    task_res = client.get(f"/scan/{task_b_id}", headers={"Authorization": f"Bearer {token_b}"})
    assert task_res.status_code == 200
    assert task_res.json()["task_id"] == task_b_id
