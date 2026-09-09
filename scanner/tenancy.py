"""
Gestor de Multi-Tenancy y Control de Acceso Basado en Roles (RBAC).
Permite la segregación de organizaciones (tenants) y permisos para Admin, Auditor y Developer.
"""
import contextlib
import datetime
import hashlib
import hmac
import json
import logging
import os
import secrets
import sqlite3
import threading
from collections.abc import Generator
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Optional

logger = logging.getLogger("VulnScanner.Tenancy")


class Role(str, Enum):
    ADMIN = "admin"
    AUDITOR = "auditor"
    DEVELOPER = "developer"


ROLE_PERMISSIONS: dict[Role, set[str]] = {
    Role.ADMIN: {
        "scan:launch",
        "scan:read",
        "scan:delete",
        "scan:profile:aggressive",
        "deception:manage",
        "cluster:manage",
        "org:manage",
        "users:manage",
    },
    Role.AUDITOR: {
        "scan:launch",
        "scan:read",
        "scan:profile:aggressive",
        "deception:read",
        "report:export",
    },
    Role.DEVELOPER: {
        "scan:read",
        "autofix:read",
        "autofix:apply",
        "findings:read",
    },
}


@dataclass
class Organization:
    """Entidad de Tenant / Organización aislada."""

    id: str
    name: str
    slug: str
    tier: str = "enterprise"
    created_at: str = field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())
    max_scans_monthly: int = 1000

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class User:
    """Usuario miembro de una organización con un rol específico."""

    id: str
    org_id: str
    email: str
    password_hash: str
    full_name: str
    role: Role
    is_active: bool = True
    created_at: str = field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d.pop("password_hash", None)
        d["role"] = self.role.value
        return d

    def has_permission(self, perm: str) -> bool:
        allowed = ROLE_PERMISSIONS.get(self.role, set())
        return perm in allowed or self.role == Role.ADMIN


class PasswordHasher:
    """Hash seguro con PBKDF2-HMAC-SHA256 (100,000 iteraciones + salt aleatorio de 16 bytes)."""

    ITERATIONS = 100_000

    @classmethod
    def hash_password(cls, password: str) -> str:
        salt = secrets.token_bytes(16)
        key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, cls.ITERATIONS)
        return f"{salt.hex()}${cls.ITERATIONS}${key.hex()}"

    @classmethod
    def verify_password(cls, password: str, stored_hash: str) -> bool:
        try:
            salt_hex, iters_str, key_hex = stored_hash.split("$", 2)
            salt = bytes.fromhex(salt_hex)
            iters = int(iters_str)
            computed = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iters)
            return hmac.compare_digest(computed.hex(), key_hex)
        except Exception:
            return False


class JWTManager:
    """Gestor criptográfico de tokens JWT (HS256) sin dependencias externas pesadas."""

    def __init__(self, secret: Optional[str] = None) -> None:
        self.secret = (secret or os.environ.get("VULNSCANNER_JWT_SECRET") or "vulnscanner_enterprise_secret_key_32bytes!").encode("utf-8")

    def create_token(self, user: User, expires_in_seconds: int = 86400) -> str:
        header = {"alg": "HS256", "typ": "JWT"}
        exp = int(datetime.datetime.now(datetime.timezone.utc).timestamp()) + expires_in_seconds
        payload = {
            "sub": user.id,
            "org_id": user.org_id,
            "email": user.email,
            "role": user.role.value,
            "exp": exp,
            "jti": secrets.token_hex(8),
        }

        import base64
        h_part = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
        p_part = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
        msg = f"{h_part}.{p_part}".encode()
        sig = base64.urlsafe_b64encode(hmac.new(self.secret, msg, hashlib.sha256).digest()).decode().rstrip("=")
        return f"{h_part}.{p_part}.{sig}"

    def decode_token(self, token: str) -> Optional[dict[str, Any]]:
        import base64
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return None
            h_part, p_part, sig_part = parts
            msg = f"{h_part}.{p_part}".encode()
            expected_sig = base64.urlsafe_b64encode(hmac.new(self.secret, msg, hashlib.sha256).digest()).decode().rstrip("=")
            if not hmac.compare_digest(sig_part, expected_sig):
                return None

            # Añadir padding si es necesario
            rem = len(p_part) % 4
            padded = p_part + ("=" * (4 - rem) if rem else "")
            payload = json.loads(base64.urlsafe_b64decode(padded.encode()).decode("utf-8"))

            exp = payload.get("exp", 0)
            if datetime.datetime.now(datetime.timezone.utc).timestamp() > exp:
                return None  # Token expirado

            return payload if isinstance(payload, dict) else None
        except Exception as e:
            logger.debug("Error decodificando JWT: %s", e)
            return None


class TenancyManager:
    """Base de datos y lógica de control de organizaciones, miembros y credenciales."""

    def __init__(self, db_path: Optional[str] = None) -> None:
        if db_path is None:
            reports_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "reports")
            os.makedirs(reports_dir, exist_ok=True)
            self.db_path = os.path.join(reports_dir, "tenancy.db")
        else:
            self.db_path = db_path
            os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)

        self._lock = threading.Lock()
        self.jwt = JWTManager()
        self._init_db()

    @contextlib.contextmanager
    def _connection(self) -> Generator[sqlite3.Connection, None, None]:
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        try:
            yield conn
        finally:
            conn.close()

    def _init_db(self) -> None:
        with self._lock, self._connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS organizations (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    slug TEXT UNIQUE NOT NULL,
                    tier TEXT NOT NULL DEFAULT 'enterprise',
                    created_at TEXT NOT NULL,
                    max_scans_monthly INTEGER NOT NULL DEFAULT 1000
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY,
                    org_id TEXT NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    full_name TEXT NOT NULL,
                    role TEXT NOT NULL DEFAULT 'developer',
                    is_active INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (org_id) REFERENCES organizations (id)
                )
            """)
            conn.commit()

        # Asegurar organización y usuario default para retrocompatibilidad local
        self._seed_default_tenant()

    def _seed_default_tenant(self) -> None:
        default_org_id = "org_default"
        default_user_id = "user_default_admin"

        with self._lock, self._connection() as conn:
            row_org = conn.execute("SELECT id FROM organizations WHERE id = ?", (default_org_id,)).fetchone()
            if not row_org:
                now_str = datetime.datetime.now(datetime.timezone.utc).isoformat()
                conn.execute(
                    "INSERT INTO organizations (id, name, slug, tier, created_at, max_scans_monthly) VALUES (?, ?, ?, ?, ?, ?)",
                    (default_org_id, "Organización Principal", "default-org", "enterprise", now_str, 999999),
                )

            row_user = conn.execute("SELECT id FROM users WHERE id = ?", (default_user_id,)).fetchone()
            if not row_user:
                now_str = datetime.datetime.now(datetime.timezone.utc).isoformat()
                pw_hash = PasswordHasher.hash_password("admin_vulnscanner_2026")
                conn.execute(
                    "INSERT INTO users (id, org_id, email, password_hash, full_name, role, is_active, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (default_user_id, default_org_id, "admin@vulnscanner.local", pw_hash, "SecOps Admin", Role.ADMIN.value, 1, now_str),
                )
            conn.commit()

    def create_organization(self, name: str, slug: Optional[str] = None, tier: str = "enterprise") -> Organization:
        clean_slug = slug or name.lower().replace(" ", "-").replace("_", "-")
        org_id = f"org_{secrets.token_hex(6)}"

        with self._lock, self._connection() as conn:
            existing = conn.execute("SELECT * FROM organizations WHERE slug = ?", (clean_slug,)).fetchone()
            if existing:
                return Organization(
                    id=existing["id"],
                    name=existing["name"],
                    slug=existing["slug"],
                    tier=existing["tier"],
                    created_at=existing["created_at"],
                    max_scans_monthly=existing["max_scans_monthly"],
                )

            org = Organization(id=org_id, name=name, slug=clean_slug, tier=tier)
            conn.execute(
                "INSERT INTO organizations (id, name, slug, tier, created_at, max_scans_monthly) VALUES (?, ?, ?, ?, ?, ?)",
                (org.id, org.name, org.slug, org.tier, org.created_at, org.max_scans_monthly),
            )
            conn.commit()

        logger.info("[TENANCY] Organización creada: %s (%s)", org.name, org.id)
        return org

    def get_organization(self, org_id: str) -> Optional[Organization]:
        with self._lock, self._connection() as conn:
            row = conn.execute("SELECT * FROM organizations WHERE id = ?", (org_id,)).fetchone()
            if not row:
                return None
            return Organization(
                id=row["id"],
                name=row["name"],
                slug=row["slug"],
                tier=row["tier"],
                created_at=row["created_at"],
                max_scans_monthly=row["max_scans_monthly"],
            )

    def register_user(
        self,
        org_id: str,
        email: str,
        password: str,
        full_name: str,
        role: Role = Role.DEVELOPER,
    ) -> User:
        clean_email = email.strip().lower()

        with self._lock, self._connection() as conn:
            existing = conn.execute("SELECT * FROM users WHERE email = ?", (clean_email,)).fetchone()
            if existing:
                return User(
                    id=existing["id"],
                    org_id=existing["org_id"],
                    email=existing["email"],
                    password_hash=existing["password_hash"],
                    full_name=existing["full_name"],
                    role=Role(existing["role"]),
                    is_active=bool(existing["is_active"]),
                    created_at=existing["created_at"],
                )

            user_id = f"usr_{secrets.token_hex(6)}"
            pw_hash = PasswordHasher.hash_password(password)
            user = User(
                id=user_id,
                org_id=org_id,
                email=clean_email,
                password_hash=pw_hash,
                full_name=full_name,
                role=role,
            )
            conn.execute(
                "INSERT INTO users (id, org_id, email, password_hash, full_name, role, is_active, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (user.id, user.org_id, user.email, user.password_hash, user.full_name, user.role.value, 1, user.created_at),
            )
            conn.commit()

        logger.info("[TENANCY] Usuario registrado: %s (%s) en Org: %s con Rol: %s", user.email, user.id, org_id, role.value)
        return user

    def authenticate_user(self, email: str, password: str) -> Optional[tuple[User, str]]:
        clean_email = email.strip().lower()
        with self._lock, self._connection() as conn:
            row = conn.execute("SELECT * FROM users WHERE email = ? AND is_active = 1", (clean_email,)).fetchone()
            if not row:
                return None

            if not PasswordHasher.verify_password(password, row["password_hash"]):
                return None

            user = User(
                id=row["id"],
                org_id=row["org_id"],
                email=row["email"],
                password_hash=row["password_hash"],
                full_name=row["full_name"],
                role=Role(row["role"]),
                is_active=bool(row["is_active"]),
                created_at=row["created_at"],
            )
            token = self.jwt.create_token(user)
            return user, token

    def get_user(self, user_id: str) -> Optional[User]:
        with self._lock, self._connection() as conn:
            row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
            if not row:
                return None
            return User(
                id=row["id"],
                org_id=row["org_id"],
                email=row["email"],
                password_hash=row["password_hash"],
                full_name=row["full_name"],
                role=Role(row["role"]),
                is_active=bool(row["is_active"]),
                created_at=row["created_at"],
            )

    def get_user_from_token(self, token: str) -> Optional[User]:
        payload = self.jwt.decode_token(token)
        if not payload or "sub" not in payload:
            return None
        return self.get_user(payload["sub"])

    def get_default_user(self) -> User:
        user = self.get_user("user_default_admin")
        if user:
            return user
        # Fallback de seguridad si fue limpiado
        return User(
            id="user_default_admin",
            org_id="org_default",
            email="admin@vulnscanner.local",
            password_hash="",
            full_name="SecOps Admin",
            role=Role.ADMIN,
        )

    def list_users_in_org(self, org_id: str) -> list[User]:
        with self._lock, self._connection() as conn:
            rows = conn.execute("SELECT * FROM users WHERE org_id = ?", (org_id,)).fetchall()
            return [
                User(
                    id=r["id"],
                    org_id=r["org_id"],
                    email=r["email"],
                    password_hash=r["password_hash"],
                    full_name=r["full_name"],
                    role=Role(r["role"]),
                    is_active=bool(r["is_active"]),
                    created_at=r["created_at"],
                )
                for r in rows
            ]
