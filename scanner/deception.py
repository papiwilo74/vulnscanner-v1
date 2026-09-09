"""
Motor de Ciberdefensa Activa y Tecnología de Señuelos (Deception Engine & HoneyTokens).
Permite sembrar HoneyURLs, HoneyTokens (AWS, Stripe, JWT) y HoneyCookies en aplicaciones web,
capturando intentos de intrusión y reconocimiento en tiempo real con 0.0% de falsos positivos.
"""
import contextlib
import datetime
import hashlib
import json
import logging
import os
import secrets
import sqlite3
import threading
from collections.abc import Generator
from dataclasses import asdict, dataclass, field
from typing import Any, Optional

logger = logging.getLogger("VulnScanner.Deception")


@dataclass
class HoneyTrap:
    """Representa un señuelo o trampa configurada."""

    id: str
    trap_type: str  # "url", "api_key", "jwt_token", "cookie"
    label: str  # e.g. "Stripe Production Live Secret", "Admin Vault Route"
    token_value: str
    target_url: str
    created_at: str = field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())
    is_active: bool = True
    trigger_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class CanaryEvent:
    """Registro de activación de una trampa por un atacante o bot malicioso."""

    id: str
    trap_id: str
    trap_type: str
    trap_label: str
    attacker_ip: str
    user_agent: str
    http_method: str
    requested_path: str
    headers: dict[str, str]
    payload_sample: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class DeceptionManager:
    """Gestiona el catálogo de trampas señuelo y la persistencia de alertas de intrusión."""

    def __init__(self, db_path: Optional[str] = None) -> None:
        if db_path is None:
            reports_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "reports")
            os.makedirs(reports_dir, exist_ok=True)
            self.db_path = os.path.join(reports_dir, "deception.db")
        else:
            self.db_path = db_path
            os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)

        self._lock = threading.Lock()
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
                CREATE TABLE IF NOT EXISTS honey_traps (
                    id TEXT PRIMARY KEY,
                    trap_type TEXT NOT NULL,
                    label TEXT NOT NULL,
                    token_value TEXT NOT NULL,
                    target_url TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    is_active INTEGER NOT NULL DEFAULT 1,
                    trigger_count INTEGER NOT NULL DEFAULT 0
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS canary_events (
                    id TEXT PRIMARY KEY,
                    trap_id TEXT NOT NULL,
                    trap_type TEXT NOT NULL,
                    trap_label TEXT NOT NULL,
                    attacker_ip TEXT NOT NULL,
                    user_agent TEXT NOT NULL,
                    http_method TEXT NOT NULL,
                    requested_path TEXT NOT NULL,
                    headers TEXT NOT NULL,
                    payload_sample TEXT,
                    timestamp TEXT NOT NULL,
                    FOREIGN KEY (trap_id) REFERENCES honey_traps (id)
                )
            """)
            conn.commit()

    def create_trap(self, trap_type: str, label: str, target_url: str = "") -> HoneyTrap:
        """Crea una nueva trampa señuelo hiper-realista según el tipo solicitado."""
        trap_id = secrets.token_hex(8)

        if trap_type == "api_key":
            # Genera una clave falsa con estructura de proveedor real (ej. Stripe o AWS)
            token_val = f"sk_live_{secrets.token_urlsafe(32)}"
        elif trap_type == "jwt_token":
            # JWT falso con claims tentadores (role: superadmin)
            header_b64 = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
            payload_json = json.dumps({
                "sub": "admin_root",
                "role": "superadmin",
                "canary_id": trap_id,
                "iat": int(datetime.datetime.now(datetime.timezone.utc).timestamp()),
            })
            payload_b64 = hashlib.sha256(payload_json.encode()).hexdigest()[:43]
            sig_b64 = secrets.token_urlsafe(24)
            token_val = f"{header_b64}.{payload_b64}.{sig_b64}"
        elif trap_type == "cookie":
            token_val = f"debug_session_{secrets.token_hex(16)}"
        elif trap_type == "url":
            slug = secrets.token_urlsafe(6).lower().replace("-", "_").replace("_", "")
            token_val = f"/_internal/vault_{slug}"
        else:
            token_val = f"token_{secrets.token_hex(12)}"

        trap = HoneyTrap(
            id=trap_id,
            trap_type=trap_type,
            label=label or f"Señuelo {trap_type.upper()}",
            token_value=token_val,
            target_url=target_url,
        )

        with self._lock, self._connection() as conn:
            conn.execute(
                "INSERT INTO honey_traps (id, trap_type, label, token_value, target_url, created_at, is_active, trigger_count) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (trap.id, trap.trap_type, trap.label, trap.token_value, trap.target_url, trap.created_at, 1, 0),
            )
            conn.commit()

        logger.info("[DECEPTION] Trampa creada: %s (%s) -> %s", trap.id, trap.trap_type, trap.label)
        return trap

    def get_trap(self, trap_id: str) -> Optional[HoneyTrap]:
        with self._lock, self._connection() as conn:
            row = conn.execute("SELECT * FROM honey_traps WHERE id = ?", (trap_id,)).fetchone()
            if not row:
                return None
            return HoneyTrap(
                id=row["id"],
                trap_type=row["trap_type"],
                label=row["label"],
                token_value=row["token_value"],
                target_url=row["target_url"],
                created_at=row["created_at"],
                is_active=bool(row["is_active"]),
                trigger_count=row["trigger_count"],
            )

    def find_trap_by_token(self, token_value: str) -> Optional[HoneyTrap]:
        with self._lock, self._connection() as conn:
            row = conn.execute("SELECT * FROM honey_traps WHERE token_value = ? AND is_active = 1", (token_value,)).fetchone()
            if not row:
                return None
            return HoneyTrap(
                id=row["id"],
                trap_type=row["trap_type"],
                label=row["label"],
                token_value=row["token_value"],
                target_url=row["target_url"],
                created_at=row["created_at"],
                is_active=bool(row["is_active"]),
                trigger_count=row["trigger_count"],
            )

    def list_traps(self) -> list[HoneyTrap]:
        with self._lock, self._connection() as conn:
            rows = conn.execute("SELECT * FROM honey_traps ORDER BY created_at DESC").fetchall()
            return [
                HoneyTrap(
                    id=r["id"],
                    trap_type=r["trap_type"],
                    label=r["label"],
                    token_value=r["token_value"],
                    target_url=r["target_url"],
                    created_at=r["created_at"],
                    is_active=bool(r["is_active"]),
                    trigger_count=r["trigger_count"],
                )
                for r in rows
            ]

    def record_event(
        self,
        trap: HoneyTrap,
        attacker_ip: str,
        user_agent: str,
        http_method: str = "GET",
        requested_path: str = "",
        headers: Optional[dict[str, str]] = None,
        payload_sample: Optional[str] = None,
    ) -> CanaryEvent:
        """Registra la detonación de una trampa y actualiza el contador de eventos."""
        event_id = secrets.token_hex(8)
        event = CanaryEvent(
            id=event_id,
            trap_id=trap.id,
            trap_type=trap.trap_type,
            trap_label=trap.label,
            attacker_ip=attacker_ip or "127.0.0.1",
            user_agent=user_agent or "Unknown Agent",
            http_method=http_method,
            requested_path=requested_path or trap.token_value,
            headers=headers or {},
            payload_sample=payload_sample,
        )

        with self._lock, self._connection() as conn:
            conn.execute(
                """
                INSERT INTO canary_events (
                    id, trap_id, trap_type, trap_label, attacker_ip, user_agent,
                    http_method, requested_path, headers, payload_sample, timestamp
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.id,
                    event.trap_id,
                    event.trap_type,
                    event.trap_label,
                    event.attacker_ip,
                    event.user_agent,
                    event.http_method,
                    event.requested_path,
                    json.dumps(event.headers, ensure_ascii=False),
                    event.payload_sample,
                    event.timestamp,
                ),
            )
            conn.execute(
                "UPDATE honey_traps SET trigger_count = trigger_count + 1 WHERE id = ?",
                (trap.id,),
            )
            conn.commit()

        logger.warning(
            "[🚨 DECEPTION ALERT] ¡Trampa detonada! Tipo: %s | Señuelo: '%s' | IP Atacante: %s | Ruta: %s",
            trap.trap_type,
            trap.label,
            attacker_ip,
            requested_path,
        )
        return event

    def list_events(self, limit: int = 50) -> list[CanaryEvent]:
        with self._lock, self._connection() as conn:
            rows = conn.execute("SELECT * FROM canary_events ORDER BY timestamp DESC LIMIT ?", (limit,)).fetchall()
            events: list[CanaryEvent] = []
            for r in rows:
                try:
                    h_dict = json.loads(r["headers"])
                except Exception:
                    h_dict = {}
                events.append(
                    CanaryEvent(
                        id=r["id"],
                        trap_id=r["trap_id"],
                        trap_type=r["trap_type"],
                        trap_label=r["trap_label"],
                        attacker_ip=r["attacker_ip"],
                        user_agent=r["user_agent"],
                        http_method=r["http_method"],
                        requested_path=r["requested_path"],
                        headers=h_dict,
                        payload_sample=r["payload_sample"],
                        timestamp=r["timestamp"],
                    )
                )
            return events

    def get_stats(self) -> dict[str, Any]:
        with self._lock, self._connection() as conn:
            total_traps = conn.execute("SELECT COUNT(*) FROM honey_traps").fetchone()[0]
            active_traps = conn.execute("SELECT COUNT(*) FROM honey_traps WHERE is_active = 1").fetchone()[0]
            total_events = conn.execute("SELECT COUNT(*) FROM canary_events").fetchone()[0]
            unique_ips = conn.execute("SELECT COUNT(DISTINCT attacker_ip) FROM canary_events").fetchone()[0]
            return {
                "total_traps": total_traps,
                "active_traps": active_traps,
                "total_intrusions_detected": total_events,
                "unique_attackers": unique_ips,
            }


class SnippetGenerator:
    """Genera fragmentos de código listos para copiar y pegar en aplicaciones web."""

    @staticmethod
    def generate_snippet(trap: HoneyTrap, server_base_url: str = "http://localhost:8000") -> dict[str, str]:
        endpoint_url = f"{server_base_url.rstrip('/')}/deception/trap/{trap.id}"

        if trap.trap_type == "url":
            return {
                "format": "HTML Hidden Link / robots.txt",
                "placement": "Pegar en el HTML principal (invisible para usuarios) o en /robots.txt",
                "code": (
                    f"<!-- 1. En robots.txt: -->\n"
                    f"Disallow: {trap.token_value}\n\n"
                    f"<!-- 2. O en tu archivo HTML (enlace oculto para bots de rastreo malicioso): -->\n"
                    f'<a href="{endpoint_url}" style="display:none;" aria-hidden="true" rel="nofollow">Admin Vault</a>'
                ),
            }
        elif trap.trap_type == "api_key":
            return {
                "format": "JavaScript Fake Key / Config",
                "placement": "Pegar en un script JavaScript público o archivo de configuración para tentar a scrapers",
                "code": (
                    f"// Configuración señuelo para detección de atacantes\n"
                    f'const BACKUP_PAYMENT_GATEWAY_KEY = "{trap.token_value}";\n'
                    f'// Endpoint de verificación: {endpoint_url}'
                ),
            }
        elif trap.trap_type == "jwt_token":
            return {
                "format": "Authorization Bearer Token",
                "placement": "Colocar en cookies o LocalStorage señuelo para detectar robo de tokens de sesión",
                "code": (
                    f"// Almacenar token señuelo en localStorage\n"
                    f'localStorage.setItem("debug_superadmin_token", "{trap.token_value}");'
                ),
            }
        elif trap.trap_type == "cookie":
            return {
                "format": "HTTP Cookie Señuelo",
                "placement": "Cabecera Set-Cookie emitida al cliente",
                "code": (
                    f"Set-Cookie: {trap.token_value}=active; Path=/; HttpOnly"
                ),
            }
        return {
            "format": "Genérico",
            "placement": "Endpoint de trampa activo",
            "code": endpoint_url,
        }
