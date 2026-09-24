"""
Ejecutor de Migraciones Versionadas para SQLite y PostgreSQL (Migration Runner).

Garantiza la evolución controlada del esquema de base de datos tanto en entornos
locales de pruebas (SQLite) como en entornos Cloud (PostgreSQL / Neon) con
registro transaccional en la tabla 'schema_migrations'.
"""
from __future__ import annotations

import datetime
import logging
import re
from pathlib import Path

from scanner.db_adapter import UniversalConnection

logger = logging.getLogger("OmniBreach.Migrations")


class MigrationManager:
    """Gestiona el descubrimiento, validación y aplicación de migraciones SQL versionadas."""

    def __init__(self, connection: UniversalConnection, migrations_dir: str | Path | None = None) -> None:
        self.conn = connection
        if migrations_dir is None:
            self.migrations_dir = Path(__file__).parent
        else:
            self.migrations_dir = Path(migrations_dir)

    def init_migration_table(self) -> None:
        """Crea la tabla de control de versiones de esquema si no existe."""
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                applied_at TEXT NOT NULL
            )
        """)
        self.conn.commit()

    def get_applied_versions(self) -> set[int]:
        """Obtiene el conjunto de versiones de migración ya aplicadas."""
        self.init_migration_table()
        rows = self.conn.execute("SELECT version FROM schema_migrations ORDER BY version ASC").fetchall()
        applied: set[int] = set()
        for r in rows:
            val = r[0] if isinstance(r, (tuple, list)) else r["version"]
            applied.add(int(val))
        return applied

    def discover_migrations(self) -> list[tuple[int, str, Path]]:
        """Descubre archivos .sql con formato 'XXX_nombre.sql' ordenados por versión."""
        pattern = re.compile(r"^(\d+)_([a-zA-Z0-9_-]+)\.sql$")
        migrations: list[tuple[int, str, Path]] = []

        if not self.migrations_dir.exists():
            return migrations

        for p in self.migrations_dir.glob("*.sql"):
            match = pattern.match(p.name)
            if match:
                version = int(match.group(1))
                name = match.group(2)
                migrations.append((version, name, p))

        return sorted(migrations, key=lambda x: x[0])

    def apply_pending_migrations(self) -> list[int]:
        """Ejecuta todas las migraciones pendientes en orden secuencial."""
        applied_versions = self.get_applied_versions()
        discovered = self.discover_migrations()
        newly_applied: list[int] = []

        for version, name, file_path in discovered:
            if version in applied_versions:
                continue

            logger.info("[MIGRATION] Aplicando versión %03d: %s...", version, name)
            with open(file_path, encoding="utf-8") as f:
                sql_content = f.read()

            # Separar sentencias SQL individuales
            statements = [stmt.strip() for stmt in sql_content.split(";") if stmt.strip()]

            try:
                for stmt in statements:
                    self.conn.execute(stmt)

                now_str = datetime.datetime.now(datetime.timezone.utc).isoformat()
                self.conn.execute(
                    "INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)",
                    (version, name, now_str),
                )
                self.conn.commit()
                newly_applied.append(version)
                logger.info("[MIGRATION] Versión %03d (%s) aplicada exitosamente.", version, name)
            except Exception as err:
                self.conn.rollback()
                logger.error("[MIGRATION ERROR] Fallo aplicando versión %03d (%s): %s", version, name, err)
                raise RuntimeError(f"Error en migración {version} ({name}): {err}") from err

        return newly_applied
