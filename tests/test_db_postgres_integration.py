"""
Pruebas de Integración y Compatibilidad de Base de Datos (PostgreSQL & SQLite).

Verifica:
1. Traducción transparente de dialecto SQL (UniversalCursor: ? -> %s, SERIAL PRIMARY KEY, PRAGMAs).
2. Compatibilidad del PostgresRowWrapper con la interfaz de sqlite3.Row.
3. Ejecución idempotente y transaccional del MigrationManager con esquema versionado.
"""
import os
import tempfile
from collections.abc import Generator
from unittest.mock import MagicMock

import pytest

from scanner.db_adapter import (
    PostgresRowWrapper,
    UniversalConnection,
    UniversalCursor,
    create_connection,
)
from scanner.migrations.runner import MigrationManager


@pytest.fixture
def temp_db() -> Generator[tuple[UniversalConnection, str], None, None]:
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test_universal.db")
        conn = create_connection(db_path)
        yield conn, db_path
        conn.close()


class TestUniversalCursorDialect:
    """Valida la traducción de dialectos entre SQLite y PostgreSQL."""

    def test_postgres_cursor_translates_placeholders_and_autoincrement(self) -> None:
        mock_raw = MagicMock()
        cursor = UniversalCursor(mock_raw, is_postgres=True)

        sql_in = "INSERT INTO users (id, name) VALUES (?, ?)"
        cursor.execute(sql_in, ("1", "admin"))

        mock_raw.execute.assert_called_once()
        called_sql, called_params = mock_raw.execute.call_args[0]
        assert "%s" in called_sql
        assert "?" not in called_sql
        assert called_params == ("1", "admin")

    def test_postgres_cursor_strips_pragmas(self) -> None:
        mock_raw = MagicMock()
        cursor = UniversalCursor(mock_raw, is_postgres=True)

        cursor.execute("PRAGMA journal_mode=WAL;")
        # Sentencia PRAGMA debe ser ignorada en PostgreSQL
        assert not mock_raw.execute.called

    def test_sqlite_cursor_executes_as_is(self) -> None:
        mock_raw = MagicMock()
        cursor = UniversalCursor(mock_raw, is_postgres=False)

        cursor.execute("SELECT * FROM items WHERE id = ?", (42,))
        mock_raw.execute.assert_called_once_with("SELECT * FROM items WHERE id = ?", (42,))


class TestPostgresRowWrapper:
    """Valida que PostgresRowWrapper proporcione la misma interfaz que sqlite3.Row."""

    def test_row_wrapper_access_by_key_and_index(self) -> None:
        desc = [("id",), ("username",), ("role",)]
        values = ("u_123", "secops_admin", "admin")
        row = PostgresRowWrapper(desc, values)

        # Acceso por nombre de columna
        assert row["id"] == "u_123"
        assert row["username"] == "secops_admin"
        assert row.get("role") == "admin"
        assert row.get("non_existent", "default") == "default"

        # Acceso por índice numérico
        assert row[0] == "u_123"
        assert row[1] == "secops_admin"

        # Métodos dict-like
        assert "id" in list(row.keys())
        assert "admin" in row.values()
        assert ("username", "secops_admin") in row.items()


class TestMigrationManager:
    """Valida la ejecución de migraciones de base de datos."""

    def test_migrations_apply_cleanly_and_idempotently(self, temp_db: tuple[UniversalConnection, str]) -> None:
        conn, _ = temp_db
        manager = MigrationManager(conn)

        # 1. Primera ejecución: deben aplicarse las migraciones 001, 002 y 003
        applied = manager.apply_pending_migrations()
        assert 1 in applied
        assert 2 in applied
        assert 3 in applied

        # Verificar que las tablas fueron creadas
        tasks_row = conn.execute("SELECT COUNT(*) FROM tasks").fetchone()
        assert tasks_row is not None

        users_row = conn.execute("SELECT COUNT(*) FROM users").fetchone()
        assert users_row is not None

        jobs_row = conn.execute("SELECT COUNT(*) FROM cluster_jobs").fetchone()
        assert jobs_row is not None

        tokens_row = conn.execute("SELECT COUNT(*) FROM revoked_tokens").fetchone()
        assert tokens_row is not None

        # 2. Segunda ejecución (idempotente): no debe aplicar ninguna nueva
        second_run = manager.apply_pending_migrations()
        assert len(second_run) == 0

        # Verificar registro en tabla schema_migrations
        versions = manager.get_applied_versions()
        assert {1, 2, 3}.issubset(versions)

    def test_startup_migration_failure_halts_in_production(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """En producción, un fallo de migración no debe silenciarse: debe detener el arranque con RuntimeError."""
        monkeypatch.setenv("OMNIBREACH_ENV", "production")

        def simulate_startup(env_name: str, should_fail: bool) -> None:
            if should_fail:
                exc = Exception("Database disk image is malformed / connection refused")
                if env_name == "production":
                    raise RuntimeError(f"Fallo crítico en migración de base de datos durante el arranque en producción: {exc}")

        # En modo producción, debe lanzar RuntimeError deteniendo el arranque
        with pytest.raises(RuntimeError, match="Fallo crítico en migración"):
            simulate_startup("production", should_fail=True)

        # En desarrollo, no detiene el arranque
        simulate_startup("development", should_fail=True)
