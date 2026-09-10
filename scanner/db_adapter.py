"""
Adaptador de Base de Datos Agnóstico (SQLite / Neon PostgreSQL).
Permite ejecutar OmniBreach tanto en desarrollo local (SQLite sin dependencias externas)
como en entornos Cloud (Neon PostgreSQL / Render) usando DATABASE_URL.
"""
from __future__ import annotations

import contextlib
import logging
import os
import re
import sqlite3
from collections.abc import Sequence
from typing import Any

logger = logging.getLogger("OmniBreach.DB")


class PostgresRowWrapper:
    """Envuelve una fila de PostgreSQL para permitir acceso por nombre de columna como sqlite3.Row."""

    def __init__(self, description: Sequence[Any], values: Sequence[Any]) -> None:
        self._data: dict[str, Any] = {desc[0]: val for desc, val in zip(description, values)}

    def __getitem__(self, item: str | int) -> Any:
        if isinstance(item, int):
            return list(self._data.values())[item]
        return self._data[item]

    def get(self, key: str, default: Any = None) -> Any:
        return self._data.get(key, default)

    def keys(self) -> list[str]:
        return list(self._data.keys())

    def values(self) -> list[Any]:
        return list(self._data.values())

    def items(self) -> list[tuple[str, Any]]:
        return list(self._data.items())

    def __iter__(self) -> Any:
        return iter(self._data)

    def __repr__(self) -> str:
        return repr(self._data)


class UniversalCursor:
    """Cursor que traduce automáticamente marcadores '?' a '%s' si el backend es PostgreSQL."""

    def __init__(self, raw_cursor: Any, is_postgres: bool = False) -> None:
        self.raw = raw_cursor
        self.is_postgres = is_postgres

    def execute(self, sql: str, params: Sequence[Any] = ()) -> UniversalCursor:
        if self.is_postgres:
            sql_pg = sql.replace("?", "%s")
            sql_pg = re.sub(r"\bINTEGER\s+PRIMARY\s+KEY\s+AUTOINCREMENT\b", "SERIAL PRIMARY KEY", sql_pg, flags=re.IGNORECASE)
            sql_pg = re.sub(r"\bPRAGMA\s+[^;]+;?", "", sql_pg, flags=re.IGNORECASE)
            if sql_pg.strip():
                self.raw.execute(sql_pg, tuple(params))
        else:
            self.raw.execute(sql, tuple(params))
        return self

    def fetchone(self) -> Any | None:
        row = self.raw.fetchone()
        if row is None:
            return None
        if self.is_postgres and self.raw.description:
            return PostgresRowWrapper(self.raw.description, row)
        return row

    def fetchall(self) -> list[Any]:
        rows = self.raw.fetchall()
        if self.is_postgres and self.raw.description:
            return [PostgresRowWrapper(self.raw.description, r) for r in rows]
        return list(rows)

    @property
    def rowcount(self) -> int:
        return int(getattr(self.raw, "rowcount", -1))


class UniversalConnection:
    """Conexión universal compatible con la API de sqlite3 y psycopg2."""

    def __init__(self, raw_conn: Any, is_postgres: bool = False) -> None:
        self.raw = raw_conn
        self.is_postgres = is_postgres

    def execute(self, sql: str, params: Sequence[Any] = ()) -> UniversalCursor:
        cursor = UniversalCursor(self.raw.cursor(), is_postgres=self.is_postgres)
        return cursor.execute(sql, params)

    def commit(self) -> None:
        self.raw.commit()

    def rollback(self) -> None:
        self.raw.rollback()

    def close(self) -> None:
        self.raw.close()

    def __enter__(self) -> UniversalConnection:
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        if exc_type:
            self.rollback()
        else:
            self.commit()
        self.close()


def get_db_url() -> str:
    """Obtiene la URL de base de datos desde variables de entorno."""
    return os.environ.get("DATABASE_URL") or os.environ.get("OMNIBREACH_DATABASE_URL") or ""


def create_connection(fallback_sqlite_path: str) -> UniversalConnection:
    """
    Crea una conexión de base de datos universal.
    Si DATABASE_URL está configurado (Neon PostgreSQL), se conecta a PostgreSQL.
    De lo contrario, utiliza SQLite en fallback_sqlite_path.
    """
    db_url = get_db_url().strip()
    if db_url.startswith("postgres://") or db_url.startswith("postgresql://"):
        if db_url.startswith("postgres://"):
            db_url = "postgresql://" + db_url[len("postgres://"):]

        try:
            import psycopg2  # type: ignore[import-untyped]
            conn = psycopg2.connect(db_url)
            logger.info("[DB] Conectado exitosamente a PostgreSQL (Neon Cloud)")
            return UniversalConnection(conn, is_postgres=True)
        except ImportError:
            logger.warning("[DB] DATABASE_URL configurada pero psycopg2 no está instalado. Utilizando SQLite local.")
        except Exception as err:
            logger.error("[DB] Error al conectar a PostgreSQL (%s). Utilizando SQLite local de respaldo.", err)

    os.makedirs(os.path.dirname(os.path.abspath(fallback_sqlite_path)), exist_ok=True)
    sqlite_conn = sqlite3.connect(fallback_sqlite_path, check_same_thread=False)
    sqlite_conn.row_factory = sqlite3.Row
    with contextlib.suppress(sqlite3.Error):
        sqlite_conn.execute("PRAGMA journal_mode=WAL")
    return UniversalConnection(sqlite_conn, is_postgres=False)
