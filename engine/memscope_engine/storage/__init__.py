"""SQLite access layer."""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from memscope_engine.storage.schema import MIGRATIONS, SCHEMA_VERSION


class Database:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._conn.execute("PRAGMA journal_mode = WAL")
        self.migrate()

    def close(self) -> None:
        self._conn.close()

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        try:
            yield self._conn
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise

    def execute(self, sql: str, params: tuple[Any, ...] | list[Any] = ()) -> sqlite3.Cursor:
        return self._conn.execute(sql, params)

    def executemany(self, sql: str, seq: list[tuple[Any, ...]]) -> sqlite3.Cursor:
        return self._conn.executemany(sql, seq)

    def fetchone(self, sql: str, params: tuple[Any, ...] | list[Any] = ()) -> dict[str, Any] | None:
        row = self._conn.execute(sql, params).fetchone()
        return dict(row) if row else None

    def fetchall(self, sql: str, params: tuple[Any, ...] | list[Any] = ()) -> list[dict[str, Any]]:
        rows = self._conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]

    def migrate(self) -> None:
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS schema_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
        )
        row = self._conn.execute(
            "SELECT value FROM schema_meta WHERE key = 'schema_version'"
        ).fetchone()
        current = int(row["value"]) if row else 0
        for version in range(current + 1, SCHEMA_VERSION + 1):
            sql = MIGRATIONS.get(version)
            if not sql:
                raise RuntimeError(f"Missing migration for schema version {version}")
            self._conn.executescript(sql)
            self._conn.execute(
                "INSERT INTO schema_meta(key, value) VALUES('schema_version', ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (str(version),),
            )
            self._conn.commit()

    def schema_version(self) -> int:
        row = self.fetchone(
            "SELECT value FROM schema_meta WHERE key = 'schema_version'"
        )
        return int(row["value"]) if row else 0
