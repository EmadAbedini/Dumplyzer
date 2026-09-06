"""File-backed analysis cache indexed in SQLite.

Cache key includes evidence SHA-256, Volatility version, plugin id,
canonical parameters, and MemScope schema version.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from memscope_engine.paths import AppPaths
from memscope_engine.storage import Database
from memscope_engine.storage.schema import SCHEMA_VERSION


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def canonical_params(params: dict[str, Any] | None) -> dict[str, Any]:
    """Stable, JSON-serializable parameter dict (sorted keys, no Nones)."""
    out: dict[str, Any] = {}
    for key in sorted((params or {}).keys()):
        val = (params or {})[key]
        if val is None:
            continue
        if isinstance(val, dict):
            out[key] = canonical_params(val)
        elif isinstance(val, list):
            out[key] = [canonical_params(x) if isinstance(x, dict) else x for x in val]
        else:
            out[key] = val
    return out


def cache_key(
    *,
    evidence_sha256: str,
    volatility_version: str,
    plugin_id: str,
    parameters: dict[str, Any] | None,
    schema_version: int = SCHEMA_VERSION,
    model_version: int = 1,
) -> str:
    payload = {
        "evidence_sha256": evidence_sha256.lower(),
        "volatility_version": str(volatility_version),
        "plugin_id": plugin_id,
        "parameters": canonical_params(parameters),
        "schema_version": int(schema_version),
        "result_model_version": int(model_version),
    }
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


class AnalysisCache:
    def __init__(self, db: Database, paths: AppPaths) -> None:
        self.db = db
        self.paths = paths
        (self.paths.cache / "plugin_results").mkdir(parents=True, exist_ok=True)

    def result_path_for(self, key: str) -> Path:
        safe = "".join(c for c in key if c.isalnum())
        return self.paths.cache / "plugin_results" / f"{safe}.json"

    def get(self, key: str) -> dict[str, Any] | None:
        row = self.db.fetchone("SELECT * FROM analysis_cache WHERE cache_key = ?", (key,))
        if not row:
            return None
        path = Path(row["result_path"]) if row.get("result_path") else self.result_path_for(key)
        if not path.is_file():
            self.db.execute("DELETE FROM analysis_cache WHERE cache_key = ?", (key,))
            return None
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        if not isinstance(payload, dict):
            return None
        return {
            "entry": dict(row),
            "payload": payload,
            "result_path": str(path),
        }

    def put(
        self,
        *,
        key: str,
        evidence_id: str,
        evidence_sha256: str,
        volatility_version: str,
        plugin_id: str,
        parameters: dict[str, Any],
        payload: dict[str, Any],
        analysis_run_id: str | None = None,
        plugin_execution_id: str | None = None,
    ) -> dict[str, Any]:
        path = self.result_path_for(key)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, default=str), encoding="utf-8")
        row_count = int((payload.get("table") or {}).get("row_count") or 0)
        now = _utcnow()
        existing = self.db.fetchone("SELECT id FROM analysis_cache WHERE cache_key = ?", (key,))
        if existing:
            self.db.execute(
                """
                UPDATE analysis_cache SET evidence_id=?, evidence_sha256=?, volatility_version=?,
                  plugin_id=?, parameters_json=?, schema_version=?, result_path=?, row_count=?,
                  analysis_run_id=?, plugin_execution_id=?, created_at=?
                WHERE cache_key=?
                """,
                (
                    evidence_id,
                    evidence_sha256,
                    volatility_version,
                    plugin_id,
                    json.dumps(canonical_params(parameters)),
                    SCHEMA_VERSION,
                    str(path),
                    row_count,
                    analysis_run_id,
                    plugin_execution_id,
                    now,
                    key,
                ),
            )
            cache_id = existing["id"]
        else:
            cache_id = str(uuid4())
            self.db.execute(
                """
                INSERT INTO analysis_cache (
                  id, cache_key, evidence_id, evidence_sha256, volatility_version, plugin_id,
                  parameters_json, schema_version, result_path, row_count, analysis_run_id,
                  plugin_execution_id, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    cache_id,
                    key,
                    evidence_id,
                    evidence_sha256,
                    volatility_version,
                    plugin_id,
                    json.dumps(canonical_params(parameters)),
                    SCHEMA_VERSION,
                    str(path),
                    row_count,
                    analysis_run_id,
                    plugin_execution_id,
                    now,
                ),
            )
        return {"id": cache_id, "cache_key": key, "result_path": str(path), "row_count": row_count}
