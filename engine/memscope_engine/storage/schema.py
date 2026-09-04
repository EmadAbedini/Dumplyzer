"""SQLite schema version 1 for MemScope metadata (not memory images)."""

from __future__ import annotations

SCHEMA_VERSION = 1

MIGRATIONS: dict[int, str] = {
    1: """
    CREATE TABLE IF NOT EXISTS schema_meta (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS evidence (
      id TEXT PRIMARY KEY,
      path TEXT NOT NULL,
      filename TEXT NOT NULL,
      size_bytes INTEGER NOT NULL,
      sha256 TEXT NOT NULL,
      detected_os TEXT,
      architecture TEXT,
      volatility_compatible INTEGER,
      symbol_status TEXT NOT NULL DEFAULT 'unknown',
      symbol_detail TEXT,
      import_status TEXT NOT NULL DEFAULT 'imported',
      import_timestamp TEXT NOT NULL,
      metadata_json TEXT NOT NULL DEFAULT '{}',
      UNIQUE(sha256)
    );

    CREATE TABLE IF NOT EXISTS analysis_runs (
      id TEXT PRIMARY KEY,
      evidence_id TEXT NOT NULL REFERENCES evidence(id) ON DELETE CASCADE,
      kind TEXT NOT NULL,
      status TEXT NOT NULL,
      started_at TEXT NOT NULL,
      finished_at TEXT,
      error_json TEXT,
      volatility_version TEXT,
      schema_version INTEGER NOT NULL,
      notes TEXT
    );

    CREATE TABLE IF NOT EXISTS plugin_executions (
      id TEXT PRIMARY KEY,
      analysis_run_id TEXT NOT NULL REFERENCES analysis_runs(id) ON DELETE CASCADE,
      evidence_id TEXT NOT NULL REFERENCES evidence(id) ON DELETE CASCADE,
      plugin TEXT NOT NULL,
      parameters_json TEXT NOT NULL DEFAULT '{}',
      status TEXT NOT NULL,
      started_at TEXT NOT NULL,
      finished_at TEXT,
      error_json TEXT,
      row_count INTEGER,
      transparency_json TEXT NOT NULL DEFAULT '{}'
    );

    CREATE TABLE IF NOT EXISTS processes (
      id TEXT PRIMARY KEY,
      evidence_id TEXT NOT NULL REFERENCES evidence(id) ON DELETE CASCADE,
      analysis_run_id TEXT NOT NULL REFERENCES analysis_runs(id) ON DELETE CASCADE,
      pid INTEGER NOT NULL,
      ppid INTEGER,
      name TEXT,
      username TEXT,
      image_path TEXT,
      command_line TEXT,
      create_time TEXT,
      exit_time TEXT,
      offset_hex TEXT,
      threads INTEGER,
      handles INTEGER,
      session_id INTEGER,
      wow64 INTEGER,
      source_plugin TEXT NOT NULL,
      UNIQUE(evidence_id, analysis_run_id, pid, offset_hex)
    );

    CREATE INDEX IF NOT EXISTS idx_processes_evidence ON processes(evidence_id);
    CREATE INDEX IF NOT EXISTS idx_processes_pid ON processes(evidence_id, pid);
    CREATE INDEX IF NOT EXISTS idx_processes_name ON processes(evidence_id, name);

    CREATE TABLE IF NOT EXISTS jobs (
      id TEXT PRIMARY KEY,
      kind TEXT NOT NULL,
      status TEXT NOT NULL,
      evidence_id TEXT,
      created_at TEXT NOT NULL,
      started_at TEXT,
      finished_at TEXT,
      progress_kind TEXT NOT NULL DEFAULT 'indeterminate',
      message TEXT,
      error_json TEXT,
      result_json TEXT
    );
    """
}
