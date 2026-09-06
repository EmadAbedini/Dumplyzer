"""SQLite schema migrations for MemScope metadata (not memory images)."""

from __future__ import annotations

SCHEMA_VERSION = 7

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
    """,
    2: """
    ALTER TABLE jobs ADD COLUMN process_id TEXT;
    ALTER TABLE jobs ADD COLUMN pid INTEGER;
    ALTER TABLE jobs ADD COLUMN analysis_run_id TEXT;
    ALTER TABLE jobs ADD COLUMN params_json TEXT NOT NULL DEFAULT '{}';
    ALTER TABLE jobs ADD COLUMN cancel_requested INTEGER NOT NULL DEFAULT 0;

    ALTER TABLE analysis_runs ADD COLUMN process_id TEXT;
    ALTER TABLE analysis_runs ADD COLUMN pid INTEGER;
    ALTER TABLE analysis_runs ADD COLUMN job_id TEXT;
    ALTER TABLE analysis_runs ADD COLUMN strategy_json TEXT NOT NULL DEFAULT '[]';

    CREATE TABLE IF NOT EXISTS modules (
      id TEXT PRIMARY KEY,
      evidence_id TEXT NOT NULL REFERENCES evidence(id) ON DELETE CASCADE,
      analysis_run_id TEXT NOT NULL REFERENCES analysis_runs(id) ON DELETE CASCADE,
      process_id TEXT REFERENCES processes(id) ON DELETE SET NULL,
      pid INTEGER NOT NULL,
      name TEXT,
      path TEXT,
      base_address TEXT,
      size TEXT,
      load_count INTEGER,
      load_time TEXT,
      source_plugin TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_modules_evidence_pid ON modules(evidence_id, pid);

    CREATE TABLE IF NOT EXISTS network_connections (
      id TEXT PRIMARY KEY,
      evidence_id TEXT NOT NULL REFERENCES evidence(id) ON DELETE CASCADE,
      analysis_run_id TEXT NOT NULL REFERENCES analysis_runs(id) ON DELETE CASCADE,
      process_id TEXT REFERENCES processes(id) ON DELETE SET NULL,
      pid INTEGER,
      protocol TEXT,
      local_address TEXT,
      local_port INTEGER,
      remote_address TEXT,
      remote_port INTEGER,
      state TEXT,
      owner TEXT,
      created TEXT,
      offset_hex TEXT,
      source_plugin TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_net_evidence_pid ON network_connections(evidence_id, pid);

    CREATE TABLE IF NOT EXISTS handle_entries (
      id TEXT PRIMARY KEY,
      evidence_id TEXT NOT NULL REFERENCES evidence(id) ON DELETE CASCADE,
      analysis_run_id TEXT NOT NULL REFERENCES analysis_runs(id) ON DELETE CASCADE,
      process_id TEXT REFERENCES processes(id) ON DELETE SET NULL,
      pid INTEGER NOT NULL,
      offset_hex TEXT,
      handle_value TEXT,
      handle_type TEXT,
      granted_access TEXT,
      name TEXT,
      source_plugin TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_handles_evidence_pid ON handle_entries(evidence_id, pid);

    CREATE TABLE IF NOT EXISTS memory_regions (
      id TEXT PRIMARY KEY,
      evidence_id TEXT NOT NULL REFERENCES evidence(id) ON DELETE CASCADE,
      analysis_run_id TEXT NOT NULL REFERENCES analysis_runs(id) ON DELETE CASCADE,
      process_id TEXT REFERENCES processes(id) ON DELETE SET NULL,
      pid INTEGER NOT NULL,
      process_name TEXT,
      offset_hex TEXT,
      start_vpn TEXT,
      end_vpn TEXT,
      tag TEXT,
      protection TEXT,
      commit_charge INTEGER,
      private_memory INTEGER,
      parent TEXT,
      file_path TEXT,
      source_plugin TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_vad_evidence_pid ON memory_regions(evidence_id, pid);

    CREATE TABLE IF NOT EXISTS findings (
      id TEXT PRIMARY KEY,
      evidence_id TEXT NOT NULL REFERENCES evidence(id) ON DELETE CASCADE,
      analysis_run_id TEXT,
      process_id TEXT,
      pid INTEGER,
      finding_type TEXT NOT NULL,
      severity TEXT NOT NULL,
      explanation TEXT NOT NULL,
      field_name TEXT,
      field_value TEXT,
      plugin TEXT,
      confidence TEXT,
      created_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_findings_evidence ON findings(evidence_id);
    CREATE INDEX IF NOT EXISTS idx_findings_pid ON findings(evidence_id, pid);
    """,
    3: """
    CREATE TABLE IF NOT EXISTS iocs (
      id TEXT PRIMARY KEY,
      evidence_id TEXT NOT NULL REFERENCES evidence(id) ON DELETE CASCADE,
      process_id TEXT,
      pid INTEGER,
      ioc_type TEXT NOT NULL,
      value TEXT NOT NULL,
      context TEXT,
      source TEXT,
      created_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_iocs_evidence ON iocs(evidence_id);
    CREATE INDEX IF NOT EXISTS idx_iocs_type ON iocs(evidence_id, ioc_type);
    CREATE INDEX IF NOT EXISTS idx_iocs_value ON iocs(evidence_id, value);
    """,
    4: """
    ALTER TABLE memory_regions ADD COLUMN size_bytes INTEGER;
    ALTER TABLE memory_regions ADD COLUMN indicators_json TEXT NOT NULL DEFAULT '[]';

    CREATE TABLE IF NOT EXISTS artifacts (
      id TEXT PRIMARY KEY,
      evidence_id TEXT NOT NULL REFERENCES evidence(id) ON DELETE CASCADE,
      process_id TEXT,
      pid INTEGER,
      memory_region_id TEXT,
      filename TEXT NOT NULL,
      stored_path TEXT NOT NULL,
      sha256 TEXT NOT NULL,
      size_bytes INTEGER NOT NULL,
      file_type TEXT,
      extraction_method TEXT NOT NULL,
      source_plugin TEXT,
      tool_name TEXT,
      tool_version TEXT,
      source_address TEXT,
      start_vpn TEXT,
      end_vpn TEXT,
      extracted_at TEXT NOT NULL,
      notes TEXT,
      metadata_json TEXT NOT NULL DEFAULT '{}'
    );
    CREATE INDEX IF NOT EXISTS idx_artifacts_evidence ON artifacts(evidence_id);
    CREATE INDEX IF NOT EXISTS idx_artifacts_sha ON artifacts(sha256);
    CREATE INDEX IF NOT EXISTS idx_artifacts_process ON artifacts(evidence_id, pid);

    CREATE TABLE IF NOT EXISTS timeline_events (
      id TEXT PRIMARY KEY,
      evidence_id TEXT NOT NULL REFERENCES evidence(id) ON DELETE CASCADE,
      event_time TEXT,
      time_precision TEXT NOT NULL DEFAULT 'unknown',
      classification TEXT NOT NULL,
      event_kind TEXT NOT NULL,
      summary TEXT NOT NULL,
      process_id TEXT,
      pid INTEGER,
      related_entity_type TEXT,
      related_entity_id TEXT,
      source_table TEXT,
      source_plugin TEXT,
      provenance_json TEXT NOT NULL DEFAULT '{}',
      created_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_timeline_evidence_time ON timeline_events(evidence_id, event_time);
    CREATE INDEX IF NOT EXISTS idx_timeline_kind ON timeline_events(evidence_id, event_kind);
    """,
    5: """
    CREATE TABLE IF NOT EXISTS yara_scans (
      id TEXT PRIMARY KEY,
      evidence_id TEXT NOT NULL REFERENCES evidence(id) ON DELETE CASCADE,
      artifact_id TEXT NOT NULL REFERENCES artifacts(id) ON DELETE CASCADE,
      process_id TEXT,
      pid INTEGER,
      memory_region_id TEXT,
      analysis_run_id TEXT,
      job_id TEXT,
      status TEXT NOT NULL,
      match_count INTEGER NOT NULL DEFAULT 0,
      yara_version TEXT,
      ruleset_json TEXT NOT NULL DEFAULT '{}',
      error_json TEXT,
      started_at TEXT NOT NULL,
      finished_at TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_yara_scans_artifact ON yara_scans(artifact_id);
    CREATE INDEX IF NOT EXISTS idx_yara_scans_evidence ON yara_scans(evidence_id);

    CREATE TABLE IF NOT EXISTS yara_matches (
      id TEXT PRIMARY KEY,
      scan_id TEXT NOT NULL REFERENCES yara_scans(id) ON DELETE CASCADE,
      evidence_id TEXT NOT NULL REFERENCES evidence(id) ON DELETE CASCADE,
      artifact_id TEXT NOT NULL REFERENCES artifacts(id) ON DELETE CASCADE,
      process_id TEXT,
      pid INTEGER,
      memory_region_id TEXT,
      rule_name TEXT NOT NULL,
      namespace TEXT,
      rule_source TEXT,
      tags_json TEXT NOT NULL DEFAULT '[]',
      meta_json TEXT NOT NULL DEFAULT '{}',
      strings_json TEXT NOT NULL DEFAULT '[]',
      created_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_yara_matches_scan ON yara_matches(scan_id);
    CREATE INDEX IF NOT EXISTS idx_yara_matches_artifact ON yara_matches(artifact_id);
    CREATE INDEX IF NOT EXISTS idx_yara_matches_rule ON yara_matches(evidence_id, rule_name);

    CREATE TABLE IF NOT EXISTS app_settings (
      key TEXT PRIMARY KEY,
      value_json TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );
    """,
    6: """
    ALTER TABLE artifacts ADD COLUMN parent_artifact_id TEXT;

    CREATE TABLE IF NOT EXISTS pe_sieve_scans (
      id TEXT PRIMARY KEY,
      evidence_id TEXT REFERENCES evidence(id) ON DELETE CASCADE,
      artifact_id TEXT REFERENCES artifacts(id) ON DELETE SET NULL,
      process_id TEXT,
      pid INTEGER,
      memory_region_id TEXT,
      analysis_run_id TEXT,
      job_id TEXT,
      status TEXT NOT NULL,
      ui_state TEXT NOT NULL,
      target_kind TEXT NOT NULL,
      live_pid INTEGER,
      pe_sieve_version TEXT,
      executable_path TEXT,
      output_dir TEXT,
      exit_code INTEGER,
      pesieve_result TEXT,
      observed_json TEXT NOT NULL DEFAULT '{}',
      interpretation_json TEXT NOT NULL DEFAULT '{}',
      error_json TEXT,
      started_at TEXT NOT NULL,
      finished_at TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_pe_sieve_scans_artifact ON pe_sieve_scans(artifact_id);
    CREATE INDEX IF NOT EXISTS idx_pe_sieve_scans_evidence ON pe_sieve_scans(evidence_id);

    CREATE TABLE IF NOT EXISTS pe_sieve_outputs (
      id TEXT PRIMARY KEY,
      scan_id TEXT NOT NULL REFERENCES pe_sieve_scans(id) ON DELETE CASCADE,
      artifact_id TEXT NOT NULL REFERENCES artifacts(id) ON DELETE CASCADE,
      evidence_id TEXT,
      dump_file TEXT,
      dump_mode TEXT,
      module_base TEXT,
      is_shellcode INTEGER,
      role TEXT NOT NULL,
      observed_json TEXT NOT NULL DEFAULT '{}',
      created_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_pe_sieve_outputs_scan ON pe_sieve_outputs(scan_id);
    """,
    7: """
    CREATE TABLE IF NOT EXISTS mal_unpack_scans (
      id TEXT PRIMARY KEY,
      evidence_id TEXT REFERENCES evidence(id) ON DELETE CASCADE,
      artifact_id TEXT REFERENCES artifacts(id) ON DELETE SET NULL,
      process_id TEXT,
      pid INTEGER,
      memory_region_id TEXT,
      analysis_run_id TEXT,
      job_id TEXT,
      status TEXT NOT NULL,
      ui_state TEXT NOT NULL,
      target_kind TEXT NOT NULL,
      mal_unpack_version TEXT,
      executable_path TEXT,
      output_dir TEXT,
      exit_code INTEGER,
      unpack_result TEXT,
      invoked INTEGER NOT NULL DEFAULT 0,
      observed_json TEXT NOT NULL DEFAULT '{}',
      interpretation_json TEXT NOT NULL DEFAULT '{}',
      error_json TEXT,
      started_at TEXT NOT NULL,
      finished_at TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_mal_unpack_scans_artifact ON mal_unpack_scans(artifact_id);
    CREATE INDEX IF NOT EXISTS idx_mal_unpack_scans_evidence ON mal_unpack_scans(evidence_id);

    CREATE TABLE IF NOT EXISTS mal_unpack_outputs (
      id TEXT PRIMARY KEY,
      scan_id TEXT NOT NULL REFERENCES mal_unpack_scans(id) ON DELETE CASCADE,
      artifact_id TEXT NOT NULL REFERENCES artifacts(id) ON DELETE CASCADE,
      evidence_id TEXT,
      dump_file TEXT,
      dump_mode TEXT,
      module_base TEXT,
      is_shellcode INTEGER,
      role TEXT NOT NULL,
      observed_json TEXT NOT NULL DEFAULT '{}',
      created_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_mal_unpack_outputs_scan ON mal_unpack_outputs(scan_id);
    """,
}
