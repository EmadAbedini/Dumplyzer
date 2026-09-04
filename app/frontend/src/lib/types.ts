export type AppErrorPayload = {
  message: string;
  app_code?: string;
  details?: string;
  suggestion?: string;
  entity?: string;
  raw?: string;
};

export type Evidence = {
  id: string;
  path: string;
  filename: string;
  size_bytes: number;
  sha256: string;
  detected_os: string | null;
  architecture: string | null;
  volatility_compatible: boolean | null;
  symbol_status: string | null;
  symbol_detail: string | null;
  import_status: string | null;
  import_timestamp: string | null;
  metadata?: Record<string, unknown>;
};

export type ProcessRow = {
  id: string;
  evidence_id: string;
  analysis_run_id: string;
  pid: number;
  ppid: number | null;
  name: string | null;
  username: string | null;
  image_path: string | null;
  command_line: string | null;
  create_time: string | null;
  exit_time: string | null;
  offset_hex: string | null;
  threads: number | null;
  handles: number | null;
  session_id: number | null;
  wow64: boolean | null;
  source_plugin: string | null;
};

export type Overview = {
  evidence: Evidence;
  process_count: number;
  network_count: number;
  module_count: number;
  finding_count: number;
  ioc_count: number;
  recent_runs: Array<Record<string, unknown>>;
};

export type NavId =
  | "overview"
  | "processes"
  | "network"
  | "modules"
  | "memory"
  | "findings"
  | "iocs"
  | "timeline"
  | "artifacts"
  | "jobs"
  | "plugins"
  | "settings";
