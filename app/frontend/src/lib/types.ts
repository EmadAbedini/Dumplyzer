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

export type ModuleRow = {
  id: string;
  evidence_id: string;
  process_id: string | null;
  pid: number;
  name: string | null;
  path: string | null;
  base_address: string | null;
  size: string | null;
  load_count: number | null;
  load_time: string | null;
  source_plugin: string | null;
};

export type NetworkConnection = {
  id: string;
  evidence_id: string;
  process_id: string | null;
  pid: number | null;
  protocol: string | null;
  local_address: string | null;
  local_port: number | null;
  remote_address: string | null;
  remote_port: number | null;
  state: string | null;
  owner: string | null;
  created: string | null;
  offset_hex: string | null;
  source_plugin: string | null;
};

export type HandleRow = {
  id: string;
  pid: number;
  offset_hex: string | null;
  handle_value: string | null;
  handle_type: string | null;
  granted_access: string | null;
  name: string | null;
  source_plugin: string | null;
};

export type MemoryRegion = {
  id: string;
  evidence_id?: string;
  analysis_run_id?: string | null;
  process_id: string | null;
  pid: number;
  process_name: string | null;
  offset_hex: string | null;
  start_vpn: string | null;
  end_vpn: string | null;
  size_bytes?: number | null;
  tag: string | null;
  protection: string | null;
  commit_charge: number | null;
  private_memory: number | null;
  parent: string | null;
  file_path: string | null;
  source_plugin: string | null;
  indicators?: Array<{ code: string; label: string; detail: string }>;
  indicator_codes?: string[];
};

export type Artifact = {
  id: string;
  evidence_id: string;
  process_id: string | null;
  pid: number | null;
  memory_region_id: string | null;
  filename: string;
  stored_path: string;
  sha256: string;
  size_bytes: number;
  file_type: string | null;
  extraction_method: string;
  source_plugin: string | null;
  tool_name: string | null;
  tool_version: string | null;
  source_address: string | null;
  start_vpn: string | null;
  end_vpn: string | null;
  extracted_at: string | null;
  notes: string | null;
  metadata?: Record<string, unknown>;
  provenance_chain?: Array<Record<string, unknown>>;
};

export type TimelineEvent = {
  id: string;
  evidence_id: string;
  event_time: string | null;
  time_precision: string;
  classification: string;
  event_kind: string;
  summary: string;
  process_id: string | null;
  pid: number | null;
  related_entity_type: string | null;
  related_entity_id: string | null;
  source_table: string | null;
  source_plugin: string | null;
  provenance?: Record<string, unknown>;
  created_at: string | null;
};

export type Finding = {
  id: string;
  evidence_id: string;
  process_id: string | null;
  pid: number | null;
  finding_type: string;
  severity: string;
  explanation: string;
  field_name: string | null;
  field_value: string | null;
  plugin: string | null;
  confidence: string | null;
  created_at: string | null;
};

export type ProcessDeepDive = {
  process: ProcessRow;
  parent: ProcessRow | null;
  children: ProcessRow[];
  modules: ModuleRow[];
  network: NetworkConnection[];
  handles: HandleRow[];
  memory_regions: MemoryRegion[];
  findings: Finding[];
  analysis_runs: Array<Record<string, unknown>>;
  counts: {
    modules: number;
    network: number;
    handles: number;
    memory_regions: number;
    findings: number;
    children: number;
  };
};

export type Job = {
  id: string;
  kind: string;
  status: string;
  evidence_id: string | null;
  process_id: string | null;
  pid: number | null;
  analysis_run_id: string | null;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  progress_kind: string;
  message: string | null;
  error: Record<string, unknown> | null;
  result: Record<string, unknown> | null;
  params: Record<string, unknown>;
  cancel_requested: boolean;
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
  | "process_dive"
  | "network"
  | "modules"
  | "memory"
  | "findings"
  | "iocs"
  | "search"
  | "timeline"
  | "artifacts"
  | "jobs"
  | "plugins"
  | "settings";

export type SearchHit = {
  entity: string;
  value: string;
  context: string;
  process_id: string | null;
  pid: number | null;
  source: string | null;
  plugin: string | null;
  ref_id: string | null;
};

export type Ioc = {
  id: string;
  evidence_id: string;
  process_id: string | null;
  pid: number | null;
  ioc_type: string;
  value: string;
  context: string | null;
  source: string | null;
  created_at: string | null;
};
