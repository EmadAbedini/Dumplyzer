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
  parent_artifact_id?: string | null;
  yara_scans?: YaraScanBundle[];
  yara_status?: YaraStatus;
  pe_sieve_scans?: PeSieveScanBundle[];
  pe_sieve_status?: PeSieveStatus;
  mal_unpack_scans?: MalUnpackScanBundle[];
  mal_unpack_status?: MalUnpackStatus;
};

export type YaraStatus = {
  available: boolean;
  reason?: string | null;
  suggestion?: string | null;
  yara_version?: string | null;
  binding?: string | null;
  provider?: string;
  rule_file_count?: number;
  rule_files?: string[];
  default_rules_dir?: string | null;
  extra_rule_paths?: string[];
  timeout_secs?: number;
};

export type YaraMatch = {
  id: string;
  scan_id: string;
  evidence_id: string;
  artifact_id: string;
  process_id: string | null;
  pid: number | null;
  memory_region_id: string | null;
  rule_name: string;
  namespace: string | null;
  rule_source: string | null;
  tags: string[];
  meta: Record<string, unknown>;
  strings: Array<{
    identifier: string;
    instances?: Array<{
      offset?: number | null;
      matched_length?: number | null;
      matched_data_hex?: string | null;
    }>;
  }>;
  created_at: string | null;
};

export type YaraScan = {
  id: string;
  evidence_id: string;
  artifact_id: string;
  process_id: string | null;
  pid: number | null;
  memory_region_id: string | null;
  analysis_run_id: string | null;
  job_id: string | null;
  status: string;
  match_count: number;
  yara_version: string | null;
  ruleset?: Record<string, unknown>;
  error?: Record<string, unknown> | null;
  started_at: string | null;
  finished_at: string | null;
};

export type YaraScanBundle = {
  scan: YaraScan;
  matches: YaraMatch[];
};

export type PeSieveStatus = {
  available: boolean;
  reason?: string | null;
  suggestion?: string | null;
  pe_sieve_version?: string | null;
  executable_path?: string | null;
  tools_dir?: string | null;
  timeout_secs?: number;
  verified_release?: string;
  supported_target_kinds?: string[];
  memscope_artifact_targets_supported?: boolean;
  unsupported_target_explanation?: string | null;
  ui_state?: string;
  license?: {
    name?: string;
    redistribution?: string;
    bundled_in_memscope?: boolean;
  };
};

export type PeSieveScan = {
  id: string;
  evidence_id: string | null;
  artifact_id: string | null;
  process_id: string | null;
  pid: number | null;
  memory_region_id: string | null;
  analysis_run_id: string | null;
  job_id: string | null;
  status: string;
  ui_state: string | null;
  target_kind: string | null;
  live_pid: number | null;
  pe_sieve_version: string | null;
  executable_path: string | null;
  output_dir: string | null;
  exit_code: number | null;
  pesieve_result: string | null;
  observed?: Record<string, unknown>;
  interpretation?: Record<string, unknown>;
  error?: Record<string, unknown> | null;
  started_at: string | null;
  finished_at: string | null;
};

export type PeSieveOutput = {
  id: string;
  scan_id: string;
  artifact_id: string;
  dump_file: string | null;
  dump_mode: string | null;
  module_base: string | null;
  is_shellcode: boolean;
  role: string;
  sha256?: string | null;
  filename?: string | null;
  size_bytes?: number | null;
  file_type?: string | null;
  observed?: Record<string, unknown>;
};

export type PeSieveScanBundle = {
  scan: PeSieveScan;
  outputs: PeSieveOutput[];
};

export type MalUnpackStatus = {
  available: boolean;
  reason?: string | null;
  suggestion?: string | null;
  mal_unpack_version?: string | null;
  executable_path?: string | null;
  tools_dir?: string | null;
  timeout_secs?: number;
  timeout_ms?: number;
  verified_release?: string;
  verified_version_str?: string;
  verified_repo?: string;
  native_target_kinds?: string[];
  supported_target_kinds?: string[];
  memscope_artifact_targets_supported?: boolean;
  executes_sample?: boolean;
  unsupported_target_explanation?: string | null;
  ui_state?: string;
  license?: {
    name?: string;
    redistribution?: string;
    bundled_in_memscope?: boolean;
  };
};

export type MalUnpackScan = {
  id: string;
  evidence_id: string | null;
  artifact_id: string | null;
  process_id: string | null;
  pid: number | null;
  memory_region_id: string | null;
  analysis_run_id: string | null;
  job_id: string | null;
  status: string;
  ui_state: string | null;
  target_kind: string | null;
  mal_unpack_version: string | null;
  executable_path: string | null;
  output_dir: string | null;
  exit_code: number | null;
  unpack_result: string | null;
  invoked: boolean;
  observed?: Record<string, unknown>;
  interpretation?: Record<string, unknown>;
  error?: Record<string, unknown> | null;
  started_at: string | null;
  finished_at: string | null;
};

export type MalUnpackOutput = {
  id: string;
  scan_id: string;
  artifact_id: string;
  dump_file: string | null;
  dump_mode: string | null;
  module_base: string | null;
  is_shellcode: boolean;
  role: string;
  sha256?: string | null;
  filename?: string | null;
  size_bytes?: number | null;
  file_type?: string | null;
  observed?: Record<string, unknown>;
};

export type MalUnpackScanBundle = {
  scan: MalUnpackScan;
  outputs: MalUnpackOutput[];
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

export type PluginRequirement = {
  name: string;
  type: string;
  classification: string;
  configurable: boolean;
  optional: boolean;
  default?: unknown;
  description?: string;
  choices?: string[];
  element_type?: string;
  oses?: string[];
  architectures?: string[];
  children?: Array<Record<string, unknown>>;
};

export type PluginListItem = {
  id: string;
  name: string;
  module_path: string;
  class_name: string;
  category: string;
  description: string;
  available: boolean;
  version?: string | null;
  oses?: string[];
  architectures?: string[];
  discovery_errors?: string[];
  configurable_parameter_count?: number;
  runnable: boolean;
  runnable_reason?: string;
  os_match?: string;
};

export type PluginCatalog = {
  model_version: number;
  volatility_version: string;
  plugin_count: number;
  import_failures: string[];
  categories: Array<{ id: string; count: number }>;
  items: PluginListItem[];
  evidence_id?: string | null;
};

export type PluginDetail = {
  plugin: PluginListItem & {
    requirements: PluginRequirement[];
    configurable_parameters: PluginRequirement[];
    version_tuple?: number[] | null;
    required_framework_version?: number[] | null;
    hidden?: boolean;
  };
  runnable: { runnable: boolean; reason: string; os_match: string };
  volatility_version: string;
  evidence_id?: string | null;
  notes?: string;
};

export type PluginResultRow = {
  depth: number;
  cells: unknown[];
  values: Record<string, unknown>;
};

export type PluginExecutionBundle = {
  execution: {
    id: string;
    analysis_run_id: string;
    evidence_id: string;
    plugin: string;
    plugin_id: string;
    parameters: Record<string, unknown>;
    status: string;
    started_at: string | null;
    finished_at: string | null;
    row_count: number | null;
    cache_hit: boolean;
    cache_key?: string | null;
    error?: Record<string, unknown> | null;
    transparency?: Record<string, unknown>;
  };
  result: {
    model_version?: number;
    columns: Array<{ name: string; type: string }>;
    row_count: number;
    nested?: boolean;
    rows: PluginResultRow[];
    files: Array<Record<string, unknown>>;
    links: Array<{
      kind: string;
      pid?: number;
      process_id?: string;
      name?: string | null;
      reliable?: boolean;
    }>;
    raw?: Record<string, unknown>;
    truncated?: boolean;
    execution?: Record<string, unknown>;
  };
};

export type PluginExecutionSummary = {
  id: string;
  plugin: string;
  status: string;
  started_at: string | null;
  finished_at: string | null;
  row_count: number | null;
  cache_hit: boolean;
  analysis_run_id: string;
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
  | "export"
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

export type ExportFormat = "json" | "csv" | "html";
export type ExportScope = "complete" | "selected";
export type ExportUiState =
  | "idle"
  | "queued"
  | "running"
  | "completed"
  | "failed"
  | "cancelled";

export type ExportRecord = {
  id: string;
  evidence_id: string;
  job_id: string | null;
  format: ExportFormat | string;
  scope: ExportScope | string;
  sections: string[];
  status: string;
  output_dir: string | null;
  primary_path: string | null;
  files: Array<{ name: string; kind: string; size_bytes?: number }>;
  size_bytes: number | null;
  report_schema_version: number | null;
  error: Record<string, unknown> | null;
  created_at: string | null;
  finished_at: string | null;
};

export type ExportOptions = {
  formats: ExportFormat[];
  scopes: ExportScope[];
  sections: string[];
  csv_datasets: string[];
  report_schema_version: number;
  pdf: boolean;
  destination: string;
};
