export type AppErrorPayload = {
  message: string;
  app_code?: string;
  details?: string;
  suggestion?: string;
  entity?: string;
  raw?: string;
  data?: Record<string, unknown>;
};

export type KernelSymbolNeed = {
  pdb_name: string;
  guid: string;
  age: number;
  filename_pdb: string;
  filename_isf: string;
  download_url: string;
  dest_dir: string;
  accepted_extensions: string[];
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
  process_name?: string | null;
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
  process_name?: string | null;
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

export type NetworkArtifact = {
  id: string;
  run_id?: string | null;
  evidence_id: string;
  analysis_run_id?: string | null;
  connection_id?: string | null;
  process_id: string | null;
  pid: number | null;
  process_name?: string | null;
  artifact_type: string;
  value: string;
  protocol: string | null;
  local_address: string | null;
  local_port: number | null;
  remote_address: string | null;
  remote_port: number | null;
  state: string | null;
  source: string;
  source_plugin: string | null;
  extraction_method: string;
  source_address: string | null;
  offset_hex: string | null;
  context: string | null;
  metadata?: Record<string, unknown>;
  created_at: string | null;
};

export type NetworkArtifactRun = {
  id: string;
  evidence_id: string;
  status: string;
  artifact_count: number;
  type_counts: Record<string, number>;
  sources: string[];
  started_at: string | null;
  finished_at: string | null;
};

export type PcapFlowResult = {
  id: string;
  reconstruction_id: string;
  connection_id: string | null;
  process_id: string | null;
  pid: number | null;
  protocol: string | null;
  local_address: string | null;
  local_port: number | null;
  remote_address: string | null;
  remote_port: number | null;
  status: string;
  display_status: string;
  packet_count: number;
  truncated_count: number;
  notes: string | null;
  flow_pcap_path: string | null;
  exportable: boolean;
};

export type PcapReconstruction = {
  id: string;
  evidence_id: string;
  status: string;
  ui_state: string | null;
  reconstruction_status: string;
  display_status: string;
  packet_count: number;
  truncated_count: number;
  ethernet_count: number;
  raw_ip_count: number;
  flow_count: number;
  output_path: string | null;
  output_dir: string | null;
  files: Array<Record<string, unknown>>;
  limitations: string[];
  observed?: {
    imported_pcap_packets?: number | null;
    imported_pcap_path?: string | null;
    [key: string]: unknown;
  } | null;
  pcap_embedded?: boolean;
  error?: Record<string, unknown> | null;
  started_at: string | null;
  finished_at: string | null;
};

export type PcapReconstructionBundle = {
  reconstruction: PcapReconstruction;
  flows: PcapFlowResult[];
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
  capa_scans?: CapaScanBundle[];
  capa_status?: CapaStatus;
  floss_scans?: FlossScanBundle[];
  floss_status?: FlossStatus;
};

export type YaraStatus = {
  available: boolean;
  reason?: string | null;
  suggestion?: string | null;
  yara_version?: string | null;
  binding?: string | null;
  provider?: string;
  bundled?: boolean;
  rule_file_count?: number;
  valid_rule_file_count?: number;
  skipped_rule_file_count?: number;
  loaded_rule_count?: number;
  memory_rule_file_count?: number;
  artifact_rule_file_count?: number;
  bundled_rule_file_count?: number;
  custom_rule_file_count?: number;
  extra_rule_file_count?: number;
  bundled_rule_count?: number;
  custom_rule_count?: number;
  extra_rule_count?: number;
  skipped_rule_files?: Array<{ path?: string; error?: string }>;
  rule_files?: string[];
  default_rules_dir?: string | null;
  bundled_dir?: string | null;
  custom_dir?: string | null;
  extra_rule_paths?: string[];
  timeout_secs?: number;
  memory_timeout_secs?: number;
  scan_modes?: string[];
  status_summary?: string;
};

export type YaraMatch = {
  id: string;
  scan_id: string;
  evidence_id: string;
  artifact_id: string | null;
  target_kind?: string;
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
  artifact_id: string | null;
  target_kind?: string;
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

export type PeExtractionStatus = {
  available: boolean;
  reason?: string | null;
  suggestion?: string | null;
  volatility_version?: string | null;
  pedump_available?: boolean;
  target?: string;
  methods?: string[];
  notes?: string;
  produces?: string;
  not_a_malware_verdict?: boolean;
};

export type PeExtractionRun = {
  id: string;
  evidence_id: string;
  analysis_run_id?: string | null;
  job_id?: string | null;
  status: string;
  volatility_version?: string | null;
  extracted_count: number;
  exe_count: number;
  dll_count: number;
  skipped_count: number;
  candidate_count?: number;
  output_dir?: string | null;
  methods?: string[];
  observed?: Record<string, unknown>;
  error?: Record<string, unknown> | null;
  started_at: string | null;
  finished_at: string | null;
};

export type PeExtractionItem = {
  id: string;
  run_id: string;
  artifact_id: string | null;
  evidence_id?: string | null;
  process_id: string | null;
  pid: number | null;
  process_name: string | null;
  original_path: string | null;
  pe_kind: string | null;
  memory_region: string | null;
  source_address?: string | null;
  start_vpn?: string | null;
  end_vpn?: string | null;
  extraction_method: string;
  source_plugin: string | null;
  filename: string | null;
  stored_path: string | null;
  sha256: string | null;
  size_bytes: number | null;
  metadata?: Record<string, unknown>;
  label?: string;
  created_at?: string | null;
};

export type PeExtractionBundle = {
  run: PeExtractionRun;
  items: PeExtractionItem[];
};

export type CapaStatus = {
  available: boolean;
  reason?: string | null;
  suggestion?: string | null;
  capa_version?: string | null;
  executable_path?: string | null;
  tools_dir?: string | null;
  timeout_secs?: number;
  verified_release?: string;
  supported_target_kinds?: string[];
  target?: string;
  source?: "bundled" | "user-supplied" | string | null;
  license?: {
    name?: string;
    redistribution?: string;
    bundled_in_memscope?: boolean;
  };
};

export type CapaCapability = {
  id: string;
  scan_id: string;
  evidence_id?: string | null;
  artifact_id?: string | null;
  process_id?: string | null;
  pid?: number | null;
  name: string;
  namespace: string | null;
  scope: string | null;
  attck: unknown[];
  mbc: unknown[];
  authors: unknown[];
  description: string | null;
  created_at: string | null;
};

export type CapaScan = {
  id: string;
  evidence_id: string | null;
  artifact_id: string;
  process_id: string | null;
  pid: number | null;
  memory_region_id?: string | null;
  pe_extraction_run_id?: string | null;
  analysis_run_id?: string | null;
  job_id?: string | null;
  status: string;
  capa_version: string | null;
  executable_path?: string | null;
  capability_count: number;
  exit_code?: number | null;
  output_json_path?: string | null;
  observed?: Record<string, unknown>;
  interpretation?: Record<string, unknown>;
  error?: Record<string, unknown> | null;
  started_at: string | null;
  finished_at: string | null;
};

export type CapaScanBundle = {
  scan: CapaScan;
  capabilities: CapaCapability[];
};

export type FlossStatus = {
  available: boolean;
  reason?: string | null;
  suggestion?: string | null;
  floss_version?: string | null;
  executable_path?: string | null;
  tools_dir?: string | null;
  timeout_secs?: number;
  verified_release?: string;
  supported_target_kinds?: string[];
  target?: string;
  source?: "bundled" | "user-supplied" | string | null;
  license?: {
    name?: string;
    redistribution?: string;
    bundled_in_memscope?: boolean;
  };
};

export type FlossString = {
  id: string;
  scan_id: string;
  evidence_id?: string | null;
  artifact_id?: string | null;
  process_id?: string | null;
  pid?: number | null;
  kind: string;
  value: string;
  offset?: string | null;
  encoding?: string | null;
  observed?: Record<string, unknown>;
  created_at?: string | null;
};

export type FlossScan = {
  id: string;
  evidence_id: string | null;
  artifact_id: string;
  process_id: string | null;
  pid: number | null;
  memory_region_id?: string | null;
  pe_extraction_run_id?: string | null;
  analysis_run_id?: string | null;
  job_id?: string | null;
  status: string;
  floss_version: string | null;
  executable_path?: string | null;
  string_count: number;
  exit_code?: number | null;
  output_json_path?: string | null;
  observed?: Record<string, unknown>;
  interpretation?: Record<string, unknown>;
  error?: Record<string, unknown> | null;
  started_at: string | null;
  finished_at: string | null;
};

export type FlossScanBundle = {
  scan: FlossScan;
  strings: FlossString[];
};

export type BulkExtractorStatus = {
  available: boolean;
  reason?: string | null;
  suggestion?: string | null;
  bulk_extractor_version?: string | null;
  executable_path?: string | null;
  tools_dir?: string | null;
  analysis_dir?: string | null;
  timeout_secs?: number;
  verified_release?: string;
  verified_repo?: string;
  supported_target_kinds?: string[];
  source?: "bundled" | "user-supplied" | string | null;
  bundled_dir?: string | null;
  windows_notes?: string | null;
  ui_state?: string;
  license?: {
    name?: string;
    redistribution?: string;
    bundled_in_memscope?: boolean;
  };
};

export type BulkExtractorCategory = {
  id: string;
  label: string;
  description?: string;
  unique_count: number;
  row_count: number;
  scanners?: string[];
  columns?: string[];
};

export type BulkExtractorScan = {
  id: string;
  evidence_id: string | null;
  analysis_run_id: string | null;
  job_id: string | null;
  status: string;
  ui_state: string | null;
  bulk_extractor_version: string | null;
  executable_path: string | null;
  output_dir: string | null;
  exit_code: number | null;
  feature_count: number;
  feature_file_count?: number;
  feature_counts?: Record<string, number>;
  unique_counts?: Record<string, number>;
  categories?: BulkExtractorCategory[];
  scanner_count: number;
  invoked: boolean;
  observed?: Record<string, unknown>;
  interpretation?: Record<string, unknown>;
  error?: Record<string, unknown> | null;
  started_at: string | null;
  finished_at: string | null;
};

export type BulkExtractorOutput = {
  id: string;
  scan_id: string;
  evidence_id?: string | null;
  relative_path: string | null;
  role: string;
  scanner?: string | null;
  size_bytes?: number | null;
  observed?: Record<string, unknown>;
  created_at?: string | null;
};

export type BulkExtractorScanBundle = {
  scan: BulkExtractorScan;
  outputs: BulkExtractorOutput[];
};

export type BulkExtractorFeature = {
  id: string;
  scan_id?: string;
  evidence_id?: string | null;
  scanner: string;
  category: string;
  ioc_type: string;
  finding_type?: string;
  offset: string | null;
  value: string;
  context: string | null;
  count: number;
  extra?: Record<string, unknown>;
  created_at?: string | null;
};

export type BulkExtractorFeaturePage = {
  scan_id: string;
  evidence_id?: string | null;
  categories: BulkExtractorCategory[];
  category?: string | null;
  scanner?: string | null;
  items: BulkExtractorFeature[];
  total: number;
  shown?: number;
  limit?: number;
  offset?: number;
  hide_weak?: boolean;
  note?: string;
};

export type TimelineEvent = {
  id: string;
  evidence_id: string;
  event_time: string | null;
  /** When the analyst ran Dumplyzer; not dump OS time. */
  recorded_at?: string | null;
  /** dump = forensic OS clock; analysis = tool/run wall clock. */
  clock?: "dump" | "analysis";
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
  evidence_filename?: string | null;
};

export type AnalysisCapability = {
  id: string;
  label: string;
  scope: "evidence" | "process" | string;
  description: string;
};

export type AnalysisProfileInfo = {
  id: "full" | "recommended" | "custom" | string;
  label: string;
  capabilities: string[];
  description: string;
};

export type AnalysisProfileCatalog = {
  profiles: AnalysisProfileInfo[];
  capabilities: AnalysisCapability[];
  full_analysis: string;
  select_all_evidence: string[];
  select_all_with_process: string[];
};

export type Overview = {
  evidence: Evidence;
  process_count: number;
  network_count: number;
  module_count: number;
  finding_count: number;
  ioc_count: number;
  recent_runs: Array<Record<string, unknown>>;
  coverage?: AnalysisCoverage;
};

export type AnalysisCoverageState =
  | "analyzed"
  | "analyzed_zero"
  | "not_analyzed"
  | "failed";

export type CapabilityCoverage = {
  id: string;
  state: AnalysisCoverageState;
  count: number | null;
  updating?: boolean;
  waitingForPdb?: boolean;
};

export type AnalysisCoverage = {
  items: Record<string, CapabilityCoverage>;
  executed: string[];
  failed: string[];
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
  | "signatures"
  | "jobs"
  | "plugins"
  | "export"
  | "settings"
  | "about";

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

export type ExportFormat = "json" | "xlsx" | "html";
export type ExportScope = "complete" | "selected";
export type ExportUiState =
  | "idle"
  | "queued"
  | "running"
  | "completed"
  | "failed"
  | "cancelled";

export function exportStatusLabel(state: ExportUiState): string {
  if (state === "queued") return "queued";
  if (state === "running") return "generating";
  return state;
}

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
