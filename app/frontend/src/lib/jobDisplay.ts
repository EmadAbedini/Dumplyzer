import {
  ANALYSIS_PROFILE_COPY,
  capabilityLabel,
  formatJobPercent,
  isJobCancelling,
  isTerminalJobStatus,
  jobErrorPayload,
  jobPercent,
  jobPhase,
} from "./analysisOptions";
import { CAPABILITY } from "./analysisCapabilities";
import type { Job } from "./types";

/** Registered job kinds → existing product labels. Backend ids stay unchanged. */
const JOB_KIND_LABELS: Record<string, string> = {
  evidence_import: "Memory Image Import",
  analysis_profile: ANALYSIS_PROFILE_COPY.custom.title,
  basic_triage: capabilityLabel("processes") ?? "Processes",
  process_recommended: capabilityLabel("recommended") ?? "Process Analysis",
  vad_scan: capabilityLabel("memory_vad") ?? "Memory / VAD",
  vad_extract: capabilityLabel("artifacts") ?? "Carved Data",
  yara_artifact_scan: CAPABILITY.signatureDetection,
  yara_memory_scan: CAPABILITY.signatureDetection,
  yara_extracted_scan: CAPABILITY.signatureDetection,
  pe_extraction: CAPABILITY.peReconstruction,
  capa_artifact: CAPABILITY.capabilityAnalysis,
  floss_artifact: CAPABILITY.stringAnalysis,
  bulk_extractor_scan: CAPABILITY.artifactExtraction,
  network_artifact_extraction: "Network Artifact Extraction",
  pcap_reconstruction: "PCAP Reconstruction",
  plugin_advanced: "Plugins",
  export_report: "Export",
};

const PHASE_PERCENT: Record<string, number> = {
  processes: 1,
  session: 14,
  command_lines: 20,
  modules: 27,
  network: 37,
  handles: 47,
  findings: 89,
  iocs: 92,
  network_artifacts: 94,
  timeline: 96,
  recommended: 90,
  vad: 97,
  memory_vad: 97,
  pe_extract: 4,
  process_images: 12,
  pe_modules: 18,
  pe_vad: 70,
  pe_cache: 90,
  scan: 4,
  done: 100,
};

/** Inclusive start / exclusive-ish end of the time-weighted bar for each phase. */
const PHASE_RANGE: Record<string, [number, number]> = {
  processes: [1, 14],
  session: [14, 20],
  command_lines: [20, 27],
  modules: [27, 37],
  network: [37, 47],
  handles: [47, 89],
  findings: [89, 92],
  iocs: [92, 94],
  network_artifacts: [94, 96],
  timeline: [96, 100],
  recommended: [90, 97],
  vad: [97, 100],
  memory_vad: [97, 100],
  pe_extract: [2, 12],
  process_images: [12, 18],
  pe_modules: [18, 70],
  pe_vad: [70, 90],
  pe_cache: [90, 98],
  scan: [2, 92],
};

const lastShownPercent = new Map<string, number>();
const creepOrigin = new Map<string, { base: number; at: number; phase: string }>();
const frozenPercent = new Map<string, number>();

function clearJobDisplay(jobId: string) {
  lastShownPercent.delete(jobId);
  creepOrigin.delete(jobId);
  frozenPercent.delete(jobId);
}

const PHASE_LABELS: Record<string, string> = {
  processes: capabilityLabel("processes") ?? "Processes",
  command_lines: capabilityLabel("command_lines") ?? "Command Lines",
  modules: capabilityLabel("modules") ?? "Modules / DLLs",
  network: capabilityLabel("network") ?? "Network Connections",
  handles: capabilityLabel("handles") ?? "Handles",
  findings: capabilityLabel("findings") ?? "Findings & Heuristics",
  iocs: capabilityLabel("iocs") ?? "IOC Extraction",
  network_artifacts: capabilityLabel("network_artifacts") ?? "Network Artifact Extraction",
  timeline: capabilityLabel("timeline") ?? "Timeline",
  recommended: capabilityLabel("recommended") ?? "Process Analysis",
  vad: capabilityLabel("memory_vad") ?? "Memory / VAD",
  memory_vad: capabilityLabel("memory_vad") ?? "Memory / VAD",
  session: "Opening memory image",
  pe_extract: "Extracting PE images",
  process_images: "Extracting process images",
  pe_modules: "Extracting loaded modules",
  pe_vad: "Scanning memory regions",
  pe_cache: "Extracting cached PE files",
  done: "Completed",
  hash: "Computing SHA-256 Hash",
  validate: "Validating memory image",
  register: "Registering evidence",
  start: "Importing memory image",
  scan: "Scanning for artifacts",
};

const MESSAGE_LABELS: Record<string, string> = {
  completed: "Completed",
  cancelled: "Cancelled",
  "cancel requested": "Cancelling…",
  "cancelled before start": "Cancelled",
  queued: "Queued",
  "importing memory image…": "Importing memory image",
  "importing memory image": "Importing memory image",
  "opening memory image": "Opening memory image",
  "opening memory image (volatility session)": capabilityLabel("processes") ?? "Processes",
  "running windows.info": capabilityLabel("processes") ?? "Processes",
  "running windows.pslist": capabilityLabel("processes") ?? "Processes",
  "windows.netscan (filter to pid)": capabilityLabel("network") ?? "Network Connections",
  "processes (basic triage)": capabilityLabel("processes") ?? "Processes",
  "processes (basic triage, required)": capabilityLabel("processes") ?? "Processes",
  "analysis complete": "Completed",
  "extracting iocs": capabilityLabel("iocs") ?? "IOC Extraction",
  "extracting network artifacts": capabilityLabel("network_artifacts") ?? "Network Artifact Extraction",
  "network artifact extraction": "Extracting network artifacts",
  "network artifact extraction complete": "Network artifacts extracted",
  "pcap reconstruction": "Reconstructing PCAP",
  "reconstructing packet records from the memory image": "Reconstructing packet records",
  "pcap reconstruction complete": "PCAP reconstruction complete",
  "building timeline": capabilityLabel("timeline") ?? "Timeline",
  "findings / heuristics": capabilityLabel("findings") ?? "Findings & Heuristics",
  "recommended process analysis": capabilityLabel("recommended") ?? "Process Analysis",
  "memory / vad": capabilityLabel("memory_vad") ?? "Memory / VAD",
  "generating investigation export": "Generating export",
  "generate investigation export": "Generating export",
  "collecting investigation data": "Collecting investigation data",
  "extracting pe images from the memory dump": "Extracting PE images",
  "pe extraction from imported memory dump": "Extracting PE images",
  "pe reconstruction complete": "PE reconstruction complete",
  "bulk_extractor scan of imported memory image": "Scanning for artifacts",
  "running bulk_extractor against the memory image…": "Scanning for artifacts",
  "scanning memory image for artifacts": "Scanning for artifacts",
  "scanning memory image": "Scanning for artifacts",
  "bulk_extractor finished": "Artifact scan complete",
  "signature detection artifact scan": "Scanning artifact",
  "signature detection memory dump scan": "Scanning memory image",
  "signature detection extracted files scan": "Scanning extracted files",
  "scanning extracted file": "Scanning extracted files",
  "compiling signature detection rules": "Compiling rules",
  "compiling memory signature detection rules": "Compiling rules",
  "extract vad region": "Extracting region",
  "constructing volatility session for vad dump": "Opening memory image",
  "locating process and vad object": capabilityLabel("memory_vad") ?? "Memory / VAD",
  "dumping vad bytes (volatility vad_dump)": "Extracting region",
};

const STATUS_LABELS: Record<string, string> = {
  queued: "Queued",
  running: "Running",
  cancelling: "Cancelling",
  completed: "Completed",
  cancelled: "Cancelled",
  canceled: "Cancelled",
  failed: "Failed",
  timeout: "Timed out",
  timed_out: "Timed out",
};

export function jobAnalysisLabel(job: Job): string {
  if (job.kind === "analysis_profile") {
    const profile = String(job.params?.profile ?? "").toLowerCase();
    if (profile === "full") return ANALYSIS_PROFILE_COPY.full.title;
    if (profile === "recommended") return ANALYSIS_PROFILE_COPY.recommended.title;
    if (profile === "custom") return ANALYSIS_PROFILE_COPY.custom.title;
  }
  return JOB_KIND_LABELS[job.kind] ?? "Job";
}

export function jobFileName(job: Job, fallback?: string | null): string {
  const named = typeof job.evidence_filename === "string" ? job.evidence_filename.trim() : "";
  if (named) return named;
  const params = job.params ?? {};
  if (typeof params.filename === "string" && params.filename.trim()) return params.filename.trim();
  if (typeof params.path === "string" && params.path.trim()) {
    const normalized = params.path.replace(/\\/g, "/");
    const base = normalized.split("/").pop();
    if (base) return base;
  }
  const result = job.result;
  if (result && typeof result === "object") {
    const evidence = (result as { evidence?: { filename?: unknown } }).evidence;
    if (typeof evidence?.filename === "string" && evidence.filename.trim()) {
      return evidence.filename.trim();
    }
  }
  if (fallback && fallback.trim()) return fallback.trim();
  return "—";
}

export function jobStatusDisplay(statusLabel: string): string {
  return STATUS_LABELS[statusLabel] ?? statusLabel;
}

export function jobTableMessage(
  job: Job,
  pendingIds?: ReadonlySet<string>,
  nowMs: number = Date.now(),
): { text: string; title: string } {
  const failed = job.status === "failed";
  const payload = failed ? jobErrorPayload(job, job.message || "Job failed") : null;
  const titleParts = failed
    ? [payload?.message, payload?.details, payload?.suggestion].filter(Boolean)
    : [];
  if (job.status === "completed") {
    clearJobDisplay(job.id);
    return { text: "Completed", title: titleParts.join(" — ") || "Completed" };
  }
  if (job.status === "cancelled" || job.status === "canceled") {
    clearJobDisplay(job.id);
    return { text: "Cancelled", title: titleParts.join(" — ") || "Cancelled" };
  }
  if (failed) {
    clearJobDisplay(job.id);
    const text = sanitizeUserText(payload?.message || "Job failed") || "Job failed";
    return { text, title: titleParts.join(" — ") || text };
  }

  const cancelling = isJobCancelling(job, pendingIds);
  const stage = jobStageLabel(job);
  const percentText = jobProgressPercentText(job, nowMs, pendingIds);
  let text = stage;
  if (percentText && !text.includes(percentText)) {
    text = text ? `${text} · ${percentText}` : percentText;
  }
  if (!text) text = cancelling ? "Cancelling…" : "Running";
  const title = titleParts.join(" — ") || text;
  return { text, title };
}

export function jobProgressPercentText(
  job: Job | null,
  nowMs: number = Date.now(),
  pendingIds?: ReadonlySet<string>,
): string | null {
  if (!job || isTerminalJobStatus(job.status)) return null;
  const cancelling = isJobCancelling(job, pendingIds);
  const percent = jobDisplayPercent(job, jobStageLabel(job), nowMs, cancelling);
  return percent != null ? formatJobPercent(percent) : null;
}

export function jobAnalysisTitle(job: Job): string {
  const label = jobAnalysisLabel(job);
  if (typeof job.pid === "number") return `${label} · PID ${job.pid}`;
  return label;
}

function jobDisplayPercent(
  job: Job,
  stage: string,
  nowMs: number,
  freeze = false,
): number | null {
  if (freeze || frozenPercent.has(job.id)) {
    const held =
      frozenPercent.get(job.id) ?? lastShownPercent.get(job.id) ?? jobPercent(job);
    if (held != null) {
      frozenPercent.set(job.id, held);
      lastShownPercent.set(job.id, held);
    }
    return held ?? null;
  }
  const stored = jobPercent(job);
  const phase = jobPhase(job);
  const phaseKey =
    (phase && (PHASE_PERCENT[phase] != null || PHASE_RANGE[phase]) ? phase : null) ??
    Object.entries(PHASE_LABELS).find(([, label]) => label === stage)?.[0];
  const range = phaseKey ? PHASE_RANGE[phaseKey] : undefined;
  let base = stored;
  if (base == null && phaseKey && PHASE_PERCENT[phaseKey] != null) {
    base = PHASE_PERCENT[phaseKey];
  }
  if (base == null) return lastShownPercent.get(job.id) ?? null;

  let cap = range ? range[1] - 1 : Math.min(99, base + 8);
  if (base >= cap) cap = Math.min(99, base + Math.max(6, (range ? range[1] - range[0] : 12) * 0.5));

  const origin = creepOrigin.get(job.id);
  if (!origin || origin.phase !== (phaseKey || stage) || base > origin.base + 0.4) {
    creepOrigin.set(job.id, { base, at: nowMs, phase: phaseKey || stage });
  }
  const creep = creepOrigin.get(job.id)!;
  const span = Math.max(0, cap - creep.base);
  const tau = span > 20 ? 180 : 70;
  const elapsedSec = Math.max(0, (nowMs - creep.at) / 1000);
  const crept = creep.base + span * (1 - Math.exp(-elapsedSec / tau));
  let shown = Math.max(base, crept);
  shown = Math.min(cap, shown);
  const prev = lastShownPercent.get(job.id);
  if (prev != null) shown = Math.max(prev, shown);
  lastShownPercent.set(job.id, shown);
  return shown;
}

function jobStageLabel(job: Job): string {
  const phase = jobPhase(job);
  if (phase && PHASE_LABELS[phase]) return PHASE_LABELS[phase];
  const raw = (job.message ?? "").trim();
  if (!raw) return "";
  const key = stripPercentSuffix(raw).toLowerCase();
  if (MESSAGE_LABELS[key]) return MESSAGE_LABELS[key];
  if (/^opening image for pid\b/i.test(key)) return "Opening memory image";
  const fromPlugin = stageFromPluginMessage(key);
  if (fromPlugin) return fromPlugin;
  if (/^running [a-z][a-z0-9_]*$/.test(key)) return "Starting";
  if (key.startsWith("running ")) {
    const rest = sanitizeUserText(stripPercentSuffix(raw).slice("Running ".length));
    return rest || "Starting";
  }
  if (key.startsWith("analysis (")) return "Starting";
  if (key.startsWith("recommended analysis")) return capabilityLabel("recommended") ?? "Process Analysis";
  if (key.startsWith("vad scan")) return capabilityLabel("memory_vad") ?? "Memory / VAD";
  if (key.startsWith("capa analysis")) return "Analyzing artifact";
  if (key.startsWith("floss analysis")) return "Analyzing artifact";
  if (key.startsWith("advanced plugin")) return "Running plugin";
  if (key.startsWith("scanning extracted file")) return "Scanning extracted files";
  if (key.startsWith("scanning artifact ")) return "Scanning artifact";
  if (key.startsWith("scanning memory dump")) return "Scanning memory image";
  return sanitizeUserText(stripPercentSuffix(raw));
}

function stageFromPluginMessage(key: string): string | undefined {
  if (/^windows\.(info|pslist)\b/.test(key)) return capabilityLabel("processes");
  if (/^windows\.cmdline\b/.test(key)) return capabilityLabel("command_lines");
  if (/^windows\.dlllist\b/.test(key)) return capabilityLabel("modules");
  if (/^windows\.netscan\b/.test(key)) return capabilityLabel("network");
  if (/^windows\.handles\b/.test(key)) return capabilityLabel("handles");
  if (/^windows\.vadinfo\b/.test(key)) return capabilityLabel("memory_vad");
  return undefined;
}

function stripPercentSuffix(value: string): string {
  return value.replace(/\s*\(\d+(?:\.\d+)?%\)$/, "").trim();
}

function sanitizeUserText(value: string): string {
  return value
    .replace(/\s*\((?:windows|linux|mac)\.[^)]+\)/gi, "")
    .replace(/\b(?:windows|linux|mac)\.\w+/gi, "")
    .replace(/\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi, "")
    .replace(/\s{2,}/g, " ")
    .replace(/\s+([,.;:])/g, "$1")
    .trim();
}
