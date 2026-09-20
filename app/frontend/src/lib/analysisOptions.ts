import type {
  AnalysisCapability,
  AnalysisProfileCatalog,
  AppErrorPayload,
  Evidence,
  Job,
} from "./types";

export function selectAllIds(catalog: AnalysisProfileCatalog): string[] {
  return [...catalog.select_all_evidence];
}

export function clearAllIds(): string[] {
  return [];
}

export function fullProfileIds(catalog: AnalysisProfileCatalog): string[] {
  const full = catalog.profiles.find((p) => p.id === "full");
  return full ? [...full.capabilities] : [...catalog.select_all_evidence];
}

export function recommendedProfileIds(catalog: AnalysisProfileCatalog): string[] {
  const rec = catalog.profiles.find((p) => p.id === "recommended");
  return rec ? [...rec.capabilities] : [];
}

export function capabilitiesById(
  catalog: AnalysisProfileCatalog,
): Map<string, AnalysisCapability> {
  return new Map(catalog.capabilities.map((c) => [c.id, c]));
}

/** User-facing copy for Analysis Options. Ids stay the engine capability ids. */
export const ANALYSIS_PROFILE_COPY: Record<
  "full" | "recommended" | "custom",
  { title: string; description: string; hint?: string }
> = {
  full: {
    title: "Complete Analysis",
    description: "Run the full supported analysis pipeline for this memory image.",
    hint: "Recommended for most investigations.",
  },
  recommended: {
    title: "Quick Triage",
    description:
      "Quickly identify the operating system and review running processes.",
    hint: "Faster first look — processes only. Search, IOCs, network, modules, and timeline stay limited until you run a fuller analysis.",
  },
  custom: {
    title: "Custom Analysis",
    description: "Select specific capabilities to run.",
  },
};

const CAPABILITY_COPY: Record<string, { label: string; description: string }> = {
  processes: {
    label: "Processes",
    description: "Identify the operating system and review running processes.",
  },
  command_lines: {
    label: "Command Lines",
    description: "Review process command-line arguments.",
  },
  modules: {
    label: "Modules / DLLs",
    description: "Review modules and DLLs loaded by processes.",
  },
  network: {
    label: "Network Connections",
    description: "Review network connections found in the memory image.",
  },
  network_artifacts: {
    label: "Network Artifact Extraction",
    description:
      "Recover network indicators from stored connections and process text. Does not rescan the dump.",
  },
  handles: {
    label: "Handles",
    description: "Review open handles associated with processes.",
  },
  findings: {
    label: "Findings & Heuristics",
    description:
      "Review heuristic findings from command lines already stored. Requires Command Lines, or run Complete Analysis.",
  },
  iocs: {
    label: "IOC Extraction",
    description:
      "Extract indicators from stored process, module, and network data. Does not rescan the dump — results match whatever those capabilities collected.",
  },
  timeline: {
    label: "Timeline",
    description:
      "Build an investigation timeline from stored records. Does not rescan the dump.",
  },
  recommended: {
    label: "Process Analysis",
    description: "Perform the standard per-process analysis for a selected process.",
  },
  memory_vad: {
    label: "Memory / VAD",
    description: "Inspect virtual memory regions for a selected process.",
  },
  process_deep_dive: {
    label: "Process Deep Dive",
    description: "Perform deeper analysis of a selected process.",
  },
  artifacts: {
    label: "Carved Data",
    description: "Extract artifacts from a targeted memory region.",
  },
  pe_extraction: {
    label: "Extracted Files",
    description:
      "Reconstruct EXE/DLL images from the memory dump. Start this from Carved Data after analysis.",
  },
  bulk_extractor: {
    label: "Carved Artifacts",
    description:
      "Carve emails, keys, URLs, and other strings from the dump. Start this from Carved Data after analysis.",
  },
};

export const ANALYSIS_PROFILE_ORDER: Array<"full" | "recommended" | "custom"> = [
  "full",
  "recommended",
  "custom",
];

export function capabilityCopy(capability: AnalysisCapability): {
  label: string;
  description: string;
} {
  return (
    CAPABILITY_COPY[capability.id] ?? {
      label: capability.label,
      description: capability.description,
    }
  );
}

export function capabilityLabel(id: string): string | undefined {
  return CAPABILITY_COPY[id]?.label;
}

export function fullAnalysisIncludes(catalog: AnalysisProfileCatalog): string {
  return fullProfileIds(catalog)
    .map((id) => CAPABILITY_COPY[id]?.label)
    .filter((label): label is string => Boolean(label))
    .join(" · ");
}

export function isActiveJobStatus(status: string): boolean {
  return status === "queued" || status === "running";
}

export function activeJobOfKind(
  jobs: readonly Job[] | null | undefined,
  ...kinds: string[]
): Job | null {
  if (!jobs?.length || kinds.length === 0) return null;
  const wanted = new Set(kinds);
  return jobs.find((job) => wanted.has(job.kind) && isActiveJobStatus(job.status)) ?? null;
}

export function isTerminalJobStatus(status: string): boolean {
  return (
    status === "completed" ||
    status === "failed" ||
    status === "cancelled" ||
    status === "canceled" ||
    status === "timeout" ||
    status === "timed_out"
  );
}

export function jobErrorPayload(job: Job, fallbackMessage: string): AppErrorPayload {
  const err = job.error;
  const appCode =
    typeof err?.code === "string"
      ? err.code
      : typeof err?.app_code === "string"
        ? err.app_code
        : undefined;
  return {
    message: typeof err?.message === "string" ? err.message : fallbackMessage,
    app_code: appCode,
    suggestion: typeof err?.suggestion === "string" ? err.suggestion : undefined,
  };
}

const STRUCTURE_LEAK =
  /\b(?:memscope_engine|volatility3|Traceback \(most recent call last\)|File "[^"]+", line \d+)\b/i;

function sanitizeErrorMessage(text: string): string {
  let value = text.replace(/\r\n/g, "\n").trim();
  value = value.replace(/^[A-Za-z_][\w.]*Error:\s*/g, "");
  const leakAt = value.search(STRUCTURE_LEAK);
  if (leakAt >= 0) {
    value = value.slice(0, leakAt).trim();
  }
  return value.replace(/\s{2,}/g, " ").trim();
}

/** User-visible error text only — no stack traces, paths, or engine internals. */
export function formatUserError(
  err: AppErrorPayload | string | null | undefined,
  fallback = "Something went wrong.",
): string {
  if (err == null) return fallback;
  const payload = typeof err === "string" ? { message: err } : err;
  const message = sanitizeErrorMessage(payload.message || "") || fallback;
  const suggestion =
    typeof payload.suggestion === "string" ? payload.suggestion.trim() : "";
  if (suggestion && !message.toLowerCase().includes(suggestion.toLowerCase())) {
    return `${message}\n${suggestion}`;
  }
  return message;
}

export function isNotMemoryImageError(err: AppErrorPayload): boolean {
  if (err.app_code === "evidence_not_memory_image") return true;
  return /not a memory dump/i.test(err.message);
}

/** Full copy for a wrapping toast — never concatenated onto the top bar. */
export function notMemoryImageToast(_err: AppErrorPayload): string {
  return [
    "This file is not a memory dump!",
    "Select a real memory image (Windows crash dump, raw physical memory, LiME, or ELF core)",
  ].join("\n");
}

export function jobPercent(job: Job | null): number | null {
  const value = job?.result?.percent;
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "string" && value.trim()) {
    const parsed = Number(value);
    if (Number.isFinite(parsed)) return parsed;
  }
  return null;
}

/** Display-only whole-percent text. Does not change the stored percent value. */
export function formatJobPercent(value: number): string {
  return `${Math.round(value)}%`;
}

export function isJobCancelling(job: Job, pendingIds?: ReadonlySet<string>): boolean {
  if (!isActiveJobStatus(job.status)) return false;
  return Boolean(job.cancel_requested) || Boolean(pendingIds?.has(job.id));
}

export function jobStatusLabel(job: Job, pendingIds?: ReadonlySet<string>): string {
  if (isJobCancelling(job, pendingIds)) return "cancelling";
  return job.status;
}

export function jobPhase(job: Job | null): string | null {
  const value = job?.result?.phase;
  return typeof value === "string" && value ? value : null;
}

/** Wall-clock elapsed from a frontend origin; never derived from job percent. */
export function formatElapsed(startMs: number | null, nowMs: number): string {
  if (startMs == null || !Number.isFinite(startMs) || !Number.isFinite(nowMs)) {
    return "0s";
  }
  const secs = Math.max(0, Math.floor((nowMs - startMs) / 1000));
  const m = Math.floor(secs / 60);
  const s = secs % 60;
  return m > 0 ? `${m}m ${s}s` : `${s}s`;
}

export function importStageLabel(job: Job | null): string {
  if (job?.status === "queued") return "Waiting to start";
  const phase = jobPhase(job);
  if (phase === "hash") return "Computing SHA-256 Hash";
  if (phase === "validate") return "Validating memory image";
  if (phase === "register") return "Registering evidence";
  if (phase === "done") return "Import complete";
  if (phase === "start") return "Importing memory image";
  const msg = job?.message?.trim();
  if (msg) return msg.replace(/\s*\(\d+(?:\.\d+)?%\)$/, "");
  return "Working";
}

export function evidenceFromImportJob(job: Job): Evidence | null {
  const raw = job.result?.evidence;
  if (!raw || typeof raw !== "object") return null;
  const ev = raw as Evidence;
  return typeof ev.id === "string" ? ev : null;
}
