import { capabilityLabel } from "./analysisOptions";
import {
  coverageHasRows,
  coverageItem,
  coverageLiveKind,
  coverageWasExecuted,
} from "./analysisCoverage";
import type { AnalysisCoverage } from "./types";

/** Evidence-wide capabilities included in Complete Analysis. */
export const COMPLETE_ANALYSIS_IDS = [
  "processes",
  "command_lines",
  "modules",
  "network",
  "handles",
  "findings",
  "iocs",
  "network_artifacts",
  "timeline",
] as const;

/** Source tables a derived view reads. Missing sources mean a smaller result set. */
export const DERIVED_SOURCE_IDS = {
  iocs: [
    "processes",
    "command_lines",
    "modules",
    "network",
    "handles",
    "network_artifacts",
  ],
  network_artifacts: ["network", "command_lines", "processes"],
  findings: ["command_lines"],
  timeline: [
    "processes",
    "command_lines",
    "modules",
    "network",
    "handles",
    "findings",
    "iocs",
    "network_artifacts",
  ],
  search: [
    "processes",
    "command_lines",
    "modules",
    "network",
    "network_artifacts",
    "findings",
    "iocs",
    "handles",
  ],
} as const;

export const SEARCH_FIELD_SOURCES: Record<string, readonly string[]> = {
  all: [],
  process_names: ["processes"],
  pids: ["processes"],
  usernames: ["processes"],
  command_lines: ["command_lines"],
  modules: ["modules"],
  ip_addresses: ["network", "network_artifacts", "iocs"],
  ports: ["network", "network_artifacts"],
  file_paths: ["processes", "modules", "handles"],
  handles: ["handles"],
  findings: ["findings"],
  iocs: ["iocs", "network_artifacts"],
};

export const STORED_ACTION_TITLE =
  "Uses analysis results already stored for this dump. Does not rescan the memory image.";

export function formatCapabilityList(ids: readonly string[]): string {
  const labels = ids.map((id) => capabilityLabel(id) ?? id);
  if (labels.length === 0) return "";
  if (labels.length === 1) return labels[0];
  if (labels.length === 2) return `${labels[0]} and ${labels[1]}`;
  return `${labels.slice(0, -1).join(", ")}, and ${labels[labels.length - 1]}`;
}

export function capabilityHasStoredData(
  coverage: AnalysisCoverage | undefined,
  id: string,
): boolean {
  const item = coverageItem(coverage, id);
  const kind = coverageLiveKind(item);
  if (kind === "in_progress" || kind === "partial") return true;
  return coverageWasExecuted(item) || coverageHasRows(item);
}

export function uncoveredSourceIds(
  coverage: AnalysisCoverage | undefined,
  sourceIds: readonly string[],
): string[] {
  return sourceIds.filter((id) => !capabilityHasStoredData(coverage, id));
}

/** True when no Complete Analysis capability is still in progress. */
export function evidenceAnalysisSettled(coverage?: AnalysisCoverage): boolean {
  if (!coverage) return true;
  for (const id of COMPLETE_ANALYSIS_IDS) {
    const kind = coverageLiveKind(coverageItem(coverage, id));
    if (kind === "in_progress" || kind === "partial") return false;
  }
  return true;
}

/** Missing sources after the last evidence-wide analysis has settled. */
export function settledMissingSourceIds(
  coverage: AnalysisCoverage | undefined,
  sourceIds: readonly string[],
): string[] {
  if (!evidenceAnalysisSettled(coverage)) return [];
  return uncoveredSourceIds(coverage, sourceIds);
}

export function searchFieldHasData(
  coverage: AnalysisCoverage | undefined,
  fieldId: string,
): boolean {
  const sources = SEARCH_FIELD_SOURCES[fieldId];
  if (!sources || sources.length === 0) return true;
  return sources.some((id) => capabilityHasStoredData(coverage, id));
}

export function isPartialEvidenceAnalysis(coverage?: AnalysisCoverage): boolean {
  if (!coverage) return false;
  let ready = 0;
  for (const id of COMPLETE_ANALYSIS_IDS) {
    if (capabilityHasStoredData(coverage, id)) ready += 1;
  }
  return ready > 0 && ready < COMPLETE_ANALYSIS_IDS.length;
}

export function storedActionNote(missingIds: readonly string[]): string {
  if (missingIds.length === 0) {
    return "This uses analysis results already stored for this dump. It does not rescan the memory image.";
  }
  if (missingIds.length >= 4) {
    return "This uses analysis results already stored for this dump — it does not rescan the memory image. Quick Triage and Custom Analysis only include the capabilities you selected, so results can be incomplete. Run Complete Analysis for a fuller set.";
  }
  const list = formatCapabilityList(missingIds);
  const verb = missingIds.length === 1 ? "was" : "were";
  return `This uses analysis results already stored for this dump — it does not rescan the memory image. ${list} ${verb} not included in the last analysis, so results can be incomplete. Run Complete Analysis for a fuller set.`;
}

export function limitedResultsNote(missingIds: readonly string[]): string {
  if (missingIds.length >= 4) {
    return "Run Complete Analysis for the full dataset. Quick Triage and Custom Analysis only store the capabilities you selected.";
  }
  const list = formatCapabilityList(missingIds);
  const verb = missingIds.length === 1 ? "was" : "were";
  return `Run Complete Analysis for the full dataset. ${list} ${verb} not collected in the last run.`;
}

export function findingsScopeNote(missingIds: readonly string[]): string {
  const base =
    "Findings come from collected command lines and Analyze Process, not a scan of the whole dump.";
  if (missingIds.length === 0) return base;
  return `${base} Run Complete Analysis to collect command lines for every process.`;
}

export function iocsScopeNote(missingIds: readonly string[]): string {
  if (missingIds.length === 0) {
    return "IOCs are extracted from stored process, module, network, and handle records. This does not rescan the dump.";
  }
  return "IOCs are extracted from records already stored, not from a rescan of the dump. Run Complete Analysis first so those records are available to extract from.";
}

export function searchScopeNote(missingIds: readonly string[]): string {
  if (missingIds.length === 0) {
    return "Search looks only at records already extracted. It does not search the raw memory image.";
  }
  return "Search looks only at records already extracted, not the raw memory image. Run Complete Analysis to extract the rest of the data you want to search.";
}
