import type { AnalysisCoverage, CapabilityCoverage, NavId, Overview } from "./types";

const NAV_CAPABILITY: Partial<Record<NavId, string>> = {
  processes: "processes",
  process_dive: "processes",
  network: "network",
  modules: "modules",
  memory: "memory_vad",
  findings: "findings",
  iocs: "iocs",
  timeline: "timeline",
  artifacts: "artifacts",
  signatures: "signatures",
};

export const SEARCHABLE_IDS = [
  "processes",
  "command_lines",
  "modules",
  "network",
  "network_artifacts",
  "findings",
  "iocs",
  "timeline",
] as const;

export type CoverageLiveKind =
  | "failed"
  | "analyzed"
  | "analyzed_zero"
  | "partial"
  | "in_progress"
  | "not_analyzed";

/** Always-visible Overview capability rows. Never filter this list by coverage state. */
export const OVERVIEW_COVERAGE_ROWS: { id: string; label: string }[] = [
  { id: "processes", label: "Processes" },
  { id: "command_lines", label: "Command Lines" },
  { id: "network", label: "Network" },
  { id: "network_artifacts", label: "Network Artifacts" },
  { id: "modules", label: "Modules" },
  { id: "handles", label: "Handles" },
  { id: "findings", label: "Findings" },
  { id: "iocs", label: "IOCs" },
  { id: "timeline", label: "Timeline" },
  { id: "memory_vad", label: "Memory / VAD" },
  { id: "artifacts", label: "Carved Data" },
];

export const EMPTY_COVERAGE: AnalysisCoverage = {
  items: {},
  executed: [],
  failed: [],
};

function notAnalyzed(id: string): CapabilityCoverage {
  return { id, state: "not_analyzed", count: null };
}

export function coverageFromOverview(overview: Overview | null | undefined): AnalysisCoverage | undefined {
  if (!overview) return undefined;
  return overview.coverage ?? EMPTY_COVERAGE;
}

export function coverageItem(
  coverage: AnalysisCoverage | undefined,
  id: string,
): CapabilityCoverage {
  const item = coverage?.items?.[id] ?? notAnalyzed(id);
  if (id !== "command_lines") return item;
  if (item.state === "failed") return item;
  if (item.count != null) return item;
  return notAnalyzed(id);
}

export function coverageForNav(
  coverage: AnalysisCoverage | undefined,
  nav: NavId,
): CapabilityCoverage | undefined {
  if (nav === "search") {
    if (!coverage) return undefined;
    if (coverageHasSearchableData(coverage)) return undefined;
    if (SEARCHABLE_IDS.some((id) => coverageLiveKind(coverageItem(coverage, id)) === "in_progress")) {
      return { id: "search", state: "not_analyzed", count: 0 };
    }
    return notAnalyzed("search");
  }
  const id = NAV_CAPABILITY[nav];
  if (!id) return undefined;
  if (!coverage) return undefined;
  return coverageItem(coverage, id);
}

export function coverageEmptyMessage(
  item: CapabilityCoverage | undefined,
  analyzedZero: string,
  notAnalyzedText: string,
  failed: string,
): string {
  if (item?.state === "failed") return failed;
  if (item?.state === "analyzed_zero" || item?.state === "analyzed") return analyzedZero;
  return notAnalyzedText;
}

export function coverageWasExecuted(item: CapabilityCoverage | undefined): boolean {
  return item?.state === "analyzed" || item?.state === "analyzed_zero";
}

export function coverageLiveKind(item: CapabilityCoverage | undefined): CoverageLiveKind {
  if (!item) return "not_analyzed";
  if (item.state === "failed") return "failed";
  if (item.state === "analyzed") return "analyzed";
  if (item.state === "analyzed_zero") return "analyzed_zero";
  if (item.state === "not_analyzed" && item.count != null) {
    return item.count > 0 ? "partial" : "in_progress";
  }
  return "not_analyzed";
}

export function coverageIsUpdating(item: CapabilityCoverage | undefined): boolean {
  const kind = coverageLiveKind(item);
  return kind === "in_progress" || kind === "partial";
}

export function coverageCanExport(coverage?: AnalysisCoverage): boolean {
  if (!coverage) return false;
  if (Object.values(coverage.items).some((item) => coverageIsUpdating(item))) {
    return false;
  }
  return coverage.executed.length > 0 || coverage.failed.length > 0;
}

export function coverageHasRows(item: CapabilityCoverage | undefined): boolean {
  return (item?.count ?? 0) > 0;
}

export function coverageHasSearchableData(coverage?: AnalysisCoverage): boolean {
  if (!coverage) return false;
  return SEARCHABLE_IDS.some((id) => {
    const item = coverageItem(coverage, id);
    return coverageWasExecuted(item) || coverageHasRows(item);
  });
}

export function coverageProcessListReady(
  coverage?: AnalysisCoverage,
  processCount = 0,
): boolean {
  const item = coverageItem(coverage, "processes");
  return coverageWasExecuted(item) || coverageHasRows(item) || processCount > 0;
}

export function coverageRefreshKey(coverage?: AnalysisCoverage): string {
  if (!coverage) return "";
  return Object.keys(coverage.items)
    .sort()
    .map((id) => {
      const item = coverage.items[id];
      return `${id}:${item.state}:${item.count ?? ""}`;
    })
    .join("|");
}

export function coverageResultCaption(
  item: CapabilityCoverage | undefined,
  rowCount: number,
  filteredCount?: number,
): string | null {
  const kind = coverageLiveKind(item);
  const n = rowCount;
  const filtered = filteredCount != null && filteredCount !== n ? `${filteredCount.toLocaleString()} / ` : "";
  if (kind === "partial" || (kind === "in_progress" && n > 0)) {
    return `${filtered}${n.toLocaleString()} results · Updating…`;
  }
  if (kind === "analyzed") {
    return `${filtered}${n.toLocaleString()} results ✓`;
  }
  if (kind === "analyzed_zero") return "0 results ✓";
  if (kind === "in_progress") return "Updating…";
  if (kind === "failed") return "Failed";
  if (n > 0) {
    return filteredCount != null ? `${filteredCount.toLocaleString()} / ${n.toLocaleString()}` : n.toLocaleString();
  }
  return null;
}

export function processScopedEmptyMessage(
  evidenceItem: CapabilityCoverage | undefined,
  processTargetedCompleted: boolean,
  analyzedZero: string,
  notAnalyzedText: string,
  failed: string,
  processFailed = false,
): string {
  if (processTargetedCompleted) return analyzedZero;
  if (processFailed) return failed;
  return coverageEmptyMessage(evidenceItem, analyzedZero, notAnalyzedText, failed);
}
