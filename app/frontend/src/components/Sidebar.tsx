import type { LucideIcon } from "lucide-react";
import {
  Boxes,
  Crosshair,
  Download,
  FileSearch,
  Fingerprint,
  History,
  Info,
  LayoutDashboard,
  ListTodo,
  ListTree,
  MemoryStick,
  Network,
  Puzzle,
  Search,
  Settings,
  ShieldAlert,
} from "lucide-react";
import type { AnalysisCoverage, NavId } from "../lib/types";
import { coverageForNav, coverageLiveKind } from "../lib/analysisCoverage";
import { cn } from "../lib/utils";
import { CoverageStatus } from "./CoverageStatus";

export const IMPORTING_NAV_HINT =
  "Analysis views are available after the memory image import finishes.";

export const PLUGIN_JOB_BUSY_HINT =
  "Plugin execution starts a new job and cannot run while analysis is in progress.";

export const EXPORT_JOB_BUSY_HINT =
  "Export starts a new job and cannot run while analysis is in progress.";

export const EXPORT_NEEDS_ANALYSIS_HINT =
  "Generate is available after analysis completes. Reports include only the capabilities that already ran.";

const PRIMARY_NAV: { id: NavId; label: string; icon: LucideIcon }[] = [
  { id: "overview", label: "Overview", icon: LayoutDashboard },
  { id: "processes", label: "Processes", icon: ListTree },
  { id: "network", label: "Network", icon: Network },
  { id: "modules", label: "Modules", icon: Boxes },
  { id: "memory", label: "Memory", icon: MemoryStick },
  { id: "findings", label: "Findings", icon: ShieldAlert },
  { id: "iocs", label: "IOCs", icon: Crosshair },
  { id: "search", label: "Search", icon: Search },
  { id: "timeline", label: "Timeline", icon: History },
  { id: "artifacts", label: "Carved Data", icon: FileSearch },
  { id: "signatures", label: "Signatures", icon: Fingerprint },
  { id: "jobs", label: "Jobs", icon: ListTodo },
  { id: "plugins", label: "Plugins", icon: Puzzle },
  { id: "export", label: "Export", icon: Download },
];

const SECONDARY_NAV: { id: NavId; label: string; icon: LucideIcon }[] = [
  { id: "settings", label: "Settings", icon: Settings },
  { id: "about", label: "About", icon: Info },
];

const NAV_OPEN_DURING_IMPORT = new Set<NavId>(["jobs"]);

export function navStartsConcurrentJob(id: NavId): boolean {
  return id === "plugins" || id === "export";
}

export function navLockedDuringImport(id: NavId): boolean {
  return !NAV_OPEN_DURING_IMPORT.has(id);
}

/** Pages that stay reachable while an analysis job runs. Import keeps only Jobs reachable. */
export function navOpenDuringJobs(
  id: NavId,
  _coverage?: AnalysisCoverage,
  importing = false,
): boolean {
  if (NAV_OPEN_DURING_IMPORT.has(id)) return true;
  if (importing) return false;
  return true;
}

function concurrentJobHint(id: NavId): string | undefined {
  if (id === "plugins") return PLUGIN_JOB_BUSY_HINT;
  if (id === "export") return EXPORT_JOB_BUSY_HINT;
  return undefined;
}

const SECTION_TITLE: Partial<Record<NavId, string>> = {
  processes: "Processes",
  process_dive: "Process Deep Dive",
  network: "Network",
  modules: "Modules / DLLs",
  memory: "Memory / VAD",
  findings: "Findings",
  iocs: "IOCs",
  search: "Search",
  timeline: "Timeline",
  artifacts: "Carved Data",
  signatures: "Signatures",
  plugins: "Plugins",
  export: "Export",
};

export function navSectionTitle(id: NavId): string {
  return (
    SECTION_TITLE[id] ??
    PRIMARY_NAV.find((item) => item.id === id)?.label ??
    SECONDARY_NAV.find((item) => item.id === id)?.label ??
    id
  );
}

type Props = {
  active: NavId;
  onSelect: (id: NavId) => void;
  evidenceLabel?: string | null;
  coverage?: AnalysisCoverage;
  jobsRunning?: boolean;
  jobsPercent?: string | null;
  importing?: boolean;
};

function NavButton({
  id,
  label,
  icon: Icon,
  active,
  onSelect,
  coverage,
  running,
  percent,
  importing = false,
  analysisBusy = false,
}: {
  id: NavId;
  label: string;
  icon: LucideIcon;
  active: boolean;
  onSelect: (id: NavId) => void;
  coverage?: ReturnType<typeof coverageForNav>;
  running?: boolean;
  percent?: string | null;
  importing?: boolean;
  analysisBusy?: boolean;
}) {
  const showCoverage = coverage !== undefined;
  const importLocked = importing && navLockedDuringImport(id);
  const concurrentBusy = analysisBusy && !importing && navStartsConcurrentJob(id);
  const live = coverageLiveKind(coverage);
  const muted = importLocked || live === "not_analyzed";
  const title = importLocked
    ? IMPORTING_NAV_HINT
    : concurrentBusy
      ? concurrentJobHint(id)
      : undefined;
  return (
    <button
      type="button"
      aria-disabled={importLocked}
      onClick={() => {
        if (importLocked) return;
        onSelect(id);
      }}
      title={title}
      className={cn(
        "flex min-h-9 w-full items-center gap-2 rounded-md px-2.5 py-2 text-left text-sm transition-colors",
        importLocked ? "cursor-not-allowed opacity-60" : "cursor-pointer",
        muted && !active && !importLocked ? "text-muted/80" : null,
        active
          ? "bg-surface-2 font-medium text-foreground"
          : importLocked
            ? "text-muted"
            : "text-muted hover:bg-surface-2/70 hover:text-foreground",
      )}
    >
      <Icon className="h-4 w-4 shrink-0" strokeWidth={1.75} aria-hidden />
      <span className="min-w-0 flex-1 overflow-clip py-0.5 leading-normal text-ellipsis whitespace-nowrap [overflow-clip-margin:0.22em]">
        {label}
      </span>
      {running ? (
        <span className="inline-flex shrink-0 items-center gap-1 tabular-nums text-xs leading-none text-accent">
          {percent ? <span>{percent}</span> : null}
          <span
            className="h-3.5 w-3.5 shrink-0 animate-spin rounded-full border-2 border-border border-t-accent"
            role="status"
            aria-label={percent ? `Jobs running ${percent}` : "Jobs running"}
          />
        </span>
      ) : concurrentBusy ? (
        <span className="text-[0.7rem] text-muted" title={title}>
          Busy
        </span>
      ) : showCoverage ? (
        <span className="shrink-0 tabular-nums text-right text-xs leading-none">
          <CoverageStatus item={coverage} compact />
        </span>
      ) : null}
    </button>
  );
}

export function Sidebar({
  active,
  onSelect,
  evidenceLabel,
  coverage,
  jobsRunning = false,
  jobsPercent = null,
  importing = false,
}: Props) {
  const analysisBusy = jobsRunning && !importing;
  return (
    <aside className="flex w-[calc(13rem+15px)] shrink-0 flex-col border-r border-border bg-surface">
      <div className="border-b border-border px-3 py-2.5">
        <div className="text-[0.72rem] font-medium uppercase tracking-wider text-muted">Evidence</div>
        <div className="mt-0.5 truncate text-sm" title={evidenceLabel ?? undefined}>
          {evidenceLabel ?? "None loaded"}
        </div>
      </div>
      <nav className="flex min-h-0 flex-1 flex-col gap-0.5 overflow-y-auto p-1.5">
        {PRIMARY_NAV.map((item) => (
          <NavButton
            key={item.id}
            id={item.id}
            label={item.label}
            icon={item.icon}
            active={active === item.id || (item.id === "processes" && active === "process_dive")}
            onSelect={onSelect}
            coverage={coverageForNav(coverage, item.id)}
            running={item.id === "jobs" && jobsRunning}
            percent={item.id === "jobs" ? jobsPercent : null}
            importing={importing}
            analysisBusy={analysisBusy}
          />
        ))}
      </nav>
      <div className="mt-auto flex flex-col gap-0.5 border-t border-border p-1.5 pb-9">
        {SECONDARY_NAV.map((item) => (
          <NavButton
            key={item.id}
            id={item.id}
            label={item.label}
            icon={item.icon}
            active={active === item.id}
            onSelect={onSelect}
            importing={importing}
          />
        ))}
      </div>
    </aside>
  );
}
