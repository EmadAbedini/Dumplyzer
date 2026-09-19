import type { ReactNode } from "react";
import { CircleAlert, CircleDashed, Info } from "lucide-react";
import { coverageLiveKind } from "../lib/analysisCoverage";
import type { CapabilityCoverage } from "../lib/types";
import { cn } from "../lib/utils";

const NOT_ANALYZED_DETAIL =
  "This data was not collected in the analysis you ran.";
const NOT_ANALYZED_HINT =
  "Quick Triage only collects processes. Run Complete Analysis, or select this capability in Custom Analysis.";

const IN_PROGRESS_HINT = "Results will appear here automatically when available.";

function LiveSpinner({ label }: { label: string }) {
  return (
    <span
      className="h-3.5 w-3.5 shrink-0 animate-spin rounded-full border-2 border-border border-t-accent"
      role="status"
      aria-label={label}
    />
  );
}

export function CoverageStatus({
  item,
  compact = false,
}: {
  item: CapabilityCoverage | undefined;
  compact?: boolean;
}) {
  const kind = coverageLiveKind(item);
  const count = item?.count;

  if (kind === "in_progress") {
    const label = "Analysis in progress";
    return (
      <span className="inline-flex items-center gap-1 text-accent" title={label} aria-label={label}>
        <LiveSpinner label={label} />
      </span>
    );
  }

  if (kind === "partial") {
    const n = count ?? 0;
    const label = `${n.toLocaleString()} so far · Updating…`;
    return (
      <span className="inline-flex items-center gap-1" title={label} aria-label={label}>
        <span>{n.toLocaleString()}</span>
        {compact ? <LiveSpinner label={label} /> : <span className="text-muted">Updating…</span>}
      </span>
    );
  }

  if (kind === "has_results") {
    const n = count ?? 0;
    const label = `${n.toLocaleString()} records`;
    return (
      <span className="tabular-nums" title={label} aria-label={label}>
        {n.toLocaleString()}
      </span>
    );
  }

  if (kind === "not_analyzed") {
    if (compact) {
      return (
        <span className="text-muted" title="Not analyzed" aria-label="Not analyzed">
          —
        </span>
      );
    }
    return (
      <span
        className="text-muted"
        title="Not collected in the last analysis."
      >
        Not analyzed
      </span>
    );
  }

  if (kind === "failed") {
    return (
      <span
        className={cn("text-danger", compact ? "text-[0.75rem] font-medium" : "")}
        title="Analysis failed."
      >
        Failed
      </span>
    );
  }

  if (kind === "analyzed_zero") {
    return (
      <span className="inline-flex items-center gap-1" title="Analysis completed and found no records.">
        <span>0</span>
        <span className="text-[0.7rem] text-success" aria-hidden>
          ✓
        </span>
      </span>
    );
  }

  const label = count != null ? `${count.toLocaleString()} analyzed` : "Analyzed";
  return (
    <span className="inline-flex items-center gap-1" title="Analyzed with results." aria-label={label}>
      {count != null ? <span>{count.toLocaleString()}</span> : null}
      <span className="text-[0.7rem] text-success" aria-hidden>
        ✓
      </span>
    </span>
  );
}

export function AnalysisScopeNote({ children }: { children: ReactNode }) {
  return (
    <div className="analysis-profile-note flex min-w-0 items-start gap-2 overflow-hidden rounded-md px-2.5 py-2 text-xs leading-snug">
      <Info size={14} className="mt-0.5 shrink-0" aria-hidden />
      <p className="min-w-0 flex-1 wrap-anywhere">{children}</p>
    </div>
  );
}

export function CoverageEmptyState({
  item,
  title,
  analyzedZeroDetail,
  analyzedZeroHint,
  notAnalyzedDetail = NOT_ANALYZED_DETAIL,
  notAnalyzedHint,
  failedDetail,
  inProgressDetail,
  showTitle = true,
}: {
  item: CapabilityCoverage | undefined;
  title: string;
  analyzedZeroDetail: string;
  analyzedZeroHint?: string;
  notAnalyzedDetail?: string;
  notAnalyzedHint?: string;
  failedDetail: string;
  inProgressDetail?: string;
  showTitle?: boolean;
}) {
  const kind = coverageLiveKind(item);
  let heading = "Not analyzed";
  let headingClass = "text-foreground";
  let detail = notAnalyzedDetail;
  let hint: string | null = notAnalyzedHint ?? null;
  let live = false;
  if (kind === "failed") {
    heading = "Failed";
    headingClass = "text-danger";
    detail = failedDetail;
    hint = null;
  } else if (kind === "analyzed" || kind === "analyzed_zero") {
    heading = "0 results";
    headingClass = "text-foreground";
    detail = analyzedZeroDetail;
    hint = analyzedZeroHint ?? null;
  } else if (kind === "in_progress" || kind === "partial") {
    heading = "Analysis in progress";
    headingClass = "text-foreground";
    detail = inProgressDetail ?? `${title} are still being analyzed.`;
    hint = IN_PROGRESS_HINT;
    live = true;
  } else if (hint == null && notAnalyzedDetail === NOT_ANALYZED_DETAIL) {
    hint = NOT_ANALYZED_HINT;
  }
  return (
    <div className="flex min-h-0 flex-1 flex-col">
      {showTitle ? (
        <div className="border-b border-border px-3 py-2 text-sm font-semibold">{title}</div>
      ) : null}
      <div
        className="flex min-h-[16rem] flex-1 flex-col items-center justify-center px-6 py-16 text-center"
        role={live ? "status" : undefined}
        aria-live={live ? "polite" : undefined}
        aria-busy={live || undefined}
      >
        <div
          className="flex h-12 w-12 items-center justify-center rounded-full bg-surface-2"
          aria-hidden
        >
          {live ? (
            <span className="h-6 w-6 animate-spin rounded-full border-[2.5px] border-border border-t-accent" />
          ) : kind === "failed" ? (
            <CircleAlert className="h-5 w-5 text-danger" strokeWidth={1.75} />
          ) : kind === "analyzed" || kind === "analyzed_zero" ? (
            <span className="text-sm font-medium text-foreground">0</span>
          ) : (
            <CircleDashed className="h-5 w-5 text-muted" strokeWidth={1.75} />
          )}
        </div>
        <div className={cn("mt-4 text-sm font-semibold", headingClass)}>{heading}</div>
        {live ? (
          <div className="mt-3 h-1.5 w-52 overflow-hidden rounded-full bg-surface-2" aria-hidden>
            <div className="list-loading-bar h-full w-2/5 rounded-full bg-accent" />
          </div>
        ) : null}
        <p className="mt-4 max-w-md text-sm leading-5 text-muted">{detail}</p>
        {hint ? <p className="mt-3 max-w-md text-xs leading-5 text-muted">{hint}</p> : null}
      </div>
    </div>
  );
}

export function CenteredLoading({ label = "Loading…" }: { label?: string }) {
  return (
    <div
      className="flex min-h-[16rem] flex-1 flex-col items-center justify-center gap-3 px-4 py-16"
      role="status"
      aria-live="polite"
      aria-busy="true"
    >
      <div
        className="h-9 w-9 shrink-0 animate-spin rounded-full border-[2.5px] border-border border-t-accent"
        aria-hidden
      />
      <div className="h-1.5 w-52 overflow-hidden rounded-full bg-surface-2">
        <div className="list-loading-bar h-full w-2/5 rounded-full bg-accent" />
      </div>
      <div className="text-sm text-muted">{label}</div>
    </div>
  );
}

export function ImportEvidenceState({
  title,
  message = "Import evidence first.",
}: {
  title: string;
  message?: string;
}) {
  return (
    <div className="flex min-h-0 flex-col">
      <div className="border-b border-border px-3 py-2 text-sm font-semibold">{title}</div>
      <div className="p-6 text-sm text-muted">{message}</div>
    </div>
  );
}

export function ListLoadingState({ title }: { title: string }) {
  return (
    <div className="flex min-h-full flex-1 flex-col">
      <div className="flex items-center gap-2 border-b border-border px-3 py-2">
        <div className="text-sm font-semibold">{title}</div>
      </div>
      <CenteredLoading />
    </div>
  );
}

export function coverageShowsEmptyPanel(item: CapabilityCoverage | undefined, rowCount: number): boolean {
  if (rowCount > 0) return false;
  const state = item?.state ?? "not_analyzed";
  return state === "not_analyzed" || state === "failed" || state === "analyzed_zero" || state === "analyzed";
}
