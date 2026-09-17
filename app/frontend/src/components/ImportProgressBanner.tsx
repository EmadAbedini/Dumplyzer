import {
  formatElapsed,
  importStageLabel,
  isActiveJobStatus,
  jobPercent,
  jobPhase,
} from "../lib/analysisOptions";
import type { Job } from "../lib/types";
import { Button } from "./ui/button";

type Props = {
  job: Job;
  elapsedStartMs: number | null;
  nowMs: number;
  onCancel: () => void;
};

export function ImportProgressBanner({
  job,
  elapsedStartMs,
  nowMs,
  onCancel,
}: Props) {
  const percent = jobPercent(job);
  const phase = jobPhase(job);
  const hashing = phase === "hash";
  const cancellable = isActiveJobStatus(job.status);
  const width = percent == null ? undefined : `${Math.max(0, Math.min(100, percent))}%`;
  const elapsed = formatElapsed(elapsedStartMs, nowMs);
  const parts = [importStageLabel(job)];
  if (hashing && percent != null) {
    parts.push(`${Math.round(percent)}%`);
  }
  parts.push(`Elapsed ${elapsed}`);

  return (
    <div className="border-b border-border bg-surface-2 px-3 py-2">
      <div className="flex items-center gap-3">
        <div className="min-w-0 flex-1">
          <div className="text-sm font-medium">Importing Memory Image…</div>
          <div className="mt-0.5 truncate text-sm text-muted">{parts.join(" · ")}</div>
          <div className="mt-1.5 h-1.5 overflow-hidden rounded bg-background">
            <div
              className={
                percent == null
                  ? "h-full w-1/3 animate-pulse rounded bg-accent"
                  : "h-full rounded bg-accent"
              }
              style={width ? { width } : undefined}
            />
          </div>
        </div>
        {cancellable && (
          <Button size="sm" variant="outline" onClick={onCancel}>
            Cancel
          </Button>
        )}
      </div>
    </div>
  );
}
