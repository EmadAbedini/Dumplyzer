import { startTransition, useCallback, useEffect, useRef, useState } from "react";
import { engineCall, EngineClientError } from "../lib/api";
import {
  isActiveJobStatus,
  isJobCancelling,
  isTerminalJobStatus,
  jobStatusLabel,
} from "../lib/analysisOptions";
import {
  jobAnalysisLabel,
  jobAnalysisTitle,
  jobFileName,
  jobStatusDisplay,
  jobTableMessage,
} from "../lib/jobDisplay";
import { useTableSort } from "../lib/tableSort";
import { cn } from "../lib/utils";
import type { Job } from "../lib/types";
import { Badge } from "./ui/badge";
import { Button } from "./ui/button";
import { SortableTh } from "./SortableTh";
import { RefreshButton, StatusToast, useStatusToast } from "./StatusToast";

type Props = {
  evidenceFilename?: string | null;
  refreshToken?: number;
  onError: (msg: string) => void;
};

function statusBadgeClass(label: string): string {
  if (label === "failed") return "border-danger text-danger";
  if (label === "completed") return "border-success text-success";
  if (label === "running") return "border-accent text-accent";
  if (label === "cancelling") return "border-warning text-warning";
  return "";
}

export function JobsView({ evidenceFilename, refreshToken, onError }: Props) {
  const [jobs, setJobs] = useState<Job[]>([]);
  const [ready, setReady] = useState(false);
  const [cancellingIds, setCancellingIds] = useState<Set<string>>(() => new Set());
  const [nowMs, setNowMs] = useState(() => Date.now());
  const { toast, showToast } = useStatusToast();
  const loadInFlight = useRef(false);
  const loadAgain = useRef(false);

  const load = useCallback(async () => {
    if (loadInFlight.current) {
      loadAgain.current = true;
      return;
    }
    loadInFlight.current = true;
    try {
      do {
        loadAgain.current = false;
        try {
          const res = await engineCall<{ items: Job[] }>("jobs.list", {
            limit: 100,
          });
          const items = res.items.filter(
            (job) =>
              job.kind !== "kernel_symbols_fetch" &&
              job.error?.code !== "kernel_symbols_required",
          );
          startTransition(() => {
            setJobs(items);
            setReady(true);
            setCancellingIds((prev) => {
              if (prev.size === 0) return prev;
              const byId = new Map(items.map((job) => [job.id, job]));
              const next = new Set<string>();
              for (const id of prev) {
                const job = byId.get(id);
                if (job && isActiveJobStatus(job.status)) next.add(id);
              }
              return next;
            });
          });
        } catch (err) {
          setReady(true);
          onError(err instanceof EngineClientError ? err.message : String(err));
        }
      } while (loadAgain.current);
    } finally {
      loadInFlight.current = false;
      if (loadAgain.current) {
        void load();
      }
    }
  }, [onError]);

  useEffect(() => {
    void load();
  }, [load, refreshToken]);

  useEffect(() => {
    const t = window.setInterval(() => void load(), 2000);
    return () => window.clearInterval(t);
  }, [load]);

  const sortValue = useCallback(
    (job: Job, key: string) => {
      if (key === "status") return jobStatusLabel(job, cancellingIds);
      if (key === "analysis") return jobAnalysisLabel(job);
      if (key === "file") return jobFileName(job, evidenceFilename);
      if (key === "message") return jobTableMessage(job, cancellingIds).text;
      return "";
    },
    [cancellingIds, evidenceFilename],
  );
  const { sorted, sort, toggle } = useTableSort(jobs, sortValue);

  useEffect(() => {
    if (!jobs.some((job) => isActiveJobStatus(job.status))) return;
    const timer = window.setInterval(() => setNowMs(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, [jobs]);

  const cancel = (id: string) => {
    const current = jobs.find((job) => job.id === id);
    if (current && (isJobCancelling(current, cancellingIds) || isTerminalJobStatus(current.status))) {
      return;
    }
    setCancellingIds((prev) => {
      if (prev.has(id)) return prev;
      const next = new Set(prev);
      next.add(id);
      return next;
    });
    void engineCall("jobs.cancel", { job_id: id })
      .then(() => void load())
      .catch((err: unknown) => {
        setCancellingIds((prev) => {
          if (!prev.has(id)) return prev;
          const next = new Set(prev);
          next.delete(id);
          return next;
        });
        onError(err instanceof EngineClientError ? err.message : String(err));
      });
  };

  return (
    <div className="flex h-full flex-col">
      <div className="flex items-center gap-2 border-b border-border px-3 py-2">
        <div className="text-sm font-semibold">Jobs</div>
        <div className="text-sm text-muted">
          Status updates while analysis and jobs run
        </div>
        <div className="ml-auto">
          <RefreshButton onRefresh={load} doneMessage="Jobs updated" showToast={showToast} />
        </div>
      </div>
      <div className="min-h-0 flex-1 overflow-auto">
        <table className="app-result-table app-jobs-table w-full text-center text-xs">
          <colgroup>
            <col className="jobs-status" />
            <col className="jobs-analysis" />
            <col className="jobs-file" />
            <col className="jobs-message" />
            <col className="jobs-actions" />
          </colgroup>
          <thead className="sticky top-0 bg-surface-2 text-muted">
            <tr>
              <SortableTh label="Status" column="status" sort={sort} onToggle={toggle} />
              <SortableTh label="Analysis" column="analysis" sort={sort} onToggle={toggle} />
              <SortableTh label="File name" column="file" sort={sort} onToggle={toggle} />
              <SortableTh label="Message" column="message" sort={sort} onToggle={toggle} />
              <th className="jobs-action-col px-2 py-1.5">Action</th>
            </tr>
          </thead>
          <tbody>
            {sorted.map((j) => {
              const cancelling = isJobCancelling(j, cancellingIds);
              const statusLabel = jobStatusLabel(j, cancellingIds);
              const canCancel = isActiveJobStatus(j.status);
              const analysis = jobAnalysisLabel(j);
              const fileName = jobFileName(j, evidenceFilename);
              const message = jobTableMessage(j, cancellingIds, nowMs);
              return (
              <tr key={j.id} className="border-t border-border/40">
                <td className="jobs-status-cell px-2 py-1">
                  <Badge className={cn("jobs-status-badge", statusBadgeClass(statusLabel))}>
                    {jobStatusDisplay(statusLabel)}
                  </Badge>
                </td>
                <td className="px-2 py-1" title={jobAnalysisTitle(j)}>
                  {analysis}
                </td>
                <td className="jobs-file-cell px-2 py-1" title={fileName === "—" ? undefined : fileName}>
                  {fileName}
                </td>
                <td className="jobs-message-cell px-2 py-1 tabular-nums" title={message.title}>
                  {message.text}
                </td>
                <td className="jobs-action-col px-2 py-1">
                  {canCancel && (
                    <Button
                      size="sm"
                      variant="outline"
                      className="jobs-cancel-btn h-6 px-2 border-danger/50 bg-danger/10 text-danger hover:border-danger hover:bg-danger/20"
                      disabled={cancelling}
                      onClick={() => cancel(j.id)}
                    >
                      {cancelling ? "Cancelling…" : "Cancel"}
                    </Button>
                  )}
                </td>
              </tr>
              );
            })}
            {jobs.length === 0 && (
              <tr className="app-row-empty">
                <td colSpan={5} className="px-3 py-6 text-muted">
                  {ready ? "No jobs yet." : "Loading jobs…"}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
      <StatusToast message={toast} />
    </div>
  );
}
