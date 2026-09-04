import { useCallback, useEffect, useState } from "react";
import { engineCall, EngineClientError } from "../lib/api";
import type { Job } from "../lib/types";
import { Badge } from "./ui/badge";
import { Button } from "./ui/button";

type Props = {
  evidenceId: string | null;
  refreshToken?: number;
  onError: (msg: string) => void;
};

export function JobsView({ evidenceId, refreshToken, onError }: Props) {
  const [jobs, setJobs] = useState<Job[]>([]);

  const load = useCallback(async () => {
    try {
      const res = await engineCall<{ items: Job[] }>("jobs.list", {
        evidence_id: evidenceId ?? undefined,
        limit: 100,
      });
      setJobs(res.items);
    } catch (err) {
      onError(err instanceof EngineClientError ? err.message : String(err));
    }
  }, [evidenceId, onError]);

  useEffect(() => {
    void load();
    const t = window.setInterval(() => void load(), 2000);
    return () => window.clearInterval(t);
  }, [load, refreshToken]);

  const cancel = async (id: string) => {
    try {
      await engineCall("jobs.cancel", { job_id: id });
      await load();
    } catch (err) {
      onError(err instanceof EngineClientError ? err.message : String(err));
    }
  };

  return (
    <div className="flex h-full flex-col">
      <div className="flex items-center gap-2 border-b border-border px-3 py-2">
        <div className="text-sm font-semibold">Jobs</div>
        <div className="text-xs text-muted">Progress is indeterminate unless a plugin reports more</div>
        <Button size="sm" variant="outline" className="ml-auto" onClick={() => void load()}>
          Refresh
        </Button>
      </div>
      <div className="min-h-0 flex-1 overflow-auto">
        <table className="w-full text-left text-xs">
          <thead className="sticky top-0 bg-surface-2 text-muted">
            <tr>
              <th className="px-2 py-1.5">Status</th>
              <th className="px-2 py-1.5">Kind</th>
              <th className="px-2 py-1.5">PID</th>
              <th className="px-2 py-1.5">Message</th>
              <th className="px-2 py-1.5">Created</th>
              <th className="px-2 py-1.5" />
            </tr>
          </thead>
          <tbody>
            {jobs.map((j) => (
              <tr key={j.id} className="border-t border-border/40">
                <td className="px-2 py-1">
                  <Badge
                    className={
                      j.status === "failed"
                        ? "border-danger text-danger"
                        : j.status === "completed"
                          ? "border-success text-success"
                          : j.status === "running"
                            ? "border-accent text-accent"
                            : ""
                    }
                  >
                    {j.status}
                  </Badge>
                </td>
                <td className="px-2 py-1 font-mono">{j.kind}</td>
                <td className="px-2 py-1 font-mono">{j.pid ?? "—"}</td>
                <td className="max-w-md truncate px-2 py-1">{j.message ?? "—"}</td>
                <td className="px-2 py-1 font-mono">{j.created_at}</td>
                <td className="px-2 py-1">
                  {(j.status === "queued" || j.status === "running") && (
                    <Button size="sm" variant="outline" onClick={() => void cancel(j.id)}>
                      Cancel
                    </Button>
                  )}
                </td>
              </tr>
            ))}
            {jobs.length === 0 && (
              <tr>
                <td colSpan={6} className="px-3 py-6 text-muted">
                  No jobs yet.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
