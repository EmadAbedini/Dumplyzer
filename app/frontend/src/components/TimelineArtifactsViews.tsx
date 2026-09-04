import { useCallback, useEffect, useState } from "react";
import { engineCall, EngineClientError } from "../lib/api";
import type { TimelineEvent } from "../lib/types";
import { Badge } from "./ui/badge";
import { Button } from "./ui/button";

export function TimelineView({
  evidenceId,
  onOpenProcess,
  onError,
  refreshToken,
}: {
  evidenceId: string | null;
  onOpenProcess: (processId: string) => void;
  onError: (m: string) => void;
  refreshToken?: number;
}) {
  const [items, setItems] = useState<TimelineEvent[]>([]);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    if (!evidenceId) return;
    try {
      const res = await engineCall<{ items: TimelineEvent[] }>("timeline.list", {
        evidence_id: evidenceId,
      });
      setItems(res.items);
    } catch (e) {
      onError(e instanceof EngineClientError ? e.message : String(e));
    }
  }, [evidenceId, onError]);

  useEffect(() => {
    void load();
  }, [load, refreshToken]);

  const rebuild = async () => {
    if (!evidenceId) return;
    setBusy(true);
    try {
      const res = await engineCall<{ items: TimelineEvent[] }>("timeline.build", {
        evidence_id: evidenceId,
      });
      setItems(res.items);
    } catch (e) {
      onError(e instanceof EngineClientError ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  if (!evidenceId) {
    return <div className="p-4 text-sm text-muted">Import evidence first.</div>;
  }

  return (
    <div className="flex h-full flex-col text-xs">
      <div className="flex items-center gap-2 border-b border-border px-3 py-2">
        <div className="text-sm font-semibold">Timeline</div>
        <Button size="sm" onClick={() => void rebuild()} disabled={busy}>
          {busy ? "Building…" : "Rebuild from evidence"}
        </Button>
        <Button size="sm" variant="outline" onClick={() => void load()}>
          Refresh
        </Button>
        <span className="text-muted">
          observed = forensic field; inferred = heuristic/analysis time
        </span>
      </div>
      <div className="min-h-0 flex-1 overflow-auto">
        <table className="w-full text-left">
          <thead className="sticky top-0 bg-surface-2 text-muted">
            <tr>
              <th className="px-2 py-1.5">Time</th>
              <th className="px-2 py-1.5">Class</th>
              <th className="px-2 py-1.5">Kind</th>
              <th className="px-2 py-1.5">Summary</th>
              <th className="px-2 py-1.5">PID</th>
              <th className="px-2 py-1.5">Source</th>
            </tr>
          </thead>
          <tbody>
            {items.map((e) => (
              <tr key={e.id} className="border-t border-border/40 align-top">
                <td className="whitespace-nowrap px-2 py-1 font-mono">
                  {e.event_time ?? "—"}
                  <div className="text-[10px] text-muted">{e.time_precision}</div>
                </td>
                <td className="px-2 py-1">
                  <Badge
                    className={
                      e.classification === "inferred"
                        ? "border-warning text-warning"
                        : "border-success text-success"
                    }
                  >
                    {e.classification}
                  </Badge>
                </td>
                <td className="px-2 py-1 font-mono">{e.event_kind}</td>
                <td className="max-w-xl px-2 py-1">{e.summary}</td>
                <td className="px-2 py-1 font-mono">
                  {e.process_id ? (
                    <button
                      type="button"
                      className="text-accent hover:underline"
                      onClick={() => onOpenProcess(e.process_id!)}
                    >
                      {e.pid ?? "open"}
                    </button>
                  ) : (
                    (e.pid ?? "—")
                  )}
                </td>
                <td className="px-2 py-1 text-muted">
                  {e.source_plugin ?? e.source_table ?? "—"}
                </td>
              </tr>
            ))}
            {items.length === 0 && (
              <tr>
                <td colSpan={6} className="px-3 py-6 text-muted">
                  No timeline events. Analyze evidence, then Rebuild.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
