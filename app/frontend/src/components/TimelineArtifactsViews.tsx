import { useCallback, useEffect, useState } from "react";
import { engineCall, EngineClientError } from "../lib/api";
import type { Artifact, TimelineEvent } from "../lib/types";
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

export function ArtifactsView({
  evidenceId,
  onError,
  refreshToken,
}: {
  evidenceId: string | null;
  onError: (m: string) => void;
  refreshToken?: number;
}) {
  const [items, setItems] = useState<Artifact[]>([]);
  const [detail, setDetail] = useState<Artifact | null>(null);

  const load = useCallback(async () => {
    if (!evidenceId) return;
    try {
      const res = await engineCall<{ items: Artifact[] }>("artifacts.list", {
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

  const openDetail = async (id: string) => {
    try {
      const a = await engineCall<Artifact>("artifacts.get", { artifact_id: id });
      setDetail(a);
    } catch (e) {
      onError(e instanceof EngineClientError ? e.message : String(e));
    }
  };

  if (!evidenceId) {
    return <div className="p-4 text-sm text-muted">Import evidence first.</div>;
  }

  return (
    <div className="flex h-full min-h-0 text-xs">
      <div className="min-w-0 flex-1 overflow-auto">
        <div className="flex items-center gap-2 border-b border-border px-3 py-2">
          <div className="text-sm font-semibold">Artifacts</div>
          <Button size="sm" variant="outline" onClick={() => void load()}>
            Refresh
          </Button>
          <span className="text-muted">Stored under controlled app data; never auto-executed</span>
        </div>
        <table className="w-full text-left">
          <thead className="sticky top-0 bg-surface-2 text-muted">
            <tr>
              <th className="px-2 py-1.5">Filename</th>
              <th className="px-2 py-1.5">SHA-256</th>
              <th className="px-2 py-1.5">Size</th>
              <th className="px-2 py-1.5">Type</th>
              <th className="px-2 py-1.5">PID</th>
              <th className="px-2 py-1.5">Method</th>
              <th className="px-2 py-1.5">Extracted</th>
            </tr>
          </thead>
          <tbody>
            {items.map((a) => (
              <tr
                key={a.id}
                className="cursor-pointer border-t border-border/40 hover:bg-surface-2/50"
                onClick={() => void openDetail(a.id)}
              >
                <td className="px-2 py-1 font-mono">{a.filename}</td>
                <td className="max-w-[14rem] truncate px-2 py-1 font-mono">{a.sha256}</td>
                <td className="px-2 py-1 font-mono">{a.size_bytes.toLocaleString()}</td>
                <td className="px-2 py-1">{a.file_type ?? "—"}</td>
                <td className="px-2 py-1 font-mono">{a.pid ?? "—"}</td>
                <td className="px-2 py-1 text-muted">{a.extraction_method}</td>
                <td className="px-2 py-1 font-mono">{a.extracted_at}</td>
              </tr>
            ))}
            {items.length === 0 && (
              <tr>
                <td colSpan={7} className="px-3 py-6 text-muted">
                  No artifacts. Extract a VAD region from Memory explorer.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
      <aside className="w-96 shrink-0 overflow-auto border-l border-border p-3">
        {!detail ? (
          <div className="text-muted">Select an artifact for provenance.</div>
        ) : (
          <div className="space-y-2">
            <div className="font-semibold">Provenance</div>
            <div className="break-all font-mono text-[11px]">{detail.sha256}</div>
            <div className="text-muted">{detail.notes}</div>
            <div className="text-muted">Chain</div>
            <ol className="list-decimal space-y-1 pl-4">
              {(detail.provenance_chain ?? []).map((s, i) => (
                <li key={i} className="font-mono text-[11px]">
                  {String(s.step)}: {JSON.stringify(s)}
                </li>
              ))}
            </ol>
            <div className="break-all text-[11px] text-muted">Path: {detail.stored_path}</div>
            <div className="text-[11px] text-muted">
              Tool: {detail.tool_name} {detail.tool_version}
            </div>
          </div>
        )}
      </aside>
    </div>
  );
}
