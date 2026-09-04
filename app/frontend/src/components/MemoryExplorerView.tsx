import { useCallback, useEffect, useMemo, useState } from "react";
import { engineCall, EngineClientError } from "../lib/api";
import type { Job, MemoryRegion, ProcessRow } from "../lib/types";
import { Badge } from "./ui/badge";
import { Button } from "./ui/button";
import { Input } from "./ui/input";

export function MemoryExplorerView({
  evidenceId,
  processes,
  selectedProcessId,
  onSelectProcess,
  onJobSubmitted,
  onError,
  refreshToken,
}: {
  evidenceId: string | null;
  processes: ProcessRow[];
  selectedProcessId: string | null;
  onSelectProcess: (id: string) => void;
  onJobSubmitted: (job: Job) => void;
  onError: (m: string) => void;
  refreshToken?: number;
}) {
  const [pidFilter, setPidFilter] = useState<string>("");
  const [suspiciousOnly, setSuspiciousOnly] = useState(false);
  const [items, setItems] = useState<MemoryRegion[]>([]);
  const [selected, setSelected] = useState<MemoryRegion | null>(null);
  const [busy, setBusy] = useState(false);

  const activePid = useMemo(() => {
    if (pidFilter.trim()) {
      const n = Number(pidFilter);
      return Number.isFinite(n) ? n : null;
    }
    if (selectedProcessId) {
      const p = processes.find((x) => x.id === selectedProcessId);
      return p?.pid ?? null;
    }
    return null;
  }, [pidFilter, selectedProcessId, processes]);

  const load = useCallback(async () => {
    if (!evidenceId) return;
    try {
      const res = await engineCall<{ items: MemoryRegion[] }>("memory.list", {
        evidence_id: evidenceId,
        pid: activePid ?? undefined,
        suspicious_only: suspiciousOnly,
        limit: 20000,
      });
      setItems(res.items);
    } catch (e) {
      onError(e instanceof EngineClientError ? e.message : String(e));
    }
  }, [evidenceId, activePid, suspiciousOnly, onError]);

  useEffect(() => {
    void load();
  }, [load, refreshToken]);

  const scan = async () => {
    if (!evidenceId || activePid == null) {
      onError("Select or enter a PID before scanning VADs.");
      return;
    }
    setBusy(true);
    try {
      const job = await engineCall<Job>("memory.scan", {
        evidence_id: evidenceId,
        pid: activePid,
        process_id: selectedProcessId ?? undefined,
      });
      onJobSubmitted(job);
    } catch (e) {
      onError(e instanceof EngineClientError ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  const extract = async (region: MemoryRegion) => {
    if (!evidenceId) return;
    setBusy(true);
    try {
      const job = await engineCall<Job>("memory.extract", {
        evidence_id: evidenceId,
        memory_region_id: region.id,
        pid: region.pid,
        process_id: region.process_id ?? undefined,
      });
      onJobSubmitted(job);
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
    <div className="flex h-full min-h-0 flex-col text-xs">
      <div className="flex flex-wrap items-center gap-2 border-b border-border px-3 py-2">
        <div className="text-sm font-semibold">Memory / VAD</div>
        <Input
          className="w-28"
          placeholder="PID"
          value={pidFilter}
          onChange={(e) => setPidFilter(e.target.value)}
        />
        <label className="flex items-center gap-1 text-muted">
          <input
            type="checkbox"
            checked={suspiciousOnly}
            onChange={(e) => setSuspiciousOnly(e.target.checked)}
          />
          Indicators only
        </label>
        <Button size="sm" variant="outline" onClick={() => void load()}>
          Refresh
        </Button>
        <Button size="sm" onClick={() => void scan()} disabled={busy || activePid == null}>
          {busy ? "Working…" : "Scan VADs (job)"}
        </Button>
        <span className="text-muted">
          Indicators are evidence-based (e.g. W+X), not a malice verdict.
        </span>
      </div>
      <div className="flex min-h-0 flex-1">
        <div className="min-w-0 flex-1 overflow-auto">
          <table className="w-full text-left">
            <thead className="sticky top-0 bg-surface-2 text-muted">
              <tr>
                <th className="px-2 py-1.5">PID</th>
                <th className="px-2 py-1.5">Start</th>
                <th className="px-2 py-1.5">End</th>
                <th className="px-2 py-1.5">Size</th>
                <th className="px-2 py-1.5">Protection</th>
                <th className="px-2 py-1.5">Tag</th>
                <th className="px-2 py-1.5">Private</th>
                <th className="px-2 py-1.5">File</th>
                <th className="px-2 py-1.5">Indicators</th>
              </tr>
            </thead>
            <tbody>
              {items.map((r) => (
                <tr
                  key={r.id}
                  className={
                    "cursor-pointer border-t border-border/40 hover:bg-surface-2/50 " +
                    (selected?.id === r.id ? "bg-surface-2" : "")
                  }
                  onClick={() => setSelected(r)}
                >
                  <td className="px-2 py-1 font-mono">{r.pid}</td>
                  <td className="px-2 py-1 font-mono">{r.start_vpn ?? "—"}</td>
                  <td className="px-2 py-1 font-mono">{r.end_vpn ?? "—"}</td>
                  <td className="px-2 py-1 font-mono">
                    {r.size_bytes != null ? r.size_bytes.toLocaleString() : "—"}
                  </td>
                  <td className="px-2 py-1 font-mono">{r.protection ?? "—"}</td>
                  <td className="px-2 py-1">{r.tag ?? "—"}</td>
                  <td className="px-2 py-1 font-mono">{r.private_memory ?? "—"}</td>
                  <td className="max-w-[12rem] truncate px-2 py-1">{r.file_path ?? "—"}</td>
                  <td className="px-2 py-1">
                    {(r.indicators ?? []).map((i) => (
                      <Badge key={i.code} className="mr-1 border-warning text-warning">
                        {i.code}
                      </Badge>
                    ))}
                  </td>
                </tr>
              ))}
              {items.length === 0 && (
                <tr>
                  <td colSpan={9} className="px-3 py-6 text-muted">
                    No VAD rows stored. Select a process, run Analyze process or Scan VADs.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
        <aside className="w-80 shrink-0 overflow-auto border-l border-border p-3">
          {!selected ? (
            <div className="text-muted">Select a region for details and extraction.</div>
          ) : (
            <div className="space-y-2">
              <div className="font-semibold">Region detail</div>
              <KV k="PID" v={selected.pid} />
              <KV k="Start" v={selected.start_vpn} />
              <KV k="End" v={selected.end_vpn} />
              <KV k="Size" v={selected.size_bytes} />
              <KV k="Protection" v={selected.protection} />
              <KV k="Tag" v={selected.tag} />
              <KV k="Private" v={selected.private_memory} />
              <KV k="File" v={selected.file_path} />
              <KV k="Source" v={selected.source_plugin} />
              <div className="text-muted">Indicators</div>
              {(selected.indicators ?? []).length === 0 ? (
                <div className="text-muted">None flagged</div>
              ) : (
                (selected.indicators ?? []).map((i) => (
                  <div key={i.code} className="rounded border border-border p-2">
                    <div className="font-medium">{i.label}</div>
                    <div className="text-muted">{i.detail}</div>
                  </div>
                ))
              )}
              {selected.process_id && (
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => onSelectProcess(selected.process_id!)}
                >
                  Open process
                </Button>
              )}
              <Button size="sm" onClick={() => void extract(selected)} disabled={busy}>
                Extract region (job)
              </Button>
              <div className="text-[11px] text-muted">
                Extraction uses Volatility vad_dump into the controlled artifact store. Artifacts
                are never executed.
              </div>
            </div>
          )}
        </aside>
      </div>
    </div>
  );
}

function KV({ k, v }: { k: string; v: unknown }) {
  return (
    <div className="grid grid-cols-[72px_1fr] gap-1">
      <div className="text-muted">{k}</div>
      <div className="break-all font-mono">{v == null || v === "" ? "—" : String(v)}</div>
    </div>
  );
}
