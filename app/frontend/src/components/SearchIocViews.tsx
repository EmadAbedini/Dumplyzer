import { useCallback, useState } from "react";
import { engineCall, EngineClientError } from "../lib/api";
import type { SearchHit, Ioc } from "../lib/types";
import { Button } from "./ui/button";
import { Input } from "./ui/input";
import { Badge } from "./ui/badge";

export function SearchView({
  evidenceId,
  onOpenProcess,
  onError,
}: {
  evidenceId: string | null;
  onOpenProcess: (processId: string) => void;
  onError: (m: string) => void;
}) {
  const [q, setQ] = useState("");
  const [items, setItems] = useState<SearchHit[]>([]);
  const [busy, setBusy] = useState(false);

  const run = useCallback(async () => {
    if (!evidenceId || !q.trim()) return;
    setBusy(true);
    try {
      const res = await engineCall<{ items: SearchHit[] }>("search.query", {
        evidence_id: evidenceId,
        query: q.trim(),
        limit: 300,
      });
      setItems(res.items);
    } catch (e) {
      onError(e instanceof EngineClientError ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }, [evidenceId, q, onError]);

  if (!evidenceId) {
    return <div className="p-4 text-sm text-muted">Import evidence first.</div>;
  }

  return (
    <div className="flex h-full flex-col text-xs">
      <div className="flex items-center gap-2 border-b border-border px-3 py-2">
        <div className="text-sm font-semibold">Search</div>
        <Input
          className="max-w-md"
          placeholder="powershell, 10.0.0.1, ntdll.dll, C:\\Users…"
          value={q}
          onChange={(e) => setQ(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") void run();
          }}
        />
        <Button size="sm" onClick={() => void run()} disabled={busy}>
          {busy ? "Searching…" : "Search"}
        </Button>
      </div>
      <div className="min-h-0 flex-1 overflow-auto">
        <table className="w-full text-left">
          <thead className="sticky top-0 bg-surface-2 text-muted">
            <tr>
              <th className="px-2 py-1.5">Entity</th>
              <th className="px-2 py-1.5">Value</th>
              <th className="px-2 py-1.5">Context</th>
              <th className="px-2 py-1.5">PID</th>
              <th className="px-2 py-1.5">Source</th>
            </tr>
          </thead>
          <tbody>
            {items.map((h, i) => (
              <tr key={i} className="border-t border-border/40">
                <td className="px-2 py-1">
                  <Badge>{h.entity}</Badge>
                </td>
                <td className="max-w-xs truncate px-2 py-1 font-mono">{h.value}</td>
                <td className="max-w-sm truncate px-2 py-1 text-muted">{h.context}</td>
                <td className="px-2 py-1 font-mono">
                  {h.process_id ? (
                    <button
                      type="button"
                      className="text-accent hover:underline"
                      onClick={() => onOpenProcess(h.process_id!)}
                    >
                      {h.pid ?? "open"}
                    </button>
                  ) : (
                    (h.pid ?? "—")
                  )}
                </td>
                <td className="px-2 py-1 text-muted">{h.plugin ?? h.source ?? "—"}</td>
              </tr>
            ))}
            {items.length === 0 && (
              <tr>
                <td colSpan={5} className="px-3 py-6 text-muted">
                  No results. Search runs on normalized data already stored from analysis.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export function IocsView({
  evidenceId,
  onError,
}: {
  evidenceId: string | null;
  onError: (m: string) => void;
}) {
  const [items, setItems] = useState<Ioc[]>([]);
  const [filter, setFilter] = useState("");
  const [busy, setBusy] = useState(false);
  const [exportText, setExportText] = useState<string | null>(null);

  const load = useCallback(async () => {
    if (!evidenceId) return;
    const res = await engineCall<{ items: Ioc[] }>("iocs.list", {
      evidence_id: evidenceId,
    });
    setItems(res.items);
  }, [evidenceId]);

  const extract = async () => {
    if (!evidenceId) return;
    setBusy(true);
    try {
      const res = await engineCall<{ items: Ioc[] }>("iocs.extract", {
        evidence_id: evidenceId,
      });
      setItems(res.items);
    } catch (e) {
      onError(e instanceof EngineClientError ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  const doExport = async (fmt: "json" | "csv") => {
    if (!evidenceId) return;
    try {
      if (fmt === "json") {
        const res = await engineCall<Record<string, unknown>>("iocs.export_json", {
          evidence_id: evidenceId,
        });
        setExportText(JSON.stringify(res, null, 2));
      } else {
        const res = await engineCall<{ csv: string }>("iocs.export_csv", {
          evidence_id: evidenceId,
        });
        setExportText(res.csv);
      }
    } catch (e) {
      onError(e instanceof EngineClientError ? e.message : String(e));
    }
  };

  if (!evidenceId) {
    return <div className="p-4 text-sm text-muted">Import evidence first.</div>;
  }

  const filtered = items.filter((i) => {
    const q = filter.trim().toLowerCase();
    if (!q) return true;
    return (
      i.value.toLowerCase().includes(q) ||
      i.ioc_type.toLowerCase().includes(q) ||
      (i.context ?? "").toLowerCase().includes(q)
    );
  });

  return (
    <div className="flex h-full flex-col text-xs">
      <div className="flex flex-wrap items-center gap-2 border-b border-border px-3 py-2">
        <div className="text-sm font-semibold">IOCs</div>
        <Button size="sm" onClick={() => void extract()} disabled={busy}>
          {busy ? "Extracting…" : "Extract IOCs"}
        </Button>
        <Button size="sm" variant="outline" onClick={() => void load()}>
          Refresh
        </Button>
        <Button size="sm" variant="outline" onClick={() => void doExport("json")}>
          Export JSON
        </Button>
        <Button size="sm" variant="outline" onClick={() => void doExport("csv")}>
          Export CSV
        </Button>
        <Input
          className="ml-auto max-w-xs"
          placeholder="Filter…"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
        />
      </div>
      {exportText && (
        <div className="border-b border-border p-2">
          <div className="mb-1 flex gap-2">
            <span className="text-muted">Export preview</span>
            <Button
              size="sm"
              variant="ghost"
              onClick={() => void navigator.clipboard.writeText(exportText)}
            >
              Copy
            </Button>
            <Button size="sm" variant="ghost" onClick={() => setExportText(null)}>
              Close
            </Button>
          </div>
          <pre className="max-h-40 overflow-auto rounded bg-surface-2 p-2 font-mono text-[11px]">
            {exportText}
          </pre>
        </div>
      )}
      <div className="min-h-0 flex-1 overflow-auto">
        <table className="w-full text-left">
          <thead className="sticky top-0 bg-surface-2 text-muted">
            <tr>
              <th className="px-2 py-1.5">Type</th>
              <th className="px-2 py-1.5">Value</th>
              <th className="px-2 py-1.5">PID</th>
              <th className="px-2 py-1.5">Context</th>
              <th className="px-2 py-1.5">Source</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((i) => (
              <tr key={i.id} className="border-t border-border/40">
                <td className="px-2 py-1">
                  <Badge>{i.ioc_type}</Badge>
                </td>
                <td className="max-w-md truncate px-2 py-1 font-mono">{i.value}</td>
                <td className="px-2 py-1 font-mono">{i.pid ?? "—"}</td>
                <td className="max-w-sm truncate px-2 py-1 text-muted">{i.context ?? "—"}</td>
                <td className="px-2 py-1 text-muted">{i.source ?? "—"}</td>
              </tr>
            ))}
            {filtered.length === 0 && (
              <tr>
                <td colSpan={5} className="px-3 py-6 text-muted">
                  No IOCs. Run analysis then Extract IOCs (derived from stored normalized fields
                  only).
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
