import { useEffect, useState } from "react";
import { engineCall, EngineClientError } from "../lib/api";
import type { Job, ProcessDeepDive } from "../lib/types";
import { Badge } from "./ui/badge";
import { Button } from "./ui/button";

type Props = {
  processId: string;
  evidenceId: string;
  onOpenProcess: (processId: string) => void;
  onError: (msg: string) => void;
  onJobSubmitted?: (job: Job) => void;
};

type Tab =
  | "overview"
  | "cmdline"
  | "modules"
  | "network"
  | "handles"
  | "memory"
  | "findings"
  | "family";

export function ProcessDeepDiveView({
  processId,
  evidenceId,
  onOpenProcess,
  onError,
  onJobSubmitted,
}: Props) {
  const [data, setData] = useState<ProcessDeepDive | null>(null);
  const [tab, setTab] = useState<Tab>("overview");
  const [busy, setBusy] = useState(false);

  const reload = async () => {
    const d = await engineCall<ProcessDeepDive>("process.get", {
      process_id: processId,
    });
    setData(d);
  };

  useEffect(() => {
    void (async () => {
      try {
        await reload();
      } catch (err) {
        onError(err instanceof EngineClientError ? err.message : String(err));
      }
    })();
  }, [processId]); // eslint-disable-line react-hooks/exhaustive-deps

  const runRecommended = async () => {
    if (!data) return;
    setBusy(true);
    try {
      const job = await engineCall<Job>("process.analyze_recommended", {
        evidence_id: evidenceId,
        process_id: processId,
        pid: data.process.pid,
      });
      onJobSubmitted?.(job);
    } catch (err) {
      onError(err instanceof EngineClientError ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  if (!data) {
    return <div className="p-4 text-sm text-muted">Loading process…</div>;
  }

  const p = data.process;
  const tabs: { id: Tab; label: string; count?: number }[] = [
    { id: "overview", label: "Overview" },
    { id: "cmdline", label: "Command line" },
    { id: "family", label: "Parent / children", count: data.counts.children },
    { id: "modules", label: "DLLs / modules", count: data.counts.modules },
    { id: "network", label: "Network", count: data.counts.network },
    { id: "handles", label: "Handles", count: data.counts.handles },
    { id: "memory", label: "Memory / VAD", count: data.counts.memory_regions },
    { id: "findings", label: "Findings", count: data.counts.findings },
  ];

  return (
    <div className="flex h-full flex-col">
      <div className="flex flex-wrap items-center gap-2 border-b border-border px-3 py-2">
        <div className="text-sm font-semibold">
          Process Deep Dive — {p.name ?? "?"} ({p.pid})
        </div>
        <Badge>PID {p.pid}</Badge>
        {p.ppid != null && <Badge>PPID {p.ppid}</Badge>}
        <div className="ml-auto flex gap-2">
          <Button size="sm" variant="outline" onClick={() => void reload()} disabled={busy}>
            Refresh
          </Button>
          <Button size="sm" onClick={() => void runRecommended()} disabled={busy}>
            {busy ? "Queuing…" : "Analyze process"}
          </Button>
        </div>
      </div>

      <div className="flex gap-1 overflow-x-auto border-b border-border px-2 py-1">
        {tabs.map((t) => (
          <button
            key={t.id}
            type="button"
            onClick={() => setTab(t.id)}
            className={
              "rounded px-2 py-1 text-xs " +
              (tab === t.id ? "bg-surface-2 text-foreground" : "text-muted hover:bg-surface-2/60")
            }
          >
            {t.label}
            {t.count != null ? ` (${t.count})` : ""}
          </button>
        ))}
      </div>

      <div className="min-h-0 flex-1 overflow-auto p-3 text-xs">
        {tab === "overview" && (
          <div className="space-y-1">
            <KV k="PID" v={p.pid} />
            <KV k="PPID" v={p.ppid} />
            <KV k="Name" v={p.name} />
            <KV k="Username" v={p.username} />
            <KV k="Image path" v={p.image_path} />
            <KV k="Create time" v={p.create_time} />
            <KV k="Exit time" v={p.exit_time} />
            <KV k="Threads" v={p.threads} />
            <KV k="Handles (pslist)" v={p.handles} />
            <KV k="Session" v={p.session_id} />
            <KV k="Wow64" v={p.wow64 == null ? null : p.wow64 ? "yes" : "no"} />
            <KV k="Offset" v={p.offset_hex} />
            <KV k="Source" v={p.source_plugin} />
            <div className="mt-3 text-[10px] uppercase tracking-wide text-muted">
              Recommended analysis strategy (last runs)
            </div>
            {data.analysis_runs.length === 0 ? (
              <div className="text-muted">
                No process-targeted analysis yet. Use Analyze process.
              </div>
            ) : (
              <table className="mt-1 w-full text-left">
                <thead className="text-muted">
                  <tr>
                    <th className="py-1">Kind</th>
                    <th className="py-1">Status</th>
                    <th className="py-1">Started</th>
                  </tr>
                </thead>
                <tbody>
                  {data.analysis_runs.map((r) => (
                    <tr key={String(r.id)} className="border-t border-border/40">
                      <td className="py-1">{String(r.kind)}</td>
                      <td className="py-1">{String(r.status)}</td>
                      <td className="py-1 font-mono">{String(r.started_at ?? "")}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        )}

        {tab === "cmdline" && (
          <pre className="whitespace-pre-wrap break-all font-mono text-xs">
            {p.command_line ?? "No command line stored yet. Run Analyze process (windows.cmdline)."}
          </pre>
        )}

        {tab === "family" && (
          <div className="space-y-3">
            <div>
              <div className="mb-1 text-muted">Parent</div>
              {data.parent ? (
                <button
                  type="button"
                  className="text-left text-accent hover:underline"
                  onClick={() => onOpenProcess(data.parent!.id)}
                >
                  {data.parent.name} ({data.parent.pid})
                </button>
              ) : (
                <span className="text-muted">None / not in process list</span>
              )}
            </div>
            <div>
              <div className="mb-1 text-muted">Children</div>
              {data.children.length === 0 ? (
                <span className="text-muted">None</span>
              ) : (
                <ul className="space-y-1">
                  {data.children.map((c) => (
                    <li key={c.id}>
                      <button
                        type="button"
                        className="text-accent hover:underline"
                        onClick={() => onOpenProcess(c.id)}
                      >
                        {c.name} ({c.pid})
                      </button>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </div>
        )}

        {tab === "modules" && (
          <EntityTable
            empty="No modules yet. Run Analyze process (windows.dlllist)."
            columns={["Name", "Base", "Size", "Path"]}
            rows={data.modules.map((m) => [
              m.name ?? "—",
              m.base_address ?? "—",
              m.size ?? "—",
              m.path ?? "—",
            ])}
          />
        )}

        {tab === "network" && (
          <EntityTable
            empty="No network rows for this PID. Run Analyze process (windows.netscan)."
            columns={["Proto", "Local", "Remote", "State", "Created"]}
            rows={data.network.map((n) => [
              n.protocol ?? "—",
              `${n.local_address ?? ""}:${n.local_port ?? ""}`,
              `${n.remote_address ?? ""}:${n.remote_port ?? ""}`,
              n.state ?? "—",
              n.created ?? "—",
            ])}
          />
        )}

        {tab === "handles" && (
          <EntityTable
            empty="No handles yet. Run Analyze process (windows.handles)."
            columns={["Type", "Value", "Access", "Name"]}
            rows={data.handles.map((h) => [
              h.handle_type ?? "—",
              h.handle_value ?? "—",
              h.granted_access ?? "—",
              h.name ?? "—",
            ])}
          />
        )}

        {tab === "memory" && (
          <EntityTable
            empty="No VAD regions yet. Run Analyze process (windows.vadinfo)."
            columns={["Start", "End", "Protection", "Tag", "Private", "File"]}
            rows={data.memory_regions.map((r) => [
              r.start_vpn ?? "—",
              r.end_vpn ?? "—",
              r.protection ?? "—",
              r.tag ?? "—",
              r.private_memory ?? "—",
              r.file_path ?? "—",
            ])}
          />
        )}

        {tab === "findings" && (
          <div className="space-y-2">
            {data.findings.length === 0 ? (
              <div className="text-muted">
                No findings for this process. Heuristics run after recommended analysis when
                evidence supports them.
              </div>
            ) : (
              data.findings.map((f) => (
                <div key={f.id} className="rounded border border-border bg-surface p-2">
                  <div className="mb-1 flex gap-2">
                    <Badge>{f.severity}</Badge>
                    <span className="font-medium">{f.finding_type}</span>
                    <span className="text-muted">{f.plugin}</span>
                  </div>
                  <div>{f.explanation}</div>
                  {f.field_value && (
                    <pre className="mt-1 max-h-24 overflow-auto whitespace-pre-wrap break-all text-[11px] text-muted">
                      {f.field_value}
                    </pre>
                  )}
                </div>
              ))
            )}
          </div>
        )}
      </div>
    </div>
  );
}

function KV({ k, v }: { k: string; v: unknown }) {
  return (
    <div className="grid grid-cols-[120px_1fr] gap-2 border-b border-border/50 py-1">
      <div className="text-muted">{k}</div>
      <div className="break-all font-mono">{v == null || v === "" ? "—" : String(v)}</div>
    </div>
  );
}

function EntityTable({
  columns,
  rows,
  empty,
}: {
  columns: string[];
  rows: (string | number)[][];
  empty: string;
}) {
  if (rows.length === 0) {
    return <div className="text-muted">{empty}</div>;
  }
  return (
    <table className="w-full border-collapse text-left">
      <thead className="sticky top-0 bg-surface-2 text-muted">
        <tr>
          {columns.map((c) => (
            <th key={c} className="px-2 py-1 font-medium">
              {c}
            </th>
          ))}
        </tr>
      </thead>
      <tbody>
        {rows.map((r, i) => (
          <tr key={i} className="border-t border-border/40">
            {r.map((cell, j) => (
              <td key={j} className="max-w-[20rem] truncate px-2 py-1 font-mono">
                {cell}
              </td>
            ))}
          </tr>
        ))}
      </tbody>
    </table>
  );
}
