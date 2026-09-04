import { useEffect, useState } from "react";
import { engineCall, EngineClientError } from "../lib/api";
import type { NetworkConnection, ModuleRow, Finding } from "../lib/types";

export function NetworkView({
  evidenceId,
  onError,
}: {
  evidenceId: string | null;
  onError: (m: string) => void;
}) {
  const [items, setItems] = useState<NetworkConnection[]>([]);
  useEffect(() => {
    if (!evidenceId) return;
    void (async () => {
      try {
        const res = await engineCall<{ items: NetworkConnection[] }>("network.list", {
          evidence_id: evidenceId,
        });
        setItems(res.items);
      } catch (e) {
        onError(e instanceof EngineClientError ? e.message : String(e));
      }
    })();
  }, [evidenceId, onError]);

  if (!evidenceId) return <Empty text="Import evidence first." />;
  return (
    <SimpleTable
      title="Network"
      empty="No network connections stored. Run process recommended analysis (netscan) or analyze processes of interest."
      columns={["PID", "Proto", "Local", "Remote", "State", "Owner"]}
      rows={items.map((n) => [
        n.pid ?? "—",
        n.protocol ?? "—",
        `${n.local_address ?? ""}:${n.local_port ?? ""}`,
        `${n.remote_address ?? ""}:${n.remote_port ?? ""}`,
        n.state ?? "—",
        n.owner ?? "—",
      ])}
    />
  );
}

export function ModulesView({
  evidenceId,
  onError,
}: {
  evidenceId: string | null;
  onError: (m: string) => void;
}) {
  const [items, setItems] = useState<ModuleRow[]>([]);
  useEffect(() => {
    if (!evidenceId) return;
    void (async () => {
      try {
        const res = await engineCall<{ items: ModuleRow[] }>("modules.list", {
          evidence_id: evidenceId,
        });
        setItems(res.items);
      } catch (e) {
        onError(e instanceof EngineClientError ? e.message : String(e));
      }
    })();
  }, [evidenceId, onError]);

  if (!evidenceId) return <Empty text="Import evidence first." />;
  return (
    <SimpleTable
      title="Modules / DLLs"
      empty="No modules stored yet. Run Analyze process on targets of interest."
      columns={["PID", "Name", "Base", "Path"]}
      rows={items.map((m) => [m.pid, m.name ?? "—", m.base_address ?? "—", m.path ?? "—"])}
    />
  );
}

export function FindingsView({
  evidenceId,
  onError,
}: {
  evidenceId: string | null;
  onError: (m: string) => void;
}) {
  const [items, setItems] = useState<Finding[]>([]);
  useEffect(() => {
    if (!evidenceId) return;
    void (async () => {
      try {
        const res = await engineCall<{ items: Finding[] }>("findings.list", {
          evidence_id: evidenceId,
        });
        setItems(res.items);
      } catch (e) {
        onError(e instanceof EngineClientError ? e.message : String(e));
      }
    })();
  }, [evidenceId, onError]);

  if (!evidenceId) return <Empty text="Import evidence first." />;
  if (items.length === 0) {
    return (
      <div className="p-4 text-sm text-muted">
        No findings yet. Findings are transparent heuristics derived from analysis results (not
        risk scores).
      </div>
    );
  }
  return (
    <div className="space-y-2 p-3 text-xs">
      <div className="text-sm font-semibold">Findings</div>
      {items.map((f) => (
        <div key={f.id} className="rounded border border-border bg-surface p-2">
          <div className="mb-1 font-medium">
            [{f.severity}] {f.finding_type} {f.pid != null ? `(PID ${f.pid})` : ""}
          </div>
          <div>{f.explanation}</div>
        </div>
      ))}
    </div>
  );
}

function Empty({ text }: { text: string }) {
  return <div className="p-4 text-sm text-muted">{text}</div>;
}

function SimpleTable({
  title,
  columns,
  rows,
  empty,
}: {
  title: string;
  columns: string[];
  rows: (string | number)[][];
  empty: string;
}) {
  return (
    <div className="flex h-full flex-col text-xs">
      <div className="border-b border-border px-3 py-2 text-sm font-semibold">{title}</div>
      {rows.length === 0 ? (
        <div className="p-4 text-muted">{empty}</div>
      ) : (
        <div className="min-h-0 flex-1 overflow-auto">
          <table className="w-full text-left">
            <thead className="sticky top-0 bg-surface-2 text-muted">
              <tr>
                {columns.map((c) => (
                  <th key={c} className="px-2 py-1.5 font-medium">
                    {c}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rows.map((r, i) => (
                <tr key={i} className="border-t border-border/40">
                  {r.map((cell, j) => (
                    <td key={j} className="max-w-[24rem] truncate px-2 py-1 font-mono">
                      {cell}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
