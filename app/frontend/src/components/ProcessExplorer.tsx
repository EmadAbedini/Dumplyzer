import { useMemo, useState } from "react";
import type { ProcessRow } from "../lib/types";
import { Input } from "./ui/input";

type Props = {
  items: ProcessRow[];
  total: number;
  loading: boolean;
  selectedId?: string | null;
  onSelect: (p: ProcessRow) => void;
};

export function ProcessExplorer({
  items,
  total,
  loading,
  selectedId,
  onSelect,
}: Props) {
  const [filter, setFilter] = useState("");
  const filtered = useMemo(() => {
    const q = filter.trim().toLowerCase();
    if (!q) return items;
    return items.filter((p) => {
      const hay = `${p.pid} ${p.ppid ?? ""} ${p.name ?? ""} ${p.command_line ?? ""}`.toLowerCase();
      return hay.includes(q);
    });
  }, [items, filter]);

  return (
    <div className="flex h-full flex-col">
      <div className="flex items-center gap-2 border-b border-border px-3 py-2">
        <div className="text-sm font-semibold">Processes</div>
        <div className="text-xs text-muted">
          {loading ? "Loading…" : `${filtered.length} / ${total}`}
        </div>
        <div className="ml-auto w-56">
          <Input
            placeholder="Filter PID / name / cmdline…"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
          />
        </div>
      </div>
      <div className="min-h-0 flex-1 overflow-auto">
        <table className="w-full border-collapse text-left text-xs">
          <thead className="sticky top-0 bg-surface-2 text-muted">
            <tr>
              <th className="px-2 py-1.5 font-medium">PID</th>
              <th className="px-2 py-1.5 font-medium">PPID</th>
              <th className="px-2 py-1.5 font-medium">Name</th>
              <th className="px-2 py-1.5 font-medium">Command line</th>
              <th className="px-2 py-1.5 font-medium">Threads</th>
              <th className="px-2 py-1.5 font-medium">Create time</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((p) => (
              <tr
                key={p.id}
                onClick={() => onSelect(p)}
                className={
                  "cursor-pointer border-t border-border/40 hover:bg-surface-2/50 " +
                  (selectedId === p.id ? "bg-surface-2" : "")
                }
              >
                <td className="px-2 py-1 font-mono">{p.pid}</td>
                <td className="px-2 py-1 font-mono">{p.ppid ?? "—"}</td>
                <td className="px-2 py-1">{p.name ?? "—"}</td>
                <td className="max-w-[28rem] truncate px-2 py-1 font-mono text-muted">
                  {p.command_line ?? "—"}
                </td>
                <td className="px-2 py-1 font-mono">{p.threads ?? "—"}</td>
                <td className="px-2 py-1 font-mono">{p.create_time ?? "—"}</td>
              </tr>
            ))}
            {!loading && filtered.length === 0 && (
              <tr>
                <td colSpan={6} className="px-3 py-6 text-muted">
                  No processes. Import a memory image and run basic triage.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
