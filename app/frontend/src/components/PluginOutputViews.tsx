import { useCallback, useState, type ReactNode } from "react";
import { TimestampText, isIsoTimestamp } from "../lib/datetime";
import { matchesFieldQuery } from "../lib/resultFilter";
import { useTableSort } from "../lib/tableSort";
import type { PluginExecutionBundle, PluginResultRow } from "../lib/types";
import { ResultFilterBar } from "./ResultFilterBar";
import { SortableTh } from "./SortableTh";

export function ConsoleOutput({ text }: { text: string }) {
  const lines = text.length ? text.split("\n") : [];
  if (lines.length === 0) {
    return <div className="p-2 text-muted">Plugin completed with no console output.</div>;
  }
  return (
    <pre
      className="plugin-console min-h-0 flex-1"
      tabIndex={0}
      role="region"
      aria-label="Plugin console output"
    >
      {lines.map((line, index) => (
        <div key={index} className="plugin-console-line">
          {highlightConsoleLine(line, index)}
        </div>
      ))}
    </pre>
  );
}

const CONSOLE_TOKEN =
  /(0x[0-9a-fA-F]+)|(\b\d+\b)|(\b(?:True|False|None|N\/A)\b)/g;

function highlightConsoleLine(line: string, index: number): ReactNode {
  if (line.startsWith("#")) {
    return <span className="plugin-console-comment">{line}</span>;
  }
  if (index === 0) {
    return <span className="plugin-console-header">{line}</span>;
  }
  const parts: ReactNode[] = [];
  let last = 0;
  const re = new RegExp(CONSOLE_TOKEN.source, "g");
  let match: RegExpExecArray | null;
  while ((match = re.exec(line))) {
    if (match.index > last) parts.push(line.slice(last, match.index));
    const [all, hex, , kw] = match;
    const cls = hex ? "plugin-console-hex" : kw ? "plugin-console-kw" : "plugin-console-num";
    parts.push(
      <span key={match.index} className={cls}>
        {all}
      </span>,
    );
    last = match.index + all.length;
  }
  if (last < line.length) parts.push(line.slice(last));
  return parts;
}

export function ResultTable({
  bundle,
  onOpenProcess,
}: {
  bundle: PluginExecutionBundle;
  onOpenProcess?: (id: string) => void;
}) {
  const [filter, setFilter] = useState("");
  const [filterField, setFilterField] = useState("all");
  const cols = bundle.result.columns ?? [];
  const links = new Map(
    (bundle.result.links ?? [])
      .filter((l) => l.kind === "process" && l.process_id && l.pid != null)
      .map((l) => [l.pid as number, l.process_id as string]),
  );
  const rows = (bundle.result.rows ?? []).filter((row) => {
    const values: Record<string, unknown> = {};
    for (const c of cols) values[c.name] = row.values?.[c.name];
    return matchesFieldQuery(filter, filterField, values);
  });
  const getValue = useCallback((row: PluginResultRow, key: string) => row.values?.[key], []);
  const { sorted, sort, toggle } = useTableSort(rows, getValue);
  return (
    <div>
      <div className="mb-2 flex justify-end">
        <ResultFilterBar
          query={filter}
          onQueryChange={setFilter}
          field={filterField}
          onFieldChange={setFilterField}
          placeholder="Filter result rows…"
          fields={cols.map((c) => ({ id: c.name, label: c.name }))}
        />
      </div>
      <table className="app-result-table w-full text-center">
        <thead className="sticky top-0 bg-surface-2 text-muted">
          <tr>
            {cols.map((c) => (
              <SortableTh
                key={c.name}
                label={c.name}
                column={c.name}
                sort={sort}
                onToggle={toggle}
                className="px-2 py-1"
              />
            ))}
          </tr>
        </thead>
        <tbody>
          {sorted.map((row, i) => (
            <tr key={i} className="border-t border-border/40">
              {cols.map((c, colIndex) => {
                const val = row.values?.[c.name];
                const pid =
                  c.name.toLowerCase() === "pid" &&
                  (typeof val === "number" || typeof val === "string")
                    ? Number(val)
                    : null;
                const procId = pid != null ? links.get(pid) : undefined;
                const treePad =
                  colIndex === 0 &&
                  (row.depth || 0) > 0 &&
                  cols.some((col) => col.name.toLowerCase() === "pid")
                    ? 8 + row.depth * 12
                    : undefined;
                return (
                  <td
                    key={c.name}
                    className="px-2 py-2 font-mono"
                    style={
                      treePad != null ? { paddingLeft: treePad, textAlign: "left" } : undefined
                    }
                  >
                    {procId && onOpenProcess ? (
                      <button
                        type="button"
                        className="text-accent underline"
                        onClick={() => onOpenProcess(procId)}
                      >
                        {formatCell(val)}
                      </button>
                    ) : (
                      formatCell(val)
                    )}
                  </td>
                );
              })}
            </tr>
          ))}
          {bundle.result.rows.length === 0 && (
            <tr>
              <td colSpan={Math.max(cols.length, 1)} className="px-2 py-4 text-muted">
                Plugin completed with no rows.
              </td>
            </tr>
          )}
          {bundle.result.rows.length > 0 && rows.length === 0 && (
            <tr>
              <td colSpan={Math.max(cols.length, 1)} className="px-2 py-4 text-muted">
                No rows match the current filter.
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}

function formatCell(val: unknown): ReactNode {
  if (val == null) return "—";
  if (typeof val === "object") return JSON.stringify(val);
  const text = String(val);
  if (isIsoTimestamp(text)) return <TimestampText value={text} />;
  return text;
}
