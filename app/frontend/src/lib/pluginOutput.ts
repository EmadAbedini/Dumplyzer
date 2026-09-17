import type { PluginExecutionBundle, PluginResultRow } from "./types";

const MAX_COL = 80;

export function formatPluginCell(value: unknown): string {
  if (value == null) return "";
  if (typeof value === "boolean") return value ? "True" : "False";
  if (typeof value === "number") return String(value);
  if (typeof value === "string") return value.replace(/^\s+/, "");
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

function columnNames(bundle: PluginExecutionBundle): string[] {
  return (bundle.result.columns ?? []).map((c) => c.name);
}

function widthsFor(cols: string[], rows: PluginResultRow[]): number[] {
  return cols.map((name) => {
    let width = name.length;
    for (const row of rows) {
      const text = formatPluginCell(row.values?.[name]);
      width = Math.max(width, text.length);
    }
    return Math.min(Math.max(width, 3), MAX_COL);
  });
}

function padCell(text: string, width: number, last: boolean): string {
  if (last) return text;
  if (text.length >= width) return `${text} `;
  return text.padEnd(width + 1, " ");
}

export function formatPluginConsole(bundle: PluginExecutionBundle): string {
  const cols = columnNames(bundle);
  const rows = bundle.result.rows ?? [];
  if (cols.length === 0) {
    if (rows.length === 0) return "";
    return rows
      .map((row) =>
        (row.cells ?? []).map((cell) => formatPluginCell(cell)).join("\t"),
      )
      .join("\n");
  }
  const widths = widthsFor(cols, rows);
  const header = cols
    .map((name, i) => padCell(name, widths[i], i === cols.length - 1))
    .join("")
    .trimEnd();
  const body = rows.map((row) =>
    cols
      .map((name, i) =>
        padCell(formatPluginCell(row.values?.[name]), widths[i], i === cols.length - 1),
      )
      .join("")
      .trimEnd(),
  );
  return [header, ...body].join("\n");
}

export function formatPluginTsv(bundle: PluginExecutionBundle): string {
  const cols = columnNames(bundle);
  const rows = bundle.result.rows ?? [];
  const esc = (value: string) =>
    /[\t\n\r"]/.test(value) ? `"${value.replace(/"/g, '""')}"` : value;
  const header = cols.join("\t");
  const body = rows.map((row) =>
    cols.map((name) => esc(formatPluginCell(row.values?.[name]))).join("\t"),
  );
  return [header, ...body].join("\n");
}

export function pluginCopyPayload(
  bundle: PluginExecutionBundle,
  view: "table" | "console",
): { text: string; label: string } {
  if (view === "console") {
    return { text: formatPluginConsole(bundle), label: "Console output copied" };
  }
  return { text: formatPluginTsv(bundle), label: "Table copied" };
}
