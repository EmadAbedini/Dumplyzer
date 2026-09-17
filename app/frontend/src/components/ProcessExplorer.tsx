import { useCallback, useMemo, useState, type KeyboardEvent } from "react";
import { ChevronRight } from "lucide-react";
import { TimestampText } from "../lib/datetime";
import { matchesFieldQuery } from "../lib/resultFilter";
import { useTableSort } from "../lib/tableSort";
import { coverageResultCaption } from "../lib/analysisCoverage";
import type { ProcessRow, CapabilityCoverage } from "../lib/types";
import { CoverageEmptyState, ImportEvidenceState, coverageShowsEmptyPanel } from "./CoverageStatus";
import { ResultFilterBar } from "./ResultFilterBar";
import { SortableTh } from "./SortableTh";

type Props = {
  evidenceId?: string | null;
  items: ProcessRow[];
  total: number;
  loading: boolean;
  selectedId?: string | null;
  onSelect: (p: ProcessRow) => void;
  coverage?: CapabilityCoverage;
};

export function ProcessExplorer({
  evidenceId,
  items,
  total,
  loading,
  selectedId,
  onSelect,
  coverage,
}: Props) {
  const [filter, setFilter] = useState("");
  const [filterField, setFilterField] = useState("all");
  const filtered = useMemo(() => {
    return items.filter((p) =>
      matchesFieldQuery(
        filter,
        filterField,
        {
          pid: p.pid,
          ppid: p.ppid,
          name: p.name,
          cmdline: p.command_line,
          threads: p.threads,
          created: p.create_time,
        },
        [p.image_path, p.username],
      ),
    );
  }, [items, filter, filterField]);

  const processSortValue = useCallback((p: ProcessRow, key: string) => {
    if (key === "pid") return p.pid;
    if (key === "ppid") return p.ppid;
    if (key === "name") return p.name ?? "";
    if (key === "cmdline") return p.command_line ?? "";
    if (key === "threads") return p.threads;
    if (key === "created") return p.create_time ?? "";
    return "";
  }, []);
  const { sorted, sort, toggle } = useTableSort(filtered, processSortValue);

  if (!evidenceId) {
    return <ImportEvidenceState title="Processes" />;
  }

  if (!loading && items.length === 0 && coverageShowsEmptyPanel(coverage, 0)) {
    return (
      <CoverageEmptyState
        item={coverage}
        title="Processes"
        inProgressDetail="Processes are still being analyzed."
        analyzedZeroDetail="Process analysis completed and found no processes."
        notAnalyzedDetail="This capability was not included in the selected analysis mode."
        notAnalyzedHint="Run Quick Triage, Complete Analysis, or select Processes in Custom Analysis to analyze it."
        failedDetail="Process analysis failed."
      />
    );
  }

  return (
    <div className="flex h-full flex-col">
      <div className="flex items-center gap-2 border-b border-border px-3 py-2">
        <div className="min-w-0 shrink-0">
          <div className="flex items-baseline gap-2">
            <div className="text-sm font-semibold">Processes</div>
            <div className="text-xs text-muted">
              {loading
                ? "Loading…"
                : coverageResultCaption(coverage, total, filtered.length) ?? `${filtered.length} / ${total}`}
            </div>
          </div>
          <div className="text-xs text-muted">Select a process to inspect its details.</div>
        </div>
        <ResultFilterBar
          query={filter}
          onQueryChange={setFilter}
          field={filterField}
          onFieldChange={setFilterField}
          placeholder="Filter PID / name / cmdline…"
          fields={[
            { id: "pid", label: "PID" },
            { id: "ppid", label: "PPID" },
            { id: "name", label: "Name" },
            { id: "cmdline", label: "Command line" },
            { id: "threads", label: "Threads" },
            { id: "created", label: "Create time" },
          ]}
        />
      </div>
      <div className="min-h-0 flex-1 overflow-auto">
        <table className="app-result-table w-full border-collapse text-center text-xs">
          <thead className="sticky top-0 bg-surface-2 text-muted">
            <tr>
              <SortableTh label="PID" column="pid" sort={sort} onToggle={toggle} className="w-[4.5rem] whitespace-nowrap" />
              <SortableTh label="PPID" column="ppid" sort={sort} onToggle={toggle} className="w-[4.5rem] whitespace-nowrap" />
              <SortableTh label="Name" column="name" sort={sort} onToggle={toggle} className="w-[10rem]" />
              <SortableTh label="Command line" column="cmdline" sort={sort} onToggle={toggle} />
              <SortableTh label="Threads" column="threads" sort={sort} onToggle={toggle} className="w-[5.5rem] whitespace-nowrap" />
              <SortableTh label="Create time" column="created" sort={sort} onToggle={toggle} className="w-[11rem] whitespace-nowrap" />
              <th className="w-8 px-2 py-1.5" aria-hidden />
            </tr>
          </thead>
          <tbody>
            {sorted.map((p) => {
              const label = `Open details for ${p.name ?? "process"} (PID ${p.pid})`;
              const open = () => onSelect(p);
              const onRowKey = (e: KeyboardEvent<HTMLTableRowElement>) => {
                if (e.key === "Enter" || e.key === " ") {
                  e.preventDefault();
                  open();
                }
              };
              return (
              <tr
                key={p.id}
                tabIndex={0}
                role="link"
                aria-label={label}
                title={label}
                onClick={open}
                onKeyDown={onRowKey}
                className={
                  "cursor-pointer border-t border-border/40 " +
                  (selectedId === p.id ? "app-row-active" : "")
                }
              >
                <td className="whitespace-nowrap px-2 py-1 font-mono">{p.pid}</td>
                <td className="whitespace-nowrap px-2 py-1 font-mono">{p.ppid ?? "—"}</td>
                <td className="px-2 py-1">
                  <span className="font-medium text-accent">{p.name ?? "—"}</span>
                </td>
                <td className="px-2 py-1 font-mono text-muted whitespace-pre-wrap break-all [overflow-wrap:anywhere]">
                  {p.command_line ?? "—"}
                </td>
                <td className="whitespace-nowrap px-2 py-1 font-mono">{p.threads ?? "—"}</td>
                <td className="whitespace-nowrap px-2 py-1 font-mono">
                  <TimestampText value={p.create_time} />
                </td>
                <td className="px-2 py-1 text-muted" aria-hidden>
                  <ChevronRight className="mx-auto h-4 w-4" strokeWidth={2} />
                </td>
              </tr>
              );
            })}
            {!loading && filtered.length === 0 && (
              <tr>
                <td colSpan={7} className="px-3 py-6 text-muted">
                  No processes match the current filter.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
