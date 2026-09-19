import { useCallback, useEffect, useMemo, useState } from "react";
import { engineCall, EngineClientError } from "../lib/api";
import { formatResultCell } from "../lib/datetime";
import { matchesFieldQuery } from "../lib/resultFilter";
import { useTableSort } from "../lib/tableSort";
import {
  coverageLiveKind,
  coverageResultCaption,
} from "../lib/analysisCoverage";
import { countFindingsBySeverity, sortFindings } from "../lib/findings";
import {
  CoverageEmptyState,
  ImportEvidenceState,
  ListLoadingState,
  AnalysisScopeNote,
  coverageShowsEmptyPanel,
} from "./CoverageStatus";
import {
  DERIVED_SOURCE_IDS,
  capabilityHasStoredData,
  limitedResultsNote,
  settledMissingSourceIds,
} from "../lib/analysisScope";
import type { AnalysisCoverage, ModuleRow, Finding, CapabilityCoverage } from "../lib/types";
import { FindingCard } from "./FindingCard";
import { ResultFilterBar } from "./ResultFilterBar";
import { SortableTh } from "./SortableTh";

function PidCell({
  value,
  processId,
  onOpenProcess,
}: {
  value: string | number;
  processId?: string | null;
  onOpenProcess?: (processId: string) => void;
}) {
  const label = formatResultCell(value);
  if (processId && onOpenProcess) {
    return (
      <button
        type="button"
        className="text-accent hover:underline"
        onClick={() => onOpenProcess(processId)}
      >
        {label}
      </button>
    );
  }
  return <>{label}</>;
}

function useEvidenceItems<T>(
  evidenceId: string | null,
  method: string,
  onError: (m: string) => void,
  refreshToken?: number | string,
): { items: T[]; loading: boolean } {
  const [items, setItems] = useState<T[]>([]);
  const [loadedEvidenceId, setLoadedEvidenceId] = useState<string | null>(null);

  useEffect(() => {
    if (!evidenceId) {
      setItems([]);
      setLoadedEvidenceId(null);
      return;
    }
    let cancelled = false;
    void (async () => {
      try {
        const res = await engineCall<{ items: T[] }>(method, { evidence_id: evidenceId });
        if (!cancelled) {
          setItems(res.items);
          setLoadedEvidenceId(evidenceId);
        }
      } catch (e) {
        if (!cancelled) {
          setItems([]);
          setLoadedEvidenceId(evidenceId);
          onError(e instanceof EngineClientError ? e.message : String(e));
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [evidenceId, method, onError, refreshToken]);

  return {
    items,
    loading: Boolean(evidenceId) && loadedEvidenceId !== evidenceId,
  };
}

export function ModulesView({
  evidenceId,
  onError,
  coverage,
  refreshToken,
  onOpenProcess,
}: {
  evidenceId: string | null;
  onError: (m: string) => void;
  coverage?: CapabilityCoverage;
  refreshToken?: number | string;
  onOpenProcess: (processId: string) => void;
}) {
  const { items, loading } = useEvidenceItems<ModuleRow>(
    evidenceId,
    "modules.list",
    onError,
    refreshToken,
  );
  const [filter, setFilter] = useState("");
  const [filterField, setFilterField] = useState("all");

  const filtered = useMemo(
    () =>
      items.filter((m) =>
        matchesFieldQuery(
          filter,
          filterField,
          {
            pid: m.pid,
            process: m.process_name,
            name: m.name,
            base: m.base_address,
            path: m.path,
          },
          [m.size, m.source_plugin, m.process_name],
        ),
      ),
    [items, filter, filterField],
  );

  if (!evidenceId) return <ImportEvidenceState title="Modules / DLLs" />;
  if (loading && items.length === 0 && coverageLiveKind(coverage) !== "in_progress") {
    return <ListLoadingState title="Modules / DLLs" />;
  }
  if (coverageShowsEmptyPanel(coverage, items.length)) {
    return (
      <CoverageEmptyState
        item={coverage}
        title="Modules / DLLs"
        inProgressDetail="Modules / DLLs are still being analyzed."
        analyzedZeroDetail="Module analysis completed and found no modules."
        notAnalyzedDetail="This data was not collected in the analysis you ran."
        notAnalyzedHint="Quick Triage only collects processes. Run Complete Analysis, or select Modules in Custom Analysis."
        failedDetail="Module analysis failed."
      />
    );
  }
  return (
    <SimpleTable
      title="Modules / DLLs"
      caption={coverageResultCaption(coverage, items.length, filtered.length)}
      filter={filter}
      onFilter={setFilter}
      filterField={filterField}
      onFilterField={setFilterField}
      filterFields={[
        { id: "pid", label: "PID" },
        { id: "process", label: "Process" },
        { id: "name", label: "Name" },
        { id: "base", label: "Base" },
        { id: "path", label: "Path" },
      ]}
      filterPlaceholder="Filter name / path / PID…"
      empty="0 results. Module analysis completed and found no modules."
      emptyFilter="No modules match the current filter."
      columns={["PID", "Process", "Name", "Base", "Path"]}
      rows={filtered.map((m) => ({
        key: m.id,
        processId: m.process_id,
        cells: [
          m.pid ?? "—",
          m.process_name?.trim() || "—",
          m.name ?? "—",
          m.base_address ?? "—",
          m.path ?? "—",
        ],
      }))}
      total={items.length}
      onOpenProcess={onOpenProcess}
    />
  );
}

export function FindingsView({
  evidenceId,
  onError,
  coverage,
  analysisCoverage,
  refreshToken,
  onOpenProcess,
}: {
  evidenceId: string | null;
  onError: (m: string) => void;
  coverage?: CapabilityCoverage;
  analysisCoverage?: AnalysisCoverage;
  refreshToken?: number | string;
  onOpenProcess?: (processId: string) => void;
}) {
  const { items, loading } = useEvidenceItems<Finding>(
    evidenceId,
    "findings.list",
    onError,
    refreshToken,
  );
  const [filter, setFilter] = useState("");
  const [filterField, setFilterField] = useState("all");

  const filtered = useMemo(
    () =>
      sortFindings(
        items.filter((f) =>
          matchesFieldQuery(filter, filterField, {
            title: f.finding_type,
            severity: f.severity,
            evidence: f.explanation,
            pid: f.pid,
            plugin: f.plugin,
            field: f.field_name,
            value: f.field_value,
          }),
        ),
      ),
    [items, filter, filterField],
  );
  const severityCounts = useMemo(() => countFindingsBySeverity(filtered), [filtered]);
  const missingSources = settledMissingSourceIds(analysisCoverage, DERIVED_SOURCE_IDS.findings);
  const commandLinesReady = capabilityHasStoredData(analysisCoverage, "command_lines");
  const findingsNotAnalyzedDetail = commandLinesReady
    ? "Command lines are stored, but Findings was not included in the last analysis."
    : "Findings come from command-line heuristics already stored — they are not scanned from the dump itself.";
  const findingsNotAnalyzedHint = commandLinesReady
    ? "Run Complete Analysis, or select Findings in Custom Analysis."
    : "Quick Triage does not collect command lines. Run Complete Analysis, or select Command Lines and Findings in Custom Analysis.";
  const findingsZeroHint =
    missingSources.length > 0
      ? "Command lines were not collected in the last analysis, so command-line heuristics had little to evaluate."
      : undefined;

  if (!evidenceId) return <ImportEvidenceState title="Findings" />;
  if (loading && items.length === 0 && coverageLiveKind(coverage) !== "in_progress") {
    return <ListLoadingState title="Findings" />;
  }
  if (coverageShowsEmptyPanel(coverage, items.length)) {
    return (
      <div className="flex h-full min-h-0 flex-1 flex-col">
        {missingSources.length > 0 ? (
          <div className="border-b border-border px-3 py-2">
            <AnalysisScopeNote>{limitedResultsNote(missingSources)}</AnalysisScopeNote>
          </div>
        ) : null}
        <CoverageEmptyState
          item={coverage}
          title="Findings"
          inProgressDetail="Findings are still being analyzed."
          analyzedZeroDetail="Complete Analysis found no matching command-line heuristics (encoded PowerShell, cmd.exe LOLBins, or user-temp execution). Memory-region findings appear after Analyze process."
          analyzedZeroHint={findingsZeroHint}
          notAnalyzedDetail={findingsNotAnalyzedDetail}
          notAnalyzedHint={findingsNotAnalyzedHint}
          failedDetail="Findings analysis failed."
        />
      </div>
    );
  }
  return (
    <div className="flex h-full flex-col text-xs">
      <div className="flex flex-wrap items-center gap-2 border-b border-border px-3 py-2">
        <div className="text-sm font-semibold">Findings</div>
        <div className="text-xs text-muted">
          {coverageResultCaption(coverage, items.length, filtered.length) ??
            `${filtered.length.toLocaleString()} / ${items.length.toLocaleString()} records`}
        </div>
        {severityCounts.length > 0 ? (
          <div className="flex flex-wrap gap-1">
            {severityCounts.map((row) => (
              <span
                key={row.id}
                className="rounded-full border border-border bg-surface-2 px-2 py-0.5 text-[11px] capitalize text-muted"
              >
                {row.count} {row.id}
              </span>
            ))}
          </div>
        ) : null}
        <ResultFilterBar
          query={filter}
          onQueryChange={setFilter}
          field={filterField}
          onFieldChange={setFilterField}
          placeholder="Filter title / PID / evidence…"
          fields={[
            { id: "title", label: "Title" },
            { id: "severity", label: "Severity" },
            { id: "pid", label: "PID" },
            { id: "evidence", label: "Evidence" },
            { id: "plugin", label: "Plugin" },
          ]}
        />
      </div>
      {missingSources.length > 0 ? (
        <div className="border-b border-border px-3 py-2">
          <AnalysisScopeNote>{limitedResultsNote(missingSources)}</AnalysisScopeNote>
        </div>
      ) : null}
      <div className="min-h-0 flex-1 space-y-2 overflow-auto p-3">
        {filtered.map((f) => (
          <FindingCard key={f.id} finding={f} onOpenProcess={onOpenProcess} />
        ))}
        {filtered.length === 0 && (
          <div className="p-4 text-muted">No findings match the current filter.</div>
        )}
      </div>
    </div>
  );
}

function SimpleTable({
  title,
  caption,
  columns,
  rows,
  empty,
  emptyFilter,
  filter,
  onFilter,
  filterField,
  onFilterField,
  filterFields,
  filterPlaceholder,
  total,
  onOpenProcess,
}: {
  title: string;
  caption?: string | null;
  columns: string[];
  rows: { key: string; processId?: string | null; cells: (string | number)[] }[];
  empty: string;
  emptyFilter?: string;
  filter?: string;
  onFilter?: (value: string) => void;
  filterField?: string;
  onFilterField?: (value: string) => void;
  filterFields?: { id: string; label: string }[];
  filterPlaceholder?: string;
  total?: number;
  onOpenProcess?: (processId: string) => void;
}) {
  const count = total ?? rows.length;
  const getValue = useCallback(
    (row: { cells: (string | number)[] }, key: string) => row.cells[columns.indexOf(key)],
    [columns],
  );
  const { sorted, sort, toggle } = useTableSort(rows, getValue);
  const pidIndex = columns.indexOf("PID");
  return (
    <div className="flex h-full flex-col text-xs">
      <div className="flex items-center gap-2 border-b border-border px-3 py-2">
        <div className="text-sm font-semibold">{title}</div>
        <div className="text-xs text-muted">
          {caption ?? `${rows.length} / ${count}`}
        </div>
        {onFilter && filterFields && onFilterField ? (
          <ResultFilterBar
            query={filter ?? ""}
            onQueryChange={onFilter}
            field={filterField ?? "all"}
            onFieldChange={onFilterField}
            fields={filterFields}
            placeholder={filterPlaceholder}
          />
        ) : onFilter ? (
          <ResultFilterBar
            query={filter ?? ""}
            onQueryChange={onFilter}
            field="all"
            onFieldChange={() => undefined}
            fields={[]}
            placeholder={filterPlaceholder}
          />
        ) : null}
      </div>
      {count === 0 ? (
        <div className="p-4 text-muted">{empty}</div>
      ) : rows.length === 0 ? (
        <div className="p-4 text-muted">{emptyFilter ?? "No results match the current filter."}</div>
      ) : (
        <div className="min-h-0 flex-1 overflow-auto">
          <table className="app-result-table w-full text-center">
            <thead className="sticky top-0 bg-surface-2 text-muted">
              <tr>
                {columns.map((c) => (
                  <SortableTh key={c} label={c} column={c} sort={sort} onToggle={toggle} />
                ))}
              </tr>
            </thead>
            <tbody>
              {sorted.map((r) => (
                <tr key={r.key} className="border-t border-border/40">
                  {r.cells.map((cell, j) => (
                    <td key={j} className="max-w-[24rem] truncate px-2 py-1 font-mono">
                      {j === pidIndex ? (
                        <PidCell
                          value={cell}
                          processId={r.processId}
                          onOpenProcess={onOpenProcess}
                        />
                      ) : (
                        formatResultCell(cell)
                      )}
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
