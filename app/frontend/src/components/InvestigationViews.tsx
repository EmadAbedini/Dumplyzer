import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { engineCall, EngineClientError } from "../lib/api";
import { formatResultCell } from "../lib/datetime";
import { matchesFieldQuery } from "../lib/resultFilter";
import { useTableSort } from "../lib/tableSort";
import {
  coverageLiveKind,
  coverageResultCaption,
} from "../lib/analysisCoverage";
import { findingSeverityRank, sortFindings } from "../lib/findings";
import {
  CenteredLoading,
  CoverageEmptyState,
  ImportEvidenceState,
  ListLoadingState,
  AnalysisScopeNote,
  coverageShowsEmptyPanel,
  LoadMoreBar,
} from "./CoverageStatus";
import {
  DERIVED_SOURCE_IDS,
  capabilityHasStoredData,
  findingsScopeNote,
  settledMissingSourceIds,
} from "../lib/analysisScope";
import type { AnalysisCoverage, ModuleRow, Finding, CapabilityCoverage } from "../lib/types";
import { FindingCard } from "./FindingCard";
import { ResultFilterBar } from "./ResultFilterBar";
import { SortableTh } from "./SortableTh";
import { cn } from "../lib/utils";

const FINDING_PAGE = 300;
const MODULE_PAGE = 500;
const findingsSeverityCache = new Map<string, Record<string, number>>();

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
  const [items, setItems] = useState<ModuleRow[]>([]);
  const itemsRef = useRef<ModuleRow[]>([]);
  itemsRef.current = items;
  const [loadedEvidenceId, setLoadedEvidenceId] = useState<string | null>(null);
  const [listedTotal, setListedTotal] = useState(0);
  const [listBusy, setListBusy] = useState(false);
  const loadGen = useRef(0);
  const [filter, setFilter] = useState("");
  const [filterField, setFilterField] = useState("all");

  const load = useCallback(
    async (append = false) => {
      if (!evidenceId) return;
      const gen = ++loadGen.current;
      setListBusy(true);
      try {
        const offset = append ? itemsRef.current.length : 0;
        const res = await engineCall<{ items: ModuleRow[]; total: number }>("modules.list", {
          evidence_id: evidenceId,
          limit: MODULE_PAGE,
          offset,
        });
        if (gen !== loadGen.current) return;
        const next = append ? [...itemsRef.current, ...res.items] : res.items;
        setItems(next);
        setListedTotal(res.total);
        setLoadedEvidenceId(evidenceId);
      } catch (e) {
        if (gen !== loadGen.current) return;
        if (!append) {
          setItems([]);
          setListedTotal(0);
          setLoadedEvidenceId(evidenceId);
        }
        onError(e instanceof EngineClientError ? e.message : String(e));
      } finally {
        if (gen === loadGen.current) setListBusy(false);
      }
    },
    [evidenceId, onError],
  );

  useEffect(() => {
    void load();
  }, [load, refreshToken]);

  const loading = Boolean(evidenceId) && loadedEvidenceId !== evidenceId;
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
      caption={coverageResultCaption(coverage, listedTotal || items.length, filtered.length)}
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
      total={listedTotal || items.length}
      loadedCount={items.length}
      hasMore={!filter.trim() && items.length < listedTotal}
      loadMoreBusy={listBusy}
      onLoadMore={() => void load(true)}
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
  const [items, setItems] = useState<Finding[]>([]);
  const itemsRef = useRef<Finding[]>([]);
  itemsRef.current = items;
  const [loadedEvidenceId, setLoadedEvidenceId] = useState<string | null>(null);
  const [filter, setFilter] = useState("");
  const [filterField, setFilterField] = useState("all");
  const [severityFilter, setSeverityFilter] = useState<string | null>(null);
  const [severityCounts, setSeverityCounts] = useState<Record<string, number>>(
    () => (evidenceId ? findingsSeverityCache.get(evidenceId) ?? {} : {}),
  );
  const [listBusy, setListBusy] = useState(false);
  const [listedTotal, setListedTotal] = useState(0);
  const loadGen = useRef(0);

  const load = useCallback(
    async (append = false) => {
      if (!evidenceId) return;
      const gen = ++loadGen.current;
      setListBusy(true);
      try {
        const offset = append ? itemsRef.current.length : 0;
        const res = await engineCall<{
          items: Finding[];
          total: number;
          severity_counts?: Record<string, number>;
        }>("findings.list", {
          evidence_id: evidenceId,
          severity: severityFilter || undefined,
          limit: FINDING_PAGE,
          offset,
        });
        if (gen !== loadGen.current) return;
        const next = append ? [...itemsRef.current, ...res.items] : res.items;
        setItems(next);
        setListedTotal(res.total);
        const counts = res.severity_counts ?? {};
        setSeverityCounts(counts);
        if (evidenceId) findingsSeverityCache.set(evidenceId, counts);
      } catch (e) {
        if (gen !== loadGen.current) return;
        if (!append) {
          setItems([]);
          setListedTotal(0);
          setSeverityCounts({});
        }
        onError(e instanceof EngineClientError ? e.message : String(e));
      } finally {
        if (gen === loadGen.current) {
          setListBusy(false);
          setLoadedEvidenceId(evidenceId);
        }
      }
    },
    [evidenceId, severityFilter, onError],
  );

  useEffect(() => {
    setSeverityFilter(null);
    setItems([]);
    setSeverityCounts(evidenceId ? findingsSeverityCache.get(evidenceId) ?? {} : {});
  }, [evidenceId]);

  useEffect(() => {
    void load();
  }, [load, refreshToken]);

  const severityEntries = useMemo(
    () =>
      Object.entries(severityCounts).sort(
        (a, b) => findingSeverityRank(a[0]) - findingSeverityRank(b[0]),
      ),
    [severityCounts],
  );

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
  const missingSources = settledMissingSourceIds(analysisCoverage, DERIVED_SOURCE_IDS.findings);
  const commandLinesReady = capabilityHasStoredData(analysisCoverage, "command_lines");
  const findingsNotAnalyzedDetail = commandLinesReady
    ? "Command lines are stored, but Findings was not included in the last analysis."
    : "Findings come from collected command lines and Analyze Process, not a scan of the whole dump.";
  const findingsNotAnalyzedHint = commandLinesReady
    ? "Run Complete Analysis, or select Findings in Custom Analysis."
    : "Quick Triage does not collect command lines. Run Complete Analysis, or select Command Lines and Findings in Custom Analysis.";
  const findingsZeroHint =
    missingSources.length > 0
      ? "Command lines were not collected in the last analysis, so command-line heuristics had little to evaluate."
      : undefined;
  const loading = loadedEvidenceId !== evidenceId || (listBusy && items.length === 0);
  const findingTotal = coverage?.count ?? listedTotal;
  const captionTotal = severityFilter ? listedTotal : findingTotal;
  const coverageKind = coverageLiveKind(coverage);
  const showFilterType =
    severityEntries.length > 0 ||
    (loading &&
      (coverageKind === "analyzed" ||
        coverageKind === "in_progress" ||
        coverageKind === "has_results" ||
        coverageKind === "partial"));

  if (!evidenceId) return <ImportEvidenceState title="Findings" />;

  return (
    <div className="flex h-full min-h-0 flex-1 flex-col text-xs">
      <div className="flex flex-wrap items-center gap-2 border-b border-border px-3 py-2">
        <div className="text-sm font-semibold">Findings</div>
        <div className="text-xs text-muted">
          {coverageResultCaption(coverage, captionTotal, filtered.length) ??
            `${filtered.length.toLocaleString()} / ${captionTotal.toLocaleString()} records`}
        </div>
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
      {showFilterType ? (
        <div className="flex min-h-9 flex-wrap items-center gap-1.5 border-b border-border px-3 py-2">
          <span className="mr-1 text-[0.78rem] font-semibold text-muted">Filter Type</span>
          {severityEntries.map(([severity, count]) => {
            const active = severityFilter === severity;
            return (
              <button
                key={severity}
                type="button"
                onClick={() => setSeverityFilter(active ? null : severity)}
                className={cn(
                  "h-6 cursor-pointer rounded-md border px-1.5 text-[0.78rem] font-medium capitalize leading-none",
                  active
                    ? "border-accent bg-accent/15 text-accent"
                    : "border-border bg-surface-2 text-muted hover:bg-surface-2/80 hover:text-foreground",
                )}
              >
                {severity} {count.toLocaleString()}
              </button>
            );
          })}
          <button
            type="button"
            disabled={!severityFilter}
            aria-hidden={!severityFilter}
            tabIndex={severityFilter ? 0 : -1}
            onClick={() => setSeverityFilter(null)}
            className={cn(
              "h-6 rounded-md border px-1.5 text-[0.78rem] font-medium leading-none",
              severityFilter
                ? "cursor-pointer border-border bg-transparent text-muted hover:bg-surface-2/80 hover:text-foreground"
                : "invisible pointer-events-none",
            )}
          >
            Clear
          </button>
        </div>
      ) : null}
      <div className="border-b border-border px-3 py-2">
        <AnalysisScopeNote>{findingsScopeNote(missingSources)}</AnalysisScopeNote>
      </div>
      {loading && items.length === 0 && coverageLiveKind(coverage) !== "in_progress" ? (
        <CenteredLoading />
      ) : items.length === 0 ? (
        <CoverageEmptyState
          item={coverage}
          title="Findings"
          showTitle={false}
          inProgressDetail="Findings are still being analyzed."
          analyzedZeroDetail="Complete Analysis found no matching command-line heuristics (encoded PowerShell, cmd.exe LOLBins, or user-temp execution). Memory-region findings appear after Analyze process."
          analyzedZeroHint={findingsZeroHint}
          notAnalyzedDetail={findingsNotAnalyzedDetail}
          notAnalyzedHint={findingsNotAnalyzedHint}
          failedDetail="Findings analysis failed."
        />
      ) : (
        <div className="min-h-0 flex-1 space-y-2 overflow-auto p-3">
          {filtered.map((f) => (
            <FindingCard key={f.id} finding={f} onOpenProcess={onOpenProcess} />
          ))}
          {filtered.length === 0 && (
            <div className="p-4 text-muted">No findings match the current filter.</div>
          )}
          {!filter.trim() ? (
            <LoadMoreBar
              loaded={items.length}
              total={listedTotal}
              busy={listBusy}
              onLoadMore={() => void load(true)}
            />
          ) : null}
        </div>
      )}
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
  loadedCount,
  hasMore,
  loadMoreBusy,
  onLoadMore,
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
  loadedCount?: number;
  hasMore?: boolean;
  loadMoreBusy?: boolean;
  onLoadMore?: () => void;
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
    <div className="flex h-full min-h-0 flex-col text-xs">
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
          {hasMore && onLoadMore ? (
            <LoadMoreBar
              loaded={loadedCount ?? rows.length}
              total={count}
              busy={loadMoreBusy}
              onLoadMore={onLoadMore}
            />
          ) : null}
        </div>
      )}
    </div>
  );
}
