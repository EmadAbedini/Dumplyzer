import { useCallback, useEffect, useMemo, useState } from "react";
import { CircleDashed, Search } from "lucide-react";
import { save } from "@tauri-apps/plugin-dialog";
import { copyExportFile, engineCall, EngineClientError } from "../lib/api";
import {
  SEARCHABLE_IDS,
  coverageHasSearchableData,
  coverageItem,
  coverageLiveKind,
  coverageIsUpdating,
  coverageResultCaption,
  coverageWasExecuted,
} from "../lib/analysisCoverage";
import {
  AnalysisScopeNote,
  CoverageEmptyState,
  CenteredLoading,
  ImportEvidenceState,
} from "./CoverageStatus";
import {
  DERIVED_SOURCE_IDS,
  STORED_ACTION_TITLE,
  formatCapabilityList,
  limitedResultsNote,
  searchFieldHasData,
  storedActionNote,
  uncoveredSourceIds,
} from "../lib/analysisScope";
import { matchesFieldQuery } from "../lib/resultFilter";
import { useTableSort } from "../lib/tableSort";
import type { AnalysisCoverage, CapabilityCoverage, SearchHit, Ioc } from "../lib/types";
import { Button } from "./ui/button";
import { ClearableInput } from "./ui/input";
import { Badge } from "./ui/badge";
import { ResultFilterBar } from "./ResultFilterBar";
import { SortableTh } from "./SortableTh";
import { RefreshButton, StatusToast, useStatusToast } from "./StatusToast";

const SEARCH_LIMIT = 300;

const SEARCH_FIELDS = [
  {
    id: "all",
    label: "All",
    placeholder: "Process, PID, IP, DLL, path, command line…",
  },
  { id: "process_names", label: "Process names", placeholder: "Process name…" },
  { id: "pids", label: "PIDs", placeholder: "PID or PPID…" },
  { id: "command_lines", label: "Command lines", placeholder: "Command line…" },
  { id: "usernames", label: "Usernames", placeholder: "Username…" },
  { id: "modules", label: "Modules", placeholder: "Module or DLL name…" },
  { id: "ip_addresses", label: "IP addresses", placeholder: "IP address…" },
  { id: "ports", label: "Ports", placeholder: "Port number…" },
  { id: "file_paths", label: "File paths", placeholder: "File path…" },
  { id: "handles", label: "Handles", placeholder: "Handle name…" },
  { id: "findings", label: "Findings", placeholder: "Finding type or text…" },
  { id: "iocs", label: "IOCs", placeholder: "IOC value or type…" },
] as const;

type SearchFieldId = (typeof SEARCH_FIELDS)[number]["id"];

const SEARCH_SCOPE =
  "Search process names, PIDs, command lines, usernames, modules, IP addresses, ports, file paths, handles, findings, and IOCs.";

const SEARCH_SOURCE_HINT =
  "Search looks through analysis results already stored for this dump. It does not rescan the memory image.";

const ENTITY_LABEL: Record<string, string> = {
  process: "Process",
  module: "Module",
  network: "Network",
  finding: "Finding",
  handle: "Handle",
  ioc: "IOC",
  network_artifact: "Network artifact",
};

function searchEntityLabel(entity: string): string {
  if (ENTITY_LABEL[entity]) return ENTITY_LABEL[entity];
  return entity.replace(/[_-]+/g, " ");
}

function SearchEmptyPanel({
  heading,
  detail,
  hint,
  icon = "search",
}: {
  heading: string;
  detail: string;
  hint?: string;
  icon?: "search" | "empty";
}) {
  return (
    <div className="flex min-h-[16rem] flex-1 flex-col items-center justify-center px-6 py-16 text-center">
      <div
        className="flex h-12 w-12 items-center justify-center rounded-full bg-surface-2"
        aria-hidden
      >
        {icon === "empty" ? (
          <CircleDashed className="h-5 w-5 text-muted" strokeWidth={1.75} />
        ) : (
          <Search className="h-5 w-5 text-muted" strokeWidth={1.75} />
        )}
      </div>
      <div className="mt-4 text-sm font-semibold">{heading}</div>
      <p className="mt-4 max-w-md text-sm leading-5 text-muted">{detail}</p>
      {hint ? <p className="mt-3 max-w-md text-xs leading-5 text-muted">{hint}</p> : null}
    </div>
  );
}

export function SearchView({
  evidenceId,
  coverage,
  onOpenProcess,
  onError,
}: {
  evidenceId: string | null;
  coverage?: AnalysisCoverage;
  onOpenProcess: (processId: string) => void;
  onError: (m: string) => void;
}) {
  const [q, setQ] = useState("");
  const [scope, setScope] = useState<SearchFieldId>("all");
  const [items, setItems] = useState<SearchHit[]>([]);
  const [busy, setBusy] = useState(false);
  const [lastQuery, setLastQuery] = useState<string | null>(null);

  const field = SEARCH_FIELDS.find((item) => item.id === scope) ?? SEARCH_FIELDS[0];
  const missingSources = uncoveredSourceIds(coverage, DERIVED_SOURCE_IDS.search);
  const limitedSearch = missingSources.length > 0;

  const run = useCallback(async () => {
    const query = q.trim();
    if (!evidenceId || !query) return;
    setBusy(true);
    try {
      const res = await engineCall<{ items: SearchHit[] }>("search.query", {
        evidence_id: evidenceId,
        query,
        scope,
        limit: SEARCH_LIMIT,
      });
      setItems(res.items);
      setLastQuery(query);
    } catch (e) {
      onError(e instanceof EngineClientError ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }, [evidenceId, q, scope, onError]);

  const clearSearch = useCallback(() => {
    setQ("");
    setItems([]);
    setLastQuery(null);
  }, []);

  const searchSortValue = useCallback((h: SearchHit, key: string) => {
    if (key === "entity") return searchEntityLabel(h.entity);
    if (key === "value") return h.value ?? "";
    if (key === "context") return h.context ?? "";
    if (key === "pid") return h.pid;
    if (key === "source") return h.plugin ?? h.source ?? "";
    return "";
  }, []);
  const { sorted, sort, toggle } = useTableSort(items, searchSortValue);
  const capped = items.length >= SEARCH_LIMIT;
  const resultCaption =
    lastQuery == null || items.length === 0
      ? null
      : capped
        ? `Showing first ${SEARCH_LIMIT.toLocaleString()} results for “${lastQuery}”`
        : `${items.length.toLocaleString()} result${items.length === 1 ? "" : "s"} for “${lastQuery}”`;

  if (!evidenceId) {
    return <ImportEvidenceState title="Search" />;
  }

  if (!coverageHasSearchableData(coverage)) {
    const pending = SEARCHABLE_IDS.some(
      (id) => coverageLiveKind(coverageItem(coverage, id)) === "in_progress",
    );
    if (pending) {
      return (
        <CoverageEmptyState
          item={{ id: "search", state: "not_analyzed", count: 0 }}
          title="Search"
          inProgressDetail="Searchable analysis data is still being collected."
          analyzedZeroDetail=""
          notAnalyzedDetail={SEARCH_SCOPE}
          failedDetail="Searchable analysis data is not available."
        />
      );
    }
    return (
      <div className="flex h-full min-h-0 flex-1 flex-col">
        <div className="border-b border-border px-3 py-2 text-sm font-semibold">Search</div>
        <SearchEmptyPanel
          heading="Nothing to search yet"
          detail="Search looks through analysis results already stored for this dump. It does not rescan the memory image."
          hint="Quick Triage only collects processes. Run Complete Analysis, or select the capabilities you want to search in Custom Analysis."
        />
      </div>
    );
  }

  return (
    <div className="flex h-full flex-col text-xs">
      <div className="flex flex-wrap items-center gap-2 border-b border-border px-3 py-2">
        <div className="shrink-0 text-sm font-semibold">Search</div>
        <form
          role="search"
          className="flex min-w-0 flex-1 basis-80 items-center gap-2"
          onSubmit={(e) => {
            e.preventDefault();
            void run();
          }}
        >
          <select
            aria-label="Search field"
            className="app-result-filter-field search-scope-field h-8 shrink-0 rounded-md border border-border bg-surface px-2.5 pr-8 text-sm text-foreground shadow-sm outline-none transition-colors focus:border-accent"
            value={scope}
            onChange={(e) => {
              setScope(e.target.value as SearchFieldId);
              setItems([]);
              setLastQuery(null);
            }}
          >
            {SEARCH_FIELDS.map((item) => {
              const available = searchFieldHasData(coverage, item.id);
              return (
                <option key={item.id} value={item.id} disabled={!available}>
                  {available ? item.label : `${item.label} (not analyzed)`}
                </option>
              );
            })}
          </select>
          <ClearableInput
            type="search"
            autoFocus
            autoComplete="off"
            spellCheck={false}
            aria-label="Search analysis results"
            placeholder={field.placeholder}
            value={q}
            onChange={(e) => setQ(e.target.value)}
            onClear={() => setQ("")}
            onKeyDown={(e) => {
              if (e.key === "Escape") clearSearch();
            }}
          />
          <Button size="sm" type="submit" disabled={busy || !q.trim()}>
            {busy ? "Searching…" : "Search"}
          </Button>
          <Button
            size="sm"
            type="button"
            variant="outline"
            disabled={busy || (lastQuery == null && !q.trim())}
            onClick={clearSearch}
          >
            Clear
          </Button>
        </form>
        {resultCaption ? <div className="text-xs text-muted">{resultCaption}</div> : null}
      </div>
      {limitedSearch ? (
        <div className="border-b border-border px-3 py-2">
          <AnalysisScopeNote>{limitedResultsNote(missingSources)}</AnalysisScopeNote>
        </div>
      ) : null}
      <div className="min-h-0 flex-1 overflow-auto">
        {busy && items.length === 0 ? (
          <CenteredLoading label="Searching…" />
        ) : lastQuery == null ? (
          <SearchEmptyPanel
            heading="Search analysis results"
            detail={
              scope === "all"
                ? SEARCH_SCOPE
                : `Search ${field.label.toLowerCase()} in stored analysis results.`
            }
            hint={`${SEARCH_SOURCE_HINT} Press Enter or Search.`}
          />
        ) : items.length === 0 && !busy ? (
          <SearchEmptyPanel
            icon="empty"
            heading="No matches"
            detail={
              scope === "all"
                ? `Nothing matched “${lastQuery}”. Try another term, or choose a field from the menu.`
                : `Nothing matched “${lastQuery}” in ${field.label.toLowerCase()}. Try another term, or switch the field to All.`
            }
            hint={
              limitedSearch
                ? `Search is case-insensitive and matches partial text. Fields marked “not analyzed” have no stored data yet.`
                : "Search is case-insensitive and matches partial text."
            }
          />
        ) : (
          <table className="app-result-table w-full text-center">
            <thead className="sticky top-0 bg-surface-2 text-muted">
              <tr>
                <SortableTh label="Entity" column="entity" sort={sort} onToggle={toggle} />
                <SortableTh label="Value" column="value" sort={sort} onToggle={toggle} />
                <SortableTh label="Context" column="context" sort={sort} onToggle={toggle} />
                <SortableTh label="PID" column="pid" sort={sort} onToggle={toggle} />
                <SortableTh label="Source" column="source" sort={sort} onToggle={toggle} />
              </tr>
            </thead>
            <tbody>
              {sorted.map((h, i) => (
                <tr key={`${h.entity}:${h.ref_id ?? i}:${h.value}`} className="border-t border-border/40">
                  <td className="px-2 py-1">
                    <Badge>{searchEntityLabel(h.entity)}</Badge>
                  </td>
                  <td
                    className="max-w-xl px-2 py-1 text-left font-mono whitespace-pre-wrap break-all [overflow-wrap:anywhere]"
                    title={h.value}
                  >
                    {h.value}
                  </td>
                  <td
                    className="max-w-lg px-2 py-1 text-left text-muted whitespace-pre-wrap break-all [overflow-wrap:anywhere]"
                    title={h.context}
                  >
                    {h.context || "—"}
                  </td>
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
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

export function IocsView({
  evidenceId,
  onError,
  coverage,
  analysisCoverage,
  refreshToken,
}: {
  evidenceId: string | null;
  onError: (m: string) => void;
  coverage?: CapabilityCoverage;
  analysisCoverage?: AnalysisCoverage;
  refreshToken?: number | string;
}) {
  const [items, setItems] = useState<Ioc[]>([]);
  const [loadedEvidenceId, setLoadedEvidenceId] = useState<string | null>(null);
  const [filter, setFilter] = useState("");
  const [filterField, setFilterField] = useState("all");
  const [busy, setBusy] = useState(false);
  const [exporting, setExporting] = useState<"json" | "xlsx" | null>(null);
  const [listedTotal, setListedTotal] = useState(0);
  const [extractedHere, setExtractedHere] = useState(false);
  const { toast, showToast } = useStatusToast();

  const load = useCallback(async () => {
    if (!evidenceId) return;
    try {
      const res = await engineCall<{ items: Ioc[]; total: number }>("iocs.list", {
        evidence_id: evidenceId,
      });
      setItems(res.items);
      setListedTotal(res.total);
    } catch (e) {
      setItems([]);
      setListedTotal(0);
      throw e;
    } finally {
      setLoadedEvidenceId(evidenceId);
    }
  }, [evidenceId]);

  useEffect(() => {
    setExtractedHere(false);
  }, [evidenceId]);

  useEffect(() => {
    void (async () => {
      try {
        await load();
      } catch (e) {
        onError(e instanceof EngineClientError ? e.message : String(e));
      }
    })();
  }, [load, onError, refreshToken]);

  const extract = async () => {
    if (!evidenceId) return;
    setBusy(true);
    try {
      const res = await engineCall<{ items: Ioc[]; total: number }>("iocs.extract", {
        evidence_id: evidenceId,
      });
      setItems(res.items);
      setListedTotal(res.total);
      setLoadedEvidenceId(evidenceId);
      setExtractedHere(true);
      const n = res.total;
      const missing = uncoveredSourceIds(analysisCoverage, DERIVED_SOURCE_IDS.iocs);
      if (missing.length > 0) {
        const list = formatCapabilityList(missing);
        const verb = missing.length === 1 ? "was" : "were";
        showToast(
          n === 0
            ? `No IOCs in the data already stored. ${list} ${verb} not analyzed.`
            : `Extracted ${n.toLocaleString()} IOCs from stored analysis results. ${list} ${verb} not analyzed.`,
        );
      } else {
        showToast(
          n === 0
            ? "No IOCs in the stored analysis results."
            : `Extracted ${n.toLocaleString()} IOCs from stored analysis results.`,
        );
      }
    } catch (e) {
      onError(e instanceof EngineClientError ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  const doExport = async (fmt: "json" | "xlsx") => {
    if (!evidenceId || exporting) return;
    let dest: string | null;
    try {
      dest = await save({
        title: "Save IOC export",
        defaultPath: fmt === "json" ? "iocs-json.zip" : "iocs.xlsx",
        filters:
          fmt === "json"
            ? [{ name: "ZIP archive", extensions: ["zip"] }]
            : [{ name: "Excel workbook", extensions: ["xlsx"] }],
      });
    } catch (e) {
      onError(e instanceof EngineClientError ? e.message : String(e));
      return;
    }
    if (dest == null || dest === "") return;
    const ext = fmt === "json" ? ".zip" : ".xlsx";
    if (!dest.toLowerCase().endsWith(ext)) dest = `${dest}${ext}`;
    setExporting(fmt);
    try {
      const res = await engineCall<{
        count: number;
        type_count?: number;
        primary_path: string | null;
      }>(fmt === "json" ? "iocs.export_json" : "iocs.export_xlsx", {
        evidence_id: evidenceId,
      });
      if (!res.primary_path) {
        throw new Error("Export did not produce a file.");
      }
      await copyExportFile(res.primary_path, dest);
      const types = res.type_count ?? 0;
      showToast(
        types > 1
          ? `Saved ${res.count.toLocaleString()} IOCs in ${types} files`
          : `Saved ${res.count.toLocaleString()} IOCs`,
      );
    } catch (e) {
      onError(e instanceof EngineClientError ? e.message : String(e));
    } finally {
      setExporting(null);
    }
  };

  const filtered = useMemo(
    () =>
      items.filter((i) =>
        matchesFieldQuery(filter, filterField, {
          type: i.ioc_type,
          value: i.value,
          pid: i.pid,
          context: i.context,
          source: i.source,
        }),
      ),
    [items, filter, filterField],
  );
  const iocSortValue = useCallback((i: Ioc, key: string) => {
    if (key === "type") return i.ioc_type ?? "";
    if (key === "value") return i.value ?? "";
    if (key === "pid") return i.pid;
    if (key === "context") return i.context ?? "";
    if (key === "source") return i.source ?? "";
    return "";
  }, []);
  const { sorted, sort, toggle } = useTableSort(filtered, iocSortValue);
  const loading = loadedEvidenceId !== evidenceId;
  const updating = coverageIsUpdating(coverage);
  const actionsLocked = busy || updating || exporting !== null;
  const iocTotal = coverage?.count ?? listedTotal;
  const showExtract =
    !coverageWasExecuted(coverage) && coverageLiveKind(coverage) !== "in_progress";
  const missingSources = uncoveredSourceIds(analysisCoverage, DERIVED_SOURCE_IDS.iocs);
  const showLimitedNote = items.length > 0 && missingSources.length > 0;
  const iocEmptyItem =
    extractedHere && items.length === 0 && coverageLiveKind(coverage) === "not_analyzed"
      ? { id: "iocs", state: "analyzed_zero" as const, count: 0 }
      : coverage;
  const iocNotAnalyzedDetail =
    "IOCs are pulled from process, module, network, and handle data already stored — not by rescanning the dump.";
  const iocNotAnalyzedHint =
    missingSources.length > 0
      ? `${storedActionNote(missingSources)} You can still extract from whatever is stored.`
      : "Use Extract IOCs to collect indicators from the data already stored, or include IOC Extraction in Complete or Custom Analysis.";
  const iocAnalyzedZeroDetail =
    missingSources.length > 0
      ? "IOC extraction ran against the data that was stored, and found no indicators."
      : "IOC extraction completed and found no indicators.";
  const iocAnalyzedZeroHint =
    missingSources.length > 0 ? storedActionNote(missingSources) : undefined;

  if (!evidenceId) {
    return <ImportEvidenceState title="IOCs" />;
  }

  return (
    <div className="flex h-full min-h-0 flex-1 flex-col text-xs">
      <div className="flex flex-wrap items-center gap-2 border-b border-border px-3 py-2">
        <div className="text-sm font-semibold">IOCs</div>
        <div className="text-xs text-muted">
          {coverageResultCaption(coverage, iocTotal, filtered.length)}
        </div>
        {showExtract ? (
          <span className="inline-flex" title={STORED_ACTION_TITLE}>
            <Button size="sm" onClick={() => void extract()} disabled={actionsLocked}>
              {busy ? "Extracting…" : "Extract IOCs"}
            </Button>
          </span>
        ) : null}
        <RefreshButton
          onRefresh={load}
          doneMessage="IOCs updated"
          showToast={showToast}
          disabled={actionsLocked}
        />
        <Button
          size="sm"
          variant="outline"
          onClick={() => void doExport("json")}
          disabled={actionsLocked}
        >
          {exporting === "json" ? "Saving…" : "Export JSON"}
        </Button>
        <Button
          size="sm"
          variant="outline"
          onClick={() => void doExport("xlsx")}
          disabled={actionsLocked}
        >
          {exporting === "xlsx" ? "Saving…" : "Export Excel"}
        </Button>
        <ResultFilterBar
          query={filter}
          onQueryChange={setFilter}
          field={filterField}
          onFieldChange={setFilterField}
          placeholder="Filter value / type / PID / source…"
          fields={[
            { id: "type", label: "Type" },
            { id: "value", label: "Value" },
            { id: "pid", label: "PID" },
            { id: "context", label: "Context" },
            { id: "source", label: "Source" },
          ]}
        />
      </div>
      {showLimitedNote ? (
        <div className="border-b border-border px-3 py-2">
          <AnalysisScopeNote>{limitedResultsNote(missingSources)}</AnalysisScopeNote>
        </div>
      ) : null}
      {loading && items.length === 0 && coverageLiveKind(coverage) !== "in_progress" ? (
        <CenteredLoading />
      ) : items.length === 0 ? (
        <CoverageEmptyState
          item={iocEmptyItem}
          title="IOCs"
          showTitle={false}
          inProgressDetail="IOCs are still being extracted."
          analyzedZeroDetail={iocAnalyzedZeroDetail}
          analyzedZeroHint={iocAnalyzedZeroHint}
          notAnalyzedDetail={iocNotAnalyzedDetail}
          notAnalyzedHint={iocNotAnalyzedHint}
          failedDetail="IOC extraction failed."
        />
      ) : (
      <div className="min-h-0 flex-1 overflow-auto">
        <table className="app-result-table w-full text-center">
          <thead className="sticky top-0 bg-surface-2 text-muted">
            <tr>
              <SortableTh label="Type" column="type" sort={sort} onToggle={toggle} />
              <SortableTh label="Value" column="value" sort={sort} onToggle={toggle} />
              <SortableTh label="PID" column="pid" sort={sort} onToggle={toggle} />
              <SortableTh label="Context" column="context" sort={sort} onToggle={toggle} />
              <SortableTh label="Source" column="source" sort={sort} onToggle={toggle} />
            </tr>
          </thead>
          <tbody>
            {sorted.map((i) => (
              <tr key={i.id} className="border-t border-border/40">
                <td className="whitespace-nowrap px-2 py-1">
                  <Badge>{i.ioc_type}</Badge>
                </td>
                <td className="px-2 py-1 font-mono whitespace-pre-wrap break-all [overflow-wrap:anywhere]">
                  {i.value}
                </td>
                <td className="whitespace-nowrap px-2 py-1 font-mono">{i.pid ?? "—"}</td>
                <td className="max-w-sm truncate px-2 py-1 text-muted">{i.context ?? "—"}</td>
                <td className="whitespace-nowrap px-2 py-1 text-muted">{i.source ?? "—"}</td>
              </tr>
            ))}
            {filtered.length === 0 && (
              <tr>
                <td colSpan={5} className="px-3 py-6 text-muted">
                  No IOCs match the current filter.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
      )}
      <StatusToast message={toast} />
    </div>
  );
}
