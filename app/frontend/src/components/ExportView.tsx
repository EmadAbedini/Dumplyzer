import { useCallback, useEffect, useMemo, useState } from "react";
import { engineCall, EngineClientError } from "../lib/api";
import { TimestampText } from "../lib/datetime";
import { useTableSort } from "../lib/tableSort";
import type { AnalysisCoverage, ExportFormat, ExportOptions, ExportRecord, ExportScope, ExportUiState, Job } from "../lib/types";
import { exportStatusLabel } from "../lib/types";
import { Badge } from "./ui/badge";
import { Button } from "./ui/button";
import { SegmentedControl } from "./ui/segmented";
import { SortableTh } from "./SortableTh";
import { StatusToast, useStatusToast } from "./StatusToast";
import { ImportEvidenceState } from "./CoverageStatus";
import { EXPORT_JOB_BUSY_HINT, EXPORT_NEEDS_ANALYSIS_HINT } from "./Sidebar";
import { coverageCanExport } from "../lib/analysisCoverage";

const DEFAULT_SECTIONS = [
  "metadata",
  "summary",
  "findings",
  "processes",
  "network",
  "modules",
  "memory",
  "timeline",
  "iocs",
  "artifacts",
  "malware",
  "advanced",
];

const TABULAR_SECTIONS = new Set([
  "processes",
  "network",
  "modules",
  "memory",
  "findings",
  "iocs",
  "timeline",
  "artifacts",
]);

type Props = {
  evidenceId: string | null;
  refreshToken?: number;
  onError: (msg: string) => void;
  onJobSubmitted: (job: Job) => void;
  analysisBusy?: boolean;
  coverage?: AnalysisCoverage;
};

function statusFromJob(job: Job | null, fallback: ExportUiState): ExportUiState {
  if (!job) return fallback;
  if (job.status === "queued") return "queued";
  if (job.status === "running") return "running";
  if (job.status === "completed") return "completed";
  if (job.status === "failed") return "failed";
  if (job.status === "cancelled") return "cancelled";
  return fallback;
}

export function ExportView({
  evidenceId,
  refreshToken,
  onError,
  onJobSubmitted,
  analysisBusy = false,
  coverage,
}: Props) {
  const [options, setOptions] = useState<ExportOptions | null>(null);
  const [format, setFormat] = useState<ExportFormat>("html");
  const [scope, setScope] = useState<ExportScope>("complete");
  const [selected, setSelected] = useState<string[]>(DEFAULT_SECTIONS);
  const [uiState, setUiState] = useState<ExportUiState>("idle");
  const [job, setJob] = useState<Job | null>(null);
  const [exports, setExports] = useState<ExportRecord[]>([]);
  const [message, setMessage] = useState<string>("");
  const [checkedIds, setCheckedIds] = useState<Set<string>>(() => new Set());
  const [deleting, setDeleting] = useState(false);
  const { toast, showToast } = useStatusToast();

  const sectionList = options?.sections ?? DEFAULT_SECTIONS;

  const loadExports = useCallback(async () => {
    if (!evidenceId) {
      setExports([]);
      setCheckedIds(new Set());
      return;
    }
    const res = await engineCall<{ items: ExportRecord[] }>("export.list", {
      evidence_id: evidenceId,
      limit: 50,
    });
    setExports(res.items);
    setCheckedIds((prev) => {
      if (prev.size === 0) return prev;
      const keep = new Set(res.items.map((item) => item.id));
      const next = new Set([...prev].filter((id) => keep.has(id)));
      return next.size === prev.size ? prev : next;
    });
  }, [evidenceId]);

  useEffect(() => {
    void (async () => {
      try {
        const opts = await engineCall<ExportOptions>("export.options");
        setOptions(opts);
      } catch (err) {
        onError(err instanceof EngineClientError ? err.message : String(err));
      }
    })();
  }, [onError]);

  useEffect(() => {
    void loadExports().catch((err) => {
      onError(err instanceof EngineClientError ? err.message : String(err));
    });
  }, [loadExports, refreshToken, onError]);

  useEffect(() => {
    if (!job || (job.status !== "queued" && job.status !== "running")) return;
    const poll = async () => {
      try {
        const got = await engineCall<Job>("jobs.get", { job_id: job.id });
        setJob(got);
        setUiState(statusFromJob(got, "running"));
        setMessage(got.message || "");
        if (got.status === "completed" || got.status === "failed" || got.status === "cancelled") {
          await loadExports();
          if (got.status === "failed" && got.error) {
            const msg =
              typeof got.error.message === "string" ? got.error.message : "Export failed";
            onError(msg);
          }
        }
      } catch {
        /* ignore transient */
      }
    };
    const t = window.setInterval(() => void poll(), 800);
    const onVisible = () => {
      if (document.visibilityState === "visible") void poll();
    };
    document.addEventListener("visibilitychange", onVisible);
    return () => {
      window.clearInterval(t);
      document.removeEventListener("visibilitychange", onVisible);
    };
  }, [job, loadExports, onError]);

  const toggleSection = (id: string) => {
    setSelected((cur) =>
      cur.includes(id) ? cur.filter((s) => s !== id) : [...cur, id],
    );
  };

  const excelWarning = useMemo(() => {
    if (format !== "xlsx" || scope !== "selected") return null;
    const usable = selected.filter((s) => TABULAR_SECTIONS.has(s));
    if (usable.length === 0) {
      return "Excel requires at least one tabular section (processes, network, modules, memory, findings, IOCs, timeline, artifacts).";
    }
    return null;
  }, [format, scope, selected]);

  const analysisReady = coverageCanExport(coverage);
  const generateLocked = analysisBusy || !analysisReady;
  const generateHint = analysisBusy
    ? EXPORT_JOB_BUSY_HINT
    : analysisReady
      ? undefined
      : EXPORT_NEEDS_ANALYSIS_HINT;

  const generate = async () => {
    if (!evidenceId || generateLocked) return;
    setUiState("queued");
    setMessage("Generating…");
    try {
      const submitted = await engineCall<Job>("export.generate", {
        evidence_id: evidenceId,
        format,
        scope,
        sections: scope === "selected" ? selected : undefined,
      });
      setJob(submitted);
      setUiState(statusFromJob(submitted, "queued"));
      setMessage(submitted.message || "Generating…");
      onJobSubmitted(submitted);
    } catch (err) {
      setUiState("failed");
      onError(err instanceof EngineClientError ? err.message : String(err));
    }
  };

  const cancel = async () => {
    if (!job) return;
    try {
      const got = await engineCall<Job>("jobs.cancel", { job_id: job.id });
      setJob(got);
      setUiState(statusFromJob(got, "cancelled"));
      await loadExports();
    } catch (err) {
      onError(err instanceof EngineClientError ? err.message : String(err));
    }
  };

  const busy = uiState === "queued" || uiState === "running";
  const result = job?.result as ExportRecord | null | undefined;
  const exportSortValue = useCallback((row: ExportRecord, key: string) => {
    if (key === "status") return row.status;
    if (key === "format") return row.format;
    if (key === "scope") return row.scope;
    if (key === "path") return row.primary_path ?? "";
    if (key === "created") return row.created_at;
    return "";
  }, []);
  const { sorted: sortedExports, sort, toggle } = useTableSort(exports, exportSortValue);
  const allVisibleIds = sortedExports.map((row) => row.id);
  const allSelected = allVisibleIds.length > 0 && allVisibleIds.every((id) => checkedIds.has(id));
  const someSelected = allVisibleIds.some((id) => checkedIds.has(id));

  const toggleChecked = (id: string) => {
    setCheckedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const toggleSelectAll = () => {
    if (allSelected) {
      setCheckedIds(new Set());
      return;
    }
    setCheckedIds(new Set(allVisibleIds));
  };

  const deleteSelected = async () => {
    if (!evidenceId || checkedIds.size === 0 || deleting) return;
    setDeleting(true);
    try {
      const res = await engineCall<{
        deleted_count: number;
        skipped: Array<{ id: string; reason: string }>;
      }>("export.delete", {
        evidence_id: evidenceId,
        export_ids: [...checkedIds],
      });
      setCheckedIds(new Set());
      await loadExports();
      const skippedInProgress = res.skipped.filter((item) => item.reason === "in_progress").length;
      if (res.deleted_count > 0 && skippedInProgress > 0) {
        showToast(`Deleted ${res.deleted_count}. Skipped ${skippedInProgress} in progress.`);
      } else if (res.deleted_count > 0) {
        showToast(res.deleted_count === 1 ? "Export deleted" : `Deleted ${res.deleted_count} exports`);
      } else if (skippedInProgress > 0) {
        onError("In-progress exports cannot be deleted.");
      }
    } catch (err) {
      onError(err instanceof EngineClientError ? err.message : String(err));
    } finally {
      setDeleting(false);
    }
  };

  if (!evidenceId) {
    return (
      <ImportEvidenceState
        title="Export / Report"
        message="Import evidence before generating a report."
      />
    );
  }

  return (
    <div className="flex h-full flex-col">
      <div className="flex items-center gap-2 border-b border-border px-3 py-2">
        <div className="text-sm font-semibold">Export / Report</div>
        <div className="text-xs text-muted">
          Offline JSON, Excel, and HTML reports are stored under application data. Original evidence is never modified or overwritten.
        </div>
      </div>
      <div className="min-h-0 flex-1 overflow-auto p-3">
          <div className="grid w-full gap-4">
            <section>
              <div className="mb-1 text-[11px] uppercase tracking-wide text-muted">Format</div>
              <SegmentedControl
                ariaLabel="Format"
                value={format}
                onChange={setFormat}
                options={[
                  { id: "html", label: "HTML" },
                  { id: "json", label: "JSON" },
                  { id: "xlsx", label: "Excel" },
                ]}
              />
              <div className="mt-1 text-[11px] text-muted">
                HTML is the human-readable forensic report. JSON preserves structure. Excel is tabular
                only. PDF is not generated.
              </div>
            </section>

            <section>
              <div className="mb-1 text-[11px] uppercase tracking-wide text-muted">Scope</div>
              <SegmentedControl
                ariaLabel="Scope"
                value={scope}
                onChange={setScope}
                options={[
                  { id: "complete", label: "Complete report" },
                  { id: "selected", label: "Selected sections" },
                ]}
              />
            </section>

            {scope === "selected" ? (
              <section>
                <div className="mb-1 text-[11px] uppercase tracking-wide text-muted">Sections</div>
                <div className="grid grid-cols-2 gap-1 sm:grid-cols-3">
                  {sectionList.map((id) => (
                    <label key={id} className="flex items-center gap-2 text-xs">
                      <input
                        type="checkbox"
                        checked={selected.includes(id)}
                        onChange={() => toggleSection(id)}
                      />
                      {id}
                    </label>
                  ))}
                </div>
                {excelWarning ? (
                  <div className="mt-2 text-xs text-danger">{excelWarning}</div>
                ) : null}
              </section>
            ) : null}

            <section className="flex items-center gap-2">
              <span title={generateHint} className="inline-flex">
                <Button
                  type="button"
                  size="sm"
                  disabled={busy || !!excelWarning || generateLocked}
                  onClick={() => void generate()}
                >
                  Generate
                </Button>
              </span>
              <Button
                size="sm"
                variant="outline"
                disabled={!busy}
                onClick={() => void cancel()}
              >
                Cancel
              </Button>
              {generateHint ? (
                <span className="text-xs text-muted">{generateHint}</span>
              ) : null}
              <Badge
                className={
                  uiState === "failed"
                    ? "border-danger text-danger"
                    : uiState === "completed"
                      ? "border-success text-success"
                      : uiState === "running" || uiState === "queued"
                        ? "border-accent text-accent"
                        : ""
                }
              >
                {exportStatusLabel(uiState)}
              </Badge>
              <span className="text-xs text-muted">
                {busy && (!message || message.toLowerCase() === "queued")
                  ? "Generating…"
                  : message}
              </span>
            </section>

            {result && uiState === "completed" ? (
              <section className="rounded border border-border bg-surface-2 p-2 text-xs">
                <div>
                  Output:{" "}
                  <span className="font-mono">{result.primary_path || result.output_dir}</span>
                </div>
                <div className="mt-1 text-muted">
                  Schema v{result.report_schema_version} · {result.files?.length ?? 0} file(s)
                  {result.scope === "selected" && result.sections?.length
                    ? ` · ${result.sections.join(", ")}`
                    : result.scope === "complete"
                      ? " · complete"
                      : ""}
                </div>
                {result.files?.length ? (
                  <div className="mt-1 font-mono text-[11px] text-muted">
                    {result.files
                      .filter((f) => f.kind !== "zip")
                      .map((f) => f.name)
                      .join(", ")}
                  </div>
                ) : null}
              </section>
            ) : null}

            <section>
              <div className="mb-1 flex items-center gap-2">
                <div className="text-[11px] uppercase tracking-wide text-muted">
                  Previous exports
                </div>
                <div className="ml-auto flex items-center gap-2">
                  <Button
                    size="sm"
                    variant="outline"
                    disabled={exports.length === 0}
                    onClick={toggleSelectAll}
                  >
                    {allSelected ? "Clear selection" : "Select all"}
                  </Button>
                  <Button
                    size="sm"
                    variant="outline"
                    className="border-danger/50 bg-danger/10 text-danger hover:border-danger hover:bg-danger/20"
                    disabled={checkedIds.size === 0 || deleting}
                    onClick={() => void deleteSelected()}
                  >
                    {deleting ? "Deleting…" : "Delete"}
                  </Button>
                </div>
              </div>
              <table className="app-result-table w-full text-center text-xs">
                <thead className="bg-surface-2 text-muted">
                  <tr>
                    <th className="w-10 px-2 py-1">
                      <input
                        type="checkbox"
                        checked={allSelected}
                        ref={(el) => {
                          if (el) el.indeterminate = someSelected && !allSelected;
                        }}
                        onChange={toggleSelectAll}
                        disabled={exports.length === 0}
                        aria-label="Select all exports"
                      />
                    </th>
                    <SortableTh label="Status" column="status" sort={sort} onToggle={toggle} className="px-2 py-1" />
                    <SortableTh label="Format" column="format" sort={sort} onToggle={toggle} className="px-2 py-1" />
                    <SortableTh label="Scope" column="scope" sort={sort} onToggle={toggle} className="px-2 py-1" />
                    <SortableTh label="Path" column="path" sort={sort} onToggle={toggle} className="px-2 py-1" />
                    <SortableTh label="Created" column="created" sort={sort} onToggle={toggle} className="px-2 py-1" />
                  </tr>
                </thead>
                <tbody>
                  {sortedExports.map((row) => (
                    <tr key={row.id} className="border-t border-border/40">
                      <td className="px-2 py-1">
                        <input
                          type="checkbox"
                          checked={checkedIds.has(row.id)}
                          onChange={() => toggleChecked(row.id)}
                          aria-label={`Select export ${row.format} ${row.created_at ?? row.id}`}
                        />
                      </td>
                      <td className="px-2 py-1">{row.status}</td>
                      <td className="px-2 py-1">{row.format}</td>
                      <td className="px-2 py-1">{row.scope}</td>
                      <td className="truncate px-2 py-1 font-mono" title={row.primary_path ?? undefined}>
                        {row.primary_path}
                      </td>
                      <td className="px-2 py-1">
                        <TimestampText value={row.created_at} />
                      </td>
                    </tr>
                  ))}
                  {exports.length === 0 ? (
                    <tr className="app-row-empty">
                      <td className="px-2 py-2 text-muted" colSpan={6}>
                        No exports yet.
                      </td>
                    </tr>
                  ) : null}
                </tbody>
              </table>
            </section>
          </div>
      </div>
      <StatusToast message={toast} />
    </div>
  );
}
