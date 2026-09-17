import { useCallback, useEffect, useMemo, useState } from "react";
import { engineCall, EngineClientError } from "../lib/api";
import { isActiveJobStatus } from "../lib/analysisOptions";
import {
  coverageLiveKind,
  coverageResultCaption,
} from "../lib/analysisCoverage";
import {
  CoverageEmptyState,
  CenteredLoading,
  ImportEvidenceState,
} from "./CoverageStatus";
import { matchesFieldQuery } from "../lib/resultFilter";
import { useTableSort } from "../lib/tableSort";
import type {
  CapabilityCoverage,
  Job,
  MemoryRegion,
  ProcessRow,
} from "../lib/types";
import { Badge } from "./ui/badge";
import { Button } from "./ui/button";
import { ClearableInput } from "./ui/input";
import { SortableTh } from "./SortableTh";
import { RefreshButton, StatusToast, useStatusToast } from "./StatusToast";
import { ResultFilterBar } from "./ResultFilterBar";

export function MemoryExplorerView({
  evidenceId,
  processes,
  selectedProcessId,
  onSelectProcess,
  onJobSubmitted,
  onError,
  refreshToken,
  coverage,
}: {
  evidenceId: string | null;
  processes: ProcessRow[];
  selectedProcessId: string | null;
  onSelectProcess: (id: string) => void;
  onJobSubmitted: (job: Job) => void;
  onError: (m: string) => void;
  refreshToken?: number | string;
  coverage?: CapabilityCoverage;
}) {
  const [pidFilter, setPidFilter] = useState<string>("");
  const [textFilter, setTextFilter] = useState("");
  const [filterField, setFilterField] = useState("all");
  const [suspiciousOnly, setSuspiciousOnly] = useState(false);
  const [items, setItems] = useState<MemoryRegion[]>([]);
  const [loadedKey, setLoadedKey] = useState<string | null>(null);
  const [selected, setSelected] = useState<MemoryRegion | null>(null);
  const [busy, setBusy] = useState(false);
  const [job, setJob] = useState<Job | null>(null);
  const { toast, showToast } = useStatusToast();

  const activePid = useMemo(() => {
    if (pidFilter.trim()) {
      const n = Number(pidFilter);
      return Number.isFinite(n) ? n : null;
    }
    if (selectedProcessId) {
      const p = processes.find((x) => x.id === selectedProcessId);
      return p?.pid ?? null;
    }
    return null;
  }, [pidFilter, selectedProcessId, processes]);

  const listKey = evidenceId
    ? `${evidenceId}:${activePid ?? ""}:${suspiciousOnly ? "1" : "0"}`
    : null;

  const load = useCallback(async () => {
    if (!evidenceId || !listKey) return;
    try {
      const res = await engineCall<{ items: MemoryRegion[] }>("memory.list", {
        evidence_id: evidenceId,
        pid: activePid ?? undefined,
        suspicious_only: suspiciousOnly,
        limit: 20000,
      });
      setItems(res.items);
      setLoadedKey(listKey);
    } catch (e) {
      setItems([]);
      setLoadedKey(listKey);
      onError(e instanceof EngineClientError ? e.message : String(e));
    }
  }, [evidenceId, listKey, activePid, suspiciousOnly, onError]);

  useEffect(() => {
    void load();
  }, [load, refreshToken]);

  useEffect(() => {
    setJob(null);
  }, [evidenceId]);

  useEffect(() => {
    if (!job || !isActiveJobStatus(job.status)) return;
    const poll = async () => {
      try {
        const got = await engineCall<Job>("jobs.get", { job_id: job.id });
        setJob(got);
        if (got.status === "completed") {
          await load();
          showToast("Memory job completed");
        } else if (got.status === "failed") {
          const msg =
            typeof got.error?.message === "string"
              ? got.error.message
              : "Memory job failed";
          onError(msg);
        }
      } catch {
        /* ignore transient */
      }
    };
    const timer = window.setInterval(() => void poll(), 1000);
    const onVisible = () => {
      if (document.visibilityState === "visible") void poll();
    };
    document.addEventListener("visibilitychange", onVisible);
    return () => {
      window.clearInterval(timer);
      document.removeEventListener("visibilitychange", onVisible);
    };
  }, [job, load, onError, showToast]);

  const working = busy || (job != null && isActiveJobStatus(job.status));

  const scan = async () => {
    if (!evidenceId || activePid == null) {
      onError("Select or enter a PID before scanning VADs.");
      return;
    }
    setBusy(true);
    try {
      const submitted = await engineCall<Job>("memory.scan", {
        evidence_id: evidenceId,
        pid: activePid,
        process_id: selectedProcessId ?? undefined,
      });
      setJob(submitted);
      onJobSubmitted(submitted);
    } catch (e) {
      onError(e instanceof EngineClientError ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  const extract = async (region: MemoryRegion) => {
    if (!evidenceId) return;
    setBusy(true);
    try {
      const submitted = await engineCall<Job>("memory.extract", {
        evidence_id: evidenceId,
        memory_region_id: region.id,
        pid: region.pid,
        process_id: region.process_id ?? undefined,
      });
      setJob(submitted);
      onJobSubmitted(submitted);
    } catch (e) {
      onError(e instanceof EngineClientError ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  const visibleRegions = useMemo(
    () =>
      items.filter((r) =>
        matchesFieldQuery(
          textFilter,
          filterField,
          {
            pid: r.pid,
            start: r.start_vpn,
            end: r.end_vpn,
            size: r.size_bytes,
            protection: r.protection,
            tag: r.tag,
            private: r.private_memory,
            file: r.file_path,
            indicators: (r.indicators ?? []).map((i) => i.code),
          },
          [r.process_name],
        ),
      ),
    [items, textFilter, filterField],
  );
  const memorySortValue = useCallback((r: MemoryRegion, key: string) => {
    if (key === "pid") return r.pid;
    if (key === "start") return r.start_vpn ?? "";
    if (key === "end") return r.end_vpn ?? "";
    if (key === "size") return r.size_bytes;
    if (key === "protection") return r.protection ?? "";
    if (key === "tag") return r.tag ?? "";
    if (key === "private") return r.private_memory ?? "";
    if (key === "file") return r.file_path ?? "";
    if (key === "indicators")
      return (r.indicators ?? []).map((i) => i.code).join(" ");
    return "";
  }, []);
  const { sorted, sort, toggle } = useTableSort(
    visibleRegions,
    memorySortValue,
  );
  const loading = Boolean(listKey) && loadedKey !== listKey;

  if (!evidenceId) {
    return <ImportEvidenceState title="Memory / VAD" />;
  }

  return (
    <div className="flex h-full min-h-0 flex-1 flex-col text-xs">
      <div className="flex flex-wrap items-center gap-2 border-b border-border px-3 py-2">
        <div className="text-sm font-semibold">Memory / VAD</div>
        <div className="text-xs text-muted">
          {coverageResultCaption(coverage, items.length)}
        </div>
        <ClearableInput
          wrapperClassName="w-28 flex-none"
          placeholder="PID"
          value={pidFilter}
          onChange={(e) => setPidFilter(e.target.value)}
          onClear={() => setPidFilter("")}
        />
        <label className="flex items-center gap-1 text-muted">
          <input
            type="checkbox"
            checked={suspiciousOnly}
            onChange={(e) => setSuspiciousOnly(e.target.checked)}
          />
          Indicators only
        </label>
        <RefreshButton
          onRefresh={load}
          doneMessage="Memory regions updated"
          showToast={showToast}
        />
        <Button
          size="sm"
          onClick={() => void scan()}
          disabled={working || activePid == null}
        >
          {working ? "Working…" : "Scan VADs (job)"}
        </Button>
        <ResultFilterBar
          query={textFilter}
          onQueryChange={setTextFilter}
          field={filterField}
          onFieldChange={setFilterField}
          placeholder="Filter protection / path / tag…"
          fields={[
            { id: "pid", label: "PID" },
            { id: "start", label: "Start" },
            { id: "end", label: "End" },
            { id: "size", label: "Size" },
            { id: "protection", label: "Protection" },
            { id: "tag", label: "Tag" },
            { id: "private", label: "Private" },
            { id: "file", label: "File" },
            { id: "indicators", label: "Indicators" },
          ]}
        />
        <span className="text-muted">
          Indicators are evidence-based (e.g. W+X), not a malice verdict.
        </span>
      </div>
      <div className="flex min-h-0 flex-1">
        <div className="min-w-0 flex-1 overflow-auto">
          {loading &&
          items.length === 0 &&
          coverageLiveKind(coverage) !== "in_progress" ? (
            <CenteredLoading />
          ) : items.length === 0 ? (
            <CoverageEmptyState
              item={coverage}
              title="Memory / VAD"
              showTitle={false}
              inProgressDetail="Memory / VAD is still being analyzed."
              analyzedZeroDetail="Memory / VAD analysis completed and found no regions."
              notAnalyzedDetail="Memory / VAD is process-scoped and is not part of Quick Triage or Complete Analysis."
              notAnalyzedHint="Select a process and run Analyze process or Scan VADs."
              failedDetail="Memory / VAD analysis failed."
            />
          ) : visibleRegions.length === 0 ? (
            <div className="p-4 text-muted">
              No memory regions match the current filter.
            </div>
          ) : (
            <table className="app-result-table w-full text-center">
              <thead className="sticky top-0 bg-surface-2 text-muted">
                <tr>
                  <SortableTh
                    label="PID"
                    column="pid"
                    sort={sort}
                    onToggle={toggle}
                  />
                  <SortableTh
                    label="Start"
                    column="start"
                    sort={sort}
                    onToggle={toggle}
                  />
                  <SortableTh
                    label="End"
                    column="end"
                    sort={sort}
                    onToggle={toggle}
                  />
                  <SortableTh
                    label="Size"
                    column="size"
                    sort={sort}
                    onToggle={toggle}
                  />
                  <SortableTh
                    label="Protection"
                    column="protection"
                    sort={sort}
                    onToggle={toggle}
                  />
                  <SortableTh
                    label="Tag"
                    column="tag"
                    sort={sort}
                    onToggle={toggle}
                  />
                  <SortableTh
                    label="Private"
                    column="private"
                    sort={sort}
                    onToggle={toggle}
                  />
                  <SortableTh
                    label="File"
                    column="file"
                    sort={sort}
                    onToggle={toggle}
                  />
                  <SortableTh
                    label="Indicators"
                    column="indicators"
                    sort={sort}
                    onToggle={toggle}
                  />
                </tr>
              </thead>
              <tbody>
                {sorted.map((r) => (
                  <tr
                    key={r.id}
                    className={
                      "cursor-pointer border-t border-border/40 " +
                      (selected?.id === r.id ? "app-row-active" : "")
                    }
                    onClick={() => setSelected(r)}
                  >
                    <td className="px-2 py-1 font-mono">{r.pid}</td>
                    <td className="px-2 py-1 font-mono">
                      {r.start_vpn ?? "—"}
                    </td>
                    <td className="px-2 py-1 font-mono">{r.end_vpn ?? "—"}</td>
                    <td className="px-2 py-1 font-mono">
                      {r.size_bytes != null
                        ? r.size_bytes.toLocaleString()
                        : "—"}
                    </td>
                    <td className="px-2 py-1 font-mono">
                      {r.protection ?? "—"}
                    </td>
                    <td className="px-2 py-1">{r.tag ?? "—"}</td>
                    <td className="px-2 py-1 font-mono">
                      {r.private_memory ?? "—"}
                    </td>
                    <td className="max-w-[12rem] truncate px-2 py-1">
                      {r.file_path ?? "—"}
                    </td>
                    <td className="px-2 py-1">
                      {(r.indicators ?? []).map((i) => (
                        <Badge
                          key={i.code}
                          className="mr-1 border-warning text-warning"
                        >
                          {i.code}
                        </Badge>
                      ))}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
        <aside className="w-80 shrink-0 overflow-auto border-l border-border p-3">
          {!selected ? (
            <div className="text-muted">
              Select a region for details and extraction.
            </div>
          ) : (
            <div className="space-y-2">
              <div className="font-semibold">Region detail</div>
              <KV k="PID" v={selected.pid} />
              <KV k="Start" v={selected.start_vpn} />
              <KV k="End" v={selected.end_vpn} />
              <KV k="Size" v={selected.size_bytes} />
              <KV k="Protection" v={selected.protection} />
              <KV k="Tag" v={selected.tag} />
              <KV k="Private" v={selected.private_memory} />
              <KV k="File" v={selected.file_path} />
              <KV k="Source" v={selected.source_plugin} />
              <div className="text-muted">Indicators</div>
              {(selected.indicators ?? []).length === 0 ? (
                <div className="text-muted">None flagged</div>
              ) : (
                (selected.indicators ?? []).map((i) => (
                  <div
                    key={i.code}
                    className="rounded border border-border p-2"
                  >
                    <div className="font-medium">{i.label}</div>
                    <div className="text-muted">{i.detail}</div>
                  </div>
                ))
              )}
              {selected.process_id && (
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => onSelectProcess(selected.process_id!)}
                >
                  Open process
                </Button>
              )}
              <Button
                size="sm"
                onClick={() => void extract(selected)}
                disabled={working}
              >
                {working ? "Working…" : "Extract region (job)"}
              </Button>
              <div className="text-[11px] text-muted">
                Extraction uses Volatility vad_dump into the controlled artifact
                store. Artifacts are never executed.
              </div>
            </div>
          )}
        </aside>
      </div>
      <StatusToast message={toast} />
    </div>
  );
}

function KV({ k, v }: { k: string; v: unknown }) {
  return (
    <div className="grid grid-cols-[72px_1fr] gap-1">
      <div className="text-muted">{k}</div>
      <div className="break-all font-mono">
        {v == null || v === "" ? "—" : String(v)}
      </div>
    </div>
  );
}
