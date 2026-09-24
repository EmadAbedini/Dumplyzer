import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import { engineCall, EngineClientError } from "../lib/api";
import { activeJobOfKind, isActiveJobStatus } from "../lib/analysisOptions";
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
import { cn } from "../lib/utils";

export function MemoryExplorerView({
  evidenceId,
  selectedProcessId,
  onSelectProcess,
  onJobSubmitted,
  onError,
  refreshToken,
  coverage,
  activeJobs = [],
  onShownCountChange,
}: {
  evidenceId: string | null;
  processes: ProcessRow[];
  selectedProcessId: string | null;
  onSelectProcess: (id: string) => void;
  onJobSubmitted: (job: Job) => void;
  onError: (m: string) => void;
  refreshToken?: number | string;
  coverage?: CapabilityCoverage;
  activeJobs?: Job[];
  onShownCountChange?: (count: number) => void;
}) {
  const [pidFilter, setPidFilter] = useState(() => {
    const tracked = activeJobOfKind(activeJobs, "vad_scan", "vad_extract");
    return tracked?.pid != null ? String(tracked.pid) : "";
  });
  const [textFilter, setTextFilter] = useState("");
  const [filterField, setFilterField] = useState("all");
  const [suspiciousOnly, setSuspiciousOnly] = useState(false);
  const [items, setItems] = useState<MemoryRegion[]>([]);
  const [loadedKey, setLoadedKey] = useState<string | null>(null);
  const [selected, setSelected] = useState<MemoryRegion | null>(null);
  const [busy, setBusy] = useState(false);
  const [job, setJob] = useState<Job | null>(() =>
    activeJobOfKind(activeJobs, "vad_scan", "vad_extract"),
  );
  const restoredPidRef = useRef(Boolean(activeJobOfKind(activeJobs, "vad_scan", "vad_extract")?.pid != null));
  const prevEvidenceRef = useRef(evidenceId);
  const { toast, showToast } = useStatusToast();

  const activePid = useMemo(() => {
    const raw = pidFilter.trim();
    if (!raw) return null;
    const n = Number(raw);
    return Number.isInteger(n) && n >= 0 ? n : null;
  }, [pidFilter]);

  const listKey = evidenceId
    ? `${evidenceId}:${activePid ?? ""}:${suspiciousOnly ? "1" : "0"}`
    : null;

  const load = useCallback(async () => {
    if (!evidenceId || !listKey) return;
    if (activePid == null) {
      setItems([]);
      setSelected(null);
      setLoadedKey(listKey);
      return;
    }
    try {
      const res = await engineCall<{ items: MemoryRegion[] }>("memory.list", {
        evidence_id: evidenceId,
        pid: activePid,
        suspicious_only: suspiciousOnly,
        limit: 20000,
      });
      setItems(res.items);
      setLoadedKey(listKey);
      setSelected((cur) => {
        if (!cur) return null;
        const still = res.items.find((r) => r.id === cur.id);
        if (still) return still;
        return (
          res.items.find(
            (r) =>
              r.pid === cur.pid &&
              r.start_vpn === cur.start_vpn &&
              r.end_vpn === cur.end_vpn,
          ) ?? null
        );
      });
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
    if (prevEvidenceRef.current === evidenceId) return;
    prevEvidenceRef.current = evidenceId;
    restoredPidRef.current = false;
    setJob(null);
    setPidFilter("");
  }, [evidenceId]);

  useEffect(() => {
    const tracked = activeJobOfKind(activeJobs, "vad_scan", "vad_extract");
    if (!tracked) return;
    setJob(tracked);
    if (tracked.pid != null && !restoredPidRef.current) {
      restoredPidRef.current = true;
      setPidFilter((cur) => (cur.trim() ? cur : String(tracked.pid)));
    }
  }, [activeJobs]);

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

  const scanJob = job?.kind === "vad_scan" ? job : activeJobOfKind(activeJobs, "vad_scan");
  const extractJob =
    job?.kind === "vad_extract" ? job : activeJobOfKind(activeJobs, "vad_extract");
  const memoryJob = scanJob ?? extractJob ?? job;
  const working = busy || (memoryJob != null && isActiveJobStatus(memoryJob.status));
  const scanLabel = memoryActionLabel(scanJob, busy && !extractJob, "Scan VADs");
  const extractLabel = memoryActionLabel(extractJob, busy && !scanJob, "Extract Region");

  const scan = async () => {
    if (!evidenceId || activePid == null) return;
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
        start_vpn: region.start_vpn ?? undefined,
        end_vpn: region.end_vpn ?? undefined,
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
  const shownCount = activePid == null ? 0 : visibleRegions.length;

  useLayoutEffect(() => {
    onShownCountChange?.(shownCount);
  }, [shownCount, onShownCountChange]);

  if (!evidenceId) {
    return <ImportEvidenceState title="Memory / VAD" />;
  }

  return (
    <div className="flex h-full min-h-0 flex-1 flex-col text-xs">
      <div className="flex flex-wrap items-center gap-2 border-b border-border px-3 py-2">
        <div className="text-sm font-semibold">Memory / VAD</div>
        <div className="text-xs text-muted">
          {activePid == null
            ? null
            : coverageResultCaption(coverage, visibleRegions.length)}
        </div>
        <ClearableInput
          wrapperClassName="w-28 flex-none"
          placeholder="PID"
          value={pidFilter}
          onChange={(e) => setPidFilter(e.target.value)}
          onClear={() => {
            setPidFilter("");
            setItems([]);
            setSelected(null);
          }}
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
          {scanLabel}
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
      <div className="flex min-h-0 flex-1 flex-col">
        <div className="min-h-0 min-w-0 flex-1 overflow-auto">
          {loading &&
          items.length === 0 &&
          activePid != null &&
          coverageLiveKind(coverage) !== "in_progress" ? (
            <CenteredLoading />
          ) : activePid == null ? (
            <div className="p-4 text-muted">
              Enter a PID, then click Scan VADs to list memory regions for that process.
            </div>
          ) : items.length === 0 ? (
            <CoverageEmptyState
              item={coverage}
              title="Memory / VAD"
              showTitle={false}
              inProgressDetail="Memory / VAD is still being analyzed."
              analyzedZeroDetail="Memory / VAD analysis completed and found no regions."
              notAnalyzedDetail="Memory / VAD is process-scoped. Enter a PID and click Scan VADs."
              notAnalyzedHint="Enter the PID, then click Scan VADs."
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
                {sorted.map((r) => {
                  const isSelected = selected?.id === r.id;
                  return (
                  <tr
                    key={r.id}
                    aria-selected={isSelected}
                    className={cn(
                      "cursor-pointer border-t border-border/40",
                      isSelected && "app-row-active",
                    )}
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
                  );
                })}
              </tbody>
            </table>
          )}
        </div>
        {visibleRegions.length > 0 ? (
        <aside
          className={cn(
            "max-h-[42%] shrink-0 overflow-auto border-t border-border p-3",
            selected ? "selected-record-detail" : "bg-accent/10",
          )}
        >
          {!selected ? (
            <div className="rounded-md border border-accent/40 bg-accent/15 px-3 py-2.5 text-xs text-foreground">
              Select a region for details and extraction.
            </div>
          ) : (
            <div className="space-y-2">
              <div className="flex items-center gap-2">
                <span className="h-2 w-2 shrink-0 rounded-full bg-accent" aria-hidden />
                <div className="font-semibold">Region detail</div>
                <div className="font-mono text-muted">
                  PID {selected.pid}
                  {selected.start_vpn ? ` · ${selected.start_vpn}` : ""}
                </div>
              </div>
              <div className="grid grid-cols-1 gap-x-8 gap-y-1 sm:grid-cols-2 xl:grid-cols-3">
                <KV k="PID" v={selected.pid} />
                <KV k="Start" v={selected.start_vpn} />
                <KV k="End" v={selected.end_vpn} />
                <KV k="Size" v={selected.size_bytes} />
                <KV k="Protection" v={selected.protection} />
                <KV k="Tag" v={selected.tag} />
                <KV k="Private" v={selected.private_memory} />
                <KV k="File" v={selected.file_path} />
                <KV k="Source" v={selected.source_plugin} />
              </div>
              <div className="text-muted">Indicators</div>
              {(selected.indicators ?? []).length === 0 ? (
                <div className="text-muted">None flagged</div>
              ) : (
                <div className="grid gap-2 sm:grid-cols-2">
                  {(selected.indicators ?? []).map((i) => (
                    <div
                      key={i.code}
                      className="rounded border border-border p-2"
                    >
                      <div className="font-medium">{i.label}</div>
                      <div className="text-muted">{i.detail}</div>
                    </div>
                  ))}
                </div>
              )}
              <div className="flex flex-wrap items-center gap-2">
                {selected.process_id && (
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => onSelectProcess(selected.process_id!)}
                  >
                    Open Process
                  </Button>
                )}
                <Button
                  size="sm"
                  onClick={() => void extract(selected)}
                  disabled={working}
                >
                  {extractLabel}
                </Button>
                <div className="text-[11px] text-muted">
                  Extraction uses Volatility vad_dump into the controlled artifact
                  store. Artifacts are never executed.
                </div>
              </div>
            </div>
          )}
        </aside>
        ) : null}
      </div>
      <StatusToast message={toast} />
    </div>
  );
}

function memoryActionLabel(job: Job | null, submitting: boolean, idle: string): string {
  if (job?.status === "queued") return "Queued";
  if (job != null && isActiveJobStatus(job.status)) return "Working…";
  if (submitting) return "Queued";
  return idle;
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
