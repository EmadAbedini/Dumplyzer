import { memo, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { engineCall, EngineClientError } from "../lib/api";
import { TimestampText } from "../lib/datetime";
import { matchesFieldQuery } from "../lib/resultFilter";
import { useTableSort } from "../lib/tableSort";
import { coverageIsUpdating, coverageLiveKind, coverageResultCaption, coverageWasExecuted } from "../lib/analysisCoverage";
import {
  eventInRange,
  eventTimeMs,
  buildHistogram,
  histogramSpanFits,
  histogramSpanMs,
  resolveHistogramWindow,
} from "../lib/timelineHistogram";
import type { HistogramRange, HistogramSpanId } from "../lib/timelineHistogram";
import { CoverageEmptyState, CenteredLoading, ImportEvidenceState, AnalysisScopeNote } from "./CoverageStatus";
import {
  DERIVED_SOURCE_IDS,
  STORED_ACTION_TITLE,
  limitedResultsNote,
  storedActionNote,
  uncoveredSourceIds,
} from "../lib/analysisScope";
import type { AnalysisCoverage, CapabilityCoverage, TimelineEvent } from "../lib/types";
import { Badge } from "./ui/badge";
import { Button } from "./ui/button";
import { ResultFilterBar } from "./ResultFilterBar";
import { SortableTh } from "./SortableTh";
import { RefreshButton, StatusToast, useStatusToast } from "./StatusToast";
import { TimelineHistogram } from "./TimelineHistogram";

const ANALYSIS_EVENT_KINDS = new Set([
  "network_artifacts",
  "bulk_extractor",
  "yara_scan",
  "capa_scan",
  "floss_scan",
  "pcap_reconstruction",
  "pe_extraction",
  "finding",
  "artifact_extraction",
]);

function isAnalysisClock(e: TimelineEvent): boolean {
  if (e.clock === "analysis" || e.time_precision === "analysis_time") return true;
  if (e.clock === "dump") return false;
  return ANALYSIS_EVENT_KINDS.has(e.event_kind);
}

const ROW_ESTIMATE = 52;

function useVirtualWindow(count: number, rowHeight = ROW_ESTIMATE, overscan = 16) {
  const scrollerRef = useRef<HTMLDivElement>(null);
  const [win, setWin] = useState({ start: 0, end: Math.min(count, 80) });

  useEffect(() => {
    const el = scrollerRef.current;
    if (!el) return;
    let frame = 0;
    const update = () => {
      cancelAnimationFrame(frame);
      frame = requestAnimationFrame(() => {
        const h = el.clientHeight;
        if (h <= 0) return;
        const start = Math.max(0, Math.floor(el.scrollTop / rowHeight) - overscan);
        const end = Math.min(count, start + Math.ceil(h / rowHeight) + overscan * 2);
        setWin((prev) => (prev.start === start && prev.end === end ? prev : { start, end }));
      });
    };
    update();
    el.addEventListener("scroll", update, { passive: true });
    const obs = new ResizeObserver(update);
    obs.observe(el);
    return () => {
      cancelAnimationFrame(frame);
      el.removeEventListener("scroll", update);
      obs.disconnect();
    };
  }, [count, overscan, rowHeight]);

  return {
    scrollerRef,
    start: win.start,
    end: win.end,
    padTop: win.start * rowHeight,
    padBottom: Math.max(0, count - win.end) * rowHeight,
  };
}

const TimelineEventRow = memo(function TimelineEventRow({
  event: e,
  alt,
  onOpenProcess,
}: {
  event: TimelineEvent;
  alt: boolean;
  onOpenProcess: (processId: string) => void;
}) {
  return (
    <tr className={alt ? "app-row-alt border-t border-border/40" : "border-t border-border/40"}>
      <td className="px-2 py-1 font-mono">
        <TimestampText value={e.event_time} />
        <div className="text-[10px] text-muted">{e.time_precision}</div>
      </td>
      <td className="timeline-class-cell px-2 py-1">
        <Badge
          className={
            e.classification === "inferred"
              ? "border-warning text-warning"
              : "border-success text-success"
          }
        >
          {e.classification}
        </Badge>
      </td>
      <td className="px-2 py-1 font-mono" title={e.event_kind}>
        {e.event_kind}
      </td>
      <td className="px-2 py-1" title={e.summary}>
        {e.summary}
      </td>
      <td className="px-2 py-1 font-mono">
        {e.process_id ? (
          <button
            type="button"
            className="text-accent hover:underline"
            onClick={() => onOpenProcess(e.process_id!)}
          >
            {e.pid ?? "open"}
          </button>
        ) : (
          (e.pid ?? "—")
        )}
      </td>
      <td className="px-2 py-1 text-muted" title={e.source_plugin ?? e.source_table ?? undefined}>
        {e.source_plugin ?? e.source_table ?? "—"}
      </td>
    </tr>
  );
});

export function TimelineView({
  evidenceId,
  onOpenProcess,
  onError,
  refreshToken,
  coverage,
  analysisCoverage,
}: {
  evidenceId: string | null;
  onOpenProcess: (processId: string) => void;
  onError: (m: string) => void;
  refreshToken?: number | string;
  coverage?: CapabilityCoverage;
  analysisCoverage?: AnalysisCoverage;
}) {
  const [items, setItems] = useState<TimelineEvent[]>([]);
  const [loadedEvidenceId, setLoadedEvidenceId] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [filter, setFilter] = useState("");
  const [filterField, setFilterField] = useState("all");
  const [timeRange, setTimeRange] = useState<HistogramRange | null>(null);
  const [spanId, setSpanId] = useState<HistogramSpanId>("auto");
  const [builtHere, setBuiltHere] = useState(false);
  const { toast, showToast } = useStatusToast();

  const load = useCallback(async () => {
    if (!evidenceId) return;
    try {
      const res = await engineCall<{ items: TimelineEvent[]; total?: number }>("timeline.list", {
        evidence_id: evidenceId,
      });
      setItems(res.items);
      setLoadedEvidenceId(evidenceId);
    } catch (e) {
      setItems([]);
      setLoadedEvidenceId(evidenceId);
      onError(e instanceof EngineClientError ? e.message : String(e));
    }
  }, [evidenceId, onError]);

  useEffect(() => {
    void load();
  }, [load, refreshToken]);

  useEffect(() => {
    setTimeRange(null);
    setSpanId("auto");
    setBuiltHere(false);
  }, [evidenceId]);

  const rebuild = async () => {
    if (!evidenceId) return;
    setBusy(true);
    try {
      const res = await engineCall<{ items: TimelineEvent[]; total?: number }>("timeline.build", {
        evidence_id: evidenceId,
      });
      setItems(res.items);
      setLoadedEvidenceId(evidenceId);
      setBuiltHere(true);
      showToast("Timeline rebuilt from stored analysis results.");
    } catch (e) {
      onError(e instanceof EngineClientError ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  const dumpItems = useMemo(() => items.filter((e) => !isAnalysisClock(e)), [items]);

  const eventTimes = useMemo(() => {
    const times: number[] = [];
    for (const e of dumpItems) {
      const ms = eventTimeMs(e.event_time);
      if (ms != null) times.push(ms);
    }
    return times;
  }, [dumpItems]);

  const histogramWindow = useMemo(() => resolveHistogramWindow(eventTimes), [eventTimes]);

  useEffect(() => {
    if (spanId === "auto" || !histogramWindow) return;
    const requested = histogramSpanMs(spanId);
    if (requested && !histogramSpanFits(histogramWindow.min, histogramWindow.max, requested)) {
      setSpanId("auto");
    }
  }, [histogramWindow, spanId]);

  const spanStepMs = useMemo(() => {
    const requested = histogramSpanMs(spanId);
    if (!histogramWindow || !requested) return null;
    return histogramSpanFits(histogramWindow.min, histogramWindow.max, requested) ? requested : null;
  }, [histogramWindow, spanId]);

  const buckets = useMemo(
    () => buildHistogram(eventTimes, spanStepMs),
    [eventTimes, spanStepMs],
  );

  const onSpanChange = useCallback((id: HistogramSpanId) => {
    setSpanId(id);
    setTimeRange(null);
  }, []);

  const filtered = useMemo(
    () =>
      dumpItems.filter((e) => {
        if (!eventInRange(eventTimeMs(e.event_time), timeRange)) return false;
        return matchesFieldQuery(
          filter,
          filterField,
          {
            time: e.event_time,
            class: e.classification,
            kind: e.event_kind,
            summary: e.summary,
            pid: e.pid,
            source: e.source_plugin ?? e.source_table,
          },
          [e.time_precision, e.clock],
        );
      }),
    [dumpItems, filter, filterField, timeRange],
  );
  const timelineSortValue = useCallback((e: TimelineEvent, key: string) => {
    if (key === "time") return e.event_time ?? "";
    if (key === "class") return e.classification ?? "";
    if (key === "kind") return e.event_kind ?? "";
    if (key === "summary") return e.summary ?? "";
    if (key === "pid") return e.pid;
    if (key === "source") return e.source_plugin ?? e.source_table ?? "";
    return "";
  }, []);
  const { sorted, sort, toggle } = useTableSort(filtered, timelineSortValue);
  const virtual = useVirtualWindow(sorted.length);
  const { scrollerRef, padTop, padBottom } = virtual;

  const loading = loadedEvidenceId !== evidenceId;
  const updating = coverageIsUpdating(coverage);
  const showRebuild = !coverageWasExecuted(coverage) && coverageLiveKind(coverage) !== "in_progress";
  const missingSources = uncoveredSourceIds(analysisCoverage, DERIVED_SOURCE_IDS.timeline);
  const showLimitedNote = dumpItems.length > 0 && missingSources.length > 0;
  const timelineEmptyItem =
    builtHere && dumpItems.length === 0 && coverageLiveKind(coverage) === "not_analyzed"
      ? { id: "timeline", state: "analyzed_zero" as const, count: 0 }
      : coverage;
  const timelineNotAnalyzedDetail =
    "The timeline is built from process, network, module, and other records already stored — not by rescanning the dump.";
  const timelineNotAnalyzedHint =
    missingSources.length > 0
      ? `${storedActionNote(missingSources)} You can still rebuild from whatever is stored.`
      : "Use Rebuild from stored results to build a timeline from stored records, or include Timeline in Complete or Custom Analysis.";
  const timelineAnalyzedZeroDetail =
    missingSources.length > 0
      ? "The timeline was built from stored records and found no dump-time events."
      : "No dump-time events were recovered from this image.";
  const timelineAnalyzedZeroHint =
    missingSources.length > 0 ? storedActionNote(missingSources) : undefined;

  if (!evidenceId) {
    return <ImportEvidenceState title="Timeline" />;
  }

  return (
    <div className="flex h-full min-h-0 flex-1 flex-col text-xs">
      <div className="flex flex-wrap items-center gap-x-2 gap-y-1.5 border-b border-border px-3 py-2">
        <div className="flex min-w-0 flex-wrap items-center gap-x-2 gap-y-1">
          <div className="shrink-0 text-sm font-semibold">Timeline</div>
          <div className="shrink-0 whitespace-nowrap text-xs text-muted">
            {coverageResultCaption(coverage, dumpItems.length, filtered.length)}
          </div>
          {showRebuild ? (
            <span className="inline-flex" title={STORED_ACTION_TITLE}>
              <Button size="sm" onClick={() => void rebuild()} disabled={busy || updating}>
                {busy ? "Building…" : "Rebuild from stored results"}
              </Button>
            </span>
          ) : null}
          <RefreshButton
            onRefresh={load}
            doneMessage="Timeline updated"
            showToast={showToast}
            disabled={updating || busy}
          />
          <span
            className="hidden text-muted 2xl:inline"
            title="Timestamps recovered from the memory image, not when Dumplyzer ran."
          >
            Times are OS timestamps from the image
          </span>
        </div>
        <ResultFilterBar
          query={filter}
          onQueryChange={setFilter}
          field={filterField}
          onFieldChange={setFilterField}
          placeholder="Filter time / type / process…"
          fields={[
            { id: "time", label: "Time" },
            { id: "class", label: "Class" },
            { id: "kind", label: "Kind" },
            { id: "summary", label: "Summary" },
            { id: "pid", label: "PID" },
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
      ) : dumpItems.length === 0 ? (
        <CoverageEmptyState
          item={timelineEmptyItem}
          title="Timeline"
          showTitle={false}
          inProgressDetail="The timeline is still being built."
          analyzedZeroDetail={timelineAnalyzedZeroDetail}
          analyzedZeroHint={timelineAnalyzedZeroHint}
          notAnalyzedDetail={timelineNotAnalyzedDetail}
          notAnalyzedHint={timelineNotAnalyzedHint}
          failedDetail="Timeline analysis failed."
        />
      ) : (
      <>
      {buckets.length > 0 ? (
        <TimelineHistogram
          buckets={buckets}
          range={timeRange}
          onRangeChange={setTimeRange}
          spanId={spanId}
          onSpanChange={onSpanChange}
          windowStartMs={histogramWindow?.min ?? 0}
          windowEndMs={histogramWindow?.max ?? 0}
        />
      ) : null}
      <div ref={scrollerRef} className="min-h-0 flex-1 overflow-auto [scrollbar-gutter:stable]">
        <table className="app-result-table app-timeline-table w-full text-center">
          <colgroup>
            <col className="timeline-time" />
            <col className="timeline-class" />
            <col className="timeline-kind" />
            <col className="timeline-summary" />
            <col className="timeline-pid" />
            <col className="timeline-source" />
          </colgroup>
          <thead className="sticky top-0 bg-surface-2 text-muted">
            <tr>
              <SortableTh label="Time" column="time" sort={sort} onToggle={toggle} />
              <SortableTh label="Class" column="class" sort={sort} onToggle={toggle} />
              <SortableTh label="Kind" column="kind" sort={sort} onToggle={toggle} />
              <SortableTh label="Summary" column="summary" sort={sort} onToggle={toggle} />
              <SortableTh label="PID" column="pid" sort={sort} onToggle={toggle} />
              <SortableTh label="Source" column="source" sort={sort} onToggle={toggle} />
            </tr>
          </thead>
          <tbody>
            {padTop > 0 ? (
              <tr className="app-row-empty app-virtual-pad" aria-hidden style={{ height: padTop }}>
                <td /><td /><td /><td /><td /><td />
              </tr>
            ) : null}
            {sorted.slice(virtual.start, virtual.end).map((e, i) => (
              <TimelineEventRow
                key={e.id}
                event={e}
                alt={(virtual.start + i) % 2 === 1}
                onOpenProcess={onOpenProcess}
              />
            ))}
            {padBottom > 0 ? (
              <tr className="app-row-empty app-virtual-pad" aria-hidden style={{ height: padBottom }}>
                <td /><td /><td /><td /><td /><td />
              </tr>
            ) : null}
            {filtered.length === 0 && (
              <tr className="app-row-empty">
                <td colSpan={6} className="px-3 py-6 text-muted">
                  No timeline events match the current filter or time range.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
      </>
      )}
      <StatusToast message={toast} />
    </div>
  );
}
