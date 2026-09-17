import { memo, useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import { useDisplayTimeZone } from "../lib/datetime";
import {
  formatBucketHover,
  formatHistogramAxisDate,
  formatHistogramBound,
  formatHistogramInterval,
  histogramSpanFits,
  HISTOGRAM_SPAN_OPTIONS,
  rangeFromBuckets,
  timeBucketsOf,
  type HistogramBucket,
  type HistogramRange,
  type HistogramSpanId,
} from "../lib/timelineHistogram";
import { Button } from "./ui/button";

type Props = {
  buckets: HistogramBucket[];
  range: HistogramRange | null;
  onRangeChange: (range: HistogramRange | null) => void;
  spanId: HistogramSpanId;
  onSpanChange: (id: HistogramSpanId) => void;
  windowStartMs: number;
  windowEndMs: number;
};

const HEIGHT = 112;
const PAD = { top: 8, right: 8, bottom: 20, left: 8 };
const OVERFLOW_W = 48;
const MIN_BAR_H = 10;

type LayoutItem = { bucket: HistogramBucket; x: number; w: number };

function layoutBuckets(buckets: HistogramBucket[], innerW: number): LayoutItem[] {
  const overflowN = buckets.filter((b) => b.kind !== "time").length;
  const timeN = buckets.length - overflowN;
  const timeInner = Math.max(1, innerW - overflowN * OVERFLOW_W);
  const timeBarW = timeN > 0 ? timeInner / timeN : timeInner;
  let x = PAD.left;
  return buckets.map((bucket) => {
    const w = bucket.kind === "time" ? timeBarW : OVERFLOW_W;
    const item = { bucket, x, w };
    x += w;
    return item;
  });
}

function pct(n: number, plotW: number): string {
  return `${(n / Math.max(plotW, 1)) * 100}%`;
}

function barHeight(count: number, maxCount: number, innerH: number): number {
  if (count <= 0 || maxCount <= 0) return 0;
  const scaled = Math.sqrt(count / maxCount) * innerH;
  return Math.min(innerH, Math.max(MIN_BAR_H, scaled));
}

export const TimelineHistogram = memo(function TimelineHistogram({
  buckets,
  range,
  onRangeChange,
  spanId,
  onSpanChange,
  windowStartMs,
  windowEndMs,
}: Props) {
  const timeZone = useDisplayTimeZone();
  const wrapRef = useRef<HTMLDivElement>(null);
  const tooltipRef = useRef<HTMLDivElement>(null);
  const [hover, setHover] = useState<number | null>(null);
  const dragRef = useRef<{ origin: number; current: number } | null>(null);
  const [drag, setDrag] = useState<{ origin: number; current: number } | null>(null);
  const [tooltipLeft, setTooltipLeft] = useState(8);
  const [plotW, setPlotW] = useState(0);

  useLayoutEffect(() => {
    const el = wrapRef.current;
    if (!el) return;
    const apply = () => setPlotW(el.clientWidth);
    apply();
    const ro = new ResizeObserver(apply);
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  const timed = useMemo(() => timeBucketsOf(buckets), [buckets]);
  const spanMs = timed.length > 0 ? timed[timed.length - 1].endMs - timed[0].startMs : 0;
  const stepMs = timed.length > 0 ? timed[0].endMs - timed[0].startMs : 0;
  const outlierCount = buckets
    .filter((b) => b.kind !== "time")
    .reduce((n, b) => n + b.count, 0);
  const maxCount = useMemo(() => Math.max(1, ...timed.map((b) => b.count), 1), [timed]);
  const innerW = Math.max(1, plotW - PAD.left - PAD.right);
  const innerH = HEIGHT - PAD.top - PAD.bottom;
  const layout = useMemo(() => layoutBuckets(buckets, innerW), [buckets, innerW]);
  const firstTimeLayout = layout.find((l) => l.bucket.kind === "time");
  const lastTimeLayout = layout.filter((l) => l.bucket.kind === "time").at(-1);

  const preview = drag ? rangeFromBuckets(buckets, drag.origin, drag.current) : range;

  const selectedSet = useMemo(() => {
    if (!preview || buckets.length === 0) return null;
    const set = new Set<number>();
    buckets.forEach((b, i) => {
      if (b.endMs > preview.startMs && b.startMs < preview.endMs) set.add(i);
    });
    return set.size > 0 ? set : null;
  }, [buckets, preview]);

  const selectedSpan = useMemo(() => {
    if (!selectedSet || layout.length === 0) return null;
    let min = Infinity;
    let max = -Infinity;
    selectedSet.forEach((i) => {
      const item = layout[i];
      if (!item) return;
      if (item.x < min) min = item.x;
      const right = item.x + item.w;
      if (right > max) max = right;
    });
    return Number.isFinite(min) ? { x: min, w: max - min } : null;
  }, [layout, selectedSet]);

  const indexFromClientX = useCallback(
    (clientX: number) => {
      const el = wrapRef.current;
      if (!el || layout.length === 0) return 0;
      const rect = el.getBoundingClientRect();
      if (rect.width <= 0) return 0;
      const x = ((clientX - rect.left) / rect.width) * Math.max(plotW, 1);
      for (let i = 0; i < layout.length; i++) {
        if (x < layout[i].x + layout[i].w) return i;
      }
      return layout.length - 1;
    },
    [layout, plotW],
  );

  const commitDrag = useCallback(
    (origin: number, current: number) => {
      const next = rangeFromBuckets(buckets, origin, current);
      if (!next) return;
      const same =
        range &&
        origin === current &&
        range.startMs === next.startMs &&
        range.endMs === next.endMs;
      onRangeChange(same ? null : next);
    },
    [buckets, onRangeChange, range],
  );

  useEffect(() => {
    const onMove = (event: PointerEvent) => {
      const d = dragRef.current;
      if (!d) return;
      d.current = indexFromClientX(event.clientX);
      setDrag({ ...d });
      setHover(d.current);
    };
    const onUp = () => {
      const d = dragRef.current;
      if (!d) return;
      dragRef.current = null;
      setDrag(null);
      commitDrag(d.origin, d.current);
    };
    window.addEventListener("pointermove", onMove);
    window.addEventListener("pointerup", onUp);
    return () => {
      window.removeEventListener("pointermove", onMove);
      window.removeEventListener("pointerup", onUp);
    };
  }, [commitDrag, indexFromClientX]);

  const hoverLayout = hover != null ? layout[hover] : null;
  const hoverBucket = hover != null ? buckets[hover] : null;
  const hoverText = hoverBucket ? formatBucketHover(hoverBucket, spanMs, timeZone) : null;

  useLayoutEffect(() => {
    const el = tooltipRef.current;
    const wrap = wrapRef.current;
    if (!el || !hoverLayout || !wrap) return;
    const cssW = wrap.clientWidth;
    if (cssW <= 0) return;
    const pad = 6;
    const tw = el.offsetWidth;
    const preferred = ((hoverLayout.x + hoverLayout.w / 2) / Math.max(plotW, 1)) * cssW - tw / 2;
    setTooltipLeft(Math.min(Math.max(pad, preferred), Math.max(pad, cssW - pad - tw)));
  }, [hoverLayout, hoverText, plotW]);

  if (buckets.length === 0) return null;

  const timeCount = selectedSet
    ? [...selectedSet].reduce((n, i) => n + buckets[i].count, 0)
    : buckets.reduce((n, b) => n + b.count, 0);
  const startLabel = timed.length
    ? formatHistogramBound(timed[0].startMs, "start", timed, spanMs, timeZone)
    : "";
  const endLabel = timed.length
    ? formatHistogramBound(timed[timed.length - 1].endMs, "end", timed, spanMs, timeZone)
    : "";
  const axisDate =
    timed.length > 0 ? formatHistogramAxisDate(timed[0].startMs, timeZone) : "";
  const endDate =
    timed.length > 0 ? formatHistogramAxisDate(timed[timed.length - 1].endMs, timeZone) : "";
  const sameDay = axisDate === endDate;
  const rangeLabel = preview
    ? `${formatHistogramBound(preview.startMs, "start", buckets, spanMs, timeZone)} → ${formatHistogramBound(preview.endMs, "end", buckets, spanMs, timeZone)}`
    : null;

  return (
    <div className="border-b border-border bg-surface-2/60 px-3 py-2">
      <div className="mb-1 flex min-h-6 flex-wrap items-center gap-x-2 gap-y-1 text-xs">
        <span className="shrink-0 font-medium text-foreground">Time</span>
        <span className="min-w-0 text-muted">
          {preview
            ? `${timeCount.toLocaleString()} events · ${rangeLabel}`
            : `${timeCount.toLocaleString()} events · ${formatHistogramInterval(stepMs)} buckets${sameDay && axisDate ? ` · ${axisDate}` : ""}`}
        </span>
        {!preview && outlierCount > 0 ? (
          <span className="shrink-0 text-warning">
            {outlierCount.toLocaleString()} outside this window
          </span>
        ) : null}
        {range ? (
          <Button
            size="sm"
            variant="ghost"
            className="h-6 px-2 text-xs"
            onClick={() => onRangeChange(null)}
          >
            Clear selection
          </Button>
        ) : (
          <span className="text-muted">Click or drag to select a time range.</span>
        )}
        <label className="ml-auto flex shrink-0 items-center gap-1.5">
          <span className="text-muted">Span</span>
          <select
            aria-label="Histogram span"
            title="Bucket size for the time chart. Finer spans are unavailable when they would create too many bars."
            className="h-6 w-36 rounded-md border border-border bg-surface px-2 pr-7 text-xs text-foreground outline-none transition-colors focus:border-accent"
            value={spanId}
            onChange={(event) => onSpanChange(event.target.value as HistogramSpanId)}
          >
            {HISTOGRAM_SPAN_OPTIONS.map((option) => {
              const disabled =
                option.ms != null &&
                windowEndMs > windowStartMs &&
                !histogramSpanFits(windowStartMs, windowEndMs, option.ms);
              return (
                <option key={option.id} value={option.id} disabled={disabled}>
                  {option.label}
                </option>
              );
            })}
          </select>
        </label>
      </div>
      <div
        ref={wrapRef}
        className="relative select-none outline-none"
        tabIndex={0}
        onKeyDown={(event) => {
          if (event.key === "Escape" && range) {
            event.preventDefault();
            onRangeChange(null);
          }
        }}
        onPointerLeave={() => {
          if (!dragRef.current) setHover(null);
        }}
      >
        <svg
          width="100%"
          height={HEIGHT}
          viewBox={`0 0 ${Math.max(plotW, 1)} ${HEIGHT}`}
          preserveAspectRatio="xMinYMin meet"
          className="block cursor-crosshair"
          role="img"
          aria-label="Timeline event histogram. Click or drag to select a time range."
          onPointerDown={(event) => {
            if (event.button !== 0) return;
            event.preventDefault();
            wrapRef.current?.focus();
            const i = indexFromClientX(event.clientX);
            dragRef.current = { origin: i, current: i };
            setDrag({ origin: i, current: i });
            setHover(i);
          }}
          onPointerMove={(event) => {
            setHover(indexFromClientX(event.clientX));
          }}
        >
          {firstTimeLayout && lastTimeLayout
            ? [0.25, 0.5, 0.75].map((p) => (
                <line
                  key={p}
                  x1={firstTimeLayout.x}
                  y1={PAD.top + innerH * (1 - p)}
                  x2={lastTimeLayout.x + lastTimeLayout.w}
                  y2={PAD.top + innerH * (1 - p)}
                  stroke="var(--border)"
                  strokeWidth="1"
                  opacity="0.55"
                  vectorEffect="non-scaling-stroke"
                />
              ))
            : null}
          <line
            x1={PAD.left}
            y1={PAD.top + innerH + 0.5}
            x2={PAD.left + innerW}
            y2={PAD.top + innerH + 0.5}
            stroke="var(--border)"
            strokeWidth="1"
            vectorEffect="non-scaling-stroke"
          />
          {selectedSpan ? (
            <rect
              x={selectedSpan.x}
              y={PAD.top}
              width={selectedSpan.w}
              height={innerH}
              fill="var(--accent)"
              opacity="0.12"
            />
          ) : null}
          {hoverLayout && !selectedSpan ? (
            <rect
              x={hoverLayout.x}
              y={PAD.top}
              width={hoverLayout.w}
              height={innerH}
              fill="var(--accent)"
              opacity="0.06"
            />
          ) : null}
          {layout.map((item, i) => {
            const { bucket, x, w } = item;
            const visual =
              bucket.kind === "time" ? bucket.count : Math.min(bucket.count, maxCount);
            const h = barHeight(visual, maxCount, innerH);
            const gap = w >= 10 ? Math.min(3, w * 0.18) : w >= 4 ? 1 : 0.5;
            const selected = selectedSet ? selectedSet.has(i) : true;
            const dimmed = Boolean(selectedSet) && !selected;
            return (
              <rect
                key={`${bucket.kind}-${bucket.startMs}-${i}`}
                x={x + gap / 2}
                y={PAD.top + innerH - h}
                width={Math.max(1, w - gap)}
                height={h}
                rx={w > 8 ? 1 : 0}
                fill={bucket.kind === "time" ? "var(--accent)" : "var(--warning)"}
                opacity={dimmed ? 0.2 : hover === i ? 1 : 0.88}
              />
            );
          })}
        </svg>
        <div
          className="pointer-events-none absolute inset-x-0 bottom-0 overflow-visible text-[10px] leading-3 text-muted"
          style={{ height: PAD.bottom }}
        >
          {layout.map((item, i) => {
            if (item.bucket.kind === "earlier") {
              return (
                <span
                  key={i}
                  className="absolute bottom-0 truncate text-warning"
                  style={{ left: pct(item.x, plotW), width: pct(item.w, plotW), textAlign: "center" }}
                >
                  Earlier
                </span>
              );
            }
            if (item.bucket.kind === "later") {
              return (
                <span
                  key={i}
                  className="absolute bottom-0 truncate text-warning"
                  style={{ left: pct(item.x, plotW), width: pct(item.w, plotW), textAlign: "center" }}
                >
                  Later
                </span>
              );
            }
            return null;
          })}
          {firstTimeLayout ? (
            <span
              className="absolute bottom-0 w-max max-w-[50%] overflow-visible whitespace-nowrap"
              style={{ left: firstTimeLayout.x }}
            >
              {startLabel}
            </span>
          ) : null}
          {lastTimeLayout ? (
            <span
              className="absolute bottom-0 w-max max-w-[50%] overflow-visible whitespace-nowrap text-right"
              style={{ right: Math.max(0, plotW - (lastTimeLayout.x + lastTimeLayout.w)) }}
            >
              {endLabel}
            </span>
          ) : null}
        </div>
        {hoverText ? (
          <div
            ref={tooltipRef}
            className="pointer-events-none absolute top-1 z-10 max-w-[calc(100%-12px)] whitespace-nowrap rounded border border-border bg-surface px-2 py-1 text-[11px] text-foreground shadow-sm"
            style={{ left: tooltipLeft }}
          >
            {hoverText.title}
            <span className="ml-2 text-muted">{hoverText.detail}</span>
          </div>
        ) : null}
      </div>
    </div>
  );
});
