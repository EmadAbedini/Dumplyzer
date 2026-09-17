import { parseTimestampInstant } from "./datetime";

export type HistogramBucketKind = "time" | "earlier" | "later";

export type HistogramBucket = {
  startMs: number;
  endMs: number;
  count: number;
  kind: HistogramBucketKind;
};

export type HistogramRange = {
  startMs: number;
  endMs: number;
};

const INTERVALS_MS = [
  100,
  250,
  500,
  1_000,
  5_000,
  10_000,
  30_000,
  60_000,
  5 * 60_000,
  10 * 60_000,
  15 * 60_000,
  30 * 60_000,
  60 * 60_000,
  3 * 60 * 60_000,
  6 * 60 * 60_000,
  12 * 60 * 60_000,
  24 * 60 * 60_000,
  7 * 24 * 60 * 60_000,
  30 * 24 * 60 * 60_000,
];

/** Auto aims near this many bars across the dump's first→last range. */
const TARGET_AUTO_BARS = 24;
/** Auto will not exceed this; explicit spans may go up to MAX_SPAN_BARS. */
const MAX_AUTO_BARS = 40;
/** Upper bound when the user picks an explicit span. Finer values are unselectable. */
export const MAX_SPAN_BARS = 200;

export type HistogramSpanId =
  | "auto"
  | "1s"
  | "5s"
  | "10s"
  | "30s"
  | "1m"
  | "5m"
  | "10m"
  | "15m"
  | "30m"
  | "1h"
  | "3h"
  | "6h"
  | "12h"
  | "1d"
  | "1w";

export const HISTOGRAM_SPAN_OPTIONS: ReadonlyArray<{
  id: HistogramSpanId;
  label: string;
  ms: number | null;
}> = [
  { id: "auto", label: "Auto", ms: null },
  { id: "1s", label: "1 second", ms: 1_000 },
  { id: "5s", label: "5 seconds", ms: 5_000 },
  { id: "10s", label: "10 seconds", ms: 10_000 },
  { id: "30s", label: "30 seconds", ms: 30_000 },
  { id: "1m", label: "1 minute", ms: 60_000 },
  { id: "5m", label: "5 minutes", ms: 5 * 60_000 },
  { id: "10m", label: "10 minutes", ms: 10 * 60_000 },
  { id: "15m", label: "15 minutes", ms: 15 * 60_000 },
  { id: "30m", label: "30 minutes", ms: 30 * 60_000 },
  { id: "1h", label: "1 hour", ms: 60 * 60_000 },
  { id: "3h", label: "3 hours", ms: 3 * 60 * 60_000 },
  { id: "6h", label: "6 hours", ms: 6 * 60 * 60_000 },
  { id: "12h", label: "12 hours", ms: 12 * 60 * 60_000 },
  { id: "1d", label: "1 day", ms: 24 * 60 * 60_000 },
  { id: "1w", label: "1 week", ms: 7 * 24 * 60 * 60_000 },
];

export function eventTimeMs(value: string | null | undefined): number | null {
  if (!value) return null;
  const instant = parseTimestampInstant(value);
  if (!instant) return null;
  const ms = instant.getTime();
  return Number.isFinite(ms) ? ms : null;
}

/** Aligned buckets covering [startMs, endMs], matching Splunk-style fixed spans. */
export function histogramBarCount(startMs: number, endMs: number, stepMs: number): number {
  const step = Math.max(1, stepMs);
  const start = Math.floor(startMs / step) * step;
  const last = Math.floor(endMs / step) * step;
  return Math.max(1, Math.floor((last - start) / step) + 1);
}

function filledBarCount(
  timesMs: number[],
  startMs: number,
  endMs: number,
  stepMs: number,
): number {
  const n = histogramBarCount(startMs, endMs, stepMs);
  if (n <= 0 || timesMs.length === 0) return 0;
  const step = Math.max(1, stepMs);
  const aligned = Math.floor(startMs / step) * step;
  const used = new Set<number>();
  for (const t of timesMs) {
    used.add(Math.min(n - 1, Math.max(0, Math.floor((t - aligned) / step))));
  }
  return used.size;
}

/** Nice interval for this dump: near TARGET_AUTO_BARS, coarsened when most buckets would be empty. */
export function chooseHistogramStep(startMs: number, endMs: number, timesMs: number[] = []): number {
  const span = Math.max(endMs - startMs, 1);
  let bestStep = INTERVALS_MS[INTERVALS_MS.length - 1];
  let bestScore = Number.POSITIVE_INFINITY;
  let found = false;
  for (const step of INTERVALS_MS) {
    const n = histogramBarCount(startMs, endMs, step);
    if (n > MAX_AUTO_BARS) continue;
    const filled = timesMs.length > 0 ? filledBarCount(timesMs, startMs, endMs, step) : n;
    const empty = Math.max(0, n - filled);
    const score = Math.abs(n - TARGET_AUTO_BARS) + empty * 0.6;
    if (score < bestScore) {
      bestScore = score;
      bestStep = step;
      found = true;
    }
  }
  if (found) return bestStep;
  return Math.max(INTERVALS_MS[INTERVALS_MS.length - 1], Math.ceil(span / MAX_AUTO_BARS));
}

export function histogramSpanFits(startMs: number, endMs: number, stepMs: number): boolean {
  return histogramBarCount(startMs, endMs, stepMs) <= MAX_SPAN_BARS;
}

export function resolveHistogramStep(
  startMs: number,
  endMs: number,
  requestedMs?: number | null,
  timesMs: number[] = [],
): number {
  if (requestedMs && requestedMs > 0 && histogramSpanFits(startMs, endMs, requestedMs)) {
    return requestedMs;
  }
  return chooseHistogramStep(startMs, endMs, timesMs);
}

export function histogramSpanMs(id: HistogramSpanId): number | null {
  return HISTOGRAM_SPAN_OPTIONS.find((option) => option.id === id)?.ms ?? null;
}

export function timeBucketsOf(buckets: HistogramBucket[]): HistogramBucket[] {
  return buckets.filter((b) => b.kind === "time");
}

export type HistogramWindow = {
  min: number;
  max: number;
  span: number;
};

/** First event through last event. Span options that would overflow the bar cap are disabled separately. */
export function resolveHistogramWindow(timesMs: number[]): HistogramWindow | null {
  if (timesMs.length === 0) return null;
  let min = timesMs[0];
  let max = timesMs[0];
  for (const t of timesMs) {
    if (t < min) min = t;
    if (t > max) max = t;
  }
  return { min, max, span: Math.max(max - min, 1) };
}

export function buildHistogram(timesMs: number[], stepMs?: number | null): HistogramBucket[] {
  const win = resolveHistogramWindow(timesMs);
  if (!win) return [];
  const { min, max } = win;
  const step = resolveHistogramStep(min, max, stepMs, timesMs);
  const start = Math.floor(min / step) * step;
  const last = Math.floor(max / step) * step;
  const timed: HistogramBucket[] = [];
  for (let t = start; t <= last; t += step) {
    timed.push({ startMs: t, endMs: t + step, count: 0, kind: "time" });
  }
  if (timed.length === 0) {
    timed.push({ startMs: start, endMs: start + step, count: 0, kind: "time" });
  }
  const firstStart = timed[0].startMs;
  for (const ms of timesMs) {
    const i = Math.min(Math.max(0, Math.floor((ms - firstStart) / step)), timed.length - 1);
    timed[i].count += 1;
  }
  return timed;
}

export function rangeFromBuckets(
  buckets: HistogramBucket[],
  fromIndex: number,
  toIndex: number,
): HistogramRange | null {
  if (buckets.length === 0) return null;
  const a = Math.max(0, Math.min(fromIndex, toIndex));
  const b = Math.min(buckets.length - 1, Math.max(fromIndex, toIndex));
  return { startMs: buckets[a].startMs, endMs: buckets[b].endMs };
}

export function eventInRange(ms: number | null, range: HistogramRange | null): boolean {
  if (!range) return true;
  if (ms == null) return false;
  return ms >= range.startMs && ms < range.endMs;
}

function formatParts(ms: number, timeZone: string, opts: Intl.DateTimeFormatOptions): string {
  try {
    return new Intl.DateTimeFormat("en-US", {
      timeZone,
      hour12: false,
      hourCycle: "h23",
      ...opts,
    }).format(new Date(ms));
  } catch {
    return new Date(ms).toISOString();
  }
}

export function formatCompactHistogramTime(ms: number, spanMs: number, timeZone: string): string {
  if (!Number.isFinite(ms)) return "";
  if (spanMs <= 2 * 60_000) {
    return formatParts(ms, timeZone, {
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });
  }
  if (spanMs <= 2 * 60 * 60_000) {
    return formatParts(ms, timeZone, {
      hour: "2-digit",
      minute: "2-digit",
    });
  }
  if (spanMs <= 2 * 24 * 60 * 60_000) {
    return formatParts(ms, timeZone, {
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    });
  }
  if (spanMs <= 90 * 24 * 60 * 60_000) {
    return formatParts(ms, timeZone, { month: "short", day: "numeric" });
  }
  return formatParts(ms, timeZone, { year: "numeric", month: "short", day: "numeric" });
}

export function formatHistogramAxisDate(ms: number, timeZone: string): string {
  return formatParts(ms, timeZone, { year: "numeric", month: "short", day: "numeric" });
}

export function formatHistogramInterval(stepMs: number): string {
  if (stepMs < 1_000) return `${Math.round(stepMs)}ms`;
  if (stepMs < 60_000) return `${Math.round(stepMs / 1000)}s`;
  if (stepMs < 60 * 60_000) return `${Math.round(stepMs / 60_000)}m`;
  if (stepMs < 24 * 60 * 60_000) return `${Math.round(stepMs / (60 * 60_000))}h`;
  if (stepMs < 7 * 24 * 60 * 60_000) return `${Math.round(stepMs / (24 * 60 * 60_000))}d`;
  return `${Math.round(stepMs / (7 * 24 * 60 * 60_000))}w`;
}

export function formatHistogramBound(
  ms: number,
  edge: "start" | "end",
  buckets: HistogramBucket[],
  spanMs: number,
  timeZone: string,
): string {
  const bucket =
    edge === "start"
      ? buckets.find((b) => b.startMs === ms)
      : [...buckets].reverse().find((b) => b.endMs === ms);
  if (bucket?.kind === "earlier" && edge === "start") return "Earlier";
  if (bucket?.kind === "later" && edge === "end") return "Later";
  if (bucket?.kind === "earlier") return "Earlier";
  if (bucket?.kind === "later") return "Later";
  return formatCompactHistogramTime(ms, spanMs, timeZone);
}

export function formatBucketHover(
  bucket: HistogramBucket,
  spanMs: number,
  timeZone: string,
): { title: string; detail: string } {
  const count = `${bucket.count.toLocaleString()} events`;
  if (bucket.kind === "earlier") {
    return {
      title: `${count} earlier`,
      detail: formatCompactHistogramTime(bucket.startMs, Number.POSITIVE_INFINITY, timeZone),
    };
  }
  if (bucket.kind === "later") {
    return {
      title: `${count} later`,
      detail: formatCompactHistogramTime(bucket.endMs - 1, Number.POSITIVE_INFINITY, timeZone),
    };
  }
  return {
    title: count,
    detail: formatCompactHistogramTime(
      bucket.startMs,
      Math.min(spanMs, Math.max(bucket.endMs - bucket.startMs, 1)),
      timeZone,
    ),
  };
}
