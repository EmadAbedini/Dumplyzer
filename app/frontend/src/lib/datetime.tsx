import { createContext, useContext, type ReactNode } from "react";
import { isValidTimeZone, systemTimeZone } from "./timeZone";

const MONTHS = [
  "Jan",
  "Feb",
  "Mar",
  "Apr",
  "May",
  "Jun",
  "Jul",
  "Aug",
  "Sep",
  "Oct",
  "Nov",
  "Dec",
] as const;

/** ISO-8601 datetime with optional fractional seconds and offset. */
const ISO_TS =
  /^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(?:(Z)|([+-])(\d{2}):?(\d{2}))?$/i;

export function isIsoTimestamp(value: string): boolean {
  return ISO_TS.test(value.trim());
}

/**
 * Parse a stored timestamp as an instant.
 * Naive ISO values (no offset) are treated as UTC, matching engine storage.
 */
export function parseTimestampInstant(value: string): Date | null {
  const raw = value.trim();
  if (!raw) return null;
  const match = ISO_TS.exec(raw);
  if (!match) {
    const ms = Date.parse(raw);
    return Number.isNaN(ms) ? null : new Date(ms);
  }
  const hasOffset = Boolean(match[7] || match[8]);
  const iso = hasOffset
    ? raw
    : `${match[1]}-${match[2]}-${match[3]}T${match[4]}:${match[5]}:${match[6]}Z`;
  const ms = Date.parse(iso);
  return Number.isNaN(ms) ? null : new Date(ms);
}

/**
 * Display-only formatting.
 * When timeZone is set, convert the instant into that IANA zone.
 * When omitted, keep stored wall-clock fields (canonical presentation).
 * Never mutates the stored value.
 */
export function formatDisplayTimestamp(
  value: string | number | null | undefined,
  fallback = "—",
  timeZone?: string | null,
): string {
  if (value == null || value === "") return fallback;
  const raw = String(value).trim();
  if (!raw) return fallback;
  if (timeZone && isValidTimeZone(timeZone)) {
    const instant = parseTimestampInstant(raw);
    if (instant) {
      const converted = formatInstantInZone(instant, timeZone);
      if (converted) return converted;
    }
  }
  return formatCanonicalWallClock(raw);
}

function formatCanonicalWallClock(raw: string): string {
  const match = ISO_TS.exec(raw);
  if (!match) return raw;
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  if (!Number.isFinite(year) || month < 1 || month > 12 || day < 1 || day > 31) {
    return raw;
  }
  const time = `${match[4]}:${match[5]}:${match[6]}`;
  const date = `${MONTHS[month - 1]} ${day}, ${year}`;
  const zone = formatStoredZoneLabel(match[7], match[8], match[9], match[10]);
  return zone ? `${date}, ${time} ${zone}` : `${date}, ${time}`;
}

function formatStoredZoneLabel(
  zulu: string | undefined,
  sign: string | undefined,
  hours: string | undefined,
  minutes: string | undefined,
): string {
  if (zulu) return "UTC";
  if (!sign || hours == null || minutes == null) return "";
  if (hours === "00" && minutes === "00") return "UTC";
  return `${sign}${hours}:${minutes}`;
}

function formatInstantInZone(date: Date, timeZone: string): string | null {
  try {
    const parts = new Intl.DateTimeFormat("en-US", {
      timeZone,
      year: "numeric",
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: false,
      hourCycle: "h23",
      timeZoneName: "short",
    }).formatToParts(date);
    const get = (type: Intl.DateTimeFormatPartTypes) =>
      parts.find((p) => p.type === type)?.value ?? "";
    const month = get("month");
    const day = get("day").replace(/^0/, "");
    const year = get("year");
    const hour = get("hour").padStart(2, "0");
    const minute = get("minute").padStart(2, "0");
    const second = get("second").padStart(2, "0");
    let zone = get("timeZoneName");
    if (timeZone === "UTC" || zone === "GMT" || zone === "GMT+0" || zone === "GMT-0") {
      zone = "UTC";
    }
    if (!month || !day || !year) return null;
    return zone
      ? `${month} ${day}, ${year}, ${hour}:${minute}:${second} ${zone}`
      : `${month} ${day}, ${year}, ${hour}:${minute}:${second}`;
  } catch {
    return null;
  }
}

const DisplayTimeZoneContext = createContext<string>(systemTimeZone());

export function DisplayTimeZoneProvider({
  timeZone,
  children,
}: {
  timeZone: string;
  children: ReactNode;
}) {
  const zone = isValidTimeZone(timeZone) ? timeZone : systemTimeZone();
  return (
    <DisplayTimeZoneContext.Provider value={zone}>{children}</DisplayTimeZoneContext.Provider>
  );
}

export function useDisplayTimeZone(): string {
  return useContext(DisplayTimeZoneContext);
}

export {
  isValidTimeZone,
  listIanaTimeZones,
  systemTimeZone,
} from "./timeZone";

/** Display formatted time; hover shows the unmodified stored value. */
export function TimestampText({
  value,
  fallback = "—",
  convert = true,
}: {
  value: string | number | null | undefined;
  fallback?: string;
  /** When false, show stored wall-clock fields without converting. */
  convert?: boolean;
}): ReactNode {
  const timeZone = useDisplayTimeZone();
  if (value == null || value === "") return fallback;
  const raw = String(value);
  const text = formatDisplayTimestamp(raw, fallback, convert ? timeZone : null);
  return (
    <span title={raw} className="whitespace-nowrap">
      {text}
    </span>
  );
}

/** Format a result-table cell, converting ISO timestamps when present. */
export function formatResultCell(value: string | number | null | undefined): ReactNode {
  if (value == null || value === "") return "—";
  if (typeof value === "string" && isIsoTimestamp(value)) {
    return <TimestampText value={value} />;
  }
  return value;
}
