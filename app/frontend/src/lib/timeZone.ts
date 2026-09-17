export function systemTimeZone(): string {
  try {
    const zone = Intl.DateTimeFormat().resolvedOptions().timeZone;
    if (zone && isValidTimeZone(zone)) return zone;
  } catch {
    /* ignore */
  }
  return "UTC";
}

export function isValidTimeZone(id: string): boolean {
  if (!id) return false;
  try {
    Intl.DateTimeFormat("en-US", { timeZone: id }).format(new Date());
    return true;
  } catch {
    return false;
  }
}

export function listIanaTimeZones(): string[] {
  const intl = Intl as typeof Intl & {
    supportedValuesOf?: (key: "timeZone") => string[];
  };
  if (typeof intl.supportedValuesOf === "function") {
    try {
      return intl.supportedValuesOf("timeZone");
    } catch {
      /* ignore */
    }
  }
  return ["UTC"];
}
