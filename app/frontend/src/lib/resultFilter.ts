/** Client-side filter for already-loaded result rows. Does not trigger analysis. */

export const FILTER_FIELD_ALL = "all";

export type FilterFieldOption = { id: string; label: string };

export function matchesQuery(query: string, parts: unknown[]): boolean {
  const q = query.trim().toLowerCase();
  if (!q) return true;
  return parts.some((part) => {
    if (part == null || part === "") return false;
    if (typeof part === "object") {
      try {
        return JSON.stringify(part).toLowerCase().includes(q);
      } catch {
        return false;
      }
    }
    return String(part).toLowerCase().includes(q);
  });
}

/** Filter by one named field, or every value when `field` is All. */
export function matchesFieldQuery(
  query: string,
  field: string,
  values: Record<string, unknown | unknown[]>,
  allExtra: unknown[] = [],
): boolean {
  if (!query.trim()) return true;
  if (field === FILTER_FIELD_ALL || !(field in values)) {
    return matchesQuery(query, [
      ...Object.values(values).flatMap((v) => (Array.isArray(v) ? v : [v])),
      ...allExtra,
    ]);
  }
  const selected = values[field];
  return matchesQuery(query, Array.isArray(selected) ? selected : [selected]);
}
