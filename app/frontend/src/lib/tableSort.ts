import { useMemo, useState } from "react";

export type SortDir = "asc" | "desc";
export type SortState = { key: string; dir: SortDir };

function isEmptySortValue(value: unknown): boolean {
  return value == null || value === "" || value === "—";
}

function numericCandidate(value: unknown): number | null {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value !== "string") return null;
  const trimmed = value.trim().replace(/,/g, "");
  if (!/^-?\d+(\.\d+)?$/.test(trimmed)) return null;
  const n = Number(trimmed);
  return Number.isFinite(n) ? n : null;
}

export function compareSortValues(a: unknown, b: unknown): number {
  const emptyA = isEmptySortValue(a);
  const emptyB = isEmptySortValue(b);
  if (emptyA && emptyB) return 0;
  if (emptyA) return 1;
  if (emptyB) return -1;
  const numA = numericCandidate(a);
  const numB = numericCandidate(b);
  if (numA != null && numB != null) return numA - numB;
  return String(a).localeCompare(String(b), undefined, {
    numeric: true,
    sensitivity: "base",
  });
}

export function sortRows<T>(
  rows: T[],
  sort: SortState | null,
  getValue: (row: T, key: string) => unknown,
): T[] {
  if (!sort) return rows;
  const copy = rows.slice();
  copy.sort((left, right) => {
    const cmp = compareSortValues(getValue(left, sort.key), getValue(right, sort.key));
    return sort.dir === "asc" ? cmp : -cmp;
  });
  return copy;
}

export function useTableSort<T>(
  rows: T[],
  getValue: (row: T, key: string) => unknown,
): {
  sorted: T[];
  sort: SortState | null;
  toggle: (key: string) => void;
} {
  const [sort, setSort] = useState<SortState | null>(null);
  const toggle = (key: string) => {
    setSort((cur) => {
      if (!cur || cur.key !== key) return { key, dir: "asc" };
      if (cur.dir === "asc") return { key, dir: "desc" };
      return null;
    });
  };
  const sorted = useMemo(
    () => sortRows(rows, sort, getValue),
    [rows, sort, getValue],
  );
  return { sorted, sort, toggle };
}
