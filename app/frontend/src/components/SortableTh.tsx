import type { SortState } from "../lib/tableSort";
import { cn } from "../lib/utils";

type Props = {
  label: string;
  column: string;
  sort: SortState | null;
  onToggle: (column: string) => void;
  className?: string;
};

export function SortableTh({ label, column, sort, onToggle, className }: Props) {
  const active = sort?.key === column;
  const dir = active ? sort?.dir : null;
  return (
    <th className={cn("px-2 py-1.5 text-center font-medium", className)}>
      <button
        type="button"
        className="inline-flex w-full max-w-full cursor-pointer items-center justify-center gap-1 bg-transparent p-0 text-center font-medium tracking-[0.04em] text-inherit uppercase"
        onClick={() => onToggle(column)}
        aria-label={`Sort by ${label}`}
        title={`Sort by ${label}`}
      >
        <span className="truncate">{label}</span>
        <span
          className={cn("shrink-0 text-[0.65rem]", active ? "text-foreground" : "opacity-40")}
          aria-hidden
        >
          {dir === "asc" ? "▲" : dir === "desc" ? "▼" : "↕"}
        </span>
      </button>
    </th>
  );
}
