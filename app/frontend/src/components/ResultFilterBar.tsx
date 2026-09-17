import { FILTER_FIELD_ALL, type FilterFieldOption } from "../lib/resultFilter";
import { cn } from "../lib/utils";
import { ClearableInput } from "./ui/input";

export function ResultFilterBar({
  query,
  onQueryChange,
  field,
  onFieldChange,
  fields,
  className,
}: {
  query: string;
  onQueryChange: (value: string) => void;
  field: string;
  onFieldChange: (value: string) => void;
  fields: FilterFieldOption[];
  placeholder?: string;
  className?: string;
}) {
  const selected = field === FILTER_FIELD_ALL ? null : fields.find((item) => item.id === field);
  const inputPlaceholder = selected ? `Filter ${selected.label}…` : "Filter all items…";

  return (
    <div
      className={cn(
        "ml-auto flex min-w-0 flex-1 basis-56 items-center gap-2",
        className ?? "w-full max-w-xl",
      )}
    >
      <select
        aria-label="Filter field"
        className="app-result-filter-field h-8 shrink-0 rounded-md border border-border bg-surface px-2.5 pr-8 text-sm text-foreground shadow-sm outline-none transition-colors focus:border-accent"
        value={field}
        onChange={(e) => onFieldChange(e.target.value)}
      >
        <option value={FILTER_FIELD_ALL}>All</option>
        {fields.map((item) => (
          <option key={item.id} value={item.id}>
            {item.label}
          </option>
        ))}
      </select>
      <ClearableInput
        className="min-w-0"
        placeholder={inputPlaceholder}
        value={query}
        onChange={(e) => onQueryChange(e.target.value)}
        onClear={() => {
          onQueryChange("");
          onFieldChange(FILTER_FIELD_ALL);
        }}
      />
    </div>
  );
}
