import { cn } from "../../lib/utils";

export type SegmentedOption<T extends string> = {
  id: T;
  label: string;
  title?: string;
  disabled?: boolean;
  buttonId?: string;
};

export function SegmentedControl<T extends string>({
  value,
  onChange,
  options,
  ariaLabel,
  className,
}: {
  value: T;
  onChange: (value: T) => void;
  options: Array<SegmentedOption<T>>;
  ariaLabel: string;
  className?: string;
}) {
  return (
    <div
      role="tablist"
      aria-label={ariaLabel}
      className={cn(
        "inline-flex h-8 overflow-hidden rounded-md border border-border bg-border gap-px",
        className,
      )}
    >
      {options.map((opt) => {
        const selected = value === opt.id;
        return (
          <button
            key={opt.id}
            id={opt.buttonId}
            type="button"
            role="tab"
            title={opt.title}
            disabled={opt.disabled}
            aria-selected={selected}
            className={cn(
              "inline-flex h-full items-center justify-center whitespace-nowrap px-3 text-sm font-medium leading-none transition-colors disabled:cursor-not-allowed disabled:opacity-50",
              selected
                ? "bg-accent text-accent-fg"
                : "bg-surface-2 text-muted hover:text-foreground",
            )}
            onClick={() => onChange(opt.id)}
          >
            {opt.label}
          </button>
        );
      })}
    </div>
  );
}
