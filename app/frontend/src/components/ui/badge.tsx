import { cn } from "../../lib/utils";

export function Badge({
  className,
  ...props
}: React.HTMLAttributes<HTMLSpanElement>) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-md border border-border bg-surface-2 px-1.5 py-0.5 text-[0.78rem] font-medium uppercase tracking-wide text-muted",
        className,
      )}
      {...props}
    />
  );
}
