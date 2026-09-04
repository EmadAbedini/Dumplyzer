import { cn } from "../../lib/utils";

export function Input({
  className,
  ...props
}: React.InputHTMLAttributes<HTMLInputElement>) {
  return (
    <input
      className={cn(
        "h-8 w-full rounded-md border border-border bg-surface px-2.5 text-xs text-foreground placeholder:text-muted outline-none focus:border-accent",
        className,
      )}
      {...props}
    />
  );
}
