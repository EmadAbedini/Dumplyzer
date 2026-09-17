import { X } from "lucide-react";
import { cn } from "../../lib/utils";

export function Input({
  className,
  ...props
}: React.InputHTMLAttributes<HTMLInputElement>) {
  return (
    <input
      className={cn(
        "h-8 w-full rounded-md border border-border bg-surface px-2.5 text-sm text-foreground shadow-sm placeholder:text-muted outline-none transition-colors focus:border-accent",
        "[&::-ms-clear]:hidden [&::-ms-reveal]:hidden [&::-webkit-search-cancel-button]:hidden",
        className,
      )}
      {...props}
    />
  );
}

export function ClearableInput({
  className,
  wrapperClassName,
  value,
  onChange,
  onClear,
  ...props
}: React.InputHTMLAttributes<HTMLInputElement> & {
  wrapperClassName?: string;
  onClear?: () => void;
}) {
  const text = value == null ? "" : String(value);
  const showClear = text.length > 0;
  return (
    <div className={cn("relative min-w-0 flex-1", wrapperClassName)}>
      <Input
        className={cn(showClear && "pr-9", className)}
        value={value}
        onChange={onChange}
        {...props}
      />
      {showClear ? (
        <button
          type="button"
          className="absolute inset-y-0 right-0 flex w-8 cursor-pointer items-center justify-center text-muted transition-colors hover:text-foreground focus-visible:outline-none focus-visible:text-foreground"
          aria-label="Clear"
          title="Clear"
          onClick={() => {
            if (onClear) {
              onClear();
              return;
            }
            onChange?.({
              target: { value: "" },
            } as React.ChangeEvent<HTMLInputElement>);
          }}
        >
          <X size={16} strokeWidth={2.25} aria-hidden />
        </button>
      ) : null}
    </div>
  );
}
