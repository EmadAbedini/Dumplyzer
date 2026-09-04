import { cn } from "../../lib/utils";

type ButtonProps = React.ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: "default" | "ghost" | "outline" | "danger";
  size?: "sm" | "md";
};

export function Button({
  className,
  variant = "default",
  size = "md",
  ...props
}: ButtonProps) {
  return (
    <button
      className={cn(
        "inline-flex items-center justify-center rounded-md font-medium transition-colors disabled:opacity-50 disabled:pointer-events-none",
        size === "sm" ? "h-7 px-2.5 text-xs" : "h-8 px-3 text-xs",
        variant === "default" && "bg-accent text-accent-fg hover:bg-blue-600",
        variant === "ghost" && "hover:bg-surface-2 text-foreground",
        variant === "outline" &&
          "border border-border bg-transparent hover:bg-surface-2",
        variant === "danger" && "bg-danger/90 text-white hover:bg-danger",
        className,
      )}
      {...props}
    />
  );
}
