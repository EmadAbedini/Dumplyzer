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
        "inline-flex shrink-0 cursor-pointer items-center justify-center whitespace-nowrap rounded-md font-medium shadow-sm transition-colors disabled:cursor-not-allowed disabled:opacity-50 disabled:pointer-events-none",
        size === "sm" ? "h-8 px-3 text-sm" : "h-9 px-3.5 text-sm",
        variant === "default" && "bg-accent text-accent-fg hover:brightness-110",
        variant === "ghost" && "shadow-none hover:bg-surface-2 text-foreground",
        variant === "outline" &&
          "border border-border bg-transparent shadow-none hover:bg-surface-2",
        variant === "danger" && "bg-danger/90 text-white hover:bg-danger",
        className,
      )}
      {...props}
    />
  );
}
