import type { NavId } from "../lib/types";

export function PlaceholderView({ section }: { section: NavId }) {
  return (
    <div className="p-4 text-sm text-muted">
      <div className="mb-1 font-semibold capitalize text-foreground">{section}</div>
      This view is not available.
    </div>
  );
}
