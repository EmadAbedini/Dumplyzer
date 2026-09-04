import type { NavId } from "../lib/types";

export function PlaceholderView({ section }: { section: NavId }) {
  return (
    <div className="p-4 text-sm text-muted">
      <div className="mb-1 text-foreground font-semibold capitalize">{section}</div>
      Not implemented yet. Navigation and layout are in place for Phase 2+ work.
    </div>
  );
}
