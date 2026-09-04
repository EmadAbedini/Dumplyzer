import type { NavId } from "../lib/types";
import { cn } from "../lib/utils";

const NAV: { id: NavId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "processes", label: "Processes" },
  { id: "network", label: "Network" },
  { id: "modules", label: "Modules" },
  { id: "memory", label: "Memory" },
  { id: "findings", label: "Findings" },
  { id: "iocs", label: "IOCs" },
  { id: "timeline", label: "Timeline" },
  { id: "artifacts", label: "Artifacts" },
  { id: "jobs", label: "Jobs" },
  { id: "plugins", label: "Plugins" },
  { id: "settings", label: "Settings" },
];

type Props = {
  active: NavId;
  onSelect: (id: NavId) => void;
  evidenceLabel?: string | null;
};

export function Sidebar({ active, onSelect, evidenceLabel }: Props) {
  return (
    <aside className="flex w-48 shrink-0 flex-col border-r border-border bg-surface">
      <div className="border-b border-border px-3 py-3">
        <div className="text-sm font-semibold tracking-tight">MemScope</div>
        <div className="text-[11px] text-muted">Volatility 3 workbench</div>
      </div>
      <div className="border-b border-border px-3 py-2">
        <div className="text-[10px] uppercase tracking-wide text-muted">Evidence</div>
        <div className="mt-0.5 truncate text-xs" title={evidenceLabel ?? undefined}>
          {evidenceLabel ?? "None loaded"}
        </div>
      </div>
      <nav className="flex-1 overflow-y-auto p-1.5">
        {NAV.map((item) => (
          <button
            key={item.id}
            type="button"
            onClick={() => onSelect(item.id)}
            className={cn(
              "mb-0.5 flex w-full items-center rounded px-2 py-1.5 text-left text-xs",
              active === item.id
                ? "bg-surface-2 text-foreground"
                : "text-muted hover:bg-surface-2/60 hover:text-foreground",
            )}
          >
            {item.label}
          </button>
        ))}
      </nav>
    </aside>
  );
}
