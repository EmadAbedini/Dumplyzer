import { Button } from "./ui/button";
import type { AppErrorPayload } from "../lib/types";

type Props = {
  busy: boolean;
  error: AppErrorPayload | null;
  onImport: () => void;
  onAnalyze: () => void;
  canAnalyze: boolean;
};

export function TopBar({ busy, error, onImport, onAnalyze, canAnalyze }: Props) {
  return (
    <header className="flex items-center gap-2 border-b border-border bg-surface px-3 py-2">
      <Button size="sm" onClick={onImport} disabled={busy}>
        Import memory…
      </Button>
      <Button
        size="sm"
        variant="outline"
        onClick={onAnalyze}
        disabled={busy || !canAnalyze}
      >
        {busy ? "Working…" : "Run basic triage"}
      </Button>
      <div className="ml-auto max-w-[50%] truncate text-xs text-muted">
        {error ? (
          <span className="text-danger" title={error.details ?? error.raw}>
            {error.message}
            {error.suggestion ? ` — ${error.suggestion}` : ""}
          </span>
        ) : (
          <span>Offline workbench</span>
        )}
      </div>
    </header>
  );
}
