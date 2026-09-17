import { formatAppVersion } from "../lib/appMeta";
import type { AppErrorPayload } from "../lib/types";
import { Button } from "./ui/button";

type Props = {
  importing: boolean;
  analyzing: boolean;
  error: AppErrorPayload | null;
  appVersion: string;
  onImport: () => void;
  onAnalyze: () => void;
  canAnalyze: boolean;
};

export function TopBar({
  importing,
  analyzing,
  error,
  appVersion,
  onImport,
  onAnalyze,
  canAnalyze,
}: Props) {
  const versionLabel = formatAppVersion(appVersion);

  return (
    <header className="flex items-center gap-2 border-b border-border bg-surface px-3 py-2">
      <Button size="sm" onClick={onImport} disabled={importing}>
        Import Memory Dump
      </Button>
      <Button
        size="sm"
        variant="outline"
        onClick={onAnalyze}
        disabled={!canAnalyze}
      >
        {analyzing ? "Running analysis" : "Run Analysis"}
      </Button>
      <div className="ml-auto max-w-[50%] truncate text-sm text-muted">
        {error ? (
          <span className="text-danger" title={error.details ?? error.raw}>
            {error.message}
            {error.suggestion ? ` — ${error.suggestion}` : ""}
          </span>
        ) : importing ? (
          <span>Importing Memory Image…</span>
        ) : (
          <span>{versionLabel}</span>
        )}
      </div>
    </header>
  );
}
