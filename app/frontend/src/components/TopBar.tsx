import { formatAppVersion } from "../lib/appMeta";
import { Button } from "./ui/button";

type Props = {
  importing: boolean;
  analyzing: boolean;
  appVersion: string;
  onImport: () => void;
  onAnalyze: () => void;
  canAnalyze: boolean;
  analyzeDisabledReason?: string;
};

export function TopBar({
  importing,
  analyzing,
  appVersion,
  onImport,
  onAnalyze,
  canAnalyze,
  analyzeDisabledReason,
}: Props) {
  const versionLabel = formatAppVersion(appVersion);

  return (
    <header className="flex items-center gap-2 border-b border-border bg-surface px-3 py-2">
      <Button size="sm" onClick={onImport} disabled={importing}>
        Import Memory Dump
      </Button>
      <span className="inline-flex" title={!canAnalyze ? analyzeDisabledReason : undefined}>
        <Button
          size="sm"
          variant="outline"
          onClick={onAnalyze}
          disabled={!canAnalyze}
        >
          {analyzing ? "Running Analysis" : "Run Analysis"}
        </Button>
      </span>
      <div className="ml-auto max-w-[50%] truncate text-sm text-muted">
        {importing ? <span>Importing Memory Image…</span> : <span>{versionLabel}</span>}
      </div>
    </header>
  );
}
