import { coverageItem, OVERVIEW_COVERAGE_ROWS } from "../lib/analysisCoverage";
import { useState } from "react";
import type { ReactNode } from "react";
import type { Overview } from "../lib/types";
import { Badge } from "./ui/badge";
import { Button } from "./ui/button";
import { CoverageStatus } from "./CoverageStatus";
import { StatusToast, useStatusToast } from "./StatusToast";

function analysisHasNotRun(importStatus: string | null | undefined): boolean {
  return !importStatus || importStatus === "imported";
}

function displaySymbolStatus(
  symbolStatus: string | null | undefined,
  importStatus: string | null | undefined,
  waitingForPdb = false,
): string {
  if (waitingForPdb) return "Waiting for PDB";
  if (analysisHasNotRun(importStatus)) return "Not analyzed";
  if (!symbolStatus || symbolStatus === "unknown") return "—";
  return symbolStatus;
}

function Row({ label, value }: { label: string; value: ReactNode }) {
  return (
    <div className="grid grid-cols-[140px_1fr] items-center gap-2 border-b border-border/60 py-1.5 text-xs last:border-0">
      <div className="text-muted">{label}</div>
      <div className="font-mono break-all">{value ?? "—"}</div>
    </div>
  );
}

function HashValue({ value }: { value: string | null | undefined }) {
  const { toast, showToast } = useStatusToast();
  const [busy, setBusy] = useState(false);
  if (!value) return "—";
  return (
    <span className="inline-flex max-w-full items-center gap-2">
      <span className="min-w-0 break-all">{value}</span>
      <Button
        type="button"
        size="sm"
        variant="outline"
        className="h-6 shrink-0 px-2 text-[0.7rem]"
        disabled={busy}
        onClick={() => {
          if (busy) return;
          setBusy(true);
          void navigator.clipboard
            .writeText(value)
            .then(() => showToast("SHA-256 copied"))
            .finally(() => setBusy(false));
        }}
      >
        Copy
      </Button>
      <StatusToast message={toast} />
    </span>
  );
}

export function OverviewView({
  data,
  onImport,
  importing = false,
  waitingForPdb = false,
}: {
  data: Overview | null;
  onImport?: () => void;
  importing?: boolean;
  waitingForPdb?: boolean;
}) {
  if (!data) {
    return (
      <div className="flex h-full items-start justify-center p-8">
        <div className="w-full max-w-lg">
          <button
            type="button"
            className="card app-import-prompt group w-full cursor-pointer appearance-none p-6 text-center text-inherit disabled:pointer-events-none disabled:cursor-not-allowed disabled:opacity-60"
            onClick={onImport}
            disabled={importing || !onImport}
            aria-label="Import a memory dump"
          >
            <h2 className="text-base font-semibold transition-colors group-hover:text-accent">
              No evidence loaded
            </h2>
            <p className="mt-2 text-sm text-muted">
              Import a memory dump to begin investigation, or drag a dump file onto
              this window.
            </p>
          </button>
        </div>
      </div>
    );
  }
  const e = data.evidence;
  const notAnalyzed = analysisHasNotRun(e.import_status);
  const symbolLabel = displaySymbolStatus(e.symbol_status, e.import_status, waitingForPdb);
  return (
    <div className="p-5">
      <div className="mb-4 flex items-center gap-2">
        <h2 className="text-base font-semibold tracking-tight">Overview</h2>
        <Badge>{waitingForPdb ? "imported" : (e.import_status ?? "imported")}</Badge>
        {waitingForPdb ? (
          <Badge>Waiting for PDB</Badge>
        ) : notAnalyzed ? (
          <Badge>Not analyzed</Badge>
        ) : e.symbol_status && e.symbol_status !== "unknown" ? (
          <Badge>{e.symbol_status}</Badge>
        ) : null}
      </div>
      <div className="card overflow-hidden px-4 py-1">
      <Row label="Filename" value={e.filename} />
      <Row label="Path" value={e.path} />
      <Row label="Size" value={`${e.size_bytes.toLocaleString()} bytes`} />
      <Row label="SHA-256" value={<HashValue value={e.sha256} />} />
      <Row label="OS" value={e.detected_os} />
      <Row label="Architecture" value={e.architecture} />
      <Row label="Symbol status" value={symbolLabel} />
      <Row label="Symbol detail" value={e.symbol_detail} />
      <div className="mb-1 mt-[15px] text-[11px] font-medium uppercase tracking-wider text-muted">
        Analysis
      </div>
      {OVERVIEW_COVERAGE_ROWS.map((row) => (
        <Row
          key={row.id}
          label={row.label}
          value={<CoverageStatus item={coverageItem(data.coverage, row.id)} />}
        />
      ))}
      </div>
    </div>
  );
}
