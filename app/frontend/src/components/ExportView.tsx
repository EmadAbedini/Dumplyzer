import { useCallback, useEffect, useMemo, useState } from "react";
import { engineCall, EngineClientError } from "../lib/api";
import type {
  ExportFormat,
  ExportOptions,
  ExportRecord,
  ExportScope,
  ExportUiState,
  Job,
} from "../lib/types";
import { Badge } from "./ui/badge";
import { Button } from "./ui/button";

const DEFAULT_SECTIONS = [
  "metadata",
  "summary",
  "findings",
  "processes",
  "network",
  "modules",
  "memory",
  "timeline",
  "iocs",
  "artifacts",
  "malware",
  "advanced",
];

const CSV_SECTIONS = new Set([
  "processes",
  "network",
  "modules",
  "memory",
  "findings",
  "iocs",
  "timeline",
  "artifacts",
]);

type Props = {
  evidenceId: string | null;
  refreshToken?: number;
  onError: (msg: string) => void;
  onJobSubmitted: (job: Job) => void;
};

function statusFromJob(job: Job | null, fallback: ExportUiState): ExportUiState {
  if (!job) return fallback;
  if (job.status === "queued") return "queued";
  if (job.status === "running") return "running";
  if (job.status === "completed") return "completed";
  if (job.status === "failed") return "failed";
  if (job.status === "cancelled") return "cancelled";
  return fallback;
}

export function ExportView({
  evidenceId,
  refreshToken,
  onError,
  onJobSubmitted,
}: Props) {
  const [options, setOptions] = useState<ExportOptions | null>(null);
  const [format, setFormat] = useState<ExportFormat>("html");
  const [scope, setScope] = useState<ExportScope>("complete");
  const [selected, setSelected] = useState<string[]>(DEFAULT_SECTIONS);
  const [uiState, setUiState] = useState<ExportUiState>("idle");
  const [job, setJob] = useState<Job | null>(null);
  const [exports, setExports] = useState<ExportRecord[]>([]);
  const [message, setMessage] = useState<string>("");

  const sectionList = options?.sections ?? DEFAULT_SECTIONS;

  const loadExports = useCallback(async () => {
    if (!evidenceId) {
      setExports([]);
      return;
    }
    const res = await engineCall<{ items: ExportRecord[] }>("export.list", {
      evidence_id: evidenceId,
      limit: 50,
    });
    setExports(res.items);
  }, [evidenceId]);

  useEffect(() => {
    void (async () => {
      try {
        const opts = await engineCall<ExportOptions>("export.options");
        setOptions(opts);
      } catch (err) {
        onError(err instanceof EngineClientError ? err.message : String(err));
      }
    })();
  }, [onError]);

  useEffect(() => {
    void loadExports().catch((err) => {
      onError(err instanceof EngineClientError ? err.message : String(err));
    });
  }, [loadExports, refreshToken, onError]);

  useEffect(() => {
    if (!job || (job.status !== "queued" && job.status !== "running")) return;
    const t = window.setInterval(() => {
      void (async () => {
        try {
          const got = await engineCall<Job>("jobs.get", { job_id: job.id });
          setJob(got);
          setUiState(statusFromJob(got, "running"));
          setMessage(got.message || "");
          if (got.status === "completed" || got.status === "failed" || got.status === "cancelled") {
            await loadExports();
            if (got.status === "failed" && got.error) {
              const msg =
                typeof got.error.message === "string" ? got.error.message : "Export failed";
              onError(msg);
            }
          }
        } catch {
          /* ignore transient */
        }
      })();
    }, 800);
    return () => window.clearInterval(t);
  }, [job, loadExports, onError]);

  const toggleSection = (id: string) => {
    setSelected((cur) =>
      cur.includes(id) ? cur.filter((s) => s !== id) : [...cur, id],
    );
  };

  const csvWarning = useMemo(() => {
    if (format !== "csv" || scope !== "selected") return null;
    const usable = selected.filter((s) => CSV_SECTIONS.has(s));
    if (usable.length === 0) {
      return "CSV requires at least one tabular section (processes, network, modules, memory, findings, IOCs, timeline, artifacts).";
    }
    return null;
  }, [format, scope, selected]);

  const generate = async () => {
    if (!evidenceId) return;
    setUiState("queued");
    setMessage("Queued");
    try {
      const submitted = await engineCall<Job>("export.generate", {
        evidence_id: evidenceId,
        format,
        scope,
        sections: scope === "selected" ? selected : undefined,
      });
      setJob(submitted);
      setUiState(statusFromJob(submitted, "queued"));
      setMessage(submitted.message || "Queued");
      onJobSubmitted(submitted);
    } catch (err) {
      setUiState("failed");
      onError(err instanceof EngineClientError ? err.message : String(err));
    }
  };

  const cancel = async () => {
    if (!job) return;
    try {
      const got = await engineCall<Job>("jobs.cancel", { job_id: job.id });
      setJob(got);
      setUiState(statusFromJob(got, "cancelled"));
      await loadExports();
    } catch (err) {
      onError(err instanceof EngineClientError ? err.message : String(err));
    }
  };

  const busy = uiState === "queued" || uiState === "running";
  const result = job?.result as ExportRecord | null | undefined;

  return (
    <div className="flex h-full flex-col">
      <div className="flex items-center gap-2 border-b border-border px-3 py-2">
        <div className="text-sm font-semibold">Export / Report</div>
        <div className="text-xs text-muted">
          Offline JSON, CSV, and HTML reports under application data. Evidence is never overwritten.
        </div>
      </div>
      <div className="min-h-0 flex-1 overflow-auto p-3">
        {!evidenceId ? (
          <div className="text-xs text-muted">Import evidence before generating a report.</div>
        ) : (
          <div className="grid max-w-4xl gap-4">
            <section>
              <div className="mb-1 text-[11px] uppercase tracking-wide text-muted">Format</div>
              <div className="flex gap-2">
                {(["html", "json", "csv"] as ExportFormat[]).map((f) => (
                  <Button
                    key={f}
                    size="sm"
                    variant={format === f ? "default" : "outline"}
                    onClick={() => setFormat(f)}
                  >
                    {f.toUpperCase()}
                  </Button>
                ))}
              </div>
              <div className="mt-1 text-[11px] text-muted">
                HTML is the human-readable forensic report. JSON preserves structure. CSV is tabular
                only. PDF is not generated.
              </div>
            </section>

            <section>
              <div className="mb-1 text-[11px] uppercase tracking-wide text-muted">Scope</div>
              <div className="flex gap-2">
                {(["complete", "selected"] as ExportScope[]).map((s) => (
                  <Button
                    key={s}
                    size="sm"
                    variant={scope === s ? "default" : "outline"}
                    onClick={() => setScope(s)}
                  >
                    {s === "complete" ? "Complete report" : "Selected sections"}
                  </Button>
                ))}
              </div>
            </section>

            {scope === "selected" ? (
              <section>
                <div className="mb-1 text-[11px] uppercase tracking-wide text-muted">Sections</div>
                <div className="grid grid-cols-2 gap-1 sm:grid-cols-3">
                  {sectionList.map((id) => (
                    <label key={id} className="flex items-center gap-2 text-xs">
                      <input
                        type="checkbox"
                        checked={selected.includes(id)}
                        onChange={() => toggleSection(id)}
                      />
                      {id}
                    </label>
                  ))}
                </div>
                {csvWarning ? (
                  <div className="mt-2 text-xs text-danger">{csvWarning}</div>
                ) : null}
              </section>
            ) : null}

            <section className="flex items-center gap-2">
              <Button size="sm" disabled={busy || !!csvWarning} onClick={() => void generate()}>
                Generate
              </Button>
              <Button
                size="sm"
                variant="outline"
                disabled={!busy}
                onClick={() => void cancel()}
              >
                Cancel
              </Button>
              <Badge
                className={
                  uiState === "failed"
                    ? "border-danger text-danger"
                    : uiState === "completed"
                      ? "border-success text-success"
                      : uiState === "running" || uiState === "queued"
                        ? "border-accent text-accent"
                        : ""
                }
              >
                {uiState}
              </Badge>
              <span className="text-xs text-muted">{message}</span>
            </section>

            {result && uiState === "completed" ? (
              <section className="rounded border border-border bg-surface-2 p-2 text-xs">
                <div>
                  Output:{" "}
                  <span className="font-mono">{result.primary_path || result.output_dir}</span>
                </div>
                <div className="mt-1 text-muted">
                  Schema v{result.report_schema_version} · {result.files?.length ?? 0} file(s)
                </div>
              </section>
            ) : null}

            <section>
              <div className="mb-1 text-[11px] uppercase tracking-wide text-muted">
                Previous exports
              </div>
              <table className="w-full text-left text-xs">
                <thead className="bg-surface-2 text-muted">
                  <tr>
                    <th className="px-2 py-1">Status</th>
                    <th className="px-2 py-1">Format</th>
                    <th className="px-2 py-1">Scope</th>
                    <th className="px-2 py-1">Path</th>
                    <th className="px-2 py-1">Created</th>
                  </tr>
                </thead>
                <tbody>
                  {exports.map((row) => (
                    <tr key={row.id} className="border-t border-border/40">
                      <td className="px-2 py-1">{row.status}</td>
                      <td className="px-2 py-1">{row.format}</td>
                      <td className="px-2 py-1">{row.scope}</td>
                      <td className="max-w-md truncate px-2 py-1 font-mono" title={row.primary_path ?? undefined}>
                        {row.primary_path}
                      </td>
                      <td className="px-2 py-1">{row.created_at}</td>
                    </tr>
                  ))}
                  {exports.length === 0 ? (
                    <tr>
                      <td className="px-2 py-2 text-muted" colSpan={5}>
                        No exports yet.
                      </td>
                    </tr>
                  ) : null}
                </tbody>
              </table>
            </section>
          </div>
        )}
      </div>
    </div>
  );
}
