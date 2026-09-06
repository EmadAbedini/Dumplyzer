import { useCallback, useEffect, useMemo, useState } from "react";
import { engineCall, EngineClientError } from "../lib/api";
import { filterPluginItems } from "../lib/pluginExplorer";
import type {
  Evidence,
  Job,
  PluginCatalog,
  PluginDetail,
  PluginExecutionBundle,
  PluginExecutionSummary,
  PluginRequirement,
} from "../lib/types";
import { Badge } from "./ui/badge";
import { Button } from "./ui/button";
import { Input } from "./ui/input";

export function PluginExplorerView({
  evidence,
  onError,
  onJobSubmitted,
  onOpenProcess,
  refreshToken,
}: {
  evidence: Evidence | null;
  onError: (m: string) => void;
  onJobSubmitted?: (job: Job) => void;
  onOpenProcess?: (processId: string) => void;
  refreshToken?: number;
}) {
  const [catalog, setCatalog] = useState<PluginCatalog | null>(null);
  const [query, setQuery] = useState("");
  const [category, setCategory] = useState("all");
  const [runnableOnly, setRunnableOnly] = useState(false);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [detail, setDetail] = useState<PluginDetail | null>(null);
  const [params, setParams] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState(false);
  const [job, setJob] = useState<Job | null>(null);
  const [bundle, setBundle] = useState<PluginExecutionBundle | null>(null);
  const [history, setHistory] = useState<PluginExecutionSummary[]>([]);
  const [tab, setTab] = useState<"table" | "raw">("table");

  const loadCatalog = useCallback(async () => {
    try {
      const res = await engineCall<PluginCatalog>("plugins.list", {
        evidence_id: evidence?.id,
      });
      setCatalog(res);
    } catch (e) {
      onError(e instanceof EngineClientError ? e.message : String(e));
    }
  }, [evidence?.id, onError]);

  const loadHistory = useCallback(async () => {
    if (!evidence) {
      setHistory([]);
      return;
    }
    try {
      const res = await engineCall<{ items: PluginExecutionSummary[] }>("plugins.executions", {
        evidence_id: evidence.id,
      });
      setHistory(res.items);
    } catch {
      /* optional */
    }
  }, [evidence]);

  useEffect(() => {
    void loadCatalog();
  }, [loadCatalog]);

  useEffect(() => {
    void loadHistory();
  }, [loadHistory, refreshToken]);

  const items = useMemo(
    () => filterPluginItems(catalog?.items ?? [], { query, category, runnableOnly }),
    [catalog, query, category, runnableOnly],
  );

  const openPlugin = async (id: string) => {
    setSelectedId(id);
    setBundle(null);
    setJob(null);
    try {
      const d = await engineCall<PluginDetail>("plugins.get", {
        plugin_id: id,
        evidence_id: evidence?.id,
      });
      setDetail(d);
      const next: Record<string, string> = {};
      for (const req of d.plugin.configurable_parameters ?? []) {
        if (req.default != null && req.default !== "") {
          next[req.name] = Array.isArray(req.default)
            ? (req.default as unknown[]).join(",")
            : String(req.default);
        }
      }
      setParams(next);
    } catch (e) {
      onError(e instanceof EngineClientError ? e.message : String(e));
    }
  };

  const parseParams = (): Record<string, unknown> => {
    const out: Record<string, unknown> = {};
    const specs = detail?.plugin.configurable_parameters ?? [];
    for (const spec of specs) {
      const raw = params[spec.name];
      if (raw == null || raw === "") continue;
      if (spec.type === "BooleanRequirement") {
        out[spec.name] = raw === "true" || raw === "1";
      } else if (spec.type === "IntRequirement") {
        out[spec.name] = Number(raw);
      } else if (spec.type === "ListRequirement") {
        out[spec.name] = raw;
      } else {
        out[spec.name] = raw;
      }
    }
    return out;
  };

  const run = async () => {
    if (!evidence || !detail) return;
    setBusy(true);
    try {
      const j = await engineCall<Job>("plugins.execute", {
        evidence_id: evidence.id,
        plugin_id: detail.plugin.id,
        parameters: parseParams(),
      });
      setJob(j);
      onJobSubmitted?.(j);
    } catch (e) {
      onError(e instanceof EngineClientError ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  useEffect(() => {
    if (!job || (job.status !== "queued" && job.status !== "running")) return;
    const t = window.setInterval(() => {
      void (async () => {
        try {
          const j = await engineCall<Job>("jobs.get", { job_id: job.id });
          setJob(j);
          if (j.status === "completed" && j.result && typeof j.result === "object") {
            const execId =
              (j.result as { execution?: { id?: string } }).execution?.id ??
              (typeof j.analysis_run_id === "string" ? null : null);
            if ((j.result as PluginExecutionBundle).execution?.id) {
              setBundle(j.result as PluginExecutionBundle);
            } else if (execId) {
              const b = await engineCall<PluginExecutionBundle>("plugins.execution_get", {
                execution_id: execId,
              });
              setBundle(b);
            }
            void loadHistory();
          }
          if (j.status === "failed" || j.status === "cancelled") {
            void loadHistory();
          }
        } catch {
          /* ignore */
        }
      })();
    }, 1200);
    return () => window.clearInterval(t);
  }, [job, loadHistory]);

  const canRun =
    !!evidence &&
    !!detail?.plugin.available &&
    !!detail.runnable.runnable &&
    !busy &&
    job?.status !== "queued" &&
    job?.status !== "running";

  return (
    <div className="flex h-full min-h-0 text-xs">
      <div className="flex w-[22rem] shrink-0 flex-col border-r border-border">
        <div className="space-y-2 border-b border-border p-2">
          <div className="flex items-center gap-2">
            <div className="font-semibold">Plugin Explorer</div>
            <Badge>generic</Badge>
          </div>
          <div className="text-[11px] text-muted">
            Volatility {catalog?.volatility_version ?? "…"} · {catalog?.plugin_count ?? 0}{" "}
            plugins. Dedicated views (Processes, Memory) remain the guided workflow.
          </div>
          <Input
            placeholder="Search plugins"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
          <div className="flex gap-2">
            <select
              className="h-8 flex-1 rounded-md border border-border bg-surface px-2 text-xs"
              value={category}
              onChange={(e) => setCategory(e.target.value)}
            >
              <option value="all">All categories</option>
              {(catalog?.categories ?? []).map((c) => (
                <option key={c.id} value={c.id}>
                  {c.id} ({c.count})
                </option>
              ))}
            </select>
            <label className="flex items-center gap-1 text-[11px] text-muted">
              <input
                type="checkbox"
                checked={runnableOnly}
                onChange={(e) => setRunnableOnly(e.target.checked)}
              />
              Runnable
            </label>
          </div>
        </div>
        <div className="min-h-0 flex-1 overflow-auto">
          {items.map((p) => (
            <button
              key={p.id}
              type="button"
              onClick={() => void openPlugin(p.id)}
              className={`block w-full border-b border-border/40 px-2 py-1.5 text-left hover:bg-surface-2/60 ${
                selectedId === p.id ? "bg-surface-2" : ""
              }`}
            >
              <div className="flex items-center gap-1">
                <span className="truncate font-mono">{p.name}</span>
                <Badge className="ml-auto">{p.category}</Badge>
              </div>
              <div className="truncate text-[11px] text-muted">{p.description || p.id}</div>
              <div className="text-[10px] text-muted">
                {p.available ? (p.runnable ? "runnable" : "unsupported for evidence") : "unavailable"}
              </div>
            </button>
          ))}
          {items.length === 0 && (
            <div className="p-3 text-muted">No plugins match the current filter.</div>
          )}
        </div>
      </div>

      <div className="flex min-w-0 flex-1 flex-col">
        {!detail ? (
          <div className="p-4 text-muted">
            Select a Volatility 3 plugin. Image location and kernel/layer requirements are
            filled from the imported evidence — this is not a vol.py shell.
          </div>
        ) : (
          <>
            <div className="shrink-0 space-y-2 border-b border-border p-3">
              <div className="flex flex-wrap items-center gap-2">
                <div className="font-semibold font-mono">{detail.plugin.id}</div>
                <Badge>{detail.plugin.category}</Badge>
                <Badge
                  className={
                    detail.plugin.available
                      ? "border-success text-success"
                      : "border-danger text-danger"
                  }
                >
                  {detail.plugin.available ? "available" : "unavailable"}
                </Badge>
                <Badge>{detail.runnable.os_match}</Badge>
                {detail.plugin.version && <span className="text-muted">v{detail.plugin.version}</span>}
              </div>
              <div className="text-muted">{detail.plugin.description}</div>
              <div className="font-mono text-[11px] text-muted">{detail.plugin.module_path}</div>
              <div className="text-[11px] text-muted">
                Evidence: {evidence?.filename ?? "none"} · OS {evidence?.detected_os ?? "unknown"}
              </div>
              <div className="text-[11px] text-muted">{detail.runnable.reason}</div>
              {!!detail.plugin.discovery_errors?.length && (
                <div className="text-danger">{detail.plugin.discovery_errors.join("; ")}</div>
              )}

              <div className="grid grid-cols-2 gap-3 pt-1">
                <div>
                  <div className="mb-1 text-[10px] uppercase tracking-wide text-muted">
                    Configurable parameters
                  </div>
                  {(detail.plugin.configurable_parameters ?? []).length === 0 ? (
                    <div className="text-muted">None. Engine supplies framework requirements.</div>
                  ) : (
                    (detail.plugin.configurable_parameters ?? []).map((req) => (
                      <ParamField
                        key={req.name}
                        req={req}
                        value={params[req.name] ?? ""}
                        onChange={(v) => setParams((p) => ({ ...p, [req.name]: v }))}
                      />
                    ))
                  )}
                </div>
                <div>
                  <div className="mb-1 text-[10px] uppercase tracking-wide text-muted">
                    Framework requirements (engine)
                  </div>
                  <div className="max-h-40 overflow-auto rounded border border-border p-2">
                    {(detail.plugin.requirements ?? [])
                      .filter((r) => !r.configurable)
                      .map((r) => (
                        <div key={r.name} className="mb-1">
                          <span className="font-mono">{r.name}</span>{" "}
                          <span className="text-muted">{r.type}</span>
                          <div className="text-[11px] text-muted">{r.description}</div>
                        </div>
                      ))}
                  </div>
                </div>
              </div>

              <div className="flex items-center gap-2">
                <Button size="sm" disabled={!canRun} onClick={() => void run()}>
                  {busy || job?.status === "queued" || job?.status === "running"
                    ? job?.status || "Queuing…"
                    : "Run"}
                </Button>
                {job && <Badge className={jobStateClass(job.status)}>{job.status}</Badge>}
                {job?.message && <span className="text-muted">{job.message}</span>}
                {bundle?.execution.cache_hit && <Badge>cache hit</Badge>}
                {!evidence && <span className="text-muted">Import evidence to run.</span>}
              </div>
              {job?.status === "running" && (
                <div className="text-[11px] text-muted">
                  Cancellation is cooperative. Volatility plugin run() may finish the current
                  plugin before stopping.
                </div>
              )}
              {job?.status === "failed" && job.error && (
                <div className="text-danger">
                  {String(job.error.message ?? JSON.stringify(job.error))}
                </div>
              )}
            </div>

            <div className="flex min-h-0 flex-1 flex-col">
              <div className="flex items-center gap-2 border-b border-border px-3 py-1">
                <button
                  type="button"
                  className={tab === "table" ? "font-semibold" : "text-muted"}
                  onClick={() => setTab("table")}
                >
                  Results
                </button>
                <button
                  type="button"
                  className={tab === "raw" ? "font-semibold" : "text-muted"}
                  onClick={() => setTab("raw")}
                >
                  Raw / structured
                </button>
                <span className="ml-auto text-muted">
                  {bundle ? `${bundle.result.row_count} row(s)` : "No result yet"}
                </span>
              </div>
              <div className="min-h-0 flex-1 overflow-auto p-2">
                {!bundle ? (
                  <div className="text-muted">Run a plugin to populate the generic result table.</div>
                ) : tab === "table" ? (
                  <ResultTable bundle={bundle} onOpenProcess={onOpenProcess} />
                ) : (
                  <pre className="whitespace-pre-wrap font-mono text-[11px] text-muted">
                    {JSON.stringify(bundle.result.raw ?? bundle.result, null, 2)}
                  </pre>
                )}
              </div>
            </div>
          </>
        )}
        {history.length > 0 && (
          <div className="max-h-28 shrink-0 overflow-auto border-t border-border p-2">
            <div className="text-[10px] uppercase tracking-wide text-muted">Recent advanced executions</div>
            {history.map((h) => (
              <button
                key={h.id}
                type="button"
                className="mr-2 font-mono text-[11px] text-muted hover:text-foreground"
                onClick={() => {
                  void engineCall<PluginExecutionBundle>("plugins.execution_get", {
                    execution_id: h.id,
                  }).then(setBundle);
                }}
              >
                {h.plugin} {h.status}
                {h.cache_hit ? " (cache)" : ""}
              </button>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function ParamField({
  req,
  value,
  onChange,
}: {
  req: PluginRequirement;
  value: string;
  onChange: (v: string) => void;
}) {
  if (req.type === "BooleanRequirement") {
    return (
      <label className="mb-1 flex items-center gap-2">
        <input
          type="checkbox"
          checked={value === "true" || value === "1"}
          onChange={(e) => onChange(e.target.checked ? "true" : "false")}
        />
        <span className="font-mono">{req.name}</span>
        <span className="text-muted">{req.description}</span>
      </label>
    );
  }
  if (req.type === "ChoiceRequirement" && req.choices?.length) {
    return (
      <label className="mb-1 block">
        <div className="font-mono">{req.name}</div>
        <select
          className="h-8 w-full rounded-md border border-border bg-surface px-2"
          value={value}
          onChange={(e) => onChange(e.target.value)}
        >
          <option value="">(default)</option>
          {req.choices.map((c) => (
            <option key={c} value={c}>
              {c}
            </option>
          ))}
        </select>
      </label>
    );
  }
  return (
    <label className="mb-1 block">
      <div className="font-mono">
        {req.name}
        {req.optional ? "" : " *"}
      </div>
      <Input
        value={value}
        placeholder={req.description || req.type}
        onChange={(e) => onChange(e.target.value)}
      />
    </label>
  );
}

function ResultTable({
  bundle,
  onOpenProcess,
}: {
  bundle: PluginExecutionBundle;
  onOpenProcess?: (id: string) => void;
}) {
  const cols = bundle.result.columns ?? [];
  const links = new Map(
    (bundle.result.links ?? [])
      .filter((l) => l.kind === "process" && l.process_id && l.pid != null)
      .map((l) => [l.pid as number, l.process_id as string]),
  );
  return (
    <table className="w-full text-left">
      <thead className="sticky top-0 bg-surface-2 text-muted">
        <tr>
          {cols.map((c) => (
            <th key={c.name} className="px-2 py-1 font-medium">
              {c.name}
            </th>
          ))}
        </tr>
      </thead>
      <tbody>
        {bundle.result.rows.map((row, i) => (
          <tr key={i} className="border-t border-border/40">
            {cols.map((c) => {
              const val = row.values?.[c.name];
              const pid =
                c.name.toLowerCase() === "pid" && (typeof val === "number" || typeof val === "string")
                  ? Number(val)
                  : null;
              const procId = pid != null ? links.get(pid) : undefined;
              return (
                <td
                  key={c.name}
                  className="px-2 py-0.5 font-mono"
                  style={{ paddingLeft: 8 + (row.depth || 0) * 12 }}
                >
                  {procId && onOpenProcess ? (
                    <button
                      type="button"
                      className="text-accent underline"
                      onClick={() => onOpenProcess(procId)}
                    >
                      {formatCell(val)}
                    </button>
                  ) : (
                    formatCell(val)
                  )}
                </td>
              );
            })}
          </tr>
        ))}
        {bundle.result.rows.length === 0 && (
          <tr>
            <td colSpan={Math.max(cols.length, 1)} className="px-2 py-4 text-muted">
              Plugin completed with no rows.
            </td>
          </tr>
        )}
      </tbody>
    </table>
  );
}

function formatCell(val: unknown): string {
  if (val == null) return "—";
  if (typeof val === "object") return JSON.stringify(val);
  return String(val);
}

function jobStateClass(status: string): string {
  if (status === "failed") return "border-danger text-danger";
  if (status === "completed") return "border-success text-success";
  if (status === "running") return "border-accent text-accent";
  return "";
}
