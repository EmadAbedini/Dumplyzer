import { useCallback, useEffect, useMemo, useState } from "react";
import { Check, ChevronLeft, Copy, SquareArrowOutUpRight } from "lucide-react";
import { engineCall, EngineClientError } from "../lib/api";
import { filterPluginItems } from "../lib/pluginExplorer";
import { formatPluginConsole, pluginCopyPayload } from "../lib/pluginOutput";
import { openPluginOutputWindow } from "../lib/pluginOutputWindow";
import { FILTER_FIELD_ALL, matchesFieldQuery } from "../lib/resultFilter";
import { TimestampText } from "../lib/datetime";
import { useTableSort } from "../lib/tableSort";
import { cn } from "../lib/utils";
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
import { SegmentedControl } from "./ui/segmented";
import { ClearableInput, Input } from "./ui/input";
import { SortableTh } from "./SortableTh";
import { ResultFilterBar } from "./ResultFilterBar";
import { ConsoleOutput, ResultTable } from "./PluginOutputViews";
import { RefreshButton, StatusToast, useStatusToast } from "./StatusToast";
import { PLUGIN_JOB_BUSY_HINT } from "./Sidebar";

export function PluginExplorerView({
  evidence,
  onError,
  onJobSubmitted,
  onOpenProcess,
  refreshToken,
  analysisBusy = false,
}: {
  evidence: Evidence | null;
  onError: (m: string) => void;
  onJobSubmitted?: (job: Job) => void;
  onOpenProcess?: (processId: string) => void;
  refreshToken?: number;
  analysisBusy?: boolean;
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
  const [tab, setTab] = useState<"table" | "console">("table");
  const [copied, setCopied] = useState(false);
  const { toast, showToast } = useStatusToast();

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

  const applyPluginDetail = (d: PluginDetail) => {
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
  };

  const closePlugin = () => {
    setSelectedId(null);
    setDetail(null);
    setBundle(null);
    setJob(null);
    setParams({});
  };

  const openPlugin = async (id: string) => {
    setSelectedId(id);
    setBundle(null);
    setJob(null);
    try {
      const d = await engineCall<PluginDetail>("plugins.get", {
        plugin_id: id,
        evidence_id: evidence?.id,
      });
      applyPluginDetail(d);
    } catch (e) {
      onError(e instanceof EngineClientError ? e.message : String(e));
    }
  };

  const openHistoryRun = async (item: PluginExecutionSummary) => {
    try {
      if (selectedId !== item.plugin) {
        setSelectedId(item.plugin);
        setJob(null);
        const d = await engineCall<PluginDetail>("plugins.get", {
          plugin_id: item.plugin,
          evidence_id: evidence?.id,
        });
        applyPluginDetail(d);
      }
      const b = await engineCall<PluginExecutionBundle>("plugins.execution_get", {
        execution_id: item.id,
      });
      setBundle(b);
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
    if (!evidence || !detail || analysisBusy) return;
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
    const poll = async () => {
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
    };
    const t = window.setInterval(() => void poll(), 1200);
    const onVisible = () => {
      if (document.visibilityState === "visible") void poll();
    };
    document.addEventListener("visibilitychange", onVisible);
    return () => {
      window.clearInterval(t);
      document.removeEventListener("visibilitychange", onVisible);
    };
  }, [job, loadHistory]);

  const pluginBusy =
    busy || job?.status === "queued" || job?.status === "running";
  const canRun =
    !!evidence &&
    !!detail?.plugin.available &&
    !!detail.runnable.runnable &&
    !pluginBusy &&
    !analysisBusy;

  const consoleText = useMemo(
    () => (bundle ? formatPluginConsole(bundle) : ""),
    [bundle],
  );

  useEffect(() => {
    setCopied(false);
  }, [tab, bundle?.execution.id]);

  const copyOutput = async () => {
    if (!bundle) return;
    const { text, label } = pluginCopyPayload(bundle, tab);
    if (!text.trim()) {
      showToast("Nothing to copy");
      return;
    }
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      showToast(label);
      window.setTimeout(() => setCopied(false), 1600);
    } catch {
      onError("Could not copy to the clipboard.");
    }
  };

  const openOutputWindow = async () => {
    if (!bundle) return;
    try {
      await openPluginOutputWindow({
        executionId: bundle.execution.id,
        pluginId: bundle.execution.plugin,
        view: tab,
      });
    } catch (e) {
      onError(e instanceof Error ? e.message : "Could not open output window.");
    }
  };

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
          <ClearableInput
            placeholder="Search plugins"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onClear={() => setQuery("")}
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
              className={`block w-full cursor-pointer border-b border-border/40 px-2 py-1.5 text-left hover:bg-surface-2/60 ${
                selectedId === p.id ? "bg-surface-2" : ""
              }`}
            >
              <div className="flex items-center gap-1">
                <span className="truncate font-mono">{p.name}</span>
                <Badge className="ml-auto">{p.category}</Badge>
              </div>
              <div className="truncate text-[11px] text-muted">{p.description || p.id}</div>
              <div className="mt-1.5 text-[10px] text-muted">
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
          <PluginHistoryPanel
            evidence={evidence}
            history={history}
            onOpen={(item) => void openHistoryRun(item)}
            onRefresh={loadHistory}
            showToast={showToast}
          />
        ) : (
          <>
            <div className="shrink-0 space-y-2 border-b border-border p-3">
              <div className="flex flex-wrap items-center gap-2">
                <Button
                  type="button"
                  size="sm"
                  variant="ghost"
                  className="-ml-1.5 gap-1 px-2"
                  onClick={closePlugin}
                >
                  <ChevronLeft size={16} aria-hidden />
                  Plugins
                </Button>
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
                  <div className="mb-[10px] text-[10px] uppercase tracking-wide text-muted">
                    Configurable parameters
                  </div>
                  {(detail.plugin.configurable_parameters ?? []).length === 0 ? (
                    <div className="text-muted">None. Engine supplies framework requirements.</div>
                  ) : (
                    <div className="space-y-3">
                      {(detail.plugin.configurable_parameters ?? []).map((req) => (
                        <ParamField
                          key={req.name}
                          req={req}
                          value={params[req.name] ?? ""}
                          onChange={(v) => setParams((p) => ({ ...p, [req.name]: v }))}
                        />
                      ))}
                    </div>
                  )}
                </div>
                <div>
                  <div className="mb-[10px] text-[10px] uppercase tracking-wide text-muted">
                    Framework requirements (engine)
                  </div>
                  <div className="max-h-40 overflow-auto rounded border border-border p-2">
                    {(detail.plugin.requirements ?? [])
                      .filter((r) => !r.configurable)
                      .map((r) => (
                        <div key={r.name} className="mb-2 last:mb-0">
                          <span className="font-mono">{r.name}</span>{" "}
                          <span className="text-muted">{r.type}</span>
                          {r.description ? (
                            <div className="mt-0.5 text-[11px] leading-4 text-muted">{r.description}</div>
                          ) : null}
                        </div>
                      ))}
                  </div>
                </div>
              </div>

              <div className="flex items-center gap-2">
                <span title={analysisBusy ? PLUGIN_JOB_BUSY_HINT : undefined} className="inline-flex">
                  <Button
                    size="sm"
                    type="button"
                    className="min-w-[7.5rem] px-6"
                    disabled={!canRun}
                    onClick={() => void run()}
                  >
                    {pluginBusy ? (job?.status === "queued" ? "Queued" : "Running…") : "Run Plugin"}
                  </Button>
                </span>
                {analysisBusy ? (
                  <span className="text-muted">{PLUGIN_JOB_BUSY_HINT}</span>
                ) : null}
                {job && !pluginBusy ? (
                  <Badge className={jobStateClass(job.status)}>{pluginStatusLabel(job.status)}</Badge>
                ) : null}
                {pluginBusy && detail ? (
                  <span className="truncate font-mono text-muted">{detail.plugin.id}</span>
                ) : null}
                {bundle?.execution.cache_hit && !pluginBusy && <Badge>cache hit</Badge>}
                {!evidence && <span className="text-muted">Import evidence to run.</span>}
              </div>
              {pluginBusy ? (
                <div className="text-[11px] text-muted">
                  This can take a while on large memory images.
                </div>
              ) : null}
              {job?.status === "failed" && job.error && (
                <div className="text-danger">
                  {typeof job.error.message === "string"
                    ? job.error.message
                    : "Plugin run failed."}
                </div>
              )}
            </div>

            <div className="flex min-h-0 flex-1 flex-col">
              <div className="flex items-center gap-2 border-b border-border px-3 py-1.5">
                <span className="text-[10px] uppercase tracking-wide text-muted">
                  View type
                </span>
                <SegmentedControl
                  ariaLabel="View type"
                  value={tab}
                  onChange={setTab}
                  options={[
                    { id: "table", label: "Table", title: "Sortable rows", buttonId: "plugin-output-table" },
                    { id: "console", label: "Console", title: "Terminal-style text", buttonId: "plugin-output-console" },
                  ]}
                />
                <span className="ml-auto text-muted">
                  {bundle
                    ? `${bundle.result.row_count} row${bundle.result.row_count === 1 ? "" : "s"}`
                    : "No result yet"}
                  {bundle?.result.truncated ? " · truncated" : ""}
                </span>
                <Button
                  type="button"
                  size="sm"
                  variant="outline"
                  className="gap-1.5"
                  disabled={!bundle}
                  aria-label="Open output in a new window"
                  title="Open output in a new window"
                  onClick={() => void openOutputWindow()}
                >
                  <SquareArrowOutUpRight size={14} aria-hidden />
                  Window
                </Button>
                <Button
                  type="button"
                  size="sm"
                  variant="outline"
                  className="gap-1.5"
                  disabled={!bundle}
                  aria-label={tab === "console" ? "Copy console output" : "Copy table"}
                  title={tab === "console" ? "Copy console output" : "Copy table as TSV"}
                  onClick={() => void copyOutput()}
                >
                  {copied ? <Check size={14} aria-hidden /> : <Copy size={14} aria-hidden />}
                  {copied ? "Copied" : "Copy"}
                </Button>
              </div>
              <div
                className={
                  tab === "console" && bundle
                    ? "flex min-h-0 flex-1 flex-col overflow-hidden p-2"
                    : "min-h-0 flex-1 overflow-auto p-2"
                }
                role="tabpanel"
                aria-labelledby={`plugin-output-${tab}`}
              >
                {!bundle ? (
                  <div className="p-2 text-muted">
                    {tab === "console"
                      ? "Run a plugin to see terminal-style text output."
                      : "Run a plugin to see sortable result rows."}
                  </div>
                ) : tab === "table" ? (
                  <ResultTable bundle={bundle} onOpenProcess={onOpenProcess} />
                ) : (
                  <ConsoleOutput text={consoleText} />
                )}
              </div>
            </div>
          </>
        )}
      </div>
      <StatusToast message={toast} />
    </div>
  );
}

const HISTORY_FILTER_FIELDS = [
  { id: "plugin", label: "Plugin" },
  { id: "category", label: "Category" },
  { id: "status", label: "Status" },
  { id: "rows", label: "Rows" },
];

function PluginHistoryPanel({
  evidence,
  history,
  onOpen,
  onRefresh,
  showToast,
}: {
  evidence: Evidence | null;
  history: PluginExecutionSummary[];
  onOpen: (item: PluginExecutionSummary) => void;
  onRefresh: () => void | Promise<void>;
  showToast: (message: string) => void;
}) {
  const [filter, setFilter] = useState("");
  const [filterField, setFilterField] = useState(FILTER_FIELD_ALL);

  const rows = useMemo(() => {
    return history.filter((item) => {
      const status = historyStatusLabel(item);
      return matchesFieldQuery(filter, filterField, {
        plugin: [item.plugin, pluginShortName(item.plugin)],
        category: pluginCategoryFromId(item.plugin),
        status,
        rows: item.row_count,
      });
    });
  }, [filter, filterField, history]);

  const getValue = useCallback((item: PluginExecutionSummary, key: string) => {
    if (key === "plugin") return pluginShortName(item.plugin);
    if (key === "category") return pluginCategoryFromId(item.plugin);
    if (key === "status") return historyStatusLabel(item);
    if (key === "rows") return item.row_count;
    if (key === "time") return item.finished_at ?? item.started_at ?? "";
    return "";
  }, []);
  const { sorted, sort, toggle } = useTableSort(rows, getValue);

  const emptyMessage = !evidence
    ? "Import a memory image to run plugins and see history here."
    : history.length === 0
      ? "No plugin runs yet. Choose a plugin from the list to start."
      : "No runs match the current filter.";
  const historyHint = evidence
    ? `${history.length} previous run${history.length === 1 ? "" : "s"} · click a row to open`
    : "Runs for the current evidence appear here";

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <div className="shrink-0 space-y-1 border-b border-border px-4 py-3">
        <div className="text-sm font-semibold">Plugin Explorer</div>
        <div className="text-[11px] text-muted">
          Select a Volatility 3 plugin. Image location and kernel/layer requirements are filled
          from the imported evidence.
        </div>
      </div>
      <div className="plugin-history-toolbar @container shrink-0 border-b border-border px-3 py-2">
        <div className="flex flex-col gap-2 @[40rem]:flex-row @[40rem]:items-center">
          <div className="min-w-0 @[40rem]:shrink-0">
            <div className="text-sm font-semibold">History</div>
            <div className="text-[11px] text-muted">
              {historyHint}
            </div>
          </div>
          <div className="flex min-w-0 w-full items-center gap-2 @[40rem]:min-w-0 @[40rem]:flex-1">
            <ResultFilterBar
              query={filter}
              onQueryChange={setFilter}
              field={filterField}
              onFieldChange={setFilterField}
              fields={HISTORY_FILTER_FIELDS}
              placeholder="Filter history…"
              className="ml-0 w-full min-w-0 max-w-none flex-1 basis-0"
            />
            <div className="shrink-0">
              <RefreshButton
                onRefresh={onRefresh}
                doneMessage="History updated"
                showToast={showToast}
                disabled={!evidence}
              />
            </div>
          </div>
        </div>
      </div>
      <div className="min-h-0 flex-1 overflow-x-hidden overflow-y-auto">
        <table className="app-result-table app-plugin-history-table w-full text-center">
          <colgroup>
            <col className="plugin-history-plugin" />
            <col className="plugin-history-category" />
            <col className="plugin-history-status" />
            <col className="plugin-history-rows" />
            <col className="plugin-history-time" />
          </colgroup>
          <thead className="sticky top-0 bg-surface-2 text-muted">
            <tr>
              <SortableTh label="Plugin" column="plugin" sort={sort} onToggle={toggle} />
              <SortableTh label="Category" column="category" sort={sort} onToggle={toggle} />
              <SortableTh label="Status" column="status" sort={sort} onToggle={toggle} />
              <SortableTh label="Rows" column="rows" sort={sort} onToggle={toggle} />
              <SortableTh label="Finished" column="time" sort={sort} onToggle={toggle} />
            </tr>
          </thead>
          <tbody>
            {sorted.map((item) => {
              const status = historyStatusLabel(item);
              return (
                <tr
                  key={item.id}
                  tabIndex={0}
                  className="cursor-pointer border-t border-border/40"
                  title={`Open ${item.plugin}`}
                  onClick={() => onOpen(item)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter" || e.key === " ") {
                      e.preventDefault();
                      onOpen(item);
                    }
                  }}
                >
                  <td className="px-2 py-2">
                    <div className="font-mono">{pluginShortName(item.plugin)}</div>
                    <div className="truncate text-[11px] text-muted" title={item.plugin}>
                      {item.plugin}
                    </div>
                  </td>
                  <td className="px-2 py-2 text-muted">{pluginCategoryFromId(item.plugin)}</td>
                  <td className="px-2 py-2">
                    <Badge
                      className={cn(
                        "plugin-history-status-badge",
                        item.cache_hit && item.status === "completed"
                          ? "border-accent text-accent"
                          : jobStateClass(item.status),
                      )}
                    >
                      {status}
                    </Badge>
                  </td>
                  <td className="px-2 py-2 tabular-nums text-muted">
                    {item.row_count == null ? "—" : item.row_count}
                  </td>
                  <td className="plugin-history-time-cell px-2 py-2 text-muted">
                    <TimestampText value={item.finished_at ?? item.started_at} />
                  </td>
                </tr>
              );
            })}
            {sorted.length === 0 && (
              <tr className="app-row-empty">
                <td colSpan={5} className="px-3 py-6 text-muted">
                  {emptyMessage}
                </td>
              </tr>
            )}
          </tbody>
        </table>
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
      <label className="flex items-start gap-2">
        <input
          className="mt-0.5"
          type="checkbox"
          checked={value === "true" || value === "1"}
          onChange={(e) => onChange(e.target.checked ? "true" : "false")}
        />
        <span>
          <span className="font-mono">{req.name}</span>
          {req.description ? (
            <span className="mt-0.5 block text-[11px] leading-4 text-muted">{req.description}</span>
          ) : null}
        </span>
      </label>
    );
  }
  if (req.type === "ChoiceRequirement" && req.choices?.length) {
    return (
      <label className="block space-y-1">
        <div className="font-mono">
          {req.name}
          {req.optional ? "" : " *"}
        </div>
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
        {req.description ? (
          <div className="text-[11px] leading-4 text-muted">{req.description}</div>
        ) : null}
      </label>
    );
  }
  return (
    <label className="block space-y-1">
      <div className="font-mono">
        {req.name}
        {req.optional ? "" : " *"}
      </div>
      <Input
        value={value}
        placeholder={req.type}
        onChange={(e) => onChange(e.target.value)}
      />
      {req.description ? (
        <div className="text-[11px] leading-4 text-muted">{req.description}</div>
      ) : null}
    </label>
  );
}

function pluginShortName(id: string): string {
  const parts = id.split(".").filter(Boolean);
  return parts[parts.length - 1] || id;
}

function pluginCategoryFromId(id: string): string {
  const parts = id.split(".").filter(Boolean);
  const pluginsAt = parts.indexOf("plugins");
  if (pluginsAt >= 0 && parts[pluginsAt + 1]) return parts[pluginsAt + 1];
  return parts.length > 1 ? parts[parts.length - 2] : "—";
}

function historyStatusLabel(item: PluginExecutionSummary): string {
  if (item.cache_hit && item.status === "completed") return "Cached";
  return pluginStatusLabel(item.status);
}

function jobStateClass(status: string): string {
  if (status === "failed") return "border-danger text-danger";
  if (status === "completed") return "border-success text-success";
  if (status === "running" || status === "queued") return "border-accent text-accent";
  return "";
}

function pluginStatusLabel(status: string): string {
  if (status === "queued") return "Queued";
  if (status === "running") return "Analysing";
  if (status === "completed") return "Completed";
  if (status === "failed") return "Failed";
  if (status === "cancelled" || status === "canceled") return "Cancelled";
  return status;
}
