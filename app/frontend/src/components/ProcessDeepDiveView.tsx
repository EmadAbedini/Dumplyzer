import { useCallback, useEffect, useState, type ReactNode } from "react";
import { ChevronLeft, Info } from "lucide-react";
import { engineCall, EngineClientError } from "../lib/api";
import { isActiveJobStatus } from "../lib/analysisOptions";
import { coverageItem, coverageWasExecuted, processScopedEmptyMessage } from "../lib/analysisCoverage";
import { sortFindings } from "../lib/findings";
import { TimestampText, formatResultCell } from "../lib/datetime";
import { matchesFieldQuery, type FilterFieldOption } from "../lib/resultFilter";
import { useTableSort } from "../lib/tableSort";
import type { AnalysisCoverage, Job, PcapFlowResult, ProcessDeepDive, ProcessRow } from "../lib/types";
import { CenteredLoading } from "./CoverageStatus";
import { FindingCard } from "./FindingCard";
import { Button } from "./ui/button";
import { ResultFilterBar } from "./ResultFilterBar";
import { SortableTh } from "./SortableTh";
import { RefreshButton, StatusToast, useStatusToast } from "./StatusToast";

type Props = {
  processId: string;
  evidenceId: string;
  onBack?: () => void;
  onOpenProcess: (processId: string) => void;
  onError: (msg: string) => void;
  onJobSubmitted?: (job: Job) => void;
  coverage?: AnalysisCoverage;
  refreshToken?: number | string;
};

type Tab =
  | "overview"
  | "cmdline"
  | "modules"
  | "network"
  | "handles"
  | "memory"
  | "findings"
  | "family";

const DIVE_FILTER_FIELDS: Partial<Record<Tab, FilterFieldOption[]>> = {
  modules: [
    { id: "name", label: "Name" },
    { id: "base", label: "Base" },
    { id: "size", label: "Size" },
    { id: "path", label: "Path" },
  ],
  network: [
    { id: "proto", label: "Proto" },
    { id: "local", label: "Local" },
    { id: "remote", label: "Remote" },
    { id: "state", label: "State" },
    { id: "created", label: "Created" },
  ],
  handles: [
    { id: "type", label: "Type" },
    { id: "value", label: "Value" },
    { id: "access", label: "Access" },
    { id: "name", label: "Name" },
  ],
  memory: [
    { id: "start", label: "Start" },
    { id: "end", label: "End" },
    { id: "protection", label: "Protection" },
    { id: "tag", label: "Tag" },
    { id: "private", label: "Private" },
    { id: "file", label: "File" },
  ],
  findings: [
    { id: "title", label: "Title" },
    { id: "severity", label: "Severity" },
    { id: "plugin", label: "Plugin" },
    { id: "evidence", label: "Evidence" },
  ],
};

const ANALYZE_HINT =
  "A more complete pass for this PID: fuller command line, modules, network, handles, and memory regions. Not part of Quick Triage or Complete Analysis.";

export function ProcessDeepDiveView({
  processId,
  evidenceId,
  onBack,
  onOpenProcess,
  onError,
  onJobSubmitted,
  coverage,
  refreshToken,
}: Props) {
  const [data, setData] = useState<ProcessDeepDive | null>(null);
  const [tab, setTab] = useState<Tab>("overview");
  const [busy, setBusy] = useState(false);
  const [job, setJob] = useState<Job | null>(null);
  const [filter, setFilter] = useState("");
  const [filterField, setFilterField] = useState("all");
  const [pcapFlows, setPcapFlows] = useState<PcapFlowResult[]>([]);
  const { toast, showToast } = useStatusToast();

  const reload = useCallback(async () => {
    const d = await engineCall<ProcessDeepDive>("process.get", {
      process_id: processId,
    });
    setData(d);
    try {
      const recon = await engineCall<{ latest: { flows?: PcapFlowResult[] } | null }>(
        "pcap.reconstructions",
        { evidence_id: evidenceId },
      );
      setPcapFlows(recon.latest?.flows ?? []);
    } catch {
      setPcapFlows([]);
    }
  }, [processId, evidenceId]);

  useEffect(() => {
    setJob(null);
  }, [processId]);

  useEffect(() => {
    void (async () => {
      try {
        await reload();
      } catch (err) {
        onError(err instanceof EngineClientError ? err.message : String(err));
      }
    })();
  }, [reload, refreshToken, onError]);

  useEffect(() => {
    if (!job || !isActiveJobStatus(job.status)) return;
    const poll = async () => {
      try {
        const got = await engineCall<Job>("jobs.get", { job_id: job.id });
        setJob(got);
        if (got.status === "completed") {
          await reload();
          showToast("Process analysis completed");
        } else if (got.status === "failed") {
          const msg =
            typeof got.error?.message === "string" ? got.error.message : "Process analysis failed";
          onError(msg);
        }
      } catch {
        /* ignore transient */
      }
    };
    const timer = window.setInterval(() => void poll(), 1000);
    const onVisible = () => {
      if (document.visibilityState === "visible") void poll();
    };
    document.addEventListener("visibilitychange", onVisible);
    return () => {
      window.clearInterval(timer);
      document.removeEventListener("visibilitychange", onVisible);
    };
  }, [job, onError, reload, showToast]);

  useEffect(() => {
    if (job) return;
    if (!data) return;
    const jobId = activeAnalysisJobId(data.analysis_runs);
    if (!jobId) return;
    let cancelled = false;
    void engineCall<Job>("jobs.get", { job_id: jobId })
      .then((got) => {
        if (!cancelled && isActiveJobStatus(got.status)) setJob(got);
      })
      .catch(() => undefined);
    return () => {
      cancelled = true;
    };
  }, [data, job]);

  const runRecommended = async () => {
    if (!data) return;
    setBusy(true);
    try {
      const submitted = await engineCall<Job>("process.analyze_recommended", {
        evidence_id: evidenceId,
        process_id: processId,
        pid: data.process.pid,
      });
      setJob(submitted);
      onJobSubmitted?.(submitted);
    } catch (err) {
      onError(err instanceof EngineClientError ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  if (!data) {
    return (
      <div className="flex h-full flex-col">
        <div className="border-b border-border px-3 py-2 text-sm font-semibold">Process</div>
        <CenteredLoading label="Loading process…" />
      </div>
    );
  }

  const p = data.process;
  const processKinds = data.analysis_runs.map((r) => ({
    kind: String(r.kind),
    status: String(r.status),
  }));
  const processRecommendedCompleted = processKinds.some(
    (r) => r.status === "completed" && r.kind === "process_recommended",
  );
  const processRecommendedFailed =
    !processRecommendedCompleted &&
    processKinds.some((r) => r.status === "failed" && r.kind === "process_recommended");
  const vadCompleted = processKinds.some(
    (r) => r.status === "completed" && (r.kind === "vad_scan" || r.kind === "process_recommended"),
  );
  const vadFailed =
    !vadCompleted && processKinds.some((r) => r.status === "failed" && r.kind === "vad_scan");
  const processRunActive = processKinds.some(
    (r) =>
      isActiveJobStatus(r.status) && (r.kind === "process_recommended" || r.kind === "vad_scan"),
  );
  const analysing = busy || processRunActive || (job != null && isActiveJobStatus(job.status));
  const showAnalyze = !processRecommendedCompleted || analysing;

  const tabAnalyzed = (id: string) => {
    const item = coverageItem(coverage, id);
    if (id === "memory_vad") return vadCompleted || coverageWasExecuted(item);
    return processRecommendedCompleted || coverageWasExecuted(item);
  };

  const tabCountLabel = (count: number | undefined, analyzed: boolean) => {
    if (count == null) return "";
    if (analyzed || count > 0) return ` (${count.toLocaleString()})`;
    return "";
  };

  const cmdlineCount = p.command_line && p.command_line.trim() ? 1 : 0;
  const tabs: { id: Tab; label: string; count?: number }[] = [
    { id: "overview", label: "Overview" },
    { id: "cmdline", label: "Command line", count: cmdlineCount },
    { id: "family", label: "Family", count: data.counts.children },
    { id: "modules", label: "Modules", count: data.counts.modules },
    { id: "network", label: "Network", count: data.counts.network },
    { id: "handles", label: "Handles", count: data.counts.handles },
    { id: "memory", label: "Memory", count: data.counts.memory_regions },
    { id: "findings", label: "Findings", count: data.counts.findings },
  ];
  const tabSuffix = (id: Tab, count: number | undefined) => {
    if (id === "cmdline") return tabCountLabel(count, tabAnalyzed("command_lines"));
    if (id === "family") return tabCountLabel(count, true);
    if (id === "modules") return tabCountLabel(count, tabAnalyzed("modules"));
    if (id === "network") return tabCountLabel(count, tabAnalyzed("network"));
    if (id === "handles") return tabCountLabel(count, tabAnalyzed("handles"));
    if (id === "memory") return tabCountLabel(count, tabAnalyzed("memory_vad"));
    if (id === "findings") return tabCountLabel(count, tabAnalyzed("findings"));
    return "";
  };
  const showFilter =
    tab === "modules" ||
    tab === "network" ||
    tab === "handles" ||
    tab === "memory" ||
    tab === "findings";

  const filteredFindings = sortFindings(
    data.findings.filter((f) =>
      matchesFieldQuery(filter, filterField, {
        title: f.finding_type,
        severity: f.severity,
        plugin: f.plugin,
        evidence: [f.explanation, f.field_name, f.field_value],
        pid: f.pid,
      }),
    ),
  );

  const emptyNotAnalyzed =
    "This was not collected in the last analysis. Run Complete Analysis, select this capability in Custom Analysis, or use Analyze process for this PID.";
  const emptyFailed = "Analysis failed.";

  return (
    <div className="flex h-full flex-col">
      <div className="flex flex-wrap items-center gap-2 border-b border-border px-3 py-2">
        {onBack ? (
          <Button
            type="button"
            size="sm"
            variant="outline"
            className="gap-1 bg-surface-2 px-2.5 text-foreground hover:bg-border"
            onClick={onBack}
          >
            <ChevronLeft size={16} aria-hidden />
            Processes
          </Button>
        ) : null}
        <div className="min-w-0">
          <div className="truncate text-sm font-semibold">{p.name ?? "Unnamed process"}</div>
          <div className="text-xs text-muted">
            PID {p.pid}
            {p.ppid != null ? ` · PPID ${p.ppid}` : ""}
          </div>
        </div>
        <div className="ml-auto flex gap-2">
          <RefreshButton
            onRefresh={reload}
            doneMessage="Process updated"
            showToast={showToast}
            disabled={analysing}
          />
          {showAnalyze ? (
            <span className="inline-flex" title={ANALYZE_HINT}>
              <Button size="sm" onClick={() => void runRecommended()} disabled={analysing}>
                {analysing ? "Analysing…" : "Analyze process"}
              </Button>
            </span>
          ) : null}
        </div>
      </div>
      {showAnalyze ? (
        <div className="flex items-start gap-2 border-b border-border bg-surface-2 px-3 py-2 text-xs text-muted">
          <Info size={14} className="mt-0.5 shrink-0 text-foreground" aria-hidden />
          <p>
            <span className="font-medium text-foreground">Analyze process</span> collects a more
            complete picture for this PID — fuller command line, modules, network, handles, and
            memory regions (VAD).
          </p>
        </div>
      ) : null}

      <div className="flex gap-1 overflow-x-auto border-b border-border px-2 py-1">
        {tabs.map((t) => (
          <button
            key={t.id}
            type="button"
            onClick={() => {
              setTab(t.id);
              setFilter("");
              setFilterField("all");
            }}
            className={
              "cursor-pointer rounded-md px-2 py-1 text-xs " +
              (tab === t.id ? "bg-surface-2 text-foreground" : "text-muted hover:bg-surface-2/60")
            }
          >
            {t.label}
            {tabSuffix(t.id, t.count)}
          </button>
        ))}
      </div>

      {showFilter ? (
        <div className="flex items-center border-b border-border px-3 py-2">
          <ResultFilterBar
            className="ml-0 w-full min-w-0 max-w-none flex-1"
            query={filter}
            onQueryChange={setFilter}
            field={filterField}
            onFieldChange={setFilterField}
            placeholder="Filter this list…"
            fields={DIVE_FILTER_FIELDS[tab] ?? []}
          />
        </div>
      ) : null}

      <div className="min-h-0 flex-1 overflow-auto p-3 text-xs">
        {tab === "overview" && (
          <>
            <table className="w-full border-collapse text-xs">
              <tbody>
                <KV k="PID" v={p.pid} />
                <KV
                  k="PPID"
                  v={
                    data.parent ? (
                      <ProcessLink process={data.parent} onOpen={onOpenProcess} />
                    ) : (
                      p.ppid
                    )
                  }
                />
                <KV k="Name" v={p.name} />
                <KV k="Username" v={p.username} />
                <KV k="Image path" v={p.image_path} />
                <KV k="Create time" v={<TimestampText value={p.create_time} />} />
                <KV k="Exit time" v={<TimestampText value={p.exit_time} />} />
                <KV k="Threads" v={p.threads} />
                <KV k="Handles" v={p.handles} />
                <KV k="Session" v={p.session_id} />
                <KV k="Wow64" v={p.wow64 == null ? null : p.wow64 ? "yes" : "no"} />
                <KV k="Offset" v={p.offset_hex} />
              </tbody>
            </table>
            {analysing ? (
              <div className="pt-3 text-muted">Process analysis is running…</div>
            ) : processRecommendedCompleted ? (
              <div className="pt-3 text-muted">Process analysis completed for this PID.</div>
            ) : processRecommendedFailed ? (
              <div className="pt-3 text-muted">Process analysis failed. You can try Analyze process again.</div>
            ) : null}
          </>
        )}

        {tab === "cmdline" &&
          (p.command_line ? (
            <CommandLineBlock value={p.command_line} />
          ) : (
            <div className="text-muted">
              {processScopedEmptyMessage(
                coverageItem(coverage, "command_lines"),
                processRecommendedCompleted,
                "No command line was stored for this process.",
                emptyNotAnalyzed,
                emptyFailed,
                processRecommendedFailed,
              )}
            </div>
          ))}

        {tab === "family" && (
          <div className="space-y-4">
            <div>
              <div className="mb-1 text-[11px] uppercase tracking-wide text-muted">Parent</div>
              {data.parent ? (
                <ProcessLink process={data.parent} onOpen={onOpenProcess} />
              ) : (
                <span className="text-muted">None in the process list</span>
              )}
            </div>
            <div>
              <div className="mb-1 text-[11px] uppercase tracking-wide text-muted">
                Children{data.children.length ? ` (${data.children.length})` : ""}
              </div>
              {data.children.length === 0 ? (
                <span className="text-muted">None</span>
              ) : (
                <ul className="space-y-1">
                  {data.children.map((c) => (
                    <li key={c.id}>
                      <ProcessLink process={c} onOpen={onOpenProcess} />
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </div>
        )}

        {tab === "modules" && (
          <EntityTable
            empty={processScopedEmptyMessage(
              coverageItem(coverage, "modules"),
              processRecommendedCompleted,
              "No modules were found for this process.",
              emptyNotAnalyzed,
              emptyFailed,
              processRecommendedFailed,
            )}
            columns={["Name", "Base", "Size", "Path"]}
            rows={data.modules
              .filter((m) =>
                matchesFieldQuery(
                  filter,
                  filterField,
                  {
                    name: m.name,
                    base: m.base_address,
                    size: m.size,
                    path: m.path,
                  },
                  [m.pid],
                ),
              )
              .map((m) => [m.name ?? "—", m.base_address ?? "—", m.size ?? "—", m.path ?? "—"])}
            emptyFilter="No modules match the current filter."
            hasSource={data.modules.length > 0}
          />
        )}

        {tab === "network" && (
          <EntityTable
            empty={processScopedEmptyMessage(
              coverageItem(coverage, "network"),
              processRecommendedCompleted,
              "No network connections were found for this process.",
              emptyNotAnalyzed,
              emptyFailed,
              processRecommendedFailed,
            )}
            columns={
              pcapFlows.length
                ? ["Proto", "Local", "Remote", "State", "Created", "Packets"]
                : ["Proto", "Local", "Remote", "State", "Created"]
            }
            rows={data.network
              .filter((n) =>
                matchesFieldQuery(filter, filterField, {
                  proto: n.protocol,
                  local: `${n.local_address ?? ""}:${n.local_port ?? ""}`,
                  remote: `${n.remote_address ?? ""}:${n.remote_port ?? ""}`,
                  state: n.state,
                  created: n.created,
                }),
              )
              .map((n) => {
                const flow = pcapFlows.find((f) => f.connection_id === n.id);
                const base = [
                  n.protocol ?? "—",
                  `${n.local_address ?? ""}:${n.local_port ?? ""}`,
                  `${n.remote_address ?? ""}:${n.remote_port ?? ""}`,
                  n.state ?? "—",
                  n.created ?? "—",
                ];
                if (pcapFlows.length) base.push(flow?.display_status || "Metadata only");
                return base;
              })}
            emptyFilter="No network connections match the current filter."
            hasSource={data.network.length > 0}
          />
        )}

        {tab === "handles" && (
          <EntityTable
            empty={processScopedEmptyMessage(
              coverageItem(coverage, "handles"),
              processRecommendedCompleted,
              "No handles were found for this process.",
              emptyNotAnalyzed,
              emptyFailed,
              processRecommendedFailed,
            )}
            columns={["Type", "Value", "Access", "Name"]}
            rows={data.handles
              .filter((h) =>
                matchesFieldQuery(
                  filter,
                  filterField,
                  {
                    type: h.handle_type,
                    value: h.handle_value,
                    access: h.granted_access,
                    name: h.name,
                  },
                  [h.pid],
                ),
              )
              .map((h) => [
                h.handle_type ?? "—",
                h.handle_value ?? "—",
                h.granted_access ?? "—",
                h.name ?? "—",
              ])}
            emptyFilter="No handles match the current filter."
            hasSource={data.handles.length > 0}
          />
        )}

        {tab === "memory" && (
          <EntityTable
            empty={processScopedEmptyMessage(
              coverageItem(coverage, "memory_vad"),
              vadCompleted,
              "No memory regions were found for this process.",
              "Memory regions are collected per process. Use Analyze process.",
              emptyFailed,
              vadFailed,
            )}
            columns={["Start", "End", "Protection", "Tag", "Private", "File"]}
            rows={data.memory_regions
              .filter((r) =>
                matchesFieldQuery(filter, filterField, {
                  start: r.start_vpn,
                  end: r.end_vpn,
                  protection: r.protection,
                  tag: r.tag,
                  private: r.private_memory,
                  file: r.file_path,
                }),
              )
              .map((r) => [
                r.start_vpn ?? "—",
                r.end_vpn ?? "—",
                r.protection ?? "—",
                r.tag ?? "—",
                r.private_memory ?? "—",
                r.file_path ?? "—",
              ])}
            emptyFilter="No memory regions match the current filter."
            hasSource={data.memory_regions.length > 0}
          />
        )}

        {tab === "findings" && (
          <div className="space-y-2">
            {data.findings.length === 0 ? (
              <div className="text-muted">
                {processScopedEmptyMessage(
                  coverageItem(coverage, "findings"),
                  processRecommendedCompleted,
                  "No findings were produced for this process.",
                  emptyNotAnalyzed,
                  emptyFailed,
                  processRecommendedFailed,
                )}
              </div>
            ) : filteredFindings.length === 0 ? (
              <div className="text-muted">No findings match the current filter.</div>
            ) : (
              filteredFindings.map((f) => (
                <FindingCard key={f.id} finding={f} onOpenProcess={onOpenProcess} />
              ))
            )}
          </div>
        )}
      </div>
      <StatusToast message={toast} />
    </div>
  );
}

function activeAnalysisJobId(runs: Array<Record<string, unknown>>): string | null {
  for (const run of runs) {
    const kind = String(run.kind ?? "");
    const status = String(run.status ?? "");
    if (
      (kind === "process_recommended" || kind === "vad_scan") &&
      isActiveJobStatus(status) &&
      typeof run.job_id === "string" &&
      run.job_id
    ) {
      return run.job_id;
    }
  }
  return null;
}

function ProcessLink({
  process,
  onOpen,
}: {
  process: ProcessRow;
  onOpen: (id: string) => void;
}) {
  return (
    <button
      type="button"
      className="inline border-0 bg-transparent p-0 align-middle font-mono text-accent hover:underline"
      onClick={() => onOpen(process.id)}
    >
      {process.name ?? "?"} ({process.pid})
    </button>
  );
}

function CommandLineBlock({ value }: { value: string }) {
  return (
    <pre className="cmdline-box" tabIndex={0} role="region" aria-label="Command line">
      {highlightCommandLine(value)}
    </pre>
  );
}

const CMDLINE_REST =
  /("[^"]*")|((?:--?[A-Za-z?][\w-]*)|(?:\/[A-Za-z][\w-]*))|((?:[A-Za-z]:\\|\\\\|%)[^\s"]+)|(\b\d+\b)/g;

function highlightCommandLine(text: string): ReactNode {
  const first = text.match(/^(\s*)("[^"]*"|[^\s]+)/);
  if (!first) return text;
  const prefix = first[1] ?? "";
  const exe = first[2] ?? "";
  const rest = text.slice(first[0].length);
  const nodes: ReactNode[] = [];
  if (prefix) nodes.push(prefix);
  nodes.push(
    <span key="exe" className="cmdline-exe">
      {exe}
    </span>,
  );
  let last = 0;
  let key = 0;
  const re = new RegExp(CMDLINE_REST.source, "g");
  let match: RegExpExecArray | null;
  while ((match = re.exec(rest))) {
    if (match.index > last) nodes.push(rest.slice(last, match.index));
    const [all, quoted, flag, path, num] = match;
    const cls = quoted
      ? "cmdline-string"
      : flag
        ? "cmdline-flag"
        : path
          ? "cmdline-path"
          : num
            ? "cmdline-num"
            : undefined;
    nodes.push(
      <span key={key++} className={cls}>
        {all}
      </span>,
    );
    last = match.index + all.length;
  }
  if (last < rest.length) nodes.push(rest.slice(last));
  return nodes;
}

function KV({ k, v }: { k: string; v: ReactNode }) {
  return (
    <tr className="border-b border-border/50">
      <th className="w-36 py-2 pr-3 text-left align-middle font-normal text-muted">{k}</th>
      <td className="py-2 align-middle break-all font-mono leading-snug">
        {v == null || v === "" ? "—" : v}
      </td>
    </tr>
  );
}

function EntityTable({
  columns,
  rows,
  empty,
  emptyFilter,
  hasSource,
}: {
  columns: string[];
  rows: (string | number)[][];
  empty: string;
  emptyFilter?: string;
  hasSource?: boolean;
}) {
  const getValue = useCallback(
    (row: (string | number)[], key: string) => row[columns.indexOf(key)],
    [columns],
  );
  const { sorted, sort, toggle } = useTableSort(rows, getValue);
  if (rows.length === 0) {
    return (
      <div className="text-muted">
        {hasSource ? emptyFilter || "No results match the current filter." : empty}
      </div>
    );
  }
  return (
    <table className="app-result-table w-full border-collapse text-center">
      <thead className="sticky top-0 bg-surface-2 text-muted">
        <tr>
          {columns.map((c) => (
            <SortableTh key={c} label={c} column={c} sort={sort} onToggle={toggle} className="px-2 py-1" />
          ))}
        </tr>
      </thead>
      <tbody>
        {sorted.map((r, i) => (
          <tr key={i} className="border-t border-border/40">
            {r.map((cell, j) => (
              <td key={j} className="max-w-[20rem] truncate px-2 py-1 font-mono">
                {formatResultCell(cell)}
              </td>
            ))}
          </tr>
        ))}
      </tbody>
    </table>
  );
}
