import { useCallback, useEffect, useMemo, useState } from "react";
import { open } from "@tauri-apps/plugin-dialog";
import { engineCall, EngineClientError } from "../lib/api";
import { formatResultCell } from "../lib/datetime";
import { matchesFieldQuery } from "../lib/resultFilter";
import { useTableSort } from "../lib/tableSort";
import {
  coverageIsUpdating,
  coverageLiveKind,
  coverageResultCaption,
  coverageWasExecuted,
} from "../lib/analysisCoverage";
import type {
  CapabilityCoverage,
  Job,
  NetworkArtifact,
  NetworkConnection,
  PcapFlowResult,
  PcapReconstructionBundle,
} from "../lib/types";
import {
  CoverageEmptyState,
  ImportEvidenceState,
  ListLoadingState,
  coverageShowsEmptyPanel,
} from "./CoverageStatus";
import { ResultFilterBar } from "./ResultFilterBar";
import { SortableTh } from "./SortableTh";
import { Badge } from "./ui/badge";
import { Button } from "./ui/button";
import { SegmentedControl } from "./ui/segmented";
import { StatusToast, useStatusToast } from "./StatusToast";

type TabId = "connections" | "artifacts" | "pcap";

function PidCell({
  value,
  processId,
  onOpenProcess,
}: {
  value: string | number;
  processId?: string | null;
  onOpenProcess?: (processId: string) => void;
}) {
  const label = formatResultCell(value);
  if (processId && onOpenProcess) {
    return (
      <button
        type="button"
        className="text-accent hover:underline"
        onClick={() => onOpenProcess(processId)}
      >
        {label}
      </button>
    );
  }
  return <>{label}</>;
}

function sourceLabel(source: string | null | undefined): string {
  const raw = (source || "").trim();
  if (!raw) return "—";
  if (raw === "network_connections" || raw === "windows.netscan") return "Network connections";
  if (raw === "bulk_extractor" || raw.startsWith("provider.bulk_extractor")) return "Artifact extraction";
  if (raw === "floss_strings" || raw === "provider.floss") return "String analysis";
  if (raw === "processes.command_line") return "Command line";
  if (raw === "iocs") return "IOC extraction";
  return raw;
}

function methodLabel(method: string | null | undefined): string {
  const raw = (method || "").trim();
  if (!raw) return "—";
  if (raw === "volatility.netscan") return "Network connections";
  if (raw === "ioc_extract") return "IOC extraction";
  if (raw === "bulk_extractor") return "Artifact extraction";
  if (raw === "floss") return "String analysis";
  if (raw === "process_text") return "Command line";
  if (raw === "packet_carve") return "Packet carve";
  return raw.replace(/_/g, " ");
}

function typeLabel(value: string): string {
  return value.replace(/_/g, " ");
}

export function NetworkView({
  evidenceId,
  onError,
  coverage,
  artifactCoverage,
  refreshToken,
  onOpenProcess,
  onJobSubmitted,
  jobsRunning = false,
}: {
  evidenceId: string | null;
  onError: (m: string) => void;
  coverage?: CapabilityCoverage;
  artifactCoverage?: CapabilityCoverage;
  refreshToken?: number | string;
  onOpenProcess: (processId: string) => void;
  onJobSubmitted?: (job: Job) => void;
  jobsRunning?: boolean;
}) {
  const [tab, setTab] = useState<TabId>("connections");
  const [connections, setConnections] = useState<NetworkConnection[]>([]);
  const [artifacts, setArtifacts] = useState<NetworkArtifact[]>([]);
  const [typeCounts, setTypeCounts] = useState<Record<string, number>>({});
  const [pcap, setPcap] = useState<PcapReconstructionBundle | null>(null);
  const [importPcapPath, setImportPcapPath] = useState<string | null>(null);
  const [loadedEvidenceId, setLoadedEvidenceId] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [filter, setFilter] = useState("");
  const [filterField, setFilterField] = useState("all");
  const { toast, showToast } = useStatusToast();

  const load = useCallback(async () => {
    if (!evidenceId) {
      setConnections([]);
      setArtifacts([]);
      setPcap(null);
      setLoadedEvidenceId(null);
      return;
    }
    try {
      const [net, art, recon] = await Promise.all([
        engineCall<{ items: NetworkConnection[] }>("network.list", { evidence_id: evidenceId }),
        engineCall<{ items: NetworkArtifact[]; type_counts?: Record<string, number> }>(
          "network.artifacts",
          { evidence_id: evidenceId },
        ).catch(() => ({ items: [] as NetworkArtifact[], type_counts: {} })),
        engineCall<{ latest: PcapReconstructionBundle | null }>("pcap.reconstructions", {
          evidence_id: evidenceId,
        }).catch(() => ({ latest: null })),
      ]);
      setConnections(net.items);
      setArtifacts(art.items);
      setTypeCounts(art.type_counts ?? {});
      setPcap(recon.latest);
      setLoadedEvidenceId(evidenceId);
    } catch (e) {
      setConnections([]);
      setArtifacts([]);
      setPcap(null);
      setLoadedEvidenceId(evidenceId);
      onError(e instanceof EngineClientError ? e.message : String(e));
    }
  }, [evidenceId, onError]);

  useEffect(() => {
    void load();
  }, [load, refreshToken]);

  const flowByConnection = useMemo(() => {
    const map = new Map<string, PcapFlowResult>();
    for (const flow of pcap?.flows ?? []) {
      if (flow.connection_id) map.set(flow.connection_id, flow);
    }
    return map;
  }, [pcap]);

  const queue = async (method: string, params: Record<string, unknown>, ok: string) => {
    if (!evidenceId || busy || jobsRunning) return;
    setBusy(true);
    try {
      const job = await engineCall<Job>(method, params);
      onJobSubmitted?.(job);
      showToast(ok);
    } catch (e) {
      onError(e instanceof EngineClientError ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  const loading = Boolean(evidenceId) && loadedEvidenceId !== evidenceId;
  if (!evidenceId) return <ImportEvidenceState title="Network" />;
  if (loading && connections.length === 0 && coverageLiveKind(coverage) !== "in_progress") {
    return <ListLoadingState title="Network" />;
  }

  const recon = pcap?.reconstruction;
  const reconstructing =
    recon?.status === "running" || recon?.ui_state === "reconstructing" || recon?.status === "queued";
  const actionsLocked = busy || jobsRunning;

  return (
    <div className="flex h-full flex-col text-xs">
      <div className="flex flex-wrap items-center gap-2 border-b border-border px-3 py-2">
        <div className="text-sm font-semibold">Network</div>
        <SegmentedControl
          ariaLabel="Network sections"
          value={tab}
          onChange={setTab}
          options={[
            { id: "connections", label: "Connections" },
            { id: "artifacts", label: "Network Artifacts" },
            { id: "pcap", label: "PCAP Reconstruction" },
          ]}
        />
      </div>
      {tab === "connections" && (
        <ConnectionsPanel
          coverage={coverage}
          items={connections}
          flowByConnection={flowByConnection}
          filter={filter}
          filterField={filterField}
          onFilter={setFilter}
          onFilterField={setFilterField}
          onOpenProcess={onOpenProcess}
        />
      )}
      {tab === "artifacts" && (
        <ArtifactsPanel
          coverage={artifactCoverage}
          items={artifacts}
          typeCounts={typeCounts}
          filter={filter}
          filterField={filterField}
          onFilter={setFilter}
          onFilterField={setFilterField}
          onOpenProcess={onOpenProcess}
          onExtract={() =>
            void queue(
              "network.extract_artifacts",
              { evidence_id: evidenceId },
              "Network artifact extraction queued",
            )
          }
          extracting={actionsLocked}
        />
      )}
      {tab === "pcap" && (
        <PcapPanel
          bundle={pcap}
          reconstructing={reconstructing || actionsLocked}
          importPath={importPcapPath}
          onImportPathChange={setImportPcapPath}
          onReconstruct={() =>
            void queue(
              "pcap.reconstruct",
              {
                evidence_id: evidenceId,
                import_pcap_path: importPcapPath ?? undefined,
              },
              "PCAP reconstruction queued",
            )
          }
          onOpenProcess={onOpenProcess}
        />
      )}
      <StatusToast message={toast} />
    </div>
  );
}

function ConnectionsPanel({
  coverage,
  items,
  flowByConnection,
  filter,
  filterField,
  onFilter,
  onFilterField,
  onOpenProcess,
}: {
  coverage?: CapabilityCoverage;
  items: NetworkConnection[];
  flowByConnection: Map<string, PcapFlowResult>;
  filter: string;
  filterField: string;
  onFilter: (value: string) => void;
  onFilterField: (value: string) => void;
  onOpenProcess: (processId: string) => void;
}) {
  const filtered = useMemo(
    () =>
      items.filter((n) =>
        matchesFieldQuery(
          filter,
          filterField,
          {
            pid: n.pid,
            process: n.process_name,
            proto: n.protocol,
            local: `${n.local_address ?? ""}:${n.local_port ?? ""}`,
            remote: `${n.remote_address ?? ""}:${n.remote_port ?? ""}`,
            state: n.state,
            owner: n.owner,
          },
          [n.source_plugin, n.process_name],
        ),
      ),
    [items, filter, filterField],
  );
  if (coverageShowsEmptyPanel(coverage, items.length)) {
    return (
      <CoverageEmptyState
        item={coverage}
        title="Network Connections"
        inProgressDetail="Network connections are still being analyzed."
        analyzedZeroDetail="Network analysis completed and found no connections."
        notAnalyzedDetail="This capability was not included in the selected analysis mode."
        notAnalyzedHint="Run Complete Analysis or select Network Connections in Custom Analysis to analyze it."
        failedDetail="Network analysis failed."
      />
    );
  }
  const showPcap = flowByConnection.size > 0;
  const columns = showPcap
    ? ["PID", "Process", "Proto", "Local", "Remote", "State", "Owner", "Packets"]
    : ["PID", "Process", "Proto", "Local", "Remote", "State", "Owner"];
  const getValue = useCallback(
    (row: NetworkConnection, key: string) => {
      if (key === "PID") return row.pid ?? "";
      if (key === "Process") return row.process_name ?? "";
      if (key === "Proto") return row.protocol ?? "";
      if (key === "Local") return `${row.local_address ?? ""}:${row.local_port ?? ""}`;
      if (key === "Remote") return `${row.remote_address ?? ""}:${row.remote_port ?? ""}`;
      if (key === "State") return row.state ?? "";
      if (key === "Owner") return row.owner ?? "";
      if (key === "Packets") return flowByConnection.get(row.id)?.display_status ?? "";
      return "";
    },
    [flowByConnection],
  );
  const { sorted, sort, toggle } = useTableSort(filtered, getValue);
  return (
    <>
      <div className="flex items-center gap-2 border-b border-border px-3 py-2">
        <div className="text-xs text-muted">
          {coverageResultCaption(coverage, items.length, filtered.length)}
        </div>
        <ResultFilterBar
          query={filter}
          onQueryChange={onFilter}
          field={filterField}
          onFieldChange={onFilterField}
          placeholder="Filter address / port / protocol / PID…"
          fields={[
            { id: "pid", label: "PID" },
            { id: "process", label: "Process" },
            { id: "proto", label: "Proto" },
            { id: "local", label: "Local" },
            { id: "remote", label: "Remote" },
            { id: "state", label: "State" },
            { id: "owner", label: "Owner" },
          ]}
        />
      </div>
      {items.length === 0 ? (
        <div className="p-4 text-muted">0 results. Network analysis completed and found no connections.</div>
      ) : filtered.length === 0 ? (
        <div className="p-4 text-muted">No network connections match the current filter.</div>
      ) : (
        <div className="min-h-0 flex-1 overflow-auto">
          <table className="app-result-table w-full text-center">
            <thead className="sticky top-0 bg-surface-2 text-muted">
              <tr>
                {columns.map((c) => (
                  <SortableTh key={c} label={c} column={c} sort={sort} onToggle={toggle} />
                ))}
              </tr>
            </thead>
            <tbody>
              {sorted.map((n) => {
                const flow = flowByConnection.get(n.id);
                return (
                  <tr key={n.id} className="border-t border-border/40">
                    <td className="px-2 py-1 font-mono">
                      <PidCell value={n.pid ?? "—"} processId={n.process_id} onOpenProcess={onOpenProcess} />
                    </td>
                    <td className="max-w-[12rem] truncate px-2 py-1 font-mono">
                      {formatResultCell(n.process_name?.trim() || "—")}
                    </td>
                    <td className="px-2 py-1 font-mono">{formatResultCell(n.protocol ?? "—")}</td>
                    <td className="px-2 py-1 font-mono">
                      {formatResultCell(`${n.local_address ?? ""}:${n.local_port ?? ""}`)}
                    </td>
                    <td className="px-2 py-1 font-mono">
                      {formatResultCell(`${n.remote_address ?? ""}:${n.remote_port ?? ""}`)}
                    </td>
                    <td className="px-2 py-1 font-mono">{formatResultCell(n.state ?? "—")}</td>
                    <td className="max-w-[10rem] truncate px-2 py-1 font-mono">
                      {formatResultCell(n.owner ?? "—")}
                    </td>
                    {showPcap ? (
                      <td className="px-2 py-1">
                        {flow ? <Badge>{flow.display_status}</Badge> : "—"}
                      </td>
                    ) : null}
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </>
  );
}

function ArtifactsPanel({
  coverage,
  items,
  typeCounts,
  filter,
  filterField,
  onFilter,
  onFilterField,
  onOpenProcess,
  onExtract,
  extracting,
}: {
  coverage?: CapabilityCoverage;
  items: NetworkArtifact[];
  typeCounts: Record<string, number>;
  filter: string;
  filterField: string;
  onFilter: (value: string) => void;
  onFilterField: (value: string) => void;
  onOpenProcess: (processId: string) => void;
  onExtract: () => void;
  extracting: boolean;
}) {
  const filtered = useMemo(
    () =>
      items.filter((a) =>
        matchesFieldQuery(
          filter,
          filterField,
          {
            type: a.artifact_type,
            value: a.value,
            pid: a.pid,
            process: a.process_name,
            source: sourceLabel(a.source),
            method: methodLabel(a.extraction_method),
            offset: a.source_address || a.offset_hex,
          },
          [a.context, a.source_plugin],
        ),
      ),
    [items, filter, filterField],
  );
  const getValue = useCallback((row: NetworkArtifact, key: string) => {
    if (key === "Type") return row.artifact_type;
    if (key === "Value") return row.value;
    if (key === "PID") return row.pid ?? "";
    if (key === "Process") return row.process_name ?? "";
    if (key === "Source") return sourceLabel(row.source);
    if (key === "Method") return methodLabel(row.extraction_method);
    if (key === "Offset") return row.source_address || row.offset_hex || "";
    return "";
  }, []);
  const { sorted, sort, toggle } = useTableSort(filtered, getValue);
  const emptyCoverage = coverageShowsEmptyPanel(coverage, items.length) && items.length === 0;
  return (
    <>
      <div className="flex flex-wrap items-center gap-2 border-b border-border px-3 py-2">
        <div className="text-xs text-muted">
          {coverageResultCaption(coverage, items.length, filtered.length)}
        </div>
        <ResultFilterBar
          query={filter}
          onQueryChange={onFilter}
          field={filterField}
          onFieldChange={onFilterField}
          placeholder="Filter type / value / PID…"
          fields={[
            { id: "type", label: "Type" },
            { id: "value", label: "Value" },
            { id: "pid", label: "PID" },
            { id: "process", label: "Process" },
            { id: "source", label: "Source" },
            { id: "method", label: "Method" },
          ]}
        />
        {coverageWasExecuted(coverage) || coverageIsUpdating(coverage) ? null : (
          <Button size="sm" disabled={extracting} onClick={onExtract}>
            {extracting ? "Extracting…" : "Extract Network Artifacts"}
          </Button>
        )}
      </div>
      {Object.keys(typeCounts).length > 0 ? (
        <div className="flex flex-wrap gap-1 border-b border-border px-3 py-2">
          {Object.entries(typeCounts)
            .sort((a, b) => a[0].localeCompare(b[0]))
            .map(([type, count]) => (
              <Badge key={type}>
                {typeLabel(type)} {count}
              </Badge>
            ))}
        </div>
      ) : null}
      {emptyCoverage ? (
        <CoverageEmptyState
          item={coverage}
          title="Network Artifacts"
          inProgressDetail="Network artifacts are still being extracted."
          analyzedZeroDetail="Network artifact extraction completed and found no recoverable indicators."
          notAnalyzedDetail="This capability was not included in the selected analysis mode."
          notAnalyzedHint="Run Complete Analysis, select Network Artifact Extraction in Custom Analysis, or extract from this page."
          failedDetail="Network artifact extraction failed."
        />
      ) : items.length === 0 ? (
        <div className="p-4 text-muted">
          No network artifacts stored yet. Extract from analyzed connections, process text, and
          optional artifact-extraction results.
        </div>
      ) : filtered.length === 0 ? (
        <div className="p-4 text-muted">No network artifacts match the current filter.</div>
      ) : (
        <div className="min-h-0 flex-1 overflow-auto">
          <table className="app-result-table w-full text-center">
            <thead className="sticky top-0 bg-surface-2 text-muted">
              <tr>
                {["Type", "Value", "PID", "Process", "Source", "Method", "Offset"].map((c) => (
                  <SortableTh key={c} label={c} column={c} sort={sort} onToggle={toggle} />
                ))}
              </tr>
            </thead>
            <tbody>
              {sorted.map((a) => (
                <tr key={a.id} className="border-t border-border/40">
                  <td className="px-2 py-1 font-mono">{typeLabel(a.artifact_type)}</td>
                  <td className="max-w-[22rem] truncate px-2 py-1 font-mono" title={a.value}>
                    {a.value}
                  </td>
                  <td className="px-2 py-1 font-mono">
                    <PidCell value={a.pid ?? "—"} processId={a.process_id} onOpenProcess={onOpenProcess} />
                  </td>
                  <td className="max-w-[10rem] truncate px-2 py-1 font-mono">
                    {formatResultCell(a.process_name?.trim() || "—")}
                  </td>
                  <td className="px-2 py-1">{sourceLabel(a.source)}</td>
                  <td className="px-2 py-1">{methodLabel(a.extraction_method)}</td>
                  <td className="px-2 py-1 font-mono">
                    {formatResultCell(a.source_address || a.offset_hex || "—")}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </>
  );
}

function PcapPanel({
  bundle,
  reconstructing,
  importPath,
  onImportPathChange,
  onReconstruct,
  onOpenProcess,
}: {
  bundle: PcapReconstructionBundle | null;
  reconstructing: boolean;
  importPath: string | null;
  onImportPathChange: (path: string | null) => void;
  onReconstruct: () => void;
  onOpenProcess: (processId: string) => void;
}) {
  const recon = bundle?.reconstruction;
  const flows = bundle?.flows ?? [];
  const recoverable = flows.filter((f) => f.packet_count > 0);
  const status = recon?.display_status || "Not run";
  const importedCount = recon?.observed?.imported_pcap_packets ?? 0;
  const importedPath = recon?.observed?.imported_pcap_path ?? null;

  const pickImportFile = async () => {
    try {
      const selected = await open({
        multiple: false,
        title: "Import external PCAP",
        filters: [{ name: "PCAP capture", extensions: ["pcap"] }],
      });
      if (!selected || Array.isArray(selected)) return;
      onImportPathChange(selected);
    } catch {
      /* dialog unavailable (browser preview) or cancelled */
    }
  };

  return (
    <div className="min-h-0 flex-1 overflow-auto p-3 space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <Button size="sm" disabled={reconstructing} onClick={onReconstruct}>
          {reconstructing ? "Reconstructing…" : recon ? "Reconstruct again" : "Reconstruct PCAP"}
        </Button>
        <Badge>{reconstructing ? "Reconstructing…" : status}</Badge>
      </div>
      <div className="flex flex-wrap items-center gap-2">
        <Button size="sm" variant="outline" disabled={reconstructing} onClick={() => void pickImportFile()}>
          Import external PCAP…
        </Button>
        {importPath ? (
          <>
            <span className="break-all font-mono text-muted">{importPath}</span>
            <Button
              size="sm"
              variant="ghost"
              disabled={reconstructing}
              onClick={() => onImportPathChange(null)}
            >
              Clear
            </Button>
          </>
        ) : (
          <span className="text-muted">
            Optional: merge a capture you produced yourself (e.g. bulk_extractor packets.pcap).
          </span>
        )}
      </div>
      <p className="text-muted">
        PCAP reconstruction recovers packet-shaped records from the memory image. Connection
        metadata is not a packet capture. Missing bytes are never invented, and the original
        evidence file is not modified. An imported PCAP is read-only and is merged into the
        reconstructed capture.
      </p>
      {recon ? (
        <div className="grid gap-1 font-mono">
          <div>Packet records: {recon.packet_count}</div>
          <div>Truncated records: {recon.truncated_count}</div>
          <div>Ethernet frames: {recon.ethernet_count}</div>
          <div>Raw IP records: {recon.raw_ip_count}</div>
          {importedCount > 0 ? (
            <div>
              Imported from PCAP: {importedCount}
              {importedPath ? <span className="break-all text-muted"> ({importedPath})</span> : null}
            </div>
          ) : null}
          {recon.output_path ? <div className="break-all">Output: {recon.output_path}</div> : null}
          <div>PCAP is a separate file and is not embedded in reports.</div>
        </div>
      ) : (
        <div className="text-muted">No reconstruction has been run for this memory image.</div>
      )}
      {recon?.limitations?.length ? (
        <ul className="list-disc space-y-1 pl-4 text-muted">
          {recon.limitations.map((line) => (
            <li key={line}>{line}</li>
          ))}
        </ul>
      ) : null}
      {recoverable.length > 0 ? (
        <div>
          <div className="mb-1 font-semibold">Flows with recovered packets</div>
          <table className="app-result-table w-full text-center">
            <thead className="bg-surface-2 text-muted">
              <tr>
                {["PID", "Proto", "Local", "Remote", "Status", "Packets"].map((c) => (
                  <th key={c} className="px-2 py-1 font-medium">
                    {c}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {recoverable.map((flow) => (
                <tr key={flow.id} className="border-t border-border/40">
                  <td className="px-2 py-1 font-mono">
                    <PidCell
                      value={flow.pid ?? "—"}
                      processId={flow.process_id}
                      onOpenProcess={onOpenProcess}
                    />
                  </td>
                  <td className="px-2 py-1 font-mono">{flow.protocol ?? "—"}</td>
                  <td className="px-2 py-1 font-mono">
                    {`${flow.local_address ?? ""}:${flow.local_port ?? ""}`}
                  </td>
                  <td className="px-2 py-1 font-mono">
                    {`${flow.remote_address ?? ""}:${flow.remote_port ?? ""}`}
                  </td>
                  <td className="px-2 py-1">
                    <Badge>{flow.display_status}</Badge>
                  </td>
                  <td className="px-2 py-1 font-mono">{flow.packet_count}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {recoverable.some((f) => f.flow_pcap_path) ? (
            <div className="mt-2 break-all text-muted">
              Per-flow PCAPs were written next to the reconstructed capture when packets matched a
              connection.
            </div>
          ) : null}
        </div>
      ) : recon && recon.packet_count <= 0 ? (
        <div className="text-muted">No reconstructable traffic was found in this memory image.</div>
      ) : null}
    </div>
  );
}
