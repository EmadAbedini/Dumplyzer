import { useCallback, useEffect, useMemo, useState } from "react";
import { ShieldAlert } from "lucide-react";
import { engineCall, EngineClientError, openLocalFolder } from "../lib/api";
import { CAPABILITY, UNAVAILABLE_DETAIL } from "../lib/analysisCapabilities";
import { useCapabilityStatus } from "../lib/capabilityStatus";
import { coverageIsUpdating, coverageLiveKind, coverageResultCaption } from "../lib/analysisCoverage";
import { CoverageEmptyState, CenteredLoading, ImportEvidenceState } from "./CoverageStatus";
import { TimestampText } from "../lib/datetime";
import { matchesFieldQuery } from "../lib/resultFilter";
import { useTableSort } from "../lib/tableSort";
import { cn } from "../lib/utils";
import type {
  Artifact,
  BulkExtractorScanBundle,
  CapaScanBundle,
  CapabilityCoverage,
  FlossScanBundle,
  Job,
  PeExtractionBundle,
  YaraScanBundle,
} from "../lib/types";
import { Badge } from "./ui/badge";
import { Button } from "./ui/button";
import { SortableTh } from "./SortableTh";
import { ResultFilterBar } from "./ResultFilterBar";
import { SegmentedControl } from "./ui/segmented";
import { BulkExtractorResults } from "./BulkExtractorResults";

function artifactScanError(error: Record<string, unknown> | null | undefined): string {
  if (!error) return "Analysis failed.";
  const message = typeof error.message === "string" ? error.message.trim() : "";
  const suggestion = typeof error.suggestion === "string" ? error.suggestion.trim() : "";
  if (!message && !suggestion) return "Analysis failed.";
  if (message && suggestion && !message.includes(suggestion)) return `${message} ${suggestion}`;
  return message || suggestion;
}

type ArtifactAction = "pe" | "extraction" | "yara" | "capa" | "floss";
type DiskWriteAction = "pe" | "extraction";

function actionButtonLabel(
  idle: string,
  action: ArtifactAction,
  submitting: ArtifactAction | null,
  activeJobKind: string | null,
  locked: boolean,
): string {
  if (submitting === action) return "Starting…";
  if (action === "pe" && activeJobKind === "pe_extraction") return "Running…";
  if (action === "extraction" && activeJobKind === "bulk_extractor_scan") return "Running…";
  if (action === "yara" && activeJobKind === "yara_artifact_scan") return "Running…";
  if (action === "capa" && activeJobKind === "capa_artifact") return "Running…";
  if (action === "floss" && activeJobKind === "floss_artifact") return "Running…";
  if (submitting || locked) return "Busy";
  return idle;
}

export function ArtifactsView({
  evidenceId,
  onError,
  onJobSubmitted,
  refreshToken,
  coverage,
  jobsRunning = false,
  activeJobKind = null,
}: {
  evidenceId: string | null;
  onError: (m: string) => void;
  onJobSubmitted?: (job: Job) => void;
  refreshToken?: number | string;
  coverage?: CapabilityCoverage;
  jobsRunning?: boolean;
  activeJobKind?: string | null;
}) {
  const caps = useCapabilityStatus();
  const [items, setItems] = useState<Artifact[]>([]);
  const [loadedEvidenceId, setLoadedEvidenceId] = useState<string | null>(null);
  const [detail, setDetail] = useState<Artifact | null>(null);
  const [peOnly, setPeOnly] = useState(false);
  const [filter, setFilter] = useState("");
  const [filterField, setFilterField] = useState("all");
  const [yaraBundles, setYaraBundles] = useState<YaraScanBundle[]>([]);
  const [capaBundles, setCapaBundles] = useState<CapaScanBundle[]>([]);
  const [flossBundles, setFlossBundles] = useState<FlossScanBundle[]>([]);
  const [peBundles, setPeBundles] = useState<PeExtractionBundle[]>([]);
  const [bulkExtractorBundles, setBulkExtractorBundles] = useState<BulkExtractorScanBundle[]>(
    [],
  );
  const [busy, setBusy] = useState(false);
  const [submitting, setSubmitting] = useState<ArtifactAction | null>(null);
  const [pane, setPane] = useState<"pe" | "extraction">("extraction");
  const [confirmAction, setConfirmAction] = useState<DiskWriteAction | null>(null);
  const yaraStatus = caps.yara;
  const capaStatus = caps.capa;
  const flossStatus = caps.floss;
  const peStatus = caps.peExtraction;
  const bulkExtractorStatus = caps.bulkExtractor;

  const load = useCallback(async () => {
    if (!evidenceId) return;
    try {
      const res = await engineCall<{ items: Artifact[] }>("artifacts.list", {
        evidence_id: evidenceId,
      });
      setItems(res.items);
      setLoadedEvidenceId(evidenceId);
      try {
        const runs = await engineCall<{ items: PeExtractionBundle[] }>("pe_extraction.runs", {
          evidence_id: evidenceId,
        });
        setPeBundles(runs.items ?? []);
      } catch {
        /* optional */
      }
      try {
        const scans = await engineCall<{ items: BulkExtractorScanBundle[] }>(
          "bulk_extractor.scans",
          { evidence_id: evidenceId },
        );
        setBulkExtractorBundles(scans.items ?? []);
      } catch {
        /* optional */
      }
    } catch (e) {
      setItems([]);
      setLoadedEvidenceId(evidenceId);
      onError(e instanceof EngineClientError ? e.message : String(e));
    }
  }, [evidenceId, onError]);

  useEffect(() => {
    void load();
  }, [load, refreshToken]);

  useEffect(() => {
    if (!confirmAction) return;
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") setConfirmAction(null);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [confirmAction]);

  const visible = useMemo(() => {
    const peFiltered = peOnly
      ? items.filter(
          (a) =>
            a.file_type === "pe" ||
            (a.extraction_method || "").includes("pedump") ||
            (a.extraction_method || "").includes("dumpfiles.pe") ||
            a.metadata?.label === "extracted_pe_artifact",
        )
      : items;
    return peFiltered.filter((a) =>
      matchesFieldQuery(
        filter,
        filterField,
        {
          filename: a.filename,
          kind: a.metadata?.pe_kind || a.file_type,
          sha256: a.sha256,
          size: a.size_bytes,
          pid: a.pid,
          method: a.extraction_method,
          extracted: a.extracted_at,
        },
        [a.source_plugin, a.tool_name],
      ),
    );
  }, [items, peOnly, filter, filterField]);

  const artifactSortValue = useCallback((a: Artifact, key: string) => {
    if (key === "filename") return a.filename ?? "";
    if (key === "kind") return String(a.metadata?.pe_kind || a.file_type || "");
    if (key === "sha256") return a.sha256 ?? "";
    if (key === "size") return a.size_bytes;
    if (key === "pid") return a.pid;
    if (key === "method") return a.extraction_method ?? "";
    if (key === "extracted") return a.extracted_at ?? "";
    return "";
  }, []);
  const { sorted, sort, toggle } = useTableSort(visible, artifactSortValue);

  const openDetail = async (id: string) => {
    try {
      const a = await engineCall<Artifact>("artifacts.get", { artifact_id: id });
      setDetail(a);
      setYaraBundles(a.yara_scans ?? []);
      setCapaBundles(a.capa_scans ?? []);
      setFlossBundles(a.floss_scans ?? []);
    } catch (e) {
      onError(e instanceof EngineClientError ? e.message : String(e));
    }
  };

  const queue = async (method: string, params: Record<string, unknown>, action?: ArtifactAction) => {
    if (jobsRunning || coverageIsUpdating(coverage) || busy) return;
    setBusy(true);
    if (action) setSubmitting(action);
    try {
      const job = await engineCall<Job>(method, params);
      onJobSubmitted?.(job);
    } catch (e) {
      onError(e instanceof EngineClientError ? e.message : String(e));
    } finally {
      setBusy(false);
      setSubmitting(null);
    }
  };

  const browseCarved = async (outputDir: string | null | undefined) => {
    if (!outputDir) {
      onError("Carved artifacts folder is not available yet.");
      return;
    }
    try {
      await openLocalFolder(outputDir);
    } catch (e) {
      onError(e instanceof EngineClientError ? e.message : String(e));
    }
  };

  if (!evidenceId) {
    return <ImportEvidenceState title="Carved Data" />;
  }

  const loading = loadedEvidenceId !== evidenceId;
  const latestPe = peBundles[0]?.run;
  const latestBe = bulkExtractorBundles[0];
  const extractedCount = latestPe?.extracted_count ?? visible.filter((a) => a.file_type === "pe").length;
  const actionsLocked = busy || jobsRunning || coverageIsUpdating(coverage);
  const peAvailable = Boolean(peStatus?.available);
  const extractionAvailable = Boolean(bulkExtractorStatus?.available);
  const carvedOutputDir =
    latestBe?.scan.status === "completed" ? latestBe.scan.output_dir : null;
  const peLiveKind = coverageLiveKind(coverage);
  const peCaption = coverageResultCaption(coverage, items.length, visible.length);

  const requestDiskWrite = (action: DiskWriteAction) => {
    if (actionsLocked) return;
    if (action === "pe" && !peAvailable) return;
    if (action === "extraction" && !extractionAvailable) return;
    setConfirmAction(action);
  };

  const confirmDiskWrite = () => {
    const action = confirmAction;
    setConfirmAction(null);
    if (!action || !evidenceId) return;
    if (action === "pe") {
      void queue("pe_extraction.run", { evidence_id: evidenceId }, "pe");
      return;
    }
    setPane("extraction");
    void queue("bulk_extractor.scan", { evidence_id: evidenceId }, "extraction");
  };

  return (
    <div className="flex h-full min-h-0 flex-1 flex-col text-xs">
      <div className="flex shrink-0 flex-wrap items-center gap-2 border-b border-border px-3 py-2">
        <div className="text-sm font-semibold">Carved Data</div>
        <SegmentedControl
          ariaLabel="Artifact sections"
          value={pane}
          onChange={setPane}
          options={[
            { id: "extraction", label: "Carved Artifacts" },
            { id: "pe", label: "Extracted Files" },
          ]}
        />
      </div>

      {pane === "extraction" ? (
        <div className="flex min-h-0 min-w-0 flex-1 flex-col overflow-hidden">
          <div className="shrink-0 border-b border-border px-3 py-2">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <p className="text-sm leading-5 text-muted">
                Email, phone numbers, AES keys, URLs, shortcuts, and other recoverable data
                carved from the memory image.
              </p>
              <div className="flex shrink-0 flex-wrap items-center gap-2">
                {carvedOutputDir ? (
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => void browseCarved(carvedOutputDir)}
                  >
                    Browse carved artifacts
                  </Button>
                ) : null}
                <Button
                  size="sm"
                  disabled={actionsLocked || !extractionAvailable}
                  onClick={() => requestDiskWrite("extraction")}
                >
                  {actionButtonLabel(
                    "Carve Artifacts",
                    "extraction",
                    submitting,
                    activeJobKind,
                    actionsLocked,
                  )}
                </Button>
              </div>
            </div>
            <AntivirusBanner />
          </div>
          <div className="min-h-0 flex-1 overflow-hidden">
            {latestBe ? (
              <BulkExtractorResults bundle={latestBe} onError={onError} />
            ) : (
              <EmptyHint
                title="No carved artifacts yet."
                detail="Carve artifacts from this memory image."
              />
            )}
          </div>
        </div>
      ) : (
        <div className="flex min-h-0 min-w-0 flex-1 overflow-hidden">
          <div className="flex min-h-0 min-w-0 flex-1 flex-col overflow-hidden">
            <div className="shrink-0 border-b border-border px-3 py-2">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <p className="text-sm leading-5 text-muted">
                  Reconstructed and extracted files from this memory image. Select a file to
                  inspect it and run signature, capability, or string analysis.
                </p>
                <div className="flex shrink-0 flex-wrap items-center gap-2">
                  <label
                    className="mr-3 flex items-center gap-1.5 text-sm text-muted"
                    title="Filters this list to reconstructed EXE/DLL files. Use Run PE Reconstruction to extract files."
                  >
                    <input
                      type="checkbox"
                      checked={peOnly}
                      disabled={actionsLocked}
                      onChange={(e) => setPeOnly(e.target.checked)}
                    />
                    <span>
                      Extracted PE only
                      <span className="block text-[11px] font-normal leading-4">
                        Filter this list to reconstructed EXE/DLL files
                      </span>
                    </span>
                  </label>
                  <Button
                    size="sm"
                    disabled={actionsLocked || !peAvailable}
                    onClick={() => requestDiskWrite("pe")}
                  >
                    {actionButtonLabel(
                      "Run PE Reconstruction",
                      "pe",
                      submitting,
                      activeJobKind,
                      actionsLocked,
                    )}
                  </Button>
                </div>
              </div>
              <AntivirusBanner />
              <div className="mt-2 flex flex-wrap items-center gap-2">
                <ResultFilterBar
                  className="ml-0 w-full max-w-xl flex-none basis-auto"
                  query={filter}
                  onQueryChange={setFilter}
                  field={filterField}
                  onFieldChange={setFilterField}
                  placeholder="Filter name / hash / PID…"
                  fields={[
                    { id: "filename", label: "Filename" },
                    { id: "kind", label: "Kind" },
                    { id: "sha256", label: "SHA-256" },
                    { id: "size", label: "Size" },
                    { id: "pid", label: "PID" },
                    { id: "method", label: "Method" },
                    { id: "extracted", label: "Extracted" },
                  ]}
                />
                {latestPe ? (
                  <span className="text-muted">
                    {extractedCount} PE artifact{extractedCount === 1 ? "" : "s"} (
                    {latestPe.exe_count} EXE / {latestPe.dll_count} DLL)
                  </span>
                ) : peCaption ? (
                  <span className="text-muted">{peCaption}</span>
                ) : null}
              </div>
            </div>
            <div className="min-h-0 flex-1 overflow-auto">
              {loading && items.length === 0 && peLiveKind !== "in_progress" ? (
                <CenteredLoading />
              ) : visible.length === 0 ? (
                filter.trim() ? (
                  <div className="p-6 text-sm text-muted">No artifacts match the current filter.</div>
                ) : peLiveKind === "in_progress" || peLiveKind === "partial" || peLiveKind === "failed" ? (
                  <CoverageEmptyState
                    item={coverage}
                    title="Carved Data"
                    showTitle={false}
                    inProgressDetail="Artifacts are still being collected."
                    analyzedZeroDetail="VAD artifact extraction completed and stored no artifacts."
                    notAnalyzedDetail="Extract a region from Memory explorer after a VAD scan."
                    failedDetail="Artifact extraction failed."
                  />
                ) : (
                  <EmptyHint title="No extracted files yet." />
                )
              ) : (
                <table className="app-result-table w-full text-center">
                  <thead className="sticky top-0 bg-surface-2 text-muted">
                    <tr>
                      <SortableTh label="Filename" column="filename" sort={sort} onToggle={toggle} />
                      <SortableTh label="Kind" column="kind" sort={sort} onToggle={toggle} />
                      <SortableTh label="SHA-256" column="sha256" sort={sort} onToggle={toggle} />
                      <SortableTh label="Size" column="size" sort={sort} onToggle={toggle} />
                      <SortableTh label="PID" column="pid" sort={sort} onToggle={toggle} />
                      <SortableTh label="Method" column="method" sort={sort} onToggle={toggle} />
                      <SortableTh label="Extracted" column="extracted" sort={sort} onToggle={toggle} />
                    </tr>
                  </thead>
                  <tbody>
                    {sorted.map((a) => (
                      <tr
                        key={a.id}
                        className={cn(
                          "cursor-pointer border-t border-border/40 hover:bg-surface-2/50",
                          detail?.id === a.id && "bg-surface-2/70",
                        )}
                        onClick={() => void openDetail(a.id)}
                      >
                        <td className="px-2 py-1 font-mono">{a.filename}</td>
                        <td className="px-2 py-1">
                          {String(a.metadata?.pe_kind || a.file_type || "—")}
                        </td>
                        <td className="max-w-[14rem] truncate px-2 py-1 font-mono">{a.sha256}</td>
                        <td className="px-2 py-1 font-mono">{a.size_bytes.toLocaleString()}</td>
                        <td className="px-2 py-1 font-mono">{a.pid ?? "—"}</td>
                        <td className="px-2 py-1 text-muted">{a.extraction_method}</td>
                        <td className="px-2 py-1 font-mono">
                          <TimestampText value={a.extracted_at} />
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          </div>
          {pane === "pe" && detail ? (
            <aside className="w-[24rem] shrink-0 overflow-auto border-l border-border p-3">
              <div className="space-y-3">
                <div className="flex items-start justify-between gap-2">
                  <div className="font-semibold">Extracted PE artifact</div>
                  <Button size="sm" variant="ghost" onClick={() => setDetail(null)}>
                    Close
                  </Button>
                </div>
                <div className="text-[11px] text-muted">
                  Not classified as malware because it was found in memory. Analysis
                  results below are tool observations.
                </div>
                <div className="break-all font-mono text-[11px]">{detail.sha256}</div>
                <div className="text-muted">{detail.notes}</div>
                <div className="text-muted">Provenance</div>
                <ol className="list-decimal space-y-1 pl-4">
                  {(detail.provenance_chain ?? []).map((s, i) => (
                    <li key={i} className="font-mono text-[11px]">
                      {String(s.step)}: {JSON.stringify(s)}
                    </li>
                  ))}
                </ol>
                <div className="break-all text-[11px] text-muted">Path: {detail.stored_path}</div>
                <div className="text-[11px] text-muted">
                  Process: {String(detail.metadata?.original_path || "—")} PID {detail.pid ?? "—"}
                </div>
                <div className="text-[11px] text-muted">
                  Method: {detail.extraction_method} · {detail.tool_name} {detail.tool_version}
                </div>

                <ArtifactToolPanel
                  title={CAPABILITY.signatureDetection}
                  checking={caps.rows.signatureDetection.kind === "checking"}
                  available={caps.rows.signatureDetection.kind === "available"}
                  unavailableReason={
                    caps.rows.signatureDetection.kind === "unavailable"
                      ? UNAVAILABLE_DETAIL
                      : undefined
                  }
                  extra={yaraStatus?.status_summary}
                  busy={actionsLocked}
                  runLabel={actionButtonLabel(
                    "Scan signatures",
                    "yara",
                    submitting,
                    activeJobKind,
                    actionsLocked,
                  )}
                  onRun={() =>
                    void queue("yara.scan_artifact", {
                      artifact_id: detail.id,
                      evidence_id: evidenceId,
                      process_id: detail.process_id ?? undefined,
                      pid: detail.pid ?? undefined,
                    }, "yara")
                  }
                  note="Scans the extracted artifact file only. Matches are not a malware verdict."
                >
                  {yaraBundles.length === 0 ? (
                    <div className="text-muted">No signature scans yet for this artifact.</div>
                  ) : (
                    yaraBundles.map((b) => (
                      <div key={b.scan.id} className="rounded border border-border bg-surface p-2">
                        <div className="mb-1 flex flex-wrap items-center gap-2">
                          <Badge>{b.scan.status}</Badge>
                          <span>
                            {b.scan.match_count} match{b.scan.match_count === 1 ? "" : "es"}
                          </span>
                        </div>
                        {b.matches.map((m) => (
                          <div key={m.id} className="mt-1 border-t border-border/50 pt-1">
                            <div className="font-medium">{m.rule_name}</div>
                          </div>
                        ))}
                      </div>
                    ))
                  )}
                </ArtifactToolPanel>

                <ArtifactToolPanel
                  title={CAPABILITY.capabilityAnalysis}
                  checking={caps.rows.capabilityAnalysis.kind === "checking"}
                  available={caps.rows.capabilityAnalysis.kind === "available"}
                  unavailableReason={
                    caps.rows.capabilityAnalysis.kind === "unavailable"
                      ? UNAVAILABLE_DETAIL
                      : undefined
                  }
                  version={capaStatus?.capa_version}
                  busy={actionsLocked}
                  runLabel={actionButtonLabel(
                    "Analyze capabilities",
                    "capa",
                    submitting,
                    activeJobKind,
                    actionsLocked,
                  )}
                  onRun={() =>
                    void queue("capa.scan_artifact", {
                      artifact_id: detail.id,
                      evidence_id: evidenceId,
                      process_id: detail.process_id ?? undefined,
                      pid: detail.pid ?? undefined,
                    }, "capa")
                  }
                  note="Reports capabilities (injection, network, persistence, …), not a malware verdict."
                >
                  {capaBundles.length === 0 ? (
                    <div className="text-muted">No capability results yet for this artifact.</div>
                  ) : (
                    capaBundles.map((b) => (
                      <div key={b.scan.id} className="rounded border border-border bg-surface p-2">
                        <div className="mb-1 flex flex-wrap items-center gap-2">
                          <Badge>{b.scan.status}</Badge>
                          {b.scan.status === "completed" ? (
                            <span>
                              {b.scan.capability_count} capability
                              {b.scan.capability_count === 1 ? "" : "ies"}
                            </span>
                          ) : null}
                        </div>
                        {b.scan.status === "failed" || b.scan.status === "cancelled" ? (
                          <div className="text-[11px] text-danger">{artifactScanError(b.scan.error)}</div>
                        ) : (
                          b.capabilities.slice(0, 12).map((c) => (
                            <div key={c.id} className="mt-1 border-t border-border/50 pt-1">
                              <div className="font-medium">{c.name}</div>
                              <div className="text-muted">{c.namespace}</div>
                            </div>
                          ))
                        )}
                      </div>
                    ))
                  )}
                </ArtifactToolPanel>

                <ArtifactToolPanel
                  title={CAPABILITY.stringAnalysis}
                  checking={caps.rows.stringAnalysis.kind === "checking"}
                  available={caps.rows.stringAnalysis.kind === "available"}
                  unavailableReason={
                    caps.rows.stringAnalysis.kind === "unavailable"
                      ? UNAVAILABLE_DETAIL
                      : undefined
                  }
                  version={flossStatus?.floss_version}
                  busy={actionsLocked}
                  runLabel={actionButtonLabel(
                    "Extract strings",
                    "floss",
                    submitting,
                    activeJobKind,
                    actionsLocked,
                  )}
                  onRun={() =>
                    void queue("floss.scan_artifact", {
                      artifact_id: detail.id,
                      evidence_id: evidenceId,
                      process_id: detail.process_id ?? undefined,
                      pid: detail.pid ?? undefined,
                    }, "floss")
                  }
                  note="Static and decoded strings. Not treated as malicious findings."
                >
                  {flossBundles.length === 0 ? (
                    <div className="text-muted">No string results yet for this artifact.</div>
                  ) : (
                    flossBundles.map((b) => (
                      <div key={b.scan.id} className="rounded border border-border bg-surface p-2">
                        <div className="mb-1 flex flex-wrap items-center gap-2">
                          <Badge>{b.scan.status}</Badge>
                          {b.scan.status === "completed" ? (
                            <span>
                              {b.scan.string_count} string{b.scan.string_count === 1 ? "" : "s"}
                            </span>
                          ) : null}
                        </div>
                        {b.scan.status === "failed" || b.scan.status === "cancelled" ? (
                          <div className="text-[11px] text-danger">{artifactScanError(b.scan.error)}</div>
                        ) : (
                          b.strings.slice(0, 20).map((s) => (
                            <div key={s.id} className="mt-1 font-mono text-[11px] text-muted">
                              [{s.kind}] {s.value.slice(0, 120)}
                            </div>
                          ))
                        )}
                      </div>
                    ))
                  )}
                </ArtifactToolPanel>
              </div>
            </aside>
          ) : null}
        </div>
      )}

      <AntivirusConfirmDialog
        open={confirmAction != null}
        busy={busy}
        onCancel={() => setConfirmAction(null)}
        onContinue={confirmDiskWrite}
      />
    </div>
  );
}

function EmptyHint({ title, detail }: { title: string; detail?: string }) {
  return (
    <div className="flex min-h-[16rem] flex-1 flex-col items-center justify-center px-6 py-16 text-center">
      <div className="text-sm font-semibold">{title}</div>
      {detail ? <p className="mt-2 max-w-sm text-sm leading-5 text-muted">{detail}</p> : null}
    </div>
  );
}

function AntivirusBanner() {
  return (
    <div className="mt-2 flex min-w-0 w-full items-center gap-2 rounded-md border border-danger/40 bg-danger/5 px-2.5 py-2 text-[11px] leading-relaxed text-muted">
      <ShieldAlert size={16} className="shrink-0 text-danger" aria-hidden />
      <p className="min-w-0 flex-1 text-justify">
        Pause real-time <span className="font-bold text-danger">antivirus</span> for the
        Dumplyzer data folder before running either job in this section. Carved Artifacts
        and Extracted Files both write recovered content to disk, including reconstructed
        EXE/DLL files; endpoint products often quarantine those files because they look
        like live binaries, which can delete output or stop the scan mid-run.
      </p>
    </div>
  );
}

function AntivirusConfirmDialog({
  open,
  busy,
  onCancel,
  onContinue,
}: {
  open: boolean;
  busy: boolean;
  onCancel: () => void;
  onContinue: () => void;
}) {
  if (!open) return null;
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4">
      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby="carved-av-warning-title"
        aria-describedby="carved-av-warning-body"
        className="card w-full max-w-md shadow-xl"
      >
        <div className="px-4 py-3">
          <div className="flex items-start gap-2">
            <ShieldAlert size={16} className="mt-0.5 shrink-0 text-danger" aria-hidden />
            <div className="min-w-0">
              <h2 id="carved-av-warning-title" className="text-sm font-semibold">
                Antivirus warning
              </h2>
              <p id="carved-av-warning-body" className="mt-1.5 text-justify text-sm leading-5 text-muted">
                Carved Artifacts and Extracted Files both write recovered content to the
                Dumplyzer data folder. Real-time antivirus may quarantine those files and
                interrupt the analysis.
              </p>
            </div>
          </div>
        </div>
        <div className="flex flex-wrap items-center justify-end gap-2 border-t border-border px-4 py-3">
          <Button size="sm" variant="ghost" disabled={busy} onClick={onCancel}>
            Cancel
          </Button>
          <Button size="sm" disabled={busy} onClick={onContinue}>
            Continue
          </Button>
        </div>
      </div>
    </div>
  );
}

function ArtifactToolPanel({
  title,
  checking = false,
  available,
  unavailableReason,
  suggestion,
  version,
  extra,
  busy,
  onRun,
  runLabel,
  note,
  children,
}: {
  title: string;
  checking?: boolean;
  available: boolean;
  unavailableReason?: string | null;
  suggestion?: string | null;
  version?: string | null;
  extra?: string;
  busy: boolean;
  onRun: () => void;
  runLabel: string;
  note: string;
  children: React.ReactNode;
}) {
  return (
    <div className="border-t border-border pt-3">
      <div className="mb-2 font-semibold">{title}</div>
      {checking ? (
        <div className="text-muted">{title} — Checking…</div>
      ) : !available ? (
        <div className="space-y-1 text-muted">
          <div>{title} unavailable</div>
          <div>{unavailableReason}</div>
          <div>{suggestion}</div>
        </div>
      ) : (
        <div className="space-y-2">
          {version && <div className="text-muted">Version {version}</div>}
          {extra && <div className="break-all font-mono text-[11px] text-muted">{extra}</div>}
          <div className="flex gap-2">
            <Button size="sm" onClick={onRun} disabled={busy}>
              {runLabel}
            </Button>
          </div>
          <div className="text-[11px] text-muted">{note}</div>
          {children}
        </div>
      )}
    </div>
  );
}
