import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { ShieldAlert } from "lucide-react";
import { engineCall, EngineClientError, openLocalFolder } from "../lib/api";
import { CAPABILITY, UNAVAILABLE_DETAIL } from "../lib/analysisCapabilities";
import { activeJobOfKind, isActiveJobStatus } from "../lib/analysisOptions";
import { jobProgressPercentText } from "../lib/jobDisplay";
import { useCapabilityStatus, type CapabilitySnapshot } from "../lib/capabilityStatus";
import { coverageIsUpdating, coverageLiveKind, coverageResultCaption } from "../lib/analysisCoverage";
import { CoverageEmptyState, CenteredLoading, ImportEvidenceState, AnalysisScopeNote } from "./CoverageStatus";
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

function isPeArtifact(a: Artifact): boolean {
  const label = String(a.metadata?.label || "");
  if (label === "extracted_pe_artifact") return true;
  if ((a.file_type || "").toLowerCase() === "pe") return true;
  const kind = String(a.metadata?.pe_kind || "").toLowerCase();
  if (kind === "exe" || kind === "dll") return true;
  const method = (a.extraction_method || "").toLowerCase();
  return method.includes("pedump") || method.includes("dumpfiles.pe");
}

function isUnsupportedScan(error: Record<string, unknown> | null | undefined): boolean {
  const text = artifactScanError(error).toLowerCase();
  return text.includes("not this file") || text.includes("extracted pe");
}

function isBoilerplateNotes(notes: string | null | undefined): boolean {
  if (!notes?.trim()) return true;
  return /not executed|not classified as malware/i.test(notes);
}

type ArtifactAction = "pe" | "extraction" | "yara" | "capa" | "floss";
type DiskWriteAction = "pe" | "extraction";

const ACTION_JOB_KINDS: Record<ArtifactAction, string[]> = {
  pe: ["pe_extraction"],
  extraction: ["bulk_extractor_scan"],
  yara: ["yara_artifact_scan"],
  capa: ["capa_artifact"],
  floss: ["floss_artifact"],
};

function actionJob(
  action: ArtifactAction,
  activeJobs: Job[] | undefined,
): Job | null {
  return activeJobOfKind(activeJobs, ...ACTION_JOB_KINDS[action]);
}

function actionIsRunning(
  action: ArtifactAction,
  submitting: ArtifactAction | null,
  activeJobs: Job[] | undefined,
): boolean {
  if (submitting === action) return true;
  const job = actionJob(action, activeJobs);
  return job != null && isActiveJobStatus(job.status);
}

function BusyLabel({ children }: { children: ReactNode }) {
  return (
    <span className="inline-flex items-center gap-1.5">
      <span
        className="h-3.5 w-3.5 shrink-0 animate-spin rounded-full border-2 border-current/30 border-t-current"
        aria-hidden
      />
      {children}
    </span>
  );
}

function actionButtonLabel(
  idle: string,
  action: ArtifactAction,
  submitting: ArtifactAction | null,
  activeJobs: Job[] | undefined,
  locked: boolean,
  percent?: string | null,
): ReactNode {
  if (submitting === action) return <BusyLabel>Starting…</BusyLabel>;
  const job = actionJob(action, activeJobs);
  if (job && isActiveJobStatus(job.status)) {
    if (job.status === "queued") return <BusyLabel>Queued</BusyLabel>;
    return <BusyLabel>{percent ? `Running… ${percent}` : "Running…"}</BusyLabel>;
  }
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
  activeJobs = [],
  nowMs = Date.now(),
  onShownCountChange,
}: {
  evidenceId: string | null;
  onError: (m: string) => void;
  onJobSubmitted?: (job: Job) => void;
  refreshToken?: number | string;
  coverage?: CapabilityCoverage;
  jobsRunning?: boolean;
  activeJobs?: Job[];
  nowMs?: number;
  onShownCountChange?: (count: number) => void;
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
    setDetail(null);
    setYaraBundles([]);
    setCapaBundles([]);
    setFlossBundles([]);
    setItems([]);
    setPeBundles([]);
    setBulkExtractorBundles([]);
    setLoadedEvidenceId(null);
  }, [evidenceId]);

  useEffect(() => {
    if (!confirmAction) return;
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") setConfirmAction(null);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [confirmAction]);

  const visible = useMemo(() => {
    const peFiltered = peOnly ? items.filter(isPeArtifact) : items;
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

  const carvedShownCount = useMemo(() => {
    const completed = bulkExtractorBundles.find((b) => b.scan.status === "completed");
    const features = completed?.scan.feature_count ?? 0;
    return items.length + features;
  }, [bulkExtractorBundles, items.length]);

  useLayoutEffect(() => {
    onShownCountChange?.(carvedShownCount);
  }, [carvedShownCount, onShownCountChange]);

  const openDetail = useCallback(async (id: string) => {
    try {
      const a = await engineCall<Artifact>("artifacts.get", { artifact_id: id });
      setDetail(a);
      setYaraBundles(a.yara_scans ?? []);
      setCapaBundles(a.capa_scans ?? []);
      setFlossBundles(a.floss_scans ?? []);
    } catch (e) {
      onError(e instanceof EngineClientError ? e.message : String(e));
    }
  }, [onError]);

  const selectedDetailId = useRef<string | null>(null);
  selectedDetailId.current = detail?.id ?? null;
  const prevJobsRunning = useRef(jobsRunning);

  useEffect(() => {
    const wasRunning = prevJobsRunning.current;
    prevJobsRunning.current = jobsRunning;
    if (!wasRunning || jobsRunning) return;
    const id = selectedDetailId.current;
    if (id) void openDetail(id);
  }, [jobsRunning, openDetail]);

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
  const latestBe =
    bulkExtractorBundles.find((b) => b.scan.status === "completed") ??
    bulkExtractorBundles.find(
      (b) => b.scan.status === "running" || b.scan.status === "queued",
    ) ??
    null;
  const extractedCount = latestPe?.extracted_count ?? visible.filter((a) => a.file_type === "pe").length;
  const actionsLocked = busy || jobsRunning || coverageIsUpdating(coverage);
  const peAvailable = Boolean(peStatus?.available);
  const extractionAvailable = Boolean(bulkExtractorStatus?.available);
  const carvedOutputDir =
    latestBe?.scan.status === "completed" ? latestBe.scan.output_dir : null;
  const peLiveKind = coverageLiveKind(coverage);
  const peCaption = coverageResultCaption(
    coverage,
    items.length,
    visible.length !== items.length ? visible.length : undefined,
  );
  const carvingJob = actionJob("extraction", activeJobs);
  const peJob = actionJob("pe", activeJobs);
  const carvingBusy =
    submitting === "extraction" || (carvingJob != null && isActiveJobStatus(carvingJob.status));
  const peBusy = submitting === "pe" || (peJob != null && isActiveJobStatus(peJob.status));
  const carvingPercent = jobProgressPercentText(carvingJob, nowMs);
  const pePercent = jobProgressPercentText(peJob, nowMs);

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
                  className="min-w-[5.75rem]"
                  disabled={actionsLocked || !extractionAvailable}
                  onClick={() => requestDiskWrite("extraction")}
                >
                  {actionButtonLabel(
                    "Carve Artifacts",
                    "extraction",
                    submitting,
                    activeJobs,
                    actionsLocked,
                    carvingBusy ? carvingPercent : null,
                  )}
                </Button>
              </div>
            </div>
            <AntivirusBanner />
          </div>
          <div className="min-h-0 flex-1 overflow-hidden">
            {carvingBusy ? (
              <CenteredLoading
                label={
                  carvingPercent
                    ? `Carving artifacts… ${carvingPercent}`
                    : carvingJob?.status === "queued"
                      ? "Queued…"
                      : "Carving artifacts…"
                }
              />
            ) : latestBe ? (
              <BulkExtractorResults
                key={latestBe.scan.id}
                bundle={latestBe}
                onError={onError}
              />
            ) : (
              <EmptyHint
                title="No carved artifacts yet."
                detail="Carve artifacts from this memory image."
              />
            )}
          </div>
        </div>
      ) : (
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
                    className="min-w-[5.75rem]"
                    disabled={actionsLocked || !peAvailable}
                    onClick={() => requestDiskWrite("pe")}
                  >
                  {actionButtonLabel(
                      "Run PE Reconstruction",
                      "pe",
                      submitting,
                      activeJobs,
                      actionsLocked,
                      peBusy ? pePercent : null,
                    )}
                  </Button>
                </div>
              </div>
              <AntivirusBanner />
              <div className="mt-2">
              <AnalysisScopeNote>
                PE reconstruction walks the whole memory image. On large dumps this often
                takes much longer than other jobs — you can keep using other sections while
                it runs.
              </AnalysisScopeNote>
              </div>
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
                    {peOnly && items.length !== visible.length
                      ? ` · ${visible.length.toLocaleString()} shown`
                      : ""}
                  </span>
                ) : visible.length > 0 || !peOnly ? (
                  peCaption ? <span className="text-muted">{peCaption}</span> : null
                ) : null}
              </div>
            </div>
            <div className="flex min-h-0 flex-1 flex-col overflow-auto">
              {peBusy ? (
                <CenteredLoading
                  label={
                    pePercent
                      ? `Reconstructing files… ${pePercent}`
                      : peJob?.status === "queued"
                        ? "Queued…"
                        : "Reconstructing files…"
                  }
                />
              ) : (
                <>
                  <div className="min-h-32 min-w-0 flex-1 overflow-auto">
              {loading && items.length === 0 && peLiveKind !== "in_progress" ? (
                <CenteredLoading />
              ) : visible.length === 0 ? (
                filter.trim() ? (
                  <div className="p-6 text-sm text-muted">No artifacts match the current filter.</div>
                ) : peOnly && items.length > 0 ? (
                  <div className="p-6 text-sm text-muted">
                    No reconstructed EXE/DLL files in this list. Run PE Reconstruction, or clear
                    Extracted PE only to inspect other extracted files.
                  </div>
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
                    {sorted.map((a) => {
                      const isSelected = detail?.id === a.id;
                      return (
                      <tr
                        key={a.id}
                        aria-selected={isSelected}
                        className={cn(
                          "cursor-pointer border-t border-border/40",
                          isSelected && "app-row-active",
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
                      );
                    })}
                  </tbody>
                </table>
              )}
            </div>
            <aside
              className={cn(
                "h-auto shrink-0 border-t border-border p-3",
                detail && "selected-record-detail",
              )}
            >
              {!detail ? (
                <div className="text-muted">
                  Select a reconstructed EXE or DLL for details and analysis.
                </div>
              ) : (
              <ExtractedFileDetail
                detail={detail}
                evidenceId={evidenceId}
                yaraBundles={yaraBundles}
                capaBundles={capaBundles}
                flossBundles={flossBundles}
                caps={caps}
                actionsLocked={actionsLocked}
                submitting={submitting}
                activeJobs={activeJobs}
                nowMs={nowMs}
                onQueue={queue}
              />
              )}
            </aside>
                </>
              )}
            </div>
        </div>
      )}

      <AntivirusConfirmDialog
        open={confirmAction != null}
        action={confirmAction}
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

function KV({ k, v }: { k: string; v: unknown }) {
  return (
    <div className="grid grid-cols-[72px_1fr] gap-1">
      <div className="text-muted">{k}</div>
      <div className="break-all font-mono">
        {v == null || v === "" ? "—" : String(v)}
      </div>
    </div>
  );
}

function fileScanBusyLabel(
  submitting: ArtifactAction | null,
  activeJobs: Job[] | undefined,
  percent?: string | null,
): string {
  const job =
    actionJob("capa", activeJobs) ??
    actionJob("floss", activeJobs) ??
    actionJob("yara", activeJobs);
  if (job?.status === "queued") return "Queued";
  let label = "Analyzing…";
  if (submitting === "capa" || actionIsRunning("capa", submitting, activeJobs)) {
    label = "Analyzing capabilities…";
  } else if (submitting === "floss" || actionIsRunning("floss", submitting, activeJobs)) {
    label = "Extracting strings…";
  } else if (submitting === "yara" || actionIsRunning("yara", submitting, activeJobs)) {
    label = "Scanning signatures…";
  }
  return percent ? `${label} ${percent}` : label;
}

function ExtractedFileDetail({
  detail,
  evidenceId,
  yaraBundles,
  capaBundles,
  flossBundles,
  caps,
  actionsLocked,
  submitting,
  activeJobs,
  nowMs,
  onQueue,
}: {
  detail: Artifact;
  evidenceId: string;
  yaraBundles: YaraScanBundle[];
  capaBundles: CapaScanBundle[];
  flossBundles: FlossScanBundle[];
  caps: CapabilitySnapshot;
  actionsLocked: boolean;
  submitting: ArtifactAction | null;
  activeJobs: Job[];
  nowMs: number;
  onQueue: (method: string, params: Record<string, unknown>, action?: ArtifactAction) => Promise<void>;
}) {
  const isPe = isPeArtifact(detail);
  const kind = String(detail.metadata?.pe_kind || detail.file_type || "");
  const yaraRow = caps.rows.signatureDetection;
  const capaRow = caps.rows.capabilityAnalysis;
  const flossRow = caps.rows.stringAnalysis;
  const yaraReady = yaraRow.kind === "available";
  const capaReady = capaRow.kind === "available";
  const flossReady = flossRow.kind === "available";
  const yaraResults = yaraBundles.filter((b) => !isUnsupportedScan(b.scan.error));
  const capaResults = isPe
    ? capaBundles.filter((b) => !isUnsupportedScan(b.scan.error))
    : [];
  const flossResults = isPe
    ? flossBundles.filter((b) => !isUnsupportedScan(b.scan.error))
    : [];
  const runParams = {
    artifact_id: detail.id,
    evidence_id: evidenceId,
    process_id: detail.process_id ?? undefined,
    pid: detail.pid ?? undefined,
  };
  const yaraPercent = jobProgressPercentText(actionJob("yara", activeJobs), nowMs);
  const capaPercent = jobProgressPercentText(actionJob("capa", activeJobs), nowMs);
  const flossPercent = jobProgressPercentText(actionJob("floss", activeJobs), nowMs);
  const scanBusy =
    actionIsRunning("yara", submitting, activeJobs) ||
    actionIsRunning("capa", submitting, activeJobs) ||
    actionIsRunning("floss", submitting, activeJobs);

  return (
    <div className="space-y-3">
      <div className="flex items-center gap-2">
        <span className="h-2 w-2 shrink-0 rounded-full bg-accent" aria-hidden />
        <div className="font-semibold">File detail</div>
        <div className="min-w-0 truncate font-mono text-muted">
          {detail.filename}
          {kind ? ` · ${kind}` : ""}
        </div>
      </div>
      <div className="grid grid-cols-1 gap-x-8 gap-y-1 sm:grid-cols-2 xl:grid-cols-3">
        <KV k="Filename" v={detail.filename} />
        <KV k="Kind" v={kind || null} />
        <KV k="SHA-256" v={detail.sha256} />
        <KV k="Size" v={detail.size_bytes.toLocaleString()} />
        <KV k="PID" v={detail.pid} />
        <KV k="Method" v={detail.extraction_method} />
        <KV k="Path" v={detail.stored_path} />
        <KV k="Original" v={detail.metadata?.original_path} />
      </div>
      {!isBoilerplateNotes(detail.notes) ? (
        <div className="text-muted">{detail.notes}</div>
      ) : null}

      <div className="space-y-2 border-t border-border pt-3">
        <div className="flex flex-wrap items-center gap-2">
          <Button
            size="sm"
            className="min-w-[5.75rem]"
            disabled={actionsLocked || !yaraReady}
            title={!yaraReady ? UNAVAILABLE_DETAIL : undefined}
            onClick={() => void onQueue("yara.scan_artifact", runParams, "yara")}
          >
            {actionButtonLabel(
              "Scan signatures",
              "yara",
              submitting,
              activeJobs,
              actionsLocked,
              actionIsRunning("yara", submitting, activeJobs) ? yaraPercent : null,
            )}
          </Button>
          {isPe ? (
            <>
              <Button
                size="sm"
                className="min-w-[5.75rem]"
                disabled={actionsLocked || !capaReady}
                title={!capaReady ? UNAVAILABLE_DETAIL : undefined}
                onClick={() => void onQueue("capa.scan_artifact", runParams, "capa")}
              >
                {actionButtonLabel(
                  "Analyze capabilities",
                  "capa",
                  submitting,
                  activeJobs,
                  actionsLocked,
                  actionIsRunning("capa", submitting, activeJobs) ? capaPercent : null,
                )}
              </Button>
              <Button
                size="sm"
                className="min-w-[5.75rem]"
                disabled={actionsLocked || !flossReady}
                title={!flossReady ? UNAVAILABLE_DETAIL : undefined}
                onClick={() => void onQueue("floss.scan_artifact", runParams, "floss")}
              >
                {actionButtonLabel(
                  "Extract strings",
                  "floss",
                  submitting,
                  activeJobs,
                  actionsLocked,
                  actionIsRunning("floss", submitting, activeJobs) ? flossPercent : null,
                )}
              </Button>
            </>
          ) : null}
        </div>
        {isPe ? (
          <p className="text-[11px] text-muted">
            These tools inspect the extracted file. Matches and capabilities are observations, not a
            malware verdict.
          </p>
        ) : (
          <p className="text-[11px] text-muted">
            Signature scans can run on this file. Capability Analysis and String Analysis need a
            reconstructed EXE or DLL — run PE Reconstruction, or enable Extracted PE only.
          </p>
        )}
      </div>

      {scanBusy ? (
        <CenteredLoading
          label={fileScanBusyLabel(submitting, activeJobs, yaraPercent ?? capaPercent ?? flossPercent)}
        />
      ) : (
        <>
      {yaraResults.length > 0 ? (
        <ResultBlock title={CAPABILITY.signatureDetection}>
          {yaraResults.map((b) => (
            <div key={b.scan.id} className="rounded border border-border bg-surface p-2">
              <div className="mb-1 text-muted">
                {b.scan.status === "failed" || b.scan.status === "cancelled"
                  ? artifactScanError(b.scan.error)
                  : `${b.scan.match_count} signature match${b.scan.match_count === 1 ? "" : "es"}`}
              </div>
              {b.matches.map((m) => (
                <div key={m.id} className="mt-1 border-t border-border/50 pt-1 font-medium">
                  {m.rule_name}
                </div>
              ))}
            </div>
          ))}
        </ResultBlock>
      ) : null}

      {capaResults.length > 0 ? (
        <ResultBlock title={CAPABILITY.capabilityAnalysis}>
          {capaResults.map((b) => (
            <div key={b.scan.id} className="rounded border border-border bg-surface p-2">
              {b.scan.status === "failed" || b.scan.status === "cancelled" ? (
                <div className="text-danger">{artifactScanError(b.scan.error)}</div>
              ) : (
                <>
                  <div className="mb-1 text-muted">
                    {b.scan.capability_count} capabilit
                    {b.scan.capability_count === 1 ? "y" : "ies"}
                  </div>
                  {b.capabilities.slice(0, 12).map((c) => (
                    <div key={c.id} className="mt-1 border-t border-border/50 pt-1">
                      <div className="font-medium">{c.name}</div>
                      {c.namespace ? <div className="text-muted">{c.namespace}</div> : null}
                    </div>
                  ))}
                </>
              )}
            </div>
          ))}
        </ResultBlock>
      ) : null}

      {flossResults.length > 0 ? (
        <ResultBlock title={CAPABILITY.stringAnalysis}>
          {flossResults.map((b) => (
            <div key={b.scan.id} className="rounded border border-border bg-surface p-2">
              {b.scan.status === "failed" || b.scan.status === "cancelled" ? (
                <div className="text-danger">{artifactScanError(b.scan.error)}</div>
              ) : (
                <>
                  <div className="mb-1 text-muted">
                    {b.scan.string_count} string{b.scan.string_count === 1 ? "" : "s"}
                  </div>
                  {b.strings.slice(0, 20).map((s) => (
                    <div key={s.id} className="mt-1 font-mono text-[11px] text-muted">
                      [{s.kind}] {s.value.slice(0, 120)}
                    </div>
                  ))}
                </>
              )}
            </div>
          ))}
        </ResultBlock>
      ) : null}
        </>
      )}
    </div>
  );
}

function ResultBlock({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="space-y-2 border-t border-border pt-3">
      <div className="font-semibold">{title}</div>
      {children}
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
  action,
  busy,
  onCancel,
  onContinue,
}: {
  open: boolean;
  action: DiskWriteAction | null;
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
                {action === "pe" ? (
                  <>
                    {" "}
                    PE reconstruction also walks the whole dump, so on large memory images it
                    can take a long time.
                  </>
                ) : null}
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
