import {
  useCallback,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import { Info } from "lucide-react";
import { engineCall, EngineClientError } from "../lib/api";
import { activeJobOfKind, isActiveJobStatus } from "../lib/analysisOptions";
import { jobProgressPercentText } from "../lib/jobDisplay";
import {
  CHECKING_DETAIL,
  UNAVAILABLE_DETAIL,
} from "../lib/analysisCapabilities";
import { useCapabilityStatus } from "../lib/capabilityStatus";
import { TimestampText } from "../lib/datetime";
import {
  findingSeverityClass,
  findingSeverityRank,
  formatRuleLevel,
  ruleLevelFromMeta,
} from "../lib/findings";
import { useTableSort } from "../lib/tableSort";
import type { Artifact, Job, YaraMatch, YaraScanBundle } from "../lib/types";
import { Badge } from "./ui/badge";
import { Button } from "./ui/button";
import { AnalysisScopeNote, ImportEvidenceState } from "./CoverageStatus";
import { SegmentedControl } from "./ui/segmented";
import { SortableTh } from "./SortableTh";

type TabId = "memory" | "extracted";

export function SignaturesView({
  evidenceId,
  onError,
  onJobSubmitted,
  refreshToken,
  jobsRunning = false,
  activeJobs = [],
  nowMs = Date.now(),
}: {
  evidenceId: string | null;
  onError: (m: string) => void;
  onJobSubmitted?: (job: Job) => void;
  refreshToken?: number | string;
  jobsRunning?: boolean;
  activeJobs?: Job[];
  nowMs?: number;
}) {
  const caps = useCapabilityStatus();
  const yara = caps.yara;
  const yaraRow = caps.rows.signatureDetection;
  const [tab, setTab] = useState<TabId>("memory");
  const [bundles, setBundles] = useState<YaraScanBundle[]>([]);
  const [peFiles, setPeFiles] = useState<Artifact[]>([]);
  const [submitting, setSubmitting] = useState<"memory" | "extracted" | null>(
    null,
  );

  const load = useCallback(async () => {
    if (!evidenceId) {
      setBundles([]);
      setPeFiles([]);
      return;
    }
    try {
      const [scans, pe] = await Promise.all([
        engineCall<{ items: YaraScanBundle[] }>("yara.scans_for_evidence", {
          evidence_id: evidenceId,
        }),
        engineCall<{ items: Artifact[] }>("pe_extraction.artifacts", {
          evidence_id: evidenceId,
        }),
      ]);
      setBundles(scans.items ?? []);
      setPeFiles(pe.items ?? []);
    } catch (err) {
      onError(err instanceof EngineClientError ? err.message : String(err));
    }
  }, [evidenceId, onError]);

  useEffect(() => {
    void load();
  }, [load, refreshToken]);

  const peById = useMemo(() => {
    const map = new Map<string, Artifact>();
    for (const art of peFiles) map.set(art.id, art);
    return map;
  }, [peFiles]);

  const memoryBundles = useMemo(
    () =>
      bundles.filter((b) => (b.scan.target_kind || "artifact") === "memory"),
    [bundles],
  );
  const extractedBundles = useMemo(
    () =>
      bundles.filter((b) => (b.scan.target_kind || "artifact") === "artifact"),
    [bundles],
  );

  const available = yaraRow.kind === "available";
  const checking = yaraRow.kind === "checking";
  const actionsLocked = jobsRunning || submitting != null;

  const queue = async (
    method: "yara.scan_memory" | "yara.scan_extracted",
    kind: "memory" | "extracted",
  ) => {
    if (!evidenceId || submitting) return;
    setSubmitting(kind);
    try {
      const job = await engineCall<Job>(method, { evidence_id: evidenceId });
      onJobSubmitted?.(job);
    } catch (err) {
      onError(err instanceof EngineClientError ? err.message : String(err));
    } finally {
      setSubmitting(null);
    }
  };

  if (!evidenceId) return <ImportEvidenceState title="Signatures" />;

  const memoryJob = activeJobOfKind(activeJobs, "yara_memory_scan");
  const extractedJob = activeJobOfKind(
    activeJobs,
    "yara_extracted_scan",
    "yara_artifact_scan",
  );
  const scanBusy =
    submitting === "memory" ||
    (memoryJob != null && isActiveJobStatus(memoryJob.status)) ||
    (actionsLocked && tab === "memory");
  const extractedBusy =
    submitting === "extracted" ||
    (extractedJob != null && isActiveJobStatus(extractedJob.status)) ||
    (actionsLocked && tab === "extracted");
  const memoryPercent = jobProgressPercentText(memoryJob, nowMs);
  const extractedPercent = jobProgressPercentText(extractedJob, nowMs);
  const showMemoryPercent = Boolean(memoryPercent && scanBusy && memoryJob?.status !== "queued");
  const showExtractedPercent = Boolean(
    extractedPercent && extractedBusy && extractedJob?.status !== "queued",
  );

  return (
    <div className="flex h-full min-h-0 flex-col text-xs">
      <div className="flex shrink-0 flex-wrap items-center gap-2 border-b border-border px-3 py-2">
        <div className="text-sm font-semibold">Signatures</div>
        <SegmentedControl
          ariaLabel="Signature scan targets"
          value={tab}
          onChange={setTab}
          options={[
            { id: "memory", label: "Memory Image" },
            { id: "extracted", label: "Extracted PE Scan" },
          ]}
        />
      </div>
      <div className="flex min-h-0 flex-1 flex-col overflow-hidden">
        {checking ? (
          <p className="p-4 text-sm text-muted">{CHECKING_DETAIL}</p>
        ) : !available ? (
          <p className="p-4 text-sm text-muted">
            {yara?.reason || UNAVAILABLE_DETAIL}
            {yara?.suggestion ? ` ${yara.suggestion}` : ""}
          </p>
        ) : (
          <>
            <div className="analysis-profile-note mx-4 mt-4 inline-flex w-fit shrink-0 items-center gap-2 rounded-md px-2.5 py-2 text-xs leading-none">
              <Info size={14} className="shrink-0" aria-hidden />
              <span className="whitespace-nowrap">
                To add your own YARA rules, open{" "}
                <span className="font-bold">Settings</span>. Copy{" "}
                <span className="font-mono">.yar</span> or{" "}
                <span className="font-mono">.yara</span> files into the custom
                rules folder, then Reload Rules.
              </span>
            </div>
            {tab === "memory" ? (
              <ScanPanel
                title="Memory Image"
                description="Scan the imported memory image with YARA rules. Progress stays on this page."
                buttonLabel={scanButtonLabel(
                  submitting === "memory",
                  memoryJob,
                  showMemoryPercent ? memoryPercent : null,
                  "Scan Memory Image",
                )}
                disabled={scanBusy}
                extra={yara?.status_summary}
                percent={showMemoryPercent ? memoryPercent : null}
                onScan={() => void queue("yara.scan_memory", "memory")}
                empty="No memory-image scans yet."
                bundles={memoryBundles}
              />
            ) : (
              <ScanPanel
                title="Extracted PE Scan"
                description="Scan files already listed in Carved Data → Extracted Files. This page does not extract them from the dump."
                buttonLabel={scanButtonLabel(
                  submitting === "extracted",
                  extractedJob,
                  showExtractedPercent ? extractedPercent : null,
                  "Scan Extracted PE Files",
                )}
                disabled={extractedBusy || peFiles.length === 0}
                buttonTitle={
                  peFiles.length === 0
                    ? "Extract files in Carved Data → Extracted Files, or extract a region from Memory first."
                    : undefined
                }
                extra={
                  peFiles.length === 0 ? (
                    <AnalysisScopeNote>
                      Extract files before scanning. Open{" "}
                      <span className="font-semibold">Carved Data</span>, switch
                      to <span className="font-semibold">Extracted Files</span>,
                      then run{" "}
                      <span className="font-semibold">
                        Run PE Reconstruction
                      </span>{" "}
                      or extract a region from Memory. When those files appear,
                      return here and scan them.
                    </AnalysisScopeNote>
                  ) : (
                    `${peFiles.length} extracted file${peFiles.length === 1 ? "" : "s"} ready to scan.`
                  )
                }
                percent={showExtractedPercent ? extractedPercent : null}
                onScan={() => void queue("yara.scan_extracted", "extracted")}
                empty={peFiles.length === 0 ? "" : "No scans yet."}
                bundles={extractedBundles}
                peById={peById}
              />
            )}
          </>
        )}
      </div>
    </div>
  );
}

function scanButtonLabel(
  submitting: boolean,
  job: Job | null,
  percent: string | null,
  idle: string,
): string {
  if (submitting && !job) return "Starting…";
  if (job?.status === "queued") return "Queued";
  if (job != null && isActiveJobStatus(job.status)) {
    return percent ? `Scanning… ${percent}` : "Scanning…";
  }
  return idle;
}

function ScanPanel({
  title,
  description,
  buttonLabel,
  disabled,
  buttonTitle,
  extra,
  percent,
  onScan,
  empty,
  bundles,
  peById,
}: {
  title: string;
  description: string;
  buttonLabel: string;
  disabled: boolean;
  buttonTitle?: string;
  extra?: ReactNode;
  percent?: string | null;
  onScan: () => void;
  empty: string;
  bundles: YaraScanBundle[];
  peById?: Map<string, Artifact>;
}) {
  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <div className="shrink-0 px-4 pt-4 pb-3">
        <h3 className="text-sm font-semibold">{title}</h3>
        <p className="mt-1 text-sm text-muted">{description}</p>
        {typeof extra === "string" ? (
          <p className="mt-1 text-xs text-muted">{extra}</p>
        ) : extra ? (
          <div className="mt-2">{extra}</div>
        ) : null}
        <Button
          size="sm"
          className="mt-3 min-w-[10rem]"
          disabled={disabled}
          title={buttonTitle}
          onClick={onScan}
        >
          {buttonLabel}
        </Button>
        {percent ? (
          <div className="mt-2 max-w-xs">
            <div className="mb-1 text-[11px] text-muted">
              Scan progress {percent}
            </div>
            <div className="h-1.5 overflow-hidden rounded-full bg-surface-2">
              <div
                className="h-full rounded-full bg-accent transition-[width]"
                style={{ width: percent }}
              />
            </div>
          </div>
        ) : null}
      </div>
      {bundles.length === 0 ? (
        empty ? (
          <p className="px-4 text-sm text-muted">{empty}</p>
        ) : null
      ) : (
        <div className="min-h-0 flex-1 overflow-auto">
          {bundles.map((b) => (
            <ScanResultCard key={b.scan.id} bundle={b} peById={peById} />
          ))}
        </div>
      )}
    </div>
  );
}

function scanStatusLabel(status: string): string {
  if (status === "completed") return "Completed";
  if (status === "failed") return "Failed";
  if (status === "cancelled" || status === "canceled") return "Cancelled";
  if (status === "running") return "Scanning";
  if (status === "queued") return "Queued";
  return status.replace(/_/g, " ");
}

function ScanResultCard({
  bundle,
  peById,
}: {
  bundle: YaraScanBundle;
  peById?: Map<string, Artifact>;
}) {
  const scan = bundle.scan;
  const artifactName =
    scan.artifact_id && peById
      ? peById.get(scan.artifact_id)?.filename
      : undefined;
  const grouped = useMemo(() => groupMatches(bundle.matches), [bundle.matches]);
  const getValue = useCallback((row: GroupedRule, key: string) => {
    if (key === "rule") return row.rule_name;
    if (key === "level") return row.level ? findingSeverityRank(row.level) : 99;
    if (key === "namespace") return row.namespace ?? "";
    if (key === "hits") return row.hits;
    return "";
  }, []);
  const { sorted, sort, toggle } = useTableSort(grouped, getValue);

  return (
    <section className="w-full border-t border-border bg-surface">
      <header className="flex flex-wrap items-center gap-2 border-b border-border bg-surface px-3 py-2">
        <Badge
          className={
            scan.status === "failed"
              ? "border-danger text-danger"
              : scan.status === "completed"
                ? "border-success text-success"
                : ""
          }
        >
          {scanStatusLabel(scan.status)}
        </Badge>
        <span className="text-sm font-medium">
          {scan.match_count.toLocaleString()} matching rule
          {scan.match_count === 1 ? "" : "s"}
        </span>
        {grouped.length !== scan.match_count ? (
          <span className="text-muted">
            ({grouped.length.toLocaleString()} unique)
          </span>
        ) : null}
        {artifactName ? (
          <span className="font-mono text-muted" title={artifactName}>
            {artifactName}
          </span>
        ) : (
          <span className="text-muted">Memory image</span>
        )}
        {scan.finished_at || scan.started_at ? (
          <span className="ml-auto text-muted">
            <TimestampText value={scan.finished_at ?? scan.started_at} />
          </span>
        ) : null}
      </header>
      {typeof scan.error?.message === "string" ? (
        <p className="px-3 py-2 text-danger">{scan.error.message}</p>
      ) : null}
      {sorted.length === 0 ? (
        scan.status === "completed" ? (
          <p className="px-3 py-3 text-muted">No signature matches.</p>
        ) : null
      ) : (
        <div>
          <table className="app-result-table w-full table-fixed text-center">
            <colgroup>
              <col className="w-[44%]" />
              <col className="w-[12%]" />
              <col className="w-[32%]" />
              <col className="w-[12%]" />
            </colgroup>
            <thead className="sticky top-0 z-10 bg-surface-2 text-muted">
              <tr>
                <SortableTh
                  label="Rule"
                  column="rule"
                  sort={sort}
                  onToggle={toggle}
                />
                <SortableTh
                  label="Level"
                  column="level"
                  sort={sort}
                  onToggle={toggle}
                />
                <SortableTh
                  label="Namespace"
                  column="namespace"
                  sort={sort}
                  onToggle={toggle}
                />
                <SortableTh
                  label="Hits"
                  column="hits"
                  sort={sort}
                  onToggle={toggle}
                />
              </tr>
            </thead>
            <tbody>
              {sorted.map((row) => (
                <tr key={row.key} className="border-t border-border/40">
                  <td className="px-2 py-1.5 font-medium break-all">
                    {row.rule_name}
                  </td>
                  <td className="px-2 py-1.5">
                    {row.level ? (
                      <Badge className={findingSeverityClass(row.level)}>
                        {formatRuleLevel(row.level)}
                      </Badge>
                    ) : (
                      <span className="text-muted">—</span>
                    )}
                  </td>
                  <td className="px-2 py-1.5 font-mono text-muted break-all">
                    {row.namespace || "—"}
                  </td>
                  <td className="px-2 py-1.5 tabular-nums">
                    {row.hits.toLocaleString()}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

type GroupedRule = {
  key: string;
  rule_name: string;
  namespace: string | null;
  level: string | null;
  hits: number;
};

function groupMatches(matches: YaraMatch[]): GroupedRule[] {
  const map = new Map<string, GroupedRule>();
  for (const match of matches) {
    const key = `${match.namespace ?? ""}::${match.rule_name}`;
    const existing = map.get(key);
    if (existing) {
      existing.hits += 1;
      if (!existing.level) existing.level = ruleLevelFromMeta(match.meta);
    } else {
      map.set(key, {
        key,
        rule_name: match.rule_name,
        namespace: match.namespace,
        level: ruleLevelFromMeta(match.meta),
        hits: 1,
      });
    }
  }
  return [...map.values()];
}
