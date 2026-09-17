import { useCallback, useEffect, useMemo, useState } from "react";
import { Info } from "lucide-react";
import { engineCall, EngineClientError } from "../lib/api";
import { CHECKING_DETAIL, UNAVAILABLE_DETAIL } from "../lib/analysisCapabilities";
import { useCapabilityStatus } from "../lib/capabilityStatus";
import { TimestampText } from "../lib/datetime";
import type { Artifact, Job, YaraScanBundle } from "../lib/types";
import { Badge } from "./ui/badge";
import { Button } from "./ui/button";
import { ImportEvidenceState } from "./CoverageStatus";
import { SegmentedControl } from "./ui/segmented";

type TabId = "memory" | "extracted";

export function SignaturesView({
  evidenceId,
  onError,
  onJobSubmitted,
  refreshToken,
  jobsRunning = false,
  activeJobKind = null,
}: {
  evidenceId: string | null;
  onError: (m: string) => void;
  onJobSubmitted?: (job: Job) => void;
  refreshToken?: number | string;
  jobsRunning?: boolean;
  activeJobKind?: string | null;
}) {
  const caps = useCapabilityStatus();
  const yara = caps.yara;
  const yaraRow = caps.rows.signatureDetection;
  const [tab, setTab] = useState<TabId>("memory");
  const [bundles, setBundles] = useState<YaraScanBundle[]>([]);
  const [peFiles, setPeFiles] = useState<Artifact[]>([]);
  const [submitting, setSubmitting] = useState<"memory" | "extracted" | null>(null);

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
    () => bundles.filter((b) => (b.scan.target_kind || "artifact") === "memory"),
    [bundles],
  );
  const extractedBundles = useMemo(
    () => bundles.filter((b) => (b.scan.target_kind || "artifact") === "artifact"),
    [bundles],
  );

  const available = yaraRow.kind === "available";
  const checking = yaraRow.kind === "checking";
  const actionsLocked = jobsRunning || submitting != null;

  const queue = async (method: "yara.scan_memory" | "yara.scan_extracted", kind: "memory" | "extracted") => {
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

  const scanBusy =
    submitting === "memory" ||
    activeJobKind === "yara_memory_scan" ||
    (actionsLocked && tab === "memory");
  const extractedBusy =
    submitting === "extracted" ||
    activeJobKind === "yara_extracted_scan" ||
    activeJobKind === "yara_artifact_scan" ||
    (actionsLocked && tab === "extracted");

  return (
    <div className="flex h-full flex-col text-xs">
      <div className="flex flex-wrap items-center gap-2 border-b border-border px-3 py-2">
        <div className="text-sm font-semibold">Signatures</div>
        <SegmentedControl
          ariaLabel="Signature scan targets"
          value={tab}
          onChange={setTab}
          options={[
            { id: "memory", label: "Memory Image" },
            { id: "extracted", label: "Extracted Files" },
          ]}
        />
      </div>
      <div className="min-h-0 flex-1 overflow-auto p-4">
        {checking ? (
          <p className="text-sm text-muted">{CHECKING_DETAIL}</p>
        ) : !available ? (
          <p className="text-sm text-muted">
            {yara?.reason || UNAVAILABLE_DETAIL}
            {yara?.suggestion ? ` ${yara.suggestion}` : ""}
          </p>
        ) : (
          <>
            <div className="analysis-profile-note mb-4 inline-flex w-fit items-center gap-2 rounded-md px-2.5 py-2 text-xs leading-none">
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
                description="Scan the memory image using YARA rules."
                buttonLabel={
                  submitting === "memory" || activeJobKind === "yara_memory_scan"
                    ? "Scanning…"
                    : "Scan Memory Image"
                }
                disabled={scanBusy}
                extra={yara?.status_summary}
                onScan={() => void queue("yara.scan_memory", "memory")}
                empty="No memory-image scans yet."
                bundles={memoryBundles}
              />
            ) : (
              <ScanPanel
                title="Extracted Files"
                description="Scan extracted PE files using YARA rules."
                buttonLabel={
                  submitting === "extracted" ||
                  activeJobKind === "yara_extracted_scan"
                    ? "Scanning…"
                    : "Scan Extracted Files"
                }
                disabled={extractedBusy || peFiles.length === 0}
                extra={
                  peFiles.length === 0
                    ? "No extracted PE files yet. Run Extracted Files from Carved Data first."
                    : `${peFiles.length} extracted PE file${peFiles.length === 1 ? "" : "s"} available.`
                }
                onScan={() => void queue("yara.scan_extracted", "extracted")}
                empty="No extracted-file scans yet."
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

function ScanPanel({
  title,
  description,
  buttonLabel,
  disabled,
  extra,
  onScan,
  empty,
  bundles,
  peById,
}: {
  title: string;
  description: string;
  buttonLabel: string;
  disabled: boolean;
  extra?: string;
  onScan: () => void;
  empty: string;
  bundles: YaraScanBundle[];
  peById?: Map<string, Artifact>;
}) {
  return (
    <div className="max-w-3xl space-y-4">
      <div>
        <h3 className="text-sm font-semibold">{title}</h3>
        <p className="mt-1 text-sm text-muted">{description}</p>
        {extra ? <p className="mt-1 text-xs text-muted">{extra}</p> : null}
        <Button size="sm" className="mt-3" disabled={disabled} onClick={onScan}>
          {buttonLabel}
        </Button>
      </div>
      {bundles.length === 0 ? (
        <p className="text-sm text-muted">{empty}</p>
      ) : (
        <div className="space-y-2">
          {bundles.map((b) => (
            <ScanResultCard key={b.scan.id} bundle={b} peById={peById} />
          ))}
        </div>
      )}
    </div>
  );
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
    scan.artifact_id && peById ? peById.get(scan.artifact_id)?.filename : undefined;
  return (
    <div className="rounded-md border border-border bg-surface p-3">
      <div className="mb-1 flex flex-wrap items-center gap-2">
        <Badge>{scan.status}</Badge>
        <span>
          {scan.match_count} match{scan.match_count === 1 ? "" : "es"}
        </span>
        {artifactName ? (
          <span className="font-mono text-muted">{artifactName}</span>
        ) : null}
        {scan.started_at ? (
          <span className="text-muted">
            <TimestampText value={scan.started_at} />
          </span>
        ) : null}
      </div>
      {typeof scan.error?.message === "string" ? (
        <p className="text-danger">{scan.error.message}</p>
      ) : null}
      {bundle.matches.map((m) => (
        <div key={m.id} className="mt-1 border-t border-border/50 pt-1">
          <div className="font-medium">{m.rule_name}</div>
          {m.namespace ? <div className="text-muted">{m.namespace}</div> : null}
        </div>
      ))}
    </div>
  );
}
