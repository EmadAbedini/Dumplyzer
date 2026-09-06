import { useCallback, useEffect, useState } from "react";
import { engineCall, EngineClientError } from "../lib/api";
import type {
  Artifact,
  Job,
  MalUnpackScanBundle,
  MalUnpackStatus,
  PeSieveScanBundle,
  PeSieveStatus,
  YaraScanBundle,
  YaraStatus,
} from "../lib/types";
import { Badge } from "./ui/badge";
import { Button } from "./ui/button";

export function ArtifactsView({
  evidenceId,
  onError,
  onJobSubmitted,
  refreshToken,
}: {
  evidenceId: string | null;
  onError: (m: string) => void;
  onJobSubmitted?: (job: Job) => void;
  refreshToken?: number;
}) {
  const [items, setItems] = useState<Artifact[]>([]);
  const [detail, setDetail] = useState<Artifact | null>(null);
  const [yaraStatus, setYaraStatus] = useState<YaraStatus | null>(null);
  const [yaraBundles, setYaraBundles] = useState<YaraScanBundle[]>([]);
  const [peSieveStatus, setPeSieveStatus] = useState<PeSieveStatus | null>(null);
  const [peSieveBundles, setPeSieveBundles] = useState<PeSieveScanBundle[]>([]);
  const [malUnpackStatus, setMalUnpackStatus] = useState<MalUnpackStatus | null>(null);
  const [malUnpackBundles, setMalUnpackBundles] = useState<MalUnpackScanBundle[]>([]);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    if (!evidenceId) return;
    try {
      const res = await engineCall<{ items: Artifact[] }>("artifacts.list", {
        evidence_id: evidenceId,
      });
      setItems(res.items);
      try {
        const st = await engineCall<YaraStatus>("yara.status");
        setYaraStatus(st);
      } catch {
        /* optional */
      }
      try {
        const st = await engineCall<PeSieveStatus>("pe_sieve.status");
        setPeSieveStatus(st);
      } catch {
        /* optional */
      }
      try {
        const st = await engineCall<MalUnpackStatus>("mal_unpack.status");
        setMalUnpackStatus(st);
      } catch {
        /* optional */
      }
    } catch (e) {
      onError(e instanceof EngineClientError ? e.message : String(e));
    }
  }, [evidenceId, onError]);

  useEffect(() => {
    void load();
  }, [load, refreshToken]);

  const openDetail = async (id: string) => {
    try {
      const a = await engineCall<Artifact>("artifacts.get", { artifact_id: id });
      setDetail(a);
      setYaraStatus(a.yara_status ?? yaraStatus);
      setYaraBundles(a.yara_scans ?? []);
      setPeSieveStatus(a.pe_sieve_status ?? peSieveStatus);
      setPeSieveBundles(a.pe_sieve_scans ?? []);
      setMalUnpackStatus(a.mal_unpack_status ?? malUnpackStatus);
      setMalUnpackBundles(a.mal_unpack_scans ?? []);
    } catch (e) {
      onError(e instanceof EngineClientError ? e.message : String(e));
    }
  };

  const scanYara = async () => {
    if (!detail || !evidenceId) return;
    setBusy(true);
    try {
      const job = await engineCall<Job>("yara.scan_artifact", {
        artifact_id: detail.id,
        evidence_id: evidenceId,
        process_id: detail.process_id ?? undefined,
        pid: detail.pid ?? undefined,
      });
      onJobSubmitted?.(job);
    } catch (e) {
      onError(e instanceof EngineClientError ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  const refreshYara = async () => {
    if (!detail) return;
    try {
      const res = await engineCall<{ items: YaraScanBundle[] }>(
        "yara.scans_for_artifact",
        { artifact_id: detail.id },
      );
      setYaraBundles(res.items);
    } catch (e) {
      onError(e instanceof EngineClientError ? e.message : String(e));
    }
  };

  const refreshMalUnpack = async () => {
    if (!detail) return;
    try {
      const [st, res] = await Promise.all([
        engineCall<MalUnpackStatus>("mal_unpack.status"),
        engineCall<{ items: MalUnpackScanBundle[] }>("mal_unpack.scans_for_artifact", {
          artifact_id: detail.id,
        }),
      ]);
      setMalUnpackStatus(st);
      setMalUnpackBundles(res.items);
    } catch (e) {
      onError(e instanceof EngineClientError ? e.message : String(e));
    }
  };

  const refreshPeSieve = async () => {
    if (!detail) return;
    try {
      const [st, res] = await Promise.all([
        engineCall<PeSieveStatus>("pe_sieve.status"),
        engineCall<{ items: PeSieveScanBundle[] }>("pe_sieve.scans_for_artifact", {
          artifact_id: detail.id,
        }),
      ]);
      setPeSieveStatus(st);
      setPeSieveBundles(res.items);
    } catch (e) {
      onError(e instanceof EngineClientError ? e.message : String(e));
    }
  };

  if (!evidenceId) {
    return <div className="p-4 text-sm text-muted">Import evidence first.</div>;
  }

  return (
    <div className="flex h-full min-h-0 text-xs">
      <div className="min-w-0 flex-1 overflow-auto">
        <div className="flex items-center gap-2 border-b border-border px-3 py-2">
          <div className="text-sm font-semibold">Artifacts</div>
          <Button size="sm" variant="outline" onClick={() => void load()}>
            Refresh
          </Button>
          <span className="text-muted">
            Stored under controlled app data; never auto-executed
          </span>
          {peSieveStatus && (
            <Badge
              className={
                peSieveStatus.available
                  ? "border-success text-success"
                  : "border-muted text-muted"
              }
            >
              PE-sieve{" "}
              {peSieveStatus.available
                ? peSieveStatus.pe_sieve_version || "available"
                : "unavailable"}
            </Badge>
          )}
          {malUnpackStatus && (
            <Badge
              className={
                malUnpackStatus.available
                  ? "border-success text-success"
                  : "border-muted text-muted"
              }
            >
              mal_unpack{" "}
              {malUnpackStatus.available
                ? malUnpackStatus.mal_unpack_version || "available"
                : "unavailable"}
            </Badge>
          )}
        </div>
        <table className="w-full text-left">
          <thead className="sticky top-0 bg-surface-2 text-muted">
            <tr>
              <th className="px-2 py-1.5">Filename</th>
              <th className="px-2 py-1.5">SHA-256</th>
              <th className="px-2 py-1.5">Size</th>
              <th className="px-2 py-1.5">Type</th>
              <th className="px-2 py-1.5">PID</th>
              <th className="px-2 py-1.5">Method</th>
              <th className="px-2 py-1.5">Extracted</th>
            </tr>
          </thead>
          <tbody>
            {items.map((a) => (
              <tr
                key={a.id}
                className="cursor-pointer border-t border-border/40 hover:bg-surface-2/50"
                onClick={() => void openDetail(a.id)}
              >
                <td className="px-2 py-1 font-mono">{a.filename}</td>
                <td className="max-w-[14rem] truncate px-2 py-1 font-mono">{a.sha256}</td>
                <td className="px-2 py-1 font-mono">{a.size_bytes.toLocaleString()}</td>
                <td className="px-2 py-1">{a.file_type ?? "—"}</td>
                <td className="px-2 py-1 font-mono">{a.pid ?? "—"}</td>
                <td className="px-2 py-1 text-muted">{a.extraction_method}</td>
                <td className="px-2 py-1 font-mono">{a.extracted_at}</td>
              </tr>
            ))}
            {items.length === 0 && (
              <tr>
                <td colSpan={7} className="px-3 py-6 text-muted">
                  No artifacts. Extract a VAD region from Memory explorer.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
      <aside className="w-[26rem] shrink-0 overflow-auto border-l border-border p-3">
        {!detail ? (
          <div className="text-muted">Select an artifact for provenance, YARA, PE-sieve, and mal_unpack.</div>
        ) : (
          <div className="space-y-3">
            <div className="font-semibold">Provenance</div>
            <div className="break-all font-mono text-[11px]">{detail.sha256}</div>
            <div className="text-muted">{detail.notes}</div>
            <div className="text-muted">Chain</div>
            <ol className="list-decimal space-y-1 pl-4">
              {(detail.provenance_chain ?? []).map((s, i) => (
                <li key={i} className="font-mono text-[11px]">
                  {String(s.step)}: {JSON.stringify(s)}
                </li>
              ))}
            </ol>
            <div className="break-all text-[11px] text-muted">Path: {detail.stored_path}</div>
            <div className="text-[11px] text-muted">
              Tool: {detail.tool_name} {detail.tool_version}
            </div>

            <div className="border-t border-border pt-3">
              <div className="mb-2 font-semibold">YARA</div>
              {!yaraStatus ? (
                <div className="text-muted">Checking YARA…</div>
              ) : !yaraStatus.available ? (
                <div className="space-y-1 text-muted">
                  <div>YARA unavailable</div>
                  <div>{yaraStatus.reason}</div>
                  <div>{yaraStatus.suggestion}</div>
                </div>
              ) : (
                <div className="space-y-2">
                  <div className="text-muted">
                    Version {yaraStatus.yara_version} · {yaraStatus.rule_file_count} rule
                    file(s)
                  </div>
                  {yaraStatus.default_rules_dir && (
                    <div className="break-all font-mono text-[11px] text-muted">
                      Rules: {yaraStatus.default_rules_dir}
                    </div>
                  )}
                  <div className="flex gap-2">
                    <Button size="sm" onClick={() => void scanYara()} disabled={busy}>
                      {busy ? "Queuing…" : "Scan with YARA"}
                    </Button>
                    <Button size="sm" variant="outline" onClick={() => void refreshYara()}>
                      Refresh results
                    </Button>
                  </div>
                  <div className="text-[11px] text-muted">
                    Scans the extracted artifact file only (not a live process). Job runs in
                    background.
                  </div>
                  {yaraBundles.length === 0 ? (
                    <div className="text-muted">No YARA scans yet for this artifact.</div>
                  ) : (
                    yaraBundles.map((b) => (
                      <div
                        key={b.scan.id}
                        className="rounded border border-border bg-surface p-2"
                      >
                        <div className="mb-1 flex flex-wrap items-center gap-2">
                          <Badge
                            className={
                              b.scan.status === "failed"
                                ? "border-danger text-danger"
                                : b.scan.status === "completed"
                                  ? "border-success text-success"
                                  : ""
                            }
                          >
                            {b.scan.status}
                          </Badge>
                          <span>
                            {b.scan.match_count} match
                            {b.scan.match_count === 1 ? "" : "es"}
                          </span>
                          <span className="text-muted">{b.scan.yara_version}</span>
                        </div>
                        {b.scan.status === "completed" && b.scan.match_count === 0 && (
                          <div className="text-muted">No matches</div>
                        )}
                        {b.scan.error && (
                          <div className="text-danger">
                            {String(
                              (b.scan.error as { message?: string }).message ??
                                JSON.stringify(b.scan.error),
                            )}
                          </div>
                        )}
                        {b.matches.map((m) => (
                          <div key={m.id} className="mt-1 border-t border-border/50 pt-1">
                            <div className="font-medium">{m.rule_name}</div>
                            {m.namespace && (
                              <div className="text-muted">ns: {m.namespace}</div>
                            )}
                            {m.rule_source && (
                              <div className="truncate text-[11px] text-muted">
                                {m.rule_source}
                              </div>
                            )}
                            {m.strings.slice(0, 5).map((s, idx) => (
                              <div key={idx} className="font-mono text-[11px] text-muted">
                                {s.identifier}
                                {s.instances?.[0]?.offset != null
                                  ? ` @ ${s.instances[0].offset}`
                                  : ""}
                              </div>
                            ))}
                          </div>
                        ))}
                      </div>
                    ))
                  )}
                </div>
              )}
            </div>

            <div className="border-t border-border pt-3">
              <div className="mb-2 font-semibold">PE-sieve</div>
              {!peSieveStatus ? (
                <div className="text-muted">Checking PE-sieve…</div>
              ) : (
                <div className="space-y-2">
                  <div className="flex flex-wrap items-center gap-2">
                    <Badge className={peSieveStateClass(peSieveStatus.ui_state)}>
                      {peSieveStateLabel(
                        peSieveStatus.available
                          ? "unsupported_target"
                          : "unavailable",
                      )}
                    </Badge>
                    <span className="text-muted">
                      {peSieveStatus.available
                        ? `Version ${peSieveStatus.pe_sieve_version ?? "unknown"}`
                        : "Provider unavailable"}
                    </span>
                  </div>
                  {peSieveStatus.executable_path ? (
                    <div className="break-all font-mono text-[11px] text-muted">
                      EXE: {peSieveStatus.executable_path}
                    </div>
                  ) : (
                    <div className="break-all font-mono text-[11px] text-muted">
                      Tools dir: {peSieveStatus.tools_dir ?? "—"}
                    </div>
                  )}
                  <div className="text-[11px] text-muted">
                    Supported target types: live Windows process (/pid only). Extracted
                    artifacts and memory-image PIDs are not valid PE-sieve targets.
                  </div>
                  {!peSieveStatus.available && (
                    <div className="space-y-1 text-muted">
                      <div>{peSieveStatus.reason}</div>
                      <div>{peSieveStatus.suggestion}</div>
                    </div>
                  )}
                  <div className="text-muted">
                    {peSieveStatus.unsupported_target_explanation}
                  </div>
                  <div className="flex gap-2">
                    <Button size="sm" disabled title="PE-sieve cannot scan extracted artifacts">
                      Scan with PE-sieve
                    </Button>
                    <Button size="sm" variant="outline" onClick={() => void refreshPeSieve()}>
                      Refresh results
                    </Button>
                  </div>
                  <div className="text-[11px] text-muted">
                    The scan control is disabled so a dump PID is never sent to a live
                    process scanner. No malware score is assigned.
                  </div>
                  {peSieveBundles.length === 0 ? (
                    <div className="text-muted">No PE-sieve records for this artifact.</div>
                  ) : (
                    peSieveBundles.map((b) => (
                      <div
                        key={b.scan.id}
                        className="rounded border border-border bg-surface p-2"
                      >
                        <div className="mb-1 flex flex-wrap items-center gap-2">
                          <Badge className={peSieveStateClass(b.scan.ui_state)}>
                            {peSieveStateLabel(b.scan.ui_state)}
                          </Badge>
                          <span className="text-muted">{b.scan.pe_sieve_version}</span>
                        </div>
                        {b.scan.interpretation && (
                          <div className="text-muted">
                            {String(
                              (b.scan.interpretation as { summary?: string }).summary ??
                                (b.scan.interpretation as { notes?: string }).notes ??
                                "",
                            )}
                          </div>
                        )}
                        {b.scan.error && (
                          <div className="text-danger">
                            {String(
                              (b.scan.error as { message?: string }).message ??
                                JSON.stringify(b.scan.error),
                            )}
                          </div>
                        )}
                        {b.outputs.length > 0 && (
                          <div className="mt-1 border-t border-border/50 pt-1">
                            <div className="text-muted">Generated artifacts</div>
                            {b.outputs.map((o) => (
                              <div key={o.id} className="font-mono text-[11px]">
                                {o.role}: {o.filename}{" "}
                                {o.sha256 ? o.sha256.slice(0, 12) : ""}{" "}
                                {o.dump_mode ? `(${o.dump_mode})` : ""}
                              </div>
                            ))}
                          </div>
                        )}
                        {Array.isArray(
                          (b.scan.observed as { scan_report?: { module_scans?: unknown[] } })
                            ?.scan_report?.module_scans,
                        ) &&
                          (
                            (
                              b.scan.observed as {
                                scan_report?: {
                                  module_scans?: Array<{
                                    scan_type?: string;
                                    module?: string;
                                    status?: number;
                                  }>;
                                };
                              }
                            ).scan_report?.module_scans ?? []
                          )
                            .slice(0, 8)
                            .map((m, idx) => (
                              <div key={idx} className="font-mono text-[11px] text-muted">
                                {m.scan_type} {m.module} status={String(m.status)}
                              </div>
                            ))}
                      </div>
                    ))
                  )}
                </div>
              )}
            </div>

            <div className="border-t border-border pt-3">
              <div className="mb-2 font-semibold">mal_unpack</div>
              {!malUnpackStatus ? (
                <div className="text-muted">Checking mal_unpack…</div>
              ) : (
                <div className="space-y-2">
                  <div className="flex flex-wrap items-center gap-2">
                    <Badge className={malUnpackStateClass(malUnpackStatus.ui_state)}>
                      {malUnpackStateLabel(
                        malUnpackStatus.available
                          ? "unsupported_target"
                          : "unavailable",
                      )}
                    </Badge>
                    <span className="text-muted">
                      {malUnpackStatus.available
                        ? `Version ${malUnpackStatus.mal_unpack_version ?? "unknown"}`
                        : "Provider unavailable"}
                    </span>
                  </div>
                  {malUnpackStatus.executable_path ? (
                    <div className="break-all font-mono text-[11px] text-muted">
                      EXE: {malUnpackStatus.executable_path}
                    </div>
                  ) : (
                    <div className="break-all font-mono text-[11px] text-muted">
                      Tools dir: {malUnpackStatus.tools_dir ?? "—"}
                    </div>
                  )}
                  <div className="text-[11px] text-muted">
                    Supported MemScope target types: none. Native mal_unpack 1.0
                    target is a PE file passed as /exe and executed. Live processes,
                    memory dumps, VAD regions, and extracted artifacts are not safe
                    unpack targets here.
                  </div>
                  {!malUnpackStatus.available && (
                    <div className="space-y-1 text-muted">
                      <div>{malUnpackStatus.reason}</div>
                      <div>{malUnpackStatus.suggestion}</div>
                    </div>
                  )}
                  <div className="text-muted">
                    {malUnpackStatus.unsupported_target_explanation}
                  </div>
                  <div className="flex gap-2">
                    <Button
                      size="sm"
                      disabled
                      title="mal_unpack executes /exe; MemScope will not unpack artifacts"
                    >
                      Unpack with mal_unpack
                    </Button>
                    <Button size="sm" variant="outline" onClick={() => void refreshMalUnpack()}>
                      Refresh results
                    </Button>
                  </div>
                  <div className="text-[11px] text-muted">
                    The unpack control is disabled so forensic artifacts are never
                    started as processes. Unpacked output is never auto-executed. No
                    malware score is assigned.
                  </div>
                  {malUnpackBundles.length === 0 ? (
                    <div className="text-muted">No mal_unpack records for this artifact.</div>
                  ) : (
                    malUnpackBundles.map((b) => (
                      <div
                        key={b.scan.id}
                        className="rounded border border-border bg-surface p-2"
                      >
                        <div className="mb-1 flex flex-wrap items-center gap-2">
                          <Badge className={malUnpackStateClass(b.scan.ui_state)}>
                            {malUnpackStateLabel(b.scan.ui_state)}
                          </Badge>
                          <span className="text-muted">{b.scan.mal_unpack_version}</span>
                          {b.scan.invoked ? (
                            <span className="text-muted">invoked</span>
                          ) : (
                            <span className="text-muted">not invoked</span>
                          )}
                        </div>
                        {b.scan.interpretation && (
                          <div className="text-muted">
                            {String(
                              (b.scan.interpretation as { summary?: string }).summary ??
                                (b.scan.interpretation as { notes?: string }).notes ??
                                "",
                            )}
                          </div>
                        )}
                        {b.scan.error && (
                          <div className="text-danger">
                            {String(
                              (b.scan.error as { message?: string }).message ??
                                JSON.stringify(b.scan.error),
                            )}
                          </div>
                        )}
                        {b.outputs.length > 0 && (
                          <div className="mt-1 border-t border-border/50 pt-1">
                            <div className="text-muted">Generated artifacts</div>
                            {b.outputs.map((o) => (
                              <div key={o.id} className="font-mono text-[11px]">
                                {o.role}: {o.filename}{" "}
                                {o.sha256 ? o.sha256.slice(0, 12) : ""}{" "}
                                {o.dump_mode ? `(${o.dump_mode})` : ""}
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                    ))
                  )}
                </div>
              )}
            </div>
          </div>
        )}
      </aside>
    </div>
  );
}

function peSieveStateLabel(state: string | null | undefined): string {
  switch (state) {
    case "unavailable":
      return "unavailable";
    case "unsupported_target":
      return "unsupported target";
    case "queued":
      return "queued";
    case "running":
      return "running";
    case "completed_no_findings":
      return "completed / no findings";
    case "completed_indicators":
      return "completed / indicators";
    case "failed":
      return "failed";
    case "cancelled":
      return "cancelled";
    default:
      return state || "unknown";
  }
}

function peSieveStateClass(state: string | null | undefined): string {
  if (state === "failed") return "border-danger text-danger";
  if (state === "completed_indicators") return "border-warning text-warning";
  if (state === "completed_no_findings" || state === "unsupported_target") {
    return "border-success text-success";
  }
  return "";
}

function malUnpackStateLabel(state: string | null | undefined): string {
  switch (state) {
    case "unavailable":
      return "unavailable";
    case "unsupported_target":
      return "unsupported target";
    case "queued":
      return "queued";
    case "running":
      return "running";
    case "completed_no_output":
      return "completed / no output";
    case "completed_output_generated":
      return "completed / output generated";
    case "failed":
      return "failed";
    case "cancelled":
      return "cancelled";
    default:
      return state || "unknown";
  }
}

function malUnpackStateClass(state: string | null | undefined): string {
  if (state === "failed") return "border-danger text-danger";
  if (state === "completed_output_generated") return "border-warning text-warning";
  if (state === "completed_no_output" || state === "unsupported_target") {
    return "border-success text-success";
  }
  return "";
}
