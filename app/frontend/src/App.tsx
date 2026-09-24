import { useCallback, useEffect, useLayoutEffect, useRef, useState, type ReactNode } from "react";
import { open } from "@tauri-apps/plugin-dialog";
import { Sidebar, IMPORTING_NAV_HINT, navLockedDuringImport, navSectionTitle } from "./components/Sidebar";
import { TopBar } from "./components/TopBar";
import { OverviewView } from "./components/OverviewView";
import { ProcessExplorer } from "./components/ProcessExplorer";
import { ProcessDeepDiveView } from "./components/ProcessDeepDiveView";
import { JobsView } from "./components/JobsView";
import {
  FindingsView,
  ModulesView,
} from "./components/InvestigationViews";
import { NetworkView } from "./components/NetworkView";
import { IocsView, SearchView } from "./components/SearchIocViews";
import { MemoryExplorerView } from "./components/MemoryExplorerView";
import { TimelineView } from "./components/TimelineArtifactsViews";
import { ArtifactsView } from "./components/ArtifactsView";
import { SignaturesView } from "./components/SignaturesView";
import { PluginExplorerView } from "./components/PluginExplorerView";
import { ExportView } from "./components/ExportView";
import { PlaceholderView } from "./components/PlaceholderView";
import { SettingsView } from "./components/SettingsView";
import { AboutView } from "./components/AboutView";
import { DropOverlay } from "./components/DropOverlay";
import { CoverageEmptyState, ImportEvidenceState } from "./components/CoverageStatus";
import { ImportProgressBanner } from "./components/ImportProgressBanner";
import { StatusToast, TOAST_FADE_MS, useStatusToast } from "./components/StatusToast";
import { AnalysisOptionsDialog } from "./components/AnalysisOptionsDialog";
import { KernelSymbolsDialog } from "./components/KernelSymbolsDialog";
import { engineCall, ensureAppPaths, EngineClientError } from "./lib/api";
import {
  coverageShownInView,
  coverageFromJobResult,
  coverageFromOverview,
  coverageItem,
  coverageProcessListReady,
  coverageRefreshKey,
  coverageWaitingForPdb,
} from "./lib/analysisCoverage";
import { loadAppMeta } from "./lib/appMeta";
import { firstDroppedFilePath, subscribeFileDrop } from "./lib/fileDrop";
import {
  evidenceFromImportJob,
  formatUserError,
  isActiveJobStatus,
  isNotMemoryImageError,
  jobErrorPayload,
  jobPercent,
  kernelSymbolNeedFromError,
  notMemoryImageToast,
} from "./lib/analysisOptions";
import { averageJobProgressPercentText } from "./lib/jobDisplay";
import {
  applyPreferences,
  persistPreferences,
  readPreferences,
  type FontSizePx,
  type ThemeId,
} from "./lib/preferences";
import { DisplayTimeZoneProvider } from "./lib/datetime";
import { notifyMainWindowReady } from "./lib/mainWindowReady";
import type {
  AnalysisProfileCatalog,
  AppErrorPayload,
  Evidence,
  Job,
  KernelSymbolNeed,
  NavId,
  Overview,
  ProcessRow,
} from "./lib/types";
import "./styles.css";

const ERROR_TOAST_MS = 5000;

function retryPayloadFromJob(job: Job): { method: string; params: Record<string, unknown> } {
  if (job.kind === "analysis_profile") {
    return { method: "analysis.run", params: { ...(job.params || {}) } };
  }
  if (job.kind === "process_recommended") {
    return { method: "process.analyze_recommended", params: { ...(job.params || {}) } };
  }
  return {
    method: "jobs.submit",
    params: {
      kind: job.kind,
      evidence_id: job.evidence_id,
      process_id: job.process_id,
      pid: job.pid,
      params: job.params || {},
    },
  };
}

export default function App() {
  const [nav, setNav] = useState<NavId>("overview");
  const [busy, setBusy] = useState(false);
  const [evidence, setEvidence] = useState<Evidence | null>(null);
  const [overview, setOverview] = useState<Overview | null>(null);
  const [processes, setProcesses] = useState<ProcessRow[]>([]);
  const [processTotal, setProcessTotal] = useState(0);
  const [memoryShownCount, setMemoryShownCount] = useState(0);
  const [timelineShownCount, setTimelineShownCount] = useState<number | null>(null);
  const [artifactsShownCount, setArtifactsShownCount] = useState<number | null>(null);
  const [selectedProcessId, setSelectedProcessId] = useState<string | null>(null);
  const [jobTick, setJobTick] = useState(0);
  const [activeJobIds, setActiveJobIds] = useState<string[]>([]);
  const [activeJobs, setActiveJobs] = useState<Job[]>([]);
  const [importJob, setImportJob] = useState<Job | null>(null);
  const [nowMs, setNowMs] = useState(() => Date.now());
  const [importElapsedOriginMs, setImportElapsedOriginMs] = useState<number | null>(
    null,
  );
  const [analysisOpen, setAnalysisOpen] = useState(false);
  const [kernelNeed, setKernelNeed] = useState<KernelSymbolNeed | null>(null);
  const [kernelBusy, setKernelBusy] = useState(false);
  const [kernelDownloadPercent, setKernelDownloadPercent] = useState<number | null>(
    null,
  );
  const [kernelFetchJobId, setKernelFetchJobId] = useState<string | null>(null);
  const kernelFetchLockRef = useRef(false);
  const [analysisCatalog, setAnalysisCatalog] =
    useState<AnalysisProfileCatalog | null>(null);
  const [prefs, setPrefs] = useState(readPreferences);
  const [appMeta, setAppMeta] = useState({ name: "", version: "" });
  const [dropActive, setDropActive] = useState(false);
  const { toast, showToast, dismissToast } = useStatusToast();
  const importingRef = useRef(false);
  const importStartRef = useRef(false);
  const importGenerationRef = useRef(0);
  const importJobIdRef = useRef<string | null>(null);
  const analysisPromptAfterImportRef = useRef(false);
  const pendingRetryRef = useRef<{ method: string; params: Record<string, unknown> } | null>(
    null,
  );
  const lastProcessCountRef = useRef<number | null>(null);

  useLayoutEffect(() => {
    notifyMainWindowReady();
  }, []);

  const presentError = useCallback(
    (payload: AppErrorPayload) => {
      if (isNotMemoryImageError(payload)) {
        showToast(notMemoryImageToast(payload), 8000);
        return;
      }
      showToast(formatUserError(payload), ERROR_TOAST_MS);
    },
    [showToast],
  );

  const setErr = useCallback((msg: string) => {
    presentError({ message: msg });
  }, [presentError]);

  const updatePrefs = useCallback(
    (patch: { theme?: ThemeId; fontSize?: FontSizePx; timeZone?: string }) => {
      setPrefs((cur) => {
        const next = {
          theme: patch.theme ?? cur.theme,
          fontSize: patch.fontSize ?? cur.fontSize,
          timeZone: patch.timeZone ?? cur.timeZone,
        };
        persistPreferences(next);
        applyPreferences(next);
        return next;
      });
    },
    [],
  );

  const trackJob = useCallback((job: Job) => {
    setActiveJobIds((ids) => (ids.includes(job.id) ? ids : [...ids, job.id]));
    setActiveJobs((jobs) => {
      const index = jobs.findIndex((item) => item.id === job.id);
      if (index >= 0) {
        const next = jobs.slice();
        next[index] = job;
        return next;
      }
      return [...jobs, job];
    });
    setJobTick((t) => t + 1);
  }, []);

  const retryPendingAnalysis = useCallback(async () => {
    const pending = pendingRetryRef.current;
    if (!pending) return;
    setKernelNeed(null);
    setKernelDownloadPercent(null);
    setKernelFetchJobId(null);
    kernelFetchLockRef.current = false;
    setBusy(true);
    try {
      const job = await engineCall<Job>(pending.method, pending.params);
      trackJob(job);
      setNav("jobs");
    } catch (err) {
      if (err instanceof EngineClientError) presentError(err.payload);
      else presentError({ message: String(err) });
    } finally {
      setBusy(false);
    }
  }, [presentError, trackJob]);

  const handleFailedJob = useCallback(
    (job: Job) => {
      const payload = jobErrorPayload(job, "Job failed");
      const need = kernelSymbolNeedFromError(payload);
      if (need && job.kind !== "kernel_symbols_fetch") {
        pendingRetryRef.current = retryPayloadFromJob(job);
        setActiveJobIds([]);
        setActiveJobs([]);
        setAnalysisOpen(false);
        setNav("overview");
        setKernelNeed(need);
        void engineCall("jobs.reset_visible")
          .catch(() => undefined)
          .finally(() => setJobTick((t) => t + 1));
        return;
      }
      presentError(payload);
    },
    [presentError],
  );

  const returnToImportedReady = useCallback(() => {
    analysisPromptAfterImportRef.current = false;
    pendingRetryRef.current = null;
    setKernelNeed(null);
    setKernelBusy(false);
    setKernelDownloadPercent(null);
    setKernelFetchJobId(null);
    kernelFetchLockRef.current = false;
    setActiveJobIds([]);
    setActiveJobs([]);
    setAnalysisOpen(false);
    setNav("overview");
    void engineCall("jobs.reset_visible")
      .catch(() => undefined)
      .finally(() => setJobTick((t) => t + 1));
  }, []);

  useEffect(() => {
    if (!kernelFetchJobId) return;
    let stopped = false;
    let finishing = false;
    let inFlight = false;
    let timer = 0;
    const poll = async () => {
      if (stopped || finishing || inFlight) return;
      inFlight = true;
      try {
        const job = await engineCall<Job>("jobs.get", { job_id: kernelFetchJobId });
        if (stopped || finishing) return;
        if (job.status === "completed") {
          finishing = true;
          window.clearInterval(timer);
          setKernelDownloadPercent(100);
          await new Promise((resolve) => window.setTimeout(resolve, 500));
          if (stopped) return;
          await retryPendingAnalysis();
          return;
        }
        const pct = jobPercent(job);
        if (pct != null) {
          const next = Math.max(0, Math.min(100, pct));
          setKernelDownloadPercent((prev) =>
            prev == null ? next : Math.max(prev, next),
          );
        }
        if (isActiveJobStatus(job.status)) return;
        const failedDownload = job.status !== "cancelled" && job.status !== "canceled";
        const payload = failedDownload
          ? jobErrorPayload(job, "Kernel symbols download failed")
          : null;
        returnToImportedReady();
        if (payload) presentError(payload);
      } catch (err) {
        if (stopped || finishing) return;
        returnToImportedReady();
        if (err instanceof EngineClientError) presentError(err.payload);
        else presentError({ message: String(err) });
      } finally {
        inFlight = false;
      }
    };
    void poll();
    timer = window.setInterval(() => void poll(), 500);
    return () => {
      stopped = true;
      window.clearInterval(timer);
    };
  }, [kernelFetchJobId, presentError, retryPendingAnalysis, returnToImportedReady]);

  useEffect(() => {
    applyPreferences(prefs);
  }, [prefs]);

  useEffect(() => {
    void (async () => {
      try {
        setAppMeta(await loadAppMeta());
      } catch {
        /* version/name stay empty until Tauri app metadata is available */
      }
    })();
  }, []);

  useEffect(() => {
    void (async () => {
      try {
        await ensureAppPaths();
        void engineCall("plugins.warmup", {}).catch(() => undefined);
        // Fresh launch: do not restore the previous case into the UI.
        // Evidence remains in the local database until the analyst imports again.
      } catch (err) {
        if (err instanceof EngineClientError) presentError(err.payload);
        else presentError({ message: String(err) });
      }
    })();
  }, []);

  const refreshOverview = useCallback(async (ev: Evidence) => {
    const ov = await engineCall<Overview>("overview.get", {
      evidence_id: ev.id,
    });
    setOverview(ov);
    setEvidence(ov.evidence);
  }, []);

  const refreshEvidenceViews = useCallback(async (ev: Evidence) => {
    await refreshOverview(ev);
    const procs = await engineCall<{ items: ProcessRow[]; total: number }>(
      "processes.list",
      { evidence_id: ev.id, limit: 10000, offset: 0 },
    );
    setProcesses(procs.items);
    setProcessTotal(procs.total);
    lastProcessCountRef.current = procs.total;
  }, [refreshOverview]);

  useEffect(() => {
    if (!evidence) return;
    void (async () => {
      try {
        await refreshEvidenceViews(evidence);
      } catch (err) {
        if (err instanceof EngineClientError) presentError(err.payload);
      }
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [evidence?.id]);

  const loadCatalog = useCallback(async () => {
    const catalog = await engineCall<AnalysisProfileCatalog>("analysis.profiles");
    setAnalysisCatalog(catalog);
    return catalog;
  }, []);

  const importJobId = importJob?.id ?? null;

  useEffect(() => {
    if (activeJobIds.length === 0 && !importJobId) return;
    const t = window.setInterval(() => setNowMs(Date.now()), 1000);
    return () => window.clearInterval(t);
  }, [activeJobIds.length, importJobId]);

  const endImportWatch = useCallback(() => {
    importGenerationRef.current += 1;
    importJobIdRef.current = null;
    importStartRef.current = false;
    importingRef.current = false;
    setImportJob(null);
    setImportElapsedOriginMs(null);
  }, []);

  const importStillCurrent = useCallback((generation: number, jobId?: string | null) => {
    if (importGenerationRef.current !== generation) return false;
    if (jobId && importJobIdRef.current !== jobId) return false;
    return true;
  }, []);

  const applyCompletedImport = useCallback(
    async (job: Job, generation: number) => {
      if (!importStillCurrent(generation, job.id)) return;
      endImportWatch();
      const imported = evidenceFromImportJob(job);
      if (!imported) return;
      setSelectedProcessId(null);
      setProcesses([]);
      setProcessTotal(0);
      lastProcessCountRef.current = null;
      setMemoryShownCount(0);
      setTimelineShownCount(null);
      setArtifactsShownCount(null);
      setOverview(null);
      setEvidence(imported);
      setNav("overview");
      try {
        await refreshEvidenceViews(imported);
        await loadCatalog();
        analysisPromptAfterImportRef.current = true;
        setAnalysisOpen(true);
      } catch (err) {
        if (err instanceof EngineClientError) presentError(err.payload);
        else presentError({ message: String(err) });
      }
    },
    [endImportWatch, importStillCurrent, loadCatalog, presentError, refreshEvidenceViews],
  );

  const applyFailedImport = useCallback(
    (job: Job, generation: number) => {
      if (!importStillCurrent(generation, job.id)) return;
      endImportWatch();
      presentError(jobErrorPayload(job, "Import failed"));
    },
    [endImportWatch, importStillCurrent, presentError],
  );

  const applyCancelledImport = useCallback(
    (generation: number, jobId?: string | null) => {
      if (!importStillCurrent(generation, jobId)) return;
      endImportWatch();
    },
    [endImportWatch, importStillCurrent],
  );

  // Poll active jobs; refresh coverage while they run, and full views when they finish
  const jobPollBusyRef = useRef(false);
  useEffect(() => {
    if (activeJobIds.length === 0 && !importJobId) return;
    const fast = !!importJobId;
    let cancelled = false;
    const poll = () => {
      if (jobPollBusyRef.current) return;
      jobPollBusyRef.current = true;
      void (async () => {
        try {
          const still: string[] = [];
          let finished = false;
          const found: Job[] = [];
          const tickGen = importGenerationRef.current;
          const watchedImportId = importJobId;
          const ids = watchedImportId
            ? Array.from(new Set([...activeJobIds, watchedImportId]))
            : activeJobIds;
          for (const id of ids) {
            try {
              const j = await engineCall<Job>("jobs.get", { job_id: id });
              if (cancelled) return;
              if (watchedImportId && j.id === watchedImportId) {
                if (!importStillCurrent(tickGen, watchedImportId)) {
                  continue;
                }
                if (isActiveJobStatus(j.status)) {
                  if (!importStillCurrent(tickGen, watchedImportId)) {
                    continue;
                  }
                  setImportJob((prev) =>
                    importStillCurrent(tickGen, watchedImportId) ? j : prev,
                  );
                  still.push(id);
                  continue;
                }
                if (j.status === "completed") {
                  await applyCompletedImport(j, tickGen);
                } else if (j.status === "failed") {
                  applyFailedImport(j, tickGen);
                } else {
                  applyCancelledImport(tickGen, j.id);
                }
                continue;
              }
              if (isActiveJobStatus(j.status)) {
                still.push(id);
                found.push(j);
              } else {
                finished = true;
                if (j.kind === "kernel_symbols_fetch") {
                  continue;
                }
                if (j.status === "failed" && j.error) {
                  handleFailedJob(j);
                }
              }
            } catch {
              /* ignore transient */
            }
          }
          if (cancelled) return;
          setActiveJobIds((prev) => {
            const next = still.filter((id) => id !== watchedImportId);
            if (prev.length === next.length && prev.every((id, i) => id === next[i])) {
              return prev;
            }
            return next;
          });
          setActiveJobs(found);
          const liveCoverage = found
            .map((job) => coverageFromJobResult(job.result))
            .find((item): item is NonNullable<typeof item> => Boolean(item));
          if (liveCoverage) {
            setOverview((prev) =>
              prev
                ? {
                    ...prev,
                    coverage: liveCoverage,
                    process_count:
                      liveCoverage.items.processes?.count ?? prev.process_count,
                  }
                : prev,
            );
            const processCount = liveCoverage.items.processes?.count;
            if (
              evidence &&
              processCount != null &&
              processCount !== lastProcessCountRef.current
            ) {
              lastProcessCountRef.current = processCount;
              try {
                const procs = await engineCall<{ items: ProcessRow[]; total: number }>(
                  "processes.list",
                  { evidence_id: evidence.id, limit: 10000, offset: 0 },
                );
                if (!cancelled) {
                  setProcesses(procs.items);
                  setProcessTotal(procs.total);
                }
              } catch {
                /* ignore transient */
              }
            }
          }
          if (finished) {
            setJobTick((t) => t + 1);
          }
          if (evidence && finished) {
            try {
              await refreshEvidenceViews(evidence);
            } catch {
              /* ignore */
            }
          }
        } finally {
          jobPollBusyRef.current = false;
        }
      })();
    };
    poll();
    const timer = window.setInterval(poll, fast ? 500 : 1500);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [
    activeJobIds,
    applyCancelledImport,
    applyCompletedImport,
    applyFailedImport,
    evidence,
    handleFailedJob,
    importJobId,
    importStillCurrent,
    presentError,
    refreshEvidenceViews,
  ]);

  const importFromPath = useCallback(async (path: string) => {
    if (importStartRef.current || importingRef.current) {
      return;
    }
    importStartRef.current = true;
    const generation = ++importGenerationRef.current;
    setActiveJobIds([]);
    setActiveJobs([]);
    setNav("jobs");
    try {
      const job = await engineCall<Job>("evidence.import", { path });
      if (!importStillCurrent(generation)) {
        if (job.id) {
          void engineCall("jobs.cancel", { job_id: job.id }).catch(() => undefined);
        }
        return;
      }
      importJobIdRef.current = job.id;
      importingRef.current = true;
      setImportElapsedOriginMs(Date.now());
      setImportJob(job);
      setNowMs(Date.now());
      setJobTick((t) => t + 1);
    } catch (err) {
      if (importStillCurrent(generation)) {
        importStartRef.current = false;
        importingRef.current = false;
        if (err instanceof EngineClientError) presentError(err.payload);
        else presentError({ message: String(err) });
      }
    } finally {
      if (importGenerationRef.current === generation) {
        importStartRef.current = false;
      }
    }
  }, [importStillCurrent, presentError]);

  const onImport = useCallback(async () => {
    if (toast) {
      dismissToast();
      await new Promise<void>((resolve) => {
        window.setTimeout(resolve, TOAST_FADE_MS);
      });
    }
    try {
      const selected = await open({
        multiple: false,
        title: "Select Memory Image",
        filters: [
          {
            name: "Memory images",
            extensions: ["raw", "dmp", "mem", "vmem", "bin", "img", "lime", "aff4"],
          },
          { name: "All files", extensions: ["*"] },
        ],
      });
      if (!selected || Array.isArray(selected)) {
        return;
      }
      await importFromPath(selected);
    } catch (err) {
      if (err instanceof EngineClientError) presentError(err.payload);
      else presentError({ message: String(err) });
    }
  }, [dismissToast, importFromPath, presentError, toast]);

  useEffect(() => {
    let disposed = false;
    let unlisten: (() => void) | undefined;
    let leaveTimer: number | undefined;
    const clearLeaveTimer = () => {
      if (leaveTimer !== undefined) {
        window.clearTimeout(leaveTimer);
        leaveTimer = undefined;
      }
    };
    void subscribeFileDrop((kind, paths) => {
      if (kind === "enter" || kind === "over") {
        clearLeaveTimer();
        setDropActive(true);
        return;
      }
      if (kind === "leave") {
        clearLeaveTimer();
        leaveTimer = window.setTimeout(() => setDropActive(false), 80);
        return;
      }
      clearLeaveTimer();
      setDropActive(false);
      const path = firstDroppedFilePath(paths);
      if (!path) {
        console.info("[dumplyzer:file-drop] drop without filesystem path; waiting for native bridge");
        return;
      }
      if (importingRef.current || importStartRef.current) {
        presentError({
          message: "An import is already in progress.",
          suggestion: "Wait for it to finish, or cancel it from the banner.",
        });
        return;
      }
      console.info("[dumplyzer:file-drop] importFromPath", path);
      void importFromPath(path);
    }).then((fn) => {
      if (disposed) fn();
      else unlisten = fn;
    });
    return () => {
      disposed = true;
      clearLeaveTimer();
      unlisten?.();
    };
  }, [importFromPath, presentError]);

  const onCancelImport = useCallback(async () => {
    const jobId = importJobIdRef.current;
    if (!jobId) return;
    const generation = importGenerationRef.current;
    try {
      const updated = await engineCall<Job>("jobs.cancel", { job_id: jobId });
      if (!importStillCurrent(generation, jobId)) return;
      if (updated.status === "completed") {
        await applyCompletedImport(updated, generation);
        return;
      }
      if (updated.status === "failed") {
        applyFailedImport(updated, generation);
        return;
      }
      applyCancelledImport(generation, jobId);
    } catch (err) {
      if (!importStillCurrent(generation, jobId)) return;
      if (err instanceof EngineClientError) presentError(err.payload);
      else presentError({ message: String(err) });
    }
  }, [applyCancelledImport, applyCompletedImport, applyFailedImport, importStillCurrent, presentError]);

  const discardUnanalyzedImport = useCallback(() => {
    analysisPromptAfterImportRef.current = false;
    pendingRetryRef.current = null;
    setKernelNeed(null);
    setKernelBusy(false);
    setKernelDownloadPercent(null);
    setKernelFetchJobId(null);
    kernelFetchLockRef.current = false;
    setActiveJobIds([]);
    setActiveJobs([]);
    setEvidence(null);
    setOverview(null);
    setProcesses([]);
    setProcessTotal(0);
    lastProcessCountRef.current = null;
    setMemoryShownCount(0);
    setTimelineShownCount(null);
    setArtifactsShownCount(null);
    setSelectedProcessId(null);
    setNav("overview");
    void engineCall("jobs.reset_visible")
      .catch(() => undefined)
      .finally(() => setJobTick((t) => t + 1));
  }, []);

  const onAnalyze = useCallback(async () => {
    if (!evidence) return;
    try {
      await loadCatalog();
      analysisPromptAfterImportRef.current = false;
      setAnalysisOpen(true);
    } catch (err) {
      if (err instanceof EngineClientError) presentError(err.payload);
      else presentError({ message: String(err) });
    }
  }, [evidence, loadCatalog, presentError]);

  const onRunAnalysis = useCallback(
    async (profile: "full" | "recommended" | "custom", capabilities: string[]) => {
      if (!evidence) return;
      setBusy(true);
      try {
        const selected = processes.find((p) => p.id === selectedProcessId);
        const job = await engineCall<Job>("analysis.run", {
          evidence_id: evidence.id,
          profile,
          capabilities,
          process_id: selected?.id ?? null,
          pid: selected?.pid ?? null,
        });
        analysisPromptAfterImportRef.current = false;
        setAnalysisOpen(false);
        trackJob(job);
        setNav("jobs");
      } catch (err) {
        if (err instanceof EngineClientError) presentError(err.payload);
        else presentError({ message: String(err) });
      } finally {
        setBusy(false);
      }
    },
    [evidence, processes, selectedProcessId, trackJob, presentError],
  );

  const onSelectProcess = (p: ProcessRow) => {
    setSelectedProcessId(p.id);
    setNav("process_dive");
  };

  const onPluginJobSubmitted = (job: Job) => {
    trackJob(job);
  };

  const onExportJobSubmitted = (job: Job) => {
    trackJob(job);
  };

  const importing = importStartRef.current || importJobIdRef.current != null;
  importingRef.current = importing;
  useEffect(() => {
    if (importing && navLockedDuringImport(nav)) {
      setNav("jobs");
    }
  }, [importing, nav]);
  const jobsRunning =
    activeJobIds.length > 0 ||
    Boolean(importJob && isActiveJobStatus(importJob.status));
  const jobsPercent = averageJobProgressPercentText(
    [
      ...activeJobs,
      ...(importJob && isActiveJobStatus(importJob.status) ? [importJob] : []),
    ],
    nowMs,
  );
  const waitingForPdb = kernelNeed != null;
  const coverage = coverageWaitingForPdb(coverageFromOverview(overview), waitingForPdb);
  const coverageTick = coverageRefreshKey(coverage);
  const sidebarCoverage = coverage
    ? {
        ...coverage,
        items: {
          ...coverage.items,
          memory_vad:
            coverageShownInView(coverageItem(coverage, "memory_vad"), memoryShownCount) ??
            coverageItem(coverage, "memory_vad"),
          timeline:
            timelineShownCount != null && timelineShownCount > 0
              ? coverageShownInView(
                  coverageItem(coverage, "timeline"),
                  timelineShownCount,
                ) ?? coverageItem(coverage, "timeline")
              : coverageItem(coverage, "timeline"),
          artifacts:
            artifactsShownCount != null && artifactsShownCount > 0
              ? coverageShownInView(
                  coverageItem(coverage, "artifacts"),
                  artifactsShownCount,
                ) ?? coverageItem(coverage, "artifacts")
              : coverageItem(coverage, "artifacts"),
        },
      }
    : coverage;
  const analysisBusy = jobsRunning && !importing;
  const overviewForView =
    overview && waitingForPdb && coverage
      ? { ...overview, coverage }
      : overview;

  let body: ReactNode;
  if (importing && navLockedDuringImport(nav)) {
    body = (
      <ImportEvidenceState
        title={navSectionTitle(nav)}
        message={IMPORTING_NAV_HINT}
      />
    );
  } else {
  switch (nav) {
    case "overview":
      body = (
        <OverviewView
          data={overviewForView}
          importing={importing}
          waitingForPdb={waitingForPdb}
          onImport={() => void onImport()}
        />
      );
      break;
    case "processes":
      body = (
        <ProcessExplorer
          evidenceId={evidence?.id ?? null}
          items={processes}
          total={processTotal}
          loading={false}
          selectedId={selectedProcessId}
          onSelect={onSelectProcess}
          coverage={coverageItem(coverage, "processes")}
          analysisCoverage={coverage}
        />
      );
      break;
    case "process_dive": {
      const processesCov = coverageItem(coverage, "processes");
      if (selectedProcessId && evidence) {
        body = (
          <ProcessDeepDiveView
            processId={selectedProcessId}
            evidenceId={evidence.id}
            onBack={() => {
              setSelectedProcessId(null);
              setNav("processes");
            }}
            onOpenProcess={(id) => {
              setSelectedProcessId(id);
            }}
            onError={setErr}
            onJobSubmitted={onPluginJobSubmitted}
            coverage={coverage}
            refreshToken={coverageTick}
            nowMs={nowMs}
            activeJobs={activeJobs}
          />
        );
      } else if (!evidence) {
        body = <ImportEvidenceState title="Process Deep Dive" />;
      } else if (!coverageProcessListReady(coverage, processes.length)) {
        body = (
          <CoverageEmptyState
            item={processesCov}
            title="Process Deep Dive"
            inProgressDetail="Process data is still being collected."
            analyzedZeroDetail="Process analysis completed and found no processes."
            notAnalyzedDetail="Run analysis, then select a process in the Processes view."
            failedDetail="Process analysis failed."
          />
        );
      } else {
        body = (
          <ImportEvidenceState
            title="Process Deep Dive"
            message="Select a process in the Processes view."
          />
        );
      }
      break;
    }
    case "network":
      body = (
        <NetworkView
          evidenceId={evidence?.id ?? null}
          onError={setErr}
          coverage={coverageItem(coverage, "network")}
          artifactCoverage={coverageItem(coverage, "network_artifacts")}
          analysisCoverage={coverage}
          refreshToken={`${coverageTick}:${jobTick}`}
          onOpenProcess={(id) => {
            setSelectedProcessId(id);
            setNav("process_dive");
          }}
          onJobSubmitted={onPluginJobSubmitted}
          jobsRunning={jobsRunning}
          activeJobs={activeJobs}
          nowMs={nowMs}
        />
      );
      break;
    case "modules":
      body = (
        <ModulesView
          evidenceId={evidence?.id ?? null}
          onError={setErr}
          coverage={coverageItem(coverage, "modules")}
          refreshToken={coverageTick}
          onOpenProcess={(id) => {
            setSelectedProcessId(id);
            setNav("process_dive");
          }}
        />
      );
      break;
    case "memory":
      body = (
        <MemoryExplorerView
          evidenceId={evidence?.id ?? null}
          processes={processes}
          selectedProcessId={selectedProcessId}
          onSelectProcess={(id) => {
            setSelectedProcessId(id);
            setNav("process_dive");
          }}
          onJobSubmitted={onPluginJobSubmitted}
          onError={setErr}
          refreshToken={coverageTick}
          coverage={coverageItem(coverage, "memory_vad")}
          activeJobs={activeJobs}
          onShownCountChange={setMemoryShownCount}
        />
      );
      break;
    case "findings":
      body = (
        <FindingsView
          evidenceId={evidence?.id ?? null}
          onError={setErr}
          coverage={coverageItem(coverage, "findings")}
          analysisCoverage={coverage}
          refreshToken={coverageTick}
          onOpenProcess={(id) => {
            setSelectedProcessId(id);
            setNav("process_dive");
          }}
        />
      );
      break;
    case "iocs":
      body = (
        <IocsView
          evidenceId={evidence?.id ?? null}
          onError={setErr}
          coverage={coverageItem(coverage, "iocs")}
          analysisCoverage={coverage}
          refreshToken={coverageTick}
        />
      );
      break;
    case "search":
      body = (
        <SearchView
          evidenceId={evidence?.id ?? null}
          coverage={coverage}
          onOpenProcess={(id) => {
            setSelectedProcessId(id);
            setNav("process_dive");
          }}
          onError={setErr}
        />
      );
      break;
    case "timeline":
      body = (
        <TimelineView
          evidenceId={evidence?.id ?? null}
          onOpenProcess={(id) => {
            setSelectedProcessId(id);
            setNav("process_dive");
          }}
          onError={setErr}
          refreshToken={coverageTick}
          coverage={coverageItem(coverage, "timeline")}
          analysisCoverage={coverage}
          onShownCountChange={setTimelineShownCount}
          onCoverageRefresh={() => {
            if (evidence) void refreshOverview(evidence);
          }}
        />
      );
      break;
    case "artifacts":
      body = (
        <ArtifactsView
          evidenceId={evidence?.id ?? null}
          onError={setErr}
          onJobSubmitted={onPluginJobSubmitted}
          refreshToken={coverageTick}
          coverage={coverageItem(coverage, "artifacts")}
          jobsRunning={jobsRunning}
          activeJobs={activeJobs}
          nowMs={nowMs}
          onShownCountChange={setArtifactsShownCount}
        />
      );
      break;
    case "signatures":
      body = (
        <SignaturesView
          evidenceId={evidence?.id ?? null}
          onError={setErr}
          onJobSubmitted={onPluginJobSubmitted}
          refreshToken={`${coverageTick}:${jobTick}`}
          jobsRunning={jobsRunning}
          activeJobs={activeJobs}
          nowMs={nowMs}
        />
      );
      break;
    case "jobs":
      body = (
        <JobsView
          evidenceFilename={evidence?.filename ?? null}
          refreshToken={jobTick}
          onError={setErr}
        />
      );
      break;
    case "plugins":
      body = (
        <PluginExplorerView
          evidence={evidence}
          onError={setErr}
          onJobSubmitted={onPluginJobSubmitted}
          onOpenProcess={(id) => {
            setSelectedProcessId(id);
            setNav("process_dive");
          }}
          refreshToken={jobTick}
          analysisBusy={analysisBusy}
        />
      );
      break;
    case "export":
      body = (
        <ExportView
          evidenceId={evidence?.id ?? null}
          refreshToken={jobTick}
          onError={setErr}
          onJobSubmitted={onExportJobSubmitted}
          analysisBusy={analysisBusy}
          coverage={coverage}
        />
      );
      break;
    case "settings":
      body = (
        <SettingsView
          theme={prefs.theme}
          fontSize={prefs.fontSize}
          timeZone={prefs.timeZone}
          onTheme={(theme) => updatePrefs({ theme })}
          onFontSize={(fontSize) => updatePrefs({ fontSize })}
          onTimeZone={(timeZone) => updatePrefs({ timeZone })}
        />
      );
      break;
    case "about":
      body = <AboutView appName={appMeta.name} appVersion={appMeta.version} />;
      break;
    default:
      body = <PlaceholderView section={nav} />;
  }
  }

  return (
    <DisplayTimeZoneProvider timeZone={prefs.timeZone}>
    <div className="relative flex h-full min-h-0 flex-col">
      {dropActive && <DropOverlay importing={importing} />}
      <TopBar
        importing={importing}
        analyzing={busy || jobsRunning}
        appVersion={appMeta.version}
        onImport={() => void onImport()}
        onAnalyze={() => void onAnalyze()}
        canAnalyze={!!evidence && !importing && !jobsRunning}
      />
      {importJob && importJobIdRef.current === importJob.id && (
        <ImportProgressBanner
          job={importJob}
          elapsedStartMs={importElapsedOriginMs}
          nowMs={nowMs}
          onCancel={() => void onCancelImport()}
        />
      )}
      <div className="flex min-h-0 min-w-0 flex-1">
        <Sidebar
          active={nav}
          onSelect={(id) => {
            if (importing && navLockedDuringImport(id)) return;
            if (id === "processes") setSelectedProcessId(null);
            setNav(id);
          }}
          evidenceLabel={evidence?.filename}
          coverage={sidebarCoverage}
          jobsRunning={jobsRunning}
          jobsPercent={jobsPercent}
          importing={importing}
        />
        <main className="flex min-h-0 min-w-0 flex-1 flex-col overflow-auto bg-background">{body}</main>
      </div>
      <AnalysisOptionsDialog
        open={analysisOpen}
        catalog={analysisCatalog}
        busy={busy}
        timeZone={prefs.timeZone}
        onTimeZoneChange={(timeZone) => updatePrefs({ timeZone })}
        onClose={() => {
          setAnalysisOpen(false);
          if (analysisPromptAfterImportRef.current) {
            discardUnanalyzedImport();
          }
        }}
        onRun={(profile, capabilities) => {
          updatePrefs({ timeZone: prefs.timeZone });
          void onRunAnalysis(profile, capabilities);
        }}
      />
      <KernelSymbolsDialog
        open={kernelNeed != null}
        need={kernelNeed}
        busy={kernelBusy || busy}
        downloadPercent={kernelDownloadPercent}
        onClose={() => {
          if (kernelFetchJobId) {
            void engineCall("jobs.cancel", { job_id: kernelFetchJobId }).catch(
              () => undefined,
            );
          }
          returnToImportedReady();
        }}
        onDownload={() => {
          if (!kernelNeed || kernelBusy || kernelFetchLockRef.current) return;
          kernelFetchLockRef.current = true;
          setKernelBusy(true);
          setKernelDownloadPercent(0);
          void engineCall<Job>("symbols.fetch", {
            evidence_id: evidence?.id ?? null,
            pdb_name: kernelNeed.pdb_name,
            guid: kernelNeed.guid,
            age: kernelNeed.age,
          })
            .then((job) => {
              setKernelFetchJobId(job.id);
            })
            .catch((err) => {
              if (err instanceof EngineClientError) presentError(err.payload);
              else presentError({ message: String(err) });
              returnToImportedReady();
            });
        }}
        onImported={(path) => {
          if (!kernelNeed) return;
          setKernelBusy(true);
          void engineCall("symbols.import_file", {
            path,
            pdb_name: kernelNeed.pdb_name,
            guid: kernelNeed.guid,
            age: kernelNeed.age,
          })
            .then(() => retryPendingAnalysis())
            .catch((err) => {
              if (err instanceof EngineClientError) presentError(err.payload);
              else presentError({ message: String(err) });
            })
            .finally(() => setKernelBusy(false));
        }}
      />
      <StatusToast message={toast} />
    </div>
    </DisplayTimeZoneProvider>
  );
}
