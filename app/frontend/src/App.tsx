import { useCallback, useEffect, useRef, useState, type ReactNode } from "react";
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
import { engineCall, ensureAppPaths, EngineClientError } from "./lib/api";
import { startCapabilityChecks } from "./lib/capabilityStatus";
import {
  coverageFromOverview,
  coverageItem,
  coverageProcessListReady,
  coverageRefreshKey,
} from "./lib/analysisCoverage";
import { loadAppMeta } from "./lib/appMeta";
import { firstDroppedFilePath, subscribeFileDrop } from "./lib/fileDrop";
import {
  evidenceFromImportJob,
  isActiveJobStatus,
  isNotMemoryImageError,
  jobErrorPayload,
  notMemoryImageToast,
} from "./lib/analysisOptions";
import { jobProgressPercentText } from "./lib/jobDisplay";
import {
  applyPreferences,
  persistPreferences,
  readPreferences,
  type FontSizePx,
  type ThemeId,
} from "./lib/preferences";
import { DisplayTimeZoneProvider } from "./lib/datetime";
import type {
  AnalysisProfileCatalog,
  AppErrorPayload,
  Evidence,
  Job,
  NavId,
  Overview,
  ProcessRow,
} from "./lib/types";
import "./styles.css";

export default function App() {
  const [nav, setNav] = useState<NavId>("overview");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<AppErrorPayload | null>(null);
  const [evidence, setEvidence] = useState<Evidence | null>(null);
  const [overview, setOverview] = useState<Overview | null>(null);
  const [processes, setProcesses] = useState<ProcessRow[]>([]);
  const [processTotal, setProcessTotal] = useState(0);
  const [selectedProcessId, setSelectedProcessId] = useState<string | null>(null);
  const [jobTick, setJobTick] = useState(0);
  const [activeJobIds, setActiveJobIds] = useState<string[]>([]);
  const [runningJob, setRunningJob] = useState<Job | null>(null);
  const [importJob, setImportJob] = useState<Job | null>(null);
  const [nowMs, setNowMs] = useState(() => Date.now());
  const [importElapsedOriginMs, setImportElapsedOriginMs] = useState<number | null>(
    null,
  );
  const [analysisOpen, setAnalysisOpen] = useState(false);
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

  const presentError = useCallback(
    (payload: AppErrorPayload) => {
      if (isNotMemoryImageError(payload)) {
        showToast(notMemoryImageToast(payload), 8000);
        setError(null);
        return;
      }
      setError(payload);
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
    setRunningJob(job);
    setJobTick((t) => t + 1);
  }, []);

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
    startCapabilityChecks();
  }, []);

  useEffect(() => {
    void (async () => {
      try {
        await ensureAppPaths();
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
      setError(null);
      const imported = evidenceFromImportJob(job);
      if (!imported) return;
      setSelectedProcessId(null);
      setProcesses([]);
      setProcessTotal(0);
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
      setError(null);
    },
    [endImportWatch, importStillCurrent],
  );

  // Poll active jobs; refresh coverage while they run, and full views when they finish
  useEffect(() => {
    if (activeJobIds.length === 0 && !importJobId) return;
    const fast = !!importJobId;
    const timer = window.setInterval(() => {
      void (async () => {
        const still: string[] = [];
        let finished = false;
        let latest: Job | null = null;
        const tickGen = importGenerationRef.current;
        const watchedImportId = importJobId;
        const ids = watchedImportId
          ? Array.from(new Set([...activeJobIds, watchedImportId]))
          : activeJobIds;
        for (const id of ids) {
          try {
            const j = await engineCall<Job>("jobs.get", { job_id: id });
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
                latest = j;
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
              latest = j;
            } else {
              finished = true;
              if (j.status === "failed" && j.error) {
                presentError(jobErrorPayload(j, "Job failed"));
              }
            }
          } catch {
            /* ignore transient */
          }
        }
        setActiveJobIds((prev) => {
          const next = still.filter((id) => id !== watchedImportId);
          if (prev.length === next.length && prev.every((id, i) => id === next[i])) {
            return prev;
          }
          return next;
        });
        setRunningJob(latest);
        setJobTick((t) => t + 1);
        if (evidence) {
          try {
            if (finished) await refreshEvidenceViews(evidence);
            else if (still.length > 0) {
              await refreshOverview(evidence);
              const procs = await engineCall<{ items: ProcessRow[]; total: number }>(
                "processes.list",
                { evidence_id: evidence.id, limit: 10000, offset: 0 },
              );
              setProcesses(procs.items);
              setProcessTotal(procs.total);
            }
          } catch {
            /* ignore */
          }
        }
      })();
    }, fast ? 400 : 800);
    return () => window.clearInterval(timer);
  }, [
    activeJobIds,
    applyCancelledImport,
    applyCompletedImport,
    applyFailedImport,
    evidence,
    importJobId,
    importStillCurrent,
    presentError,
    refreshEvidenceViews,
    refreshOverview,
  ]);

  const importFromPath = useCallback(async (path: string) => {
    if (importStartRef.current || importingRef.current) {
      return;
    }
    importStartRef.current = true;
    const generation = ++importGenerationRef.current;
    setError(null);
    setActiveJobIds([]);
    setRunningJob(null);
    setJobTick((t) => t + 1);
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
      setRunningJob(job);
      setNowMs(Date.now());
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
    setError(null);
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
        setError({
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
  }, [importFromPath]);

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
    setEvidence(null);
    setOverview(null);
    setProcesses([]);
    setProcessTotal(0);
    setSelectedProcessId(null);
    setError(null);
    setNav("overview");
  }, []);

  const onAnalyze = useCallback(async () => {
    if (!evidence) return;
    setError(null);
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
      setError(null);
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

  const onJobSubmitted = (job: Job) => {
    trackJob(job);
    setNav("jobs");
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
  const jobsPercent = jobProgressPercentText(
    runningJob && isActiveJobStatus(runningJob.status) ? runningJob : importJob,
    nowMs,
  );
  const coverage = coverageFromOverview(overview);
  const coverageTick = coverageRefreshKey(coverage);
  const analysisBusy = jobsRunning && !importing;

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
          data={overview}
          importing={importing}
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
            onBack={() => setNav("processes")}
            onOpenProcess={(id) => {
              setSelectedProcessId(id);
            }}
            onError={setErr}
            onJobSubmitted={onPluginJobSubmitted}
            coverage={coverage}
            refreshToken={coverageTick}
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
          refreshToken={coverageTick}
          onOpenProcess={(id) => {
            setSelectedProcessId(id);
            setNav("process_dive");
          }}
          onJobSubmitted={onPluginJobSubmitted}
          jobsRunning={jobsRunning}
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
          activeJobKind={runningJob?.kind ?? null}
        />
      );
      break;
    case "signatures":
      body = (
        <SignaturesView
          evidenceId={evidence?.id ?? null}
          onError={setErr}
          onJobSubmitted={onJobSubmitted}
          refreshToken={`${coverageTick}:${jobTick}`}
          jobsRunning={jobsRunning}
          activeJobKind={runningJob?.kind ?? null}
        />
      );
      break;
    case "jobs":
      body = (
        <JobsView
          evidenceId={evidence?.id ?? null}
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
        error={error}
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
            setNav(id);
          }}
          evidenceLabel={evidence?.filename}
          coverage={coverage}
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
      <StatusToast message={toast} />
    </div>
    </DisplayTimeZoneProvider>
  );
}
