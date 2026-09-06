import { useCallback, useEffect, useState, type ReactNode } from "react";
import { open } from "@tauri-apps/plugin-dialog";
import { Sidebar } from "./components/Sidebar";
import { TopBar } from "./components/TopBar";
import { OverviewView } from "./components/OverviewView";
import { ProcessExplorer } from "./components/ProcessExplorer";
import { ProcessDeepDiveView } from "./components/ProcessDeepDiveView";
import { JobsView } from "./components/JobsView";
import {
  FindingsView,
  ModulesView,
  NetworkView,
} from "./components/InvestigationViews";
import { IocsView, SearchView } from "./components/SearchIocViews";
import { MemoryExplorerView } from "./components/MemoryExplorerView";
import { TimelineView } from "./components/TimelineArtifactsViews";
import { ArtifactsView } from "./components/ArtifactsView";
import { PluginExplorerView } from "./components/PluginExplorerView";
import { ExportView } from "./components/ExportView";
import { PlaceholderView } from "./components/PlaceholderView";
import { engineCall, ensureAppPaths, EngineClientError } from "./lib/api";
import type {
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

  const setErr = useCallback((msg: string) => {
    setError({ message: msg });
  }, []);

  useEffect(() => {
    void (async () => {
      try {
        await ensureAppPaths();
        const listed = await engineCall<{ items: Evidence[] }>("evidence.list");
        if (listed.items[0]) setEvidence(listed.items[0]);
      } catch (err) {
        if (err instanceof EngineClientError) setError(err.payload);
        else setError({ message: String(err) });
      }
    })();
  }, []);

  const refreshEvidenceViews = useCallback(async (ev: Evidence) => {
    const ov = await engineCall<Overview>("overview.get", {
      evidence_id: ev.id,
    });
    setOverview(ov);
    setEvidence(ov.evidence);
    const procs = await engineCall<{ items: ProcessRow[]; total: number }>(
      "processes.list",
      { evidence_id: ev.id, limit: 10000, offset: 0 },
    );
    setProcesses(procs.items);
    setProcessTotal(procs.total);
  }, []);

  useEffect(() => {
    if (!evidence) return;
    void (async () => {
      try {
        await refreshEvidenceViews(evidence);
      } catch (err) {
        if (err instanceof EngineClientError) setError(err.payload);
      }
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [evidence?.id]);

  // Poll active jobs; refresh data when they finish
  useEffect(() => {
    if (activeJobIds.length === 0) return;
    const timer = window.setInterval(() => {
      void (async () => {
        const still: string[] = [];
        let finished = false;
        for (const id of activeJobIds) {
          try {
            const j = await engineCall<Job>("jobs.get", { job_id: id });
            if (j.status === "queued" || j.status === "running") {
              still.push(id);
            } else {
              finished = true;
              if (j.status === "failed" && j.error) {
                const msg =
                  typeof j.error.message === "string"
                    ? j.error.message
                    : "Job failed";
                setError({
                  message: msg,
                  details:
                    typeof j.error.details === "string" ? j.error.details : undefined,
                  suggestion:
                    typeof j.error.suggestion === "string"
                      ? j.error.suggestion
                      : undefined,
                });
              }
            }
          } catch {
            /* ignore transient */
          }
        }
        setActiveJobIds(still);
        setJobTick((t) => t + 1);
        if (finished && evidence) {
          try {
            await refreshEvidenceViews(evidence);
          } catch {
            /* ignore */
          }
        }
      })();
    }, 1500);
    return () => window.clearInterval(timer);
  }, [activeJobIds, evidence, refreshEvidenceViews]);

  const onImport = useCallback(async () => {
    setError(null);
    setBusy(true);
    try {
      const selected = await open({
        multiple: false,
        title: "Select memory image",
        filters: [
          {
            name: "Memory images",
            extensions: ["raw", "dmp", "mem", "vmem", "bin", "img", "lime", "aff4"],
          },
          { name: "All files", extensions: ["*"] },
        ],
      });
      if (!selected || Array.isArray(selected)) {
        setBusy(false);
        return;
      }
      const imported = await engineCall<Evidence>(
        "evidence.import",
        { path: selected },
        600,
      );
      setEvidence(imported);
      setSelectedProcessId(null);
      setNav("overview");
    } catch (err) {
      if (err instanceof EngineClientError) setError(err.payload);
      else setError({ message: String(err) });
    } finally {
      setBusy(false);
    }
  }, []);

  const onAnalyze = useCallback(async () => {
    if (!evidence) return;
    setError(null);
    setBusy(true);
    try {
      const job = await engineCall<Job>("evidence.analyze_basic", {
        evidence_id: evidence.id,
      });
      setActiveJobIds((ids) => [...ids, job.id]);
      setJobTick((t) => t + 1);
      setNav("jobs");
    } catch (err) {
      if (err instanceof EngineClientError) setError(err.payload);
      else setError({ message: String(err) });
    } finally {
      setBusy(false);
    }
  }, [evidence]);

  const onSelectProcess = (p: ProcessRow) => {
    setSelectedProcessId(p.id);
    setNav("process_dive");
  };

  const onJobSubmitted = (job: Job) => {
    setActiveJobIds((ids) => [...ids, job.id]);
    setJobTick((t) => t + 1);
    setNav("jobs");
  };

  const onExportJobSubmitted = (job: Job) => {
    setActiveJobIds((ids) => [...ids, job.id]);
    setJobTick((t) => t + 1);
  };

  let body: ReactNode;
  switch (nav) {
    case "overview":
      body = <OverviewView data={overview} />;
      break;
    case "processes":
      body = (
        <ProcessExplorer
          items={processes}
          total={processTotal}
          loading={busy}
          selectedId={selectedProcessId}
          onSelect={onSelectProcess}
        />
      );
      break;
    case "process_dive":
      body =
        selectedProcessId && evidence ? (
          <ProcessDeepDiveView
            processId={selectedProcessId}
            evidenceId={evidence.id}
            onOpenProcess={(id) => {
              setSelectedProcessId(id);
            }}
            onError={setErr}
            onJobSubmitted={onJobSubmitted}
          />
        ) : (
          <div className="p-4 text-sm text-muted">
            Select a process in the Processes view.
          </div>
        );
      break;
    case "network":
      body = <NetworkView evidenceId={evidence?.id ?? null} onError={setErr} />;
      break;
    case "modules":
      body = <ModulesView evidenceId={evidence?.id ?? null} onError={setErr} />;
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
          onJobSubmitted={onJobSubmitted}
          onError={setErr}
          refreshToken={jobTick}
        />
      );
      break;
    case "findings":
      body = <FindingsView evidenceId={evidence?.id ?? null} onError={setErr} />;
      break;
    case "iocs":
      body = <IocsView evidenceId={evidence?.id ?? null} onError={setErr} />;
      break;
    case "search":
      body = (
        <SearchView
          evidenceId={evidence?.id ?? null}
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
          refreshToken={jobTick}
        />
      );
      break;
    case "artifacts":
      body = (
        <ArtifactsView
          evidenceId={evidence?.id ?? null}
          onError={setErr}
          onJobSubmitted={onJobSubmitted}
          refreshToken={jobTick}
        />
      );
      break;
    case "jobs":
      body = (
        <JobsView
          evidenceId={evidence?.id ?? null}
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
          onJobSubmitted={onJobSubmitted}
          onOpenProcess={(id) => {
            setSelectedProcessId(id);
            setNav("process_dive");
          }}
          refreshToken={jobTick}
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
        />
      );
      break;
    default:
      body = <PlaceholderView section={nav} />;
  }

  return (
    <div className="flex h-full min-h-0 flex-col">
      <TopBar
        busy={busy || activeJobIds.length > 0}
        error={error}
        onImport={onImport}
        onAnalyze={onAnalyze}
        canAnalyze={!!evidence}
      />
      <div className="flex min-h-0 flex-1">
        <Sidebar
          active={nav}
          onSelect={setNav}
          evidenceLabel={evidence?.filename}
        />
        <main className="min-w-0 flex-1 overflow-auto bg-background">{body}</main>
      </div>
    </div>
  );
}
