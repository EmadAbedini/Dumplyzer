import { useCallback, useEffect, useState } from "react";
import { open } from "@tauri-apps/plugin-dialog";
import { Sidebar } from "./components/Sidebar";
import { TopBar } from "./components/TopBar";
import { OverviewView } from "./components/OverviewView";
import { ProcessExplorer } from "./components/ProcessExplorer";
import { PlaceholderView } from "./components/PlaceholderView";
import { engineCall, ensureAppPaths, EngineClientError } from "./lib/api";
import type {
  AppErrorPayload,
  Evidence,
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

  useEffect(() => {
    void (async () => {
      try {
        await ensureAppPaths();
        const listed = await engineCall<{ items: Evidence[] }>("evidence.list");
        if (listed.items[0]) {
          setEvidence(listed.items[0]);
        }
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
  }, [evidence?.id]); // eslint-disable-line react-hooks/exhaustive-deps

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
      const imported = await engineCall<Evidence>("evidence.import", {
        path: selected,
      }, 600);
      setEvidence(imported);
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
      const result = await engineCall<{
        evidence: Evidence;
        process_count: number;
      }>("evidence.analyze_basic", { evidence_id: evidence.id }, 900);
      setEvidence(result.evidence);
      await refreshEvidenceViews(result.evidence);
      setNav("processes");
    } catch (err) {
      if (err instanceof EngineClientError) setError(err.payload);
      else setError({ message: String(err) });
      // Still refresh overview to show failed run status if stored
      try {
        if (evidence) await refreshEvidenceViews(evidence);
      } catch {
        /* ignore */
      }
    } finally {
      setBusy(false);
    }
  }, [evidence, refreshEvidenceViews]);

  let body: React.ReactNode;
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
        />
      );
      break;
    default:
      body = <PlaceholderView section={nav} />;
  }

  return (
    <div className="flex h-full min-h-0 flex-col">
      <TopBar
        busy={busy}
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
