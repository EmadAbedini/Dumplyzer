import { useEffect, useMemo, useState } from "react";
import { Check, Copy } from "lucide-react";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { engineCall, EngineClientError } from "../lib/api";
import { DisplayTimeZoneProvider } from "../lib/datetime";
import { formatPluginConsole, pluginCopyPayload } from "../lib/pluginOutput";
import {
  pluginOutputSearchParams,
  pluginShortName,
} from "../lib/pluginOutputWindow";
import { readPreferences } from "../lib/preferences";
import { cn } from "../lib/utils";
import type { PluginExecutionBundle } from "../lib/types";
import { ConsoleOutput, ResultTable } from "./PluginOutputViews";
import { Badge } from "./ui/badge";
import { Button } from "./ui/button";
import { SegmentedControl } from "./ui/segmented";
import { StatusToast, useStatusToast } from "./StatusToast";

export function PluginOutputWindow() {
  const prefs = useMemo(() => readPreferences(), []);
  const { executionId, view: initialView } = useMemo(() => pluginOutputSearchParams(), []);
  const [tab, setTab] = useState<"table" | "console">(initialView);
  const [bundle, setBundle] = useState<PluginExecutionBundle | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const { toast, showToast } = useStatusToast();

  useEffect(() => {
    const current = getCurrentWindow();
    void (async () => {
      try {
        await current.show();
        await current.setFocus();
      } catch {
        /* window APIs may be unavailable in browser preview */
      }
    })();
  }, []);

  useEffect(() => {
    if (!executionId) {
      setError("Missing plugin execution.");
      return;
    }
    let cancelled = false;
    void (async () => {
      try {
        const b = await engineCall<PluginExecutionBundle>("plugins.execution_get", {
          execution_id: executionId,
        });
        if (cancelled) return;
        setBundle(b);
        document.title = `Output · ${pluginShortName(b.execution.plugin)}`;
      } catch (e) {
        if (!cancelled) {
          setError(e instanceof EngineClientError ? e.message : String(e));
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [executionId]);

  const consoleText = useMemo(
    () => (bundle ? formatPluginConsole(bundle) : ""),
    [bundle],
  );

  useEffect(() => {
    setCopied(false);
  }, [tab, bundle?.execution.id]);

  const copyOutput = async () => {
    if (!bundle) return;
    const { text, label } = pluginCopyPayload(bundle, tab);
    if (!text.trim()) {
      showToast("Nothing to copy");
      return;
    }
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      showToast(label);
      window.setTimeout(() => setCopied(false), 1600);
    } catch {
      showToast("Could not copy to the clipboard.");
    }
  };

  const pluginId = bundle?.execution.plugin ?? "";
  const shortName = pluginId ? pluginShortName(pluginId) : "Plugin output";
  const status = bundle ? outputStatus(bundle) : null;
  const meta = [
    bundle ? `${bundle.result.row_count} row${bundle.result.row_count === 1 ? "" : "s"}` : null,
    bundle?.result.truncated ? "truncated" : null,
    bundle?.execution.cache_hit ? "cached" : null,
  ]
    .filter(Boolean)
    .join(" · ");

  return (
    <DisplayTimeZoneProvider timeZone={prefs.timeZone}>
      <div className="flex h-full min-h-0 flex-col">
        <header className="flex shrink-0 flex-wrap items-center gap-x-4 gap-y-2 border-b border-border bg-surface px-4 py-3">
          <div className="min-w-0 flex-1">
            <div className="flex min-w-0 items-center gap-2">
              <h1 className="truncate text-sm font-semibold font-mono" title={pluginId || undefined}>
                {shortName}
              </h1>
              {status ? (
                <Badge className={cn("shrink-0 normal-case tracking-normal", status.className)}>
                  {status.label}
                </Badge>
              ) : null}
            </div>
            <div className="mt-0.5 truncate text-[11px] text-muted" title={pluginId || undefined}>
              {error ? "Could not load result" : bundle ? `${pluginId}${meta ? ` · ${meta}` : ""}` : "Loading…"}
            </div>
          </div>
          <div className="flex shrink-0 items-center gap-2">
            <SegmentedControl
              ariaLabel="View"
              value={tab}
              onChange={setTab}
              options={[
                { id: "table", label: "Table" },
                { id: "console", label: "Console" },
              ]}
            />
            <Button
              type="button"
              size="sm"
              variant="outline"
              className="h-8 gap-1.5"
              disabled={!bundle}
              aria-label={tab === "console" ? "Copy console output" : "Copy table"}
              title={tab === "console" ? "Copy console output" : "Copy table as TSV"}
              onClick={() => void copyOutput()}
            >
              {copied ? <Check size={14} aria-hidden /> : <Copy size={14} aria-hidden />}
              {copied ? "Copied" : "Copy"}
            </Button>
          </div>
        </header>
        <div
          className={
            tab === "console" && bundle
              ? "flex min-h-0 flex-1 flex-col overflow-hidden p-3"
              : "min-h-0 flex-1 overflow-auto p-3"
          }
        >
          {error ? (
            <div className="p-3 text-danger">{error}</div>
          ) : !bundle ? (
            <div className="p-3 text-muted">Loading plugin output…</div>
          ) : tab === "table" ? (
            <ResultTable bundle={bundle} />
          ) : (
            <ConsoleOutput text={consoleText} />
          )}
        </div>
        <StatusToast message={toast} />
      </div>
    </DisplayTimeZoneProvider>
  );
}

function outputStatus(bundle: PluginExecutionBundle): { label: string; className: string } {
  const status = bundle.execution.status;
  if (bundle.execution.cache_hit && status === "completed") {
    return { label: "Cached", className: "border-accent text-accent" };
  }
  if (status === "completed") {
    return { label: "Completed", className: "border-success text-success" };
  }
  if (status === "failed") {
    return { label: "Failed", className: "border-danger text-danger" };
  }
  if (status === "queued" || status === "running") {
    return { label: "Analysing", className: "border-accent text-accent" };
  }
  return { label: status, className: "" };
}
