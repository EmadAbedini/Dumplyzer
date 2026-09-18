import { useEffect, useMemo, useState } from "react";
import { Info } from "lucide-react";
import {
  ANALYSIS_PROFILE_COPY,
  ANALYSIS_PROFILE_ORDER,
  capabilityCopy,
  clearAllIds,
  fullAnalysisIncludes,
  fullProfileIds,
  recommendedProfileIds,
  selectAllIds,
} from "../lib/analysisOptions";
import { cn } from "../lib/utils";
import type { AnalysisProfileCatalog } from "../lib/types";
import { Button } from "./ui/button";
import { TimeZoneSelect } from "./TimeZoneSelect";

type ProfileId = "full" | "recommended" | "custom";

type Props = {
  open: boolean;
  catalog: AnalysisProfileCatalog | null;
  busy?: boolean;
  timeZone: string;
  onTimeZoneChange: (timeZone: string) => void;
  onClose: () => void;
  onRun: (profile: ProfileId, capabilities: string[]) => void;
};

export function AnalysisOptionsDialog({
  open,
  catalog,
  busy,
  timeZone,
  onTimeZoneChange,
  onClose,
  onRun,
}: Props) {
  const [profile, setProfile] = useState<ProfileId>("full");
  const [selected, setSelected] = useState<string[]>([]);

  useEffect(() => {
    if (!open || !catalog) return;
    setProfile("full");
    setSelected(fullProfileIds(catalog));
  }, [open, catalog]);

  const evidenceCaps = useMemo(() => {
    if (!catalog) return [];
    return catalog.capabilities.filter((c) => c.scope === "evidence");
  }, [catalog]);

  const includes = catalog ? fullAnalysisIncludes(catalog) : "";

  if (!open) return null;

  const toggle = (id: string) => {
    setProfile("custom");
    setSelected((cur) =>
      cur.includes(id) ? cur.filter((x) => x !== id) : [...cur, id],
    );
  };

  const chooseProfile = (id: ProfileId) => {
    if (!catalog) return;
    setProfile(id);
    if (id === "full") setSelected(fullProfileIds(catalog));
    else if (id === "recommended") setSelected(recommendedProfileIds(catalog));
  };

  const runPrimary = () => {
    if (!catalog) return;
    if (profile === "recommended") {
      onRun("recommended", recommendedProfileIds(catalog));
      return;
    }
    if (profile === "custom") {
      onRun("custom", selected);
      return;
    }
    onRun("full", fullProfileIds(catalog));
  };

  const primaryLabel =
    profile === "recommended"
      ? "Run Quick Triage"
      : profile === "custom"
        ? "Run Selected"
        : "Run Complete Analysis";

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4">
      <div
        role="dialog"
        aria-labelledby="analysis-options-title"
        className="card flex max-h-[90vh] w-full max-w-2xl flex-col shadow-xl"
      >
        <div className="border-b border-border px-4 py-3">
          <h2 id="analysis-options-title" className="text-base font-semibold">
            Analysis Options
          </h2>
          <p className="mt-1 text-sm text-muted">
            Choose an analysis mode and how times are displayed.
          </p>
        </div>
        <div className="min-h-0 flex-1 overflow-auto px-4 py-3">
          {!catalog ? (
            <div className="text-sm text-muted">Loading analysis options…</div>
          ) : (
            <>
              <div className="grid gap-2">
                {ANALYSIS_PROFILE_ORDER.map((id) => {
                  const copy = ANALYSIS_PROFILE_COPY[id];
                  const active = profile === id;
                  const suggested = id === "full";
                  return (
                    <button
                      key={id}
                      type="button"
                      onClick={() => chooseProfile(id)}
                      className={cn(
                        "w-full cursor-pointer rounded-md border px-3 py-2.5 text-left transition-colors",
                        suggested &&
                          active &&
                          "analysis-profile-recommended-active",
                        !suggested && active && "analysis-profile-active",
                        !active &&
                          "border-border bg-background hover:bg-surface-2/70",
                      )}
                    >
                      <div className="flex items-start justify-between gap-2">
                        <div className="text-sm font-semibold">
                          {copy.title}
                        </div>
                        {suggested ? (
                          <span className="analysis-profile-recommended-badge shrink-0 rounded-full px-2 py-0.5 text-[0.68rem] font-semibold uppercase tracking-wide">
                            Recommended
                          </span>
                        ) : null}
                      </div>
                      <div
                        className={cn(
                          "mt-0.5 text-sm text-muted",
                          id === "full" && "text-justify",
                        )}
                      >
                        {copy.description}
                      </div>
                      {copy.hint ? (
                        <div
                          className={cn(
                            "mt-1 text-xs text-muted",
                            id === "full" && "text-justify",
                          )}
                        >
                          {copy.hint}
                        </div>
                      ) : null}
                      {id === "full" && includes ? (
                        <div className="mt-1.5 text-justify text-xs leading-relaxed text-muted">
                          Includes: {includes}
                        </div>
                      ) : null}
                      {id === "full" ? (
                        <div className="analysis-profile-note mt-2 flex items-center gap-2 rounded-md px-2.5 py-2 text-xs leading-snug">
                          <Info size={14} className="shrink-0" aria-hidden />
                          <span className="min-w-0 flex-1 text-justify">
                            Extracted files and carved artifacts are not
                            included by default. Run these from{" "}
                            <span className="font-bold">Carved Data</span> when
                            needed. They are optional and can take significantly
                            longer to complete.
                          </span>
                        </div>
                      ) : null}
                    </button>
                  );
                })}
              </div>

              {profile === "custom" ? (
                <>
                  <div className="mt-4 mb-2 flex gap-2">
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => {
                        setProfile("custom");
                        setSelected(selectAllIds(catalog));
                      }}
                    >
                      Select All
                    </Button>
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => {
                        setProfile("custom");
                        setSelected(clearAllIds());
                      }}
                    >
                      Clear All
                    </Button>
                  </div>
                  <div className="mt-1 grid gap-1">
                    {evidenceCaps.map((c) => {
                      const copy = capabilityCopy(c);
                      return (
                        <label
                          key={c.id}
                          className="flex items-start gap-2 py-0.5"
                        >
                          <input
                            type="checkbox"
                            className="mt-1"
                            checked={selected.includes(c.id)}
                            onChange={() => toggle(c.id)}
                          />
                          <span>
                            <span className="text-sm font-medium">
                              {copy.label}
                            </span>
                            <span className="block text-sm text-muted">
                              {copy.description}
                            </span>
                          </span>
                        </label>
                      );
                    })}
                  </div>
                  <div className="analysis-profile-note mt-3 flex items-start gap-2 rounded-md px-2.5 py-2 text-xs leading-snug">
                    <Info size={14} className="mt-0.5 shrink-0" aria-hidden />
                    <span className="min-w-0 flex-1">
                      IOC Extraction, Findings, Network Artifact Extraction, and Timeline read
                      stored results. They do not rescan the dump, so include Command Lines,
                      Modules, and Network Connections or the output will be sparse.
                    </span>
                  </div>
                </>
              ) : null}

              <div className="mt-4 border-t border-border pt-3">
                <label
                  htmlFor="analysis-timezone"
                  className="text-sm font-semibold"
                >
                  Time Zone
                </label>
                <p className="mt-0.5 mb-2 text-sm text-muted">
                  Controls how Dumplyzer displays analysis and evidence
                  timestamps. Stored timestamps and the original memory image
                  are not modified.
                </p>
                <TimeZoneSelect
                  id="analysis-timezone"
                  value={timeZone}
                  onChange={onTimeZoneChange}
                />
              </div>
            </>
          )}
        </div>
        <div className="flex flex-wrap items-center justify-end gap-2 border-t border-border px-4 py-3">
          <Button size="sm" variant="ghost" disabled={busy} onClick={onClose}>
            Cancel
          </Button>
          <Button
            size="sm"
            disabled={
              busy ||
              !catalog ||
              (profile === "custom" && selected.length === 0)
            }
            onClick={runPrimary}
          >
            {primaryLabel}
          </Button>
        </div>
      </div>
    </div>
  );
}
