import { FONT_MAX, FONT_MIN, FONT_STEPS, type FontSizePx, type ThemeId } from "../lib/preferences";
import { CAPABILITY, CHECKING_DETAIL, UNAVAILABLE_DETAIL } from "../lib/analysisCapabilities";
import { engineCall, EngineClientError, openUserFolder } from "../lib/api";
import { refreshSignatureDetection, useCapabilityStatus } from "../lib/capabilityStatus";
import type { YaraStatus } from "../lib/types";
import { Button } from "./ui/button";
import { SegmentedControl } from "./ui/segmented";
import { TimeZoneSelect } from "./TimeZoneSelect";
import { StatusToast, useStatusToast } from "./StatusToast";
import { useState } from "react";

function signatureRuleCounts(yara: YaraStatus): {
  bundled: number;
  custom: number;
  total: number;
} {
  const bundled = yara.bundled_rule_count ?? yara.bundled_rule_file_count ?? 0;
  const custom = yara.custom_rule_count ?? yara.custom_rule_file_count ?? 0;
  const total = yara.loaded_rule_count ?? bundled + custom;
  return { bundled, custom, total };
}

function RuleCountCell({ value, label }: { value: number; label: string }) {
  return (
    <div className="px-3 py-2 text-center">
      <div className="text-sm font-semibold tabular-nums">{value}</div>
      <div className="text-[11px] text-muted">{label}</div>
    </div>
  );
}

type Props = {
  theme: ThemeId;
  fontSize: FontSizePx;
  timeZone: string;
  onTheme: (theme: ThemeId) => void;
  onFontSize: (size: FontSizePx) => void;
  onTimeZone: (timeZone: string) => void;
};

export function SettingsView({
  theme,
  fontSize,
  timeZone,
  onTheme,
  onFontSize,
  onTimeZone,
}: Props) {
  const caps = useCapabilityStatus();
  const yara = caps.yara;
  const yaraRow = caps.rows.signatureDetection;
  const [yaraNote, setYaraNote] = useState<string | null>(null);
  const { toast, showToast } = useStatusToast();
  const [openingFolder, setOpeningFolder] = useState(false);
  const [reloading, setReloading] = useState(false);
  const busy = openingFolder || reloading;
  const counts = yara ? signatureRuleCounts(yara) : null;

  return (
    <div className="mx-auto max-w-xl p-5">
      <h2 className="text-base font-semibold tracking-tight">Settings</h2>
      <p className="mt-1 text-sm text-muted">
        Appearance preferences are stored on this workstation.
      </p>

      <section className="card mt-5 p-4">
        <h3 className="text-sm font-semibold">Theme</h3>
        <p className="mt-1 text-sm text-muted">
        Applies to the workbench chrome. The default theme is Light. HTML
        investigation reports stay self-contained and follow the browser
        print/color scheme.
        </p>
        <div className="mt-3">
          <SegmentedControl
            ariaLabel="Theme"
            value={theme}
            onChange={onTheme}
            options={[
              { id: "dark", label: "Dark" },
              { id: "light", label: "Light" },
            ]}
          />
        </div>
      </section>

      <section className="card mt-4 p-4">
        <h3 className="text-sm font-semibold">Font size</h3>
        <p className="mt-1 text-sm text-muted">
          Default {FONT_STEPS.includes(13) ? "13" : FONT_MIN}px. Allowed range {FONT_MIN}–{FONT_MAX}px.
        </p>
        <div className="mt-3">
          <SegmentedControl
            ariaLabel="Font size"
            value={String(fontSize)}
            onChange={(step) => onFontSize(Number(step) as FontSizePx)}
            options={FONT_STEPS.map((step) => ({
              id: String(step),
              label: `${step}px`,
            }))}
          />
        </div>
        <label className="mt-3 flex items-center gap-3 text-sm">
          <span className="w-16 text-muted">Scale</span>
          <input
            type="range"
            min={FONT_MIN}
            max={FONT_MAX}
            step={1}
            value={fontSize}
            onChange={(e) => onFontSize(Number(e.target.value) as FontSizePx)}
            className="flex-1 accent-accent"
          />
          <span className="w-10 font-mono text-sm">{fontSize}px</span>
        </label>
      </section>

      <section className="card mt-4 p-4">
        <h3 className="text-sm font-semibold">Time Zone</h3>
        <p className="mt-1 text-sm text-muted">
          Display preference for analysis and evidence times. Canonical stored
          timestamps are not rewritten.
        </p>
        <div className="mt-3">
          <TimeZoneSelect value={timeZone} onChange={onTimeZone} />
        </div>
      </section>

      <section className="card mt-4 p-4">
        <h3 className="text-sm font-semibold">{CAPABILITY.signatureDetection}</h3>
        {yaraRow.kind === "checking" ? (
          <p className="mt-1 text-sm text-muted">{CHECKING_DETAIL}</p>
        ) : yara?.available && counts ? (
          <>
            <div className="mt-3 grid grid-cols-3 divide-x divide-border overflow-hidden rounded-md border border-border bg-surface-2">
              <RuleCountCell value={counts.bundled} label="bundled" />
              <RuleCountCell value={counts.custom} label="custom" />
              <RuleCountCell value={counts.total} label="total" />
            </div>
            <p className="mt-3 text-sm text-muted">
              Dumplyzer includes a built-in set of YARA rules. Add your own{" "}
              <span className="font-mono">.yar</span> or{" "}
              <span className="font-mono">.yara</span> files to extend
              signature detection.
            </p>
          </>
        ) : (
          <p className="mt-1 text-sm text-muted">{UNAVAILABLE_DETAIL}</p>
        )}
        {yaraNote ? <p className="mt-2 text-xs text-danger">{yaraNote}</p> : null}
        <div className="mt-4 flex items-center gap-3">
          <Button
            type="button"
            size="sm"
            className="shrink-0"
            disabled={busy}
            onClick={() => {
              void (async () => {
                setOpeningFolder(true);
                setYaraNote(null);
                try {
                  await openUserFolder("yara_rules_custom");
                } catch (err) {
                  setYaraNote(
                    err instanceof EngineClientError ? err.message : String(err),
                  );
                } finally {
                  setOpeningFolder(false);
                }
              })();
            }}
          >
            Open Folder
          </Button>
          <Button
            type="button"
            size="sm"
            variant="outline"
            className="shrink-0"
            disabled={busy}
            aria-busy={reloading}
            onClick={() => {
              if (reloading) return;
              void (async () => {
                setReloading(true);
                setYaraNote(null);
                try {
                  const status = await engineCall<YaraStatus>("yara.reload");
                  await refreshSignatureDetection(status);
                  showToast("YARA rules reloaded");
                } catch (err) {
                  setYaraNote(
                    err instanceof EngineClientError ? err.message : String(err),
                  );
                } finally {
                  setReloading(false);
                }
              })();
            }}
          >
            {reloading ? "Reloading…" : "Reload Rules"}
          </Button>
        </div>
      </section>
      <StatusToast message={toast} />
    </div>
  );
}
