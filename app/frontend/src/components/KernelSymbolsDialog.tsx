import { useEffect, useState } from "react";
import { open as openFileDialog } from "@tauri-apps/plugin-dialog";
import { Check, Copy } from "lucide-react";
import { openUserFolder } from "../lib/api";
import type { KernelSymbolNeed } from "../lib/types";
import { Button } from "./ui/button";

type Props = {
  open: boolean;
  need: KernelSymbolNeed | null;
  busy?: boolean;
  downloadPercent?: number | null;
  onClose: () => void;
  onDownload: () => void;
  onImported: (path: string) => void;
};

export function KernelSymbolsDialog({
  open,
  need,
  busy,
  downloadPercent,
  onClose,
  onDownload,
  onImported,
}: Props) {
  const [browseError, setBrowseError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (!open) return;
    setBrowseError(null);
    setCopied(false);
  }, [open, need?.guid, need?.age, need?.filename_pdb]);

  useEffect(() => {
    if (!open) return;
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.preventDefault();
        onClose();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, onClose]);

  if (!open || !need) return null;

  const blocked = Boolean(busy);
  const pct =
    downloadPercent == null
      ? null
      : Math.round(Math.max(0, Math.min(100, downloadPercent)));
  const downloading = blocked && pct != null && pct < 100;
  const downloadReady = pct != null && pct >= 100;
  const downloadLabel = downloadReady
    ? "Symbol ready — continuing analysis..."
    : downloading
      ? (pct ?? 0) >= 62
        ? "Converting symbols..."
        : "Downloading Symbol..."
      : "Download & Continue";

  const copyGuid = async () => {
    await navigator.clipboard.writeText(need.guid);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1500);
  };

  const browse = async () => {
    setBrowseError(null);
    const selected = await openFileDialog({
      multiple: false,
      directory: false,
      title: "Select kernel PDB or ISF file",
      filters: [
        {
          name: "Kernel symbols",
          extensions: ["pdb", "json", "json.xz", "json.gz"],
        },
      ],
    });
    const path = Array.isArray(selected) ? selected[0] : selected;
    if (!path || typeof path !== "string") return;
    onImported(path);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4">
      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby="kernel-symbols-title"
        aria-describedby="kernel-symbols-desc"
        aria-busy={blocked || undefined}
        className="card flex max-h-[90vh] w-full max-w-lg flex-col shadow-xl"
      >
        <div className="border-b border-border px-4 py-3">
          <h2 id="kernel-symbols-title" className="text-base font-semibold leading-snug">
            Kernel Symbols Required
          </h2>
          <p id="kernel-symbols-desc" className="mt-1 text-sm leading-relaxed text-muted">
            This memory image requires Windows kernel symbols before analysis can
            continue.
          </p>
        </div>

        <div className="min-h-0 flex-1 space-y-5 overflow-auto px-4 py-4">
          <section>
            <h3 className="text-[0.7rem] font-semibold uppercase tracking-[0.08em] text-muted">
              This dump&apos;s kernel
            </h3>
            <div className="mt-2 rounded-md bg-surface-2 px-3 py-2.5">
              <p className="break-all font-mono text-sm font-medium leading-snug">
                {need.filename_pdb}
              </p>
              <dl className="mt-2 grid grid-cols-[auto_minmax(0,1fr)] items-center gap-x-3 gap-y-1">
                <dt className="text-xs text-muted">GUID</dt>
                <dd className="flex min-w-0 items-center gap-1">
                  <span className="min-w-0 break-all font-mono text-xs leading-snug">
                    {need.guid}
                  </span>
                  <Button
                    type="button"
                    size="sm"
                    variant="ghost"
                    className="h-7 w-7 shrink-0 px-0"
                    disabled={blocked}
                    title={copied ? "Copied" : "Copy GUID"}
                    aria-label={copied ? "GUID copied" : "Copy GUID"}
                    onClick={() => {
                      void copyGuid().catch(() =>
                        setBrowseError("Could not copy the GUID."),
                      );
                    }}
                  >
                    {copied ? (
                      <Check size={13} aria-hidden />
                    ) : (
                      <Copy size={13} aria-hidden />
                    )}
                  </Button>
                </dd>
                <dt className="text-xs text-muted">Age</dt>
                <dd className="font-mono text-xs leading-snug">{need.age}</dd>
              </dl>
            </div>
          </section>

          <section>
            <h3 className="text-sm font-semibold leading-snug">Recommended</h3>
            <p className="mt-1 text-sm leading-relaxed text-muted">
              Download the required symbol from Microsoft. Only this kernel build
              will be downloaded. Analysis will continue automatically when the
              symbol is ready.
            </p>
            <Button
              type="button"
              disabled={blocked}
              autoFocus
              className="mt-3 h-10 w-full font-semibold"
              onClick={onDownload}
            >
              {downloadLabel}
            </Button>
            {downloading ? (
              <div className="mt-2">
                <div
                  className="h-1 overflow-hidden rounded-full bg-surface-2"
                  role="progressbar"
                  aria-valuemin={0}
                  aria-valuemax={100}
                  aria-valuenow={pct ?? 0}
                  aria-label="Symbol download progress"
                >
                  <div
                    className="h-full bg-accent transition-[width] duration-200"
                    style={{ width: `${pct ?? 0}%` }}
                  />
                </div>
                <p className="mt-1 text-xs text-muted">{pct}%</p>
              </div>
            ) : null}
          </section>

          <section>
            <h3 className="text-sm font-semibold leading-snug">Already have the symbol?</h3>
            <p className="mt-1 text-sm leading-relaxed text-muted">
              Select a matching PDB or Volatility ISF file.
            </p>
            <Button
              type="button"
              size="sm"
              variant="outline"
              className="mt-2.5"
              disabled={blocked}
              onClick={() => {
                void browse().catch((err) =>
                  setBrowseError(String(err instanceof Error ? err.message : err)),
                );
              }}
            >
              Browse File...
            </Button>
          </section>

          <div className="border-t border-border pt-3">
            <section className="flex items-center justify-between gap-3">
              <div className="min-w-0">
                <p className="text-xs leading-relaxed text-muted">
                  Imported symbols are stored in:
                </p>
                <p className="mt-0.5 break-all font-mono text-xs leading-snug text-muted">
                  {need.dest_dir}
                </p>
              </div>
              <Button
                type="button"
                size="sm"
                variant="ghost"
                className="shrink-0 bg-surface-2 shadow-none hover:bg-border"
                disabled={blocked}
                onClick={() => {
                  void openUserFolder("symbols").catch(() => undefined);
                }}
              >
                Open Folder
              </Button>
            </section>
          </div>

          {browseError ? <p className="text-sm text-danger">{browseError}</p> : null}
        </div>

        <div className="flex items-center justify-end border-t border-border px-4 py-3">
          <Button type="button" variant="ghost" size="sm" onClick={onClose}>
            Cancel
          </Button>
        </div>
      </div>
    </div>
  );
}
