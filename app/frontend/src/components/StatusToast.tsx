import { useCallback, useEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { cn } from "../lib/utils";
import { Button } from "./ui/button";

const TOAST_MS = 4000;
export const TOAST_FADE_MS = 220;

export function StatusToast({ message }: { message: string | null }) {
  const [visible, setVisible] = useState<string | null>(null);
  const [leaving, setLeaving] = useState(false);
  const shownRef = useRef<string | null>(null);

  useEffect(() => {
    if (message) {
      shownRef.current = message;
      setVisible(message);
      setLeaving(false);
      return;
    }
    if (!shownRef.current) return;
    setLeaving(true);
    const t = window.setTimeout(() => {
      shownRef.current = null;
      setVisible(null);
      setLeaving(false);
    }, TOAST_FADE_MS);
    return () => window.clearTimeout(t);
  }, [message]);

  if (!visible || typeof document === "undefined") return null;

  return createPortal(
    <div className="pointer-events-none fixed inset-x-0 top-5 z-50 flex justify-center px-4">
      <div
        role={visible.includes("\n") ? "alert" : "status"}
        aria-live={visible.includes("\n") ? "assertive" : "polite"}
        className={cn(
          "app-toast max-w-md rounded-md px-4 py-2.5 text-center text-sm leading-5 shadow-md",
          visible.includes("\n") ? "whitespace-pre-line" : "whitespace-nowrap",
          leaving ? "app-toast-fade-out" : "app-toast-fade-in",
        )}
      >
        {visible.includes("\n") ? (
          <>
            <div className="font-medium">{visible.slice(0, visible.indexOf("\n"))}</div>
            <div className="mt-1 text-[0.92em] leading-5 opacity-90">
              {visible.slice(visible.indexOf("\n") + 1)}
            </div>
          </>
        ) : (
          visible
        )}
      </div>
    </div>,
    document.body,
  );
}

export function useStatusToast(durationMs = TOAST_MS): {
  toast: string | null;
  showToast: (message: string, durationMs?: number) => void;
  dismissToast: (only?: string) => void;
} {
  const [toast, setToast] = useState<string | null>(null);
  const toastRef = useRef<string | null>(null);
  const timer = useRef<number | null>(null);
  toastRef.current = toast;
  useEffect(() => {
    return () => {
      if (timer.current != null) window.clearTimeout(timer.current);
    };
  }, []);
  const showToast = useCallback(
    (message: string, ms?: number) => {
      if (timer.current != null) {
        window.clearTimeout(timer.current);
        timer.current = null;
      }
      setToast(message);
      timer.current = window.setTimeout(() => {
        setToast(null);
        timer.current = null;
      }, ms ?? durationMs);
    },
    [durationMs],
  );
  const dismissToast = useCallback((only?: string) => {
    if (only != null && toastRef.current !== only) return;
    if (!toastRef.current) return;
    if (timer.current != null) {
      window.clearTimeout(timer.current);
      timer.current = null;
    }
    setToast(null);
  }, []);
  return { toast, showToast, dismissToast };
}

export function RefreshButton({
  onRefresh,
  label = "Refresh",
  doneMessage,
  showToast,
  disabled = false,
}: {
  onRefresh: () => void | Promise<void>;
  label?: string;
  doneMessage: string;
  showToast: (message: string) => void;
  disabled?: boolean;
}) {
  const [busy, setBusy] = useState(false);
  return (
    <Button
      size="sm"
      variant="outline"
      disabled={busy || disabled}
      aria-busy={busy}
      onClick={() => {
        if (busy || disabled) return;
        setBusy(true);
        void Promise.resolve(onRefresh())
          .then(() => showToast(doneMessage))
          .finally(() => setBusy(false));
      }}
    >
      {busy ? "Refreshing…" : label}
    </Button>
  );
}
