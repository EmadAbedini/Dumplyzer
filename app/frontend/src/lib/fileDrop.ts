import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { getCurrentWindow } from "@tauri-apps/api/window";

export type FileDropKind = "enter" | "over" | "drop" | "leave";

type FileDropNotice =
  | { type: "enter"; paths?: string[] }
  | { type: "over" }
  | { type: "drop"; paths?: string[] }
  | { type: "leave" };

type DragDropEvent = {
  payload: {
    type: FileDropKind;
    paths?: string[];
  };
};

function asPaths(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.filter((p): p is string => typeof p === "string" && p.trim().length > 0);
}

export function firstDroppedFilePath(paths: string[]): string | undefined {
  return asPaths(paths)[0];
}

function logFileDrop(kind: FileDropKind, paths: string[]): void {
  if (kind === "over") return;
  console.info("[dumplyzer:file-drop]", kind, {
    count: paths.length,
    first: paths[0] ?? null,
  });
}

function hasFilePayload(event: DragEvent): boolean {
  const types = event.dataTransfer?.types;
  if (!types) return false;
  return Array.from(types).includes("Files");
}

function pathsFromDomDrop(event: DragEvent): string[] {
  const withPaths = event as DragEvent & { paths?: unknown };
  const fromEvent = asPaths(withPaths.paths);
  if (fromEvent.length > 0) return fromEvent;
  const transfer = event.dataTransfer as (DataTransfer & { paths?: unknown }) | null;
  if (!transfer) return [];
  const fromTransfer = asPaths(transfer.paths);
  if (fromTransfer.length > 0) return fromTransfer;
  const out: string[] = [];
  for (const file of Array.from(transfer.files)) {
    const path = (file as File & { path?: string }).path;
    if (typeof path === "string" && path.trim().length > 0) {
      out.push(path);
    }
  }
  return out;
}

/**
 * HTML5 drag events are used only to mark a valid drop target and to clear the
 * overlay. Explorer filesystem paths come from the native `dumplyzer://file-drop`
 * / Tauri DragDrop bridge — WebView2 does not put `File.path` on DOM drops.
 */
function attachDomFileDrop(
  onEvent: (kind: FileDropKind, paths: string[]) => void,
): UnlistenFn {
  const opts: AddEventListenerOptions = { capture: true };
  const onDragEnter = (event: DragEvent) => {
    if (!hasFilePayload(event)) return;
    event.preventDefault();
    onEvent("enter", []);
  };
  const onDragOver = (event: DragEvent) => {
    if (!hasFilePayload(event)) return;
    event.preventDefault();
    if (event.dataTransfer) event.dataTransfer.dropEffect = "copy";
    onEvent("over", []);
  };
  const onDragLeave = (event: DragEvent) => {
    if (!hasFilePayload(event)) return;
    const related = event.relatedTarget as Node | null;
    if (related && document.documentElement.contains(related)) return;
    onEvent("leave", []);
  };
  const onDrop = (event: DragEvent) => {
    event.preventDefault();
    event.stopPropagation();
    onEvent("drop", pathsFromDomDrop(event));
  };
  window.addEventListener("dragenter", onDragEnter, opts);
  window.addEventListener("dragover", onDragOver, opts);
  window.addEventListener("dragleave", onDragLeave, opts);
  window.addEventListener("drop", onDrop, opts);
  return () => {
    window.removeEventListener("dragenter", onDragEnter, opts);
    window.removeEventListener("dragover", onDragOver, opts);
    window.removeEventListener("dragleave", onDragLeave, opts);
    window.removeEventListener("drop", onDrop, opts);
  };
}

function fromTauriDrag(event: DragDropEvent, onEvent: (kind: FileDropKind, paths: string[]) => void) {
  const kind = event.payload.type;
  const paths = kind === "enter" || kind === "drop" ? event.payload.paths : [];
  onEvent(kind, asPaths(paths));
}

export async function subscribeFileDrop(
  onEvent: (kind: FileDropKind, paths: string[]) => void,
): Promise<UnlistenFn> {
  const traced: typeof onEvent = (kind, paths) => {
    logFileDrop(kind, paths);
    onEvent(kind, paths);
  };
  const unlistens: UnlistenFn[] = [];

  unlistens.push(attachDomFileDrop(traced));

  unlistens.push(
    await listen<FileDropNotice>("dumplyzer://file-drop", (event) => {
      const notice = event.payload;
      if (!notice || typeof notice.type !== "string") return;
      traced(notice.type, asPaths("paths" in notice ? notice.paths : []));
    }),
  );

  try {
    unlistens.push(
      await getCurrentWindow().onDragDropEvent((event) => {
        fromTauriDrag(event, traced);
      }),
    );
  } catch {
    /* window drag-drop API unavailable outside Tauri */
  }

  try {
    const { getCurrentWebview } = await import("@tauri-apps/api/webview");
    unlistens.push(
      await getCurrentWebview().onDragDropEvent((event) => {
        fromTauriDrag(event, traced);
      }),
    );
  } catch {
    /* webview drag-drop API unavailable outside Tauri */
  }

  return () => {
    for (const unlisten of unlistens) unlisten();
  };
}
