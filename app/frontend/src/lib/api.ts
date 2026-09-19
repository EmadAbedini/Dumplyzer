import { invoke } from "@tauri-apps/api/core";
import type { AppErrorPayload } from "./types";

export class EngineClientError extends Error {
  payload: AppErrorPayload;

  constructor(payload: AppErrorPayload) {
    super(payload.message);
    this.name = "EngineClientError";
    this.payload = payload;
  }
}

function parseEngineError(err: unknown): EngineClientError {
  const raw = String(err);
  // Tauri serializes EngineError as string: "message | {json data}"
  const parts = raw.split(" | ");
  if (parts.length >= 2) {
    const message = parts[0].replace(/^.*?:\s*/, "");
    try {
      const data = JSON.parse(parts.slice(1).join(" | ")) as Record<string, unknown>;
      return new EngineClientError({
        message: message || "Something went wrong.",
        app_code: typeof data.app_code === "string" ? data.app_code : undefined,
        suggestion: typeof data.suggestion === "string" ? data.suggestion : undefined,
        entity: typeof data.entity === "string" ? data.entity : undefined,
      });
    } catch {
      /* fall through */
    }
  }
  const cleaned = raw.replace(/^.*?:\s*/, "").trim();
  const message =
    /traceback|memscope_engine|volatility3|File "[^"]+", line \d+/i.test(cleaned)
      ? "Something went wrong."
      : cleaned || "Something went wrong.";
  return new EngineClientError({ message });
}

export async function engineCall<T = unknown>(
  method: string,
  params?: Record<string, unknown>,
  timeoutSecs?: number,
): Promise<T> {
  try {
    return await invoke<T>("engine_call", {
      method,
      params: params ?? {},
      timeoutSecs: timeoutSecs ?? null,
    });
  } catch (err) {
    throw parseEngineError(err);
  }
}

export async function ensureAppPaths(): Promise<Record<string, string>> {
  try {
    return await invoke("get_app_paths");
  } catch (err) {
    throw parseEngineError(err);
  }
}

export async function openUserFolder(kind: string): Promise<void> {
  try {
    await invoke("open_user_folder", { kind });
  } catch (err) {
    throw parseEngineError(err);
  }
}

export async function openLocalFolder(path: string): Promise<void> {
  try {
    await invoke("open_local_folder", { path });
  } catch (err) {
    throw parseEngineError(err);
  }
}

export async function openExternalUrl(url: string): Promise<void> {
  try {
    await invoke("open_external_url", { url });
  } catch (err) {
    throw parseEngineError(err);
  }
}

export async function copyExportFile(source: string, destination: string): Promise<void> {
  try {
    await invoke("copy_export_file", { source, destination });
  } catch (err) {
    throw parseEngineError(err);
  }
}
