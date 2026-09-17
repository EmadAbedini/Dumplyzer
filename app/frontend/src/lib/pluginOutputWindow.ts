import { WebviewWindow } from "@tauri-apps/api/webviewWindow";

export const PLUGIN_OUTPUT_PARAM = "pluginOutput";

export function isPluginOutputWindow(): boolean {
  return new URLSearchParams(window.location.search).get(PLUGIN_OUTPUT_PARAM) === "1";
}

export function pluginOutputSearchParams(): {
  executionId: string;
  view: "table" | "console";
} {
  const params = new URLSearchParams(window.location.search);
  return {
    executionId: params.get("execution")?.trim() ?? "",
    view: params.get("view") === "console" ? "console" : "table",
  };
}

export function pluginOutputWindowLabel(executionId: string): string {
  const id = executionId.replace(/[^a-zA-Z0-9-]/g, "").slice(0, 48);
  return `plugin-output-${id || "view"}`;
}

export function pluginShortName(id: string): string {
  const parts = id.split(".").filter(Boolean);
  return parts[parts.length - 1] || id;
}

export async function openPluginOutputWindow(opts: {
  executionId: string;
  pluginId: string;
  view: "table" | "console";
}): Promise<void> {
  const label = pluginOutputWindowLabel(opts.executionId);
  const existing = await WebviewWindow.getByLabel(label);
  if (existing) {
    await bringPluginOutputForward(existing);
    return;
  }

  const url = new URL(window.location.href);
  url.hash = "";
  url.search = "";
  url.searchParams.set(PLUGIN_OUTPUT_PARAM, "1");
  url.searchParams.set("execution", opts.executionId);
  url.searchParams.set("view", opts.view);

  const webview = new WebviewWindow(label, {
    url: `${url.pathname}${url.search}`,
    title: `Output · ${pluginShortName(opts.pluginId)}`,
    width: 1100,
    height: 760,
    minWidth: 720,
    minHeight: 480,
    center: true,
    focus: true,
    resizable: true,
    visible: true,
    parent: "main",
  });
  await new Promise<void>((resolve, reject) => {
    void webview.once("tauri://created", () => resolve());
    void webview.once("tauri://error", (event) => {
      reject(new Error(String(event.payload ?? "Could not open output window")));
    });
  });
  await bringPluginOutputForward(webview);
}

async function bringPluginOutputForward(window: WebviewWindow): Promise<void> {
  try {
    await window.unminimize();
  } catch {
    /* optional */
  }
  try {
    await window.show();
  } catch {
    /* optional */
  }
  try {
    await window.setAlwaysOnTop(true);
  } catch {
    /* optional */
  }
  try {
    await window.setFocus();
  } catch {
    /* optional */
  }
  globalThis.setTimeout(() => {
    void window.setAlwaysOnTop(false).catch(() => undefined);
  }, 120);
}
