import { invoke } from "@tauri-apps/api/core";
import { isPluginOutputWindow } from "./pluginOutputWindow";

let sent = false;

/** Tell the native shell the workbench has painted so the splash can close. */
export function notifyMainWindowReady(): void {
  if (sent || isPluginOutputWindow()) {
    return;
  }
  sent = true;
  const send = () => {
    void invoke("ui_ready").catch(() => {
      /* browser preview has no splash command */
    });
  };
  requestAnimationFrame(() => {
    requestAnimationFrame(send);
  });
}
