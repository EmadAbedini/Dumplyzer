import { getCurrentWindow } from "@tauri-apps/api/window";
import { isValidTimeZone, systemTimeZone } from "./timeZone";

export const FONT_MIN = 12;
export const FONT_MAX = 16;
export const FONT_DEFAULT = 13;
export const FONT_STEPS = [12, 13, 14, 15, 16] as const;

export type ThemeId = "dark" | "light";
export type FontSizePx = (typeof FONT_STEPS)[number];

const THEME_KEY = "dumplyzer.ui.theme";
const FONT_KEY = "dumplyzer.ui.fontSize";
const TIMEZONE_KEY = "dumplyzer.ui.timeZone";
const LEGACY_THEME_KEY = "memscope.ui.theme";
const LEGACY_FONT_KEY = "memscope.ui.fontSize";

export type UiPreferences = {
  theme: ThemeId;
  fontSize: FontSizePx;
  timeZone: string;
};

function clampFont(n: number): FontSizePx {
  const rounded = Math.round(n);
  const bounded = Math.min(FONT_MAX, Math.max(FONT_MIN, rounded));
  return (FONT_STEPS.includes(bounded as FontSizePx)
    ? bounded
    : FONT_DEFAULT) as FontSizePx;
}

function readStored(key: string, legacy?: string): string | null {
  const cur = localStorage.getItem(key);
  if (cur != null) return cur;
  return legacy ? localStorage.getItem(legacy) : null;
}

export function readPreferences(): UiPreferences {
  let theme: ThemeId = "light";
  let fontSize: FontSizePx = FONT_DEFAULT;
  let timeZone = systemTimeZone();
  try {
    const t = readStored(THEME_KEY, LEGACY_THEME_KEY);
    if (t === "light" || t === "dark") theme = t;
    const f = readStored(FONT_KEY, LEGACY_FONT_KEY);
    if (f) fontSize = clampFont(Number(f));
    const z = readStored(TIMEZONE_KEY);
    if (z && isValidTimeZone(z)) timeZone = z;
  } catch {
    /* ignore */
  }
  return { theme, fontSize, timeZone };
}

export function persistPreferences(prefs: UiPreferences): void {
  try {
    localStorage.setItem(THEME_KEY, prefs.theme);
    localStorage.setItem(FONT_KEY, String(prefs.fontSize));
    localStorage.setItem(TIMEZONE_KEY, prefs.timeZone);
  } catch {
    /* ignore */
  }
}

export function applyPreferences(prefs: UiPreferences): void {
  const root = document.documentElement;
  root.setAttribute("data-theme", prefs.theme);
  root.style.colorScheme = prefs.theme;
  root.style.setProperty("--app-font-size", `${prefs.fontSize}px`);
  void syncNativeWindowTheme(prefs.theme);
}

async function syncNativeWindowTheme(theme: ThemeId): Promise<void> {
  try {
    await getCurrentWindow().setTheme(theme);
  } catch {
    /* browser preview / splash / missing permission */
  }
}
