import { getName, getVersion } from "@tauri-apps/api/app";

export type AppMeta = {
  name: string;
  version: string;
};

export async function loadAppMeta(): Promise<AppMeta> {
  const [name, version] = await Promise.all([getName(), getVersion()]);
  return { name, version };
}

export function formatAppVersion(version: string): string {
  const trimmed = version.trim();
  if (!trimmed) return "";
  return trimmed.startsWith("v") || trimmed.startsWith("V") ? trimmed : `v${trimmed}`;
}
