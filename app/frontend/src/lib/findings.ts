import type { Finding } from "./types";

const TITLE_COPY: Record<string, string> = {
  encoded_powershell: "Encoded PowerShell",
  cmd_launch_lolbin: "LOLBin launched via cmd.exe",
  user_temp_execution_path: "Executable path under user temp",
  vad_writable_executable: "Writable executable memory",
  private_executable_vad: "Private executable VAD",
};

const SEVERITY_RANK: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
  informational: 4,
};

export function findingTitle(finding: Finding): string {
  const raw = (finding.finding_type || "").trim();
  if (!raw) return "Finding";
  return TITLE_COPY[raw] ?? humanizeToken(raw);
}

export function findingSeverity(finding: Finding): string {
  const value = (finding.severity || "").trim();
  return value || "info";
}

export function findingSeverityRank(severity: string): number {
  return SEVERITY_RANK[severity.toLowerCase()] ?? 50;
}

export function sortFindings(items: Finding[]): Finding[] {
  return [...items].sort((a, b) => {
    const sev = findingSeverityRank(findingSeverity(a)) - findingSeverityRank(findingSeverity(b));
    if (sev !== 0) return sev;
    return findingTitle(a).localeCompare(findingTitle(b));
  });
}

export function countFindingsBySeverity(items: Finding[]): Array<{ id: string; count: number }> {
  const counts = new Map<string, number>();
  for (const item of items) {
    const id = findingSeverity(item).toLowerCase();
    counts.set(id, (counts.get(id) ?? 0) + 1);
  }
  return [...counts.entries()]
    .sort((a, b) => findingSeverityRank(a[0]) - findingSeverityRank(b[0]))
    .map(([id, count]) => ({ id, count }));
}

export function findingSeverityClass(severity: string): string {
  const value = severity.toLowerCase();
  if (value === "critical" || value === "high") return "finding-sev-high";
  if (value === "medium") return "finding-sev-medium";
  if (value === "low") return "finding-sev-low";
  return "finding-sev-info";
}

function humanizeToken(value: string): string {
  return value
    .replace(/[_-]+/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .replace(/\b\w/g, (ch) => ch.toUpperCase());
}
