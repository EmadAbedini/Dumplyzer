/** User-facing capability labels. Underlying provider IDs stay unchanged. */

export const CAPABILITY = {
  memoryAnalysis: "Memory Analysis",
  artifactExtraction: "Artifact Extraction",
  peReconstruction: "PE Reconstruction",
  signatureDetection: "Signature Detection",
  capabilityAnalysis: "Capability Analysis",
  stringAnalysis: "String Analysis",
} as const;

export const CHECKING_DETAIL = "Checking…";
export const UNAVAILABLE_DETAIL = "Unavailable";

export function availableDetail(available: boolean): string {
  return available ? "Available" : UNAVAILABLE_DETAIL;
}

export function capabilityMark(kind: "checking" | "available" | "unavailable"): "✓" | "○" {
  return kind === "unavailable" ? "○" : "✓";
}

export function technicalImplementationLine(
  toolName: string,
  version: string | null | undefined,
  available: boolean,
  optional = false,
): string {
  if (!available) {
    return optional ? `${toolName} — optional` : `${toolName} — not available`;
  }
  const ver = typeof version === "string" && version.trim() ? version.trim() : null;
  return ver ? `${toolName} — ${ver}` : `${toolName} — available`;
}
