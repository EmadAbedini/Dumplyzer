/** Bundled tools are assumed present. Live counts refresh in the background. */

import { useSyncExternalStore } from "react";
import {
  BUNDLED_TOOL,
  CHECKING_DETAIL,
  UNAVAILABLE_DETAIL,
} from "./analysisCapabilities";
import { engineCall } from "./api";
import type {
  BulkExtractorStatus,
  CapaStatus,
  FlossStatus,
  PeExtractionStatus,
  YaraStatus,
} from "./types";

export type CapabilityId =
  | "memoryAnalysis"
  | "artifactExtraction"
  | "peReconstruction"
  | "signatureDetection"
  | "capabilityAnalysis"
  | "stringAnalysis";

export type CapabilityRowState = {
  kind: "checking" | "available" | "unavailable";
  detail: string;
};

export type CapabilitySnapshot = {
  rows: Record<CapabilityId, CapabilityRowState>;
  yara: YaraStatus | null;
  peExtraction: PeExtractionStatus | null;
  capa: CapaStatus | null;
  floss: FlossStatus | null;
  bulkExtractor: BulkExtractorStatus | null;
  volatilityVersion: string | null;
};

type VolInit = {
  ok?: boolean;
  volatility3_version?: string | null;
};

type CapabilitiesStatus = {
  checking?: boolean;
  volatility?: VolInit;
  pe_extraction?: PeExtractionStatus;
  bulk_extractor?: BulkExtractorStatus;
  capa?: CapaStatus;
  floss?: FlossStatus;
  yara?: YaraStatus;
};

const AVAILABLE_ROW: CapabilityRowState = {
  kind: "available",
  detail: "Available",
};

const CHECKING_ROW: CapabilityRowState = {
  kind: "checking",
  detail: CHECKING_DETAIL,
};

function bundledRows(): Record<CapabilityId, CapabilityRowState> {
  return {
    memoryAnalysis: { ...AVAILABLE_ROW },
    artifactExtraction: { ...AVAILABLE_ROW },
    peReconstruction: { ...AVAILABLE_ROW },
    signatureDetection: { ...AVAILABLE_ROW },
    capabilityAnalysis: { ...AVAILABLE_ROW },
    stringAnalysis: { ...AVAILABLE_ROW },
  };
}

function bundledSnapshot(): CapabilitySnapshot {
  return {
    rows: bundledRows(),
    yara: {
      available: true,
      yara_version: BUNDLED_TOOL.yara,
      bundled_rule_count: BUNDLED_TOOL.yaraRuleCount,
      custom_rule_count: 0,
      loaded_rule_count: BUNDLED_TOOL.yaraRuleCount,
    },
    peExtraction: {
      available: true,
      volatility_version: BUNDLED_TOOL.volatility,
      pedump_available: true,
    },
    capa: { available: true, capa_version: BUNDLED_TOOL.capa },
    floss: { available: true, floss_version: BUNDLED_TOOL.floss },
    bulkExtractor: {
      available: true,
      bulk_extractor_version: BUNDLED_TOOL.bulkExtractor,
    },
    volatilityVersion: BUNDLED_TOOL.volatility,
  };
}

let snapshot: CapabilitySnapshot = bundledSnapshot();
let started = false;
const inflight = new Map<CapabilityId, Promise<void>>();
const listeners = new Set<() => void>();

function emit(): void {
  snapshot = {
    ...snapshot,
    rows: { ...snapshot.rows },
  };
  listeners.forEach((listener) => listener());
}

function setRow(id: CapabilityId, kind: CapabilityRowState["kind"], detail: string): void {
  snapshot.rows[id] = { kind, detail };
  emit();
}

function markFromAvailable(
  id: CapabilityId,
  available: boolean,
  availableDetail: string,
): void {
  setRow(
    id,
    available ? "available" : "unavailable",
    available ? availableDetail : UNAVAILABLE_DETAIL,
  );
}

function runOne(id: CapabilityId, work: () => Promise<void>): Promise<void> {
  const existing = inflight.get(id);
  if (existing) return existing;
  const pending = (async () => {
    try {
      await work();
    } catch {
      setRow(id, "unavailable", UNAVAILABLE_DETAIL);
    } finally {
      inflight.delete(id);
    }
  })();
  inflight.set(id, pending);
  return pending;
}

function applyVolatility(vol: VolInit | undefined): void {
  snapshot.volatilityVersion = vol?.volatility3_version ?? snapshot.volatilityVersion;
  const ok = vol?.ok !== false && Boolean(vol?.volatility3_version || vol?.ok);
  markFromAvailable("memoryAnalysis", ok, "Available");
}

async function checkMemoryAnalysis(): Promise<void> {
  applyVolatility(await engineCall<VolInit>("volatility.init"));
}

async function checkArtifactExtraction(): Promise<void> {
  const status = await engineCall<BulkExtractorStatus>("bulk_extractor.status");
  snapshot.bulkExtractor = status;
  markFromAvailable("artifactExtraction", Boolean(status.available), "Available");
}

async function checkPeReconstruction(): Promise<void> {
  const status = await engineCall<PeExtractionStatus>("pe_extraction.status");
  snapshot.peExtraction = status;
  markFromAvailable("peReconstruction", Boolean(status.available), "Available");
}

async function checkSignatureDetection(): Promise<void> {
  const status = await engineCall<YaraStatus>("yara.status");
  applySignatureDetection(status);
}

async function checkCapabilityAnalysis(): Promise<void> {
  const status = await engineCall<CapaStatus>("capa.status");
  snapshot.capa = status;
  markFromAvailable("capabilityAnalysis", Boolean(status.available), "Available");
}

async function checkStringAnalysis(): Promise<void> {
  const status = await engineCall<FlossStatus>("floss.status");
  snapshot.floss = status;
  markFromAvailable("stringAnalysis", Boolean(status.available), "Available");
}

export function applySignatureDetection(status: YaraStatus): void {
  snapshot = {
    ...snapshot,
    yara: { ...status },
    rows: {
      ...snapshot.rows,
      signatureDetection: {
        kind: status.available ? "available" : "unavailable",
        detail: status.available ? "Available" : UNAVAILABLE_DETAIL,
      },
    },
  };
  listeners.forEach((listener) => listener());
}

const CHECK_RETRY_MS = 2000;
let checkRetry: number | null = null;

function scheduleCapabilityRetry(): void {
  if (checkRetry != null) return;
  checkRetry = window.setTimeout(() => {
    checkRetry = null;
    started = false;
    startCapabilityChecks();
  }, CHECK_RETRY_MS);
}

async function checkAllCombined(): Promise<void> {
  const result = await engineCall<CapabilitiesStatus>("capabilities.status");
  if (result.checking) {
    scheduleCapabilityRetry();
    return;
  }
  applyVolatility(result.volatility);
  snapshot.peExtraction = result.pe_extraction ?? null;
  markFromAvailable("peReconstruction", Boolean(result.pe_extraction?.available), "Available");
  snapshot.bulkExtractor = result.bulk_extractor ?? null;
  markFromAvailable("artifactExtraction", Boolean(result.bulk_extractor?.available), "Available");
  snapshot.capa = result.capa ?? null;
  markFromAvailable("capabilityAnalysis", Boolean(result.capa?.available), "Available");
  snapshot.floss = result.floss ?? null;
  markFromAvailable("stringAnalysis", Boolean(result.floss?.available), "Available");
  if (result.yara) {
    applySignatureDetection(result.yara);
  } else {
    setRow("signatureDetection", "unavailable", UNAVAILABLE_DETAIL);
  }
}

/** Kick off background checks once. Safe to call from multiple views. */
export function startCapabilityChecks(): void {
  if (started) return;
  started = true;
  void (async () => {
    try {
      await checkAllCombined();
    } catch {
      void runOne("memoryAnalysis", checkMemoryAnalysis);
      void runOne("peReconstruction", checkPeReconstruction);
      void runOne("artifactExtraction", checkArtifactExtraction);
      void runOne("capabilityAnalysis", checkCapabilityAnalysis);
      void runOne("stringAnalysis", checkStringAnalysis);
      void runOne("signatureDetection", checkSignatureDetection);
    }
  })();
}

/** Re-run Signature Detection after Reload Rules. Does not restart other checks. */
export function refreshSignatureDetection(status?: YaraStatus): Promise<void> {
  started = true;
  inflight.delete("signatureDetection");
  if (status) {
    applySignatureDetection(status);
    return Promise.resolve();
  }
  snapshot.yara = null;
  snapshot.rows.signatureDetection = { ...CHECKING_ROW };
  emit();
  return runOne("signatureDetection", checkSignatureDetection);
}

export function getCapabilitySnapshot(): CapabilitySnapshot {
  return snapshot;
}

export function subscribeCapabilityStatus(listener: () => void): () => void {
  listeners.add(listener);
  startCapabilityChecks();
  return () => {
    listeners.delete(listener);
  };
}

export function useCapabilityStatus(): CapabilitySnapshot {
  return useSyncExternalStore(
    subscribeCapabilityStatus,
    getCapabilitySnapshot,
    getCapabilitySnapshot,
  );
}
