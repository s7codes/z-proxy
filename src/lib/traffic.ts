import type { TrafficFindingKind } from "./types";

/** Passive audit categories: the engine's finding kinds plus contract drift. */
export type AuditKind = TrafficFindingKind | "contractDrift";

export const AUDIT_KINDS: readonly AuditKind[] = [
  "nPlusOneBurst",
  "retryStorm",
  "unboundedCollection",
  "headerMisconfiguration",
  "passiveDisclosure",
  "latencyRegression",
  "contractDrift",
];

export const AUDIT_LABEL: Record<AuditKind, string> = {
  nPlusOneBurst: "N+1 burst",
  retryStorm: "Retry storm",
  unboundedCollection: "Unbounded collection",
  headerMisconfiguration: "Header misconfiguration",
  passiveDisclosure: "Passive disclosure",
  latencyRegression: "Latency regression",
  contractDrift: "Contract drift",
};

export const AUDIT_SHORT: Record<AuditKind, string> = {
  nPlusOneBurst: "n+1",
  retryStorm: "storm",
  unboundedCollection: "unbounded",
  headerMisconfiguration: "headers",
  passiveDisclosure: "leak",
  latencyRegression: "slow",
  contractDrift: "drift",
};

export function emptyAuditCounts(): Record<AuditKind, number> {
  return {
    nPlusOneBurst: 0,
    retryStorm: 0,
    unboundedCollection: 0,
    headerMisconfiguration: 0,
    passiveDisclosure: 0,
    latencyRegression: 0,
    contractDrift: 0,
  };
}
