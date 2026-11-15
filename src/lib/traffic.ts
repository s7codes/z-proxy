import type { TrafficFindingKind } from "./types";

/** Passive audit categories: the engine's finding kinds plus contract drift. */
export type AuditKind = TrafficFindingKind | "contractDrift";

export const AUDIT_KINDS: readonly AuditKind[] = [
  "nPlusOneBurst",
  "unboundedCollection",
  "headerMisconfiguration",
  "passiveDisclosure",
  "contractDrift",
];

export const AUDIT_LABEL: Record<AuditKind, string> = {
  nPlusOneBurst: "N+1 burst",
  unboundedCollection: "Unbounded collection",
  headerMisconfiguration: "Header misconfiguration",
  passiveDisclosure: "Passive disclosure",
  contractDrift: "Contract drift",
};

export const AUDIT_SHORT: Record<AuditKind, string> = {
  nPlusOneBurst: "n+1",
  unboundedCollection: "unbounded",
  headerMisconfiguration: "headers",
  passiveDisclosure: "leak",
  contractDrift: "drift",
};

export function emptyAuditCounts(): Record<AuditKind, number> {
  return {
    nPlusOneBurst: 0,
    unboundedCollection: 0,
    headerMisconfiguration: 0,
    passiveDisclosure: 0,
    contractDrift: 0,
  };
}
