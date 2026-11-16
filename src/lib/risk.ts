import type { BurstSyncMode, MutationClass, RouteRiskKind } from "./types";

export const RISK_KINDS: readonly RouteRiskKind[] = [
  "unvalidatedMutation",
  "unboundedQuery",
  "floatingAsync",
  "nonAtomicMultiWrite",
  "unsafeSqlInterpolation",
];

export const RISK_LABEL: Record<RouteRiskKind, string> = {
  unvalidatedMutation: "Unvalidated mutation",
  unboundedQuery: "Unbounded query",
  floatingAsync: "Floating async",
  nonAtomicMultiWrite: "Non-atomic multi-write",
  unsafeSqlInterpolation: "Unsafe SQL interpolation",
};

export const RISK_SHORT: Record<RouteRiskKind, string> = {
  unvalidatedMutation: "unvalidated",
  unboundedQuery: "unbounded",
  floatingAsync: "floating",
  nonAtomicMultiWrite: "non-atomic",
  unsafeSqlInterpolation: "sql-interp",
};

/** Burst setup an auto-targeted risk opens with. */
export interface BurstPreset {
  workers: number;
  syncMode: BurstSyncMode;
}

/** Fuzzer setup an auto-targeted risk opens with. */
export interface FuzzPreset {
  classes: MutationClass[];
}

/**
 * How a static finding is exercised live. Interleaving faults (partial writes, unbounded
 * scans) surface under synchronized concurrency; input faults (missing validation, string-built
 * SQL, unguarded rejections) surface under malformed payloads.
 */
export type AutoTarget =
  | { tab: "burst"; burst: BurstPreset; reason: string }
  | { tab: "fuzzer"; fuzz: FuzzPreset; reason: string };

const CONTENDED_BURST: BurstPreset = { workers: 32, syncMode: "lastByte" };

export const AUTO_TARGET: Record<RouteRiskKind, AutoTarget> = {
  unvalidatedMutation: {
    tab: "fuzzer",
    fuzz: { classes: ["nullInjection", "boundaryNumbers", "typeConfusion", "missingFields", "schemaContractBounds"] },
    reason: "type, null, boundary and schema-contract vectors against the unvalidated body",
  },
  unsafeSqlInterpolation: {
    tab: "fuzzer",
    fuzz: {
      classes: [
        "emptyStrings",
        "typeConfusion",
        "oversizedField",
        "pathParamValidation",
        "delimiterEscaping",
        "queryAndHeaderBounds",
      ],
    },
    reason: "delimiter, query, string, type and path vectors that reach the string-built query",
  },
  floatingAsync: {
    tab: "fuzzer",
    fuzz: { classes: ["nullInjection", "typeConfusion", "malformedJson"] },
    reason: "inputs that make the dropped call reject",
  },
  nonAtomicMultiWrite: {
    tab: "burst",
    burst: CONTENDED_BURST,
    reason: "32 workers, last byte held, to interleave the unguarded writes",
  },
  unboundedQuery: {
    tab: "burst",
    burst: CONTENDED_BURST,
    reason: "32 workers, last byte held, to stack the unbounded reads",
  },
};
