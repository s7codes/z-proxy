import type { RouteRiskKind } from "./types";

export const RISK_KINDS: readonly RouteRiskKind[] = ["unvalidatedMutation", "unboundedQuery", "floatingAsync"];

export const RISK_LABEL: Record<RouteRiskKind, string> = {
  unvalidatedMutation: "Unvalidated mutation",
  unboundedQuery: "Unbounded query",
  floatingAsync: "Floating async",
};

export const RISK_SHORT: Record<RouteRiskKind, string> = {
  unvalidatedMutation: "unvalidated",
  unboundedQuery: "unbounded",
  floatingAsync: "floating",
};
