import { toBurstMethod } from "./routes";
import type {
  BurstMethod,
  ContractViolation,
  ContractViolationKind,
  DiscoveredRoute,
  ResponseContract,
  RouteContract,
} from "./types";

export const VIOLATION_LABEL: Record<ContractViolationKind, string> = {
  undocumentedStatus: "undocumented status",
  missingRequiredField: "missing field",
  responseTypeMismatch: "type mismatch",
};

export function describeViolation(violation: ContractViolation): string {
  if (violation.pointer === null) return `status ${violation.actual} not documented; ${violation.expected}`;
  const at = violation.pointer === "" ? "body" : violation.pointer;
  return `${at}: expected ${violation.expected}, got ${violation.actual}`;
}

/** First violation in words, with the remainder as a count. */
export function summarizeViolations(violations: readonly ContractViolation[]): string | null {
  const first = violations[0];
  if (first === undefined) return null;
  const rest = violations.length - 1;
  return `${describeViolation(first)}${rest > 0 ? ` (+${rest})` : ""}`;
}

/** Every OpenAPI route of a scan report that documents responses, in the engine's inbound shape. */
export function routeContracts(routes: readonly DiscoveredRoute[]): RouteContract[] {
  return routes.flatMap((route) =>
    route.contract === null ? [] : [{ method: route.method, path: route.path, contract: route.contract }],
  );
}

/** The selected route's contract while the request panels still target that operation. */
export function contractFor(
  route: DiscoveredRoute | null,
  method: BurstMethod,
  path: string,
): ResponseContract | null {
  if (route === null || route.contract === null || route.path !== path) return null;
  return route.method === "ANY" || toBurstMethod(route.method) === method ? route.contract : null;
}

export function contractSummary(contract: ResponseContract): string {
  const statuses = [
    ...contract.statuses.map(String),
    ...contract.statusClasses.map((digit) => `${digit}XX`),
    ...(contract.hasDefault ? ["default"] : []),
  ];
  const fields = contract.fields.filter((field) => field.pointer !== "").length;
  return `${statuses.join(" ")}${contract.bodyStatus === null ? "" : `; ${fields} fields on ${contract.bodyStatus}`}`;
}
