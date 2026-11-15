import type { BurstMethod, RouteMethod, RouteSource } from "./types";

/** Method and path shared by the Burst and Fuzzer panels; a route selection writes both. */
export interface RequestTarget {
  method: BurstMethod;
  path: string;
}

export const SOURCE_LABEL: Record<RouteSource, string> = {
  nextAppRouter: "next app",
  nextPagesApi: "next pages",
  express: "express",
  fastify: "fastify",
  hono: "hono",
  axum: "axum",
  go: "go",
  openApi: "openapi",
};

// Same abbreviations HTTP clients use, so every badge fits one fixed column.
export const METHOD_BADGE: Record<RouteMethod, string> = {
  GET: "GET",
  POST: "POST",
  PUT: "PUT",
  PATCH: "PATCH",
  DELETE: "DEL",
  HEAD: "HEAD",
  OPTIONS: "OPT",
  ANY: "ANY",
};

const BURST_METHODS: ReadonlySet<string> = new Set<BurstMethod>(["GET", "POST", "PUT", "PATCH", "DELETE"]);

function isBurstMethod(method: RouteMethod): method is BurstMethod {
  return BURST_METHODS.has(method);
}

/** `null` for ANY / HEAD / OPTIONS: the panels keep their current method. */
export function toBurstMethod(method: RouteMethod): BurstMethod | null {
  return isBurstMethod(method) ? method : null;
}

/** Value the engine sends for every `{param}` placeholder (engine/pathparam.rs). */
export const DEFAULT_PATH_VALUE = "1";

/**
 * `{name}` and `{*name}` placeholders in a request path, with the name syntax the engine
 * recognizes; catch-alls keep their `*`.
 */
export function pathParams(path: string): string[] {
  return Array.from(path.matchAll(/\{(\*?[A-Za-z0-9_.-]+)\}/g), (match) => match[1] ?? "");
}

export function fileLabel(file: string, line: number): string {
  const slash = file.lastIndexOf("/");
  return `${slash === -1 ? file : file.slice(slash + 1)}:${line}`;
}
