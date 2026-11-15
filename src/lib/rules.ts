import type { FaultProfile, FaultRule, ProxyStatus, RouteMethod } from "./types";

/** Listener port the Faults tab and "Route via Proxy" default to. */
export const DEFAULT_LISTEN_PORT = 8787;

export function summarizeProfile(profile: FaultProfile): string {
  const parts: string[] = [];
  if (profile.latencyMs > 0 || profile.jitterMs > 0) {
    parts.push(profile.jitterMs > 0 ? `${profile.latencyMs}±${profile.jitterMs}ms` : `${profile.latencyMs}ms`);
  }
  if (profile.dropRate > 0) parts.push(`rst ${profile.dropRate}%`);
  if (profile.statusMutation !== "none" && profile.mutationRate > 0) {
    parts.push(`${profile.statusMutation}@${profile.mutationRate}%`);
  }
  return parts.length === 0 ? "passthrough" : parts.join(" ");
}

export function ruleLabel(rule: FaultRule): string {
  return `${rule.method ?? "ANY"} ${rule.pathPattern}`;
}

function escapeRegex(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * Anchored regex for a rule pattern, built like engine/fault.rs `PathMatcher::compile`:
 * `{name}` is one segment (also embedded), `{*name}` the remainder as the final segment.
 * `null` for a pattern the engine would reject.
 */
export function compileRulePattern(pattern: string): RegExp | null {
  if (!pattern.startsWith("/")) return null;
  const segments = pattern.split("/").filter((s) => s !== "");
  let source = "^";
  for (const [index, segment] of segments.entries()) {
    const catchAll = /^\{\*([^{}]+)\}$/.exec(segment);
    if (catchAll !== null) {
      if (index + 1 !== segments.length) return null;
      source += "(?:/.*)?";
      continue;
    }
    source += "/";
    let rest = segment;
    for (let open = rest.indexOf("{"); open !== -1; open = rest.indexOf("{")) {
      const close = rest.indexOf("}", open);
      if (close === -1) return null;
      const name = rest.slice(open + 1, close);
      if (name === "" || name.includes("*") || name.includes("{")) return null;
      source += `${escapeRegex(rest.slice(0, open))}[^/]+`;
      rest = rest.slice(close + 1);
    }
    if (rest.includes("}")) return null;
    source += escapeRegex(rest);
  }
  if (segments.length === 0) source += "/";
  return new RegExp(`${source}$`);
}

/** Empty segments collapse before matching, as on the engine side. */
function collapse(path: string): string {
  return `/${path.split("/").filter((s) => s !== "").join("/")}`;
}

/**
 * Upstream path for an inbound path: the proxy prefixes the upstream base path
 * (engine/proxy.rs `upstream_url`), and rules match against that.
 */
export function upstreamPath(upstream: string | null, path: string): string {
  const pathOnly = path.split("?")[0] ?? path;
  if (upstream === null) return pathOnly;
  try {
    const prefix = new URL(upstream).pathname.replace(/\/+$/, "");
    return `${prefix}${pathOnly.startsWith("/") ? pathOnly : `/${pathOnly}`}`;
  } catch {
    return pathOnly;
  }
}

export interface RuleMatch {
  index: number;
  rule: FaultRule;
}

/**
 * First proxy rule that applies to a route. A route template is matched as literal text,
 * so its `{param}` segments stand for any one segment, the way requests to it would. A route
 * declared for ANY method can receive a request every rule method matches.
 */
export function matchingRule(proxy: ProxyStatus | null, method: RouteMethod, path: string): RuleMatch | null {
  if (proxy === null || proxy.rules.length === 0) return null;
  const target = collapse(upstreamPath(proxy.upstream, path));
  for (const [index, rule] of proxy.rules.entries()) {
    const methodOk = rule.method === null || rule.method === "ANY" || method === "ANY" || rule.method === method;
    if (!methodOk) continue;
    if (compileRulePattern(rule.pathPattern)?.test(target) === true) return { index, rule };
  }
  return null;
}
