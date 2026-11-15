import type { HeaderPair } from "./types";

/** Where Burst and Fuzzer requests go: the validated target, or the proxy in front of it. */
export interface RequestOrigin {
  url: string;
  /** Upstream the proxy forwards to, while requests are routed through the listener. */
  via: string | null;
}

export function originOf(normalized: string): string | null {
  try {
    return new URL(normalized).origin;
  } catch {
    return null;
  }
}

export function joinTarget(origin: string, path: string): string {
  return `${origin}${path.startsWith("/") ? path : `/${path}`}`;
}

/** One `Name: value` pair per line; blank lines are ignored. */
export function parseHeaders(text: string): { headers: HeaderPair[]; error: string | null } {
  const headers: HeaderPair[] = [];
  const lines = text.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]?.trim() ?? "";
    if (line === "") continue;
    const colon = line.indexOf(":");
    if (colon <= 0) return { headers, error: `line ${i + 1}: expected "Name: value"` };
    headers.push({ name: line.slice(0, colon).trim(), value: line.slice(colon + 1).trim() });
  }
  return { headers, error: null };
}
