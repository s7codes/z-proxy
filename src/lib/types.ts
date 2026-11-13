// Mirrors src-tauri/src/engine/types.rs and engine/error.rs. Keep field names and unions
// in lockstep with the serde attributes on the Rust side.

export type HostKind = "ipv4" | "ipv6" | "localhost";

export type Verdict = "accepted" | "rejected";

export type ProbeResult =
  | { state: "reachable"; status: number; latencyUs: number }
  | { state: "unreachable"; reason: string; latencyUs: number };

export interface ValidatedTarget {
  input: string;
  normalized: string;
  scheme: string;
  host: string;
  hostKind: HostKind;
  port: number;
  probe: ProbeResult;
}

export interface EngineStatus {
  version: string;
  uptimeMs: number;
  telemetrySubscribers: number;
  guardMode: string;
  allowlist: [string, string, string];
  proxyListener: string | null;
}

export type TelemetryEvent =
  | {
      kind: "engineHeartbeat";
      seq: number;
      tsUs: number;
      uptimeMs: number;
      subscribers: number;
    }
  | {
      kind: "guardDecision";
      seq: number;
      id: string;
      tsUs: number;
      input: string;
      verdict: Verdict;
      host: string | null;
      code: EngineErrorCode | null;
    }
  | {
      kind: "probeCompleted";
      seq: number;
      id: string;
      tsUs: number;
      url: string;
      status: number | null;
      latencyUs: number;
      error: string | null;
    };

export type TelemetryKind = TelemetryEvent["kind"];

export type EngineErrorCode =
  | "NON_LOOPBACK_TARGET_REJECTED"
  | "INVALID_TARGET"
  | "UNSUPPORTED_SCHEME"
  | "CLIENT_BUILD_FAILED";

export type EngineError =
  | { code: "NON_LOOPBACK_TARGET_REJECTED"; message: string; host: string }
  | { code: "INVALID_TARGET"; message: string; input: string }
  | { code: "UNSUPPORTED_SCHEME"; message: string; scheme: string }
  | { code: "CLIENT_BUILD_FAILED"; message: string };

/** Frontend-only staging shape; becomes the Rust `FaultProfile` when the M2 proxy lands. */
export interface FaultProfile {
  latencyMs: number;
  jitterMs: number;
  dropRate: number;
  statusMutation: StatusMutation;
  mutationRate: number;
}

export type StatusMutation = "none" | "500" | "502" | "503" | "504" | "429";
