// Mirrors src-tauri/src/engine/{types,fault,error}.rs. Keep field names and unions in
// lockstep with the serde attributes on the Rust side.

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

// ---- fault injection / proxy ----------------------------------------------------------

export type StatusMutation = "none" | "429" | "500" | "502" | "503" | "504";

/** Rates are integer percentages (0-100). */
export interface FaultProfile {
  latencyMs: number;
  jitterMs: number;
  dropRate: number;
  statusMutation: StatusMutation;
  mutationRate: number;
}

export interface ProxyConfig {
  upstream: string;
  /** `0` binds an ephemeral port. */
  listenPort: number;
}

export interface ProxyStatus {
  running: boolean;
  listener: string | null;
  upstream: string | null;
  armed: boolean;
  profile: FaultProfile;
}

export type FaultKind = "statusMutation" | "connectionDrop";

// ---- concurrency burst ----------------------------------------------------------------

export type BurstMethod = "GET" | "POST" | "PUT" | "PATCH" | "DELETE";

export interface HeaderPair {
  name: string;
  value: string;
}

export interface BurstSpec {
  target: string;
  method: BurstMethod;
  workers: number;
  headers: HeaderPair[];
  body: string | null;
  timeoutMs: number;
}

export interface WorkerSample {
  worker: number;
  status: number | null;
  dispatchOffsetUs: number | null;
  latencyUs: number;
  bytes: number;
  bodyHash: string | null;
  error: string | null;
}

export interface StatusBucket {
  status: number | null;
  count: number;
}

export interface LatencyStats {
  minUs: number;
  maxUs: number;
  meanUs: number;
  p50Us: number;
  p95Us: number;
  p99Us: number;
}

export interface SizeStats {
  minBytes: number;
  maxBytes: number;
}

export type AnomalyKind = "raceWindow" | "statusDivergence" | "bodyDivergence" | "transportErrors";

export type Severity = "warn" | "fault";

export interface Anomaly {
  kind: AnomalyKind;
  severity: Severity;
  detail: string;
  workers: number[];
}

export interface BurstReport {
  id: string;
  target: string;
  method: BurstMethod;
  workers: number;
  wallUs: number;
  dispatchSpreadUs: number | null;
  statusHistogram: StatusBucket[];
  latency: LatencyStats | null;
  size: SizeStats | null;
  distinctBodies: number;
  anomalies: Anomaly[];
  samples: WorkerSample[];
}

// ---- telemetry ------------------------------------------------------------------------

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
    }
  | {
      kind: "proxyStateChanged";
      seq: number;
      tsUs: number;
      status: ProxyStatus;
    }
  | {
      kind: "proxyExchange";
      seq: number;
      id: string;
      tsUs: number;
      method: string;
      path: string;
      upstream: string;
      status: number | null;
      latencyUs: number;
      injectedDelayUs: number;
      upstreamLatencyUs: number | null;
      fault: FaultKind | null;
      requestBytes: number;
      responseBytes: number;
      error: string | null;
    }
  | {
      kind: "burstStarted";
      seq: number;
      id: string;
      tsUs: number;
      target: string;
      method: BurstMethod;
      workers: number;
    }
  | {
      kind: "burstSample";
      seq: number;
      id: string;
      tsUs: number;
      sample: WorkerSample;
    }
  | {
      kind: "burstCompleted";
      seq: number;
      id: string;
      tsUs: number;
      wallUs: number;
      dispatchSpreadUs: number | null;
      anomalies: number;
      errors: number;
    };

export type TelemetryKind = TelemetryEvent["kind"];

export type TelemetryEventOf<K extends TelemetryKind> = Extract<TelemetryEvent, { kind: K }>;

// ---- errors ---------------------------------------------------------------------------

export type EngineErrorCode =
  | "NON_LOOPBACK_TARGET_REJECTED"
  | "INVALID_TARGET"
  | "UNSUPPORTED_SCHEME"
  | "PLAINTEXT_ONLY"
  | "CLIENT_BUILD_FAILED"
  | "PROXY_ALREADY_RUNNING"
  | "LISTENER_BIND_FAILED"
  | "PROXY_LOOP"
  | "INVALID_FAULT_PROFILE"
  | "INVALID_BURST_SPEC";

export type EngineError =
  | { code: "NON_LOOPBACK_TARGET_REJECTED"; message: string; host: string }
  | { code: "INVALID_TARGET"; message: string; input: string }
  | { code: "UNSUPPORTED_SCHEME"; message: string; scheme: string }
  | { code: "PLAINTEXT_ONLY"; message: string; scheme: string }
  | { code: "CLIENT_BUILD_FAILED"; message: string }
  | { code: "PROXY_ALREADY_RUNNING"; message: string; listener: string }
  | { code: "LISTENER_BIND_FAILED"; message: string; addr: string }
  | { code: "PROXY_LOOP"; message: string; addr: string }
  | { code: "INVALID_FAULT_PROFILE"; message: string; field: string }
  | { code: "INVALID_BURST_SPEC"; message: string; field: string };
