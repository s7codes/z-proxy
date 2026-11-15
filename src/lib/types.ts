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

// ---- fuzzer ---------------------------------------------------------------------------

/** Declaration order is execution order. */
export type MutationClass =
  | "nullInjection"
  | "emptyStrings"
  | "boundaryNumbers"
  | "typeConfusion"
  | "oversizedField"
  | "malformedJson"
  | "missingFields";

export interface FuzzSpec {
  target: string;
  method: BurstMethod;
  headers: HeaderPair[];
  /** JSON object to mutate; `null` or blank uses the built-in template. */
  baseBody: string | null;
  /** Empty selects every class. */
  classes: MutationClass[];
  timeoutMs: number;
}

export type FuzzVerdict = "rejected" | "accepted" | "serverError" | "transportFailure" | "unreachable" | "skipped";

export interface FuzzCaseResult {
  index: number;
  /** `null` for the unmutated baseline request. */
  class: MutationClass | null;
  label: string;
  /** RFC 6901 pointer of the mutated field; `null` for whole-body mutations. */
  pointer: string | null;
  requestBytes: number;
  status: number | null;
  latencyUs: number;
  responseBytes: number;
  responsePreview: string | null;
  verdict: FuzzVerdict;
  severity: Severity | null;
  error: string | null;
}

export interface ClassSummary {
  class: MutationClass;
  cases: number;
  rejected: number;
  accepted: number;
  faults: number;
  unreached: number;
}

export interface FuzzReport {
  id: string;
  target: string;
  method: BurstMethod;
  fields: number;
  wallUs: number;
  baseline: FuzzCaseResult;
  cases: FuzzCaseResult[];
  summary: ClassSummary[];
  faults: number;
  warnings: number;
  aborted: string | null;
  notes: string[];
}

// ---- route scanner --------------------------------------------------------------------

export type RouteMethod = "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS" | "ANY";

export type RouteSource =
  | "nextAppRouter"
  | "nextPagesApi"
  | "express"
  | "fastify"
  | "hono"
  | "axum"
  | "go"
  | "openApi";

export interface DiscoveredRoute {
  method: RouteMethod;
  /** Normalized template: parameters as `{name}`, catch-alls as `{*name}`. */
  path: string;
  params: string[];
  source: RouteSource;
  /** Relative to the scan root, `/`-separated. */
  file: string;
  line: number;
}

export interface ScanIssue {
  file: string;
  reason: string;
}

export interface RouteScanReport {
  id: string;
  root: string;
  filesVisited: number;
  filesParsed: number;
  elapsedUs: number;
  truncated: boolean;
  routes: DiscoveredRoute[];
  issues: ScanIssue[];
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
    }
  | {
      kind: "routeScanCompleted";
      seq: number;
      id: string;
      tsUs: number;
      root: string;
      routes: number;
      filesVisited: number;
      elapsedUs: number;
      truncated: boolean;
    }
  | {
      kind: "fuzzerStarted";
      seq: number;
      id: string;
      tsUs: number;
      target: string;
      method: BurstMethod;
      /** Mutation cases, excluding the baseline. */
      cases: number;
    }
  | {
      kind: "fuzzerCaseCompleted";
      seq: number;
      id: string;
      tsUs: number;
      result: FuzzCaseResult;
    }
  | {
      kind: "fuzzerCompleted";
      seq: number;
      id: string;
      tsUs: number;
      wallUs: number;
      cases: number;
      faults: number;
      warnings: number;
      aborted: string | null;
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
  | "INVALID_BURST_SPEC"
  | "INVALID_FUZZ_SPEC"
  | "FUZZER_BUSY"
  | "INVALID_SCAN_ROOT"
  | "INTERNAL_TASK_FAILED";

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
  | { code: "INVALID_BURST_SPEC"; message: string; field: string }
  | { code: "INVALID_FUZZ_SPEC"; message: string; field: string }
  | { code: "FUZZER_BUSY"; message: string }
  | { code: "INVALID_SCAN_ROOT"; message: string; path: string }
  | { code: "INTERNAL_TASK_FAILED"; message: string };
