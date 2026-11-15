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
  /**
   * Share of forwarded responses cut mid-body: head and leading bytes reach the client, then
   * the connection is reset. `null` (or absent from an older caller) is 0.
   */
  partialDropRate?: number | null;
  /** Body bytes written before the reset; `null` cuts at half the body. */
  partialDropBytes?: number | null;
}

/** Binds a profile to one route, matched against the path the upstream receives. */
export interface FaultRule {
  /** `null` or `ANY` matches every method. */
  method: RouteMethod | null;
  /** Scanner template syntax: `{name}` one segment, `{*name}` the remainder (last segment). */
  pathPattern: string;
  profile: FaultProfile;
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
  /** Evaluated in order before the global profile; the first match wins. */
  rules: FaultRule[];
  /** Response contracts the proxy checks forwarded responses against. */
  contracts: number;
}

export type FaultKind = "statusMutation" | "connectionDrop" | "partialBodyDrop";

// ---- concurrency burst ----------------------------------------------------------------

export type BurstMethod = "GET" | "POST" | "PUT" | "PATCH" | "DELETE";

export interface HeaderPair {
  name: string;
  value: string;
}

/**
 * `preConnected`: connections handshaken before the barrier, full requests written on release.
 * `lastByte`: every request byte but the last written before the barrier; release writes one.
 */
export type BurstSyncMode = "preConnected" | "lastByte";

export interface BurstSpec {
  /** May hold `{param}` placeholders in the path; each is sent as `1`. */
  target: string;
  method: BurstMethod;
  workers: number;
  headers: HeaderPair[];
  body: string | null;
  timeoutMs: number;
  /**
   * Upper bound on 2xx responses the operation may produce (1 for a single-use coupon or an
   * idempotent charge); more is a race window even without conflicts. `null`: no quota.
   */
  expectedMaxSuccesses: number | null;
  /**
   * Every worker sends one `Idempotency-Key` (a supplied header, else a generated UUID);
   * 2xx responses must then carry one replayed body. POST, PUT and PATCH only.
   */
  idempotencyMode: boolean;
  /** `null` is `preConnected`. */
  syncMode?: BurstSyncMode | null;
  /** Documented responses of the targeted operation; every response is checked against it. */
  contract?: ResponseContract | null;
}

export interface WorkerSample {
  worker: number;
  status: number | null;
  dispatchOffsetUs: number | null;
  /** Request write to parsed response head; `null` when no head arrived. */
  ttfbUs: number | null;
  /** Request write to the last body frame, or to the failure. */
  latencyUs: number;
  bytes: number;
  bodyHash: string | null;
  error: string | null;
  /** Drift of this response from the spec's `contract`; empty without one. */
  violations: ContractViolation[];
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

export type AnomalyKind =
  | "raceWindow"
  | "statusDivergence"
  | "bodyDivergence"
  | "transportErrors"
  | "idempotencyViolation"
  /** Responses that broke the spec's contract under load; `fault` when a 2xx drifted. */
  | "contractDrift";

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
  syncMode: BurstSyncMode;
  wallUs: number;
  dispatchSpreadUs: number | null;
  statusHistogram: StatusBucket[];
  /** Total exchange time over responded workers. */
  latency: LatencyStats | null;
  /** Time to the response head over responded workers. */
  ttfb: LatencyStats | null;
  size: SizeStats | null;
  distinctBodies: number;
  /** Quota the race analysis applied, echoed from the spec. */
  expectedMaxSuccesses: number | null;
  /** Key every worker sent in idempotency mode. */
  idempotencyKey: string | null;
  /** Responses that broke the spec's `contract`; 0 without one. */
  contractViolations: number;
  anomalies: Anomaly[];
  samples: WorkerSample[];
}

// ---- fuzzer ---------------------------------------------------------------------------

/** Declaration order is execution order; new classes are appended so case indices hold. */
export type MutationClass =
  | "nullInjection"
  | "emptyStrings"
  | "boundaryNumbers"
  | "typeConfusion"
  | "oversizedField"
  | "malformedJson"
  | "missingFields"
  | "schemaContractBounds"
  | "pathParamValidation";

export interface FuzzSpec {
  /** May hold `{param}` placeholders in the path; path vectors vary each slot. */
  target: string;
  method: BurstMethod;
  headers: HeaderPair[];
  /** JSON object to mutate; `null` or blank uses the built-in template. */
  baseBody: string | null;
  /** Empty selects every class. */
  classes: MutationClass[];
  timeoutMs: number;
  /** Documented responses of the targeted operation; every response is checked against it. */
  contract: ResponseContract | null;
}

export type FuzzVerdict = "rejected" | "accepted" | "serverError" | "transportFailure" | "unreachable" | "skipped";

/** Runtime or database internals exposed in a response body. */
export type DisclosureKind =
  | "nodeStackTrace"
  | "pythonTraceback"
  | "rustPanic"
  | "goPanic"
  | "jvmStackTrace"
  | "dotNetStackTrace"
  | "sqlError";

export interface Disclosure {
  kind: DisclosureKind;
  /** Matched fragment, trimmed to 160 characters. */
  evidence: string;
}

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
  /** Found in the preview whatever the status; raises a clean mutation case to `warn`. */
  disclosure: Disclosure | null;
  /** Drift from the spec's `contract`; empty without one. Raises a clean mutation case to `warn`. */
  violations: ContractViolation[];
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
  /** Mutation cases whose response disclosed a stack trace or database error. */
  disclosures: number;
  /** Requests, baseline included, whose response broke the documented contract. */
  contractViolations: number;
  aborted: string | null;
  notes: string[];
  /** Base payload exactly as sent in the baseline; with `classes` and `pathTemplate` it reproduces any case. */
  baseBody: string;
  /** Classes in execution order. */
  classes: MutationClass[];
  /** Origin-form target path with its `{param}` slots; `null` when it had none. */
  pathTemplate: string | null;
}

/** Addresses one case of a finished suite for replay. */
export interface FuzzCaseRef {
  baseBody: string;
  classes: MutationClass[];
  pathTemplate: string | null;
  /** `0` is the baseline. */
  index: number;
}

export interface FuzzCasePayload {
  index: number;
  label: string;
  /** Origin-form request target of a path case; `null` when the case used the suite target. */
  path: string | null;
  body: string;
  /** Size of the body as sent by the fuzzer. */
  bytes: number;
  /** The sent body was not valid UTF-8; invalid sequences in `body` are U+FFFD. */
  lossy: boolean;
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
  /** Normalized mount prefix resolved within the declaring file; already part of `path`. */
  prefix: string | null;
  /** Pretty-printed JSON request body from the OpenAPI `requestBody` (example or schema). */
  sampleBody: string | null;
  /** Documented responses of an OpenAPI operation. */
  contract: ResponseContract | null;
  /** Static reliability findings in the handler's source; empty for OpenAPI routes. */
  risks: RouteRisk[];
}

/** Declaration order is report order. */
export type RouteRiskKind = "unvalidatedMutation" | "unboundedQuery" | "floatingAsync";

export interface RouteRisk {
  kind: RouteRiskKind;
  /** 1-based line of the evidence in the route's file. */
  line: number;
  /** The evidence line, trimmed to 120 characters. */
  evidence: string;
  detail: string;
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

// ---- response contracts ---------------------------------------------------------------

/** JSON value type as an OpenAPI schema names it; `integer` is a number without a fraction. */
export type JsonKind = "string" | "integer" | "number" | "boolean" | "array" | "object" | "null";

export interface ContractField {
  /** RFC 6901 pointer from the body root; `""` is the root itself. */
  pointer: string;
  /** Accepted types; empty accepts any value. */
  kinds: JsonKind[];
  /** Listed in the parent schema's `required`; nested fields are checked while the parent is present. */
  required: boolean;
  /** Value constraints declared on the field's schema; `null` when it declares none. */
  constraints?: ValueConstraints | null;
}

/** String formats the contract check validates; any other `format` is not checked. */
export type StringFormat = "uuid" | "email" | "dateTime" | "date";

export interface NumericBound {
  value: number;
  /** `exclusiveMinimum` / `exclusiveMaximum` (3.0 flag or 3.1 number). */
  exclusive: boolean;
}

/** A scalar `enum` member. */
export type EnumValue = string | number | boolean | null;

/** Constraints on a field's value beyond its type; a `null` value is never judged against them. */
export interface ValueConstraints {
  minimum: NumericBound | null;
  maximum: NumericBound | null;
  /** String length in Unicode scalar values. */
  minLength: number | null;
  maxLength: number | null;
  /** Members of an all-scalar `enum` (or a scalar `const`). */
  enumValues: EnumValue[] | null;
  format: StringFormat | null;
}

export interface ResponseContract {
  /** Explicit status codes under `responses`, ascending. */
  statuses: number[];
  /** Leading digit of each documented range (`4XX` is 4). */
  statusClasses: number[];
  /** A `default` response documents every status. */
  hasDefault: boolean;
  /** Status whose JSON body `fields` describe: 200, else 201. */
  bodyStatus: number | null;
  fields: ContractField[];
}

export type ContractViolationKind =
  | "undocumentedStatus"
  | "missingRequiredField"
  | "responseTypeMismatch"
  /** A correctly typed value outside its documented bounds, length, enum or format. */
  | "constraintViolation";

export interface ContractViolation {
  kind: ContractViolationKind;
  /** Field pointer; `null` for a status violation. */
  pointer: string | null;
  expected: string;
  actual: string;
}

/** A contract bound to a route template, matched against the path the upstream receives. */
export interface RouteContract {
  method: RouteMethod;
  path: string;
  contract: ResponseContract;
}

// ---- passive traffic audit ------------------------------------------------------------

export type TrafficFindingKind =
  | "nPlusOneBurst"
  | "unboundedCollection"
  | "headerMisconfiguration"
  | "passiveDisclosure"
  /** One exact request repeated 10+ times inside 250 ms: a render loop or a retry without backoff. */
  | "retryStorm"
  /** A 2xx upstream latency at least 4x the template's rolling median and at least 250 ms. */
  | "latencyRegression";

export interface TrafficFinding {
  kind: TrafficFindingKind;
  severity: Severity;
  detail: string;
  /** Route template, header value or matched fragment the finding rests on. */
  evidence: string | null;
}

// ---- target lab -----------------------------------------------------------------------

export type LabMode = "unprotected" | "hardened";

export interface LabConfig {
  /** `null` tries 17480, then an ephemeral port; `0` is ephemeral. */
  port: number | null;
  mode: LabMode;
}

export interface LabCounters {
  /** Uses recorded on the coupon row; a lost update keeps it at the limit. */
  redeemed: number;
  /** Redemptions answered with 200; above the limit means the race was won twice. */
  granted: number;
  orders: number;
  requests: number;
}

export interface LabStatus {
  running: boolean;
  listener: string | null;
  baseUrl: string | null;
  mode: LabMode;
  couponCode: string;
  couponLimit: number;
  counters: LabCounters;
}

// ---- audit report ---------------------------------------------------------------------

export type ReportFormat = "markdown" | "json";

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
      /** Route rule that supplied the fault profile, as `METHOD /pattern`. */
      rule: string | null;
      requestBytes: number;
      responseBytes: number;
      error: string | null;
      /** Response contract matched to the upstream path, as `METHOD /pattern`. */
      contract: string | null;
      /** Drift of a forwarded response from `contract`; injected faults are not checked. */
      violations: ContractViolation[];
      /** Passive audit: N+1 bursts for every GET, response checks for forwarded responses. */
      findings: TrafficFinding[];
    }
  | {
      kind: "burstStarted";
      seq: number;
      id: string;
      tsUs: number;
      target: string;
      method: BurstMethod;
      workers: number;
      syncMode: BurstSyncMode;
      idempotencyKey: string | null;
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
      disclosures: number;
      violations: number;
      aborted: string | null;
    }
  | {
      kind: "labStateChanged";
      seq: number;
      tsUs: number;
      status: LabStatus;
    }
  | {
      kind: "labExchange";
      seq: number;
      id: string;
      tsUs: number;
      method: string;
      path: string;
      status: number;
      latencyUs: number;
      mode: LabMode;
      outcome: string;
      counters: LabCounters;
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
  | "INVALID_FAULT_RULE"
  | "INVALID_CONTRACT_SET"
  | "INVALID_BURST_SPEC"
  | "INVALID_FUZZ_SPEC"
  | "FUZZER_BUSY"
  | "INVALID_SCAN_ROOT"
  | "LAB_ALREADY_RUNNING"
  | "REPORT_EXPORT_FAILED"
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
  | { code: "INVALID_FAULT_RULE"; message: string; index: number }
  | { code: "INVALID_CONTRACT_SET"; message: string; index: number }
  | { code: "INVALID_BURST_SPEC"; message: string; field: string }
  | { code: "INVALID_FUZZ_SPEC"; message: string; field: string }
  | { code: "FUZZER_BUSY"; message: string }
  | { code: "INVALID_SCAN_ROOT"; message: string; path: string }
  | { code: "LAB_ALREADY_RUNNING"; message: string; listener: string }
  | { code: "REPORT_EXPORT_FAILED"; message: string; path: string | null }
  | { code: "INTERNAL_TASK_FAILED"; message: string };
