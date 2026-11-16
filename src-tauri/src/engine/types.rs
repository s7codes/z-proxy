//! IPC data contracts. Mirrored 1:1 in `src/lib/types.ts`; any change here must land there
//! in the same commit.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::fault::{FaultProfile, FaultRule};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum HostKind {
    Ipv4,
    Ipv6,
    Localhost,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Verdict {
    Accepted,
    Rejected,
}

#[derive(Debug, Clone, Serialize)]
#[serde(
    tag = "state",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum ProbeResult {
    Reachable { status: u16, latency_us: u64 },
    Unreachable { reason: String, latency_us: u64 },
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidatedTarget {
    pub input: String,
    pub normalized: String,
    pub scheme: String,
    pub host: String,
    pub host_kind: HostKind,
    pub port: u16,
    pub probe: ProbeResult,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EngineStatus {
    pub version: &'static str,
    pub uptime_ms: u64,
    pub telemetry_subscribers: u32,
    pub guard_mode: &'static str,
    pub allowlist: [&'static str; 3],
    pub proxy_listener: Option<String>,
}

// ---- proxy ----------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProxyConfig {
    pub upstream: String,
    /// `0` requests an ephemeral port; the bound port is reported in `ProxyStatus.listener`.
    pub listen_port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProxyStatus {
    pub running: bool,
    pub listener: Option<String>,
    pub upstream: Option<String>,
    pub armed: bool,
    pub profile: FaultProfile,
    /// Evaluated in order before the global profile; the first match wins.
    pub rules: Vec<FaultRule>,
    /// Response contracts the proxy checks forwarded responses against.
    pub contracts: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum FaultKind {
    StatusMutation,
    ConnectionDrop,
    /// Upstream head and leading body bytes forwarded, then the connection reset mid-body.
    PartialBodyDrop,
}

// ---- concurrency burst ----------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum BurstMethod {
    Get,
    Post,
    Put,
    Patch,
    Delete,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeaderPair {
    pub name: String,
    pub value: String,
}

/// What the barrier releases.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum BurstSyncMode {
    /// Connections are opened and handshaken before the barrier; release writes each full
    /// request.
    #[default]
    PreConnected,
    /// Every request except its final byte is written and flushed before the barrier;
    /// release writes one byte per worker, so no server can finish parsing a request early.
    LastByte,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BurstSpec {
    /// May hold `{param}` placeholders in the path; each is sent as `1`.
    pub target: String,
    pub method: BurstMethod,
    pub workers: u16,
    pub headers: Vec<HeaderPair>,
    pub body: Option<String>,
    pub timeout_ms: u32,
    /// Upper bound on 2xx responses the operation may legitimately produce (1 for a
    /// single-use coupon or an idempotent charge). More successes are a race window even
    /// when no request was answered with a conflict. `None` applies no quota.
    pub expected_max_successes: Option<u16>,
    /// Every worker sends the same `Idempotency-Key` (the operator's, else a generated
    /// UUID); 2xx responses must then be one replayed body. Absent means off.
    #[serde(default)]
    pub idempotency_mode: bool,
    /// `None` is `PreConnected`.
    pub sync_mode: Option<BurstSyncMode>,
    /// Documented responses of the targeted operation; every response is checked against it
    /// once all workers finished, outside the timed section.
    pub contract: Option<ResponseContract>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkerSample {
    pub worker: u16,
    /// `None` when the request never produced a response (connect, timeout, reset).
    pub status: Option<u16>,
    /// Offset from the first worker past the barrier; `None` if the worker never fired.
    pub dispatch_offset_us: Option<u64>,
    /// Request write to parsed response head; `None` when no head arrived.
    pub ttfb_us: Option<u64>,
    /// Request write to the last body frame, or to the failure.
    pub latency_us: u64,
    pub bytes: u64,
    /// 64-bit SipHash of the response body as 16 hex digits; a string because the value
    /// exceeds `Number.MAX_SAFE_INTEGER`.
    pub body_hash: Option<String>,
    pub error: Option<String>,
    /// Drift of this response from the spec's `contract`; empty without one.
    pub violations: Vec<ContractViolation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StatusBucket {
    pub status: Option<u16>,
    pub count: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LatencyStats {
    pub min_us: u64,
    pub max_us: u64,
    pub mean_us: u64,
    pub p50_us: u64,
    pub p95_us: u64,
    pub p99_us: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SizeStats {
    pub min_bytes: u64,
    pub max_bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum AnomalyKind {
    RaceWindow,
    StatusDivergence,
    BodyDivergence,
    TransportErrors,
    /// 2xx responses to one `Idempotency-Key` with distinct bodies: the key was not
    /// deduplicated and the operation ran more than once.
    IdempotencyViolation,
    /// Responses that broke the spec's `contract` under concurrent load. A `Fault` when a 2xx
    /// response drifted (a balance below its documented minimum), else a `Warn`.
    ContractDrift,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Severity {
    Warn,
    Fault,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Anomaly {
    pub kind: AnomalyKind,
    pub severity: Severity,
    pub detail: String,
    pub workers: Vec<u16>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BurstReport {
    pub id: Uuid,
    pub target: String,
    pub method: BurstMethod,
    pub workers: u16,
    pub sync_mode: BurstSyncMode,
    pub wall_us: u64,
    pub dispatch_spread_us: Option<u64>,
    pub status_histogram: Vec<StatusBucket>,
    /// Total exchange time over responded workers.
    pub latency: Option<LatencyStats>,
    /// Time to the response head over responded workers. A wide gap to `latency` puts the
    /// cost in body generation or streaming rather than in the handler before the head.
    pub ttfb: Option<LatencyStats>,
    pub size: Option<SizeStats>,
    pub distinct_bodies: u32,
    /// Quota the race analysis applied, echoed from the spec.
    pub expected_max_successes: Option<u16>,
    /// Key every worker sent in idempotency mode.
    pub idempotency_key: Option<String>,
    /// Responses that broke the spec's `contract`; 0 without one.
    pub contract_violations: u32,
    pub anomalies: Vec<Anomaly>,
    pub samples: Vec<WorkerSample>,
}

// ---- fuzzer ---------------------------------------------------------------------------

/// Declaration order is execution order. Case indices are replay keys, so new classes are
/// appended and never shift the indices of earlier ones.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum MutationClass {
    NullInjection,
    EmptyStrings,
    BoundaryNumbers,
    TypeConfusion,
    OversizedField,
    MalformedJson,
    MissingFields,
    /// Valid-syntax bodies that break a strict schema: duplicate keys, deep nesting,
    /// undeclared fields, numbers outside `f64` range.
    SchemaContractBounds,
    /// Boundary identifiers in each `{param}` slot of the target path; the body stays the base.
    PathParamValidation,
    /// Each string field set to ordinary business values carrying quote, backslash,
    /// separator, wildcard and invisible-Unicode delimiters. A service that binds or escapes
    /// its strings stores them or refuses them cleanly; one that splices them into a query,
    /// path or pattern fails.
    DelimiterEscaping,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FuzzSpec {
    /// May hold `{param}` placeholders in the path: the baseline and body cases send
    /// `1`, path cases vary one slot at a time.
    pub target: String,
    pub method: BurstMethod,
    pub headers: Vec<HeaderPair>,
    /// JSON object to mutate; `None` or blank uses the built-in template.
    pub base_body: Option<String>,
    /// Empty selects every class.
    pub classes: Vec<MutationClass>,
    pub timeout_ms: u32,
    /// Documented responses of the targeted operation; every response is checked against it.
    pub contract: Option<ResponseContract>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum FuzzVerdict {
    /// 4xx: the service refused the payload.
    Rejected,
    /// 1xx-3xx: the service took the payload.
    Accepted,
    /// 5xx.
    ServerError,
    /// Reset, closed before a full response, or timed out after connecting.
    TransportFailure,
    /// The connection could not be opened; not attributable to this case's payload.
    Unreachable,
    /// Not executed (cancelled, or the run aborted earlier).
    Skipped,
}

/// Runtime or database internals exposed in a response body.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum DisclosureKind {
    NodeStackTrace,
    PythonTraceback,
    RustPanic,
    GoPanic,
    JvmStackTrace,
    DotNetStackTrace,
    SqlError,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Disclosure {
    pub kind: DisclosureKind,
    /// Matched fragment, trimmed to 160 characters.
    pub evidence: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FuzzCaseResult {
    pub index: u32,
    /// `None` for the unmutated baseline request.
    pub class: Option<MutationClass>,
    pub label: String,
    /// RFC 6901 pointer of the mutated field; `None` for whole-body mutations.
    pub pointer: Option<String>,
    pub request_bytes: u64,
    pub status: Option<u16>,
    pub latency_us: u64,
    pub response_bytes: u64,
    /// Leading response bytes, lossily decoded.
    pub response_preview: Option<String>,
    pub verdict: FuzzVerdict,
    pub severity: Option<Severity>,
    /// Stack trace or database error found in the preview, whatever the status. Raises an
    /// otherwise clean mutation case to `Severity::Warn`.
    pub disclosure: Option<Disclosure>,
    /// Drift from the spec's `contract`; empty without one. Raises an otherwise clean
    /// mutation case to `Severity::Warn`.
    pub violations: Vec<ContractViolation>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClassSummary {
    pub class: MutationClass,
    pub cases: u32,
    pub rejected: u32,
    pub accepted: u32,
    /// Server errors and transport failures.
    pub faults: u32,
    /// Unreachable and skipped cases.
    pub unreached: u32,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FuzzReport {
    pub id: Uuid,
    pub target: String,
    pub method: BurstMethod,
    /// Fields of the base payload that received per-field mutations.
    pub fields: u32,
    pub wall_us: u64,
    pub baseline: FuzzCaseResult,
    pub cases: Vec<FuzzCaseResult>,
    pub summary: Vec<ClassSummary>,
    pub faults: u32,
    pub warnings: u32,
    /// Mutation cases whose response disclosed a stack trace or database error.
    pub disclosures: u32,
    /// Requests, baseline included, whose response broke the documented contract.
    pub contract_violations: u32,
    /// Set when the run stopped early: target unreachable or operator cancel.
    pub aborted: Option<String>,
    /// Context that changes how results read, such as a baseline that was not accepted.
    pub notes: Vec<String>,
    /// Base payload exactly as sent in the baseline; with `classes` and `path_template` it
    /// reproduces any case.
    pub base_body: String,
    /// Classes in execution order.
    pub classes: Vec<MutationClass>,
    /// Origin-form path of the target with its `{param}` slots (`/orders/{id}`); `None` when
    /// the target had none.
    pub path_template: Option<String>,
}

/// Addresses one case of a finished suite for replay.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FuzzCaseRef {
    pub base_body: String,
    pub classes: Vec<MutationClass>,
    pub path_template: Option<String>,
    /// `0` is the baseline.
    pub index: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FuzzCasePayload {
    pub index: u32,
    pub label: String,
    /// Origin-form request target of a path case; `None` when the case used the suite target.
    pub path: Option<String>,
    pub body: String,
    /// Size of the body as sent by the fuzzer.
    pub bytes: u64,
    /// The sent body was not valid UTF-8; invalid sequences in `body` are U+FFFD.
    pub lossy: bool,
}

// ---- route scanner --------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum RouteMethod {
    Get,
    Post,
    Put,
    Patch,
    Delete,
    Head,
    Options,
    /// Declared without a method constraint (`app.all`, net/http without a method prefix,
    /// a Pages API handler with no `req.method` checks).
    Any,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum RouteSource {
    NextAppRouter,
    NextPagesApi,
    Express,
    Fastify,
    Hono,
    Axum,
    Go,
    OpenApi,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DiscoveredRoute {
    pub method: RouteMethod,
    /// Normalized template: parameters as `{name}`, catch-alls as `{*name}`.
    pub path: String,
    pub params: Vec<String>,
    pub source: RouteSource,
    /// Relative to the scan root, `/`-separated on every platform.
    pub file: String,
    pub line: u32,
    /// Normalized mount prefix resolved within the declaring file; already part of `path`.
    pub prefix: Option<String>,
    /// Pretty-printed JSON request body from the OpenAPI `requestBody` (example or schema).
    pub sample_body: Option<String>,
    /// Documented responses of an OpenAPI operation.
    pub contract: Option<ResponseContract>,
    /// Static reliability findings in the handler's source; empty for OpenAPI routes.
    pub risks: Vec<RouteRisk>,
}

/// Declaration order is report order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum RouteRiskKind {
    /// A POST, PUT, PATCH or DELETE handler that reads the request body with no schema
    /// validation in reach.
    UnvalidatedMutation,
    /// A collection read with no limit, take or pagination.
    UnboundedQuery,
    /// A side-effecting async call whose promise or error is dropped, or an async Express
    /// handler with no error path.
    FloatingAsync,
    /// Two or more database writes in one handler with no transaction in sight: a failure
    /// or a concurrent request between them leaves partial state.
    NonAtomicMultiWrite,
    /// SQL text built by interpolating values (`${...}`, concatenation, `format!`,
    /// `fmt.Sprintf`) instead of binding parameters.
    UnsafeSqlInterpolation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RouteRisk {
    pub kind: RouteRiskKind,
    /// 1-based line of the evidence, in `file` when set, else in the route's file.
    pub line: u32,
    /// The evidence line, trimmed to 120 characters.
    pub evidence: String,
    pub detail: String,
    /// Scan-root-relative path of the module holding the evidence when the handler was
    /// imported from another file; `None` when the evidence is in the route's file.
    pub file: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanIssue {
    pub file: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RouteScanReport {
    pub id: Uuid,
    pub root: String,
    pub files_visited: u32,
    pub files_parsed: u32,
    pub elapsed_us: u64,
    /// File or route cap reached; the route list is a prefix of the full result.
    pub truncated: bool,
    pub routes: Vec<DiscoveredRoute>,
    pub issues: Vec<ScanIssue>,
}

// ---- response contracts ---------------------------------------------------------------

/// JSON value type as an OpenAPI schema names it. `Integer` is a number without a fraction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum JsonKind {
    String,
    Integer,
    Number,
    Boolean,
    Array,
    Object,
    Null,
}

/// One documented location in the success response body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContractField {
    /// RFC 6901 pointer from the body root; `""` is the root itself.
    pub pointer: String,
    /// Accepted types; empty accepts any value (untyped or composed schema).
    pub kinds: Vec<JsonKind>,
    /// Listed in the parent schema's `required`. A nested field is only checked while its
    /// parent object is present.
    pub required: bool,
    /// Value constraints declared on the field's schema; `None` when it declares none.
    pub constraints: Option<ValueConstraints>,
}

/// String formats the contract check validates; any other `format` is not checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum StringFormat {
    Uuid,
    Email,
    /// RFC 3339 `date-time`.
    DateTime,
    /// RFC 3339 `full-date`.
    Date,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NumericBound {
    pub value: serde_json::Number,
    /// `exclusiveMinimum` / `exclusiveMaximum`, in either the 3.0 flag or the 3.1 number form.
    pub exclusive: bool,
}

/// Constraints on a field's value beyond its type. A `null` value is never judged against
/// them; nullability is a type question.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ValueConstraints {
    pub minimum: Option<NumericBound>,
    pub maximum: Option<NumericBound>,
    /// String length in Unicode scalar values, as JSON Schema counts it.
    pub min_length: Option<u32>,
    pub max_length: Option<u32>,
    /// Members of an all-scalar `enum` (or a scalar `const`).
    pub enum_values: Option<Vec<serde_json::Value>>,
    pub format: Option<StringFormat>,
}

/// Response side of one OpenAPI operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResponseContract {
    /// Explicit status codes under `responses`, ascending.
    pub statuses: Vec<u16>,
    /// Leading digit of each documented range (`4XX` is 4).
    pub status_classes: Vec<u8>,
    /// A `default` response documents every status.
    pub has_default: bool,
    /// Status whose JSON body `fields` describe: 200, else 201. `None` when neither declares
    /// a JSON schema.
    pub body_status: Option<u16>,
    pub fields: Vec<ContractField>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ContractViolationKind {
    /// A 2xx or 4xx status the operation does not document.
    UndocumentedStatus,
    MissingRequiredField,
    ResponseTypeMismatch,
    /// A correctly typed value outside its documented bounds, length, enum or format.
    ConstraintViolation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContractViolation {
    pub kind: ContractViolationKind,
    /// Field pointer; `None` for a status violation.
    pub pointer: Option<String>,
    /// `integer`, `string | null`, `one of 201, 422, 500`.
    pub expected: String,
    /// `string`, `missing`, `404`.
    pub actual: String,
}

/// A contract bound to a route template. The proxy matches it like a fault rule, against
/// the path the upstream receives.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RouteContract {
    pub method: RouteMethod,
    pub path: String,
    pub contract: ResponseContract,
}

// ---- passive traffic audit ------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum TrafficFindingKind {
    /// Distinct GETs to one route template inside a short window: a client loading a
    /// collection one member at a time.
    NPlusOneBurst,
    /// A JSON collection above the item limit without pagination metadata, or a JSON body
    /// above 1 MiB.
    UnboundedCollection,
    /// Content-Type, Content-Encoding, CORS or Cache-Control headers that contradict the
    /// response.
    HeaderMisconfiguration,
    /// Stack trace or database error in a proxied response.
    PassiveDisclosure,
    /// One exact request (method, path and query) repeated 10 or more times inside 250 ms
    /// (an effect that re-runs on every render), or retried 4 times in a row, each within
    /// 100 ms of a 429 / 503 answer to it (a retry loop without backoff).
    RetryStorm,
    /// A 2xx upstream latency at least 4x the route template's rolling median and at least
    /// 250 ms.
    LatencyRegression,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TrafficFinding {
    pub kind: TrafficFindingKind,
    pub severity: Severity,
    pub detail: String,
    /// Route template, header value or matched fragment the finding rests on.
    pub evidence: Option<String>,
}

// ---- target lab -----------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum LabMode {
    /// Check-then-act coupon redemption; unvalidated checkout input leaks traces.
    #[default]
    Unprotected,
    /// Conditional-update redemption; every invalid checkout is a 422.
    Hardened,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LabConfig {
    /// `None` tries 17480, then an ephemeral port; `Some(0)` is ephemeral; any other value
    /// is bound exactly.
    pub port: Option<u16>,
    pub mode: LabMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LabCounters {
    /// Uses recorded on the coupon row. A lost update under the race keeps it at the limit.
    pub redeemed: u32,
    /// Redemptions answered with 200; above the limit means the race was won more than once.
    pub granted: u32,
    pub orders: u32,
    pub requests: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LabStatus {
    pub running: bool,
    pub listener: Option<String>,
    /// `http://127.0.0.1:<port>`; `None` while stopped.
    pub base_url: Option<String>,
    pub mode: LabMode,
    pub coupon_code: &'static str,
    pub coupon_limit: u32,
    pub counters: LabCounters,
}

// ---- audit report ---------------------------------------------------------------------

/// Rendering of an audit report; decides the extension and the save-dialog filter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ReportFormat {
    Markdown,
    Json,
}

// ---- telemetry ------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum TelemetryEvent {
    EngineHeartbeat {
        seq: u64,
        ts_us: u64,
        uptime_ms: u64,
        subscribers: u32,
    },
    GuardDecision {
        seq: u64,
        id: Uuid,
        ts_us: u64,
        input: String,
        verdict: Verdict,
        host: Option<String>,
        code: Option<&'static str>,
    },
    ProbeCompleted {
        seq: u64,
        id: Uuid,
        ts_us: u64,
        url: String,
        status: Option<u16>,
        latency_us: u64,
        error: Option<String>,
    },
    /// Emitted on start, stop and every fault-profile change, so the UI never polls.
    ProxyStateChanged {
        seq: u64,
        ts_us: u64,
        status: ProxyStatus,
    },
    ProxyExchange {
        seq: u64,
        id: Uuid,
        ts_us: u64,
        method: String,
        path: String,
        upstream: String,
        /// Status written to the client; `None` when the connection was dropped.
        status: Option<u16>,
        latency_us: u64,
        injected_delay_us: u64,
        upstream_latency_us: Option<u64>,
        fault: Option<FaultKind>,
        /// Route rule that supplied the fault profile, as `METHOD /pattern`.
        rule: Option<String>,
        request_bytes: u64,
        response_bytes: u64,
        error: Option<String>,
        /// Response contract matched to the upstream path, as `METHOD /pattern`.
        contract: Option<String>,
        /// Drift of a forwarded response from `contract`; injected faults are not checked.
        violations: Vec<ContractViolation>,
        /// Passive audit of the exchange: N+1 bursts for every GET, response checks for
        /// forwarded responses.
        findings: Vec<TrafficFinding>,
    },
    BurstStarted {
        seq: u64,
        id: Uuid,
        ts_us: u64,
        target: String,
        method: BurstMethod,
        workers: u16,
        sync_mode: BurstSyncMode,
        idempotency_key: Option<String>,
    },
    BurstSample {
        seq: u64,
        id: Uuid,
        ts_us: u64,
        sample: WorkerSample,
    },
    BurstCompleted {
        seq: u64,
        id: Uuid,
        ts_us: u64,
        wall_us: u64,
        /// What the barrier released, so a spread is never read without the mode it was
        /// measured under.
        sync_mode: BurstSyncMode,
        dispatch_spread_us: Option<u64>,
        anomalies: u32,
        errors: u32,
    },
    RouteScanCompleted {
        seq: u64,
        id: Uuid,
        ts_us: u64,
        root: String,
        routes: u32,
        files_visited: u32,
        elapsed_us: u64,
        truncated: bool,
    },
    FuzzerStarted {
        seq: u64,
        id: Uuid,
        ts_us: u64,
        target: String,
        method: BurstMethod,
        /// Mutation cases, excluding the baseline.
        cases: u32,
    },
    /// One per executed request, baseline included; skipped cases emit nothing.
    FuzzerCaseCompleted {
        seq: u64,
        id: Uuid,
        ts_us: u64,
        result: FuzzCaseResult,
    },
    FuzzerCompleted {
        seq: u64,
        id: Uuid,
        ts_us: u64,
        wall_us: u64,
        cases: u32,
        faults: u32,
        warnings: u32,
        disclosures: u32,
        violations: u32,
        aborted: Option<String>,
    },
    /// Lab start, stop, mode switch and reset.
    LabStateChanged {
        seq: u64,
        ts_us: u64,
        status: LabStatus,
    },
    /// One per request the lab served, as the service saw it.
    LabExchange {
        seq: u64,
        id: Uuid,
        ts_us: u64,
        method: String,
        path: String,
        status: u16,
        latency_us: u64,
        mode: LabMode,
        /// What the handler did: `granted`, `conflict: coupon exhausted`, `crash: rust panic`.
        outcome: String,
        counters: LabCounters,
    },
}
