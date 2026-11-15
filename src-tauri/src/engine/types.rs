//! IPC data contracts. Mirrored 1:1 in `src/lib/types.ts`; any change here must land there
//! in the same commit.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::fault::FaultProfile;

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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum FaultKind {
    StatusMutation,
    ConnectionDrop,
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

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BurstSpec {
    pub target: String,
    pub method: BurstMethod,
    pub workers: u16,
    pub headers: Vec<HeaderPair>,
    pub body: Option<String>,
    pub timeout_ms: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkerSample {
    pub worker: u16,
    /// `None` when the request never produced a response (connect, timeout, reset).
    pub status: Option<u16>,
    /// Offset from the first worker past the barrier; `None` if the worker never fired.
    pub dispatch_offset_us: Option<u64>,
    pub latency_us: u64,
    pub bytes: u64,
    /// 64-bit SipHash of the response body as 16 hex digits; a string because the value
    /// exceeds `Number.MAX_SAFE_INTEGER`.
    pub body_hash: Option<String>,
    pub error: Option<String>,
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
    pub wall_us: u64,
    pub dispatch_spread_us: Option<u64>,
    pub status_histogram: Vec<StatusBucket>,
    pub latency: Option<LatencyStats>,
    pub size: Option<SizeStats>,
    pub distinct_bodies: u32,
    pub anomalies: Vec<Anomaly>,
    pub samples: Vec<WorkerSample>,
}

// ---- route scanner --------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
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
        request_bytes: u64,
        response_bytes: u64,
        error: Option<String>,
    },
    BurstStarted {
        seq: u64,
        id: Uuid,
        ts_us: u64,
        target: String,
        method: BurstMethod,
        workers: u16,
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
}
