//! IPC data contracts. Mirrored 1:1 in `src/lib/types.ts`; any change here must land there
//! in the same commit.

use serde::Serialize;
use uuid::Uuid;

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
    /// `None` until the M2 reverse proxy listener exists.
    pub proxy_listener: Option<String>,
}

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
}
