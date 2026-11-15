use serde::ser::{Serialize, SerializeStruct, Serializer};

/// Domain errors produced by the engine.
///
/// Serialized as `{ code, message, ...detail }` so the frontend can branch on a stable
/// machine-readable `code` instead of parsing `Display` output.
#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    #[error("target host `{host}` is not on the loopback allowlist (127.0.0.1, ::1, localhost)")]
    NonLoopbackTargetRejected { host: String },

    #[error("invalid target `{input}`: {reason}")]
    InvalidTarget { input: String, reason: String },

    #[error("unsupported scheme `{scheme}`; expected http, https, ws or wss")]
    UnsupportedScheme { scheme: String },

    #[error("scheme `{scheme}` requires TLS, which the engine does not link; use http")]
    PlaintextOnly { scheme: String },

    #[error("http client construction failed: {0}")]
    ClientBuild(String),

    #[error("proxy listener is already running on {listener}")]
    ProxyAlreadyRunning { listener: String },

    #[error("cannot bind proxy listener on {addr}: {reason}")]
    ListenerBind { addr: String, reason: String },

    #[error("upstream {addr} is the proxy listener itself; requests would loop")]
    ProxyLoop { addr: String },

    #[error("invalid fault profile field `{field}`: {reason}")]
    InvalidFaultProfile { field: &'static str, reason: String },

    #[error("invalid fault rule #{index}: {reason}")]
    InvalidFaultRule { index: usize, reason: String },

    #[error("invalid burst spec field `{field}`: {reason}")]
    InvalidBurstSpec { field: &'static str, reason: String },

    #[error("invalid fuzz spec field `{field}`: {reason}")]
    InvalidFuzzSpec { field: &'static str, reason: String },

    #[error("a fuzzer suite is already running")]
    FuzzerBusy,

    #[error("cannot scan `{path}`: {reason}")]
    InvalidScanRoot { path: String, reason: String },

    #[error("target lab is already running on {listener}")]
    LabAlreadyRunning { listener: String },

    #[error("cannot export audit report: {reason}")]
    ReportExport {
        /// Destination chosen in the save dialog; `None` when the export failed before one.
        path: Option<String>,
        reason: String,
    },

    #[error("engine task failed: {reason}")]
    InternalTask { reason: String },
}

impl EngineError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::NonLoopbackTargetRejected { .. } => "NON_LOOPBACK_TARGET_REJECTED",
            Self::InvalidTarget { .. } => "INVALID_TARGET",
            Self::UnsupportedScheme { .. } => "UNSUPPORTED_SCHEME",
            Self::PlaintextOnly { .. } => "PLAINTEXT_ONLY",
            Self::ClientBuild(_) => "CLIENT_BUILD_FAILED",
            Self::ProxyAlreadyRunning { .. } => "PROXY_ALREADY_RUNNING",
            Self::ListenerBind { .. } => "LISTENER_BIND_FAILED",
            Self::ProxyLoop { .. } => "PROXY_LOOP",
            Self::InvalidFaultProfile { .. } => "INVALID_FAULT_PROFILE",
            Self::InvalidFaultRule { .. } => "INVALID_FAULT_RULE",
            Self::InvalidBurstSpec { .. } => "INVALID_BURST_SPEC",
            Self::InvalidFuzzSpec { .. } => "INVALID_FUZZ_SPEC",
            Self::FuzzerBusy => "FUZZER_BUSY",
            Self::InvalidScanRoot { .. } => "INVALID_SCAN_ROOT",
            Self::LabAlreadyRunning { .. } => "LAB_ALREADY_RUNNING",
            Self::ReportExport { .. } => "REPORT_EXPORT_FAILED",
            Self::InternalTask { .. } => "INTERNAL_TASK_FAILED",
        }
    }
}

impl Serialize for EngineError {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut s = serializer.serialize_struct("EngineError", 3)?;
        s.serialize_field("code", self.code())?;
        s.serialize_field("message", &self.to_string())?;
        match self {
            Self::NonLoopbackTargetRejected { host } => s.serialize_field("host", host)?,
            Self::InvalidTarget { input, .. } => s.serialize_field("input", input)?,
            Self::UnsupportedScheme { scheme } | Self::PlaintextOnly { scheme } => {
                s.serialize_field("scheme", scheme)?
            }
            Self::ProxyAlreadyRunning { listener } | Self::LabAlreadyRunning { listener } => {
                s.serialize_field("listener", listener)?
            }
            Self::ListenerBind { addr, .. } | Self::ProxyLoop { addr } => {
                s.serialize_field("addr", addr)?
            }
            Self::InvalidFaultProfile { field, .. }
            | Self::InvalidBurstSpec { field, .. }
            | Self::InvalidFuzzSpec { field, .. } => s.serialize_field("field", field)?,
            Self::InvalidFaultRule { index, .. } => s.serialize_field("index", index)?,
            Self::InvalidScanRoot { path, .. } => s.serialize_field("path", path)?,
            Self::ReportExport { path, .. } => s.serialize_field("path", path)?,
            Self::ClientBuild(_) | Self::InternalTask { .. } | Self::FuzzerBusy => {}
        }
        s.end()
    }
}

pub type EngineResult<T> = Result<T, EngineError>;
