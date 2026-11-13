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

    #[error("http client construction failed: {0}")]
    ClientBuild(String),
}

impl EngineError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::NonLoopbackTargetRejected { .. } => "NON_LOOPBACK_TARGET_REJECTED",
            Self::InvalidTarget { .. } => "INVALID_TARGET",
            Self::UnsupportedScheme { .. } => "UNSUPPORTED_SCHEME",
            Self::ClientBuild(_) => "CLIENT_BUILD_FAILED",
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
            Self::UnsupportedScheme { scheme } => s.serialize_field("scheme", scheme)?,
            Self::ClientBuild(_) => {}
        }
        s.end()
    }
}

pub type EngineResult<T> = Result<T, EngineError>;
