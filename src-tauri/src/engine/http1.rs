//! Raw HTTP/1.1 exchanges over guarded loopback connections.
//!
//! Shared by the burst runner and the fuzzer. Both need control below what reqwest offers:
//! a connection opened before the request is built (burst), and byte-exact bodies that are
//! not valid JSON or UTF-8 (fuzzer). Every connection goes through
//! `net::connect_loopback`, which re-validates the socket address before connect and the
//! peer after.

use std::error::Error as _;
use std::fmt;
use std::hash::{DefaultHasher, Hasher};
use std::io;
use std::time::Duration;

use axum::body::Bytes;
use axum::http::header::{self, HeaderMap, HeaderName, HeaderValue};
use axum::http::{Method, Request, Uri};
use http_body_util::{BodyExt, Full};
use hyper::client::conn::http1::{self, SendRequest};
use hyper_util::rt::TokioIo;

use super::error::{EngineError, EngineResult};
use super::guard::{self, GuardedTarget};
use super::net::{self, ConnectError};
use super::types::{BurstMethod, HeaderPair};

pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);

/// Framing headers are owned by the engine; a user override would desynchronize the
/// pre-built request from the connection it is written to.
static RESERVED_HEADERS: [HeaderName; 5] = [
    header::HOST,
    header::CONTENT_LENGTH,
    header::TRANSFER_ENCODING,
    header::CONNECTION,
    header::UPGRADE,
];

/// Builds the field-specific validation error of the calling spec type.
pub type InvalidField = fn(&'static str, String) -> EngineError;

/// A validated request line, Host and user headers for one loopback target.
pub struct RequestTemplate {
    pub target: GuardedTarget,
    pub label: String,
    pub method: Method,
    uri: Uri,
    host: HeaderValue,
    headers: HeaderMap,
}

impl RequestTemplate {
    pub fn new(
        target: &str,
        method: BurstMethod,
        headers: &[HeaderPair],
        invalid: InvalidField,
    ) -> EngineResult<Self> {
        let target = guard::validate_url(target)?;
        net::require_plaintext(&target)?;

        let origin_form = match target.url.query() {
            Some(query) => format!("{}?{query}", target.url.path()),
            None => target.url.path().to_owned(),
        };
        let uri = origin_form
            .parse::<Uri>()
            .map_err(|err| invalid("target", err.to_string()))?;
        let host_str = target.url.host_str().unwrap_or_default();
        let authority = match target.url.port() {
            Some(port) => format!("{host_str}:{port}"),
            None => host_str.to_owned(),
        };
        let host =
            HeaderValue::try_from(authority).map_err(|err| invalid("target", err.to_string()))?;

        let mut map = HeaderMap::new();
        for pair in headers {
            let name = HeaderName::from_bytes(pair.name.trim().as_bytes()).map_err(|_| {
                invalid(
                    "headers",
                    format!("`{}` is not a valid header name", pair.name),
                )
            })?;
            if RESERVED_HEADERS.contains(&name) {
                return Err(invalid(
                    "headers",
                    format!("`{name}` is managed by the engine"),
                ));
            }
            let value = HeaderValue::from_str(&pair.value).map_err(|_| {
                invalid(
                    "headers",
                    format!("value for `{name}` contains invalid characters"),
                )
            })?;
            map.append(name, value);
        }

        Ok(Self {
            label: target.url.to_string(),
            target,
            method: to_method(method),
            uri,
            host,
            headers: map,
        })
    }

    pub fn has_header(&self, name: &HeaderName) -> bool {
        self.headers.contains_key(name)
    }

    pub fn request(&self, body: Bytes) -> Request<Full<Bytes>> {
        let mut request = Request::new(Full::new(body));
        *request.method_mut() = self.method.clone();
        *request.uri_mut() = self.uri.clone();
        let headers = request.headers_mut();
        headers.clone_from(&self.headers);
        headers.insert(header::HOST, self.host.clone());
        request
    }
}

pub fn to_method(method: BurstMethod) -> Method {
    match method {
        BurstMethod::Get => Method::GET,
        BurstMethod::Post => Method::POST,
        BurstMethod::Put => Method::PUT,
        BurstMethod::Patch => Method::PATCH,
        BurstMethod::Delete => Method::DELETE,
    }
}

#[derive(Debug)]
pub enum OpenError {
    Connect(ConnectError),
    Handshake(hyper::Error),
    NotReady(hyper::Error),
}

impl fmt::Display for OpenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connect(err) => write!(f, "{err}"),
            Self::Handshake(err) => write!(f, "handshake failed: {err}"),
            Self::NotReady(err) => write!(f, "connection not ready: {err}"),
        }
    }
}

/// Connects and completes the HTTP/1.1 handshake; the connection task is detached.
pub async fn open(target: &GuardedTarget) -> Result<SendRequest<Full<Bytes>>, OpenError> {
    let stream = net::connect_loopback(target, CONNECT_TIMEOUT)
        .await
        .map_err(OpenError::Connect)?;
    let (mut sender, connection) = http1::handshake(TokioIo::new(stream))
        .await
        .map_err(OpenError::Handshake)?;
    tokio::spawn(async move {
        if let Err(err) = connection.await {
            tracing::debug!(error = %err, "http/1 connection closed with error");
        }
    });
    sender.ready().await.map_err(OpenError::NotReady)?;
    Ok(sender)
}

pub struct Received {
    pub status: u16,
    pub bytes: u64,
    /// 64-bit SipHash of the full body as 16 hex digits.
    pub hash: String,
    /// Leading body bytes, up to the limit passed to `exchange`.
    pub preview: Vec<u8>,
}

#[derive(Debug)]
pub enum ExchangeError {
    Send(hyper::Error),
    Body(hyper::Error),
}

impl ExchangeError {
    /// The peer aborted the connection (RST, or EOF before a complete response), as opposed
    /// to a protocol error on a live connection.
    pub fn is_connection_abort(&self) -> bool {
        let err = match self {
            Self::Send(err) | Self::Body(err) => err,
        };
        if err.is_incomplete_message() || err.is_closed() || err.is_canceled() {
            return true;
        }
        let mut source = err.source();
        while let Some(cause) = source {
            if let Some(io) = cause.downcast_ref::<io::Error>() {
                return matches!(
                    io.kind(),
                    io::ErrorKind::ConnectionReset
                        | io::ErrorKind::ConnectionAborted
                        | io::ErrorKind::BrokenPipe
                        | io::ErrorKind::UnexpectedEof
                );
            }
            source = cause.source();
        }
        false
    }
}

impl fmt::Display for ExchangeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Send(err) => write!(f, "{err}"),
            Self::Body(err) => write!(f, "body read failed: {err}"),
        }
    }
}

/// Sends one request and drains the response, streaming the body into the fingerprint so a
/// large body costs no buffer beyond the preview.
pub async fn exchange(
    sender: &mut SendRequest<Full<Bytes>>,
    request: Request<Full<Bytes>>,
    preview_limit: usize,
) -> Result<Received, ExchangeError> {
    let response = sender
        .send_request(request)
        .await
        .map_err(ExchangeError::Send)?;
    let status = response.status().as_u16();

    let mut body = response.into_body();
    let mut hasher = DefaultHasher::new();
    let mut bytes = 0u64;
    let mut preview = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(ExchangeError::Body)?;
        if let Some(data) = frame.data_ref() {
            bytes = bytes.saturating_add(u64::try_from(data.len()).unwrap_or(u64::MAX));
            hasher.write(data);
            let room = preview_limit.saturating_sub(preview.len());
            preview.extend_from_slice(&data[..room.min(data.len())]);
        }
    }

    Ok(Received {
        status,
        bytes,
        hash: format!("{:016x}", hasher.finish()),
        preview,
    })
}
