//! Raw HTTP/1.1 exchanges over guarded loopback connections.
//!
//! Shared by the burst runner and the fuzzer. Both need control below what reqwest offers:
//! a connection opened before the request is built (burst), and byte-exact bodies that are
//! not valid JSON or UTF-8 (fuzzer). Every connection goes through
//! `net::connect_loopback`, which re-validates the socket address before connect and the
//! peer after.

use std::error::Error as _;
use std::fmt;
use std::future::Future;
use std::hash::{DefaultHasher, Hasher};
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use axum::body::Bytes;
use axum::http::header::{self, HeaderMap, HeaderName, HeaderValue};
use axum::http::{Method, Request, Response, Uri};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::client::conn::http1::{self, SendRequest};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};

use super::error::{EngineError, EngineResult};
use super::guard::{self, GuardedTarget};
use super::net::{self, ConnectError};
use super::types::{BurstMethod, HeaderPair};

pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
/// Preview capacity reserved up front; a larger limit grows the buffer only as bytes arrive.
const PREVIEW_RESERVE: usize = 4 * 1024;

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

    /// Origin-form target as validated: path and query.
    pub fn origin_form(&self) -> &Uri {
        &self.uri
    }

    pub fn request(&self, body: Bytes) -> Request<Full<Bytes>> {
        self.request_at(&self.uri, body)
    }

    /// The same request with another origin-form target. Host and connection stay those of
    /// the validated target, so a rewritten path cannot leave loopback.
    pub fn request_at(&self, uri: &Uri, body: Bytes) -> Request<Full<Bytes>> {
        let mut request = Request::new(Full::new(body));
        *request.method_mut() = self.method.clone();
        *request.uri_mut() = uri.clone();
        let headers = request.headers_mut();
        headers.clone_from(&self.headers);
        headers.insert(header::HOST, self.host.clone());
        request
    }
}

/// HTTP/1.1 wire bytes of a built request, for a caller that writes the socket itself. Same
/// shape hyper sends: origin-form target, the request's headers in map order, and
/// `content-length` only for a non-empty body.
pub fn encode(request: &Request<Full<Bytes>>, body: &[u8]) -> Vec<u8> {
    let target = request.uri().path_and_query().map_or("/", |pq| pq.as_str());
    let headers = request.headers();
    let header_bytes: usize = headers
        .iter()
        .map(|(name, value)| name.as_str().len() + value.len() + 4)
        .sum();
    let mut wire = Vec::with_capacity(64 + target.len() + header_bytes + body.len());
    wire.extend_from_slice(request.method().as_str().as_bytes());
    wire.push(b' ');
    wire.extend_from_slice(target.as_bytes());
    wire.extend_from_slice(b" HTTP/1.1\r\n");
    for (name, value) in headers {
        wire.extend_from_slice(name.as_str().as_bytes());
        wire.extend_from_slice(b": ");
        wire.extend_from_slice(value.as_bytes());
        wire.extend_from_slice(b"\r\n");
    }
    if !body.is_empty() {
        wire.extend_from_slice(format!("content-length: {}\r\n", body.len()).as_bytes());
    }
    wire.extend_from_slice(b"\r\n");
    wire.extend_from_slice(body);
    wire
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

/// A connection whose request bytes the caller writes through `writer` while hyper parses
/// the response from the read half. The request given to `sender` only moves hyper's state
/// machine to awaiting a response; hyper serializes it into a sink.
pub struct SplitConnection {
    pub sender: SendRequest<Full<Bytes>>,
    /// Dropping it half-closes the socket, which servers without half-close support treat
    /// as an abort; keep it alive until the response is drained.
    pub writer: OwnedWriteHalf,
}

pub async fn open_split(target: &GuardedTarget) -> Result<SplitConnection, OpenError> {
    let stream = net::connect_loopback(target, CONNECT_TIMEOUT)
        .await
        .map_err(OpenError::Connect)?;
    let (read, writer) = stream.into_split();
    let (mut sender, connection) = http1::handshake(TokioIo::new(ResponseSide {
        read,
        wrote: false,
        armed: false,
        parked: None,
    }))
    .await
    .map_err(OpenError::Handshake)?;
    tokio::spawn(async move {
        if let Err(err) = connection.await {
            tracing::debug!(error = %err, "split http/1 connection closed with error");
        }
    });
    sender.ready().await.map_err(OpenError::NotReady)?;
    Ok(SplitConnection { sender, writer })
}

/// Read half handed to hyper, with its writes discarded. Reads stay parked until hyper has
/// flushed its copy of the request: response bytes that reached hyper while it still
/// considered the connection idle would be rejected as an unexpected message.
struct ResponseSide {
    read: OwnedReadHalf,
    wrote: bool,
    armed: bool,
    parked: Option<Waker>,
}

impl AsyncRead for ResponseSide {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.armed {
            this.parked = Some(cx.waker().clone());
            return Poll::Pending;
        }
        Pin::new(&mut this.read).poll_read(cx, buf)
    }
}

impl AsyncWrite for ResponseSide {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.wrote |= !buf.is_empty();
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let len: usize = bufs.iter().map(|buf| buf.len()).sum();
        this.wrote |= len > 0;
        Poll::Ready(Ok(len))
    }

    fn is_write_vectored(&self) -> bool {
        true
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.wrote && !this.armed {
            this.armed = true;
            if let Some(waker) = this.parked.take() {
                waker.wake();
            }
        }
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

pub struct Received {
    /// When hyper finished parsing the status line and headers. Callers subtract their own
    /// write instant, so TTFB and total latency are measured from the same clock edge.
    pub head_at: Instant,
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
    exchange_pending(sender.send_request(request), preview_limit).await
}

/// Drains the response of a request already queued with `SendRequest::send_request`. hyper
/// enqueues on the call, not on the first poll, so a caller can queue before a barrier and
/// await after it.
pub async fn exchange_pending(
    pending: impl Future<Output = hyper::Result<Response<Incoming>>>,
    preview_limit: usize,
) -> Result<Received, ExchangeError> {
    let response = pending.await.map_err(ExchangeError::Send)?;
    let head_at = Instant::now();
    let status = response.status().as_u16();

    let mut body = response.into_body();
    let mut hasher = DefaultHasher::new();
    let mut bytes = 0u64;
    let mut preview = Vec::with_capacity(preview_limit.min(PREVIEW_RESERVE));
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
        head_at,
        status,
        bytes,
        hash: format!("{:016x}", hasher.finish()),
        preview,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::engine::error::EngineError;

    fn invalid(field: &'static str, reason: String) -> EngineError {
        EngineError::InvalidBurstSpec { field, reason }
    }

    #[test]
    fn encode_matches_the_request_hyper_would_send() {
        let headers = [HeaderPair {
            name: "Content-Type".to_owned(),
            value: "application/json".to_owned(),
        }];
        let template = RequestTemplate::new(
            "http://127.0.0.1:8080/api/redeem?dry=1",
            BurstMethod::Post,
            &headers,
            invalid,
        )
        .unwrap();
        let body = Bytes::from_static(br#"{"code":"X"}"#);
        let wire = encode(&template.request(body.clone()), &body);
        assert_eq!(
            String::from_utf8(wire).unwrap(),
            "POST /api/redeem?dry=1 HTTP/1.1\r\ncontent-type: application/json\r\nhost: 127.0.0.1:8080\r\ncontent-length: 12\r\n\r\n{\"code\":\"X\"}"
        );

        let get = RequestTemplate::new("localhost:9/", BurstMethod::Get, &[], invalid).unwrap();
        assert_eq!(
            encode(&get.request(Bytes::new()), &[]),
            b"GET / HTTP/1.1\r\nhost: localhost:9\r\n\r\n"
        );
    }
}
