//! Loopback reverse proxy with fault injection.
//!
//! Connections are driven by hyper directly rather than `axum::serve`: a connection-drop
//! fault has to tear down one specific TCP connection from inside a request handler, which
//! requires per-connection state and ownership of the socket. Routing and extraction stay
//! in axum.

use std::convert::Infallible;
use std::future::{self, Future};
use std::net::{Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use axum::body::{Body, Bytes};
use axum::extract::{Request, State};
use axum::http::header::{self, HeaderMap, HeaderName, HeaderValue};
use axum::http::{request, StatusCode};
use axum::response::Response;
use axum::{Extension, Router};
use fastrand::Rng;
use hyper::body::{Frame, Incoming};
use hyper_util::rt::TokioIo;
use reqwest::Client;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{watch, Mutex as AsyncMutex, Notify};
use tokio::task::{JoinHandle, JoinSet};
use tower::ServiceExt;
use url::Url;
use uuid::Uuid;

use super::contract::{self, ContractSet};
use super::error::{EngineError, EngineResult};
use super::fault::{self, FaultAction, FaultPlan, FaultProfile, FaultRule, FaultState};
use super::guard::{self, GuardedTarget};
use super::linter::{self, ResponseView, TrafficLinter};
use super::net;
use super::types::{
    ContractViolation, FaultKind, ProxyConfig, ProxyStatus, RouteContract, TelemetryEvent,
    TrafficFinding,
};
use crate::telemetry::{now_us, TelemetryHub};

/// Bodies are buffered so telemetry can report exact byte counts; the cap bounds memory
/// for a tool that is pointed at arbitrary local services.
const MAX_BODY_BYTES: usize = 16 * 1024 * 1024;
const DRAIN_TIMEOUT: Duration = Duration::from_secs(2);
const ACCEPT_BACKOFF: Duration = Duration::from_millis(50);
/// Pause between the last forwarded byte of a partial drop and the reset. Windows discards
/// received but unread data when an RST arrives, so the client gets time to read the head
/// and the leading bytes; otherwise the fault would look like a plain connection drop.
const PARTIAL_DROP_SETTLE: Duration = Duration::from_millis(50);

const FAULT_HEADER: &str = "x-zproxy-fault";
const DELAY_HEADER: &str = "x-zproxy-injected-delay-us";
const ERROR_HEADER: &str = "x-zproxy-error";
const FORWARDED_HOST: &str = "x-forwarded-host";
const FORWARDED_FOR: &str = "x-forwarded-for";
const VIA: &str = "1.1 z-proxy";

/// RFC 9110 section 7.6.1 connection-specific fields.
static HOP_BY_HOP: [HeaderName; 8] = [
    header::CONNECTION,
    HeaderName::from_static("keep-alive"),
    header::PROXY_AUTHENTICATE,
    header::PROXY_AUTHORIZATION,
    header::TE,
    header::TRAILER,
    header::TRANSFER_ENCODING,
    header::UPGRADE,
];

pub struct ProxyManager {
    hub: Arc<TelemetryHub>,
    client: Client,
    /// Lives outside the listener so the profile survives restarts and can be changed
    /// while traffic is flowing.
    faults: watch::Sender<FaultState>,
    /// Same lifetime as `faults`; requests take an `Arc` snapshot, never a lock across I/O.
    contracts: watch::Sender<Arc<ContractSet>>,
    running: AsyncMutex<Option<RunningProxy>>,
    seed: Option<u64>,
}

struct RunningProxy {
    listener: SocketAddr,
    upstream: String,
    shutdown: watch::Sender<bool>,
    task: JoinHandle<()>,
}

impl ProxyManager {
    pub fn new(hub: Arc<TelemetryHub>) -> EngineResult<Self> {
        Self::build(hub, None)
    }

    #[cfg(test)]
    fn with_seed(hub: Arc<TelemetryHub>, seed: u64) -> EngineResult<Self> {
        Self::build(hub, Some(seed))
    }

    fn build(hub: Arc<TelemetryHub>, seed: Option<u64>) -> EngineResult<Self> {
        Ok(Self {
            hub,
            client: net::proxy_client()?,
            faults: watch::Sender::new(FaultState::default()),
            contracts: watch::Sender::new(Arc::new(ContractSet::default())),
            running: AsyncMutex::new(None),
            seed,
        })
    }

    pub async fn start(&self, config: ProxyConfig) -> EngineResult<ProxyStatus> {
        let target = guard::validate_url(&config.upstream)?;
        net::require_plaintext(&target)?;

        let mut running = self.running.lock().await;
        if let Some(active) = running.as_ref() {
            return Err(EngineError::ProxyAlreadyRunning {
                listener: active.listener.to_string(),
            });
        }

        let bind_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, config.listen_port));
        guard::validate_socket_addr(&bind_addr)?;
        let bind_error = |err: std::io::Error| EngineError::ListenerBind {
            addr: bind_addr.to_string(),
            reason: err.to_string(),
        };
        let listener = TcpListener::bind(bind_addr).await.map_err(bind_error)?;
        let local = listener.local_addr().map_err(bind_error)?;
        if net::loopback_addr(&target) == local {
            return Err(EngineError::ProxyLoop {
                addr: local.to_string(),
            });
        }

        let upstream_label = target.url.as_str().trim_end_matches('/').to_owned();
        let context = Arc::new(ProxyContext {
            upstream: target,
            upstream_label: upstream_label.clone(),
            client: self.client.clone(),
            faults: self.faults.subscribe(),
            contracts: self.contracts.subscribe(),
            linter: TrafficLinter::default(),
            hub: Arc::clone(&self.hub),
            rng: Mutex::new(self.seed.map_or_else(Rng::new, Rng::with_seed)),
        });
        let router = Router::new().fallback(proxy_handler).with_state(context);
        let (shutdown, shutdown_rx) = watch::channel(false);
        let task = tokio::spawn(accept_loop(listener, router, shutdown_rx));

        tracing::info!(listener = %local, upstream = %upstream_label, "proxy listener started");
        *running = Some(RunningProxy {
            listener: local,
            upstream: upstream_label,
            shutdown,
            task,
        });
        let status = self.snapshot(running.as_ref());
        drop(running);
        self.publish_state(&status);
        Ok(status)
    }

    /// Idempotent. Waits for in-flight exchanges up to the drain timeout, then aborts them.
    pub async fn stop(&self) -> ProxyStatus {
        let mut running = self.running.lock().await;
        if let Some(active) = running.take() {
            // Fails only if the accept loop already exited, which is the desired end state.
            let _ = active.shutdown.send(true);
            let abort = active.task.abort_handle();
            let grace = DRAIN_TIMEOUT + Duration::from_millis(500);
            if tokio::time::timeout(grace, active.task).await.is_err() {
                abort.abort();
                tracing::warn!(listener = %active.listener, "proxy accept loop aborted after drain timeout");
            }
            tracing::info!(listener = %active.listener, "proxy listener stopped");
        }
        let status = self.snapshot(running.as_ref());
        drop(running);
        self.publish_state(&status);
        status
    }

    pub async fn set_faults(
        &self,
        armed: bool,
        profile: FaultProfile,
    ) -> EngineResult<ProxyStatus> {
        profile.validate()?;
        self.faults.send_modify(|state| {
            state.armed = armed;
            state.profile = profile;
        });
        Ok(self.changed().await)
    }

    /// Replaces the route rule set atomically; an invalid rule leaves the active set intact.
    pub async fn set_rules(&self, rules: Vec<FaultRule>) -> EngineResult<ProxyStatus> {
        let compiled = fault::compile_rules(rules)?;
        self.faults.send_modify(|state| state.rules = compiled);
        Ok(self.changed().await)
    }

    /// Replaces the contract set atomically; an invalid template leaves the active set intact.
    pub async fn set_contracts(&self, contracts: Vec<RouteContract>) -> EngineResult<ProxyStatus> {
        let compiled = ContractSet::compile(contracts)?;
        self.contracts.send_replace(Arc::new(compiled));
        Ok(self.changed().await)
    }

    async fn changed(&self) -> ProxyStatus {
        let running = self.running.lock().await;
        let status = self.snapshot(running.as_ref());
        drop(running);
        self.publish_state(&status);
        status
    }

    pub async fn status(&self) -> ProxyStatus {
        let running = self.running.lock().await;
        self.snapshot(running.as_ref())
    }

    fn snapshot(&self, running: Option<&RunningProxy>) -> ProxyStatus {
        let faults = self.faults.borrow();
        ProxyStatus {
            running: running.is_some(),
            listener: running.map(|r| r.listener.to_string()),
            upstream: running.map(|r| r.upstream.clone()),
            armed: faults.armed,
            profile: faults.profile.clone(),
            rules: faults.rules.iter().map(|rule| rule.rule.clone()).collect(),
            contracts: u32::try_from(self.contracts.borrow().len()).unwrap_or(u32::MAX),
        }
    }

    fn publish_state(&self, status: &ProxyStatus) {
        self.hub.publish(TelemetryEvent::ProxyStateChanged {
            seq: self.hub.next_seq(),
            ts_us: now_us(),
            status: status.clone(),
        });
    }
}

// ---- connection handling --------------------------------------------------------------

#[derive(Clone)]
struct ConnContext {
    peer: SocketAddr,
    abort: Arc<Notify>,
}

async fn accept_loop(listener: TcpListener, router: Router, mut shutdown: watch::Receiver<bool>) {
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            accepted = listener.accept() => match accepted {
                Ok((stream, peer)) => {
                    // The listener is bound to 127.0.0.1, so this only fires if the bind
                    // invariant is ever broken; it keeps the inbound side auditable too.
                    if let Err(err) = guard::validate_socket_addr(&peer) {
                        tracing::warn!(%peer, error = %err, "rejected non-loopback peer");
                        continue;
                    }
                    if let Err(err) = stream.set_nodelay(true) {
                        tracing::debug!(%peer, error = %err, "TCP_NODELAY not applied");
                    }
                    connections.spawn(serve_connection(stream, peer, router.clone(), shutdown.clone()));
                }
                // Transient failures (EMFILE, ECONNABORTED) must not take the listener down.
                Err(err) => {
                    tracing::warn!(error = %err, "proxy accept failed");
                    tokio::time::sleep(ACCEPT_BACKOFF).await;
                }
            },
            Some(joined) = connections.join_next(), if !connections.is_empty() => {
                if let Err(err) = joined {
                    if err.is_panic() {
                        tracing::error!(error = %err, "proxy connection task panicked");
                    }
                }
            }
        }
    }
    drop(listener);

    let drain = async { while connections.join_next().await.is_some() {} };
    if tokio::time::timeout(DRAIN_TIMEOUT, drain).await.is_err() {
        tracing::warn!(
            remaining = connections.len(),
            "forcing proxy connections closed"
        );
        connections.abort_all();
    }
}

async fn serve_connection(
    stream: TcpStream,
    peer: SocketAddr,
    router: Router,
    mut shutdown: watch::Receiver<bool>,
) {
    let abort = Arc::new(Notify::new());
    let conn = ConnContext {
        peer,
        abort: Arc::clone(&abort),
    };
    let service = hyper::service::service_fn(move |mut request: hyper::Request<Incoming>| {
        request.extensions_mut().insert(conn.clone());
        router.clone().oneshot(request)
    });
    let mut connection =
        hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(stream), service);

    let aborted = abort.notified();
    tokio::pin!(aborted);
    let mut draining = false;

    loop {
        tokio::select! {
            result = &mut connection => {
                if let Err(err) = result {
                    tracing::debug!(%peer, error = %err, "proxy connection closed with error");
                }
                return;
            }
            () = &mut aborted => {
                // SO_LINGER=0 turns the close into an RST, which is what a crashed process
                // or a load balancer reset looks like on the wire. A plain drop would send
                // FIN and read as a clean server-side close.
                let parts = connection.into_parts();
                if let Err(err) = parts.io.inner().set_zero_linger() {
                    tracing::debug!(%peer, error = %err, "SO_LINGER not applied; closing with FIN");
                }
                return;
            }
            _ = shutdown.changed(), if !draining => {
                draining = true;
                std::pin::Pin::new(&mut connection).graceful_shutdown();
            }
        }
    }
}

// ---- request handling -----------------------------------------------------------------

struct ProxyContext {
    upstream: GuardedTarget,
    upstream_label: String,
    client: Client,
    faults: watch::Receiver<FaultState>,
    contracts: watch::Receiver<Arc<ContractSet>>,
    /// N+1 windows live with the listener; a restart starts them empty.
    linter: TrafficLinter,
    hub: Arc<TelemetryHub>,
    rng: Mutex<Rng>,
}

impl ProxyContext {
    /// Decision plus the label of the rule that supplied it. Rules address routes as the
    /// service sees them, so matching uses the upstream path (base path included).
    fn plan(&self, method: &str, upstream_path: &str) -> (FaultPlan, Option<String>) {
        let state = self.faults.borrow();
        let mut rng = self.rng.lock().unwrap_or_else(PoisonError::into_inner);
        let plan = fault::plan(&state, method, upstream_path, &mut rng);
        let label = plan
            .rule
            .and_then(|index| state.rules.get(index))
            .map(|rule| rule.label());
        (plan, label)
    }

    fn finish(&self, mut record: Exchange, reply: Reply) -> Response {
        record.status = Some(reply.status.as_u16());
        record.response_bytes = byte_len(reply.body.len());
        record.retry_after = linter::retry_after(&reply.headers);
        self.publish(record);
        reply.into_response()
    }

    /// Writes the upstream head with the full Content-Length and the leading bytes of the
    /// body (`after`, else half; always short of the whole), then resets the connection. An
    /// empty body has nothing to cut and is forwarded.
    fn truncate(
        &self,
        mut record: Exchange,
        reply: Reply,
        after: Option<u32>,
        abort: &Arc<Notify>,
    ) -> Response {
        let total = reply.body.len();
        if total == 0 {
            return self.finish(record, reply);
        }
        let wanted = after.map_or(total / 2, |n| usize::try_from(n).unwrap_or(usize::MAX));
        let kept = wanted.min(total - 1);
        record.fault = Some(FaultKind::PartialBodyDrop);
        record.status = Some(reply.status.as_u16());
        record.response_bytes = byte_len(kept);
        record.retry_after = linter::retry_after(&reply.headers);
        self.publish(record);

        let Reply {
            status,
            mut headers,
            body,
        } = reply;
        headers.insert(header::CONTENT_LENGTH, HeaderValue::from(total));
        if let Ok(value) = HeaderValue::try_from(format!("partial-body-{kept}")) {
            headers.insert(HeaderName::from_static(FAULT_HEADER), value);
        }
        let mut response = Response::new(Body::new(TruncatedBody {
            head: (kept > 0).then(|| body.slice(..kept)),
            settle: Box::pin(tokio::time::sleep(PARTIAL_DROP_SETTLE)),
            abort: Some(Arc::clone(abort)),
        }));
        *response.status_mut() = status;
        *response.headers_mut() = headers;
        response
    }

    fn publish(&self, mut record: Exchange) {
        // Every request counts, whatever its fate: fan-outs and retry storms are client
        // behaviour, and a dropped or injected response does not make them less of one.
        if let Some(burst) = self
            .linter
            .track(record.started, &record.method, &record.path)
        {
            record.findings.push(burst);
        }
        if let Some(storm) = self
            .linter
            .repeat(record.started, &record.method, &record.path)
        {
            record.findings.push(storm);
        }
        // Published right before the response is handed to hyper: the client cannot see the
        // answer earlier than this instant, so a retry is measured from it.
        if let Some(storm) = self.linter.throttled_retry(
            record.started,
            Instant::now(),
            &record.method,
            &record.path,
            record.status,
            record.retry_after,
        ) {
            record.findings.push(storm);
        }
        // Upstream time excludes injected delay, so armed latency faults never read as a
        // service regression.
        if let (Some(status), Some(upstream_us)) = (record.status, record.upstream_latency_us) {
            if let Some(slow) =
                self.linter
                    .latency(&record.method, &record.path, status, upstream_us)
            {
                record.findings.push(slow);
            }
        }
        self.hub.publish(TelemetryEvent::ProxyExchange {
            seq: self.hub.next_seq(),
            id: record.id,
            ts_us: now_us(),
            method: record.method,
            path: record.path,
            upstream: self.upstream_label.clone(),
            status: record.status,
            latency_us: net::elapsed_us(record.started),
            injected_delay_us: record.injected_delay_us,
            upstream_latency_us: record.upstream_latency_us,
            fault: record.fault,
            rule: record.rule,
            request_bytes: record.request_bytes,
            response_bytes: record.response_bytes,
            error: record.error,
            contract: record.contract,
            violations: record.violations,
            findings: record.findings,
        });
    }

    /// The contract bound to the upstream path, cloned out of the snapshot (an `Arc` bump)
    /// so the watch read guard is released before any await.
    fn contract(
        &self,
        method: &str,
        upstream_path: &str,
    ) -> Option<Arc<contract::CompiledContract>> {
        self.contracts.borrow().find(method, upstream_path)
    }
}

struct Exchange {
    id: Uuid,
    started: Instant,
    method: String,
    path: String,
    status: Option<u16>,
    /// `Retry-After` the client received with `status`, for the throttled-retry check.
    retry_after: Option<Duration>,
    injected_delay_us: u64,
    upstream_latency_us: Option<u64>,
    fault: Option<FaultKind>,
    rule: Option<String>,
    request_bytes: u64,
    response_bytes: u64,
    error: Option<String>,
    contract: Option<String>,
    violations: Vec<ContractViolation>,
    findings: Vec<TrafficFinding>,
}

struct Reply {
    status: StatusCode,
    headers: HeaderMap,
    body: Bytes,
}

impl Reply {
    fn into_response(self) -> Response {
        let mut response = Response::new(Body::from(self.body));
        *response.status_mut() = self.status;
        *response.headers_mut() = self.headers;
        response
    }
}

/// Body of a partial drop: one frame with the kept bytes, then a stall that ends in the
/// connection task's RST teardown. It never reports end of stream, so hyper cannot close
/// the message cleanly.
struct TruncatedBody {
    head: Option<Bytes>,
    settle: Pin<Box<tokio::time::Sleep>>,
    abort: Option<Arc<Notify>>,
}

impl hyper::body::Body for TruncatedBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        let this = self.get_mut();
        if let Some(head) = this.head.take() {
            return Poll::Ready(Some(Ok(Frame::data(head))));
        }
        if this.settle.as_mut().poll(cx).is_ready() {
            if let Some(abort) = this.abort.take() {
                abort.notify_one();
            }
        }
        Poll::Pending
    }
}

async fn proxy_handler(
    State(ctx): State<Arc<ProxyContext>>,
    Extension(conn): Extension<ConnContext>,
    request: Request,
) -> Response {
    let mut record = Exchange {
        id: Uuid::new_v4(),
        started: Instant::now(),
        method: request.method().to_string(),
        path: request
            .uri()
            .path_and_query()
            .map_or_else(|| "/".to_owned(), |pq| pq.as_str().to_owned()),
        status: None,
        retry_after: None,
        injected_delay_us: 0,
        upstream_latency_us: None,
        fault: None,
        rule: None,
        request_bytes: 0,
        response_bytes: 0,
        error: None,
        contract: None,
        violations: Vec::new(),
        findings: Vec::new(),
    };
    // Rules and contracts address the path the service receives; both are resolved here,
    // before any await, from one joined URL.
    let (plan, contract) = {
        let upstream = upstream_url(&ctx.upstream.url, &record.path);
        let (plan, rule) = ctx.plan(&record.method, upstream.path());
        record.rule = rule;
        (plan, ctx.contract(&record.method, upstream.path()))
    };

    let (parts, body) = request.into_parts();
    let credentialed = parts.headers.contains_key(header::AUTHORIZATION)
        || parts.headers.contains_key(header::COOKIE);
    let body = match axum::body::to_bytes(body, MAX_BODY_BYTES).await {
        Ok(bytes) => bytes,
        Err(err) => {
            let status = body_error_status(&err);
            record.error = Some(format!("request body rejected: {err}"));
            return ctx.finish(
                record,
                error_reply(status, "request_body_rejected", &err.to_string()),
            );
        }
    };
    record.request_bytes = byte_len(body.len());

    if !plan.delay.is_zero() {
        tokio::time::sleep(plan.delay).await;
        record.injected_delay_us = u64::try_from(plan.delay.as_micros()).unwrap_or(u64::MAX);
    }

    match plan.action {
        FaultAction::Drop => {
            record.fault = Some(FaultKind::ConnectionDrop);
            ctx.publish(record);
            conn.abort.notify_one();
            // The connection task drops this future together with the socket.
            future::pending::<Response>().await
        }
        FaultAction::Mutate(status) => {
            record.fault = Some(FaultKind::StatusMutation);
            ctx.finish(record, injected_reply(status))
        }
        FaultAction::Forward | FaultAction::PartialDrop { .. } => {
            match forward(&ctx, &conn, parts, body).await {
                Ok((mut reply, upstream_latency_us)) => {
                    record.upstream_latency_us = Some(upstream_latency_us);
                    // Only upstream answers are judged: an injected status or a 502 from the proxy
                    // itself says nothing about the service's contract. The client receives
                    // the encoded bytes untouched; only the checks read the inflated copy.
                    {
                        let decoded = linter::decode(&reply.headers, &reply.body);
                        if let Some(bound) = contract {
                            record.violations = contract::check(
                                &bound.contract,
                                reply.status.as_u16(),
                                decoded.bytes(),
                            );
                            record.contract = Some(bound.label.clone());
                        }
                        record.findings = linter::inspect(&ResponseView {
                            method: &record.method,
                            path: &record.path,
                            credentialed,
                            status: reply.status.as_u16(),
                            headers: &reply.headers,
                            body: &decoded,
                        });
                    }
                    if record.injected_delay_us > 0 {
                        reply.headers.insert(
                            HeaderName::from_static(DELAY_HEADER),
                            HeaderValue::from(record.injected_delay_us),
                        );
                    }
                    // The checks above judged the upstream's answer; the cut is the proxy's.
                    if let FaultAction::PartialDrop { after } = plan.action {
                        return ctx.truncate(record, reply, after, &conn.abort);
                    }
                    ctx.finish(record, reply)
                }
                Err(failure) => {
                    let detail = failure.to_string();
                    record.error = Some(detail.clone());
                    ctx.finish(
                        record,
                        error_reply(failure.status(), "upstream_unavailable", &detail),
                    )
                }
            }
        }
    }
}

#[derive(Debug, thiserror::Error)]
enum ForwardError {
    #[error("upstream {detail}")]
    Upstream { detail: String, timeout: bool },
    #[error(transparent)]
    Guard(#[from] EngineError),
    #[error("upstream response exceeds {MAX_BODY_BYTES} bytes")]
    ResponseTooLarge,
}

impl ForwardError {
    /// Only a response timeout is a gateway timeout. A connect timeout is a refused or
    /// unreachable upstream: Windows retries SYN against closed loopback ports for ~2 s
    /// instead of surfacing the RST, so it routinely arrives as a timeout.
    fn upstream(err: &reqwest::Error) -> Self {
        Self::Upstream {
            detail: net::describe(err),
            timeout: err.is_timeout() && !err.is_connect(),
        }
    }

    fn status(&self) -> StatusCode {
        match self {
            Self::Upstream { timeout: true, .. } => StatusCode::GATEWAY_TIMEOUT,
            _ => StatusCode::BAD_GATEWAY,
        }
    }
}

async fn forward(
    ctx: &ProxyContext,
    conn: &ConnContext,
    parts: request::Parts,
    body: Bytes,
) -> Result<(Reply, u64), ForwardError> {
    let path_and_query = parts.uri.path_and_query().map_or("/", |pq| pq.as_str());
    let url = upstream_url(&ctx.upstream.url, path_and_query);

    let mut headers = parts.headers;
    let original_host = headers.remove(header::HOST);
    strip_hop_by_hop(&mut headers);
    // reqwest derives Host from the URL and Content-Length from the buffered body.
    headers.remove(header::CONTENT_LENGTH);
    if let Some(host) = original_host {
        headers.insert(HeaderName::from_static(FORWARDED_HOST), host);
    }
    if let Ok(peer) = HeaderValue::try_from(conn.peer.ip().to_string()) {
        headers.append(HeaderName::from_static(FORWARDED_FOR), peer);
    }
    headers.append(header::VIA, HeaderValue::from_static(VIA));

    let started = Instant::now();
    let mut response = ctx
        .client
        .request(parts.method, url)
        .headers(headers)
        .body(body)
        .send()
        .await
        .map_err(|err| ForwardError::upstream(&err))?;
    if let Some(peer) = response.remote_addr() {
        guard::validate_socket_addr(&peer)?;
    }
    if response
        .content_length()
        .is_some_and(|len| len > byte_len(MAX_BODY_BYTES))
    {
        return Err(ForwardError::ResponseTooLarge);
    }

    let status = response.status();
    let mut headers = std::mem::take(response.headers_mut());
    strip_hop_by_hop(&mut headers);

    let mut buffer = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|err| ForwardError::upstream(&err))?
    {
        if buffer.len() + chunk.len() > MAX_BODY_BYTES {
            return Err(ForwardError::ResponseTooLarge);
        }
        buffer.extend_from_slice(&chunk);
    }

    let reply = Reply {
        status,
        headers,
        body: Bytes::from(buffer),
    };
    Ok((reply, net::elapsed_us(started)))
}

/// Joins the upstream base path with the inbound path, so an upstream configured as
/// `http://127.0.0.1:3000/api` receives `/api/users` for an inbound `/users`.
fn upstream_url(base: &Url, path_and_query: &str) -> Url {
    let (path, query) = path_and_query
        .split_once('?')
        .map_or((path_and_query, None), |(path, query)| (path, Some(query)));
    let mut url = base.clone();
    let prefix = base.path().trim_end_matches('/');
    url.set_path(&format!("{prefix}{path}"));
    url.set_query(query);
    url.set_fragment(None);
    url
}

fn strip_hop_by_hop(headers: &mut HeaderMap) {
    // Fields listed in `Connection` are hop-by-hop for this message only.
    let listed: Vec<HeaderName> = headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|name| HeaderName::from_bytes(name.trim().as_bytes()).ok())
        .collect();
    for name in listed.iter().chain(HOP_BY_HOP.iter()) {
        headers.remove(name);
    }
}

fn injected_reply(status: StatusCode) -> Reply {
    let code = status.as_u16();
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    if let Ok(value) = HeaderValue::try_from(format!("status-{code}")) {
        headers.insert(HeaderName::from_static(FAULT_HEADER), value);
    }
    if status == StatusCode::TOO_MANY_REQUESTS {
        headers.insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
    }
    let body =
        serde_json::json!({ "error": "injected_fault", "status": code, "source": "z-proxy" });
    Reply {
        status,
        headers,
        body: Bytes::from(body.to_string()),
    }
}

fn error_reply(status: StatusCode, error: &str, detail: &str) -> Reply {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    if let Ok(value) = HeaderValue::try_from(error) {
        headers.insert(HeaderName::from_static(ERROR_HEADER), value);
    }
    let body = serde_json::json!({ "error": error, "detail": detail, "source": "z-proxy" });
    Reply {
        status,
        headers,
        body: Bytes::from(body.to_string()),
    }
}

fn body_error_status(err: &axum::Error) -> StatusCode {
    let mut source: Option<&(dyn std::error::Error + 'static)> = Some(err);
    while let Some(current) = source {
        if current.is::<http_body_util::LengthLimitError>() {
            return StatusCode::PAYLOAD_TOO_LARGE;
        }
        source = current.source();
    }
    StatusCode::BAD_REQUEST
}

fn byte_len(len: usize) -> u64 {
    u64::try_from(len).unwrap_or(u64::MAX)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use axum::response::IntoResponse;
    use tokio::sync::broadcast;

    use super::*;
    use crate::engine::fault::StatusMutation;
    use crate::engine::types::RouteMethod;

    const EVENT_TIMEOUT: Duration = Duration::from_secs(5);

    struct Harness {
        manager: ProxyManager,
        events: broadcast::Receiver<TelemetryEvent>,
        client: reqwest::Client,
        upstream: SocketAddr,
        hits: Arc<AtomicUsize>,
    }

    impl Harness {
        async fn new() -> Self {
            let hub = Arc::new(TelemetryHub::new());
            let events = hub.subscribe();
            let (upstream, hits) = spawn_upstream().await;
            Self {
                manager: ProxyManager::with_seed(hub, 0x5eed).unwrap(),
                events,
                client: reqwest::Client::builder().no_proxy().build().unwrap(),
                upstream,
                hits,
            }
        }

        async fn start(&self) -> SocketAddr {
            let status = self
                .manager
                .start(ProxyConfig {
                    upstream: format!("http://127.0.0.1:{}", self.upstream.port()),
                    listen_port: 0,
                })
                .await
                .unwrap();
            status.listener.unwrap().parse().unwrap()
        }

        async fn arm(&self, profile: FaultProfile) {
            self.manager.set_faults(true, profile).await.unwrap();
        }

        async fn next_exchange(&mut self) -> TelemetryEvent {
            loop {
                let event = tokio::time::timeout(EVENT_TIMEOUT, self.events.recv())
                    .await
                    .expect("telemetry event")
                    .unwrap();
                if matches!(event, TelemetryEvent::ProxyExchange { .. }) {
                    return event;
                }
            }
        }
    }

    async fn spawn_upstream() -> (SocketAddr, Arc<AtomicUsize>) {
        let hits = Arc::new(AtomicUsize::new(0));
        let router = Router::new().fallback(echo).with_state(Arc::clone(&hits));
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        (addr, hits)
    }

    async fn echo(State(hits): State<Arc<AtomicUsize>>, request: Request) -> Response {
        hits.fetch_add(1, Ordering::SeqCst);
        let (parts, body) = request.into_parts();
        let header = |name: &str| {
            parts
                .headers
                .get(name)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("-")
                .to_owned()
        };
        let line = format!(
            "{} {} host={} via={} xfh={} xff={} hop={} ka={}",
            parts.method,
            parts.uri,
            header("host"),
            header("via"),
            header("x-forwarded-host"),
            header("x-forwarded-for"),
            header("x-hop-secret"),
            header("keep-alive"),
        );
        let body = axum::body::to_bytes(body, usize::MAX).await.unwrap();
        (
            [("x-upstream", "echo")],
            format!("{line} body={}", body.len()),
        )
            .into_response()
    }

    fn free_port() -> u16 {
        let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        listener.local_addr().unwrap().port()
    }

    #[test]
    fn upstream_url_joins_base_path_and_query() {
        let base = Url::parse("http://127.0.0.1:3000/api/").unwrap();
        assert_eq!(
            upstream_url(&base, "/users?page=2").as_str(),
            "http://127.0.0.1:3000/api/users?page=2"
        );
        let root = Url::parse("http://127.0.0.1:3000").unwrap();
        assert_eq!(upstream_url(&root, "/").as_str(), "http://127.0.0.1:3000/");
    }

    #[test]
    fn connection_listed_headers_are_stripped() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONNECTION,
            HeaderValue::from_static("keep-alive, x-hop-secret"),
        );
        headers.insert("keep-alive", HeaderValue::from_static("timeout=5"));
        headers.insert("x-hop-secret", HeaderValue::from_static("1"));
        headers.insert(header::ACCEPT, HeaderValue::from_static("*/*"));
        strip_hop_by_hop(&mut headers);
        assert_eq!(headers.len(), 1);
        assert!(headers.contains_key(header::ACCEPT));
    }

    #[tokio::test]
    async fn forwards_request_and_reports_exchange() {
        let mut h = Harness::new().await;
        let proxy = h.start().await;
        assert_eq!(proxy.ip(), Ipv4Addr::LOCALHOST);

        let response = h
            .client
            .post(format!("http://{proxy}/api/items?x=1"))
            .header(header::CONNECTION, "keep-alive, x-hop-secret")
            .header("x-hop-secret", "1")
            .header("keep-alive", "timeout=5")
            .body("hello")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["x-upstream"], "echo");
        let body = response.text().await.unwrap();

        let expected = format!(
            "POST /api/items?x=1 host=127.0.0.1:{} via=1.1 z-proxy xfh={proxy} xff=127.0.0.1 hop=- ka=- body=5",
            h.upstream.port()
        );
        assert_eq!(body, expected);

        match h.next_exchange().await {
            TelemetryEvent::ProxyExchange {
                method,
                path,
                status,
                fault,
                request_bytes,
                response_bytes,
                upstream_latency_us,
                injected_delay_us,
                error,
                ..
            } => {
                assert_eq!(method, "POST");
                assert_eq!(path, "/api/items?x=1");
                assert_eq!(status, Some(200));
                assert_eq!(fault, None);
                assert_eq!(request_bytes, 5);
                assert_eq!(response_bytes, u64::try_from(body.len()).unwrap());
                assert!(upstream_latency_us.is_some());
                assert_eq!(injected_delay_us, 0);
                assert_eq!(error, None);
            }
            other => panic!("unexpected event {other:?}"),
        }
    }

    #[tokio::test]
    async fn latency_jitter_is_applied_within_bounds() {
        let mut h = Harness::new().await;
        let proxy = h.start().await;
        h.arm(FaultProfile {
            latency_ms: 60,
            jitter_ms: 20,
            ..FaultProfile::default()
        })
        .await;

        for _ in 0..8 {
            let started = Instant::now();
            let response = h
                .client
                .get(format!("http://{proxy}/"))
                .send()
                .await
                .unwrap();
            let elapsed = started.elapsed();
            assert_eq!(response.status(), StatusCode::OK);
            let reported: u64 = response.headers()[DELAY_HEADER]
                .to_str()
                .unwrap()
                .parse()
                .unwrap();

            assert!(
                (40_000..=80_000).contains(&reported),
                "reported delay {reported} us"
            );
            assert!(
                elapsed >= Duration::from_micros(reported),
                "{elapsed:?} < {reported} us"
            );
            assert!(elapsed < Duration::from_millis(80 + 500), "{elapsed:?}");

            match h.next_exchange().await {
                TelemetryEvent::ProxyExchange {
                    injected_delay_us,
                    latency_us,
                    fault,
                    ..
                } => {
                    assert_eq!(injected_delay_us, reported);
                    assert!(latency_us >= injected_delay_us);
                    assert_eq!(fault, None);
                }
                other => panic!("unexpected event {other:?}"),
            }
        }
    }

    #[tokio::test]
    async fn status_mutation_short_circuits_and_updates_live() {
        let mut h = Harness::new().await;
        let proxy = h.start().await;
        h.arm(FaultProfile {
            status_mutation: StatusMutation::ServiceUnavailable,
            mutation_rate: 100,
            ..FaultProfile::default()
        })
        .await;

        for _ in 0..10 {
            let response = h
                .client
                .get(format!("http://{proxy}/orders"))
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(response.headers()[FAULT_HEADER], "status-503");
            let body: serde_json::Value = response.json().await.unwrap();
            assert_eq!(body["status"], 503);
        }
        assert_eq!(
            h.hits.load(Ordering::SeqCst),
            0,
            "upstream must not be contacted"
        );
        match h.next_exchange().await {
            TelemetryEvent::ProxyExchange {
                status,
                fault,
                upstream_latency_us,
                ..
            } => {
                assert_eq!(status, Some(503));
                assert_eq!(fault, Some(FaultKind::StatusMutation));
                assert_eq!(upstream_latency_us, None);
            }
            other => panic!("unexpected event {other:?}"),
        }

        // Same listener, new profile: no restart required.
        h.arm(FaultProfile {
            status_mutation: StatusMutation::TooManyRequests,
            mutation_rate: 100,
            ..FaultProfile::default()
        })
        .await;
        let response = h
            .client
            .get(format!("http://{proxy}/orders"))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(response.headers()[header::RETRY_AFTER], "1");

        h.manager
            .set_faults(false, FaultProfile::default())
            .await
            .unwrap();
        let response = h
            .client
            .get(format!("http://{proxy}/orders"))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(h.hits.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn partial_mutation_rate_tracks_probability() {
        let h = Harness::new().await;
        let proxy = h.start().await;
        h.arm(FaultProfile {
            status_mutation: StatusMutation::InternalServerError,
            mutation_rate: 50,
            ..FaultProfile::default()
        })
        .await;

        let mut mutated = 0;
        for _ in 0..200 {
            let response = h
                .client
                .get(format!("http://{proxy}/"))
                .send()
                .await
                .unwrap();
            if response.status() == StatusCode::INTERNAL_SERVER_ERROR {
                mutated += 1;
            }
        }
        assert!((70..=130).contains(&mutated), "{mutated}");
        assert_eq!(h.hits.load(Ordering::SeqCst), 200 - mutated);
    }

    #[tokio::test]
    async fn connection_drop_resets_without_response() {
        let mut h = Harness::new().await;
        let proxy = h.start().await;
        h.arm(FaultProfile {
            drop_rate: 100,
            ..FaultProfile::default()
        })
        .await;

        let err = h
            .client
            .get(format!("http://{proxy}/pay"))
            .send()
            .await
            .unwrap_err();
        assert!(err.is_request() || err.is_connect(), "{err:?}");
        assert_eq!(h.hits.load(Ordering::SeqCst), 0);
        match h.next_exchange().await {
            TelemetryEvent::ProxyExchange {
                status,
                fault,
                response_bytes,
                ..
            } => {
                assert_eq!(status, None);
                assert_eq!(fault, Some(FaultKind::ConnectionDrop));
                assert_eq!(response_bytes, 0);
            }
            other => panic!("unexpected event {other:?}"),
        }

        h.manager
            .set_faults(false, FaultProfile::default())
            .await
            .unwrap();
        let response = h
            .client
            .get(format!("http://{proxy}/pay"))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn partial_body_drop_cuts_the_body_mid_stream() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let mut h = Harness::new().await;
        let proxy = h.start().await;
        h.arm(FaultProfile {
            partial_drop_rate: Some(100),
            partial_drop_bytes: Some(10),
            ..FaultProfile::default()
        })
        .await;

        // A client sees a complete head, then a body read that fails.
        let response = h
            .client
            .get(format!("http://{proxy}/orders"))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[FAULT_HEADER], "partial-body-10");
        assert!(
            response.bytes().await.is_err(),
            "truncated body must not read cleanly"
        );
        match h.next_exchange().await {
            TelemetryEvent::ProxyExchange {
                status,
                fault,
                response_bytes,
                upstream_latency_us,
                ..
            } => {
                assert_eq!(status, Some(200));
                assert_eq!(fault, Some(FaultKind::PartialBodyDrop));
                assert_eq!(response_bytes, 10);
                assert!(upstream_latency_us.is_some());
            }
            other => panic!("unexpected event {other:?}"),
        }

        // On the wire: the full Content-Length, exactly ten body bytes, then the reset.
        let mut stream = TcpStream::connect(proxy).await.unwrap();
        stream
            .write_all(b"GET /orders HTTP/1.1\r\nhost: 127.0.0.1\r\n\r\n")
            .await
            .unwrap();
        let mut wire = Vec::new();
        let mut buf = [0u8; 1024];
        loop {
            match tokio::time::timeout(EVENT_TIMEOUT, stream.read(&mut buf)).await {
                Ok(Ok(0)) | Ok(Err(_)) => break,
                Ok(Ok(n)) => wire.extend_from_slice(&buf[..n]),
                Err(_) => panic!("connection was never torn down"),
            }
        }
        let text = String::from_utf8_lossy(&wire).to_string();
        let (head, body) = text.split_once("\r\n\r\n").unwrap();
        let declared: usize = head
            .lines()
            .find_map(|line| line.strip_prefix("content-length: "))
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(body.len(), 10, "{text}");
        assert!(declared > 10, "{head}");
        assert_eq!(h.hits.load(Ordering::SeqCst), 2);

        // Disarmed, the same route answers in full again.
        h.manager
            .set_faults(false, FaultProfile::default())
            .await
            .unwrap();
        let full = h
            .client
            .get(format!("http://{proxy}/orders"))
            .send()
            .await
            .unwrap();
        assert!(full.headers().get(FAULT_HEADER).is_none());
        assert!(full.bytes().await.is_ok());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn compressed_responses_and_retry_storms_are_audited() {
        use std::io::Write;

        use crate::engine::types::TrafficFindingKind;

        let trace = b"TypeError: Cannot read properties of undefined (reading 'id')\n    at loadCart (/srv/app/cart.js:12:9)";
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(trace).unwrap();
        let compressed = Bytes::from(encoder.finish().unwrap());
        let served = compressed.clone();
        let router = Router::new().fallback(move || {
            let body = served.clone();
            async move {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    [("content-type", "text/plain"), ("content-encoding", "gzip")],
                    body,
                )
            }
        });
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let upstream = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });

        let hub = Arc::new(TelemetryHub::new());
        let mut events = hub.subscribe();
        let manager = ProxyManager::with_seed(hub, 3).unwrap();
        let proxy = manager
            .start(ProxyConfig {
                upstream: format!("http://127.0.0.1:{}", upstream.port()),
                listen_port: 0,
            })
            .await
            .unwrap()
            .listener
            .unwrap();
        let client = reqwest::Client::builder().no_proxy().build().unwrap();

        // A cart widget refetching in a render loop: twelve identical requests back to back.
        for _ in 0..12 {
            let response = client
                .get(format!("http://{proxy}/cart?user=7"))
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
            assert_eq!(
                response.bytes().await.unwrap(),
                compressed,
                "forwarded encoded"
            );
        }
        let mut leaks = 0;
        let mut storms = Vec::new();
        let mut exchanges = 0;
        while exchanges < 12 {
            let event = tokio::time::timeout(EVENT_TIMEOUT, events.recv())
                .await
                .unwrap()
                .unwrap();
            if let TelemetryEvent::ProxyExchange { findings, .. } = event {
                exchanges += 1;
                leaks += findings
                    .iter()
                    .filter(|f| f.kind == TrafficFindingKind::PassiveDisclosure)
                    .count();
                storms.extend(
                    findings
                        .into_iter()
                        .filter(|f| f.kind == TrafficFindingKind::RetryStorm),
                );
            }
        }
        assert_eq!(leaks, 12, "the inflated body is scanned on every exchange");
        assert_eq!(storms.len(), 1, "{storms:?}");
        assert_eq!(storms[0].evidence.as_deref(), Some("GET /cart?user=7"));
        manager.stop().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn injected_throttling_exposes_retries_without_backoff() {
        use crate::engine::types::TrafficFindingKind;

        let mut h = Harness::new().await;
        let proxy = h.start().await;
        h.arm(FaultProfile {
            status_mutation: StatusMutation::ServiceUnavailable,
            mutation_rate: 100,
            ..FaultProfile::default()
        })
        .await;
        let throttle_storms = |event: TelemetryEvent| match event {
            TelemetryEvent::ProxyExchange { findings, .. } => findings
                .iter()
                .filter(|f| {
                    f.kind == TrafficFindingKind::RetryStorm
                        && f.detail
                            .starts_with("immediate retry storm after 429/503 without backoff")
                })
                .count(),
            other => panic!("unexpected event {other:?}"),
        };

        // A client that resends the moment the 503 arrives: the original and four retries.
        for _ in 0..5 {
            let response = h
                .client
                .post(format!("http://{proxy}/api/v1/orders"))
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        }
        let mut storms = Vec::new();
        for _ in 0..5 {
            storms.push(throttle_storms(h.next_exchange().await));
        }
        assert_eq!(storms, [0, 0, 0, 0, 1]);

        // The same five requests with a pause longer than the window between them.
        for _ in 0..5 {
            let response = h
                .client
                .post(format!("http://{proxy}/api/v1/quotes"))
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
            tokio::time::sleep(Duration::from_millis(150)).await;
        }
        for _ in 0..5 {
            assert_eq!(throttle_storms(h.next_exchange().await), 0);
        }
        h.manager.stop().await;
    }

    /// An injected 429 carries `Retry-After: 1`. A client pausing 150 ms between attempts
    /// backs off past the immediate-retry window but still retries inside the advertised
    /// second, and the finding names the interval it broke.
    #[tokio::test]
    async fn retries_inside_an_injected_retry_after_are_reported() {
        use crate::engine::types::TrafficFindingKind;

        let mut h = Harness::new().await;
        let proxy = h.start().await;
        h.arm(FaultProfile {
            status_mutation: StatusMutation::TooManyRequests,
            mutation_rate: 100,
            ..FaultProfile::default()
        })
        .await;
        for _ in 0..5 {
            let response = h
                .client
                .post(format!("http://{proxy}/api/v1/quotes"))
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
            assert_eq!(response.headers()[header::RETRY_AFTER], "1");
            tokio::time::sleep(Duration::from_millis(150)).await;
        }
        let mut storms = Vec::new();
        for _ in 0..5 {
            match h.next_exchange().await {
                TelemetryEvent::ProxyExchange { findings, .. } => storms.extend(
                    findings
                        .into_iter()
                        .filter(|f| f.kind == TrafficFindingKind::RetryStorm)
                        .map(|f| f.detail),
                ),
                other => panic!("unexpected event {other:?}"),
            }
        }
        assert_eq!(storms.len(), 1, "{storms:?}");
        assert!(
            storms[0].starts_with("retry storm after 429/503 ignoring Retry-After: 4 retries in a row")
                && storms[0].ends_with("after a 429 answer that set Retry-After: 1 s; wait the advertised interval before retrying"),
            "{}",
            storms[0]
        );
        h.manager.stop().await;
    }

    #[tokio::test]
    async fn unreachable_upstream_yields_bad_gateway() {
        let hub = Arc::new(TelemetryHub::new());
        let mut events = hub.subscribe();
        let manager = ProxyManager::with_seed(hub, 1).unwrap();
        let status = manager
            .start(ProxyConfig {
                upstream: format!("localhost:{}", free_port()),
                listen_port: 0,
            })
            .await
            .unwrap();
        let proxy = status.listener.unwrap();

        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        let response = client.get(format!("http://{proxy}/")).send().await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        assert_eq!(response.headers()[ERROR_HEADER], "upstream_unavailable");

        loop {
            let event = tokio::time::timeout(EVENT_TIMEOUT, events.recv())
                .await
                .unwrap()
                .unwrap();
            if let TelemetryEvent::ProxyExchange {
                status,
                error,
                fault,
                ..
            } = event
            {
                assert_eq!(status, Some(502));
                assert_eq!(fault, None);
                assert!(error.is_some());
                break;
            }
        }
    }

    #[tokio::test]
    async fn rejects_unsafe_upstreams_before_binding() {
        let h = Harness::new().await;
        let cases = [
            ("http://10.0.0.1:8080", "NON_LOOPBACK_TARGET_REJECTED"),
            ("http://localhost.evil.test", "NON_LOOPBACK_TARGET_REJECTED"),
            ("https://127.0.0.1:8443", "PLAINTEXT_ONLY"),
            ("ws://127.0.0.1:4000", "PLAINTEXT_ONLY"),
        ];
        for (upstream, code) in cases {
            let err = h
                .manager
                .start(ProxyConfig {
                    upstream: upstream.to_owned(),
                    listen_port: 0,
                })
                .await
                .unwrap_err();
            assert_eq!(err.code(), code, "{upstream}");
        }
        assert!(!h.manager.status().await.running);
    }

    #[tokio::test]
    async fn lifecycle_is_exclusive_and_releases_port() {
        let mut h = Harness::new().await;
        let proxy = h.start().await;

        let err = h
            .manager
            .start(ProxyConfig {
                upstream: format!("http://127.0.0.1:{}", h.upstream.port()),
                listen_port: 0,
            })
            .await
            .unwrap_err();
        assert_eq!(err.code(), "PROXY_ALREADY_RUNNING");

        let status = h.manager.stop().await;
        assert!(!status.running);
        assert_eq!(status.listener, None);
        assert!(!h.manager.stop().await.running, "stop is idempotent");
        std::net::TcpListener::bind(proxy).expect("port released after stop");

        let mut states = Vec::new();
        while let Ok(event) = h.events.try_recv() {
            if let TelemetryEvent::ProxyStateChanged { status, .. } = event {
                states.push(status.running);
            }
        }
        assert_eq!(states, [true, false, false]);
    }

    #[tokio::test]
    async fn self_targeting_upstream_is_rejected() {
        let h = Harness::new().await;
        let port = free_port();
        for upstream in [
            format!("http://127.0.0.1:{port}"),
            format!("localhost:{port}"),
        ] {
            let err = h
                .manager
                .start(ProxyConfig {
                    upstream: upstream.clone(),
                    listen_port: port,
                })
                .await
                .unwrap_err();
            assert_eq!(err.code(), "PROXY_LOOP", "{upstream}");
        }
    }

    #[tokio::test]
    async fn route_rules_override_the_global_profile_per_upstream_path() {
        let hub = Arc::new(TelemetryHub::new());
        let mut events = hub.subscribe();
        let (upstream, hits) = spawn_upstream().await;
        let manager = ProxyManager::with_seed(hub, 0x5eed).unwrap();
        // Upstream base path `/api`: rules address the path the service receives.
        let proxy = manager
            .start(ProxyConfig {
                upstream: format!("http://127.0.0.1:{}/api", upstream.port()),
                listen_port: 0,
            })
            .await
            .unwrap()
            .listener
            .unwrap();
        let rule = |method, pattern: &str, status| FaultRule {
            method,
            path_pattern: pattern.to_owned(),
            profile: FaultProfile {
                status_mutation: status,
                mutation_rate: 100,
                ..FaultProfile::default()
            },
        };
        let status = manager
            .set_rules(vec![
                rule(
                    Some(RouteMethod::Post),
                    "/api/orders/{id}",
                    StatusMutation::ServiceUnavailable,
                ),
                rule(None, "/api/health", StatusMutation::TooManyRequests),
            ])
            .await
            .unwrap();
        assert_eq!(status.rules.len(), 2);

        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        let send = |method: reqwest::Method, path: &str| {
            client
                .request(method, format!("http://{proxy}{path}"))
                .send()
        };
        let code = |response: reqwest::Response| response.status().as_u16();

        // Rules are inert until armed.
        assert_eq!(
            code(send(reqwest::Method::POST, "/orders/7").await.unwrap()),
            200
        );
        let status = manager
            .set_faults(true, FaultProfile::default())
            .await
            .unwrap();
        assert_eq!(status.rules.len(), 2, "arming keeps the rule set");

        let mutated = send(reqwest::Method::POST, "/orders/7").await.unwrap();
        assert_eq!(mutated.headers()[FAULT_HEADER], "status-503");
        assert_eq!(code(mutated), 503);
        assert_eq!(
            code(send(reqwest::Method::GET, "/orders/7").await.unwrap()),
            200
        );
        assert_eq!(
            code(send(reqwest::Method::POST, "/orders").await.unwrap()),
            200
        );
        assert_eq!(
            code(send(reqwest::Method::DELETE, "/health/").await.unwrap()),
            429
        );
        assert_eq!(hits.load(Ordering::SeqCst), 3);

        let mut rules = Vec::new();
        while let Ok(event) = events.try_recv() {
            if let TelemetryEvent::ProxyExchange { status, rule, .. } = event {
                rules.push((status, rule));
            }
        }
        assert_eq!(
            rules,
            [
                (Some(200), None),
                (Some(503), Some("POST /api/orders/{id}".to_owned())),
                (Some(200), None),
                (Some(200), None),
                (Some(429), Some("ANY /api/health".to_owned())),
            ]
        );

        let err = manager
            .set_rules(vec![rule(None, "orders", StatusMutation::BadGateway)])
            .await
            .unwrap_err();
        assert_eq!(err.code(), "INVALID_FAULT_RULE");
        assert_eq!(manager.status().await.rules.len(), 2);
    }

    #[tokio::test]
    async fn invalid_profile_is_rejected_and_state_unchanged() {
        let h = Harness::new().await;
        let err = h
            .manager
            .set_faults(
                true,
                FaultProfile {
                    drop_rate: 150,
                    ..FaultProfile::default()
                },
            )
            .await
            .unwrap_err();
        assert_eq!(err.code(), "INVALID_FAULT_PROFILE");
        assert!(!h.manager.status().await.armed);
    }
}
