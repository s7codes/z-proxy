//! Embedded target lab: a deliberately flawed loopback microservice.
//!
//! Gives the burst runner, fuzzer and proxy a known target whose defects switch at runtime.
//! `Unprotected` mode redeems a single-use coupon with a check-then-act race, lets
//! unvalidated checkout input and order identifiers crash into handlers that leak stack
//! traces and database errors, accepts JSON that violates the documented contract, and
//! answers with bodies that drift from the documented response schemas. `Hardened` mode
//! reserves the coupon with one conditional update, rejects every invalid body or path
//! parameter with a 422 JSON body, and answers exactly as documented. The listener binds
//! 127.0.0.1 only.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::hash::{DefaultHasher, Hasher};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use axum::body::Bytes;
use axum::extract::{Path, Request, State};
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use serde::de::{DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::{json, Map, Value};
use tokio::net::TcpListener;
use tokio::sync::{oneshot, Mutex as AsyncMutex};
use tokio::task::JoinHandle;
use uuid::Uuid;

use super::error::{EngineError, EngineResult};
use super::guard;
use super::net;
use super::types::{LabConfig, LabCounters, LabMode, LabStatus, TelemetryEvent};
use crate::telemetry::{now_us, TelemetryHub};

pub const DEFAULT_PORT: u16 = 17480;
pub const COUPON_CODE: &str = "LAB-SINGLE-USE";
pub const SPEC_FILE: &str = "openapi.json";
pub const SPEC_PATH: &str = "/api/v1/lab/openapi.json";
const COUPON_LIMIT: u32 = 1;
const DISCOUNT_CENTS: u64 = 500;
/// Simulated lookup latency per redemption already in flight. Queueing delay that grows with
/// depth models a saturated connection pool, and it spreads a burst's balance reads across
/// the commit window: the first reads land before any write (winners), the late ones after
/// it (conflicts). Without it a 20-worker burst yields 20 indistinguishable winners, which
/// no response-level detector can tell apart from an unlimited coupon.
const LOOKUP_STEP: Duration = Duration::from_millis(5);
const MAX_LOOKUP_DEPTH: u32 = 64;
/// Gap between the balance check and the write (payment provider round trip). Wide enough
/// that Windows' default 15.6 ms timer resolution cannot close the race window.
const COMMIT_WINDOW: Duration = Duration::from_millis(60);
const HARDENED_MAX_BODY: usize = 32 * 1024;
/// The checkout schema nests two levels (root, customer); anything far deeper is not a
/// payload the contract describes and is refused before field validation walks it.
const HARDENED_MAX_DEPTH: usize = 8;
/// Documented `maximum` of the `orderId` path parameter.
const ORDER_ID_MAX: u64 = 999_999;
/// Confirmed orders kept for lookup; the oldest is evicted first.
const ORDER_RETENTION: usize = 1_024;
const IDEMPOTENCY_HEADER: &str = "idempotency-key";
const REPLAYED_HEADER: &str = "idempotent-replayed";
/// Upper bound of an `Idempotency-Key`, as the IETF draft recommends for UUID-sized keys.
const IDEMPOTENCY_KEY_MAX: usize = 255;
/// Seeded history, so `GET /api/v1/orders/1` resolves on a fresh lab and a fuzz baseline
/// with the default identifier is accepted.
const ORDER_HISTORY: [(u64, &str, i64); 3] = [
    (1, "LAB-KB-01", 2),
    (2, "LAB-MS-02", 1),
    (3, "LAB-HUB-03", 4),
];
const SHUTDOWN_GRACE: Duration = Duration::from_secs(2);
const SKU_MAX: usize = 64;
const EMAIL_MAX: usize = 254;
const NAME_MAX: usize = 64;
const NOTE_MAX: usize = 256;
const QUANTITY_MAX: i64 = 10_000;
const CHECKOUT_FIELDS: [&str; 5] = ["sku", "quantity", "customer", "note", "giftWrap"];
const CATALOG: [(&str, i64); 3] = [
    ("LAB-KB-01", 4_999),
    ("LAB-MS-02", 2_999),
    ("LAB-HUB-03", 8_999),
];

pub struct LabServer {
    shared: Arc<Shared>,
    running: AsyncMutex<Option<RunningLab>>,
}

struct RunningLab {
    listener: SocketAddr,
    shutdown: oneshot::Sender<()>,
    task: JoinHandle<()>,
}

struct Shared {
    hub: Arc<TelemetryHub>,
    hardened: AtomicBool,
    ledger: Mutex<Ledger>,
    redeem_depth: AtomicU32,
    requests: AtomicU64,
    next_order: AtomicU64,
}

#[derive(Default)]
struct Ledger {
    /// The coupon row's use count. A lost update under the race keeps it at the limit while
    /// `granted` keeps climbing, which is the over-redemption the burst exposes.
    redeemed: u32,
    granted: u32,
    orders: u32,
    created: VecDeque<StoredOrder>,
    /// Hardened checkout responses by `Idempotency-Key`, oldest evicted first.
    replays: ReplayLog,
}

impl Ledger {
    fn confirm(&mut self, order: StoredOrder) {
        self.orders += 1;
        if self.created.len() == ORDER_RETENTION {
            self.created.pop_front();
        }
        self.created.push_back(order);
    }
}

#[derive(Default)]
struct ReplayLog {
    by_key: HashMap<String, Replay>,
    order: VecDeque<String>,
}

struct Replay {
    /// SipHash of the request body the key was first used with.
    fingerprint: u64,
    body: String,
}

impl ReplayLog {
    fn record(&mut self, key: &str, fingerprint: u64, body: String) {
        if self.order.len() == ORDER_RETENTION {
            if let Some(oldest) = self.order.pop_front() {
                self.by_key.remove(&oldest);
            }
        }
        self.order.push_back(key.to_owned());
        self.by_key
            .insert(key.to_owned(), Replay { fingerprint, body });
    }
}

#[derive(Debug, Clone, PartialEq)]
struct StoredOrder {
    id: u64,
    sku: String,
    quantity: i64,
    total_cents: i64,
}

impl StoredOrder {
    /// The documented `Order` schema. Unprotected serializes the total through a decimal
    /// formatter that yields a string, the drift a client parsing `totalCents` as an integer
    /// trips over.
    fn to_json(&self, mode: LabMode) -> Value {
        let total = match mode {
            LabMode::Unprotected => Value::String(self.total_cents.to_string()),
            LabMode::Hardened => Value::from(self.total_cents),
        };
        json!({
            "id": self.id,
            "orderId": format!("ord-{:06}", self.id),
            "status": "confirmed",
            "sku": self.sku,
            "quantity": self.quantity,
            "totalCents": total,
        })
    }
}

impl Shared {
    fn mode(&self) -> LabMode {
        if self.hardened.load(Ordering::SeqCst) {
            LabMode::Hardened
        } else {
            LabMode::Unprotected
        }
    }

    fn ledger(&self) -> MutexGuard<'_, Ledger> {
        self.ledger.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn counters(&self) -> LabCounters {
        let ledger = self.ledger();
        LabCounters {
            redeemed: ledger.redeemed,
            granted: ledger.granted,
            orders: ledger.orders,
            requests: self.requests.load(Ordering::SeqCst),
        }
    }

    fn reset(&self) {
        *self.ledger() = Ledger::default();
        self.requests.store(0, Ordering::SeqCst);
    }

    fn find_order(&self, id: u64) -> Option<StoredOrder> {
        if let Some((_, sku, quantity)) = ORDER_HISTORY.iter().find(|(known, ..)| *known == id) {
            return Some(StoredOrder {
                id,
                sku: (*sku).to_owned(),
                quantity: *quantity,
                total_cents: price(sku).unwrap_or(0) * quantity,
            });
        }
        self.ledger()
            .created
            .iter()
            .find(|order| order.id == id)
            .cloned()
    }
}

impl LabServer {
    pub fn new(hub: Arc<TelemetryHub>) -> Self {
        Self {
            shared: Arc::new(Shared {
                hub,
                hardened: AtomicBool::new(false),
                ledger: Mutex::new(Ledger::default()),
                redeem_depth: AtomicU32::new(0),
                requests: AtomicU64::new(0),
                next_order: AtomicU64::new(ORDER_HISTORY.len() as u64 + 1),
            }),
            running: AsyncMutex::new(None),
        }
    }

    pub async fn start(&self, config: LabConfig) -> EngineResult<LabStatus> {
        let mut running = self.running.lock().await;
        if let Some(active) = running.as_ref() {
            return Err(EngineError::LabAlreadyRunning {
                listener: active.listener.to_string(),
            });
        }
        // An explicit port is honoured exactly; the default falls back to an ephemeral one so
        // a stale process holding 17480 does not block the lab.
        let candidates = match config.port {
            Some(port) => vec![port],
            None => vec![DEFAULT_PORT, 0],
        };
        let mut bound = None;
        let mut failure = None;
        for port in candidates {
            let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
            guard::validate_socket_addr(&addr)?;
            match TcpListener::bind(addr).await {
                Ok(listener) => {
                    bound = Some(listener);
                    break;
                }
                Err(err) => failure = Some((addr, err)),
            }
        }
        let listener = match (bound, failure) {
            (Some(listener), _) => listener,
            (None, Some((addr, err))) => {
                return Err(EngineError::ListenerBind {
                    addr: addr.to_string(),
                    reason: err.to_string(),
                })
            }
            (None, None) => {
                return Err(EngineError::InternalTask {
                    reason: "no lab port candidate".to_owned(),
                })
            }
        };
        let local = listener
            .local_addr()
            .map_err(|err| EngineError::ListenerBind {
                addr: format!("127.0.0.1:{}", config.port.unwrap_or(DEFAULT_PORT)),
                reason: err.to_string(),
            })?;

        self.shared
            .hardened
            .store(config.mode == LabMode::Hardened, Ordering::SeqCst);
        self.shared.reset();
        let (shutdown, signal) = oneshot::channel();
        let app = router(Arc::clone(&self.shared), base_url(local));
        let task = tokio::spawn(async move {
            let serve = axum::serve(listener, app).with_graceful_shutdown(async {
                // A dropped sender also means stop.
                let _ = signal.await;
            });
            if let Err(err) = serve.await {
                tracing::warn!(error = %err, "lab listener terminated");
            }
        });
        tracing::info!(listener = %local, mode = ?config.mode, "target lab started");
        *running = Some(RunningLab {
            listener: local,
            shutdown,
            task,
        });
        Ok(self.publish(running.as_ref()))
    }

    /// Idempotent; in-flight requests get the grace period, then the task is aborted.
    pub async fn stop(&self) -> LabStatus {
        let mut running = self.running.lock().await;
        if let Some(active) = running.take() {
            // Fails only when the server already exited, which is the desired end state.
            let _ = active.shutdown.send(());
            let abort = active.task.abort_handle();
            if tokio::time::timeout(SHUTDOWN_GRACE, active.task)
                .await
                .is_err()
            {
                abort.abort();
                tracing::warn!(listener = %active.listener, "target lab aborted after grace period");
            }
            tracing::info!(listener = %active.listener, "target lab stopped");
        }
        self.publish(running.as_ref())
    }

    /// Switching mode clears the ledger so each mode is observed from the same clean state.
    pub async fn set_mode(&self, mode: LabMode) -> LabStatus {
        let running = self.running.lock().await;
        self.shared
            .hardened
            .store(mode == LabMode::Hardened, Ordering::SeqCst);
        self.shared.reset();
        self.publish(running.as_ref())
    }

    pub async fn reset(&self) -> LabStatus {
        let running = self.running.lock().await;
        self.shared.reset();
        self.publish(running.as_ref())
    }

    pub async fn status(&self) -> LabStatus {
        let running = self.running.lock().await;
        self.snapshot(running.as_ref())
    }

    fn snapshot(&self, running: Option<&RunningLab>) -> LabStatus {
        LabStatus {
            running: running.is_some(),
            listener: running.map(|lab| lab.listener.to_string()),
            base_url: running.map(|lab| base_url(lab.listener)),
            mode: self.shared.mode(),
            coupon_code: COUPON_CODE,
            coupon_limit: COUPON_LIMIT,
            counters: self.shared.counters(),
        }
    }

    fn publish(&self, running: Option<&RunningLab>) -> LabStatus {
        let status = self.snapshot(running);
        let hub = &self.shared.hub;
        hub.publish(TelemetryEvent::LabStateChanged {
            seq: hub.next_seq(),
            ts_us: now_us(),
            status: status.clone(),
        });
        status
    }
}

fn base_url(addr: SocketAddr) -> String {
    format!("http://{addr}")
}

// ---- HTTP surface ---------------------------------------------------------------------

/// What a handler did, attached to its response for the telemetry layer.
#[derive(Clone)]
struct Outcome(String);

fn router(shared: Arc<Shared>, base_url: String) -> Router {
    let document = Arc::new(openapi_document(Some(&base_url)));
    Router::new()
        .route("/", get(index))
        .route("/api/v1/health", get(health))
        .route("/api/v1/coupons/redeem", post(redeem))
        .route("/api/v1/orders/checkout", post(checkout))
        .route("/api/v1/orders/{order_id}", get(order_lookup))
        // An empty identifier leaves a trailing slash; routed explicitly so the handler, not
        // the 404 fallback, decides how the empty parameter is treated.
        .route("/api/v1/orders/", get(empty_order_lookup))
        .route(
            SPEC_PATH,
            get(move || {
                let document = Arc::clone(&document);
                async move {
                    reply(
                        StatusCode::OK,
                        "application/json",
                        document.to_string(),
                        "spec served",
                    )
                }
            }),
        )
        .fallback(not_found)
        .layer(middleware::from_fn_with_state(Arc::clone(&shared), observe))
        .with_state(shared)
}

async fn observe(State(shared): State<Arc<Shared>>, request: Request, next: Next) -> Response {
    let started = Instant::now();
    let method = request.method().to_string();
    let path = request.uri().path().to_owned();
    let mut response = next.run(request).await;
    if shared.mode() == LabMode::Unprotected {
        // `cors({ origin: "*", credentials: true })`: the pair browsers refuse, which the
        // passive audit reports on every proxied response.
        let headers = response.headers_mut();
        headers.insert(
            header::ACCESS_CONTROL_ALLOW_ORIGIN,
            HeaderValue::from_static("*"),
        );
        headers.insert(
            header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
            HeaderValue::from_static("true"),
        );
    }
    shared.requests.fetch_add(1, Ordering::SeqCst);
    let outcome = response
        .extensions()
        .get::<Outcome>()
        .map_or_else(String::new, |outcome| outcome.0.clone());
    let hub = &shared.hub;
    hub.publish(TelemetryEvent::LabExchange {
        seq: hub.next_seq(),
        id: Uuid::new_v4(),
        ts_us: now_us(),
        method,
        path,
        status: response.status().as_u16(),
        latency_us: net::elapsed_us(started),
        mode: shared.mode(),
        outcome,
        counters: shared.counters(),
    });
    response
}

fn reply(status: StatusCode, content_type: &'static str, body: String, outcome: &str) -> Response {
    let mut response = (status, body).into_response();
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    response
        .extensions_mut()
        .insert(Outcome(outcome.to_owned()));
    response
}

fn json_reply(status: StatusCode, body: &Value, outcome: &str) -> Response {
    reply(status, "application/json", body.to_string(), outcome)
}

async fn index(State(shared): State<Arc<Shared>>) -> Response {
    json_reply(
        StatusCode::OK,
        &json!({
            "service": "z-proxy-target-lab",
            "mode": shared.mode(),
            "spec": SPEC_PATH,
            "endpoints": [
                "GET /api/v1/health",
                "POST /api/v1/coupons/redeem",
                "POST /api/v1/orders/checkout",
                "GET /api/v1/orders/{orderId}"
            ]
        }),
        "index",
    )
}

async fn health(State(shared): State<Arc<Shared>>) -> Response {
    json_reply(
        StatusCode::OK,
        &json!({ "status": "ok", "mode": shared.mode() }),
        "healthy",
    )
}

async fn not_found() -> Response {
    json_reply(
        StatusCode::NOT_FOUND,
        &json!({ "error": "not_found" }),
        "no such route",
    )
}

// ---- coupon redemption ----------------------------------------------------------------

/// In-flight redemption counter; decremented when the handler finishes or is dropped.
struct Depth<'a>(&'a AtomicU32);

impl<'a> Depth<'a> {
    fn enter(counter: &'a AtomicU32) -> (Self, u32) {
        (Self(counter), counter.fetch_add(1, Ordering::SeqCst))
    }
}

impl Drop for Depth<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

async fn redeem(State(shared): State<Arc<Shared>>, body: Bytes) -> Response {
    let hardened = shared.hardened.load(Ordering::SeqCst);
    let code = serde_json::from_slice::<Value>(&body)
        .ok()
        .and_then(|value| value.get("code").and_then(Value::as_str).map(str::to_owned));
    let Some(code) = code else {
        return if hardened {
            json_reply(
                StatusCode::UNPROCESSABLE_ENTITY,
                &validation_failed(&[violation("/code", "required string")]),
                "rejected: no coupon code",
            )
        } else {
            json_reply(
                StatusCode::BAD_REQUEST,
                &json!({ "error": "invalid_request" }),
                "rejected: no coupon code",
            )
        };
    };
    if code != COUPON_CODE {
        return json_reply(
            StatusCode::NOT_FOUND,
            &json!({ "error": "coupon_not_found" }),
            "unknown coupon",
        );
    }

    let (_depth, queued) = Depth::enter(&shared.redeem_depth);
    let lookup = LOOKUP_STEP * queued.min(MAX_LOOKUP_DEPTH);
    if !lookup.is_zero() {
        tokio::time::sleep(lookup).await;
    }

    if hardened {
        // Check and increment under one lock: the equivalent of
        // `UPDATE coupons SET used = used + 1 WHERE code = $1 AND used < max_uses`.
        let granted = {
            let mut ledger = shared.ledger();
            (ledger.redeemed < COUPON_LIMIT).then(|| {
                ledger.redeemed += 1;
                ledger.granted += 1;
                ledger.granted
            })
        };
        let Some(granted) = granted else {
            return exhausted("conflict: conditional update matched no row");
        };
        // The provider call happens after the reservation committed, so it cannot widen a
        // race window.
        tokio::time::sleep(COMMIT_WINDOW).await;
        return redeemed(
            LabMode::Hardened,
            granted,
            "granted: reservation committed before side effect",
        );
    }

    // Read, act, write back the stale snapshot: the textbook TOCTOU with a lost update.
    let used = shared.ledger().redeemed;
    if used >= COUPON_LIMIT {
        return exhausted("conflict: coupon exhausted");
    }
    tokio::time::sleep(COMMIT_WINDOW).await;
    let granted = {
        let mut ledger = shared.ledger();
        ledger.redeemed = used + 1;
        ledger.granted += 1;
        ledger.granted
    };
    let outcome = if granted > COUPON_LIMIT {
        "granted past limit: balance check passed before a concurrent commit"
    } else {
        "granted"
    };
    redeemed(LabMode::Unprotected, granted, outcome)
}

/// The documented `Redemption` schema. Unprotected still emits the field under its
/// pre-rename name, so `discountCents` is missing from the response.
///
/// `remainingUses` is derived from the grant count. Hardened grants at most the limit, so it
/// never drops below 0; every extra winner of the unprotected race takes it one lower,
/// which breaks the documented `minimum: 0` in the response itself.
fn redeemed(mode: LabMode, granted: u32, outcome: &str) -> Response {
    let discount_key = match mode {
        LabMode::Unprotected => "discount",
        LabMode::Hardened => "discountCents",
    };
    let remaining = i64::from(COUPON_LIMIT) - i64::from(granted);
    let mut body = Map::with_capacity(5);
    body.insert("status".to_owned(), json!("redeemed"));
    body.insert("code".to_owned(), json!(COUPON_CODE));
    body.insert(discount_key.to_owned(), json!(DISCOUNT_CENTS));
    body.insert("remainingUses".to_owned(), json!(remaining));
    body.insert(
        "redemptionId".to_owned(),
        json!(format!("rdm-{granted:06}")),
    );
    json_reply(StatusCode::OK, &Value::Object(body), outcome)
}

fn exhausted(outcome: &str) -> Response {
    json_reply(
        StatusCode::CONFLICT,
        &json!({ "error": "coupon_exhausted", "code": COUPON_CODE }),
        outcome,
    )
}

// ---- checkout -------------------------------------------------------------------------

#[derive(Debug, PartialEq)]
enum Checkout {
    Created {
        sku: String,
        quantity: i64,
        total_cents: i64,
    },
    /// Hardened: 422 with every violation found.
    Invalid(Vec<Value>),
    /// Hardened: 422 for a body that is not JSON.
    Malformed(String),
    /// Unprotected: a well-formed but unknown SKU.
    UnknownSku,
    /// Unprotected: the input reached code that failed, and the failure was serialized into
    /// the response.
    Leak(Leak),
}

#[derive(Debug, PartialEq)]
struct Leak {
    status: StatusCode,
    content_type: &'static str,
    body: String,
    outcome: &'static str,
}

/// Unprotected ignores `Idempotency-Key`: a retried or duplicated checkout creates another
/// order every time. Hardened stores the response per key and replays it.
async fn checkout(State(shared): State<Arc<Shared>>, headers: HeaderMap, body: Bytes) -> Response {
    let mode = shared.mode();
    if mode == LabMode::Hardened {
        if let Some(key) = headers.get(IDEMPOTENCY_HEADER) {
            return idempotent_checkout(&shared, key, &body);
        }
    }
    match evaluate_checkout(mode, &body) {
        Checkout::Created {
            sku,
            quantity,
            total_cents,
        } => {
            let order = StoredOrder {
                id: shared.next_order.fetch_add(1, Ordering::SeqCst),
                sku,
                quantity,
                total_cents,
            };
            let body = order.to_json(mode);
            shared.ledger().confirm(order);
            json_reply(StatusCode::CREATED, &body, "order confirmed")
        }
        rejected => checkout_rejection(rejected),
    }
}

/// Claim, create and record under one ledger lock: the equivalent of inserting the key with
/// a unique constraint in the order's transaction, so concurrent duplicates replay the
/// stored response instead of racing to create their own order.
fn idempotent_checkout(shared: &Shared, key: &HeaderValue, body: &[u8]) -> Response {
    let Some(key) = key
        .to_str()
        .ok()
        .filter(|key| (1..=IDEMPOTENCY_KEY_MAX).contains(&key.len()))
        .filter(|key| key.bytes().all(|b| b.is_ascii_graphic()))
    else {
        return json_reply(
            StatusCode::UNPROCESSABLE_ENTITY,
            &json!({
                "error": "invalid_idempotency_key",
                "reason": format!("1 to {IDEMPOTENCY_KEY_MAX} visible ASCII characters"),
            }),
            "rejected: invalid idempotency key",
        );
    };
    let mut hasher = DefaultHasher::new();
    hasher.write(body);
    let fingerprint = hasher.finish();

    let mut ledger = shared.ledger();
    if let Some(stored) = ledger.replays.by_key.get(key) {
        if stored.fingerprint != fingerprint {
            return json_reply(
                StatusCode::UNPROCESSABLE_ENTITY,
                &json!({ "error": "idempotency_key_reused", "detail": "the key was first used with a different payload" }),
                "rejected: idempotency key reused with another payload",
            );
        }
        let mut response = reply(
            StatusCode::CREATED,
            "application/json",
            stored.body.clone(),
            "replayed: idempotency key seen",
        );
        response.headers_mut().insert(
            HeaderName::from_static(REPLAYED_HEADER),
            HeaderValue::from_static("true"),
        );
        return response;
    }
    match evaluate_checkout(LabMode::Hardened, body) {
        Checkout::Created {
            sku,
            quantity,
            total_cents,
        } => {
            let order = StoredOrder {
                id: shared.next_order.fetch_add(1, Ordering::SeqCst),
                sku,
                quantity,
                total_cents,
            };
            let text = order.to_json(LabMode::Hardened).to_string();
            ledger.confirm(order);
            ledger.replays.record(key, fingerprint, text.clone());
            drop(ledger);
            reply(
                StatusCode::CREATED,
                "application/json",
                text,
                "order confirmed",
            )
        }
        // Only completed orders are stored: a corrected retry under the same key proceeds.
        rejected => {
            drop(ledger);
            checkout_rejection(rejected)
        }
    }
}

fn checkout_rejection(outcome: Checkout) -> Response {
    match outcome {
        Checkout::Created { .. } => json_reply(
            StatusCode::INTERNAL_SERVER_ERROR,
            &json!({ "error": "unexpected_outcome" }),
            "crash: created order routed as a rejection",
        ),
        Checkout::Invalid(violations) => json_reply(
            StatusCode::UNPROCESSABLE_ENTITY,
            &validation_failed(&violations),
            "rejected: validation failed",
        ),
        Checkout::Malformed(detail) => json_reply(
            StatusCode::UNPROCESSABLE_ENTITY,
            &json!({ "error": "malformed_json", "detail": detail }),
            "rejected: malformed json",
        ),
        Checkout::UnknownSku => json_reply(
            StatusCode::NOT_FOUND,
            &json!({ "error": "unknown_sku" }),
            "rejected: unknown sku",
        ),
        Checkout::Leak(leak) => reply(leak.status, leak.content_type, leak.body, leak.outcome),
    }
}

fn evaluate_checkout(mode: LabMode, body: &[u8]) -> Checkout {
    match mode {
        LabMode::Unprotected => unprotected_checkout(body),
        LabMode::Hardened => hardened_checkout(body),
    }
}

fn price(sku: &str) -> Option<i64> {
    CATALOG
        .iter()
        .find(|(known, _)| *known == sku)
        .map(|(_, cents)| *cents)
}

/// Reads fields the way a JavaScript gateway would, with no validation: a missing field is
/// `undefined`, a wrong type reaches a method call or a string-built query. Each failure
/// class surfaces through a different service of the simulated stack so every disclosure
/// signature the fuzzer knows has a reproducible trigger.
fn unprotected_checkout(body: &[u8]) -> Checkout {
    // `Value` keeps the last of duplicated keys, the same as `JSON.parse`, so a duplicate
    // reaches the handlers below with whatever value came last.
    let value = match serde_json::from_slice::<Value>(body) {
        Ok(value) => value,
        Err(err) => return unprotected_parse_failure(&err),
    };
    let sku = match value.get("sku") {
        None => return node_null("undefined", "trim", "normalizeSku", 42),
        Some(Value::Null) => return node_null("null", "trim", "normalizeSku", 42),
        Some(Value::String(sku)) => sku.as_str(),
        Some(other) => return mysql_syntax(&js_string(other)),
    };
    if sku.chars().count() > SKU_MAX {
        return python_truncation("sku", SKU_MAX);
    }
    if let Some(quote) = sku.find('\'') {
        return mysql_syntax(&sku[quote..]);
    }
    let quantity = match value.get("quantity") {
        None => return node_null("undefined", "toFixed", "computeTotal", 57),
        Some(Value::Null) => return node_null("null", "toFixed", "computeTotal", 57),
        Some(Value::Number(number)) => {
            let quantity = number.as_f64().unwrap_or(f64::MAX);
            if quantity < 0.0 {
                return go_reserve_panic(&number.to_string());
            }
            if quantity > QUANTITY_MAX as f64 {
                return rust_tier_panic(&number.to_string());
            }
            quantity
        }
        Some(Value::String(text)) => return postgres_invalid_input(text),
        Some(_) => return node_not_a_function("quantity.toFixed", "computeTotal", 57),
    };
    match value.get("customer") {
        None => return node_null("undefined", "email", "normalizeCustomer", 64),
        Some(Value::Null) => return node_null("null", "email", "normalizeCustomer", 64),
        Some(Value::Object(customer)) => {
            match customer.get("email") {
                None => return node_null("undefined", "toLowerCase", "normalizeCustomer", 65),
                Some(Value::Null) => {
                    return node_null("null", "toLowerCase", "normalizeCustomer", 65)
                }
                Some(Value::String(email)) if email.chars().count() > EMAIL_MAX => {
                    return python_truncation("customer_email", EMAIL_MAX)
                }
                Some(Value::String(_)) => {}
                Some(_) => {
                    return node_not_a_function(
                        "customer.email.toLowerCase",
                        "normalizeCustomer",
                        65,
                    )
                }
            }
            match customer.get("name") {
                None => return node_null("undefined", "trim", "normalizeCustomer", 66),
                Some(Value::Null) => return node_null("null", "trim", "normalizeCustomer", 66),
                Some(Value::String(name)) if name.chars().count() > NAME_MAX => {
                    return python_truncation("customer_name", NAME_MAX)
                }
                Some(Value::String(_)) => {}
                Some(_) => {
                    return node_not_a_function("customer.name.trim", "normalizeCustomer", 66)
                }
            }
        }
        // `"text".email` is `undefined` in JavaScript, so the crash is one property later.
        Some(_) => return node_null("undefined", "toLowerCase", "normalizeCustomer", 65),
    }
    match value.get("note") {
        None => {}
        Some(Value::Null) => return node_null("null", "slice", "formatNote", 79),
        Some(Value::String(note)) if note.chars().count() > NOTE_MAX => {
            return python_truncation("note", NOTE_MAX)
        }
        Some(Value::String(_)) => {}
        Some(_) => return node_not_a_function("note.slice", "formatNote", 79),
    }
    let Some(unit_cents) = price(sku) else {
        return if sku.is_empty() {
            node_null("undefined", "priceCents", "priceLine", 71)
        } else {
            Checkout::UnknownSku
        };
    };
    // Fractional quantities are priced as given: a validation gap, not a crash.
    let total = unit_cents as f64 * quantity;
    Checkout::Created {
        sku: sku.to_owned(),
        quantity: quantity as i64,
        total_cents: total as i64,
    }
}

fn hardened_checkout(body: &[u8]) -> Checkout {
    if body.len() > HARDENED_MAX_BODY {
        return Checkout::Invalid(vec![violation(
            "",
            &format!("payload exceeds {HARDENED_MAX_BODY} bytes"),
        )]);
    }
    // Out-of-range numbers (`1e309`) and nesting beyond serde_json's recursion limit fail
    // here and are answered as malformed, never coerced.
    let value = match serde_json::from_slice::<Value>(body) {
        Ok(value) => value,
        Err(err) => return Checkout::Malformed(err.to_string()),
    };
    let depth = json_depth(&value);
    if depth > HARDENED_MAX_DEPTH {
        return Checkout::Invalid(vec![violation(
            "",
            &format!("nesting depth {depth} exceeds {HARDENED_MAX_DEPTH}"),
        )]);
    }
    match duplicate_key(body) {
        Ok(Some(pointer)) => return Checkout::Invalid(vec![violation(&pointer, "duplicate key")]),
        Ok(None) => {}
        Err(err) => return Checkout::Malformed(err.to_string()),
    }
    let Some(object) = value.as_object() else {
        return Checkout::Invalid(vec![violation("", "must be a JSON object")]);
    };
    let mut violations = unknown_fields(object, &CHECKOUT_FIELDS, "");

    let sku = match object.get("sku") {
        Some(Value::String(sku)) if valid_sku(sku) => match price(sku) {
            Some(_) => Some(sku.as_str()),
            None => {
                violations.push(violation("/sku", "unknown product"));
                None
            }
        },
        Some(Value::String(_)) => {
            violations.push(violation("/sku", "must match ^[A-Z0-9-]{1,32}$"));
            None
        }
        _ => {
            violations.push(violation("/sku", "required string"));
            None
        }
    };
    let quantity = match object.get("quantity").and_then(Value::as_i64) {
        Some(quantity) if (1..=QUANTITY_MAX).contains(&quantity) => Some(quantity),
        _ => {
            violations.push(violation(
                "/quantity",
                &format!("required integer between 1 and {QUANTITY_MAX}"),
            ));
            None
        }
    };
    match object.get("customer") {
        Some(Value::Object(customer)) => {
            violations.extend(unknown_fields(customer, &["email", "name"], "/customer"));
            let email_ok = customer
                .get("email")
                .and_then(Value::as_str)
                .is_some_and(|email| {
                    (3..=EMAIL_MAX).contains(&email.chars().count())
                        && email.matches('@').count() == 1
                        && !email.starts_with('@')
                        && !email.ends_with('@')
                });
            if !email_ok {
                violations.push(violation(
                    "/customer/email",
                    &format!("required address of at most {EMAIL_MAX} characters"),
                ));
            }
            let name_ok = customer
                .get("name")
                .and_then(Value::as_str)
                .is_some_and(|name| !name.trim().is_empty() && name.chars().count() <= NAME_MAX);
            if !name_ok {
                violations.push(violation(
                    "/customer/name",
                    &format!("required non-blank string of at most {NAME_MAX} characters"),
                ));
            }
        }
        _ => violations.push(violation("/customer", "required object")),
    }
    match object.get("note") {
        None | Some(Value::Null) => {}
        Some(Value::String(note)) if note.chars().count() <= NOTE_MAX => {}
        Some(_) => violations.push(violation(
            "/note",
            &format!("optional string of at most {NOTE_MAX} characters"),
        )),
    }
    if !matches!(
        object.get("giftWrap"),
        None | Some(Value::Null) | Some(Value::Bool(_))
    ) {
        violations.push(violation("/giftWrap", "optional boolean"));
    }

    match (sku, quantity) {
        (Some(sku), Some(quantity)) if violations.is_empty() => Checkout::Created {
            sku: sku.to_owned(),
            quantity,
            total_cents: price(sku).unwrap_or(0) * quantity,
        },
        _ => Checkout::Invalid(violations),
    }
}

fn valid_sku(sku: &str) -> bool {
    (1..=32).contains(&sku.len())
        && sku
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'-')
}

fn unknown_fields(object: &Map<String, Value>, known: &[&str], prefix: &str) -> Vec<Value> {
    object
        .keys()
        .filter(|key| !known.contains(&key.as_str()))
        .map(|key| {
            let escaped = key.replace('~', "~0").replace('/', "~1");
            violation(&format!("{prefix}/{escaped}"), "unknown field")
        })
        .collect()
}

fn violation(pointer: &str, reason: &str) -> Value {
    json!({ "pointer": pointer, "reason": reason })
}

fn validation_failed(violations: &[Value]) -> Value {
    json!({ "error": "validation_failed", "violations": violations })
}

/// `String(value)` as JavaScript renders it inside a template literal.
fn js_string(value: &Value) -> String {
    match value {
        Value::Null => "null".to_owned(),
        Value::Bool(flag) => flag.to_string(),
        Value::Number(number) => number.to_string(),
        Value::String(text) => text.clone(),
        Value::Array(items) => items.iter().map(js_string).collect::<Vec<_>>().join(","),
        Value::Object(_) => "[object Object]".to_owned(),
    }
}

/// Levels of nested arrays and objects; a scalar root is 0. Bounded by serde_json's
/// recursion limit, since only parsed values reach it.
fn json_depth(value: &Value) -> usize {
    match value {
        Value::Array(items) => 1 + items.iter().map(json_depth).max().unwrap_or(0),
        Value::Object(fields) => 1 + fields.values().map(json_depth).max().unwrap_or(0),
        _ => 0,
    }
}

/// RFC 6901 pointer of the first object key that occurs twice in one object.
///
/// `serde_json::Value` silently keeps the last occurrence, as most parsers do. A validator
/// that reads the first occurrence and a handler that reads the last then disagree about the
/// same document, so a strict contract refuses duplicates instead of picking one.
fn duplicate_key(body: &[u8]) -> Result<Option<String>, serde_json::Error> {
    let mut deserializer = serde_json::Deserializer::from_slice(body);
    let found = DuplicateProbe(String::new()).deserialize(&mut deserializer)?;
    deserializer.end()?;
    Ok(found)
}

/// Seed carrying the pointer of the value it visits.
struct DuplicateProbe(String);

impl<'de> DeserializeSeed<'de> for DuplicateProbe {
    type Value = Option<String>;

    fn deserialize<D: serde::Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for DuplicateProbe {
    type Value = Option<String>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("any JSON value")
    }

    fn visit_bool<E>(self, _: bool) -> Result<Self::Value, E> {
        Ok(None)
    }

    fn visit_i64<E>(self, _: i64) -> Result<Self::Value, E> {
        Ok(None)
    }

    fn visit_u64<E>(self, _: u64) -> Result<Self::Value, E> {
        Ok(None)
    }

    fn visit_f64<E>(self, _: f64) -> Result<Self::Value, E> {
        Ok(None)
    }

    fn visit_str<E>(self, _: &str) -> Result<Self::Value, E> {
        Ok(None)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(None)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let mut found = None;
        let mut index = 0usize;
        while let Some(child) =
            seq.next_element_seed(DuplicateProbe(format!("{}/{index}", self.0)))?
        {
            found = found.or(child);
            index += 1;
        }
        Ok(found)
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut found = None;
        let mut seen = HashSet::new();
        while let Some(key) = map.next_key::<String>()? {
            let pointer = format!("{}/{}", self.0, key.replace('~', "~0").replace('/', "~1"));
            let child = map.next_value_seed(DuplicateProbe(pointer.clone()))?;
            if !seen.insert(key) {
                found = found.or(Some(pointer));
            }
            found = found.or(child);
        }
        Ok(found)
    }
}

// ---- order lookup ---------------------------------------------------------------------

#[derive(Debug, PartialEq)]
enum Lookup {
    Found(StoredOrder),
    NotFound,
    /// Hardened: 422 for an identifier outside the documented contract.
    Invalid,
    Leak(Leak),
}

async fn order_lookup(State(shared): State<Arc<Shared>>, Path(order_id): Path<String>) -> Response {
    lookup_response(&shared, &order_id)
}

async fn empty_order_lookup(State(shared): State<Arc<Shared>>) -> Response {
    lookup_response(&shared, "")
}

fn lookup_response(shared: &Shared, order_id: &str) -> Response {
    let mode = shared.mode();
    match evaluate_lookup(mode, order_id, |id| shared.find_order(id)) {
        Lookup::Found(order) => json_reply(StatusCode::OK, &order.to_json(mode), "order found"),
        Lookup::NotFound => json_reply(
            StatusCode::NOT_FOUND,
            &json!({ "error": "order_not_found" }),
            "no such order",
        ),
        Lookup::Invalid => json_reply(
            StatusCode::UNPROCESSABLE_ENTITY,
            &json!({
                "error": "invalid_path_parameter",
                "parameter": "orderId",
                "reason": format!("integer between 1 and {ORDER_ID_MAX}"),
            }),
            "rejected: invalid order id",
        ),
        Lookup::Leak(leak) => reply(leak.status, leak.content_type, leak.body, leak.outcome),
    }
}

fn evaluate_lookup(mode: LabMode, raw: &str, find: impl Fn(u64) -> Option<StoredOrder>) -> Lookup {
    match mode {
        LabMode::Unprotected => unprotected_lookup(raw, find),
        LabMode::Hardened => hardened_lookup(raw, find),
    }
}

/// `Number(req.params.orderId)` and an array index, as an unvalidated gateway would: an
/// empty segment is 0, text is `NaN`, digits beyond `f64` range are `Infinity`, and the raw
/// segment is what the database driver finally receives.
fn unprotected_lookup(raw: &str, find: impl Fn(u64) -> Option<StoredOrder>) -> Lookup {
    let trimmed = raw.trim();
    let number = if trimmed.is_empty() {
        0.0
    } else {
        trimmed.parse::<f64>().unwrap_or(f64::NAN)
    };
    if number.is_nan() {
        return Lookup::Leak(postgres_lookup_input(raw));
    }
    if number.is_infinite() {
        return Lookup::Leak(python_numeric_overflow(raw));
    }
    if number >= 9_223_372_036_854_775_807.0 {
        return Lookup::Leak(postgres_out_of_range(raw));
    }
    if number < 1.0 || number.fract() != 0.0 {
        return Lookup::Leak(node_lookup_undefined());
    }
    // `number` is a positive integer below 2^63 here, so the conversion is exact up to 2^53
    // and saturates above it, where no stored order exists anyway.
    match find(number as u64) {
        Some(order) => Lookup::Found(order),
        None => Lookup::NotFound,
    }
}

fn hardened_lookup(raw: &str, find: impl Fn(u64) -> Option<StoredOrder>) -> Lookup {
    let canonical = (1..=6).contains(&raw.len())
        && !raw.starts_with('0')
        && raw.bytes().all(|b| b.is_ascii_digit());
    let id = if canonical {
        raw.parse::<u64>().ok()
    } else {
        None
    };
    match id.filter(|id| (1..=ORDER_ID_MAX).contains(id)) {
        Some(id) => find(id).map_or(Lookup::NotFound, Lookup::Found),
        None => Lookup::Invalid,
    }
}

// ---- leaked failure bodies --------------------------------------------------------------
// Shapes follow what each runtime prints by default, so the fuzzer's disclosure signatures
// are exercised by realistic text rather than by strings written to match them.

fn leak(
    status: StatusCode,
    content_type: &'static str,
    body: String,
    outcome: &'static str,
) -> Checkout {
    Checkout::Leak(Leak {
        status,
        content_type,
        body,
        outcome,
    })
}

fn node_frames(function: &str, line: u32) -> String {
    format!(
        "    at {function} (/srv/lab/gateway/src/orders/checkout.js:{line}:17)\n    at createCheckout (/srv/lab/gateway/src/orders/checkout.js:112:21)\n    at Layer.handle [as handle_request] (/srv/lab/gateway/node_modules/express/lib/router/layer.js:95:5)\n    at next (/srv/lab/gateway/node_modules/express/lib/router/route.js:149:13)"
    )
}

fn node_null(kind: &str, property: &str, function: &str, line: u32) -> Checkout {
    leak(
        StatusCode::INTERNAL_SERVER_ERROR,
        "text/plain; charset=utf-8",
        format!(
            "TypeError: Cannot read properties of {kind} (reading '{property}')\n{}",
            node_frames(function, line)
        ),
        "crash: node TypeError",
    )
}

fn node_not_a_function(call: &str, function: &str, line: u32) -> Checkout {
    leak(
        StatusCode::INTERNAL_SERVER_ERROR,
        "text/plain; charset=utf-8",
        format!(
            "TypeError: {call} is not a function\n{}",
            node_frames(function, line)
        ),
        "crash: node TypeError",
    )
}

fn body_parser_trace(err: &serde_json::Error) -> Leak {
    Leak {
        status: StatusCode::BAD_REQUEST,
        content_type: "text/plain; charset=utf-8",
        body: format!(
            "SyntaxError: Unexpected token in JSON at line {} column {}\n    at JSON.parse (<anonymous>)\n    at parse (/srv/lab/gateway/node_modules/body-parser/lib/types/json.js:92:19)\n    at /srv/lab/gateway/node_modules/body-parser/lib/read.js:128:18",
            err.line(),
            err.column()
        ),
        outcome: "rejected with parser stack trace",
    }
}

fn python_truncation(column: &str, limit: usize) -> Checkout {
    leak(
        StatusCode::INTERNAL_SERVER_ERROR,
        "text/plain; charset=utf-8",
        format!(
            "Traceback (most recent call last):\n  File \"/srv/lab/inventory/app/orders.py\", line 57, in reserve_line\n    cursor.execute(INSERT_LINE, params)\n  File \"/srv/lab/inventory/.venv/lib/python3.12/site-packages/psycopg2/extras.py\", line 146, in execute\n    return super().execute(query, vars)\npsycopg2.errors.StringDataRightTruncation: value too long for type character varying({limit})\nCONTEXT:  column \"{column}\""
        ),
        "crash: python traceback",
    )
}

fn rust_tier_panic(quantity: &str) -> Checkout {
    leak(
        StatusCode::INTERNAL_SERVER_ERROR,
        "text/plain; charset=utf-8",
        format!(
            "thread 'pricing-worker-3' panicked at src/pricing/tiers.rs:88:21:\nindex out of bounds: the len is {QUANTITY_MAX} but the index is {quantity}\nnote: run with `RUST_BACKTRACE=1` environment variable to display a backtrace"
        ),
        "crash: rust panic",
    )
}

fn go_reserve_panic(quantity: &str) -> Checkout {
    leak(
        StatusCode::INTERNAL_SERVER_ERROR,
        "text/plain; charset=utf-8",
        format!(
            "panic: runtime error: makeslice: len out of range\n\ngoroutine 37 [running]:\nmain.reserveStock({{0xc0001a4000, 0x9}}, {quantity})\n\t/srv/lab/stock/reserve.go:58 +0x1d2\nmain.(*Server).handleReserve(0xc000118000, {{0x7f2c40, 0xc0002a0000}}, 0xc0001b6000)\n\t/srv/lab/stock/server.go:121 +0x2b4"
        ),
        "crash: go panic",
    )
}

/// The MySQL driver's error object serialized straight into the response, query included.
fn mysql_syntax(near: &str) -> Checkout {
    let near: String = near.chars().take(80).collect();
    let body = json!({
        "code": "ER_PARSE_ERROR",
        "errno": 1064,
        "sqlState": "42000",
        "sqlMessage": format!("You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '{near}' at line 1"),
        "sql": format!("SELECT price_cents FROM catalog WHERE sku = {near}"),
    });
    leak(
        StatusCode::INTERNAL_SERVER_ERROR,
        "application/json",
        body.to_string(),
        "crash: sql syntax error",
    )
}

fn postgres_invalid_input(text: &str) -> Checkout {
    let shown: String = text.chars().take(80).collect();
    let body = json!({
        "error": "database_error",
        "detail": format!("ERROR:  invalid input syntax for type integer: \"{shown}\""),
        "query": "INSERT INTO order_lines (order_id, sku, quantity) VALUES ($1, $2, $3)",
    });
    leak(
        StatusCode::INTERNAL_SERVER_ERROR,
        "application/json",
        body.to_string(),
        "crash: sql type error",
    )
}

/// Unprotected parse failures, by cause. serde_json reports both refusals below as syntax
/// errors; the message is the only distinguishing field it exposes.
fn unprotected_parse_failure(err: &serde_json::Error) -> Checkout {
    let message = err.to_string();
    if message.starts_with("recursion limit exceeded") {
        return node_recursion_overflow();
    }
    if message.starts_with("number out of range") {
        return rust_decode_panic(&message);
    }
    Checkout::Leak(body_parser_trace(err))
}

/// A recursive input sanitizer walking a deeply nested body until V8's stack runs out.
fn node_recursion_overflow() -> Checkout {
    leak(
        StatusCode::INTERNAL_SERVER_ERROR,
        "text/plain; charset=utf-8",
        "RangeError: Maximum call stack size exceeded\n    at stripKeys (/srv/lab/gateway/src/middleware/sanitize.js:14:23)\n    at stripKeys (/srv/lab/gateway/src/middleware/sanitize.js:18:16)\n    at stripKeys (/srv/lab/gateway/src/middleware/sanitize.js:18:16)\n    at sanitizeBody (/srv/lab/gateway/src/middleware/sanitize.js:31:10)".to_owned(),
        "crash: node stack overflow",
    )
}

/// The pricing service decoding the forwarded body with `unwrap()`.
fn rust_decode_panic(message: &str) -> Checkout {
    leak(
        StatusCode::INTERNAL_SERVER_ERROR,
        "text/plain; charset=utf-8",
        format!(
            "thread 'tokio-runtime-worker' panicked at src/pricing/decode.rs:31:52:\ncalled `Result::unwrap()` on an `Err` value: Error(\"{message}\")\nnote: run with `RUST_BACKTRACE=1` environment variable to display a backtrace"
        ),
        "crash: rust panic",
    )
}

fn node_lookup_undefined() -> Leak {
    Leak {
        status: StatusCode::INTERNAL_SERVER_ERROR,
        content_type: "text/plain; charset=utf-8",
        body: "TypeError: Cannot read properties of undefined (reading 'status')\n    at serializeOrder (/srv/lab/gateway/src/orders/lookup.js:23:31)\n    at loadOrder (/srv/lab/gateway/src/orders/lookup.js:12:10)\n    at Layer.handle [as handle_request] (/srv/lab/gateway/node_modules/express/lib/router/layer.js:95:5)".to_owned(),
        outcome: "crash: node TypeError",
    }
}

fn postgres_lookup_input(raw: &str) -> Leak {
    let shown: String = raw.chars().take(80).collect();
    Leak {
        status: StatusCode::INTERNAL_SERVER_ERROR,
        content_type: "application/json",
        body: json!({
            "error": "database_error",
            "detail": format!("ERROR:  invalid input syntax for type bigint: \"{shown}\""),
            "query": "SELECT * FROM orders WHERE id = $1",
        })
        .to_string(),
        outcome: "crash: sql type error",
    }
}

fn postgres_out_of_range(raw: &str) -> Leak {
    let shown: String = raw.chars().take(80).collect();
    Leak {
        status: StatusCode::INTERNAL_SERVER_ERROR,
        content_type: "application/json",
        body: json!({
            "name": "error",
            "severity": "ERROR",
            "code": "22003",
            "message": format!("value \"{shown}\" is out of range for type bigint"),
            "routine": "pg_strtoint64_safe",
        })
        .to_string(),
        outcome: "crash: sql range error",
    }
}

fn python_numeric_overflow(raw: &str) -> Leak {
    Leak {
        status: StatusCode::INTERNAL_SERVER_ERROR,
        content_type: "text/plain; charset=utf-8",
        body: format!(
            "Traceback (most recent call last):\n  File \"/srv/lab/inventory/app/orders.py\", line 88, in fetch_order\n    cursor.execute(SELECT_ORDER, (order_id,))\npsycopg2.errors.NumericValueOutOfRange: value overflows numeric format\nDETAIL:  input has {} digits",
            raw.len()
        ),
        outcome: "crash: python traceback",
    }
}

// ---- OpenAPI document -----------------------------------------------------------------

/// The lab's own OpenAPI 3.1 description, pretty-printed so route lines are meaningful.
/// Request bodies use `$ref`s, a `readOnly` property and a 3.1 type union so the scanner's
/// body synthesis is exercised end to end; success responses carry `$ref` schemas so the
/// extracted response contracts are too. Hardened mode answers exactly as documented.
pub fn openapi_document(base_url: Option<&str>) -> String {
    let server = base_url.map_or_else(|| format!("http://127.0.0.1:{DEFAULT_PORT}"), str::to_owned);
    let response = |description: &str| json!({ "description": description });
    let body = |description: &str, schema: &str| {
        json!({
            "description": description,
            "content": { "application/json": { "schema": { "$ref": format!("#/components/schemas/{schema}") } } }
        })
    };
    let document = json!({
        "openapi": "3.1.0",
        "info": {
            "title": "z-proxy Target Lab",
            "version": env!("CARGO_PKG_VERSION"),
            "description": "Embedded loopback service with switchable defects: unprotected or hardened."
        },
        "servers": [{ "url": server }],
        "paths": {
            "/api/v1/health": {
                "get": {
                    "summary": "Liveness and active mode",
                    "responses": { "200": body("Service is up", "Health") }
                }
            },
            "/api/v1/coupons/redeem": {
                "post": {
                    "summary": "Redeem the single-use coupon",
                    "requestBody": {
                        "required": true,
                        "content": { "application/json": { "schema": { "$ref": "#/components/schemas/RedeemRequest" } } }
                    },
                    "responses": {
                        "200": body("Coupon redeemed", "Redemption"),
                        "404": body("Unknown coupon", "Error"),
                        "409": body("Coupon already used", "Error"),
                        "422": body("No coupon code", "ValidationError")
                    }
                }
            },
            "/api/v1/orders/checkout": {
                "post": {
                    "summary": "Price and confirm an order",
                    "parameters": [{
                        "name": "Idempotency-Key",
                        "in": "header",
                        "required": false,
                        "description": "Repeated requests with the same key replay the first response",
                        "schema": { "type": "string", "minLength": 1, "maxLength": IDEMPOTENCY_KEY_MAX }
                    }],
                    "requestBody": { "$ref": "#/components/requestBodies/Checkout" },
                    "responses": {
                        "201": body("Order confirmed", "Order"),
                        "422": body("Validation failed", "ValidationError"),
                        "500": response("Unhandled failure")
                    }
                }
            },
            "/api/v1/orders/{orderId}": {
                "get": {
                    "summary": "Look up a confirmed order",
                    "parameters": [{
                        "name": "orderId",
                        "in": "path",
                        "required": true,
                        "schema": { "type": "integer", "minimum": 1, "maximum": ORDER_ID_MAX, "example": 1 }
                    }],
                    "responses": {
                        "200": body("Order", "Order"),
                        "404": body("Unknown order", "Error"),
                        "422": body("Identifier outside the documented range", "Error")
                    }
                }
            },
            SPEC_PATH: {
                "get": {
                    "summary": "This document",
                    "responses": { "200": response("OpenAPI document") }
                }
            }
        },
        "components": {
            "requestBodies": {
                "Checkout": {
                    "required": true,
                    "content": { "application/json": { "schema": { "$ref": "#/components/schemas/CheckoutRequest" } } }
                }
            },
            "schemas": {
                "RedeemRequest": {
                    "type": "object",
                    "required": ["code"],
                    "properties": {
                        "code": { "type": "string", "example": COUPON_CODE },
                        "userId": { "type": "string", "example": "u-1001" }
                    }
                },
                "CheckoutRequest": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["sku", "quantity", "customer"],
                    "properties": {
                        "orderId": { "type": "string", "readOnly": true },
                        "sku": { "type": "string", "pattern": "^[A-Z0-9-]{1,32}$", "example": "LAB-KB-01" },
                        "quantity": { "type": "integer", "minimum": 1, "maximum": QUANTITY_MAX, "example": 2 },
                        "customer": { "$ref": "#/components/schemas/Customer" },
                        "note": { "type": ["string", "null"], "maxLength": NOTE_MAX, "example": "leave at loading dock" },
                        "giftWrap": { "type": "boolean", "example": false }
                    }
                },
                "Customer": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["email", "name"],
                    "properties": {
                        "email": { "type": "string", "format": "email", "maxLength": EMAIL_MAX, "example": "operator@lab.local" },
                        "name": { "type": "string", "minLength": 1, "maxLength": NAME_MAX, "example": "Lab Operator" }
                    }
                },
                "Order": {
                    "type": "object",
                    "required": ["id", "orderId", "status", "sku", "quantity", "totalCents"],
                    "properties": {
                        "id": { "type": "integer", "minimum": 1 },
                        "orderId": { "type": "string", "pattern": "^ord-[0-9]{6,}$" },
                        "status": { "type": "string", "enum": ["confirmed"] },
                        "sku": { "type": "string" },
                        "quantity": { "type": "integer", "minimum": 1 },
                        "totalCents": { "type": "integer", "minimum": 0 }
                    }
                },
                "Redemption": {
                    "type": "object",
                    "required": ["status", "code", "discountCents", "remainingUses", "redemptionId"],
                    "properties": {
                        "status": { "type": "string", "enum": ["redeemed"] },
                        "code": { "type": "string" },
                        "discountCents": { "type": "integer", "minimum": 0 },
                        "remainingUses": { "type": "integer", "format": "int32", "minimum": 0 },
                        "redemptionId": { "type": "string" }
                    }
                },
                "Health": {
                    "type": "object",
                    "required": ["status", "mode"],
                    "properties": {
                        "status": { "type": "string" },
                        "mode": { "type": "string", "enum": ["unprotected", "hardened"] }
                    }
                },
                "Error": {
                    "type": "object",
                    "required": ["error"],
                    "properties": { "error": { "type": "string" } }
                },
                "ValidationError": {
                    "type": "object",
                    "required": ["error"],
                    "properties": {
                        "error": { "type": "string" },
                        "violations": { "type": "array", "items": { "type": "object" } }
                    }
                }
            }
        }
    });
    serde_json::to_string_pretty(&document).unwrap_or_default()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::engine::concurrency;
    use crate::engine::disclosure;
    use crate::engine::fuzzer::{self, FuzzerSlot};
    use crate::engine::proxy::ProxyManager;
    use crate::engine::types::{
        AnomalyKind, BurstMethod, BurstReport, BurstSpec, BurstSyncMode, ContractViolation,
        ContractViolationKind, DisclosureKind, FuzzSpec, FuzzVerdict, HeaderPair, MutationClass,
        ProxyConfig, ResponseContract, RouteContract, RouteMethod, Severity, TrafficFindingKind,
        WorkerSample,
    };
    use crate::scanner::routes;

    const CHECKOUT_SAMPLE: &str = r#"{"sku":"LAB-KB-01","quantity":2,"customer":{"email":"operator@lab.local","name":"Lab Operator"},"note":"leave at loading dock","giftWrap":false}"#;

    /// The checkout sample with one field (`name` or `parent.child`) edited.
    fn edited(field: &str, edit: impl FnOnce(&mut Map<String, Value>, &str)) -> Vec<u8> {
        let mut body: Value = serde_json::from_str(CHECKOUT_SAMPLE).unwrap();
        let root = body.as_object_mut().unwrap();
        match field.split_once('.') {
            Some((parent, child)) => edit(root[parent].as_object_mut().unwrap(), child),
            None => edit(root, field),
        }
        serde_json::to_vec(&body).unwrap()
    }

    fn with(field: &str, value: Value) -> Vec<u8> {
        edited(field, |object, key| {
            object.insert(key.to_owned(), value);
        })
    }

    fn omit(field: &str) -> Vec<u8> {
        edited(field, |object, key| {
            object.shift_remove(key);
        })
    }

    /// The checkout sample plus a `deep` field nested `levels` objects down.
    fn nested(levels: usize) -> Vec<u8> {
        let chain = format!("{}1{}", r#"{"d":"#.repeat(levels), "}".repeat(levels));
        let open = CHECKOUT_SAMPLE.strip_suffix('}').unwrap();
        format!(r#"{open},"deep":{chain}}}"#).into_bytes()
    }

    /// The checkout sample with `"key":value` appended after the original fields.
    fn duplicated(entry: &str) -> Vec<u8> {
        let open = CHECKOUT_SAMPLE.strip_suffix('}').unwrap();
        format!("{open},{entry}}}").into_bytes()
    }

    fn leaked(body: &[u8]) -> (StatusCode, Option<DisclosureKind>) {
        match unprotected_checkout(body) {
            Checkout::Leak(leak) => (leak.status, disclosure::detect(&leak.body).map(|d| d.kind)),
            other => panic!("expected a leak, got {other:?}"),
        }
    }

    #[test]
    fn unprotected_checkout_leaks_one_runtime_per_failure_class() {
        let server_error = StatusCode::INTERNAL_SERVER_ERROR;
        let node = Some(DisclosureKind::NodeStackTrace);
        let cases: Vec<(&str, Vec<u8>, StatusCode, Option<DisclosureKind>)> = vec![
            ("null sku", with("sku", Value::Null), server_error, node),
            ("missing quantity", omit("quantity"), server_error, node),
            (
                "null email",
                with("customer.email", Value::Null),
                server_error,
                node,
            ),
            ("missing name", omit("customer.name"), server_error, node),
            (
                "customer string",
                with("customer", json!("x")),
                server_error,
                node,
            ),
            ("null note", with("note", Value::Null), server_error, node),
            (
                "quantity array",
                with("quantity", json!([])),
                server_error,
                node,
            ),
            ("empty sku", with("sku", json!("")), server_error, node),
            ("array root", b"[1]".to_vec(), server_error, node),
            (
                "oversized sku",
                with("sku", json!("A".repeat(65))),
                server_error,
                Some(DisclosureKind::PythonTraceback),
            ),
            (
                "oversized note",
                with("note", json!("n".repeat(257))),
                server_error,
                Some(DisclosureKind::PythonTraceback),
            ),
            (
                "i64::MAX quantity",
                with("quantity", json!(i64::MAX)),
                server_error,
                Some(DisclosureKind::RustPanic),
            ),
            (
                "10001 quantity",
                with("quantity", json!(10_001)),
                server_error,
                Some(DisclosureKind::RustPanic),
            ),
            (
                "negative quantity",
                with("quantity", json!(-1)),
                server_error,
                Some(DisclosureKind::GoPanic),
            ),
            (
                "object sku",
                with("sku", json!({})),
                server_error,
                Some(DisclosureKind::SqlError),
            ),
            (
                "apostrophe sku",
                with("sku", json!("O'Reilly & Sons")),
                server_error,
                Some(DisclosureKind::SqlError),
            ),
            (
                "NaN quantity",
                with("quantity", json!("NaN")),
                server_error,
                Some(DisclosureKind::SqlError),
            ),
            (
                "truncated body",
                b"{\"sku\":".to_vec(),
                StatusCode::BAD_REQUEST,
                node,
            ),
            ("empty body", Vec::new(), StatusCode::BAD_REQUEST, node),
            ("200-level nesting", nested(200), server_error, node),
            (
                "1e309 quantity",
                CHECKOUT_SAMPLE
                    .replace(r#""quantity":2"#, r#""quantity":1e309"#)
                    .into_bytes(),
                server_error,
                Some(DisclosureKind::RustPanic),
            ),
        ];
        for (label, body, status, kind) in cases {
            assert_eq!(leaked(&body), (status, kind), "{label}");
        }
        let sql = match unprotected_checkout(&with("sku", json!({}))) {
            Checkout::Leak(leak) => leak.body,
            other => panic!("{other:?}"),
        };
        assert!(sql.contains("near '[object Object]'"), "{sql}");
        // The string-built lookup breaks on the apostrophe of an ordinary company name.
        let quoted = match unprotected_checkout(&with("sku", json!("O'Reilly & Sons"))) {
            Checkout::Leak(leak) => leak.body,
            other => panic!("{other:?}"),
        };
        assert!(quoted.contains("near ''Reilly & Sons'"), "{quoted}");
        for harmless in [
            "15\" display \\ rev-2",
            "item; category(1)",
            "100%_discount_*",
            "cafe\u{0301}\u{200B}test",
        ] {
            assert_eq!(
                unprotected_checkout(&with("sku", json!(harmless))),
                Checkout::UnknownSku,
                "{harmless}"
            );
        }
    }

    #[test]
    fn unprotected_checkout_accepts_what_it_cannot_see() {
        assert_eq!(
            unprotected_checkout(CHECKOUT_SAMPLE.as_bytes()),
            Checkout::Created {
                sku: "LAB-KB-01".to_owned(),
                quantity: 2,
                total_cents: 9_998
            }
        );
        for body in [
            with("quantity", json!(0)),
            with("customer.email", json!("")),
            with("giftWrap", json!("yes")),
            omit("note"),
            with("zproxyPad", json!("x".repeat(70_000))),
            duplicated(r#""giftWrap":true"#),
            duplicated(r#""note":"""#),
            nested(64),
        ] {
            assert!(
                matches!(unprotected_checkout(&body), Checkout::Created { .. }),
                "{}",
                String::from_utf8_lossy(&body[..body.len().min(120)])
            );
        }
        assert_eq!(
            unprotected_checkout(&with("sku", json!("NOPE-1"))),
            Checkout::UnknownSku
        );
    }

    #[test]
    fn hardened_checkout_rejects_everything_invalid_with_clean_bodies() {
        assert_eq!(
            hardened_checkout(CHECKOUT_SAMPLE.as_bytes()),
            Checkout::Created {
                sku: "LAB-KB-01".to_owned(),
                quantity: 2,
                total_cents: 9_998
            }
        );
        assert!(matches!(
            hardened_checkout(&with("note", Value::Null)),
            Checkout::Created { .. }
        ));
        assert!(matches!(
            hardened_checkout(&omit("giftWrap")),
            Checkout::Created { .. }
        ));
        // Delimiters are data: a free-text field stores them, the patterned SKU refuses them.
        for name in [
            "O'Reilly & Sons",
            "15\" display \\ rev-2",
            "cafe\u{0301}\u{200B}test",
        ] {
            assert!(
                matches!(
                    hardened_checkout(&with("customer.name", json!(name))),
                    Checkout::Created { .. }
                ),
                "{name}"
            );
        }

        let invalid = [
            with("sku", Value::Null),
            with("sku", json!("O'Reilly & Sons")),
            with("sku", json!("100%_discount_*")),
            with("sku", json!("lab-kb-01")),
            with("sku", json!("NOPE-1")),
            with("quantity", json!(0)),
            with("quantity", json!(2.5)),
            with("quantity", json!(i64::MAX)),
            with("quantity", json!("2")),
            with("customer", json!([])),
            with("customer.email", json!("no-at-sign")),
            with("customer.name", json!("   ")),
            with("customer.role", json!("admin")),
            with("note", json!(1)),
            with("giftWrap", json!("yes")),
            with("zproxyPad", json!("x")),
            with("sku", json!("A".repeat(40_000))),
            b"[]".to_vec(),
            duplicated(r#""giftWrap":true"#),
            duplicated(r#""note":"""#),
            nested(12),
        ];
        for body in &invalid {
            match hardened_checkout(body) {
                Checkout::Invalid(violations) => {
                    assert!(!violations.is_empty());
                    let text = validation_failed(&violations).to_string();
                    assert_eq!(disclosure::detect(&text), None, "{text}");
                }
                other => panic!(
                    "expected 422 for {}, got {other:?}",
                    String::from_utf8_lossy(&body[..body.len().min(120)])
                ),
            }
        }
        let overflow = CHECKOUT_SAMPLE
            .replace(r#""quantity":2"#, r#""quantity":1e309"#)
            .into_bytes();
        for body in [b"{\"sku\":".to_vec(), overflow, nested(200)] {
            match hardened_checkout(&body) {
                Checkout::Malformed(detail) => assert_eq!(disclosure::detect(&detail), None),
                other => panic!("{other:?}"),
            }
        }
        match hardened_checkout(&duplicated(r#""note":"""#)) {
            Checkout::Invalid(violations) => {
                assert_eq!(violations, [violation("/note", "duplicate key")]);
            }
            other => panic!("{other:?}"),
        }
        match hardened_checkout(&nested(12)) {
            Checkout::Invalid(violations) => {
                assert_eq!(violations, [violation("", "nesting depth 13 exceeds 8")]);
            }
            other => panic!("{other:?}"),
        }
        match hardened_checkout(&with("customer.role", json!("admin"))) {
            Checkout::Invalid(violations) => {
                assert_eq!(violations[0]["pointer"], "/customer/role");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn duplicate_keys_are_located_by_pointer() {
        let probe = |text: &str| duplicate_key(text.as_bytes()).unwrap();
        assert_eq!(probe(r#"{"a":1,"b":{"c":[1,{"d":2}]}}"#), None);
        assert_eq!(probe(r#"{"a":1,"a":2}"#).as_deref(), Some("/a"));
        assert_eq!(probe(r#"{"a":{"b":1,"b":2}}"#).as_deref(), Some("/a/b"));
        assert_eq!(probe(r#"[{"x":1},{"x":1,"x":2}]"#).as_deref(), Some("/1/x"));
        assert_eq!(probe(r#"{"a/b":1,"a/b":2}"#).as_deref(), Some("/a~1b"));
        // First in document order wins when several objects repeat keys.
        assert_eq!(
            probe(r#"{"o":{"k":1,"k":2},"o":3}"#).as_deref(),
            Some("/o/k")
        );
        assert!(duplicate_key(b"{\"a\":").is_err());
        assert_eq!(json_depth(&json!(1)), 0);
        assert_eq!(json_depth(&json!({"a":[{"b":{}}]})), 4);
    }

    #[test]
    fn order_lookup_by_mode() {
        let created = StoredOrder {
            id: 7,
            sku: "LAB-MS-02".to_owned(),
            quantity: 3,
            total_cents: 8_997,
        };
        let shared = Shared {
            hub: Arc::new(TelemetryHub::new()),
            hardened: AtomicBool::new(false),
            ledger: Mutex::new(Ledger::default()),
            redeem_depth: AtomicU32::new(0),
            requests: AtomicU64::new(0),
            next_order: AtomicU64::new(8),
        };
        shared.ledger().created.push_back(created.clone());
        let lookup = |mode, raw: &str| evaluate_lookup(mode, raw, |id| shared.find_order(id));
        let leak_kind = |raw: &str| match lookup(LabMode::Unprotected, raw) {
            Lookup::Leak(leak) => {
                assert_eq!(leak.status, StatusCode::INTERNAL_SERVER_ERROR, "{raw}");
                disclosure::detect(&leak.body).map(|d| d.kind)
            }
            other => panic!("expected a leak for {raw:?}, got {other:?}"),
        };

        assert!(
            matches!(lookup(LabMode::Unprotected, "1"), Lookup::Found(o) if o.sku == "LAB-KB-01" && o.total_cents == 9_998)
        );
        assert_eq!(
            lookup(LabMode::Unprotected, "7"),
            Lookup::Found(created.clone())
        );
        assert_eq!(lookup(LabMode::Unprotected, "4"), Lookup::NotFound);
        let node = Some(DisclosureKind::NodeStackTrace);
        let sql = Some(DisclosureKind::SqlError);
        let long = "9".repeat(4_096);
        for (raw, kind) in [
            ("", node),
            ("0", node),
            ("-1", node),
            ("1.5", node),
            ("9223372036854775807", sql),
            ("9223372036854775808", sql),
            ("invalid-uuid", sql),
            (long.as_str(), Some(DisclosureKind::PythonTraceback)),
        ] {
            assert_eq!(leak_kind(raw), kind, "{raw:.24}");
        }

        assert!(matches!(lookup(LabMode::Hardened, "3"), Lookup::Found(o) if o.id == 3));
        assert_eq!(lookup(LabMode::Hardened, "7"), Lookup::Found(created));
        assert_eq!(lookup(LabMode::Hardened, "999999"), Lookup::NotFound);
        for raw in [
            "",
            "0",
            "-1",
            "01",
            "1.5",
            "1000000",
            "9223372036854775807",
            "invalid-uuid",
            " 1",
            long.as_str(),
        ] {
            assert_eq!(lookup(LabMode::Hardened, raw), Lookup::Invalid, "{raw:.24}");
        }
    }

    #[test]
    fn js_string_matches_template_literal_rendering() {
        assert_eq!(js_string(&json!({})), "[object Object]");
        assert_eq!(js_string(&json!([])), "");
        assert_eq!(js_string(&json!([1, [2, 3], "a"])), "1,2,3,a");
        assert_eq!(js_string(&json!(true)), "true");
        assert_eq!(js_string(&json!(1.5)), "1.5");
    }

    // ---- integration -------------------------------------------------------------------

    async fn started(mode: LabMode) -> (Arc<TelemetryHub>, LabServer, String) {
        let hub = Arc::new(TelemetryHub::new());
        let lab = LabServer::new(Arc::clone(&hub));
        let status = lab
            .start(LabConfig {
                port: Some(0),
                mode,
            })
            .await
            .unwrap();
        (hub, lab, status.base_url.unwrap())
    }

    fn redeem_burst(base: &str) -> BurstSpec {
        BurstSpec {
            target: format!("{base}/api/v1/coupons/redeem"),
            method: BurstMethod::Post,
            workers: 20,
            headers: vec![HeaderPair {
                name: "Content-Type".to_owned(),
                value: "application/json".to_owned(),
            }],
            body: Some(format!(r#"{{"code":"{COUPON_CODE}","userId":"u-1001"}}"#)),
            timeout_ms: 10_000,
            // The coupon admits one use; the quota holds the hardened run to exactly that.
            expected_max_successes: Some(1),
            idempotency_mode: false,
            sync_mode: None,
            contract: None,
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn unprotected_redeem_admits_concurrent_winners_and_hardened_admits_one() {
        let (hub, lab, base) = started(LabMode::Unprotected).await;

        let report = concurrency::run(redeem_burst(&base), &hub).await.unwrap();
        let winners = report
            .samples
            .iter()
            .filter(|s| s.status == Some(200))
            .count();
        let conflicts = report
            .samples
            .iter()
            .filter(|s| s.status == Some(409))
            .count();
        assert!(
            winners >= 2,
            "winners {winners}: {:?}",
            report.status_histogram
        );
        assert!(
            conflicts >= 1,
            "conflicts {conflicts}: {:?}",
            report.status_histogram
        );
        assert_eq!(winners + conflicts, 20);
        assert!(
            report
                .anomalies
                .iter()
                .any(|a| a.kind == AnomalyKind::RaceWindow),
            "{:?}",
            report.anomalies
        );
        let counters = lab.status().await.counters;
        assert_eq!(counters.granted as usize, winners);
        assert_eq!(
            counters.redeemed, 1,
            "lost update keeps the coupon row at the limit"
        );

        let status = lab.set_mode(LabMode::Hardened).await;
        assert_eq!(status.counters, LabCounters::default());
        let report = concurrency::run(redeem_burst(&base), &hub).await.unwrap();
        let winners = report
            .samples
            .iter()
            .filter(|s| s.status == Some(200))
            .count();
        let conflicts = report
            .samples
            .iter()
            .filter(|s| s.status == Some(409))
            .count();
        assert_eq!(
            (winners, conflicts),
            (1, 19),
            "{:?}",
            report.status_histogram
        );
        assert!(report.anomalies.is_empty(), "{:?}", report.anomalies);
        assert_eq!(lab.status().await.counters.granted, 1);

        lab.stop().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn redeem_race_breaks_the_documented_balance_only_when_unprotected() {
        let (hub, lab, base) = started(LabMode::Unprotected).await;
        let burst = || BurstSpec {
            sync_mode: Some(BurstSyncMode::LastByte),
            contract: Some(lab_contract(
                &base,
                RouteMethod::Post,
                "/api/v1/coupons/redeem",
            )),
            ..redeem_burst(&base)
        };

        let report = concurrency::run(burst(), &hub).await.unwrap();
        assert_eq!(report.sync_mode, BurstSyncMode::LastByte);
        let kinds: Vec<AnomalyKind> = report.anomalies.iter().map(|a| a.kind).collect();
        assert!(kinds.contains(&AnomalyKind::RaceWindow), "{kinds:?}");
        let drift = report
            .anomalies
            .iter()
            .find(|a| a.kind == AnomalyKind::ContractDrift)
            .expect("contract drift under the race");
        assert_eq!(drift.severity, Severity::Fault);
        let winners: Vec<&WorkerSample> = report
            .samples
            .iter()
            .filter(|s| s.status == Some(200))
            .collect();
        assert!(winners.len() >= 2, "{:?}", report.status_histogram);
        // Every winner carries the renamed field; every winner past the first also carries a
        // balance below the documented minimum.
        let negative: Vec<&str> = winners
            .iter()
            .flat_map(|s| s.violations.iter())
            .filter(|v| {
                v.kind == ContractViolationKind::ConstraintViolation
                    && v.pointer.as_deref() == Some("/remainingUses")
            })
            .map(|v| v.actual.as_str())
            .collect();
        assert_eq!(negative.len(), winners.len() - 1, "{negative:?}");
        assert!(negative.contains(&"-1"), "{negative:?}");
        assert!(winners.iter().all(|s| s
            .violations
            .iter()
            .any(|v| v.pointer.as_deref() == Some("/discountCents"))));
        assert_eq!(report.contract_violations as usize, winners.len());

        lab.set_mode(LabMode::Hardened).await;
        let report = concurrency::run(burst(), &hub).await.unwrap();
        assert!(report.anomalies.is_empty(), "{:?}", report.anomalies);
        assert_eq!(report.contract_violations, 0);
        assert!(report.samples.iter().all(|s| s.violations.is_empty()));
        lab.stop().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn checkout_replays_one_idempotency_key_only_when_hardened() {
        let (hub, lab, base) = started(LabMode::Unprotected).await;
        let burst = || BurstSpec {
            target: format!("{base}/api/v1/orders/checkout"),
            method: BurstMethod::Post,
            workers: 20,
            headers: vec![HeaderPair {
                name: "Content-Type".to_owned(),
                value: "application/json".to_owned(),
            }],
            body: Some(CHECKOUT_SAMPLE.to_owned()),
            timeout_ms: 10_000,
            expected_max_successes: None,
            idempotency_mode: true,
            sync_mode: None,
            contract: None,
        };
        let created = |report: &crate::engine::types::BurstReport| {
            report
                .samples
                .iter()
                .filter(|s| s.status == Some(201))
                .count()
        };

        let report = concurrency::run(burst(), &hub).await.unwrap();
        assert!(report.idempotency_key.is_some());
        assert_eq!(created(&report), 20, "{:?}", report.status_histogram);
        assert_eq!(report.distinct_bodies, 20);
        let violation = report
            .anomalies
            .iter()
            .find(|a| a.kind == AnomalyKind::IdempotencyViolation)
            .expect("idempotency violation");
        assert_eq!(violation.severity, Severity::Fault);
        assert_eq!(violation.workers.len(), 19);
        assert_eq!(lab.status().await.counters.orders, 20);

        lab.set_mode(LabMode::Hardened).await;
        let report = concurrency::run(burst(), &hub).await.unwrap();
        assert_eq!(created(&report), 20, "{:?}", report.status_histogram);
        assert_eq!(report.distinct_bodies, 1);
        assert!(report.anomalies.is_empty(), "{:?}", report.anomalies);
        assert_eq!(lab.status().await.counters.orders, 1);

        // The same key with another payload is refused, not replayed.
        let key = report.idempotency_key.unwrap();
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        let reused = client
            .post(format!("{base}/api/v1/orders/checkout"))
            .header("Idempotency-Key", key.as_str())
            .body(CHECKOUT_SAMPLE.replace(r#""quantity":2"#, r#""quantity":3"#))
            .send()
            .await
            .unwrap();
        assert_eq!(reused.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let replayed = client
            .post(format!("{base}/api/v1/orders/checkout"))
            .header("Idempotency-Key", key.as_str())
            .body(CHECKOUT_SAMPLE)
            .send()
            .await
            .unwrap();
        assert_eq!(replayed.status(), StatusCode::CREATED);
        assert_eq!(replayed.headers()[REPLAYED_HEADER], "true");
        assert_eq!(lab.status().await.counters.orders, 1);
        lab.stop().await;
    }

    /// The idempotent checkout burst released by its final request byte: every duplicate
    /// carrying the key completes parsing within one write, the tightest overlap a client can
    /// produce. Spreads of both sync modes are measured against the same request and reported
    /// with the mode; neither is asserted against the other, since both depend on the host
    /// scheduler rather than on the service.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn last_byte_release_replays_one_idempotency_key_only_when_hardened() {
        let (hub, lab, base) = started(LabMode::Unprotected).await;
        let mut events = hub.subscribe();
        let contract = lab_contract(&base, RouteMethod::Post, "/api/v1/orders/checkout");
        let burst = |sync_mode| BurstSpec {
            target: format!("{base}/api/v1/orders/checkout"),
            method: BurstMethod::Post,
            workers: 24,
            headers: vec![HeaderPair {
                name: "Content-Type".to_owned(),
                value: "application/json".to_owned(),
            }],
            body: Some(CHECKOUT_SAMPLE.to_owned()),
            timeout_ms: 10_000,
            expected_max_successes: None,
            idempotency_mode: true,
            sync_mode: Some(sync_mode),
            contract: Some(contract.clone()),
        };
        let created = |report: &BurstReport| {
            report
                .samples
                .iter()
                .filter(|s| s.status == Some(201))
                .count()
        };

        // Unprotected ignores the key: every worker creates an order of its own, and every
        // body carries `totalCents` as a string.
        let report = concurrency::run(burst(BurstSyncMode::LastByte), &hub)
            .await
            .unwrap();
        assert_eq!(report.sync_mode, BurstSyncMode::LastByte);
        let key = report.idempotency_key.clone().expect("generated key");
        assert_eq!(created(&report), 24, "{:?}", report.status_histogram);
        assert_eq!(report.distinct_bodies, 24);
        let kinds: Vec<AnomalyKind> = report.anomalies.iter().map(|a| a.kind).collect();
        assert_eq!(
            kinds,
            [
                AnomalyKind::IdempotencyViolation,
                AnomalyKind::ContractDrift
            ]
        );
        assert!(report
            .anomalies
            .iter()
            .all(|a| a.severity == Severity::Fault));
        assert_eq!(report.anomalies[0].workers.len(), 23);
        assert_eq!(report.contract_violations, 24);
        assert!(report
            .samples
            .iter()
            .all(|s| s.dispatch_offset_us.is_some()));
        assert_eq!(lab.status().await.counters.orders, 24);

        let mut started_with = None;
        let mut completed_with = None;
        while let Ok(event) = events.try_recv() {
            match event {
                TelemetryEvent::BurstStarted {
                    id,
                    sync_mode,
                    idempotency_key,
                    ..
                } if id == report.id => started_with = Some((sync_mode, idempotency_key)),
                TelemetryEvent::BurstCompleted {
                    id,
                    sync_mode,
                    dispatch_spread_us,
                    ..
                } if id == report.id => completed_with = Some((sync_mode, dispatch_spread_us)),
                _ => {}
            }
        }
        assert_eq!(started_with, Some((BurstSyncMode::LastByte, Some(key))));
        assert_eq!(
            completed_with,
            Some((BurstSyncMode::LastByte, report.dispatch_spread_us))
        );

        // Hardened claims the key, creates and records under one lock: one order per burst,
        // whichever way the barrier releases, and every 2xx is the stored response.
        lab.set_mode(LabMode::Hardened).await;
        let mut spreads = Vec::with_capacity(2);
        for sync_mode in [BurstSyncMode::LastByte, BurstSyncMode::PreConnected] {
            let orders = lab.status().await.counters.orders;
            let report = concurrency::run(burst(sync_mode), &hub).await.unwrap();
            assert_eq!(report.sync_mode, sync_mode);
            assert_eq!(
                created(&report),
                24,
                "{sync_mode:?} {:?}",
                report.status_histogram
            );
            assert_eq!(report.distinct_bodies, 1, "{sync_mode:?}");
            assert!(
                report.anomalies.is_empty(),
                "{sync_mode:?} {:?}",
                report.anomalies
            );
            assert_eq!(report.contract_violations, 0);
            assert_eq!(lab.status().await.counters.orders, orders + 1);
            spreads.push((sync_mode, report.dispatch_spread_us.expect("measured")));
        }
        // Loose bound only: neither mode leaves TCP connects inside the dispatch.
        for (sync_mode, spread) in spreads {
            assert!(
                spread < 250_000,
                "{sync_mode:?} dispatch spread {spread} us"
            );
        }
        lab.stop().await;
    }

    fn checkout_fuzz(base: &str) -> FuzzSpec {
        FuzzSpec {
            target: format!("{base}/api/v1/orders/checkout"),
            method: BurstMethod::Post,
            headers: Vec::new(),
            base_body: Some(CHECKOUT_SAMPLE.to_owned()),
            classes: Vec::new(),
            timeout_ms: 5_000,
            contract: None,
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fuzzing_checkout_separates_the_two_modes() {
        let (hub, lab, base) = started(LabMode::Unprotected).await;
        let slot = FuzzerSlot::default();

        let report = fuzzer::run(checkout_fuzz(&base), &hub, &slot)
            .await
            .unwrap();
        assert_eq!(report.baseline.status, Some(201));
        assert_eq!(report.aborted, None);
        assert!(report.faults >= 20, "faults {}", report.faults);
        let kinds: std::collections::BTreeSet<String> = report
            .cases
            .iter()
            .filter_map(|c| c.disclosure.as_ref())
            .map(|d| format!("{:?}", d.kind))
            .collect();
        for expected in [
            "NodeStackTrace",
            "PythonTraceback",
            "RustPanic",
            "GoPanic",
            "SqlError",
        ] {
            assert!(
                kinds.contains(expected),
                "{expected} missing from {kinds:?}"
            );
        }
        for case in report
            .cases
            .iter()
            .filter(|c| c.class == Some(crate::engine::types::MutationClass::MalformedJson))
        {
            assert_eq!(case.status, Some(400), "{}", case.label);
            assert_eq!(case.verdict, FuzzVerdict::Rejected);
            assert!(case.disclosure.is_some(), "{}", case.label);
        }
        let apostrophe = |report: &crate::engine::types::FuzzReport| {
            report
                .cases
                .iter()
                .find(|c| c.label == r#"/sku = "O'Reilly & Sons""#)
                .cloned()
                .expect("delimiter case on /sku")
        };
        let case = apostrophe(&report);
        assert_eq!(case.class, Some(MutationClass::DelimiterEscaping));
        assert_eq!(case.verdict, FuzzVerdict::ServerError);
        assert_eq!(case.severity, Some(Severity::Fault));
        assert_eq!(
            case.disclosure.map(|d| d.kind),
            Some(DisclosureKind::SqlError)
        );

        lab.set_mode(LabMode::Hardened).await;
        let report = fuzzer::run(checkout_fuzz(&base), &hub, &slot)
            .await
            .unwrap();
        assert_eq!(report.baseline.status, Some(201));
        assert_eq!(
            (report.faults, report.warnings, report.disclosures),
            (0, 0, 0)
        );
        assert!(report
            .cases
            .iter()
            .all(|c| matches!(c.status, Some(201) | Some(422))));
        let case = apostrophe(&report);
        assert_eq!((case.status, case.severity), (Some(422), None));
        assert!(case.disclosure.is_none());
        lab.stop().await;
    }

    /// Contracts of the lab's own document, as the route list hands them to the engine.
    fn lab_contracts(base: &str) -> Vec<RouteContract> {
        routes::spec_report("target-lab", SPEC_FILE, &openapi_document(Some(base)))
            .routes
            .into_iter()
            .filter_map(|route| {
                Some(RouteContract {
                    method: route.method,
                    path: route.path,
                    contract: route.contract?,
                })
            })
            .collect()
    }

    fn lab_contract(base: &str, method: RouteMethod, path: &str) -> ResponseContract {
        lab_contracts(base)
            .into_iter()
            .find(|route| route.method == method && route.path == path)
            .map(|route| route.contract)
            .unwrap()
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn checkout_responses_drift_from_the_contract_in_unprotected_mode_only() {
        let (hub, lab, base) = started(LabMode::Unprotected).await;
        let slot = FuzzerSlot::default();
        let spec = || FuzzSpec {
            contract: Some(lab_contract(
                &base,
                RouteMethod::Post,
                "/api/v1/orders/checkout",
            )),
            ..checkout_fuzz(&base)
        };

        let report = fuzzer::run(spec(), &hub, &slot).await.unwrap();
        assert_eq!(report.baseline.status, Some(201));
        assert_eq!(
            report.baseline.violations,
            [ContractViolation {
                kind: ContractViolationKind::ResponseTypeMismatch,
                pointer: Some("/totalCents".to_owned()),
                expected: "integer".to_owned(),
                actual: "string".to_owned(),
            }]
        );
        assert!(
            report
                .notes
                .iter()
                .any(|note| note.contains("/totalCents: expected integer, got string")),
            "{:?}",
            report.notes
        );
        assert_eq!(report.baseline.severity, None, "the baseline is context");
        let undocumented: std::collections::BTreeSet<String> = report
            .cases
            .iter()
            .flat_map(|case| &case.violations)
            .filter(|v| v.kind == ContractViolationKind::UndocumentedStatus)
            .map(|v| v.actual.clone())
            .collect();
        assert!(undocumented.contains("400"), "{undocumented:?}");
        assert!(report.contract_violations > 1);
        for case in report.cases.iter().filter(|c| !c.violations.is_empty()) {
            assert!(case.severity.is_some(), "{}", case.label);
        }

        lab.set_mode(LabMode::Hardened).await;
        let report = fuzzer::run(spec(), &hub, &slot).await.unwrap();
        assert_eq!(report.baseline.status, Some(201));
        assert_eq!(report.contract_violations, 0, "{:?}", report.baseline);
        assert_eq!(
            (report.faults, report.warnings, report.disclosures),
            (0, 0, 0)
        );
        lab.stop().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn proxy_checks_lab_responses_against_the_documented_contracts() {
        let (hub, lab, base) = started(LabMode::Unprotected).await;
        let proxy = ProxyManager::new(Arc::clone(&hub)).unwrap();
        let status = proxy.set_contracts(lab_contracts(&base)).await.unwrap();
        assert_eq!(status.contracts, 5);
        let listener = proxy
            .start(ProxyConfig {
                upstream: base.clone(),
                listen_port: 0,
            })
            .await
            .unwrap()
            .listener
            .unwrap();
        let client = reqwest::Client::builder().no_proxy().build().unwrap();

        let exchanges = |mode: LabMode| {
            let client = client.clone();
            let listener = listener.clone();
            let mut events = hub.subscribe();
            async move {
                let url = |path: &str| format!("http://{listener}{path}");
                let send = |request: reqwest::RequestBuilder| async move {
                    request.send().await.unwrap().status().as_u16()
                };
                assert_eq!(send(client.get(url("/api/v1/health"))).await, 200);
                assert_eq!(
                    send(
                        client
                            .post(url("/api/v1/orders/checkout"))
                            .body(CHECKOUT_SAMPLE)
                    )
                    .await,
                    201
                );
                assert_eq!(send(client.get(url("/api/v1/orders/1"))).await, 200);
                let redeem = format!(r#"{{"code":"{COUPON_CODE}"}}"#);
                assert_eq!(
                    send(client.post(url("/api/v1/coupons/redeem")).body(redeem)).await,
                    200
                );
                let empty = send(client.post(url("/api/v1/coupons/redeem")).body("{}")).await;
                assert_eq!(empty, if mode == LabMode::Hardened { 422 } else { 400 });
                let mut seen = Vec::new();
                while seen.len() < 5 {
                    let event = tokio::time::timeout(Duration::from_secs(5), events.recv())
                        .await
                        .unwrap()
                        .unwrap();
                    if let TelemetryEvent::ProxyExchange {
                        contract,
                        violations,
                        ..
                    } = event
                    {
                        let drift: Vec<String> = violations
                            .iter()
                            .map(|v| {
                                format!("{}={}", v.pointer.as_deref().unwrap_or("status"), v.actual)
                            })
                            .collect();
                        seen.push((contract.unwrap_or_default(), drift.join(",")));
                    }
                }
                seen
            }
        };

        let drift = |label: &str, found: &str| (label.to_owned(), found.to_owned());
        assert_eq!(
            exchanges(LabMode::Unprotected).await,
            [
                drift("GET /api/v1/health", ""),
                drift("POST /api/v1/orders/checkout", "/totalCents=string"),
                drift("GET /api/v1/orders/{orderId}", "/totalCents=string"),
                drift("POST /api/v1/coupons/redeem", "/discountCents=missing"),
                drift("POST /api/v1/coupons/redeem", "status=400"),
            ]
        );

        lab.set_mode(LabMode::Hardened).await;
        let hardened = exchanges(LabMode::Hardened).await;
        assert!(
            hardened
                .iter()
                .all(|(label, found)| !label.is_empty() && found.is_empty()),
            "{hardened:?}"
        );
        proxy.stop().await;
        lab.stop().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn proxy_audits_lab_traffic_passively() {
        const LOOKUPS: usize = 12;
        let (hub, lab, base) = started(LabMode::Unprotected).await;
        let proxy = ProxyManager::new(Arc::clone(&hub)).unwrap();
        let listener = proxy
            .start(ProxyConfig {
                upstream: base.clone(),
                listen_port: 0,
            })
            .await
            .unwrap()
            .listener
            .unwrap();
        let client = reqwest::Client::builder().no_proxy().build().unwrap();

        // An order list rendered one row at a time: twelve lookups fired together. Four more
        // than the threshold, so a slow CI scheduler still lands eight inside one window.
        let audit = |mode: LabMode| {
            let client = client.clone();
            let listener = listener.clone();
            let mut events = hub.subscribe();
            async move {
                let mut lookups = tokio::task::JoinSet::new();
                for id in 1..=LOOKUPS {
                    let request = client.get(format!("http://{listener}/api/v1/orders/{id}"));
                    lookups.spawn(async move { request.send().await.unwrap().status().as_u16() });
                }
                while let Some(status) = lookups.join_next().await {
                    assert!(matches!(status.unwrap(), 200 | 404));
                }
                let leak = client
                    .get(format!("http://{listener}/api/v1/orders/invalid-id"))
                    .send()
                    .await
                    .unwrap();
                let expected = if mode == LabMode::Hardened { 422 } else { 500 };
                assert_eq!(leak.status().as_u16(), expected);

                let mut findings = Vec::new();
                let mut exchanges = 0;
                while exchanges < LOOKUPS + 1 {
                    let event = tokio::time::timeout(Duration::from_secs(5), events.recv())
                        .await
                        .unwrap()
                        .unwrap();
                    if let TelemetryEvent::ProxyExchange {
                        findings: found, ..
                    } = event
                    {
                        exchanges += 1;
                        findings.extend(found.into_iter().map(|f| (f.kind, f.severity)));
                    }
                }
                findings
            }
        };
        let count = |findings: &[(TrafficFindingKind, Severity)], kind| {
            findings.iter().filter(|(found, _)| *found == kind).count()
        };

        let unprotected = audit(LabMode::Unprotected).await;
        assert_eq!(count(&unprotected, TrafficFindingKind::NPlusOneBurst), 1);
        assert_eq!(
            count(&unprotected, TrafficFindingKind::HeaderMisconfiguration),
            LOOKUPS + 1,
            "credentialed CORS wildcard on every response"
        );
        assert!(unprotected.contains(&(TrafficFindingKind::PassiveDisclosure, Severity::Fault)));

        lab.set_mode(LabMode::Hardened).await;
        // Let the template window lapse so the hardened fan-out counts as a new burst.
        tokio::time::sleep(linter_window()).await;
        // A latency regression depends on the host scheduler, not on the service under test.
        let hardened: Vec<_> = audit(LabMode::Hardened)
            .await
            .into_iter()
            .filter(|(kind, _)| *kind != TrafficFindingKind::LatencyRegression)
            .collect();
        assert_eq!(
            hardened,
            [(TrafficFindingKind::NPlusOneBurst, Severity::Warn)],
            "N+1 is client behaviour; the hardened service adds nothing else"
        );
        proxy.stop().await;
        lab.stop().await;
    }

    fn linter_window() -> Duration {
        crate::engine::linter::N_PLUS_ONE_WINDOW * 2
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fuzzing_schema_contract_on_checkout() {
        let (hub, lab, base) = started(LabMode::Unprotected).await;
        let slot = FuzzerSlot::default();
        let spec = || FuzzSpec {
            classes: vec![MutationClass::SchemaContractBounds],
            ..checkout_fuzz(&base)
        };

        // Unprotected either accepts the contract violation or crashes on it.
        let report = fuzzer::run(spec(), &hub, &slot).await.unwrap();
        assert_eq!(report.baseline.status, Some(201));
        let outcome = |label: &str| {
            let case = report.cases.iter().find(|c| c.label == label).unwrap();
            (case.status, case.severity)
        };
        let warn = Some(crate::engine::types::Severity::Warn);
        let fault = Some(crate::engine::types::Severity::Fault);
        assert_eq!(outcome("duplicate /note = \"\""), (Some(201), warn));
        assert_eq!(outcome("duplicate /quantity = -1"), (Some(500), fault));
        assert_eq!(
            outcome("+/zproxyNest = 64 nested objects"),
            (Some(201), warn)
        );
        assert_eq!(
            outcome("+/zproxyNest = 1024 nested objects"),
            (Some(500), fault)
        );
        assert_eq!(outcome("+/isAdmin = true"), (Some(201), warn));
        assert_eq!(
            outcome("+/customer/zproxyExtra = \"unexpected\""),
            (Some(201), warn)
        );
        assert_eq!(outcome("/quantity = 1e309"), (Some(500), fault));
        assert!(report
            .cases
            .iter()
            .all(|c| matches!(c.status, Some(201) | Some(500))));

        lab.set_mode(LabMode::Hardened).await;
        let report = fuzzer::run(spec(), &hub, &slot).await.unwrap();
        assert_eq!(
            (report.faults, report.warnings, report.disclosures),
            (0, 0, 0)
        );
        assert!(report.cases.iter().all(|c| c.status == Some(422)));
        lab.stop().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fuzzing_order_lookup_path_parameters() {
        let (hub, lab, base) = started(LabMode::Unprotected).await;
        let slot = FuzzerSlot::default();
        let spec = || FuzzSpec {
            target: format!("{base}/api/v1/orders/{{orderId}}"),
            method: BurstMethod::Get,
            headers: Vec::new(),
            base_body: None,
            classes: vec![MutationClass::PathParamValidation],
            timeout_ms: 5_000,
            contract: None,
        };

        let report = fuzzer::run(spec(), &hub, &slot).await.unwrap();
        assert_eq!(report.target, format!("{base}/api/v1/orders/1"));
        assert_eq!(report.baseline.status, Some(200));
        assert_eq!(
            report.path_template.as_deref(),
            Some("/api/v1/orders/{orderId}")
        );
        assert_eq!(report.cases.len(), 7);
        assert_eq!((report.faults, report.disclosures), (7, 7));
        let kinds: Vec<(String, DisclosureKind)> = report
            .cases
            .iter()
            .map(|c| (c.label.clone(), c.disclosure.as_ref().unwrap().kind))
            .collect();
        let node = DisclosureKind::NodeStackTrace;
        let sql = DisclosureKind::SqlError;
        assert_eq!(
            kinds,
            [
                ("{orderId} = 0".to_owned(), node),
                ("{orderId} = -1".to_owned(), node),
                ("{orderId} = i64::MAX".to_owned(), sql),
                ("{orderId} = i64::MAX+1".to_owned(), sql),
                ("{orderId} = \"invalid-uuid\"".to_owned(), sql),
                ("{orderId} = empty segment".to_owned(), node),
                (
                    "{orderId} = 4 KiB of digits".to_owned(),
                    DisclosureKind::PythonTraceback
                ),
            ]
        );

        lab.set_mode(LabMode::Hardened).await;
        let report = fuzzer::run(spec(), &hub, &slot).await.unwrap();
        assert_eq!(report.baseline.status, Some(200));
        assert_eq!(
            (report.faults, report.warnings, report.disclosures),
            (0, 0, 0)
        );
        assert!(report.cases.iter().all(|c| c.status == Some(422)));
        lab.stop().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn lifecycle_spec_and_telemetry() {
        let (hub, lab, base) = started(LabMode::Unprotected).await;
        let mut events = hub.subscribe();
        let status = lab.status().await;
        assert!(status.running);
        let listener: SocketAddr = status.listener.clone().unwrap().parse().unwrap();
        assert_eq!(listener.ip(), Ipv4Addr::LOCALHOST);

        let err = lab
            .start(LabConfig {
                port: Some(0),
                mode: LabMode::Hardened,
            })
            .await
            .unwrap_err();
        assert_eq!(err.code(), "LAB_ALREADY_RUNNING");

        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        let spec: Value = client
            .get(format!("{base}{SPEC_PATH}"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(spec["servers"][0]["url"], base);
        assert!(spec["paths"]["/api/v1/orders/checkout"]["post"].is_object());
        let health: Value = client
            .get(format!("{base}/api/v1/health"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(health["mode"], "unprotected");
        let missing = client.get(format!("{base}/nope")).send().await.unwrap();
        assert_eq!(missing.status(), StatusCode::NOT_FOUND);
        let created = client
            .post(format!("{base}/api/v1/orders/checkout"))
            .body(CHECKOUT_SAMPLE)
            .send()
            .await
            .unwrap();
        assert_eq!(created.status(), StatusCode::CREATED);
        assert_eq!(lab.status().await.counters.orders, 1);
        assert_eq!(lab.status().await.counters.requests, 4);

        let mut exchanges = Vec::new();
        while let Ok(event) = events.try_recv() {
            if let TelemetryEvent::LabExchange {
                path,
                status,
                mode,
                outcome,
                ..
            } = event
            {
                exchanges.push((path, status, mode, outcome));
            }
        }
        assert_eq!(exchanges.len(), 4);
        assert_eq!(
            exchanges[3],
            (
                "/api/v1/orders/checkout".to_owned(),
                201,
                LabMode::Unprotected,
                "order confirmed".to_owned()
            )
        );

        let reset = lab.reset().await;
        assert_eq!(reset.counters, LabCounters::default());
        let stopped = lab.stop().await;
        assert!(!stopped.running && stopped.base_url.is_none());
        assert!(!lab.stop().await.running, "stop is idempotent");
        std::net::TcpListener::bind(listener).expect("port released after stop");

        let mut states = Vec::new();
        while let Ok(event) = events.try_recv() {
            if let TelemetryEvent::LabStateChanged { status, .. } = event {
                states.push(status.running);
            }
        }
        assert_eq!(states, [true, false, false]);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn order_lookup_over_http() {
        let (_hub, lab, base) = started(LabMode::Unprotected).await;
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        let get = |path: &str| {
            let request = client.get(format!("{base}{path}"));
            async move {
                let response = request.send().await.unwrap();
                let status = response.status().as_u16();
                (status, response.text().await.unwrap())
            }
        };

        let (status, body) = get("/api/v1/orders/1").await;
        assert_eq!(status, 200, "{body}");
        let order: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(
            (order["id"].as_u64(), order["orderId"].as_str()),
            (Some(1), Some("ord-000001"))
        );

        let created: Value = client
            .post(format!("{base}/api/v1/orders/checkout"))
            .body(CHECKOUT_SAMPLE)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let id = created["id"].as_u64().unwrap();
        assert!(id > ORDER_HISTORY.len() as u64, "{created}");
        let (status, body) = get(&format!("/api/v1/orders/{id}")).await;
        assert_eq!(status, 200, "{body}");
        assert_eq!(serde_json::from_str::<Value>(&body).unwrap(), created);

        let (status, body) = get("/api/v1/orders/").await;
        assert_eq!(status, 500);
        assert!(body.contains("TypeError"), "{body}");
        let (status, body) = get("/api/v1/orders/invalid-uuid").await;
        assert_eq!(status, 500);
        assert!(
            body.contains("invalid input syntax for type bigint"),
            "{body}"
        );

        lab.set_mode(LabMode::Hardened).await;
        for path in [
            "/api/v1/orders/",
            "/api/v1/orders/invalid-uuid",
            "/api/v1/orders/-1",
        ] {
            let (status, body) = get(path).await;
            assert_eq!(status, 422, "{path}: {body}");
            assert!(body.contains("invalid_path_parameter"), "{body}");
        }
        // The mode switch cleared the ledger; the seeded history stays.
        assert_eq!(get(&format!("/api/v1/orders/{id}")).await.0, 404);
        assert_eq!(get("/api/v1/orders/2").await.0, 200);
        lab.stop().await;
    }

    #[tokio::test]
    async fn explicit_busy_port_fails_and_default_falls_back() {
        let blocker = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let busy = blocker.local_addr().unwrap().port();
        let lab = LabServer::new(Arc::new(TelemetryHub::new()));
        let err = lab
            .start(LabConfig {
                port: Some(busy),
                mode: LabMode::Unprotected,
            })
            .await
            .unwrap_err();
        assert_eq!(err.code(), "LISTENER_BIND_FAILED");
        assert!(!lab.status().await.running);
        let status = lab
            .start(LabConfig {
                port: None,
                mode: LabMode::Hardened,
            })
            .await
            .unwrap();
        assert!(status.running);
        assert_eq!(status.mode, LabMode::Hardened);
        lab.stop().await;
    }

    #[test]
    fn document_is_valid_json_with_the_bound_server() {
        let document: Value =
            serde_json::from_str(&openapi_document(Some("http://127.0.0.1:4242"))).unwrap();
        assert_eq!(document["servers"][0]["url"], "http://127.0.0.1:4242");
        assert_eq!(document["paths"].as_object().unwrap().len(), 5);
        let fallback: Value = serde_json::from_str(&openapi_document(None)).unwrap();
        assert_eq!(
            fallback["servers"][0]["url"],
            format!("http://127.0.0.1:{DEFAULT_PORT}")
        );
    }
}
