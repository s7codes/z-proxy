//! Embedded target lab: a deliberately flawed loopback microservice.
//!
//! Gives the burst runner, fuzzer and proxy a known target whose defects switch at runtime.
//! `Unprotected` mode redeems a single-use coupon with a check-then-act race and lets
//! unvalidated checkout input crash into handlers that leak stack traces and database
//! errors. `Hardened` mode reserves the coupon with one conditional update and rejects every
//! invalid checkout with a 422 JSON body. The listener binds 127.0.0.1 only.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use axum::body::Bytes;
use axum::extract::{Request, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
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
                next_order: AtomicU64::new(1),
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
    let response = next.run(request).await;
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
            "endpoints": ["GET /api/v1/health", "POST /api/v1/coupons/redeem", "POST /api/v1/orders/checkout"]
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
        return redeemed(granted, "granted: reservation committed before side effect");
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
    redeemed(granted, outcome)
}

fn redeemed(granted: u32, outcome: &str) -> Response {
    json_reply(
        StatusCode::OK,
        &json!({
            "status": "redeemed",
            "code": COUPON_CODE,
            "discountCents": DISCOUNT_CENTS,
            "redemptionId": format!("rdm-{granted:06}"),
        }),
        outcome,
    )
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

async fn checkout(State(shared): State<Arc<Shared>>, body: Bytes) -> Response {
    match evaluate_checkout(shared.mode(), &body) {
        Checkout::Created {
            sku,
            quantity,
            total_cents,
        } => {
            let order = shared.next_order.fetch_add(1, Ordering::SeqCst);
            shared.ledger().orders += 1;
            json_reply(
                StatusCode::CREATED,
                &json!({
                    "orderId": format!("ord-{order:06}"),
                    "status": "confirmed",
                    "sku": sku,
                    "quantity": quantity,
                    "totalCents": total_cents,
                }),
                "order confirmed",
            )
        }
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
    let value = match serde_json::from_slice::<Value>(body) {
        Ok(value) => value,
        Err(err) => return Checkout::Leak(body_parser_trace(&err)),
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
    let value = match serde_json::from_slice::<Value>(body) {
        Ok(value) => value,
        Err(err) => return Checkout::Malformed(err.to_string()),
    };
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

// ---- OpenAPI document -----------------------------------------------------------------

/// The lab's own OpenAPI 3.1 description, pretty-printed so route lines are meaningful.
/// Request bodies use `$ref`s, a `readOnly` property and a 3.1 type union so the scanner's
/// body synthesis is exercised end to end.
pub fn openapi_document(base_url: Option<&str>) -> String {
    let server = base_url.map_or_else(|| format!("http://127.0.0.1:{DEFAULT_PORT}"), str::to_owned);
    let response = |description: &str| json!({ "description": description });
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
                    "responses": { "200": response("Service is up") }
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
                        "200": response("Coupon redeemed"),
                        "404": response("Unknown coupon"),
                        "409": response("Coupon already used")
                    }
                }
            },
            "/api/v1/orders/checkout": {
                "post": {
                    "summary": "Price and confirm an order",
                    "requestBody": { "$ref": "#/components/requestBodies/Checkout" },
                    "responses": {
                        "201": response("Order confirmed"),
                        "422": response("Validation failed"),
                        "500": response("Unhandled failure")
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
    use crate::engine::types::{
        AnomalyKind, BurstMethod, BurstSpec, DisclosureKind, FuzzSpec, FuzzVerdict, HeaderPair,
    };

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
                "quoted sku",
                with("sku", json!("KB' OR '1'='1")),
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
        ];
        for (label, body, status, kind) in cases {
            assert_eq!(leaked(&body), (status, kind), "{label}");
        }
        let sql = match unprotected_checkout(&with("sku", json!({}))) {
            Checkout::Leak(leak) => leak.body,
            other => panic!("{other:?}"),
        };
        assert!(sql.contains("near '[object Object]'"), "{sql}");
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

        let invalid = [
            with("sku", Value::Null),
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
        match hardened_checkout(b"{\"sku\":") {
            Checkout::Malformed(detail) => assert_eq!(disclosure::detect(&detail), None),
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

    fn checkout_fuzz(base: &str) -> FuzzSpec {
        FuzzSpec {
            target: format!("{base}/api/v1/orders/checkout"),
            method: BurstMethod::Post,
            headers: Vec::new(),
            base_body: Some(CHECKOUT_SAMPLE.to_owned()),
            classes: Vec::new(),
            timeout_ms: 5_000,
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
        assert_eq!(document["paths"].as_object().unwrap().len(), 4);
        let fallback: Value = serde_json::from_str(&openapi_document(None)).unwrap();
        assert_eq!(
            fallback["servers"][0]["url"],
            format!("http://127.0.0.1:{DEFAULT_PORT}")
        );
    }
}
