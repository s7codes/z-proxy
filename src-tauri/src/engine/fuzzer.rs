//! Deterministic boundary and schema payload fuzzer.
//!
//! A base JSON object expands into a fixed, ordered list of mutation cases. There is no
//! RNG: two runs against the same base send byte-identical requests, so a failure
//! reproduces by case index. Cases run sequentially, each on its own connection with
//! `Connection: close`, so a crash triggered by one payload is attributed to that payload
//! instead of surfacing on whichever request happens to reuse the dead connection.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use axum::body::Bytes;
use axum::http::header::{self, HeaderName, HeaderValue};
use axum::http::Request;
use http_body_util::Full;
use serde_json::{json, Map, Value};
use tokio::sync::Mutex;
use uuid::Uuid;

use super::disclosure;
use super::error::{EngineError, EngineResult};
use super::http1::{self, OpenError, RequestTemplate, CONNECT_TIMEOUT};
use super::net;
use super::types::{
    BurstMethod, ClassSummary, FuzzCaseResult, FuzzReport, FuzzSpec, FuzzVerdict, MutationClass,
    Severity, TelemetryEvent,
};
use crate::telemetry::{now_us, TelemetryHub};

pub const OVERSIZED_LEN: usize = 64 * 1024;
const MAX_TIMEOUT_MS: u32 = 60_000;
const MAX_BASE_BYTES: usize = 256 * 1024;
/// A field yields at most 16 cases across all per-field classes, so 48 fields keep every
/// suite below `MAX_CASES` without silently dropping mutations.
const MAX_FIELDS: usize = 48;
const MAX_DEPTH: usize = 3;
const MAX_CASES: usize = 1_024;
/// Long enough to hold the exception line and the first frames of a leaked trace, which is
/// where the disclosure signatures look.
const PREVIEW_BYTES: usize = 2 * 1024;
/// Consecutive connect failures that end a run: the target is down, not flaky.
const UNREACHABLE_LIMIT: u32 = 3;
const USER_AGENT: &str = concat!("chaosproxy-fuzzer/", env!("CARGO_PKG_VERSION"));
const CASE_HEADER: &str = "x-chaosproxy-fuzz-case";
const PAD_FIELD: &str = "chaosproxyPad";
const UTF8_FIELD: &str = "chaosproxyUtf8";
/// Serialized in place of a field, then replaced byte-wise with content serde_json refuses
/// to emit (a bare `NaN`, invalid UTF-8).
const MARKER: &str = "__chaosproxy_marker_7f3a__";

const ALL_CLASSES: [MutationClass; 7] = [
    MutationClass::NullInjection,
    MutationClass::EmptyStrings,
    MutationClass::BoundaryNumbers,
    MutationClass::TypeConfusion,
    MutationClass::OversizedField,
    MutationClass::MalformedJson,
    MutationClass::MissingFields,
];

/// Single-flight guard and cancel flag for the fuzzer; lives in `AppState`.
#[derive(Default)]
pub struct FuzzerSlot {
    running: Mutex<()>,
    cancel: AtomicBool,
}

impl FuzzerSlot {
    /// Requests cancellation of the running suite; `false` when none is running. Takes
    /// effect between cases, never mid-request.
    pub fn cancel(&self) -> bool {
        if self.running.try_lock().is_ok() {
            return false;
        }
        self.cancel.store(true, Ordering::SeqCst);
        true
    }
}

pub async fn run(
    spec: FuzzSpec,
    hub: &TelemetryHub,
    slot: &FuzzerSlot,
) -> EngineResult<FuzzReport> {
    let _running = slot
        .running
        .try_lock()
        .map_err(|_| EngineError::FuzzerBusy)?;
    slot.cancel.store(false, Ordering::SeqCst);
    let plan = prepare(&spec)?;
    Ok(execute(&plan, spec.method, hub, &slot.cancel).await)
}

// ---- case generation ------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Case {
    pub class: MutationClass,
    pub label: String,
    pub pointer: Option<String>,
    pub body: Bytes,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Null,
    Bool,
    Number,
    String,
    Array,
    Object,
}

fn kind(value: &Value) -> Kind {
    match value {
        Value::Null => Kind::Null,
        Value::Bool(_) => Kind::Bool,
        Value::Number(_) => Kind::Number,
        Value::String(_) => Kind::String,
        Value::Array(_) => Kind::Array,
        Value::Object(_) => Kind::Object,
    }
}

struct Field {
    path: Vec<String>,
    pointer: String,
    kind: Kind,
    empty_string: bool,
}

fn default_template() -> Map<String, Value> {
    let template = json!({
        "id": 1,
        "name": "chaosproxy",
        "email": "fuzz@chaosproxy.invalid",
        "quantity": 1,
        "active": true,
        "tags": ["alpha"],
        "meta": { "source": "chaosproxy" }
    });
    match template {
        Value::Object(map) => map,
        _ => Map::new(),
    }
}

fn collect_fields(base: &Map<String, Value>) -> Vec<Field> {
    fn walk(object: &Map<String, Value>, prefix: &mut Vec<String>, out: &mut Vec<Field>) {
        for (key, value) in object {
            prefix.push(key.clone());
            out.push(Field {
                path: prefix.clone(),
                pointer: pointer(prefix),
                kind: kind(value),
                empty_string: value.as_str() == Some(""),
            });
            if let Value::Object(child) = value {
                if prefix.len() < MAX_DEPTH {
                    walk(child, prefix, out);
                }
            }
            prefix.pop();
        }
    }
    let mut out = Vec::new();
    walk(base, &mut Vec::new(), &mut out);
    out
}

/// RFC 6901 JSON Pointer.
fn pointer(path: &[String]) -> String {
    path.iter()
        .map(|segment| format!("/{}", segment.replace('~', "~0").replace('/', "~1")))
        .collect()
}

/// Copy of `base` with the value at `path` replaced, or removed when `value` is `None`.
/// `shift_remove` keeps the remaining fields in their original order.
fn mutate(base: &Map<String, Value>, path: &[String], value: Option<Value>) -> Map<String, Value> {
    let mut root = base.clone();
    let Some((last, parents)) = path.split_last() else {
        return root;
    };
    let mut cursor = &mut root;
    for key in parents {
        match cursor.get_mut(key) {
            Some(Value::Object(next)) => cursor = next,
            _ => return root,
        }
    }
    match value {
        Some(value) => {
            cursor.insert(last.clone(), value);
        }
        None => {
            cursor.shift_remove(last);
        }
    }
    root
}

fn encode(map: &Map<String, Value>) -> Vec<u8> {
    serde_json::to_vec(map).unwrap_or_default()
}

/// Serializes `base` with `path` set to the marker, then splices `raw` in place of the
/// quoted marker.
fn splice(base: &Map<String, Value>, path: &[String], raw: &[u8]) -> Vec<u8> {
    let encoded = encode(&mutate(base, path, Some(Value::String(MARKER.to_owned()))));
    let quoted = format!("\"{MARKER}\"");
    match encoded
        .windows(quoted.len())
        .position(|window| window == quoted.as_bytes())
    {
        Some(at) => [&encoded[..at], raw, &encoded[at + quoted.len()..]].concat(),
        None => encoded,
    }
}

fn boundary_values() -> [(&'static str, Value); 8] {
    [
        ("0", json!(0)),
        ("-1", json!(-1)),
        ("i64::MAX", json!(i64::MAX)),
        ("i64::MIN", json!(i64::MIN)),
        // First integer an IEEE-754 double cannot represent: JavaScript backends round it to
        // 2^53 without an error, which breaks ID and amount comparisons.
        ("2^53+1", json!(9_007_199_254_740_993_i64)),
        ("\"NaN\"", json!("NaN")),
        ("\"Infinity\"", json!("Infinity")),
        ("\"-Infinity\"", json!("-Infinity")),
    ]
}

fn confusions(own: Kind) -> Vec<(&'static str, Value)> {
    [
        (Kind::Array, "[]", json!([])),
        (Kind::Object, "{}", json!({})),
        (Kind::Bool, "true", json!(true)),
        (Kind::Number, "1", json!(1)),
        (Kind::String, "\"1\"", json!("1")),
    ]
    .into_iter()
    .filter(|(kind, ..)| *kind != own)
    .map(|(_, label, value)| (label, value))
    .collect()
}

/// Expands `base` into the ordered case list for `classes` (assumed sorted and unique).
pub fn generate(base: &Map<String, Value>, classes: &[MutationClass]) -> Vec<Case> {
    let fields = collect_fields(base);
    let mut cases = Vec::new();
    let field_case = |class, field: &Field, label: &str, value: Option<Value>| Case {
        class,
        label: match value {
            Some(_) => format!("{} = {label}", field.pointer),
            None => format!("omit {}", field.pointer),
        },
        pointer: Some(field.pointer.clone()),
        body: Bytes::from(encode(&mutate(base, &field.path, value))),
    };

    for &class in classes {
        match class {
            MutationClass::NullInjection => {
                for field in fields.iter().filter(|f| f.kind != Kind::Null) {
                    cases.push(field_case(class, field, "null", Some(Value::Null)));
                }
            }
            MutationClass::EmptyStrings => {
                for field in fields.iter().filter(|f| !f.empty_string) {
                    cases.push(field_case(class, field, "\"\"", Some(json!(""))));
                }
            }
            MutationClass::BoundaryNumbers => {
                for field in fields.iter().filter(|f| f.kind == Kind::Number) {
                    for (label, value) in boundary_values() {
                        cases.push(field_case(class, field, label, Some(value)));
                    }
                }
            }
            MutationClass::TypeConfusion => {
                for field in &fields {
                    for (label, value) in confusions(field.kind) {
                        cases.push(field_case(class, field, label, Some(value)));
                    }
                }
                let mut array = b"[".to_vec();
                array.extend(encode(base));
                array.push(b']');
                cases.push(whole(class, "root = array", None, array));
            }
            MutationClass::OversizedField => {
                let oversized = "A".repeat(OVERSIZED_LEN);
                for field in fields.iter().filter(|f| f.kind == Kind::String) {
                    cases.push(field_case(
                        class,
                        field,
                        "64 KiB string",
                        Some(json!(oversized)),
                    ));
                }
                let mut padded = base.clone();
                padded.insert(PAD_FIELD.to_owned(), json!(oversized));
                cases.push(whole(
                    class,
                    &format!("+/{PAD_FIELD} = 64 KiB string"),
                    Some(format!("/{PAD_FIELD}")),
                    encode(&padded),
                ));
            }
            MutationClass::MalformedJson => cases.extend(malformed(base)),
            MutationClass::MissingFields => {
                for field in &fields {
                    cases.push(field_case(class, field, "", None));
                }
                cases.push(whole(class, "empty object", None, b"{}".to_vec()));
            }
        }
    }
    cases.truncate(MAX_CASES);
    cases
}

fn whole(class: MutationClass, label: &str, pointer: Option<String>, body: Vec<u8>) -> Case {
    Case {
        class,
        label: label.to_owned(),
        pointer,
        body: Bytes::from(body),
    }
}

fn malformed(base: &Map<String, Value>) -> Vec<Case> {
    let class = MutationClass::MalformedJson;
    let text = String::from_utf8(encode(base)).unwrap_or_default();
    let mut cases = Vec::new();

    let mut half = text.len() / 2;
    while !text.is_char_boundary(half) {
        half -= 1;
    }
    cases.push(whole(
        class,
        "truncated at 50%",
        None,
        text.as_bytes()[..half].to_vec(),
    ));
    if let Some(open) = text.strip_suffix('}') {
        cases.push(whole(
            class,
            "missing closing brace",
            None,
            open.as_bytes().to_vec(),
        ));
        if !base.is_empty() {
            cases.push(whole(
                class,
                "trailing comma",
                None,
                format!("{open},}}").into_bytes(),
            ));
        }
    }
    cases.push(whole(
        class,
        "single-quoted strings",
        None,
        text.replace('"', "'").into_bytes(),
    ));
    if !base.is_empty() {
        let entries: Vec<String> = base
            .iter()
            .map(|(key, value)| {
                format!("{key}:{}", serde_json::to_string(value).unwrap_or_default())
            })
            .collect();
        cases.push(whole(
            class,
            "unquoted keys",
            None,
            format!("{{{}}}", entries.join(",")).into_bytes(),
        ));
    }
    if let Some(key) = base.keys().next() {
        let path = [key.clone()];
        cases.push(whole(
            class,
            &format!("bare NaN at {}", pointer(&path)),
            Some(pointer(&path)),
            splice(base, &path, b"NaN"),
        ));
    }
    cases.push(whole(class, "empty body", None, Vec::new()));

    // `C3 28`: a two-byte UTF-8 lead followed by a byte that is not a continuation.
    let utf8_key = base
        .iter()
        .find(|(_, value)| value.is_string())
        .map_or(UTF8_FIELD, |(key, _)| key.as_str());
    let path = [utf8_key.to_owned()];
    cases.push(whole(
        class,
        &format!("invalid UTF-8 at {}", pointer(&path)),
        Some(pointer(&path)),
        splice(base, &path, b"\"\xC3\x28\""),
    ));
    cases
}

// ---- execution ------------------------------------------------------------------------

struct Plan {
    template: RequestTemplate,
    content_type: bool,
    timeout: Duration,
    connect_timeout: Duration,
    base: Bytes,
    fields: u32,
    classes: Vec<MutationClass>,
    cases: Vec<Case>,
}

impl Plan {
    fn request(&self, index: u32, body: Bytes) -> Request<Full<Bytes>> {
        let mut request = self.template.request(body);
        let headers = request.headers_mut();
        if self.content_type {
            headers.insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            );
        }
        headers
            .entry(header::USER_AGENT)
            .or_insert(HeaderValue::from_static(USER_AGENT));
        headers.insert(header::CONNECTION, HeaderValue::from_static("close"));
        headers.insert(
            HeaderName::from_static(CASE_HEADER),
            HeaderValue::from(index),
        );
        request
    }
}

fn prepare(spec: &FuzzSpec) -> EngineResult<Plan> {
    if spec.timeout_ms == 0 || spec.timeout_ms > MAX_TIMEOUT_MS {
        return Err(invalid(
            "timeoutMs",
            format!("must be between 1 and {MAX_TIMEOUT_MS}"),
        ));
    }
    let template = RequestTemplate::new(&spec.target, spec.method, &spec.headers, invalid)?;

    let base = match spec.base_body.as_deref().map(str::trim) {
        None | Some("") => default_template(),
        Some(text) if text.len() > MAX_BASE_BYTES => {
            return Err(invalid(
                "baseBody",
                format!("exceeds {MAX_BASE_BYTES} bytes"),
            ))
        }
        Some(text) => match serde_json::from_str::<Value>(text) {
            Ok(Value::Object(map)) => map,
            Ok(_) => return Err(invalid("baseBody", "must be a JSON object".to_owned())),
            Err(err) => return Err(invalid("baseBody", format!("not valid JSON: {err}"))),
        },
    };
    let fields = collect_fields(&base).len();
    if fields > MAX_FIELDS {
        return Err(invalid(
            "baseBody",
            format!("{fields} fields including nested ones; the limit is {MAX_FIELDS}"),
        ));
    }

    let mut classes = if spec.classes.is_empty() {
        ALL_CLASSES.to_vec()
    } else {
        spec.classes.clone()
    };
    classes.sort_unstable();
    classes.dedup();

    Ok(Plan {
        content_type: !template.has_header(&header::CONTENT_TYPE),
        template,
        timeout: Duration::from_millis(u64::from(spec.timeout_ms)),
        connect_timeout: CONNECT_TIMEOUT,
        base: Bytes::from(encode(&base)),
        fields: count_u32(fields),
        cases: generate(&base, &classes),
        classes,
    })
}

enum Outcome {
    Response {
        status: u16,
        bytes: u64,
        preview: Vec<u8>,
        latency_us: u64,
    },
    Transport {
        error: String,
        latency_us: u64,
    },
    Unreachable {
        error: String,
    },
}

async fn send(plan: &Plan, index: u32, body: Bytes) -> Outcome {
    let opened =
        tokio::time::timeout(plan.connect_timeout, http1::open(&plan.template.target)).await;
    let mut sender = match opened {
        Ok(Ok(sender)) => sender,
        Ok(Err(OpenError::Connect(err))) => {
            return Outcome::Unreachable {
                error: err.to_string(),
            }
        }
        // The listener accepted, so the service is up but broke the handshake.
        Ok(Err(err)) => {
            return Outcome::Transport {
                error: err.to_string(),
                latency_us: 0,
            }
        }
        Err(_) => {
            return Outcome::Unreachable {
                error: format!(
                    "connect timed out after {} ms",
                    plan.connect_timeout.as_millis()
                ),
            }
        }
    };

    let started = Instant::now();
    let exchange = http1::exchange(&mut sender, plan.request(index, body), PREVIEW_BYTES);
    match tokio::time::timeout(plan.timeout, exchange).await {
        Ok(Ok(received)) => Outcome::Response {
            status: received.status,
            bytes: received.bytes,
            preview: received.preview,
            latency_us: net::elapsed_us(started),
        },
        Ok(Err(err)) => Outcome::Transport {
            error: if err.is_connection_abort() {
                format!("connection aborted by peer: {err}")
            } else {
                err.to_string()
            },
            latency_us: net::elapsed_us(started),
        },
        Err(_) => Outcome::Transport {
            error: format!("no response within {} ms", plan.timeout.as_millis()),
            latency_us: net::elapsed_us(started),
        },
    }
}

fn classify(
    class: Option<MutationClass>,
    outcome: &Outcome,
    disclosed: bool,
) -> (FuzzVerdict, Option<Severity>) {
    let (verdict, severity) = match outcome {
        Outcome::Response { status, .. } if *status >= 500 => {
            (FuzzVerdict::ServerError, Some(Severity::Fault))
        }
        Outcome::Response { status, .. } if *status >= 400 => (FuzzVerdict::Rejected, None),
        // A structurally invalid body taken as valid: the service parses leniently or never
        // reads the body. Other accepted mutations may be legitimate input.
        Outcome::Response { .. } => (
            FuzzVerdict::Accepted,
            (class == Some(MutationClass::MalformedJson)).then_some(Severity::Warn),
        ),
        Outcome::Transport { .. } => (FuzzVerdict::TransportFailure, Some(Severity::Fault)),
        Outcome::Unreachable { .. } => (FuzzVerdict::Unreachable, None),
    };
    // A trace inside a 4xx is still a leak: validation rejected the payload, but only after
    // the exception reached the response serializer.
    let severity = severity.or(disclosed.then_some(Severity::Warn));
    // The baseline is context for the mutations, not a finding of its own.
    (verdict, if class.is_none() { None } else { severity })
}

fn to_result(
    index: u32,
    class: Option<MutationClass>,
    label: &str,
    pointer: Option<String>,
    request_bytes: usize,
    outcome: &Outcome,
) -> FuzzCaseResult {
    let preview = match outcome {
        Outcome::Response { preview, .. } if !preview.is_empty() => {
            Some(String::from_utf8_lossy(preview).into_owned())
        }
        _ => None,
    };
    let disclosure = preview.as_deref().and_then(disclosure::detect);
    let (verdict, severity) = classify(class, outcome, disclosure.is_some());
    let mut result = FuzzCaseResult {
        index,
        class,
        label: label.to_owned(),
        pointer,
        request_bytes: u64::try_from(request_bytes).unwrap_or(u64::MAX),
        status: None,
        latency_us: 0,
        response_bytes: 0,
        response_preview: preview,
        verdict,
        severity,
        disclosure,
        error: None,
    };
    match outcome {
        Outcome::Response {
            status,
            bytes,
            latency_us,
            ..
        } => {
            result.status = Some(*status);
            result.response_bytes = *bytes;
            result.latency_us = *latency_us;
        }
        Outcome::Transport { error, latency_us } => {
            result.error = Some(error.clone());
            result.latency_us = *latency_us;
        }
        Outcome::Unreachable { error } => result.error = Some(error.clone()),
    }
    result
}

fn skipped(index: u32, case: &Case) -> FuzzCaseResult {
    FuzzCaseResult {
        index,
        class: Some(case.class),
        label: case.label.clone(),
        pointer: case.pointer.clone(),
        request_bytes: u64::try_from(case.body.len()).unwrap_or(u64::MAX),
        status: None,
        latency_us: 0,
        response_bytes: 0,
        response_preview: None,
        verdict: FuzzVerdict::Skipped,
        severity: None,
        disclosure: None,
        error: None,
    }
}

async fn execute(
    plan: &Plan,
    method: BurstMethod,
    hub: &TelemetryHub,
    cancel: &AtomicBool,
) -> FuzzReport {
    let id = Uuid::new_v4();
    let started = Instant::now();
    let total = count_u32(plan.cases.len());
    hub.publish(TelemetryEvent::FuzzerStarted {
        seq: hub.next_seq(),
        id,
        ts_us: now_us(),
        target: plan.template.label.clone(),
        method,
        cases: total,
    });
    tracing::info!(%id, target = %plan.template.label, cases = total, "fuzzer suite started");
    let emit = |result: &FuzzCaseResult| {
        hub.publish(TelemetryEvent::FuzzerCaseCompleted {
            seq: hub.next_seq(),
            id,
            ts_us: now_us(),
            result: result.clone(),
        });
    };

    let outcome = send(plan, 0, plan.base.clone()).await;
    let baseline = to_result(0, None, "baseline", None, plan.base.len(), &outcome);
    emit(&baseline);

    let mut notes = Vec::new();
    let mut aborted = None;
    match (baseline.verdict, baseline.status) {
        (FuzzVerdict::Unreachable, _) => {
            aborted = Some(format!(
                "baseline request could not connect: {}",
                baseline.error.as_deref().unwrap_or("unknown error")
            ));
        }
        (_, Some(status)) if status >= 500 => notes.push(format!(
            "baseline returned {status}; faults below may not be caused by their mutation"
        )),
        (_, Some(status)) if status >= 400 => notes.push(format!(
            "baseline was rejected with {status}; mutations exercise validation order rather than field handling"
        )),
        (_, None) => notes.push(format!(
            "baseline request failed: {}",
            baseline.error.as_deref().unwrap_or("unknown error")
        )),
        _ => {}
    }
    if let Some(disclosure) = &baseline.disclosure {
        notes.push(format!(
            "baseline response already discloses internals ({}); disclosures below may not be caused by their mutation",
            disclosure.evidence
        ));
    }

    let mut results: Vec<FuzzCaseResult> = Vec::with_capacity(plan.cases.len());
    let mut unreachable_streak = 0u32;
    let mut last_connected: Option<usize> = None;
    for (offset, case) in plan.cases.iter().enumerate() {
        let index = count_u32(offset + 1);
        if aborted.is_none() && cancel.load(Ordering::SeqCst) {
            aborted = Some("cancelled by operator".to_owned());
        }
        if aborted.is_some() {
            results.push(skipped(index, case));
            continue;
        }

        let outcome = send(plan, index, case.body.clone()).await;
        let result = to_result(
            index,
            Some(case.class),
            &case.label,
            case.pointer.clone(),
            case.body.len(),
            &outcome,
        );
        emit(&result);
        if result.verdict == FuzzVerdict::Unreachable {
            unreachable_streak += 1;
            if unreachable_streak >= UNREACHABLE_LIMIT {
                aborted = Some(match last_connected.and_then(|at| results.get(at)) {
                    Some(last) => format!("target unreachable after case #{}", last.index),
                    None => "target unreachable after the baseline request".to_owned(),
                });
                // The last payload that reached the service is the likeliest crash trigger.
                if let Some(last) = last_connected.and_then(|at| results.get_mut(at)) {
                    last.severity = Some(Severity::Fault);
                    let blame = "target stopped accepting connections after this case";
                    last.error = Some(match last.error.take() {
                        Some(error) => format!("{error}; {blame}"),
                        None => blame.to_owned(),
                    });
                }
            }
        } else {
            unreachable_streak = 0;
            last_connected = Some(results.len());
        }
        results.push(result);
    }

    let summary = summarize(&plan.classes, &results);
    let faults = count_u32(
        results
            .iter()
            .filter(|r| r.severity == Some(Severity::Fault))
            .count(),
    );
    let warnings = count_u32(
        results
            .iter()
            .filter(|r| r.severity == Some(Severity::Warn))
            .count(),
    );
    let disclosures = count_u32(results.iter().filter(|r| r.disclosure.is_some()).count());
    let wall_us = net::elapsed_us(started);
    hub.publish(TelemetryEvent::FuzzerCompleted {
        seq: hub.next_seq(),
        id,
        ts_us: now_us(),
        wall_us,
        cases: total,
        faults,
        warnings,
        disclosures,
        aborted: aborted.clone(),
    });
    tracing::info!(%id, wall_us, faults, warnings, disclosures, aborted = ?aborted, "fuzzer suite completed");

    FuzzReport {
        id,
        target: plan.template.label.clone(),
        method,
        fields: plan.fields,
        wall_us,
        baseline,
        cases: results,
        summary,
        faults,
        warnings,
        disclosures,
        aborted,
        notes,
    }
}

fn summarize(classes: &[MutationClass], results: &[FuzzCaseResult]) -> Vec<ClassSummary> {
    classes
        .iter()
        .map(|&class| {
            let mut summary = ClassSummary {
                class,
                cases: 0,
                rejected: 0,
                accepted: 0,
                faults: 0,
                unreached: 0,
            };
            for result in results.iter().filter(|r| r.class == Some(class)) {
                summary.cases += 1;
                match result.verdict {
                    FuzzVerdict::Rejected => summary.rejected += 1,
                    FuzzVerdict::Accepted => summary.accepted += 1,
                    FuzzVerdict::ServerError | FuzzVerdict::TransportFailure => summary.faults += 1,
                    FuzzVerdict::Unreachable | FuzzVerdict::Skipped => summary.unreached += 1,
                }
            }
            summary
        })
        .collect()
}

fn count_u32(n: usize) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
}

fn invalid(field: &'static str, reason: String) -> EngineError {
    EngineError::InvalidFuzzSpec { field, reason }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::io;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::sync::atomic::AtomicUsize;
    use std::sync::Arc;

    use axum::http::Response;
    use http_body_util::BodyExt;
    use hyper::body::Incoming;
    use hyper::service::service_fn;
    use hyper_util::rt::TokioIo;
    use tokio::net::TcpListener;

    use super::*;
    use crate::engine::types::DisclosureKind;

    fn spec(target: String) -> FuzzSpec {
        FuzzSpec {
            target,
            method: BurstMethod::Post,
            headers: Vec::new(),
            base_body: None,
            classes: Vec::new(),
            timeout_ms: 5_000,
        }
    }

    fn cases_of(class: MutationClass) -> Vec<Case> {
        generate(&default_template(), &[class])
    }

    fn body_of<'a>(cases: &'a [Case], label: &str) -> &'a [u8] {
        &cases
            .iter()
            .find(|case| case.label == label)
            .unwrap_or_else(|| panic!("no case labelled {label}"))
            .body
    }

    #[test]
    fn default_template_case_counts() {
        let counts: Vec<(MutationClass, usize)> = ALL_CLASSES
            .iter()
            .map(|&class| (class, cases_of(class).len()))
            .collect();
        assert_eq!(
            counts,
            vec![
                (MutationClass::NullInjection, 8),
                (MutationClass::EmptyStrings, 8),
                (MutationClass::BoundaryNumbers, 16),
                (MutationClass::TypeConfusion, 33),
                (MutationClass::OversizedField, 4),
                (MutationClass::MalformedJson, 8),
                (MutationClass::MissingFields, 9),
            ]
        );
        assert_eq!(generate(&default_template(), &ALL_CLASSES).len(), 86);
    }

    #[test]
    fn generation_is_deterministic_and_keeps_field_order() {
        let base = default_template();
        assert_eq!(generate(&base, &ALL_CLASSES), generate(&base, &ALL_CLASSES));

        let ordered: Map<String, Value> = serde_json::from_str(r#"{"z":1,"a":{"b":"x"}}"#).unwrap();
        let cases = generate(
            &ordered,
            &[MutationClass::NullInjection, MutationClass::MissingFields],
        );
        assert_eq!(body_of(&cases, "/z = null"), br#"{"z":null,"a":{"b":"x"}}"#);
        assert_eq!(body_of(&cases, "/a/b = null"), br#"{"z":1,"a":{"b":null}}"#);
        assert_eq!(body_of(&cases, "omit /z"), br#"{"a":{"b":"x"}}"#);
    }

    #[test]
    fn boundary_numbers_serialize_exactly() {
        let cases = cases_of(MutationClass::BoundaryNumbers);
        let text = |label| String::from_utf8(body_of(&cases, label).to_vec()).unwrap();
        assert!(text("/quantity = i64::MAX").contains(r#""quantity":9223372036854775807"#));
        assert!(text("/quantity = i64::MIN").contains(r#""quantity":-9223372036854775808"#));
        assert!(text("/quantity = 2^53+1").contains(r#""quantity":9007199254740993"#));
        assert!(text("/id = \"NaN\"").contains(r#""id":"NaN""#));
        assert!(cases.iter().all(|case| case
            .pointer
            .as_deref()
            .is_some_and(|p| p == "/id" || p == "/quantity")));
    }

    #[test]
    fn type_confusion_excludes_the_original_type() {
        let cases = cases_of(MutationClass::TypeConfusion);
        let labels: Vec<&str> = cases
            .iter()
            .filter(|case| case.pointer.as_deref() == Some("/quantity"))
            .map(|case| case.label.as_str())
            .collect();
        assert_eq!(
            labels,
            [
                "/quantity = []",
                "/quantity = {}",
                "/quantity = true",
                "/quantity = \"1\""
            ]
        );
        assert!(body_of(&cases, "root = array").starts_with(b"[{"));
    }

    #[test]
    fn malformed_bodies_never_parse() {
        let cases = cases_of(MutationClass::MalformedJson);
        for case in &cases {
            assert!(
                serde_json::from_slice::<Value>(&case.body).is_err(),
                "{} parsed: {:?}",
                case.label,
                String::from_utf8_lossy(&case.body)
            );
        }
        let utf8 = body_of(&cases, "invalid UTF-8 at /name");
        assert!(std::str::from_utf8(utf8).is_err());
        assert!(utf8.windows(2).any(|pair| pair == [0xC3, 0x28]));
        assert!(body_of(&cases, "bare NaN at /id").starts_with(br#"{"id":NaN,"#));
        assert!(body_of(&cases, "empty body").is_empty());
    }

    #[test]
    fn oversized_fields_and_pointer_escaping() {
        let cases = cases_of(MutationClass::OversizedField);
        assert!(cases.iter().all(|case| case.body.len() > OVERSIZED_LEN));
        assert_eq!(
            cases.last().unwrap().pointer.as_deref(),
            Some("/chaosproxyPad")
        );
        assert_eq!(pointer(&["a/b".to_owned(), "c~d".to_owned()]), "/a~1b/c~0d");
    }

    #[test]
    fn spec_validation_happens_before_any_socket() {
        let code = |s: FuzzSpec| prepare(&s).err().unwrap().code();
        assert_eq!(
            code(spec("http://192.168.1.10:8080/orders".into())),
            "NON_LOOPBACK_TARGET_REJECTED"
        );
        assert_eq!(
            code(spec("http://example.com/orders".into())),
            "NON_LOOPBACK_TARGET_REJECTED"
        );
        assert_eq!(
            code(spec("https://127.0.0.1/orders".into())),
            "PLAINTEXT_ONLY"
        );
        let mut bad = spec("http://127.0.0.1:1/x".into());
        bad.timeout_ms = 0;
        assert_eq!(code(bad.clone()), "INVALID_FUZZ_SPEC");
        bad.timeout_ms = 1_000;
        bad.base_body = Some("[1, 2]".into());
        assert_eq!(code(bad.clone()), "INVALID_FUZZ_SPEC");
        bad.base_body = Some("{\"a\":".into());
        assert_eq!(code(bad.clone()), "INVALID_FUZZ_SPEC");
        let wide: Map<String, Value> = (0..49).map(|i| (format!("f{i}"), json!(i))).collect();
        bad.base_body = Some(serde_json::to_string(&wide).unwrap());
        assert_eq!(code(bad.clone()), "INVALID_FUZZ_SPEC");
        bad.base_body = Some("   ".into());
        assert!(prepare(&bad).is_ok());
        bad.headers = vec![crate::engine::types::HeaderPair {
            name: "Content-Length".into(),
            value: "1".into(),
        }];
        assert_eq!(code(bad), "INVALID_FUZZ_SPEC");
    }

    // ---- integration -------------------------------------------------------------------

    type Handler = fn(usize, Bytes) -> Result<(u16, &'static str), io::Error>;

    /// Raw hyper server: a handler error closes the connection without a response, which
    /// is how a crashing request handler looks to the client.
    async fn serve(handler: Handler, stop_after: Option<usize>) -> SocketAddr {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let connections = Arc::new(AtomicUsize::new(0));
        tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let n = connections.fetch_add(1, Ordering::SeqCst) + 1;
                tokio::spawn(async move {
                    let service =
                        service_fn(move |req: axum::http::Request<Incoming>| async move {
                            let body = req
                                .into_body()
                                .collect()
                                .await
                                .map_err(io::Error::other)?
                                .to_bytes();
                            let (status, text) = handler(n, body)?;
                            Ok::<_, io::Error>(
                                Response::builder()
                                    .status(status)
                                    .body(Full::new(Bytes::from(text)))
                                    .unwrap(),
                            )
                        });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                });
                if stop_after.is_some_and(|limit| n >= limit) {
                    break;
                }
            }
        });
        addr
    }

    fn orders(_: usize, body: Bytes) -> Result<(u16, &'static str), io::Error> {
        if body.len() > 32 * 1024 {
            return Err(io::Error::other("payload too large for the test service"));
        }
        let Ok(value) = serde_json::from_slice::<Value>(&body) else {
            return Ok((400, "malformed json"));
        };
        let Some(object) = value.as_object() else {
            return Ok((422, "expected object"));
        };
        if object.get("name").is_some_and(Value::is_null) {
            return Ok((500, "TypeError: Cannot read properties of null (reading 'trim')\n    at createOrder (/srv/orders.js:42:17)"));
        }
        match object.get("quantity").and_then(Value::as_i64) {
            Some(quantity) if (1..=1000).contains(&quantity) => Ok((201, "created")),
            _ => Ok((422, "quantity out of range")),
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn full_suite_against_a_validating_service() {
        let addr = serve(orders, None).await;
        let hub = TelemetryHub::new();
        let mut events = hub.subscribe();
        let slot = FuzzerSlot::default();

        let report = run(spec(format!("http://{addr}/orders")), &hub, &slot)
            .await
            .unwrap();

        assert_eq!(report.baseline.status, Some(201));
        assert_eq!(report.cases.len(), 86);
        assert_eq!(report.fields, 8);
        assert_eq!(report.aborted, None);
        assert!(report.notes.is_empty(), "{:?}", report.notes);
        assert_eq!(
            report.faults,
            5,
            "{:#?}",
            report
                .cases
                .iter()
                .filter(|c| c.severity.is_some())
                .collect::<Vec<_>>()
        );
        assert_eq!(report.warnings, 0);

        let null_name = report
            .cases
            .iter()
            .find(|c| c.label == "/name = null")
            .unwrap();
        assert_eq!(null_name.verdict, FuzzVerdict::ServerError);
        assert_eq!(null_name.severity, Some(Severity::Fault));
        assert!(null_name
            .response_preview
            .as_deref()
            .unwrap()
            .contains("TypeError"));
        let leak = null_name.disclosure.as_ref().unwrap();
        assert_eq!(leak.kind, DisclosureKind::NodeStackTrace);
        assert_eq!(leak.evidence, "at createOrder (/srv/orders.js:42:17)");
        assert_eq!(report.disclosures, 1);

        for case in report
            .cases
            .iter()
            .filter(|c| c.class == Some(MutationClass::OversizedField))
        {
            assert_eq!(
                case.verdict,
                FuzzVerdict::TransportFailure,
                "{}",
                case.label
            );
            assert!(
                case.error.as_deref().unwrap().contains("aborted"),
                "{:?}",
                case.error
            );
        }
        let malformed = report
            .summary
            .iter()
            .find(|s| s.class == MutationClass::MalformedJson)
            .unwrap();
        assert_eq!((malformed.cases, malformed.rejected), (8, 8));

        let mut kinds = (0, 0, 0);
        while let Ok(event) = events.try_recv() {
            match event {
                TelemetryEvent::FuzzerStarted { cases, .. } => {
                    assert_eq!(cases, 86);
                    kinds.0 += 1;
                }
                TelemetryEvent::FuzzerCaseCompleted { .. } => kinds.1 += 1,
                TelemetryEvent::FuzzerCompleted { faults, .. } => {
                    assert_eq!(faults, 5);
                    kinds.2 += 1;
                }
                _ => {}
            }
        }
        assert_eq!(kinds, (1, 87, 1));
    }

    /// Express default error handler in development mode: malformed JSON is rejected with
    /// 400, but the body-parser stack trace is serialized into the response.
    fn leaky_parser(_: usize, body: Bytes) -> Result<(u16, &'static str), io::Error> {
        if serde_json::from_slice::<Value>(&body).is_ok() {
            return Ok((201, "created"));
        }
        Ok((
            400,
            "SyntaxError: Unexpected token } in JSON at position 41\n    at JSON.parse (<anonymous>)\n    at parse (/srv/node_modules/body-parser/lib/types/json.js:92:19)",
        ))
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn stack_traces_in_rejections_are_warnings() {
        let addr = serve(leaky_parser, None).await;
        let hub = TelemetryHub::new();
        let mut events = hub.subscribe();
        let mut fuzz = spec(format!("http://{addr}/orders"));
        fuzz.classes = vec![MutationClass::MalformedJson, MutationClass::NullInjection];

        let report = run(fuzz, &hub, &FuzzerSlot::default()).await.unwrap();

        assert_eq!(report.baseline.disclosure, None);
        assert!(report.notes.is_empty(), "{:?}", report.notes);
        let malformed: Vec<&FuzzCaseResult> = report
            .cases
            .iter()
            .filter(|c| c.class == Some(MutationClass::MalformedJson))
            .collect();
        assert_eq!(malformed.len(), 8);
        for case in &malformed {
            assert_eq!(case.verdict, FuzzVerdict::Rejected, "{}", case.label);
            assert_eq!(case.severity, Some(Severity::Warn), "{}", case.label);
            let leak = case.disclosure.as_ref().unwrap();
            assert_eq!(leak.kind, DisclosureKind::NodeStackTrace);
            assert!(leak.evidence.contains("body-parser"), "{}", leak.evidence);
        }
        assert!(report
            .cases
            .iter()
            .filter(|c| c.class == Some(MutationClass::NullInjection))
            .all(|c| c.severity.is_none() && c.disclosure.is_none()));
        assert_eq!(
            (report.faults, report.warnings, report.disclosures),
            (0, 8, 8)
        );

        let mut completed = None;
        while let Ok(event) = events.try_recv() {
            if let TelemetryEvent::FuzzerCompleted { disclosures, .. } = event {
                completed = Some(disclosures);
            }
        }
        assert_eq!(completed, Some(8));
    }

    #[test]
    fn disclosure_raises_only_clean_mutation_cases() {
        let rejected = Outcome::Response {
            status: 422,
            bytes: 10,
            preview: Vec::new(),
            latency_us: 1,
        };
        let crashed = Outcome::Response {
            status: 500,
            bytes: 10,
            preview: Vec::new(),
            latency_us: 1,
        };
        let class = Some(MutationClass::NullInjection);
        assert_eq!(
            classify(class, &rejected, true),
            (FuzzVerdict::Rejected, Some(Severity::Warn))
        );
        assert_eq!(
            classify(class, &rejected, false),
            (FuzzVerdict::Rejected, None)
        );
        assert_eq!(
            classify(class, &crashed, true),
            (FuzzVerdict::ServerError, Some(Severity::Fault))
        );
        assert_eq!(
            classify(None, &rejected, true),
            (FuzzVerdict::Rejected, None)
        );
    }

    fn crash_on_third(n: usize, _: Bytes) -> Result<(u16, &'static str), io::Error> {
        Ok(if n == 3 {
            (500, "fatal: worker exited")
        } else {
            (200, "ok")
        })
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn aborts_when_the_target_stops_accepting_connections() {
        // Third connection (case #2) is answered, then the listener is gone.
        let addr = serve(crash_on_third, Some(3)).await;
        let hub = TelemetryHub::new();
        let mut fuzz = spec(format!("http://{addr}/orders"));
        fuzz.classes = vec![MutationClass::NullInjection];
        let mut plan = prepare(&fuzz).unwrap();
        plan.connect_timeout = Duration::from_millis(300);

        let report = execute(&plan, fuzz.method, &hub, &AtomicBool::new(false)).await;

        assert_eq!(
            report.aborted.as_deref(),
            Some("target unreachable after case #2")
        );
        let verdicts: Vec<FuzzVerdict> = report.cases.iter().map(|c| c.verdict).collect();
        assert_eq!(
            verdicts,
            [
                FuzzVerdict::Accepted,
                FuzzVerdict::ServerError,
                FuzzVerdict::Unreachable,
                FuzzVerdict::Unreachable,
                FuzzVerdict::Unreachable,
                FuzzVerdict::Skipped,
                FuzzVerdict::Skipped,
                FuzzVerdict::Skipped,
            ]
        );
        assert!(report.cases[1]
            .error
            .as_deref()
            .unwrap()
            .contains("stopped accepting connections"));
        assert_eq!(report.faults, 1);
        let null = &report.summary[0];
        assert_eq!(
            (null.cases, null.accepted, null.faults, null.unreached),
            (8, 1, 1, 6)
        );
    }

    fn slow(_: usize, _: Bytes) -> Result<(u16, &'static str), io::Error> {
        std::thread::sleep(Duration::from_millis(20));
        Ok((422, "rejected"))
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancel_skips_the_remaining_cases_and_busy_rejects_a_second_run() {
        let addr = serve(slow, None).await;
        let hub = TelemetryHub::new();
        let slot = FuzzerSlot::default();
        assert!(!slot.cancel());

        let target = format!("http://{addr}/orders");
        let (report, ()) = tokio::join!(run(spec(target.clone()), &hub, &slot), async {
            tokio::time::sleep(Duration::from_millis(150)).await;
            let busy = run(spec(target.clone()), &hub, &slot).await.unwrap_err();
            assert_eq!(busy.code(), "FUZZER_BUSY");
            assert!(slot.cancel());
        });
        let report = report.unwrap();

        assert_eq!(report.aborted.as_deref(), Some("cancelled by operator"));
        let skipped = report
            .cases
            .iter()
            .filter(|c| c.verdict == FuzzVerdict::Skipped)
            .count();
        assert!(skipped > 0 && skipped < 86, "skipped {skipped}");
        assert!(
            report.notes[0].contains("rejected with 422"),
            "{:?}",
            report.notes
        );
        assert!(!slot.cancel());
    }
}
