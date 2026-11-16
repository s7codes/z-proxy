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
use axum::http::{Request, Uri};
use http_body_util::Full;
use serde_json::{json, Map, Value};
use tokio::sync::Mutex;
use uuid::Uuid;

use super::contract;
use super::disclosure;
use super::error::{EngineError, EngineResult};
use super::http1::{self, OpenError, RequestTemplate, CONNECT_TIMEOUT};
use super::net;
use super::pathparam::{self, PathTemplate};
use super::types::{
    BurstMethod, ClassSummary, ContractViolation, FuzzCasePayload, FuzzCaseRef, FuzzCaseResult,
    FuzzReport, FuzzSpec, FuzzVerdict, MutationClass, ResponseContract, Severity, TelemetryEvent,
};
use crate::telemetry::{now_us, TelemetryHub};

pub const OVERSIZED_LEN: usize = 64 * 1024;
const MAX_TIMEOUT_MS: u32 = 60_000;
const MAX_BASE_BYTES: usize = 256 * 1024;
/// A field yields at most 16 cases across all per-field classes (a number: null, empty,
/// 8 boundaries, 4 confusions, omission, `1e309`; a string 13, five of them delimiter
/// values). 48 fields, the whole-body cases, 8
/// duplicate keys and 8 path slots of 7 values each keep every suite below `MAX_CASES`
/// without silently dropping mutations.
const MAX_FIELDS: usize = 48;
const MAX_DUPLICATE_KEYS: usize = 8;
const MAX_PATH_SLOTS: usize = 8;
/// Nesting depths for `SchemaContractBounds`: inside common parser limits (serde_json 128,
/// Python's recursion limit 1000), so the contract decides; and past them, so a recursive
/// parser or sanitizer runs out of stack.
const NEST_DEPTHS: [usize; 2] = [64, 1_024];
const NEST_FIELD: &str = "zproxyNest";
const EXTRA_FIELD: &str = "zproxyExtra";
/// A plausible privileged field: accepting it unvalidated is a mass-assignment risk.
const PRIVILEGE_FIELD: &str = "isAdmin";
/// Decimal digits of the overlong identifier: past `u64`, `f64` and most column widths.
const LONG_ID_DIGITS: usize = 4_096;
const MAX_DEPTH: usize = 3;
const MAX_CASES: usize = 1_024;
/// Long enough to hold the exception line and the first frames of a leaked trace, which is
/// where the disclosure signatures look.
const PREVIEW_BYTES: usize = 2 * 1024;
/// Consecutive connect failures that end a run: the target is down, not flaky.
const UNREACHABLE_LIMIT: u32 = 3;
const USER_AGENT: &str = concat!("z-proxy-fuzzer/", env!("CARGO_PKG_VERSION"));
const CASE_HEADER: &str = "x-zproxy-fuzz-case";
const PAD_FIELD: &str = "zproxyPad";
const UTF8_FIELD: &str = "zproxyUtf8";
/// Serialized in place of a field, then replaced byte-wise with content serde_json refuses
/// to emit (a bare `NaN`, invalid UTF-8).
const MARKER: &str = "__zproxy_marker_7f3a__";

const ALL_CLASSES: [MutationClass; 10] = [
    MutationClass::NullInjection,
    MutationClass::EmptyStrings,
    MutationClass::BoundaryNumbers,
    MutationClass::TypeConfusion,
    MutationClass::OversizedField,
    MutationClass::MalformedJson,
    MutationClass::MissingFields,
    MutationClass::SchemaContractBounds,
    MutationClass::PathParamValidation,
    MutationClass::DelimiterEscaping,
];

/// Values a correct service stores verbatim or refuses with a 4xx: a company name with an
/// apostrophe and ampersand, a product label with a double quote and backslash, a list
/// separator with parentheses, SQL `LIKE` / glob wildcards, and a combining accent followed
/// by a zero-width space. Each is plain catalogue text; a 5xx or a leaked driver error means
/// the value reached a string-built query, path or pattern unescaped. Labels spell the
/// invisible code points out.
const DELIMITER_VALUES: [(&str, &str); 5] = [
    ("\"O'Reilly & Sons\"", "O'Reilly & Sons"),
    (r#""15\" display \\ rev-2""#, "15\" display \\ rev-2"),
    ("\"item; category(1)\"", "item; category(1)"),
    ("\"100%_discount_*\"", "100%_discount_*"),
    ("\"cafe<U+0301><U+200B>test\"", "cafe\u{0301}\u{200B}test"),
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
    /// Origin-form target of a path case; `None` sends the suite target.
    pub path: Option<Uri>,
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
        "name": "z-proxy",
        "email": "fuzz@zproxy.invalid",
        "quantity": 1,
        "active": true,
        "tags": ["alpha"],
        "meta": { "source": "z-proxy" }
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
/// `path` supplies the slots for `PathParamValidation`; without it that class is empty.
pub fn generate(
    base: &Map<String, Value>,
    classes: &[MutationClass],
    path: Option<&PathTemplate>,
) -> Vec<Case> {
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
        path: None,
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
            MutationClass::SchemaContractBounds => cases.extend(contract_bounds(base, &fields)),
            MutationClass::PathParamValidation => {
                if let Some(path) = path {
                    cases.extend(path_cases(base, path));
                }
            }
            MutationClass::DelimiterEscaping => {
                for field in fields.iter().filter(|f| f.kind == Kind::String) {
                    for (label, value) in DELIMITER_VALUES {
                        cases.push(field_case(class, field, label, Some(json!(value))));
                    }
                }
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
        path: None,
    }
}

/// A value of the same JSON type that differs from `value`, so a duplicated key changes
/// meaning depending on which occurrence a parser keeps.
fn conflicting(value: &Value) -> Value {
    match value {
        Value::Null => json!(0),
        Value::Bool(flag) => json!(!flag),
        Value::Number(number) if number.as_i64() == Some(-1) => json!(0),
        Value::Number(_) => json!(-1),
        Value::String(text) if text.is_empty() => json!("1"),
        Value::String(_) => json!(""),
        Value::Array(items) if items.is_empty() => json!([null]),
        Value::Array(_) => json!([]),
        Value::Object(fields) if fields.is_empty() => json!({ EXTRA_FIELD: true }),
        Value::Object(_) => json!({}),
    }
}

/// Bodies that are valid JSON syntax but violate a strict schema. Raw splicing keeps what
/// `Map` cannot hold (a second occurrence of a key, a number outside `f64`).
fn contract_bounds(base: &Map<String, Value>, fields: &[Field]) -> Vec<Case> {
    let class = MutationClass::SchemaContractBounds;
    let encoded = encode(base);
    let mut cases = Vec::new();

    if let Some(open) = encoded.strip_suffix(b"}") {
        for (key, value) in base.iter().take(MAX_DUPLICATE_KEYS) {
            let conflict = conflicting(value);
            let entry = format!(
                ",{}:{}",
                serde_json::to_string(key).unwrap_or_default(),
                serde_json::to_string(&conflict).unwrap_or_default()
            );
            let path = [key.clone()];
            cases.push(whole(
                class,
                &format!("duplicate {} = {conflict}", pointer(&path)),
                Some(pointer(&path)),
                [open, entry.as_bytes(), b"}".as_slice()].concat(),
            ));
        }
    }

    let nest_path = [NEST_FIELD.to_owned()];
    for depth in NEST_DEPTHS {
        let chain = format!(
            "{}{{}}{}",
            r#"{"d":"#.repeat(depth - 1),
            "}".repeat(depth - 1)
        );
        cases.push(whole(
            class,
            &format!("+/{NEST_FIELD} = {depth} nested objects"),
            Some(pointer(&nest_path)),
            splice(base, &nest_path, chain.as_bytes()),
        ));
    }

    let mut extra = |path: Vec<String>, value: Value| {
        cases.push(whole(
            class,
            &format!("+{} = {value}", pointer(&path)),
            Some(pointer(&path)),
            encode(&mutate(base, &path, Some(value))),
        ));
    };
    extra(vec![EXTRA_FIELD.to_owned()], json!("unexpected"));
    if !base.contains_key(PRIVILEGE_FIELD) {
        extra(vec![PRIVILEGE_FIELD.to_owned()], json!(true));
    }
    if let Some((key, _)) = base.iter().find(|(_, value)| value.is_object()) {
        extra(
            vec![key.clone(), EXTRA_FIELD.to_owned()],
            json!("unexpected"),
        );
    }

    for field in fields.iter().filter(|f| f.kind == Kind::Number) {
        cases.push(whole(
            class,
            &format!("{} = 1e309", field.pointer),
            Some(field.pointer.clone()),
            splice(base, &field.path, b"1e309"),
        ));
    }
    cases
}

/// Each slot in turn takes boundary identifiers while the others keep the default. The body
/// is the base, so a difference from the baseline is attributable to the path alone.
fn path_cases(base: &Map<String, Value>, path: &PathTemplate) -> Vec<Case> {
    let body = Bytes::from(encode(base));
    let long = "9".repeat(LONG_ID_DIGITS);
    let values: [(&str, &str); 7] = [
        ("0", "0"),
        ("-1", "-1"),
        ("i64::MAX", "9223372036854775807"),
        ("i64::MAX+1", "9223372036854775808"),
        ("\"invalid-uuid\"", "invalid-uuid"),
        ("empty segment", ""),
        ("4 KiB of digits", long.as_str()),
    ];
    let mut cases = Vec::with_capacity(values.len() * path.params().len());
    for (slot, name) in path.params().iter().enumerate().take(MAX_PATH_SLOTS) {
        for (label, value) in values {
            // Literals come from a parsed URL and every value is unreserved ASCII, so this
            // only fails on a template the guard would not have produced; such a case is
            // left out rather than sent to the wrong path.
            let Ok(uri) = path.origin_form(slot, value).parse::<Uri>() else {
                continue;
            };
            cases.push(Case {
                class: MutationClass::PathParamValidation,
                label: format!("{{{name}}} = {label}"),
                pointer: None,
                body: body.clone(),
                path: Some(uri),
            });
        }
    }
    cases
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
    path_template: Option<PathTemplate>,
    content_type: bool,
    timeout: Duration,
    connect_timeout: Duration,
    base: Bytes,
    fields: u32,
    classes: Vec<MutationClass>,
    cases: Vec<Case>,
    contract: Option<ResponseContract>,
}

impl Plan {
    /// Body bytes kept per response: the disclosure preview, or the whole body (bounded) when
    /// a contract needs it parsed.
    fn capture_limit(&self) -> usize {
        if self.contract.is_some() {
            contract::MAX_BODY_BYTES
        } else {
            PREVIEW_BYTES
        }
    }

    fn request(&self, index: u32, body: Bytes, path: Option<&Uri>) -> Request<Full<Bytes>> {
        let mut request = match path {
            Some(uri) => self.template.request_at(uri, body),
            None => self.template.request(body),
        };
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
    let resolved = pathparam::resolve(&spec.target)?;
    let template = RequestTemplate::new(&resolved.target, spec.method, &spec.headers, invalid)?;
    let base = parse_base(spec.base_body.as_deref())?;
    let classes = normalize_classes(&spec.classes);

    Ok(Plan {
        content_type: !template.has_header(&header::CONTENT_TYPE),
        template,
        timeout: Duration::from_millis(u64::from(spec.timeout_ms)),
        connect_timeout: CONNECT_TIMEOUT,
        base: Bytes::from(encode(&base)),
        fields: count_u32(collect_fields(&base).len()),
        cases: generate(&base, &classes, resolved.template.as_ref()),
        path_template: resolved.template,
        classes,
        contract: spec.contract.clone(),
    })
}

fn parse_base(text: Option<&str>) -> EngineResult<Map<String, Value>> {
    let base = match text.map(str::trim) {
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
    Ok(base)
}

fn normalize_classes(requested: &[MutationClass]) -> Vec<MutationClass> {
    let mut classes = if requested.is_empty() {
        ALL_CLASSES.to_vec()
    } else {
        requested.to_vec()
    };
    classes.sort_unstable();
    classes.dedup();
    classes
}

/// Rebuilds the exact request body (and path, for path cases) of case `index` (0 is the
/// baseline) from the base body, classes and path template a report carries. Generation is
/// deterministic, so this is what was sent, without the report holding every payload.
pub fn materialize(reference: &FuzzCaseRef) -> EngineResult<FuzzCasePayload> {
    let base = parse_base(Some(&reference.base_body))?;
    let classes = normalize_classes(&reference.classes);
    let path_template = match reference.path_template.as_deref() {
        Some(text) => {
            PathTemplate::parse(text).map_err(|err| invalid("pathTemplate", err.to_string()))?
        }
        None => None,
    };
    let (label, body, path) = match reference.index {
        0 => ("baseline".to_owned(), encode(&base), None),
        index => {
            let offset = usize::try_from(index - 1).unwrap_or(usize::MAX);
            let mut cases = generate(&base, &classes, path_template.as_ref());
            let total = cases.len();
            if offset >= total {
                return Err(invalid(
                    "index",
                    format!("case #{index} does not exist; the suite has {total} cases"),
                ));
            }
            let case = cases.swap_remove(offset);
            (
                case.label,
                case.body.to_vec(),
                case.path.map(|uri| uri.to_string()),
            )
        }
    };
    let bytes = u64::try_from(body.len()).unwrap_or(u64::MAX);
    let (body, lossy) = match String::from_utf8(body) {
        Ok(text) => (text, false),
        Err(err) => (String::from_utf8_lossy(err.as_bytes()).into_owned(), true),
    };
    Ok(FuzzCasePayload {
        index: reference.index,
        label,
        path,
        body,
        bytes,
        lossy,
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

async fn send(plan: &Plan, index: u32, body: Bytes, path: Option<&Uri>) -> Outcome {
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
    let request = plan.request(index, body, path);
    let exchange = http1::exchange(&mut sender, request, plan.capture_limit());
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

/// `flagged`: the response leaked internals or broke the documented contract.
fn classify(
    class: Option<MutationClass>,
    outcome: &Outcome,
    flagged: bool,
) -> (FuzzVerdict, Option<Severity>) {
    let (verdict, severity) = match outcome {
        Outcome::Response { status, .. } if *status >= 500 => {
            (FuzzVerdict::ServerError, Some(Severity::Fault))
        }
        Outcome::Response { status, .. } if *status >= 400 => (FuzzVerdict::Rejected, None),
        // Accepting these is itself the finding: a structurally invalid body (lenient parser,
        // or the body is never read), a body outside the schema contract, or a boundary
        // identifier the route treated as valid. Other accepted mutations may be legitimate;
        // a delimiter value stored verbatim is the correct outcome.
        Outcome::Response { .. } => (
            FuzzVerdict::Accepted,
            matches!(
                class,
                Some(
                    MutationClass::MalformedJson
                        | MutationClass::SchemaContractBounds
                        | MutationClass::PathParamValidation
                )
            )
            .then_some(Severity::Warn),
        ),
        Outcome::Transport { .. } => (FuzzVerdict::TransportFailure, Some(Severity::Fault)),
        Outcome::Unreachable { .. } => (FuzzVerdict::Unreachable, None),
    };
    // A trace inside a 4xx is still a leak: validation rejected the payload, but only after
    // the exception reached the response serializer. An undocumented status or a drifted
    // body is a warning for the same reason: the payload was handled, but not as specified.
    let severity = severity.or(flagged.then_some(Severity::Warn));
    // The baseline is context for the mutations, not a finding of its own.
    (verdict, if class.is_none() { None } else { severity })
}

struct CaseMeta<'a> {
    index: u32,
    class: Option<MutationClass>,
    label: &'a str,
    pointer: Option<String>,
    request_bytes: usize,
}

fn to_result(
    meta: CaseMeta<'_>,
    outcome: &Outcome,
    contract: Option<&ResponseContract>,
) -> FuzzCaseResult {
    let CaseMeta {
        index,
        class,
        label,
        pointer,
        request_bytes,
    } = meta;
    let violations = match (contract, outcome) {
        (
            Some(contract),
            Outcome::Response {
                status,
                bytes,
                preview,
                ..
            },
        ) => {
            // A body longer than the capture limit was cut; its fields cannot be judged.
            let complete = usize::try_from(*bytes).is_ok_and(|total| total <= preview.len());
            contract::check(contract, *status, complete.then_some(preview.as_slice()))
        }
        _ => Vec::new(),
    };
    let preview = match outcome {
        Outcome::Response { preview, .. } if !preview.is_empty() => {
            let shown = &preview[..preview.len().min(PREVIEW_BYTES)];
            Some(String::from_utf8_lossy(shown).into_owned())
        }
        _ => None,
    };
    let disclosure = preview.as_deref().and_then(disclosure::detect);
    let flagged = disclosure.is_some() || !violations.is_empty();
    let (verdict, severity) = classify(class, outcome, flagged);
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
        violations,
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
        violations: Vec::new(),
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

    let outcome = send(plan, 0, plan.base.clone(), None).await;
    let baseline = to_result(
        CaseMeta {
            index: 0,
            class: None,
            label: "baseline",
            pointer: None,
            request_bytes: plan.base.len(),
        },
        &outcome,
        plan.contract.as_ref(),
    );
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
    if let Some(first) = baseline.violations.first() {
        notes.push(format!(
            "baseline response breaks the documented contract ({}); mutation cases inherit the drift",
            describe_violation(first)
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

        let outcome = send(plan, index, case.body.clone(), case.path.as_ref()).await;
        let result = to_result(
            CaseMeta {
                index,
                class: Some(case.class),
                label: &case.label,
                pointer: case.pointer.clone(),
                request_bytes: case.body.len(),
            },
            &outcome,
            plan.contract.as_ref(),
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
    let contract_violations = count_u32(
        std::iter::once(&baseline)
            .chain(results.iter())
            .filter(|r| !r.violations.is_empty())
            .count(),
    );
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
        violations: contract_violations,
        aborted: aborted.clone(),
    });
    tracing::info!(%id, wall_us, faults, warnings, disclosures, contract_violations, aborted = ?aborted, "fuzzer suite completed");

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
        contract_violations,
        aborted,
        notes,
        base_body: String::from_utf8_lossy(&plan.base).into_owned(),
        classes: plan.classes.clone(),
        path_template: plan.path_template.as_ref().map(ToString::to_string),
    }
}

fn describe_violation(violation: &ContractViolation) -> String {
    match &violation.pointer {
        Some(pointer) if pointer.is_empty() => {
            format!(
                "body: expected {}, got {}",
                violation.expected, violation.actual
            )
        }
        Some(pointer) => format!(
            "{pointer}: expected {}, got {}",
            violation.expected, violation.actual
        ),
        None => format!(
            "status {} not documented; {}",
            violation.actual, violation.expected
        ),
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
            contract: None,
        }
    }

    fn cases_of(class: MutationClass) -> Vec<Case> {
        generate(&default_template(), &[class], None)
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
                (MutationClass::SchemaContractBounds, 14),
                (MutationClass::PathParamValidation, 0),
                (MutationClass::DelimiterEscaping, 15),
            ]
        );
        assert_eq!(generate(&default_template(), &ALL_CLASSES, None).len(), 115);
    }

    #[test]
    fn generation_is_deterministic_and_keeps_field_order() {
        let base = default_template();
        let path = pathparam::resolve("http://127.0.0.1/orders/{id}")
            .unwrap()
            .template;
        assert_eq!(
            generate(&base, &ALL_CLASSES, path.as_ref()),
            generate(&base, &ALL_CLASSES, path.as_ref())
        );
        // Appended classes never shift the indices of earlier ones.
        let all = generate(&base, &ALL_CLASSES, path.as_ref());
        let original = &ALL_CLASSES[..7];
        assert_eq!(generate(&base, original, None)[..], all[..86]);
        let before_delimiters = generate(&base, &ALL_CLASSES[..9], path.as_ref());
        assert_eq!(before_delimiters[..], all[..before_delimiters.len()]);
        assert!(all[before_delimiters.len()..]
            .iter()
            .all(|case| case.class == MutationClass::DelimiterEscaping));

        let ordered: Map<String, Value> = serde_json::from_str(r#"{"z":1,"a":{"b":"x"}}"#).unwrap();
        let cases = generate(
            &ordered,
            &[MutationClass::NullInjection, MutationClass::MissingFields],
            None,
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
    fn delimiter_escaping_targets_string_fields_with_exact_values() {
        let cases = cases_of(MutationClass::DelimiterEscaping);
        let pointers: Vec<&str> = cases
            .iter()
            .filter_map(|case| case.pointer.as_deref())
            .collect();
        assert_eq!(pointers.len(), 15);
        assert!(pointers
            .iter()
            .all(|p| matches!(*p, "/name" | "/email" | "/meta/source")));

        let name_cases: Vec<&Case> = cases
            .iter()
            .filter(|case| case.pointer.as_deref() == Some("/name"))
            .collect();
        let labels: Vec<&str> = name_cases.iter().map(|c| c.label.as_str()).collect();
        assert_eq!(
            labels,
            [
                r#"/name = "O'Reilly & Sons""#,
                r#"/name = "15\" display \\ rev-2""#,
                r#"/name = "item; category(1)""#,
                r#"/name = "100%_discount_*""#,
                r#"/name = "cafe<U+0301><U+200B>test""#,
            ]
        );
        // Each body is valid JSON whose field decodes to the exact value; every other field
        // keeps the base value.
        for (case, (_, value)) in name_cases.iter().zip(DELIMITER_VALUES) {
            let parsed: Value = serde_json::from_slice(&case.body).unwrap();
            assert_eq!(parsed["name"], value, "{}", case.label);
            assert_eq!(parsed["email"], "fuzz@zproxy.invalid");
            assert_eq!(parsed["meta"]["source"], "z-proxy");
        }
        let wire =
            String::from_utf8(body_of(&cases, r#"/name = "15\" display \\ rev-2""#).to_vec())
                .unwrap();
        assert!(wire.contains(r#""name":"15\" display \\ rev-2""#), "{wire}");
        // The combining accent and the zero-width space travel as raw UTF-8: 13 bytes, 10
        // scalar values, so byte- and character-length checks disagree.
        let unicode: Value =
            serde_json::from_slice(body_of(&cases, r#"/name = "cafe<U+0301><U+200B>test""#))
                .unwrap();
        let text = unicode["name"].as_str().unwrap();
        assert_eq!((text.len(), text.chars().count()), (13, 10));

        let numeric: Map<String, Value> = serde_json::from_str(r#"{"qty":2,"ok":true}"#).unwrap();
        assert!(generate(&numeric, &[MutationClass::DelimiterEscaping], None).is_empty());
    }

    #[test]
    fn oversized_fields_and_pointer_escaping() {
        let cases = cases_of(MutationClass::OversizedField);
        assert!(cases.iter().all(|case| case.body.len() > OVERSIZED_LEN));
        assert_eq!(cases.last().unwrap().pointer.as_deref(), Some("/zproxyPad"));
        assert_eq!(pointer(&["a/b".to_owned(), "c~d".to_owned()]), "/a~1b/c~0d");
    }

    #[test]
    fn schema_contract_bounds_stay_valid_syntax_but_break_the_contract() {
        let cases = cases_of(MutationClass::SchemaContractBounds);
        let labels: Vec<&str> = cases.iter().map(|c| c.label.as_str()).collect();
        assert_eq!(
            labels,
            [
                "duplicate /id = -1",
                "duplicate /name = \"\"",
                "duplicate /email = \"\"",
                "duplicate /quantity = -1",
                "duplicate /active = false",
                "duplicate /tags = []",
                "duplicate /meta = {}",
                "+/zproxyNest = 64 nested objects",
                "+/zproxyNest = 1024 nested objects",
                "+/zproxyExtra = \"unexpected\"",
                "+/isAdmin = true",
                "+/meta/zproxyExtra = \"unexpected\"",
                "/id = 1e309",
                "/quantity = 1e309",
            ]
        );
        let text = |label| String::from_utf8(body_of(&cases, label).to_vec()).unwrap();

        let duplicate = text("duplicate /quantity = -1");
        assert!(duplicate.contains(r#""quantity":1,"#), "{duplicate}");
        assert!(duplicate.ends_with(r#","quantity":-1}"#), "{duplicate}");
        // A last-wins parser sees the second occurrence; a first-wins validator the first.
        let parsed: Value = serde_json::from_str(&duplicate).unwrap();
        assert_eq!(parsed["quantity"], -1);

        let nested: Value =
            serde_json::from_str(&text("+/zproxyNest = 64 nested objects")).unwrap();
        let mut levels = 1;
        let mut cursor = &nested["zproxyNest"];
        while let Some(next) = cursor.get("d") {
            levels += 1;
            cursor = next;
        }
        assert_eq!(levels, 64);
        let deep =
            serde_json::from_slice::<Value>(body_of(&cases, "+/zproxyNest = 1024 nested objects"));
        assert!(deep
            .unwrap_err()
            .to_string()
            .starts_with("recursion limit exceeded"));

        let overflow = text("/quantity = 1e309");
        assert!(overflow.contains(r#""quantity":1e309,"#), "{overflow}");
        let refused = serde_json::from_str::<Value>(&overflow).unwrap_err();
        assert!(
            refused.to_string().starts_with("number out of range"),
            "{refused}"
        );

        let nested_extra: Value =
            serde_json::from_str(&text("+/meta/zproxyExtra = \"unexpected\"")).unwrap();
        assert_eq!(nested_extra["meta"]["zproxyExtra"], "unexpected");
        assert_eq!(nested_extra["meta"]["source"], "z-proxy");
        assert!(cases.iter().all(|c| c.path.is_none()));

        let empty = generate(&Map::new(), &[MutationClass::SchemaContractBounds], None);
        let labels: Vec<&str> = empty.iter().map(|c| c.label.as_str()).collect();
        assert_eq!(
            labels,
            [
                "+/zproxyNest = 64 nested objects",
                "+/zproxyNest = 1024 nested objects",
                "+/zproxyExtra = \"unexpected\"",
                "+/isAdmin = true",
            ]
        );
    }

    #[test]
    fn path_cases_rewrite_one_slot_and_keep_the_base_body() {
        let template = pathparam::resolve("http://127.0.0.1:9/api/orders/{orderId}/lines/{line}")
            .unwrap()
            .template
            .unwrap();
        let base = default_template();
        let cases = generate(
            &base,
            &[MutationClass::PathParamValidation],
            Some(&template),
        );
        assert_eq!(cases.len(), 14);
        let path_of = |label: &str| {
            cases
                .iter()
                .find(|c| c.label == label)
                .unwrap_or_else(|| panic!("no case labelled {label}"))
                .path
                .as_ref()
                .unwrap()
                .to_string()
        };
        assert_eq!(path_of("{orderId} = 0"), "/api/orders/0/lines/1");
        assert_eq!(path_of("{orderId} = -1"), "/api/orders/-1/lines/1");
        assert_eq!(
            path_of("{orderId} = i64::MAX"),
            "/api/orders/9223372036854775807/lines/1"
        );
        assert_eq!(
            path_of("{orderId} = i64::MAX+1"),
            "/api/orders/9223372036854775808/lines/1"
        );
        assert_eq!(
            path_of("{line} = \"invalid-uuid\""),
            "/api/orders/1/lines/invalid-uuid"
        );
        assert_eq!(path_of("{line} = empty segment"), "/api/orders/1/lines/");
        assert_eq!(
            path_of("{orderId} = 4 KiB of digits").len(),
            "/api/orders//lines/1".len() + LONG_ID_DIGITS
        );
        let base_body = encode(&base);
        assert!(cases
            .iter()
            .all(|c| c.body == base_body && c.pointer.is_none()));
        assert!(generate(&base, &[MutationClass::PathParamValidation], None).is_empty());
    }

    #[test]
    fn materialize_returns_the_path_of_path_cases() {
        let fuzz = FuzzSpec {
            classes: vec![
                MutationClass::PathParamValidation,
                MutationClass::NullInjection,
            ],
            ..spec("http://127.0.0.1:9/api/orders/{orderId}".into())
        };
        let plan = prepare(&fuzz).unwrap();
        assert_eq!(plan.template.label, "http://127.0.0.1:9/api/orders/1");
        let path_template = plan.path_template.as_ref().map(ToString::to_string);
        assert_eq!(path_template.as_deref(), Some("/api/orders/{orderId}"));
        let reference = |index: u32| FuzzCaseRef {
            base_body: String::from_utf8(plan.base.to_vec()).unwrap(),
            classes: fuzz.classes.clone(),
            path_template: path_template.clone(),
            index,
        };
        // Null injection runs first (8 cases), then the 7 path cases.
        assert_eq!(plan.cases.len(), 15);
        let body_case = materialize(&reference(1)).unwrap();
        assert_eq!(body_case.path, None);
        let path_case = materialize(&reference(10)).unwrap();
        assert_eq!(path_case.label, "{orderId} = -1");
        assert_eq!(path_case.path.as_deref(), Some("/api/orders/-1"));
        assert_eq!(path_case.body.as_bytes(), &plan.base[..]);

        let mut unrooted = reference(10);
        unrooted.path_template = Some("api/orders/{orderId}".into());
        match materialize(&unrooted) {
            Err(EngineError::InvalidFuzzSpec { field, .. }) => assert_eq!(field, "pathTemplate"),
            other => panic!("expected pathTemplate rejection, got {other:?}"),
        }
        // Without the template the path cases do not exist.
        let mut bare = reference(10);
        bare.path_template = None;
        assert_eq!(materialize(&bare).unwrap_err().code(), "INVALID_FUZZ_SPEC");
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

    #[test]
    fn materialize_reproduces_every_case_byte_for_byte() {
        let mut fuzz = spec("http://127.0.0.1:9/orders".into());
        fuzz.base_body = Some(r#"{"name":"é","qty":2,"nested":{"k":"v"}}"#.into());
        // Deliberately unsorted: replay must normalize the order the same way the run did.
        fuzz.classes = vec![
            MutationClass::MissingFields,
            MutationClass::MalformedJson,
            MutationClass::NullInjection,
        ];
        let plan = prepare(&fuzz).unwrap();
        let base_body = String::from_utf8(plan.base.to_vec()).unwrap();
        let reference = |index: u32| FuzzCaseRef {
            base_body: base_body.clone(),
            classes: fuzz.classes.clone(),
            path_template: None,
            index,
        };

        let baseline = materialize(&reference(0)).unwrap();
        assert_eq!(baseline.label, "baseline");
        assert_eq!(baseline.body.as_bytes(), &plan.base[..]);

        for (offset, case) in plan.cases.iter().enumerate() {
            let payload = materialize(&reference(count_u32(offset + 1))).unwrap();
            assert_eq!(payload.label, case.label);
            assert_eq!(payload.bytes, u64::try_from(case.body.len()).unwrap());
            if payload.lossy {
                assert!(case.label.starts_with("invalid UTF-8"), "{}", case.label);
                assert!(payload.body.contains('\u{FFFD}'));
            } else {
                assert_eq!(payload.body.as_bytes(), &case.body[..], "{}", case.label);
            }
        }
        assert_eq!(
            plan.cases
                .iter()
                .enumerate()
                .filter(|(offset, _)| materialize(&reference(count_u32(offset + 1)))
                    .unwrap()
                    .lossy)
                .count(),
            1
        );

        let past_end = count_u32(plan.cases.len() + 1);
        match materialize(&reference(past_end)) {
            Err(EngineError::InvalidFuzzSpec { field, .. }) => assert_eq!(field, "index"),
            other => panic!("expected index rejection, got {other:?}"),
        }
        let mut broken = reference(1);
        broken.base_body = "[1]".into();
        assert_eq!(
            materialize(&broken).unwrap_err().code(),
            "INVALID_FUZZ_SPEC"
        );
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
        assert_eq!(report.cases.len(), 115);
        assert_eq!(report.fields, 8);
        assert_eq!(report.classes, ALL_CLASSES);
        assert_eq!(report.path_template, None);
        let replayed = materialize(&FuzzCaseRef {
            base_body: report.base_body.clone(),
            classes: report.classes.clone(),
            path_template: None,
            index: 1,
        })
        .unwrap();
        assert_eq!(replayed.label, report.cases[0].label);
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
        // Every contract case the service took: six duplicates whose last value it accepts,
        // the 64-level nest, and the three undeclared fields. The duplicate quantity (-1) is
        // rejected, and 1024 levels and 1e309 fail its parser with a 400.
        let warned: Vec<&str> = report
            .cases
            .iter()
            .filter(|c| c.severity == Some(Severity::Warn))
            .map(|c| c.label.as_str())
            .collect();
        assert_eq!(warned.len(), 10, "{warned:#?}");
        assert_eq!(report.warnings, 10);
        let contract = report
            .summary
            .iter()
            .find(|s| s.class == MutationClass::SchemaContractBounds)
            .unwrap();
        assert_eq!(
            (contract.cases, contract.accepted, contract.rejected),
            (14, 10, 4)
        );

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
        // The service stores delimiter values verbatim: accepted, and not a finding.
        let delimiters = report
            .summary
            .iter()
            .find(|s| s.class == MutationClass::DelimiterEscaping)
            .unwrap();
        assert_eq!(
            (delimiters.cases, delimiters.accepted, delimiters.faults),
            (15, 15, 0)
        );

        let mut kinds = (0, 0, 0);
        while let Ok(event) = events.try_recv() {
            match event {
                TelemetryEvent::FuzzerStarted { cases, .. } => {
                    assert_eq!(cases, 115);
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
        assert_eq!(kinds, (1, 116, 1));
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
        assert!(skipped > 0 && skipped < 115, "skipped {skipped}");
        assert!(
            report.notes[0].contains("rejected with 422"),
            "{:?}",
            report.notes
        );
        assert!(!slot.cancel());
    }
}
