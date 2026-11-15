//! Response contract drift: a live response checked against the `ResponseContract` the
//! scanner extracted from an OpenAPI operation.
//!
//! Status codes are checked for 2xx and 4xx only. A 5xx is already a fault wherever it
//! surfaces, and documenting `500` does not make one acceptable. Field checks run on the
//! documented success status, against types and `required` lists, then against the value
//! constraints of correctly typed fields: numeric bounds, string length, scalar enums and
//! the `uuid`, `email`, `date-time` and `date` formats. `pattern` is not evaluated: a
//! regex compiled from a document at check time would be an unbounded cost per response.

use std::cmp::Ordering;
use std::collections::HashMap;
use std::sync::Arc;

use serde_json::{Number, Value};

use super::error::{EngineError, EngineResult};
use super::fault::{self, PathMatcher};
use super::types::{
    ContractField, ContractViolation, ContractViolationKind, JsonKind, NumericBound,
    ResponseContract, RouteContract, RouteMethod, StringFormat, ValueConstraints,
};

/// Enum members listed in a violation before the rest is summarized as a count.
const ENUM_LABEL_MEMBERS: usize = 6;
/// Characters of an offending string quoted in a violation.
const ACTUAL_CHARS: usize = 64;

/// Violations reported per response; a body that drifts everywhere is one finding, not a
/// page of them.
pub const MAX_VIOLATIONS: usize = 16;
/// Bodies above this are not parsed for field checks; the status check still applies.
pub const MAX_BODY_BYTES: usize = 1024 * 1024;
/// A scanned project caps at 5,000 routes; only OpenAPI operations carry contracts.
pub const MAX_CONTRACTS: usize = 5_000;

/// Drift of one response from `contract`. `body` is `None` when the caller did not capture
/// the full body, which limits the check to the status.
pub fn check(
    contract: &ResponseContract,
    status: u16,
    body: Option<&[u8]>,
) -> Vec<ContractViolation> {
    let mut violations = Vec::new();
    let checked_class = (200..300).contains(&status) || (400..500).contains(&status);
    if checked_class && !documented(contract, status) {
        violations.push(ContractViolation {
            kind: ContractViolationKind::UndocumentedStatus,
            pointer: None,
            expected: documented_label(contract),
            actual: status.to_string(),
        });
    }
    if contract.body_status != Some(status) || contract.fields.is_empty() {
        return violations;
    }
    let Some(body) = body.filter(|body| body.len() <= MAX_BODY_BYTES) else {
        return violations;
    };
    match serde_json::from_slice::<Value>(body) {
        Ok(root) => check_fields(&contract.fields, &root, &mut violations),
        Err(_) => {
            if let Some(root) = contract.fields.iter().find(|f| f.pointer.is_empty()) {
                violations.push(ContractViolation {
                    kind: ContractViolationKind::ResponseTypeMismatch,
                    pointer: Some(String::new()),
                    expected: kinds_label(&root.kinds),
                    actual: if body.iter().all(u8::is_ascii_whitespace) {
                        "empty body".to_owned()
                    } else {
                        "non-JSON body".to_owned()
                    },
                });
            }
        }
    }
    violations
}

fn documented(contract: &ResponseContract, status: u16) -> bool {
    if contract.has_default || (contract.statuses.is_empty() && contract.status_classes.is_empty())
    {
        return true;
    }
    let class = u8::try_from(status / 100).unwrap_or(u8::MAX);
    contract.statuses.contains(&status) || contract.status_classes.contains(&class)
}

fn documented_label(contract: &ResponseContract) -> String {
    let listed: Vec<String> = contract
        .statuses
        .iter()
        .map(u16::to_string)
        .chain(
            contract
                .status_classes
                .iter()
                .map(|class| format!("{class}XX")),
        )
        .collect();
    format!("one of {}", listed.join(", "))
}

fn check_fields(fields: &[ContractField], root: &Value, out: &mut Vec<ContractViolation>) {
    for field in fields {
        if out.len() >= MAX_VIOLATIONS {
            return;
        }
        // A field is judged only inside a parent object; a missing or mistyped parent is
        // reported once, at the parent.
        let parent = match field.pointer.rfind('/') {
            Some(at) => root.pointer(&field.pointer[..at]),
            None => Some(root),
        };
        if !field.pointer.is_empty() && !parent.is_some_and(Value::is_object) {
            continue;
        }
        match root.pointer(&field.pointer) {
            None if field.required => out.push(ContractViolation {
                kind: ContractViolationKind::MissingRequiredField,
                pointer: Some(field.pointer.clone()),
                expected: kinds_label(&field.kinds),
                actual: "missing".to_owned(),
            }),
            None => {}
            Some(value) => {
                let actual = kind_of(value);
                if !accepts(&field.kinds, actual) {
                    out.push(ContractViolation {
                        kind: ContractViolationKind::ResponseTypeMismatch,
                        pointer: Some(field.pointer.clone()),
                        expected: kinds_label(&field.kinds),
                        actual: kind_name(actual).to_owned(),
                    });
                } else if let Some(constraints) = &field.constraints {
                    check_constraints(&field.pointer, constraints, value, out);
                }
            }
        }
    }
}

fn check_constraints(
    pointer: &str,
    constraints: &ValueConstraints,
    value: &Value,
    out: &mut Vec<ContractViolation>,
) {
    let mut push = |expected: String, actual: String| {
        if out.len() < MAX_VIOLATIONS {
            out.push(ContractViolation {
                kind: ContractViolationKind::ConstraintViolation,
                pointer: Some(pointer.to_owned()),
                expected,
                actual,
            });
        }
    };
    match value {
        Value::Null => return,
        Value::Number(number) => {
            if let Some(bound) = &constraints.minimum {
                if !within(number, bound, Ordering::Greater) {
                    let op = if bound.exclusive { ">" } else { ">=" };
                    push(format!("{op} {}", bound.value), number.to_string());
                }
            }
            if let Some(bound) = &constraints.maximum {
                if !within(number, bound, Ordering::Less) {
                    let op = if bound.exclusive { "<" } else { "<=" };
                    push(format!("{op} {}", bound.value), number.to_string());
                }
            }
        }
        Value::String(text) => {
            let length = || u32::try_from(text.chars().count()).unwrap_or(u32::MAX);
            if let Some(min) = constraints.min_length.filter(|min| length() < *min) {
                push(format!("length >= {min}"), format!("length {}", length()));
            }
            if let Some(max) = constraints.max_length.filter(|max| length() > *max) {
                push(format!("length <= {max}"), format!("length {}", length()));
            }
            if let Some(format) = constraints.format.filter(|f| !matches_format(*f, text)) {
                push(format!("format {}", format_name(format)), quoted(text));
            }
        }
        _ => {}
    }
    if let Some(members) = &constraints.enum_values {
        if !members.iter().any(|member| same_value(member, value)) {
            push(enum_label(members), compact(value));
        }
    }
}

/// `value` against `bound` from the side `allowed` names: `Greater` for a minimum.
fn within(value: &Number, bound: &NumericBound, allowed: Ordering) -> bool {
    match compare(value, &bound.value) {
        Some(Ordering::Equal) => !bound.exclusive,
        Some(order) => order == allowed,
        // NaN never reaches here (JSON has none); an incomparable pair is not drift.
        None => true,
    }
}

/// Exact for integers on either side of `i64`/`u64`, `f64` otherwise.
fn compare(a: &Number, b: &Number) -> Option<Ordering> {
    if let (Some(a), Some(b)) = (a.as_i64(), b.as_i64()) {
        return Some(a.cmp(&b));
    }
    if let (Some(a), Some(b)) = (a.as_u64(), b.as_u64()) {
        return Some(a.cmp(&b));
    }
    a.as_f64()?.partial_cmp(&b.as_f64()?)
}

/// JSON Schema equality: `1` and `1.0` are the same number.
fn same_value(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Number(a), Value::Number(b)) => compare(a, b) == Some(Ordering::Equal),
        _ => a == b,
    }
}

fn enum_label(members: &[Value]) -> String {
    let listed: Vec<String> = members
        .iter()
        .take(ENUM_LABEL_MEMBERS)
        .map(compact)
        .collect();
    let rest = members.len().saturating_sub(ENUM_LABEL_MEMBERS);
    if rest > 0 {
        format!("one of {} (+{rest} more)", listed.join(", "))
    } else {
        format!("one of {}", listed.join(", "))
    }
}

fn compact(value: &Value) -> String {
    match value {
        Value::String(text) => quoted(text),
        other => other.to_string(),
    }
}

/// JSON-quoted, cut to `ACTUAL_CHARS` characters so an oversized value stays one line.
fn quoted(text: &str) -> String {
    match text.char_indices().nth(ACTUAL_CHARS) {
        Some((cut, _)) => format!("{}...", Value::String(text[..cut].to_owned())),
        None => Value::String(text.to_owned()).to_string(),
    }
}

pub fn format_name(format: StringFormat) -> &'static str {
    match format {
        StringFormat::Uuid => "uuid",
        StringFormat::Email => "email",
        StringFormat::DateTime => "date-time",
        StringFormat::Date => "date",
    }
}

fn matches_format(format: StringFormat, text: &str) -> bool {
    match format {
        StringFormat::Uuid => is_uuid(text),
        StringFormat::Email => is_email(text),
        StringFormat::DateTime => is_date_time(text),
        StringFormat::Date => is_full_date(text.as_bytes()),
    }
}

fn is_uuid(text: &str) -> bool {
    text.len() == 36
        && text.bytes().enumerate().all(|(i, b)| match i {
            8 | 13 | 18 | 23 => b == b'-',
            _ => b.is_ascii_hexdigit(),
        })
}

/// Deliberately lenient (any non-space local part and a dotted-label domain): the check
/// exists to catch a value that is not an address at all, not to arbitrate RFC 5322.
fn is_email(text: &str) -> bool {
    let Some((local, domain)) = text.rsplit_once('@') else {
        return false;
    };
    let quoted_local = local.len() >= 2 && local.starts_with('"') && local.ends_with('"');
    !local.is_empty()
        && local.len() <= 64
        && (quoted_local || !local.contains('@'))
        && !domain.is_empty()
        && domain.len() <= 253
        && !text.chars().any(|c| c.is_whitespace() || c.is_control())
        && domain
            .split('.')
            .all(|label| !label.is_empty() && !label.starts_with('-') && !label.ends_with('-'))
}

/// RFC 3339 `date-time`: `full-date "T" partial-time time-offset`, separator in any case.
fn is_date_time(text: &str) -> bool {
    let bytes = text.as_bytes();
    if bytes.len() < 20 || !matches!(bytes[10], b'T' | b't' | b' ') {
        return false;
    }
    if !is_full_date(&bytes[..10]) {
        return false;
    }
    let time = &bytes[11..];
    let Some((hour, minute, second)) = clock(time) else {
        return false;
    };
    if hour > 23 || minute > 59 || second > 60 {
        return false;
    }
    let mut rest = &time[8..];
    if let Some(fraction) = rest.strip_prefix(b".") {
        let digits = fraction.iter().take_while(|b| b.is_ascii_digit()).count();
        if digits == 0 {
            return false;
        }
        rest = &fraction[digits..];
    }
    match rest {
        [b'Z' | b'z'] => true,
        [b'+' | b'-', h1, h2, b':', m1, m2] => {
            matches!((two_digits(*h1, *h2), two_digits(*m1, *m2)), (Some(h), Some(m)) if h <= 23 && m <= 59)
        }
        _ => false,
    }
}

/// `HH:MM:SS` at the start of `bytes`.
fn clock(bytes: &[u8]) -> Option<(u32, u32, u32)> {
    match bytes {
        [h1, h2, b':', m1, m2, b':', s1, s2, ..] => Some((
            two_digits(*h1, *h2)?,
            two_digits(*m1, *m2)?,
            two_digits(*s1, *s2)?,
        )),
        _ => None,
    }
}

/// RFC 3339 `full-date` with the month's real length (leap years included).
fn is_full_date(bytes: &[u8]) -> bool {
    let [y1, y2, y3, y4, b'-', mo1, mo2, b'-', d1, d2] = bytes else {
        return false;
    };
    let year = match (two_digits(*y1, *y2), two_digits(*y3, *y4)) {
        (Some(high), Some(low)) => high * 100 + low,
        _ => return false,
    };
    let (Some(month), Some(day)) = (two_digits(*mo1, *mo2), two_digits(*d1, *d2)) else {
        return false;
    };
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    (1..=days).contains(&day)
}

fn two_digits(high: u8, low: u8) -> Option<u32> {
    (high.is_ascii_digit() && low.is_ascii_digit())
        .then(|| u32::from(high - b'0') * 10 + u32::from(low - b'0'))
}

pub fn kind_of(value: &Value) -> JsonKind {
    match value {
        Value::Null => JsonKind::Null,
        Value::Bool(_) => JsonKind::Boolean,
        Value::Number(number) => {
            let integral = number.is_i64()
                || number.is_u64()
                || number
                    .as_f64()
                    .is_some_and(|f| f.is_finite() && f.fract() == 0.0);
            if integral {
                JsonKind::Integer
            } else {
                JsonKind::Number
            }
        }
        Value::String(_) => JsonKind::String,
        Value::Array(_) => JsonKind::Array,
        Value::Object(_) => JsonKind::Object,
    }
}

/// Every integer is also a valid `number`.
fn accepts(kinds: &[JsonKind], actual: JsonKind) -> bool {
    kinds.is_empty()
        || kinds.contains(&actual)
        || (actual == JsonKind::Integer && kinds.contains(&JsonKind::Number))
}

pub fn kind_name(kind: JsonKind) -> &'static str {
    match kind {
        JsonKind::String => "string",
        JsonKind::Integer => "integer",
        JsonKind::Number => "number",
        JsonKind::Boolean => "boolean",
        JsonKind::Array => "array",
        JsonKind::Object => "object",
        JsonKind::Null => "null",
    }
}

fn kinds_label(kinds: &[JsonKind]) -> String {
    if kinds.is_empty() {
        return "any".to_owned();
    }
    kinds
        .iter()
        .map(|kind| kind_name(*kind))
        .collect::<Vec<_>>()
        .join(" | ")
}

// ---- route binding --------------------------------------------------------------------

#[derive(Debug)]
pub struct CompiledContract {
    method: RouteMethod,
    matcher: PathMatcher,
    /// `POST /orders/{id}`, the form telemetry reports a match with.
    pub label: String,
    pub contract: ResponseContract,
}

impl CompiledContract {
    fn method_matches(&self, method: &str) -> bool {
        self.method == RouteMethod::Any || fault::method_token(self.method) == method
    }
}

/// Contracts indexed by segment count, so a request is only tested against templates that
/// can match its shape. Within a bucket literal templates precede parameterized ones:
/// `/orders/checkout` wins over `/orders/{id}`.
#[derive(Debug, Default)]
pub struct ContractSet {
    by_segments: HashMap<usize, Vec<Arc<CompiledContract>>>,
    catch_all: Vec<Arc<CompiledContract>>,
    len: usize,
}

impl ContractSet {
    /// Rejects the whole set on the first invalid template, like a fault rule set, so a
    /// partially applied list never reaches traffic.
    pub fn compile(contracts: Vec<RouteContract>) -> EngineResult<Self> {
        if contracts.len() > MAX_CONTRACTS {
            return Err(EngineError::InvalidContractSet {
                index: MAX_CONTRACTS,
                reason: format!("at most {MAX_CONTRACTS} contracts"),
            });
        }
        let mut set = Self::default();
        let mut ranked: Vec<(usize, usize, Arc<CompiledContract>)> =
            Vec::with_capacity(contracts.len());
        for (index, route) in contracts.into_iter().enumerate() {
            let matcher = PathMatcher::compile(&route.path).map_err(|reason| {
                EngineError::InvalidContractSet {
                    index,
                    reason: format!("path {reason}"),
                }
            })?;
            let segments: Vec<&str> = route.path.split('/').filter(|s| !s.is_empty()).collect();
            let params = segments.iter().filter(|s| s.contains('{')).count();
            let catch_all = segments.last().is_some_and(|s| s.starts_with("{*"));
            let compiled = Arc::new(CompiledContract {
                label: format!("{} {}", fault::method_token(route.method), route.path),
                method: route.method,
                matcher,
                contract: route.contract,
            });
            if catch_all {
                set.catch_all.push(compiled);
            } else {
                ranked.push((segments.len(), params, compiled));
            }
        }
        // Stable: equal specificity keeps the scanner's order.
        ranked.sort_by_key(|(_, params, _)| *params);
        set.len = ranked.len() + set.catch_all.len();
        for (segments, _, compiled) in ranked {
            set.by_segments.entry(segments).or_default().push(compiled);
        }
        Ok(set)
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Contract of the first template matching `method` and the upstream `path`.
    pub fn find(&self, method: &str, path: &str) -> Option<Arc<CompiledContract>> {
        if self.is_empty() {
            return None;
        }
        let collapsed = fault::collapse_path(path);
        let segments = collapsed.split('/').filter(|s| !s.is_empty()).count();
        self.by_segments
            .get(&segments)
            .into_iter()
            .flatten()
            .chain(self.catch_all.iter())
            .find(|c| c.method_matches(method) && c.matcher.matches_collapsed(&collapsed))
            .cloned()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn field(pointer: &str, kinds: &[JsonKind], required: bool) -> ContractField {
        ContractField {
            pointer: pointer.to_owned(),
            kinds: kinds.to_vec(),
            required,
            constraints: None,
        }
    }

    fn constrained(
        pointer: &str,
        kinds: &[JsonKind],
        constraints: ValueConstraints,
    ) -> ContractField {
        ContractField {
            constraints: Some(constraints),
            ..field(pointer, kinds, false)
        }
    }

    fn bound(value: i64, exclusive: bool) -> Option<NumericBound> {
        Some(NumericBound {
            value: Number::from(value),
            exclusive,
        })
    }

    fn redemption() -> ResponseContract {
        ResponseContract {
            statuses: vec![200, 409],
            status_classes: Vec::new(),
            has_default: false,
            body_status: Some(200),
            fields: vec![
                field("", &[JsonKind::Object], true),
                constrained(
                    "/remainingUses",
                    &[JsonKind::Integer],
                    ValueConstraints {
                        minimum: bound(0, false),
                        ..ValueConstraints::default()
                    },
                ),
                constrained(
                    "/ratio",
                    &[JsonKind::Number],
                    ValueConstraints {
                        minimum: bound(0, true),
                        maximum: bound(1, false),
                        ..ValueConstraints::default()
                    },
                ),
                constrained(
                    "/status",
                    &[JsonKind::String],
                    ValueConstraints {
                        enum_values: Some(vec![Value::from("redeemed"), Value::from("pending")]),
                        ..ValueConstraints::default()
                    },
                ),
                constrained(
                    "/code",
                    &[JsonKind::String, JsonKind::Null],
                    ValueConstraints {
                        min_length: Some(3),
                        max_length: Some(8),
                        ..ValueConstraints::default()
                    },
                ),
                constrained(
                    "/id",
                    &[JsonKind::String],
                    ValueConstraints {
                        format: Some(StringFormat::Uuid),
                        ..ValueConstraints::default()
                    },
                ),
                constrained(
                    "/tier",
                    &[JsonKind::Integer],
                    ValueConstraints {
                        enum_values: Some(vec![Value::from(1), Value::from(2)]),
                        ..ValueConstraints::default()
                    },
                ),
            ],
        }
    }

    #[test]
    fn value_constraints_are_checked_on_correctly_typed_fields() {
        let clean = br#"{"remainingUses":0,"ratio":1,"status":"pending","code":null,"id":"123e4567-e89b-12d3-a456-426614174000","tier":2.0}"#;
        assert!(check(&redemption(), 200, Some(clean)).is_empty());

        let drifted = br#"{"remainingUses":-2,"ratio":0,"status":"void","code":"ab","id":"order-1","tier":3}"#;
        assert_eq!(
            summary(&check(&redemption(), 200, Some(drifted))),
            [
                (
                    ContractViolationKind::ConstraintViolation,
                    "/remainingUses".to_owned(),
                    ">= 0 <- -2".to_owned()
                ),
                (
                    ContractViolationKind::ConstraintViolation,
                    "/ratio".to_owned(),
                    "> 0 <- 0".to_owned()
                ),
                (
                    ContractViolationKind::ConstraintViolation,
                    "/status".to_owned(),
                    r#"one of "redeemed", "pending" <- "void""#.to_owned()
                ),
                (
                    ContractViolationKind::ConstraintViolation,
                    "/code".to_owned(),
                    "length >= 3 <- length 2".to_owned()
                ),
                (
                    ContractViolationKind::ConstraintViolation,
                    "/id".to_owned(),
                    r#"format uuid <- "order-1""#.to_owned()
                ),
                (
                    ContractViolationKind::ConstraintViolation,
                    "/tier".to_owned(),
                    "one of 1, 2 <- 3".to_owned()
                ),
            ]
        );

        // A mistyped value is one type violation, not a type and a bound violation.
        let mistyped = br#"{"remainingUses":"-1","ratio":1.5}"#;
        assert_eq!(
            summary(&check(&redemption(), 200, Some(mistyped))),
            [
                (
                    ContractViolationKind::ResponseTypeMismatch,
                    "/remainingUses".to_owned(),
                    "integer <- string".to_owned()
                ),
                (
                    ContractViolationKind::ConstraintViolation,
                    "/ratio".to_owned(),
                    "<= 1 <- 1.5".to_owned()
                ),
            ]
        );
        // String length counts characters, not bytes.
        let multibyte = r#"{"code":"éééééééé"}"#;
        assert!(check(&redemption(), 200, Some(multibyte.as_bytes())).is_empty());
    }

    #[test]
    fn string_formats() {
        for valid in [
            "user@example.com",
            "a.b+tag@sub.example.co",
            "\"odd@local\"@example.com",
            "ops@localhost",
        ] {
            assert!(is_email(valid), "{valid}");
        }
        for invalid in [
            "",
            "user",
            "@example.com",
            "user@",
            "us er@example.com",
            "a@b..c",
            "a@-b.c",
            "a@b@c",
        ] {
            assert!(!is_email(invalid), "{invalid}");
        }
        for valid in [
            "2026-11-15T21:04:05Z",
            "2026-11-15t21:04:05.123456+01:00",
            "2024-02-29 23:59:60-08:00",
        ] {
            assert!(is_date_time(valid), "{valid}");
        }
        for invalid in [
            "2026-11-15",
            "2026-11-15T21:04:05",
            "2026-13-01T00:00:00Z",
            "2025-02-29T00:00:00Z",
            "2026-11-15T24:00:00Z",
            "2026-11-15T21:04:05.Z",
            "2026-11-15T21:04:05+1:00",
            "1763240645",
        ] {
            assert!(!is_date_time(invalid), "{invalid}");
        }
        assert!(is_full_date(b"2000-02-29"));
        assert!(!is_full_date(b"1900-02-29"));
        assert!(!is_full_date(b"2026-04-31"));
        assert!(is_uuid("00000000-0000-4000-8000-00000000000A"));
        assert!(!is_uuid("00000000000040008000000000000000"));
        assert_eq!(quoted(&"x".repeat(80)).len(), ACTUAL_CHARS + 2 + 3);
    }

    #[test]
    fn large_integers_compare_exactly() {
        let near_max = ValueConstraints {
            maximum: Some(NumericBound {
                value: Number::from(u64::MAX - 1),
                exclusive: false,
            }),
            ..ValueConstraints::default()
        };
        let mut out = Vec::new();
        check_constraints("/n", &near_max, &Value::from(u64::MAX), &mut out);
        assert_eq!(out.len(), 1);
        out.clear();
        check_constraints("/n", &near_max, &Value::from(u64::MAX - 1), &mut out);
        assert!(out.is_empty());
        check_constraints("/n", &near_max, &Value::Null, &mut out);
        assert!(out.is_empty());
    }

    fn order_contract() -> ResponseContract {
        ResponseContract {
            statuses: vec![201, 422, 500],
            status_classes: Vec::new(),
            has_default: false,
            body_status: Some(201),
            fields: vec![
                field("", &[JsonKind::Object], true),
                field("/id", &[JsonKind::Integer], true),
                field("/totalCents", &[JsonKind::Integer], true),
                field("/note", &[JsonKind::String, JsonKind::Null], false),
                field("/customer", &[JsonKind::Object], false),
                field("/customer/email", &[JsonKind::String], true),
                field("/ratio", &[JsonKind::Number], false),
            ],
        }
    }

    fn summary(violations: &[ContractViolation]) -> Vec<(ContractViolationKind, String, String)> {
        violations
            .iter()
            .map(|v| {
                (
                    v.kind,
                    v.pointer.clone().unwrap_or_else(|| "status".to_owned()),
                    format!("{} <- {}", v.expected, v.actual),
                )
            })
            .collect()
    }

    #[test]
    fn conforming_body_has_no_violations() {
        let body =
            br#"{"id":7,"totalCents":9998,"note":null,"customer":{"email":"a@b"},"ratio":2}"#;
        assert!(check(&order_contract(), 201, Some(body)).is_empty());
        let floats = br#"{"id":7.0,"totalCents":1e3,"ratio":0.5}"#;
        assert!(check(&order_contract(), 201, Some(floats)).is_empty());
    }

    #[test]
    fn drifted_fields_are_reported_by_pointer() {
        let body = br#"{"totalCents":"9998","note":4,"customer":{"email":null}}"#;
        assert_eq!(
            summary(&check(&order_contract(), 201, Some(body))),
            [
                (
                    ContractViolationKind::MissingRequiredField,
                    "/id".to_owned(),
                    "integer <- missing".to_owned()
                ),
                (
                    ContractViolationKind::ResponseTypeMismatch,
                    "/totalCents".to_owned(),
                    "integer <- string".to_owned()
                ),
                (
                    ContractViolationKind::ResponseTypeMismatch,
                    "/note".to_owned(),
                    "string | null <- integer".to_owned()
                ),
                (
                    ContractViolationKind::ResponseTypeMismatch,
                    "/customer/email".to_owned(),
                    "string <- null".to_owned()
                ),
            ]
        );
    }

    #[test]
    fn children_of_an_absent_or_mistyped_parent_are_skipped() {
        let absent = br#"{"id":1,"totalCents":1}"#;
        assert!(check(&order_contract(), 201, Some(absent)).is_empty());
        let mistyped = br#"{"id":1,"totalCents":1,"customer":"x"}"#;
        assert_eq!(
            summary(&check(&order_contract(), 201, Some(mistyped))),
            [(
                ContractViolationKind::ResponseTypeMismatch,
                "/customer".to_owned(),
                "object <- string".to_owned()
            )]
        );
        let array_root = b"[1,2]";
        assert_eq!(
            summary(&check(&order_contract(), 201, Some(array_root))),
            [(
                ContractViolationKind::ResponseTypeMismatch,
                String::new(),
                "object <- array".to_owned()
            )]
        );
    }

    #[test]
    fn statuses_are_checked_for_2xx_and_4xx_only() {
        let contract = order_contract();
        let undocumented = |status| {
            check(&contract, status, None)
                .iter()
                .any(|v| v.kind == ContractViolationKind::UndocumentedStatus)
        };
        assert!(!undocumented(201));
        assert!(!undocumented(422));
        assert!(undocumented(200));
        assert!(undocumented(404));
        assert!(!undocumented(503), "5xx is a fault elsewhere, not drift");
        assert!(!undocumented(302));
        assert_eq!(
            check(&contract, 404, None)[0].expected,
            "one of 201, 422, 500"
        );

        let ranged = ResponseContract {
            statuses: vec![200],
            status_classes: vec![4],
            ..contract.clone()
        };
        assert!(check(&ranged, 418, None).is_empty());
        assert_eq!(check(&ranged, 204, None)[0].expected, "one of 200, 4XX");
        let open = ResponseContract {
            has_default: true,
            ..contract
        };
        assert!(check(&open, 299, None).is_empty());
    }

    #[test]
    fn body_checks_need_the_documented_status_and_a_full_body() {
        let contract = order_contract();
        let drifted = br#"{"id":"x","totalCents":1}"#;
        assert!(check(&contract, 422, Some(drifted)).is_empty());
        assert!(check(&contract, 201, None).is_empty());
        assert_eq!(
            summary(&check(&contract, 201, Some(b"<html>"))),
            [(
                ContractViolationKind::ResponseTypeMismatch,
                String::new(),
                "object <- non-JSON body".to_owned()
            )]
        );
        assert_eq!(check(&contract, 201, Some(b" ")).len(), 1);
    }

    #[test]
    fn violations_are_capped() {
        let fields: Vec<ContractField> = (0..40)
            .map(|i| field(&format!("/f{i}"), &[JsonKind::String], true))
            .collect();
        let contract = ResponseContract {
            fields,
            ..order_contract()
        };
        assert_eq!(check(&contract, 201, Some(b"{}")).len(), MAX_VIOLATIONS);
    }

    fn route(method: RouteMethod, path: &str) -> RouteContract {
        RouteContract {
            method,
            path: path.to_owned(),
            contract: ResponseContract {
                statuses: vec![200],
                ..order_contract()
            },
        }
    }

    #[test]
    fn set_prefers_literal_templates_and_matches_methods() {
        let set = ContractSet::compile(vec![
            route(RouteMethod::Get, "/api/orders/{id}"),
            route(RouteMethod::Get, "/api/orders/recent"),
            route(RouteMethod::Post, "/api/orders"),
            route(RouteMethod::Any, "/files/{*rest}"),
        ])
        .unwrap();
        assert_eq!(set.len(), 4);
        let label = |method: &str, path: &str| set.find(method, path).map(|c| c.label.clone());
        assert_eq!(
            label("GET", "/api/orders/recent").as_deref(),
            Some("GET /api/orders/recent")
        );
        assert_eq!(
            label("GET", "/api/orders/7").as_deref(),
            Some("GET /api/orders/{id}")
        );
        assert_eq!(
            label("GET", "//api/orders/7/").as_deref(),
            Some("GET /api/orders/{id}")
        );
        assert_eq!(label("POST", "/api/orders/7"), None);
        assert_eq!(
            label("POST", "/api/orders").as_deref(),
            Some("POST /api/orders")
        );
        assert_eq!(
            label("DELETE", "/files/a/b/c").as_deref(),
            Some("ANY /files/{*rest}")
        );
        assert_eq!(label("GET", "/other"), None);
        assert!(ContractSet::default().find("GET", "/").is_none());
    }

    #[test]
    fn invalid_templates_reject_the_whole_set() {
        let err = ContractSet::compile(vec![
            route(RouteMethod::Get, "/ok"),
            route(RouteMethod::Get, "no-slash"),
        ])
        .unwrap_err();
        assert_eq!(err.code(), "INVALID_CONTRACT_SET");
        assert_eq!(serde_json::to_value(&err).unwrap()["index"], 1);
    }
}
