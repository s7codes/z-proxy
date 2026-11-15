//! Response contract drift: a live response checked against the `ResponseContract` the
//! scanner extracted from an OpenAPI operation.
//!
//! Status codes are checked for 2xx and 4xx only. A 5xx is already a fault wherever it
//! surfaces, and documenting `500` does not make one acceptable. Field checks run on the
//! documented success status, against types and `required` lists; formats, patterns and
//! bounds are left to the fuzzer, which owns the request side.

use std::collections::HashMap;
use std::sync::Arc;

use serde_json::Value;

use super::error::{EngineError, EngineResult};
use super::fault::{self, PathMatcher};
use super::types::{
    ContractField, ContractViolation, ContractViolationKind, JsonKind, ResponseContract,
    RouteContract, RouteMethod,
};

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
                }
            }
        }
    }
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
        }
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
