//! Path parameter placeholders in request targets.
//!
//! A target may carry the scanner's template syntax (`/orders/{id}`, `/files/{*path}`). The
//! burst runner and the fuzzer send the concrete path with every placeholder set to
//! `DEFAULT_VALUE`; the fuzzer's `PathParamValidation` class rewrites one path placeholder at
//! a time with boundary identifiers. Only the request line changes: the authority, and with
//! it the guarded loopback connection, stays that of the validated target.

use std::fmt;
use std::sync::LazyLock;

use regex::Regex;

use super::error::{EngineError, EngineResult};
use super::guard;

/// Identifier sent in place of a placeholder when no other value is being tested.
pub const DEFAULT_VALUE: &str = "1";

/// Same name syntax the scanner emits: identifier-like, optionally `*` for a catch-all.
static PLACEHOLDER: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"\{(\*?[A-Za-z0-9_.\-]+)\}").ok());

/// Stand-in that survives WHATWG URL parsing unchanged: alphanumeric, so it is neither
/// percent-encoded nor normalized, and shaped so it does not occur in a real path.
static MARKER: LazyLock<Option<Regex>> = LazyLock::new(|| Regex::new(r"zpparam(\d+)x7f3a").ok());

fn marker(index: usize) -> String {
    format!("zpparam{index}x7f3a")
}

/// Path of a target with its placeholders kept as slots.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathTemplate {
    /// Normalized path text around the slots; always one entry more than `params`.
    literals: Vec<String>,
    /// Placeholder names as written, catch-alls with their leading `*`.
    params: Vec<String>,
    /// `?query` with any placeholders resolved to the default, or empty.
    query: String,
}

impl PathTemplate {
    pub fn params(&self) -> &[String] {
        &self.params
    }

    /// Origin-form request target with slot `index` set to `value` and every other slot to
    /// `DEFAULT_VALUE`.
    pub fn origin_form(&self, index: usize, value: &str) -> String {
        let mut out = String::with_capacity(
            self.literals.iter().map(String::len).sum::<usize>() + value.len() + self.query.len(),
        );
        for (slot, literal) in self.literals.iter().enumerate() {
            out.push_str(literal);
            if slot < self.params.len() {
                out.push_str(if slot == index { value } else { DEFAULT_VALUE });
            }
        }
        out.push_str(&self.query);
        out
    }

    /// Parses an origin-form template (`/orders/{id}?x=1`) as reported in a fuzz report.
    pub fn parse(origin_form: &str) -> EngineResult<Option<Self>> {
        if !origin_form.starts_with('/') {
            return Err(EngineError::InvalidTarget {
                input: origin_form.to_owned(),
                reason: "path template must start with `/`".to_owned(),
            });
        }
        Ok(resolve(&format!("http://127.0.0.1{origin_form}"))?.template)
    }
}

/// The template in scanner syntax, the form `parse` accepts.
impl fmt::Display for PathTemplate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (slot, literal) in self.literals.iter().enumerate() {
            f.write_str(literal)?;
            if let Some(name) = self.params.get(slot) {
                write!(f, "{{{name}}}")?;
            }
        }
        f.write_str(&self.query)
    }
}

#[derive(Debug)]
pub struct Resolved {
    /// Absolute target with every placeholder set to `DEFAULT_VALUE`.
    pub target: String,
    /// `None` when the path holds no placeholder after normalization.
    pub template: Option<PathTemplate>,
}

/// Splits `input` into the concrete target and its path template.
///
/// Placeholders in the path become slots; any elsewhere (query) take the default value and
/// are not varied. The marked target goes through the loopback guard, so a placeholder in the
/// authority is rejected like any other non-loopback host, and slots are read back from the
/// normalized path (dot segments removed, unsafe bytes percent-encoded).
pub fn resolve(input: &str) -> EngineResult<Resolved> {
    let Some(placeholder) = PLACEHOLDER.as_ref() else {
        return Ok(unchanged(input));
    };
    if !placeholder.is_match(input) {
        return Ok(unchanged(input));
    }

    let (path_start, path_end) = path_span(input);
    let mut names = Vec::new();
    let mut marked = String::with_capacity(input.len() + 16);
    let mut cursor = 0;
    for found in placeholder.captures_iter(input) {
        let (Some(whole), Some(name)) = (found.get(0), found.get(1)) else {
            continue;
        };
        marked.push_str(&input[cursor..whole.start()]);
        if whole.start() >= path_start && whole.end() <= path_end {
            marked.push_str(&marker(names.len()));
            names.push(name.as_str().to_owned());
        } else {
            marked.push_str(DEFAULT_VALUE);
        }
        cursor = whole.end();
    }
    marked.push_str(&input[cursor..]);

    let guarded = guard::validate_url(&marked)?;
    let Some(marker_pattern) = MARKER.as_ref() else {
        return Ok(unchanged(input));
    };
    let path = guarded.url.path();
    let mut literals = Vec::with_capacity(names.len() + 1);
    let mut params = Vec::with_capacity(names.len());
    let mut last = 0;
    for found in marker_pattern.captures_iter(path) {
        let (Some(whole), Some(index)) = (found.get(0), found.get(1)) else {
            continue;
        };
        let Some(name) = index
            .as_str()
            .parse::<usize>()
            .ok()
            .and_then(|i| names.get(i))
        else {
            continue;
        };
        literals.push(path[last..whole.start()].to_owned());
        params.push(name.clone());
        last = whole.end();
    }
    literals.push(path[last..].to_owned());

    let target = marker_pattern
        .replace_all(guarded.url.as_str(), DEFAULT_VALUE)
        .into_owned();
    let template = (!params.is_empty()).then(|| PathTemplate {
        literals,
        params,
        query: guarded
            .url
            .query()
            .map_or_else(String::new, |query| format!("?{query}")),
    });
    Ok(Resolved { target, template })
}

fn unchanged(input: &str) -> Resolved {
    Resolved {
        target: input.to_owned(),
        template: None,
    }
}

/// Byte range of the path in a raw target: from the first `/` after the authority to the
/// query or fragment. Bracketed IPv6 literals contain no `/`, so the first one is the path.
fn path_span(input: &str) -> (usize, usize) {
    let authority = input.find("://").map_or(0, |at| at + 3);
    let Some(start) = input[authority..].find('/').map(|at| authority + at) else {
        return (input.len(), input.len());
    };
    let end = input[start..]
        .find(['?', '#'])
        .map_or(input.len(), |at| start + at);
    (start, end)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn template(input: &str) -> PathTemplate {
        resolve(input).unwrap().template.unwrap()
    }

    #[test]
    fn targets_without_placeholders_pass_through() {
        let resolved = resolve("http://127.0.0.1:3000/orders?x={\"a\":1}").unwrap();
        assert_eq!(resolved.target, "http://127.0.0.1:3000/orders?x={\"a\":1}");
        assert!(resolved.template.is_none());
    }

    #[test]
    fn path_placeholders_become_slots_and_query_ones_take_the_default() {
        let resolved =
            resolve("localhost:8080/api/orders/{orderId}/lines/{line}?expand={field}").unwrap();
        assert_eq!(
            resolved.target,
            "http://localhost:8080/api/orders/1/lines/1?expand=1"
        );
        let template = resolved.template.unwrap();
        assert_eq!(template.params(), ["orderId", "line"]);
        assert_eq!(
            template.to_string(),
            "/api/orders/{orderId}/lines/{line}?expand=1"
        );
        assert_eq!(
            template.origin_form(0, "-1"),
            "/api/orders/-1/lines/1?expand=1"
        );
        assert_eq!(template.origin_form(1, ""), "/api/orders/1/lines/?expand=1");
    }

    #[test]
    fn embedded_and_catch_all_placeholders() {
        let template = template("http://[::1]:9000/files/{name}.json/{*rest}");
        assert_eq!(template.params(), ["name", "*rest"]);
        assert_eq!(template.origin_form(0, "0"), "/files/0.json/1");
        assert_eq!(template.to_string(), "/files/{name}.json/{*rest}");
    }

    #[test]
    fn normalization_applies_to_the_template() {
        // Dot segments are resolved before slots are read back, so a placeholder the URL
        // parser removes is not a slot.
        let resolved = resolve("http://127.0.0.1/a/{id}/../b/{other}").unwrap();
        assert_eq!(resolved.target, "http://127.0.0.1/a/b/1");
        assert_eq!(resolved.template.unwrap().params(), ["other"]);
        let spaced = template("http://127.0.0.1/my items/{id}");
        assert_eq!(spaced.to_string(), "/my%20items/{id}");
    }

    #[test]
    fn placeholders_cannot_smuggle_a_host() {
        let err = resolve("http://{host}:3000/orders/{id}").unwrap_err();
        assert_eq!(err.code(), "NON_LOOPBACK_TARGET_REJECTED");
        let err = resolve("http://10.0.0.1/orders/{id}").unwrap_err();
        assert_eq!(err.code(), "NON_LOOPBACK_TARGET_REJECTED");
    }

    #[test]
    fn display_round_trips_through_parse() {
        let original = template("http://127.0.0.1:17480/api/v1/orders/{orderId}?v=2");
        let parsed = PathTemplate::parse(&original.to_string()).unwrap().unwrap();
        assert_eq!(parsed, original);
        assert!(PathTemplate::parse("/health").unwrap().is_none());
        assert_eq!(
            PathTemplate::parse("orders/{id}").unwrap_err().code(),
            "INVALID_TARGET"
        );
    }
}
