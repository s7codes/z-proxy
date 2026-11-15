//! Axum route extraction: `.route("/path", get(h).post(h))`, including multi-line method
//! routers, path-qualified constructors (`routing::get`) and `on(MethodFilter::X, h)`.
//!
//! `.nest("/p", router)` is resolved when the nested router is built in the same file:
//! inline in the call, bound with `let`, or returned by a local `fn`. Each such router is a
//! byte region of the file, and a route takes the prefixes of the innermost region around
//! it, composed outward through the regions that contain the `.nest` call itself.

use std::sync::LazyLock;

use regex::Regex;

use super::lex::{
    is_ident_byte, literal_end, matching_bracket, matching_paren, read_string, skip_ws, Lang,
    Source,
};
use super::routes::{compile, method_from_token, RawRoute};
use crate::engine::types::{RouteMethod, RouteSource};

const METHOD_ROUTERS: [&str; 8] = [
    "get", "post", "put", "patch", "delete", "head", "options", "any",
];
const MAX_NEST_DEPTH: usize = 8;
const MAX_PREFIXES: usize = 16;

static ROUTE_CALL: LazyLock<Option<Regex>> = LazyLock::new(|| compile(r"\.\s*route\s*\("));
static NEST_CALL: LazyLock<Option<Regex>> = LazyLock::new(|| compile(r"\.\s*nest\s*\("));
/// Leading path of a nested-router expression: `api`, `api.clone()`, `self::api()`,
/// `api_router(state)`, `Router::new()`.
static NESTED_EXPR: LazyLock<Option<Regex>> =
    LazyLock::new(|| compile(r"^((?:[A-Za-z_][A-Za-z0-9_]*::)*)([A-Za-z_][A-Za-z0-9_]*)\s*(\()?"));
static METHOD_FILTER: LazyLock<Option<Regex>> =
    LazyLock::new(|| compile(r"MethodFilter::(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)(?-u:\b)"));
static TEST_MODULE: LazyLock<Option<Regex>> =
    LazyLock::new(|| compile(r"#\[cfg\(test\)\][^{;]*?(?-u:\b)mod\s+[A-Za-z_][A-Za-z0-9_]*\s*\{"));

/// A router built over `region` is served under `prefix` by the `.nest` call at `at`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Nest {
    region: (usize, usize),
    prefix: String,
    at: usize,
}

pub fn extract(source: &Source) -> Vec<RawRoute> {
    let Some(route_call) = ROUTE_CALL.as_ref() else {
        return Vec::new();
    };
    let src = source.text.as_str();
    let tests = test_modules(src);
    let excluded =
        |at: usize| source.in_string(at) || tests.iter().any(|&(from, to)| from <= at && at < to);
    let nests = nests(source, &excluded);
    let mut routes = Vec::new();
    for call in route_call.find_iter(src) {
        let start = call.start();
        if excluded(start) {
            continue;
        }
        let open = call.end() - 1;
        let Some(close) = matching_paren(src, open, Lang::Rust) else {
            continue;
        };
        let arg = skip_ws(src, open + 1);
        let Some((path, end)) = read_string(src, arg, Lang::Rust) else {
            continue;
        };
        let comma = skip_ws(src, end);
        if !path.starts_with('/') || src.as_bytes().get(comma) != Some(&b',') {
            continue;
        }
        let mut methods = method_router(&src[comma + 1..close]);
        if methods.is_empty() {
            // A method router built elsewhere (`.route("/x", routes())`) still serves the path.
            methods.push(RouteMethod::Any);
        }
        let line = source.lines.line(arg);
        let prefixes = prefixes_at(start, &nests, 0);
        for method in methods {
            let route = RawRoute::new(method, path.clone(), RouteSource::Axum, line);
            routes.extend(prefixes.iter().map(|prefix| route.clone().mounted(prefix)));
        }
    }
    routes
}

fn nests(source: &Source, excluded: &dyn Fn(usize) -> bool) -> Vec<Nest> {
    let Some(nest_call) = NEST_CALL.as_ref() else {
        return Vec::new();
    };
    let src = source.text.as_str();
    let mut out = Vec::new();
    for call in nest_call.find_iter(src) {
        if excluded(call.start()) {
            continue;
        }
        let open = call.end() - 1;
        let Some(close) = matching_paren(src, open, Lang::Rust) else {
            continue;
        };
        let Some((prefix, end)) = read_string(src, skip_ws(src, open + 1), Lang::Rust) else {
            continue;
        };
        let comma = skip_ws(src, end);
        if !prefix.starts_with('/') || src.as_bytes().get(comma) != Some(&b',') {
            continue;
        }
        if let Some(region) = nested_region(source, comma + 1, close, call.start(), excluded) {
            out.push(Nest {
                region,
                prefix,
                at: call.start(),
            });
        }
    }
    out
}

/// Byte region in which the router passed to `.nest` is built.
fn nested_region(
    source: &Source,
    start: usize,
    end: usize,
    at: usize,
    excluded: &dyn Fn(usize) -> bool,
) -> Option<(usize, usize)> {
    let src = source.text.as_str();
    let expr = src[start..end].trim();
    if expr.contains(".route") || expr.contains(".nest") {
        return Some((start, end));
    }
    let caps = NESTED_EXPR.as_ref()?.captures(expr)?;
    let name = caps.get(2)?.as_str();
    // `Router::new()` names a type and `other::routes()` another module; a same-named local
    // item would be a coincidence, not the nested router.
    let qualifier = caps.get(1).map_or("", |q| q.as_str());
    if !qualifier.is_empty() && qualifier != "self::" {
        return None;
    }
    if caps.get(3).is_some() {
        return fn_body(source, name, excluded);
    }
    let_binding(source, name, at, excluded)
}

/// Body of the local `fn name(..) { .. }`.
fn fn_body(
    source: &Source,
    name: &str,
    excluded: &dyn Fn(usize) -> bool,
) -> Option<(usize, usize)> {
    let src = source.text.as_str();
    let re = compile(&format!(
        r"(?-u:\b)fn\s+{}\s*(?:<[^>{{]*>)?\s*\(",
        regex::escape(name)
    ))?;
    let body = re
        .find_iter(src)
        .filter(|found| !excluded(found.start()))
        .find_map(|found| {
            let close = matching_paren(src, found.end() - 1, Lang::Rust)?;
            let brace = close + src[close..].find(['{', ';'])?;
            // `;` first: a trait method declaration without a body.
            if src.as_bytes().get(brace) != Some(&b'{') {
                return None;
            }
            Some((brace, matching_bracket(src, brace, Lang::Rust)?))
        });
    body
}

/// Initializer of `let name = ..;`, preferring the last binding before the `.nest` call.
fn let_binding(
    source: &Source,
    name: &str,
    at: usize,
    excluded: &dyn Fn(usize) -> bool,
) -> Option<(usize, usize)> {
    let src = source.text.as_str();
    let re = compile(&format!(
        r"(?-u:\b)let\s+(?:mut\s+)?{}\s*(?::[^=;]+)?=",
        regex::escape(name)
    ))?;
    let bindings: Vec<usize> = re
        .find_iter(src)
        .filter(|found| !excluded(found.start()) && src.as_bytes().get(found.end()) != Some(&b'='))
        .map(|found| found.end())
        .collect();
    let init = bindings
        .iter()
        .rev()
        .find(|&&init| init < at)
        .or_else(|| bindings.first())
        .copied()?;
    Some((init, statement_end(src, init)?))
}

/// Offset of the `;` (or enclosing closer) that ends the expression starting at `from`.
fn statement_end(src: &str, from: usize) -> Option<usize> {
    let bytes = src.as_bytes();
    let mut depth = 0usize;
    let mut at = from;
    while at < bytes.len() {
        if let Some(end) = literal_end(bytes, at, Lang::Rust) {
            at = end;
            continue;
        }
        match bytes[at] {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' if depth == 0 => return Some(at),
            b')' | b']' | b'}' => depth -= 1,
            b';' if depth == 0 => return Some(at),
            _ => {}
        }
        at += 1;
    }
    None
}

/// Prefixes for a route at `at`: those of the innermost nested region containing it, each
/// joined under the prefixes of the region holding that region's `.nest` call. A router
/// bound once and nested twice yields both prefixes.
fn prefixes_at(at: usize, nests: &[Nest], depth: usize) -> Vec<String> {
    let containing = nests
        .iter()
        .filter(|nest| nest.region.0 <= at && at < nest.region.1);
    let Some(innermost) = containing
        .clone()
        .map(|nest| nest.region)
        .min_by_key(|(start, end)| end - start)
    else {
        return vec![String::new()];
    };
    if depth >= MAX_NEST_DEPTH {
        return vec![String::new()];
    }
    let mut out: Vec<String> = Vec::new();
    for nest in containing.filter(|nest| nest.region == innermost) {
        for outer in prefixes_at(nest.at, nests, depth + 1) {
            let joined = format!("{outer}{}", nest.prefix);
            if !out.contains(&joined) {
                out.push(joined);
            }
        }
    }
    out.truncate(MAX_PREFIXES);
    out
}

/// Methods registered by a method-router expression. Only calls at the top level of the
/// expression count, so a handler closure that itself calls `get(..)` is not mistaken for a
/// registration.
fn method_router(expr: &str) -> Vec<RouteMethod> {
    let bytes = expr.as_bytes();
    let mut methods = Vec::new();
    let mut depth = 0usize;
    let mut at = 0;
    while at < bytes.len() {
        if let Some(end) = literal_end(bytes, at, Lang::Rust) {
            at = end;
            continue;
        }
        let byte = bytes[at];
        if is_ident_byte(byte) && (at == 0 || !is_ident_byte(bytes[at - 1])) {
            let start = at;
            while at < bytes.len() && (is_ident_byte(bytes[at]) || bytes[at] == b':') {
                at += 1;
            }
            let ident = expr[start..at].rsplit("::").next().unwrap_or_default();
            let ident = ident.strip_suffix("_service").unwrap_or(ident);
            let open = skip_ws(expr, at);
            if depth == 0 && bytes.get(open) == Some(&b'(') {
                if METHOD_ROUTERS.contains(&ident) {
                    methods.extend(method_from_token(ident));
                } else if ident == "on" {
                    if let Some(close) = matching_paren(expr, open, Lang::Rust) {
                        methods.extend(method_filters(&expr[open..close]));
                    }
                }
            }
            continue;
        }
        match byte {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => depth = depth.saturating_sub(1),
            _ => {}
        }
        at += 1;
    }
    let mut unique = Vec::new();
    for method in methods {
        if !unique.contains(&method) {
            unique.push(method);
        }
    }
    unique
}

/// Byte ranges of inline `#[cfg(test)] mod name { .. }` blocks. Rust tests live next to the
/// code, and the throwaway routers they build are not part of the service's surface.
fn test_modules(src: &str) -> Vec<(usize, usize)> {
    let Some(re) = TEST_MODULE.as_ref() else {
        return Vec::new();
    };
    re.find_iter(src)
        .filter_map(|module| {
            let open = module.end() - 1;
            matching_bracket(src, open, Lang::Rust).map(|close| (module.start(), close))
        })
        .collect()
}

fn method_filters(args: &str) -> Vec<RouteMethod> {
    METHOD_FILTER.as_ref().map_or_else(Vec::new, |re| {
        re.captures_iter(args)
            .filter_map(|caps| {
                caps.get(1)
                    .and_then(|token| method_from_token(token.as_str()))
            })
            .collect()
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn run(src: &str) -> Vec<(RouteMethod, String, u32)> {
        extract(&Source::new(src, Lang::Rust))
            .into_iter()
            .map(|route| (route.method, route.path, route.line))
            .collect()
    }

    #[test]
    fn method_routers_across_lines() {
        let src = r#"pub fn router() -> Router<AppState> {
    Router::new()
        .route("/health", get(|| async { "ok" }))
        .route(
            "/orders/{id}",
            axum::routing::get(show)
                .put(replace)
                .delete(remove),
        )
        // .route("/legacy", get(old))
        .route("/upload", on(MethodFilter::POST.or(MethodFilter::PUT), upload))
        .route("/v0/:id", get(get_user))
        .route("/nested", nested_router())
        .route_service("/static", ServeDir::new("dist"))
}"#;
        assert_eq!(
            run(src),
            vec![
                (RouteMethod::Get, "/health".to_owned(), 3),
                (RouteMethod::Get, "/orders/{id}".to_owned(), 5),
                (RouteMethod::Put, "/orders/{id}".to_owned(), 5),
                (RouteMethod::Delete, "/orders/{id}".to_owned(), 5),
                (RouteMethod::Post, "/upload".to_owned(), 11),
                (RouteMethod::Put, "/upload".to_owned(), 11),
                (RouteMethod::Get, "/v0/:id".to_owned(), 12),
                (RouteMethod::Any, "/nested".to_owned(), 13),
            ]
        );
    }

    #[test]
    fn test_modules_and_string_fixtures_are_ignored() {
        let src = "fn app() -> Router { Router::new().route(\"/live\", get(live)) }\n\
                   const DOC: &str = \".route(\\\"/doc\\\", get(h))\";\n\
                   #[cfg(test)]\n\
                   #[allow(clippy::unwrap_used)]\n\
                   mod tests {\n\
                   \x20   fn fixture() { Router::new().route(\"/test-only\", get(h)); }\n\
                   }\n\
                   fn after() { r.route(\"/after\", post(h)); }\n";
        assert_eq!(
            run(src),
            vec![
                (RouteMethod::Get, "/live".to_owned(), 1),
                (RouteMethod::Post, "/after".to_owned(), 8),
            ]
        );
    }

    fn mounted(src: &str) -> Vec<(RouteMethod, String, Option<String>, u32)> {
        extract(&Source::new(src, Lang::Rust))
            .into_iter()
            .map(|route| (route.method, route.path, route.prefix, route.line))
            .collect()
    }

    #[test]
    fn nest_prefixes_resolve_inline_bindings_and_local_fns() {
        let src = r#"fn admin() -> Router<AppState> {
    Router::new().route("/stats", get(stats))
}

fn api() -> Router<AppState> {
    Router::new()
        .route("/users/{id}", get(show))
        .nest("/admin", admin())
}

pub fn app(state: AppState) -> Router {
    let billing = Router::new().route("/invoices", post(invoice));
    Router::new()
        .route("/health", get(health))
        .nest("/api/v1", api())
        .nest("/billing", billing.clone())
        .nest("/legacy/billing", billing)
        .nest("/inline", Router::new().route("/ping", get(ping)))
        .nest("/static", Router::new())
        .with_state(state)
}"#;
        let some = |p: &str| Some(p.to_owned());
        assert_eq!(
            mounted(src),
            vec![
                (
                    RouteMethod::Get,
                    "/api/v1/admin/stats".to_owned(),
                    some("/api/v1/admin"),
                    2
                ),
                (
                    RouteMethod::Get,
                    "/api/v1/users/{id}".to_owned(),
                    some("/api/v1"),
                    7
                ),
                (
                    RouteMethod::Post,
                    "/billing/invoices".to_owned(),
                    some("/billing"),
                    12
                ),
                (
                    RouteMethod::Post,
                    "/legacy/billing/invoices".to_owned(),
                    some("/legacy/billing"),
                    12
                ),
                (RouteMethod::Get, "/health".to_owned(), None, 14),
                (
                    RouteMethod::Get,
                    "/inline/ping".to_owned(),
                    some("/inline"),
                    18
                ),
            ]
        );
    }

    #[test]
    fn unresolvable_nests_leave_routes_as_declared() {
        let src = r#"fn routes() -> Router { Router::new().route("/a", get(a)) }
fn app(api: Router) -> Router {
    Router::new()
        .nest("/api", api)
        .nest("/ext", external::routes())
        .nest_service("/assets", ServeDir::new("dist"))
}
const DOC: &str = "Router::new().nest(\"/doc\", routes())";"#;
        assert_eq!(
            mounted(src),
            vec![(RouteMethod::Get, "/a".to_owned(), None, 1)]
        );
        let local = "fn routes() -> Router { Router::new().route(\"/a\", get(a)) }\n\
                     fn app() -> Router { Router::new().nest(\"/v2\", self::routes()) }";
        assert_eq!(
            mounted(local),
            vec![(
                RouteMethod::Get,
                "/v2/a".to_owned(),
                Some("/v2".to_owned()),
                1
            )]
        );
        assert_eq!(statement_end("a(b; c); d", 0), Some(7));
        assert_eq!(statement_end("x }", 0), Some(2));
    }

    #[test]
    fn closures_calling_get_are_not_registrations() {
        let src = r#"app.route("/proxy", post(|s: State<S>| async move { s.client.get("x"); }))"#;
        assert_eq!(run(src), vec![(RouteMethod::Post, "/proxy".to_owned(), 1)]);
    }
}
