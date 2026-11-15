//! Axum route extraction: `.route("/path", get(h).post(h))`, including multi-line method
//! routers, path-qualified constructors (`routing::get`) and `on(MethodFilter::X, h)`.

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

static ROUTE_CALL: LazyLock<Option<Regex>> = LazyLock::new(|| compile(r"\.\s*route\s*\("));
static METHOD_FILTER: LazyLock<Option<Regex>> =
    LazyLock::new(|| compile(r"MethodFilter::(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)(?-u:\b)"));
static TEST_MODULE: LazyLock<Option<Regex>> =
    LazyLock::new(|| compile(r"#\[cfg\(test\)\][^{;]*?(?-u:\b)mod\s+[A-Za-z_][A-Za-z0-9_]*\s*\{"));

pub fn extract(source: &Source) -> Vec<RawRoute> {
    let Some(route_call) = ROUTE_CALL.as_ref() else {
        return Vec::new();
    };
    let src = source.text.as_str();
    let tests = test_modules(src);
    let mut routes = Vec::new();
    for call in route_call.find_iter(src) {
        let start = call.start();
        if source.in_string(start) || tests.iter().any(|&(from, to)| from <= start && start < to) {
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
        routes.extend(methods.into_iter().map(|method| RawRoute {
            method,
            path: path.clone(),
            source: RouteSource::Axum,
            line,
        }));
    }
    routes
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

    #[test]
    fn closures_calling_get_are_not_registrations() {
        let src = r#"app.route("/proxy", post(|s: State<S>| async move { s.client.get("x"); }))"#;
        assert_eq!(run(src), vec![(RouteMethod::Post, "/proxy".to_owned(), 1)]);
    }
}
