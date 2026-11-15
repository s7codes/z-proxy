//! Go route extraction: net/http (including Go 1.22 `"METHOD /path"` patterns), gorilla/mux
//! `.Methods(..)`, gin/echo `.GET(..)` and chi `.Get(..)`.
//!
//! The receiver must be an identifier and the path must be followed by a handler argument;
//! together these exclude client calls such as `resty.R().Get("/x")` and `http.Get(url)`.

use std::sync::LazyLock;

use regex::Regex;

use super::lex::{matching_paren, Lang, Source};
use super::routes::{compile, method_from_token, RawRoute};
use crate::engine::types::{RouteMethod, RouteSource};

static HANDLE: LazyLock<Option<Regex>> = LazyLock::new(|| {
    compile(
        r#"(?-u:\b)[A-Za-z_][A-Za-z0-9_]*\s*\.\s*(?:HandleFunc|Handle)\s*(\()\s*"([^"\n]*)"\s*,"#,
    )
});
static VERB: LazyLock<Option<Regex>> = LazyLock::new(|| {
    compile(
        r#"(?-u:\b)[A-Za-z_][A-Za-z0-9_]*\s*\.\s*(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|Any|Get|Post|Put|Patch|Delete|Head|Options)\s*\(\s*"(/[^"\n]*)"\s*,"#,
    )
});
static METHODS_CALL: LazyLock<Option<Regex>> =
    LazyLock::new(|| compile(r#"^\s*\.\s*Methods\s*\(([^)]*)\)"#));
static QUOTED: LazyLock<Option<Regex>> = LazyLock::new(|| compile(r#""([A-Za-z]+)""#));

pub fn extract(source: &Source) -> Vec<RawRoute> {
    let src = source.text.as_str();
    let lines = &source.lines;
    let in_code =
        |caps: &regex::Captures<'_>| caps.get(0).is_some_and(|m| !source.in_string(m.start()));
    let mut routes = Vec::new();
    let mut push = |method: RouteMethod, path: &str, at: usize| {
        routes.push(RawRoute {
            method,
            path: path.to_owned(),
            source: RouteSource::Go,
            line: lines.line(at),
        });
    };

    if let Some(re) = HANDLE.as_ref() {
        for caps in re.captures_iter(src).filter(in_code) {
            let (Some(open), Some(pattern)) = (caps.get(1), caps.get(2)) else {
                continue;
            };
            let (inline, path) = match pattern.as_str().split_once(' ') {
                Some((method, path)) => (method_from_token(method), path.trim_start()),
                None => (None, pattern.as_str()),
            };
            // Patterns with a host (`example.com/`) are not reachable on a loopback target.
            if !path.starts_with('/') {
                continue;
            }
            let mut methods: Vec<RouteMethod> = inline.into_iter().collect();
            if methods.is_empty() {
                methods = gorilla_methods(src, open.start());
            }
            if methods.is_empty() {
                methods.push(RouteMethod::Any);
            }
            for method in methods {
                push(method, path, pattern.start());
            }
        }
    }

    if let Some(re) = VERB.as_ref() {
        for caps in re.captures_iter(src).filter(in_code) {
            let (Some(verb), Some(path)) = (caps.get(1), caps.get(2)) else {
                continue;
            };
            if let Some(method) = method_from_token(verb.as_str()) {
                push(method, path.as_str(), path.start());
            }
        }
    }
    routes
}

/// gorilla/mux: `r.HandleFunc("/x", h).Methods("GET", "POST")`.
fn gorilla_methods(src: &str, open: usize) -> Vec<RouteMethod> {
    let (Some(methods_re), Some(quoted)) = (METHODS_CALL.as_ref(), QUOTED.as_ref()) else {
        return Vec::new();
    };
    let Some(close) = matching_paren(src, open, Lang::Go) else {
        return Vec::new();
    };
    let Some(args) = methods_re
        .captures(&src[close + 1..])
        .and_then(|caps| caps.get(1))
    else {
        return Vec::new();
    };
    quoted
        .captures_iter(args.as_str())
        .filter_map(|caps| {
            caps.get(1)
                .and_then(|token| method_from_token(token.as_str()))
        })
        .collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn stdlib_gorilla_gin_and_chi() {
        let src = r#"func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /items/{id}", getItem)
	mux.Handle("/static/", fs)
	mux.HandleFunc("example.com/", hostOnly)
	r.HandleFunc("/orders", orders).Methods("POST", "PUT")
	g.GET("/users/:id", getUser)
	c.Delete("/users/{id}", deleteUser)
	// g.POST("/old", old)
	resp, _ := client.R().Get("/remote")
	http.Get("http://127.0.0.1/x")
}"#;
        let found: Vec<(RouteMethod, String, u32)> = extract(&Source::new(src, Lang::Go))
            .into_iter()
            .map(|route| (route.method, route.path, route.line))
            .collect();
        assert_eq!(
            found,
            vec![
                (RouteMethod::Get, "/items/{id}".to_owned(), 3),
                (RouteMethod::Any, "/static/".to_owned(), 4),
                (RouteMethod::Post, "/orders".to_owned(), 6),
                (RouteMethod::Put, "/orders".to_owned(), 6),
                (RouteMethod::Get, "/users/:id".to_owned(), 7),
                (RouteMethod::Delete, "/users/{id}".to_owned(), 8),
            ]
        );
    }
}
