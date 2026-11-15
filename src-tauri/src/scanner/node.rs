//! Express, Fastify and Hono route extraction from JavaScript/TypeScript sources.
//!
//! `x.get("/path", handler)` is also the shape of every HTTP client call (`axios.get`,
//! `api.get`), so a call only counts when its receiver is known to be a server object:
//! either declared in the same file from a server constructor, or named like one. A path
//! argument must also be followed by a handler argument, which client calls rarely have
//! and which excludes Express's `app.get("setting")` getter.

use std::collections::HashMap;
use std::sync::LazyLock;

use regex::Regex;

use super::lex::{is_ident_byte, matching_paren, read_string, skip_ws, Lang, Source};
use super::routes::{compile, method_from_token, RawRoute};
use crate::engine::types::{RouteMethod, RouteSource};

const ROUTE_VERBS: [&str; 8] = [
    "get", "post", "put", "patch", "delete", "del", "options", "head",
];

static ROOT_CALL: LazyLock<Option<Regex>> = LazyLock::new(|| {
    compile(
        r"([A-Za-z_$][A-Za-z0-9_$]*)\s*\.\s*(get|post|put|patch|delete|del|options|head|all|route)\s*\(",
    )
});
static DECLARATION: LazyLock<Option<Regex>> = LazyLock::new(|| {
    compile(
        r"(?-u:\b)(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*(?::[^=;\n]+)?=\s*(?:await\s+)?([^;\n]{1,120})",
    )
});
static IMPORT_HONO: LazyLock<Option<Regex>> =
    LazyLock::new(|| compile(r#"(?:from\s+|require\(\s*)['"]hono(?:/[^'"]*)?['"]"#));
static IMPORT_FASTIFY: LazyLock<Option<Regex>> =
    LazyLock::new(|| compile(r#"(?:from\s+|require\(\s*)['"]fastify['"]"#));
static FASTIFY_METHOD: LazyLock<Option<Regex>> =
    LazyLock::new(|| compile(r#"(?-u:\b)method\s*:\s*(\[[^\]]*\]|['"][A-Za-z]+['"])"#));
static FASTIFY_URL: LazyLock<Option<Regex>> =
    LazyLock::new(|| compile(r#"(?-u:\b)(?:url|path)\s*:\s*['"`](/[^'"`\n]*)['"`]"#));
static QUOTED_TOKEN: LazyLock<Option<Regex>> = LazyLock::new(|| compile(r#"['"]([A-Za-z]+)['"]"#));

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Receiver {
    Server(RouteSource),
    Client,
}

pub fn extract(source: &Source) -> Vec<RawRoute> {
    let src = source.text.as_str();
    let lines = &source.lines;
    let Some(root_call) = ROOT_CALL.as_ref() else {
        return Vec::new();
    };
    let declared = declarations(src);
    let file_default = file_framework(src);
    let mut routes = Vec::new();

    for caps in root_call.captures_iter(src) {
        let (Some(whole), Some(name), Some(verb)) = (caps.get(0), caps.get(1), caps.get(2)) else {
            continue;
        };
        if source.in_string(whole.start()) {
            continue;
        }
        let source = match declared.get(name.as_str()) {
            Some(Receiver::Server(source)) => *source,
            Some(Receiver::Client) => continue,
            None if plausible_server(name.as_str()) => match (file_default, name.as_str()) {
                (Some(source), _) => source,
                (None, "fastify" | "instance") => RouteSource::Fastify,
                (None, _) => RouteSource::Express,
            },
            None => continue,
        };
        let open = whole.end() - 1;
        let Some(close) = matching_paren(src, open, Lang::Js) else {
            continue;
        };
        let line = lines.line(verb.start());
        let mut push = |method: RouteMethod, path: String, line: u32| {
            routes.push(RawRoute {
                method,
                path,
                source,
                line,
            });
        };

        if verb.as_str() == "route" {
            let arg = skip_ws(src, open + 1);
            if src.as_bytes().get(arg) == Some(&b'{') {
                for (method, path) in fastify_options(&src[arg..close]) {
                    push(method, path, line);
                }
            } else if let Some((path, _)) =
                read_string(src, arg, Lang::Js).filter(|(p, _)| p.starts_with('/'))
            {
                // Express `router.route("/x").get(h).post(h)`: verbs chained without a path.
                for (verb, _, _, at) in chain(src, close + 1) {
                    if let Some(method) = route_method(verb) {
                        push(method, path.clone(), lines.line(at));
                    }
                }
            }
            continue;
        }

        if let (Some(method), Some(path)) = (route_method(verb.as_str()), route_path(src, open)) {
            push(method, path, line);
        }
        // Hono and Fastify return the app from every verb, so `app.get(..).post(..)` chains.
        for (verb, chained_open, _, at) in chain(src, close + 1) {
            if let (Some(method), Some(path)) = (route_method(verb), route_path(src, chained_open))
            {
                push(method, path, lines.line(at));
            }
        }
    }
    routes
}

fn route_method(verb: &str) -> Option<RouteMethod> {
    if verb == "all" {
        return Some(RouteMethod::Any);
    }
    if ROUTE_VERBS.contains(&verb) {
        method_from_token(verb)
    } else {
        None
    }
}

/// First argument as a static path, provided a handler argument follows it.
fn route_path(src: &str, open: usize) -> Option<String> {
    let (path, end) = read_string(src, skip_ws(src, open + 1), Lang::Js)?;
    let after = skip_ws(src, end);
    (path.starts_with('/') && src.as_bytes().get(after) == Some(&b',')).then_some(path)
}

/// Calls chained onto the expression ending at `from`: `(verb, open, close, verb_offset)`.
fn chain(src: &str, mut from: usize) -> Vec<(&str, usize, usize, usize)> {
    let bytes = src.as_bytes();
    let mut calls = Vec::new();
    loop {
        let dot = skip_ws(src, from);
        if bytes.get(dot) != Some(&b'.') {
            break;
        }
        let start = skip_ws(src, dot + 1);
        let mut end = start;
        while bytes.get(end).copied().is_some_and(is_ident_byte) {
            end += 1;
        }
        let open = skip_ws(src, end);
        if end == start || bytes.get(open) != Some(&b'(') {
            break;
        }
        let Some(close) = matching_paren(src, open, Lang::Js) else {
            break;
        };
        calls.push((&src[start..end], open, close, start));
        from = close + 1;
    }
    calls
}

fn fastify_options(object: &str) -> Vec<(RouteMethod, String)> {
    let (Some(method_re), Some(url_re), Some(token_re)) = (
        FASTIFY_METHOD.as_ref(),
        FASTIFY_URL.as_ref(),
        QUOTED_TOKEN.as_ref(),
    ) else {
        return Vec::new();
    };
    let Some(url) = url_re.captures(object).and_then(|caps| caps.get(1)) else {
        return Vec::new();
    };
    let Some(methods) = method_re.captures(object).and_then(|caps| caps.get(1)) else {
        return Vec::new();
    };
    token_re
        .captures_iter(methods.as_str())
        .filter_map(|caps| {
            caps.get(1)
                .and_then(|token| method_from_token(token.as_str()))
        })
        .map(|method| (method, url.as_str().to_owned()))
        .collect()
}

fn declarations(src: &str) -> HashMap<&str, Receiver> {
    let Some(re) = DECLARATION.as_ref() else {
        return HashMap::new();
    };
    re.captures_iter(src)
        .filter_map(|caps| {
            let name = caps.get(1)?.as_str();
            let init = caps.get(2)?.as_str();
            classify_init(init).map(|receiver| (name, receiver))
        })
        .collect()
}

fn classify_init(init: &str) -> Option<Receiver> {
    let init = init.trim_start();
    if init.contains("new Hono") || init.contains("new OpenAPIHono") {
        return Some(Receiver::Server(RouteSource::Hono));
    }
    if init.starts_with("Fastify(") || init.starts_with("fastify(") {
        return Some(Receiver::Server(RouteSource::Fastify));
    }
    if init.starts_with("express(")
        || init.contains("express.Router(")
        || init.starts_with("Router(")
        || init.starts_with("new Router(")
    {
        return Some(Receiver::Server(RouteSource::Express));
    }
    const CLIENTS: [&str; 9] = [
        "axios",
        "ky.",
        "ky(",
        "got.",
        "supertest",
        "request(",
        "useRouter(",
        "createClient",
        "superagent",
    ];
    CLIENTS
        .iter()
        .any(|client| init.contains(client))
        .then_some(Receiver::Client)
}

fn file_framework(src: &str) -> Option<RouteSource> {
    let imports = |re: &LazyLock<Option<Regex>>| re.as_ref().is_some_and(|re| re.is_match(src));
    if imports(&IMPORT_HONO) {
        Some(RouteSource::Hono)
    } else if imports(&IMPORT_FASTIFY) {
        Some(RouteSource::Fastify)
    } else {
        None
    }
}

/// Undeclared receivers (function parameters, imports) are accepted by name only. `api` is
/// deliberately absent: it is at least as common for HTTP client instances as for routers.
fn plausible_server(name: &str) -> bool {
    const EXACT: [&str; 7] = [
        "app", "server", "router", "routes", "fastify", "instance", "hono",
    ];
    const SUFFIXES: [&str; 8] = [
        "Router", "router", "Routes", "routes", "App", "app", "Server", "server",
    ];
    EXACT.contains(&name)
        || SUFFIXES
            .iter()
            .any(|suffix| name.len() > suffix.len() && name.ends_with(suffix))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn run(src: &str) -> Vec<(RouteMethod, String, RouteSource, u32)> {
        extract(&Source::new(src, Lang::Js))
            .into_iter()
            .map(|route| (route.method, route.path, route.source, route.line))
            .collect()
    }

    #[test]
    fn express_routes_and_client_calls() {
        let src = r#"const express = require("express");
const app = express();
const userRouter = express.Router();
const api = axios.create({ baseURL: "/api" });
app.get("/health", (req, res) => res.send("ok"));
userRouter.post('/users/:id(\\d+)', createUser);
app.set("env", "x"); app.get("env");
api.get("/users", { params: {} });
axios.post("/login", body);
// app.delete("/legacy", h);
app.route("/orders/:id")
  .get(getOrder)
  .put(putOrder);
"#;
        assert_eq!(
            run(src),
            vec![
                (
                    RouteMethod::Get,
                    "/health".to_owned(),
                    RouteSource::Express,
                    5
                ),
                (
                    RouteMethod::Post,
                    "/users/:id(\\d+)".to_owned(),
                    RouteSource::Express,
                    6
                ),
                (
                    RouteMethod::Get,
                    "/orders/:id".to_owned(),
                    RouteSource::Express,
                    12
                ),
                (
                    RouteMethod::Put,
                    "/orders/:id".to_owned(),
                    RouteSource::Express,
                    13
                ),
            ]
        );
    }

    #[test]
    fn fastify_shorthand_route_options_and_plugins() {
        let src = r#"import Fastify from 'fastify'
const server = Fastify({ logger: true })
server.get('/ping', async () => 'pong')
server.route({
  method: ['GET', 'POST'],
  url: '/items/:id',
  handler: async () => ({}),
})
export default async function plugin(fastify) {
  fastify.delete('/items/:id', async () => {})
}
"#;
        assert_eq!(
            run(src),
            vec![
                (
                    RouteMethod::Get,
                    "/ping".to_owned(),
                    RouteSource::Fastify,
                    3
                ),
                (
                    RouteMethod::Get,
                    "/items/:id".to_owned(),
                    RouteSource::Fastify,
                    4
                ),
                (
                    RouteMethod::Post,
                    "/items/:id".to_owned(),
                    RouteSource::Fastify,
                    4
                ),
                (
                    RouteMethod::Delete,
                    "/items/:id".to_owned(),
                    RouteSource::Fastify,
                    10
                ),
            ]
        );
    }

    #[test]
    fn hono_chains_and_dynamic_paths() {
        let src = "import { Hono } from 'hono'\n\
                   const app = new Hono()\n\
                   app.get('/a', (c) => c.text('a')).post('/b', (c) => c.text('b'))\n\
                   app.all('/any', h)\n\
                   app.get(`/user/${id}`, h)\n";
        assert_eq!(
            run(src),
            vec![
                (RouteMethod::Get, "/a".to_owned(), RouteSource::Hono, 3),
                (RouteMethod::Post, "/b".to_owned(), RouteSource::Hono, 3),
                (RouteMethod::Any, "/any".to_owned(), RouteSource::Hono, 4),
            ]
        );
    }

    #[test]
    fn receiver_names() {
        assert!(plausible_server("adminRouter"));
        assert!(plausible_server("app"));
        assert!(!plausible_server("api"));
        assert!(!plausible_server("router_"));
        assert!(!plausible_server("Router"));
    }
}
