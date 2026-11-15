//! Express, Fastify and Hono route extraction from JavaScript/TypeScript sources.
//!
//! `x.get("/path", handler)` is also the shape of every HTTP client call (`axios.get`,
//! `api.get`), so a call only counts when its receiver is known to be a server object:
//! either declared in the same file from a server constructor, or named like one. A path
//! argument must also be followed by a handler argument, which client calls rarely have
//! and which excludes Express's `app.get("setting")` getter.
//!
//! Mounts are resolved per receiver within the file: `app.use("/api", router)` and Hono
//! `app.route("/api", sub)` re-root every route registered on the child, and Hono
//! `basePath("/v1")` prefixes the instance it creates. Prefixes compose along mount chains.

use std::collections::HashMap;
use std::sync::LazyLock;

use regex::Regex;

use super::lex::{is_ident_byte, literal_end, matching_paren, read_string, skip_ws, Lang, Source};
use super::routes::{compile, method_from_token, RawRoute};
use crate::engine::types::{RouteMethod, RouteSource};

const ROUTE_VERBS: [&str; 8] = [
    "get", "post", "put", "patch", "delete", "del", "options", "head",
];
/// Bounds prefix composition; a mount cycle (`a.use(b)`, `b.use(a)`) would otherwise recurse
/// without end.
const MAX_MOUNT_DEPTH: usize = 8;
/// A router mounted under many prefixes multiplies its routes; past this the list stops being
/// useful as a target picker.
const MAX_PREFIXES: usize = 16;

static ROOT_CALL: LazyLock<Option<Regex>> = LazyLock::new(|| {
    compile(
        r"([A-Za-z_$][A-Za-z0-9_$]*)\s*\.\s*(get|post|put|patch|delete|del|options|head|all|route)\s*\(",
    )
});
static MOUNT_CALL: LazyLock<Option<Regex>> =
    LazyLock::new(|| compile(r"([A-Za-z_$][A-Za-z0-9_$]*)\s*\.\s*(?:use|route)\s*\("));
static BASE_PATH: LazyLock<Option<Regex>> =
    LazyLock::new(|| compile(r#"\.\s*basePath\s*\(\s*['"`](/[^'"`\n]*)['"`]\s*\)"#));
static DERIVED_BASE: LazyLock<Option<Regex>> =
    LazyLock::new(|| compile(r"^([A-Za-z_$][A-Za-z0-9_$]*)\s*\.\s*basePath\s*\("));
static IDENT: LazyLock<Option<Regex>> = LazyLock::new(|| compile(r"^[A-Za-z_$][A-Za-z0-9_$]*$"));
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

/// `child` serves its routes under `parent` at `prefix`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Mount<'a> {
    child: &'a str,
    parent: &'a str,
    prefix: String,
}

#[derive(Default)]
struct Declarations<'a> {
    receivers: HashMap<&'a str, Receiver>,
    /// Hono instances created with `.basePath(..)`; the prefix applies to their own routes
    /// and to sub-apps routed into them.
    bases: HashMap<&'a str, String>,
    /// `const v1 = app.basePath("/v1")` shares `app`'s router under a longer prefix.
    derived: Vec<Mount<'a>>,
}

impl Declarations<'_> {
    fn is_server(&self, name: &str) -> bool {
        match self.receivers.get(name) {
            Some(Receiver::Server(_)) => true,
            Some(Receiver::Client) => false,
            None => plausible_server(name),
        }
    }
}

pub fn extract(source: &Source) -> Vec<RawRoute> {
    let src = source.text.as_str();
    let lines = &source.lines;
    let Some(root_call) = ROOT_CALL.as_ref() else {
        return Vec::new();
    };
    let declared = declarations(src);
    let file_default = file_framework(src);
    let mut routes: Vec<(&str, RawRoute)> = Vec::new();

    for caps in root_call.captures_iter(src) {
        let (Some(whole), Some(name), Some(verb)) = (caps.get(0), caps.get(1), caps.get(2)) else {
            continue;
        };
        if source.in_string(whole.start()) {
            continue;
        }
        let receiver = name.as_str();
        let source = match declared.receivers.get(receiver) {
            Some(Receiver::Server(source)) => *source,
            Some(Receiver::Client) => continue,
            None if plausible_server(receiver) => match (file_default, receiver) {
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
            routes.push((receiver, RawRoute::new(method, path, source, line)));
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

    let mounts = mounts(source, &declared);
    let mut resolved: HashMap<&str, Vec<String>> = HashMap::new();
    let mut out = Vec::with_capacity(routes.len());
    for (receiver, route) in routes {
        let prefixes = resolved
            .entry(receiver)
            .or_insert_with(|| prefixes(receiver, &declared, &mounts, 0));
        for prefix in prefixes.iter() {
            out.push(route.clone().mounted(prefix));
        }
    }
    out
}

/// `<parent>.use("/p", child, ...)` and Hono `<parent>.route("/p", child)`. Every plain
/// identifier argument that names a server object is a mounted child; middleware
/// identifiers and inline expressions (`express.static(..)`, `require(..)`) are not.
fn mounts<'a>(source: &'a Source, declared: &Declarations<'a>) -> Vec<Mount<'a>> {
    let src = source.text.as_str();
    let (Some(mount_call), Some(ident)) = (MOUNT_CALL.as_ref(), IDENT.as_ref()) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for caps in mount_call.captures_iter(src) {
        let (Some(whole), Some(parent)) = (caps.get(0), caps.get(1)) else {
            continue;
        };
        let parent = parent.as_str();
        if source.in_string(whole.start()) || !declared.is_server(parent) {
            continue;
        }
        let open = whole.end() - 1;
        let Some(close) = matching_paren(src, open, Lang::Js) else {
            continue;
        };
        let Some((prefix, end)) = read_string(src, skip_ws(src, open + 1), Lang::Js) else {
            continue;
        };
        let comma = skip_ws(src, end);
        if !prefix.starts_with('/') || src.as_bytes().get(comma) != Some(&b',') {
            continue;
        }
        for child in top_level_args(&src[comma + 1..close]) {
            if child != parent && ident.is_match(child) && declared.is_server(child) {
                out.push(Mount {
                    child,
                    parent,
                    prefix: prefix.clone(),
                });
            }
        }
    }
    out
}

/// Comma-separated arguments at nesting depth zero; array arguments (`[auth, router]`, as
/// Express accepts) are flattened.
fn top_level_args(args: &str) -> Vec<&str> {
    let bytes = args.as_bytes();
    let mut out = Vec::new();
    let mut depth = 0usize;
    let mut start = 0;
    let mut at = 0;
    while at < bytes.len() {
        if let Some(end) = literal_end(bytes, at, Lang::Js) {
            at = end;
            continue;
        }
        match bytes[at] {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => depth = depth.saturating_sub(1),
            b',' if depth == 0 => {
                out.push(&args[start..at]);
                start = at + 1;
            }
            _ => {}
        }
        at += 1;
    }
    out.push(&args[start..]);
    out.into_iter()
        .map(str::trim)
        .flat_map(
            |arg| match arg.strip_prefix('[').and_then(|a| a.strip_suffix(']')) {
                Some(inner) => top_level_args(inner),
                None => vec![arg],
            },
        )
        .filter(|arg| !arg.is_empty())
        .collect()
}

/// Every full prefix under which `name`'s routes are served, outermost mount first. An
/// unmounted receiver is a root (or is mounted in another file) and keeps its own base path.
fn prefixes(name: &str, declared: &Declarations, mounts: &[Mount], depth: usize) -> Vec<String> {
    let own = declared.bases.get(name).map_or("", String::as_str);
    let parents: Vec<&Mount> = mounts
        .iter()
        .chain(&declared.derived)
        .filter(|mount| mount.child == name)
        .collect();
    if parents.is_empty() || depth >= MAX_MOUNT_DEPTH {
        return vec![own.to_owned()];
    }
    let mut out: Vec<String> = Vec::new();
    for mount in parents {
        for outer in prefixes(mount.parent, declared, mounts, depth + 1) {
            let joined = format!("{outer}{}{own}", mount.prefix);
            if !out.contains(&joined) {
                out.push(joined);
            }
        }
    }
    out.truncate(MAX_PREFIXES);
    out
}

fn base_path(init: &str) -> Option<String> {
    BASE_PATH
        .as_ref()?
        .captures(init)?
        .get(1)
        .map(|base| base.as_str().to_owned())
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

fn declarations(src: &str) -> Declarations<'_> {
    let mut out = Declarations::default();
    let Some(re) = DECLARATION.as_ref() else {
        return out;
    };
    for caps in re.captures_iter(src) {
        let (Some(name), Some(init)) = (caps.get(1), caps.get(2)) else {
            continue;
        };
        let (name, init) = (name.as_str(), init.as_str().trim_start());
        let derived_from = DERIVED_BASE
            .as_ref()
            .and_then(|re| re.captures(init))
            .and_then(|caps| caps.get(1));
        if let (Some(parent), Some(prefix)) = (derived_from, base_path(init)) {
            out.receivers
                .insert(name, Receiver::Server(RouteSource::Hono));
            out.derived.push(Mount {
                child: name,
                parent: parent.as_str(),
                prefix,
            });
            continue;
        }
        let Some(receiver) = classify_init(init) else {
            continue;
        };
        if receiver == Receiver::Server(RouteSource::Hono) {
            if let Some(base) = base_path(init) {
                out.bases.insert(name, base);
            }
        }
        out.receivers.insert(name, receiver);
    }
    out
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

    fn mounted(src: &str) -> Vec<(RouteMethod, String, Option<String>, u32)> {
        extract(&Source::new(src, Lang::Js))
            .into_iter()
            .map(|route| (route.method, route.path, route.prefix, route.line))
            .collect()
    }

    #[test]
    fn express_mounts_compose_through_routers() {
        let src = r#"const express = require("express");
const app = express();
const api = express.Router();
const admin = express.Router();
const orders = express.Router();
app.get("/health", h);
api.get("/users/:id", getUser);
admin.delete("/cache", flush);
orders.post("/", createOrder);
api.use("/admin", requireAdmin, admin);
app.use("/api/v1", [rateLimit, api]);
app.use("/orders", orders);
app.use("/legacy", orders);
app.use("/static", express.static("public"));
app.use(errorRouter);
"#;
        let some = |p: &str| Some(p.to_owned());
        assert_eq!(
            mounted(src),
            vec![
                (RouteMethod::Get, "/health".to_owned(), None, 6),
                (
                    RouteMethod::Get,
                    "/api/v1/users/:id".to_owned(),
                    some("/api/v1"),
                    7
                ),
                (
                    RouteMethod::Delete,
                    "/api/v1/admin/cache".to_owned(),
                    some("/api/v1/admin"),
                    8
                ),
                (RouteMethod::Post, "/orders/".to_owned(), some("/orders"), 9),
                (RouteMethod::Post, "/legacy/".to_owned(), some("/legacy"), 9),
            ]
        );
    }

    #[test]
    fn hono_base_paths_derived_instances_and_sub_apps() {
        let src = "import { Hono } from 'hono'\n\
                   const app = new Hono().basePath('/api')\n\
                   const books = new Hono()\n\
                   const v2 = app.basePath('/v2')\n\
                   books.get('/', list).post('/:id', create)\n\
                   v2.get('/status', status)\n\
                   app.route('/books', books)\n\
                   app.get('/ping', ping)\n";
        let some = |p: &str| Some(p.to_owned());
        assert_eq!(
            mounted(src),
            vec![
                (
                    RouteMethod::Get,
                    "/api/books/".to_owned(),
                    some("/api/books"),
                    5
                ),
                (
                    RouteMethod::Post,
                    "/api/books/:id".to_owned(),
                    some("/api/books"),
                    5
                ),
                (
                    RouteMethod::Get,
                    "/api/v2/status".to_owned(),
                    some("/api/v2"),
                    6
                ),
                (RouteMethod::Get, "/api/ping".to_owned(), some("/api"), 8),
            ]
        );
    }

    #[test]
    fn mount_cycles_and_client_receivers_are_bounded() {
        let src = "const a = express.Router();\nconst b = express.Router();\n\
                   const http = axios.create();\n\
                   a.use('/x', b);\nb.use('/y', a);\nhttp.use('/z', a);\na.get('/r', h);\n";
        let routes = mounted(src);
        assert_eq!(routes.len(), 1);
        let (_, path, prefix, _) = &routes[0];
        // `a` is served under `b` at `/y`, `b` under `a` at `/x`: outermost first, cut at the
        // depth bound.
        assert_eq!(path, "/x/y/x/y/x/y/x/y/r");
        assert!(prefix.is_some());
        assert!(!path.contains("/z"));
        assert_eq!(
            top_level_args(" auth, [limit, api], fn(a, b), 'x,y' "),
            ["auth", "limit", "api", "fn(a, b)", "'x,y'"]
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
