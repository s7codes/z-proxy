//! Filesystem route scanner.
//!
//! Walks a project tree and extracts HTTP route declarations with per-framework lexical
//! extractors. Mount prefixes are resolved when the mount and the router it mounts are
//! declared in the same file (`app.use("/api", router)`, Hono `basePath` and
//! `.route("/p", sub)`, Axum `.nest("/p", ..)`); composition across files is invisible to a
//! lexical pass, so such routes are reported as written at their declaration site.

use std::path::{Path, PathBuf};
use std::sync::LazyLock;
use std::time::Instant;

use regex::Regex;
use uuid::Uuid;
use walkdir::{DirEntry, WalkDir};

use super::lex::{Lang, Source};
use super::{axum, go, next, node, openapi};
use crate::engine::error::{EngineError, EngineResult};
use crate::engine::types::{DiscoveredRoute, RouteMethod, RouteScanReport, RouteSource, ScanIssue};

/// Build output, dependency and VCS trees: large, never hand-written, and full of route
/// declarations that belong to third-party code.
pub const SKIP_DIRS: [&str; 14] = [
    "node_modules",
    ".git",
    "target",
    "dist",
    ".next",
    ".turbo",
    ".vercel",
    ".svelte-kit",
    ".output",
    "coverage",
    "vendor",
    ".venv",
    "__tests__",
    "__mocks__",
];
const LOCKFILES: [&str; 3] = ["package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml"];
const MAX_FILES: u32 = 50_000;
const MAX_SOURCE_BYTES: u64 = 1024 * 1024;
const MAX_SPEC_BYTES: u64 = 8 * 1024 * 1024;
const MAX_ROUTES: usize = 5_000;
const MAX_ISSUES: usize = 100;

/// A route as an extractor sees it: path still in framework syntax.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawRoute {
    pub method: RouteMethod,
    /// Full path, mount prefix included.
    pub path: String,
    pub source: RouteSource,
    pub line: u32,
    /// Mount prefix resolved within the file and already joined into `path`.
    pub prefix: Option<String>,
}

impl RawRoute {
    pub fn new(method: RouteMethod, path: String, source: RouteSource, line: u32) -> Self {
        Self {
            method,
            path,
            source,
            line,
            prefix: None,
        }
    }

    /// Re-roots the route under `prefix`; an empty or `/` prefix leaves it unchanged.
    pub fn mounted(mut self, prefix: &str) -> Self {
        if prefix.trim_matches('/').is_empty() {
            return self;
        }
        self.path = format!("{prefix}{}", self.path);
        self.prefix = Some(prefix.to_owned());
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FileKind {
    Js,
    Rust,
    Go,
    Json,
    Yaml,
}

/// Patterns are literals exercised by every extractor test, so `None` never occurs in
/// practice; if it did, the extractor yields no routes instead of panicking. Patterns use
/// ASCII word boundaries (`(?-u:\b)`): the Unicode form disables the lazy DFA on non-ASCII
/// input, which made scans of commented or localized sources several times slower.
pub fn compile(pattern: &str) -> Option<Regex> {
    Regex::new(pattern).ok()
}

pub fn method_from_token(token: &str) -> Option<RouteMethod> {
    match token.to_ascii_lowercase().as_str() {
        "get" => Some(RouteMethod::Get),
        "post" => Some(RouteMethod::Post),
        "put" => Some(RouteMethod::Put),
        "patch" => Some(RouteMethod::Patch),
        "delete" | "del" => Some(RouteMethod::Delete),
        "head" => Some(RouteMethod::Head),
        "options" => Some(RouteMethod::Options),
        "any" | "all" => Some(RouteMethod::Any),
        _ => None,
    }
}

pub fn scan(root_input: &str) -> EngineResult<RouteScanReport> {
    let started = Instant::now();
    let root = resolve_root(root_input)?;
    let mut scan = Scan::default();

    let walker = WalkDir::new(&root)
        .follow_links(false)
        .into_iter()
        .filter_entry(|entry| !is_skipped_dir(entry));
    for entry in walker {
        let entry = match entry {
            Ok(entry) => entry,
            Err(err) => {
                let file = err
                    .path()
                    .map(|path| relative(&root, path))
                    .unwrap_or_default();
                scan.issue(file, err.to_string());
                continue;
            }
        };
        if !entry.file_type().is_file() {
            continue;
        }
        if scan.files_visited >= MAX_FILES || scan.routes.len() >= MAX_ROUTES {
            scan.truncated = true;
            break;
        }
        scan.files_visited += 1;
        scan.visit(&root, &entry);
    }

    let mut routes = scan.routes;
    routes.sort_by(|a, b| {
        (&a.path, a.method, &a.file, a.line).cmp(&(&b.path, b.method, &b.file, b.line))
    });
    routes.dedup();
    if routes.len() > MAX_ROUTES {
        routes.truncate(MAX_ROUTES);
        scan.truncated = true;
    }

    Ok(RouteScanReport {
        id: Uuid::new_v4(),
        root: display_path(&root),
        files_visited: scan.files_visited,
        files_parsed: scan.files_parsed,
        elapsed_us: u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
        truncated: scan.truncated,
        routes,
        issues: scan.issues,
    })
}

#[derive(Default)]
struct Scan {
    files_visited: u32,
    files_parsed: u32,
    truncated: bool,
    routes: Vec<DiscoveredRoute>,
    issues: Vec<ScanIssue>,
}

impl Scan {
    fn issue(&mut self, file: String, reason: String) {
        if self.issues.len() < MAX_ISSUES {
            self.issues.push(ScanIssue { file, reason });
        }
    }

    fn visit(&mut self, root: &Path, entry: &DirEntry) {
        let name = entry.file_name().to_string_lossy();
        let Some(kind) = classify(&name) else {
            return;
        };
        let file = relative(root, entry.path());
        let limit = match kind {
            FileKind::Json | FileKind::Yaml => MAX_SPEC_BYTES,
            FileKind::Js | FileKind::Rust | FileKind::Go => MAX_SOURCE_BYTES,
        };
        match entry.metadata() {
            Ok(meta) if meta.len() > limit => {
                self.issue(
                    file,
                    format!(
                        "skipped: {} bytes exceeds the {limit} byte limit",
                        meta.len()
                    ),
                );
                return;
            }
            Ok(_) => {}
            Err(err) => {
                self.issue(file, err.to_string());
                return;
            }
        }
        let src = match std::fs::read(entry.path()).map(String::from_utf8) {
            Ok(Ok(src)) => src,
            Ok(Err(_)) => {
                self.issue(file, "skipped: not valid UTF-8".to_owned());
                return;
            }
            Err(err) => {
                self.issue(file, err.to_string());
                return;
            }
        };
        self.files_parsed += 1;
        let src = src.strip_prefix('\u{feff}').unwrap_or(&src);
        let components: Vec<String> = file.split('/').map(str::to_owned).collect();

        match extract(kind, &components, src) {
            Ok(raw) => {
                self.routes
                    .extend(raw.into_iter().map(|route| discovered(route, &file)));
            }
            Err(reason) => self.issue(file, reason),
        }
    }
}

pub fn discovered(route: RawRoute, file: &str) -> DiscoveredRoute {
    let (path, params) = normalize_path(&route.path);
    let prefix = route
        .prefix
        .map(|prefix| normalize_path(&prefix).0)
        .filter(|prefix| prefix != "/");
    DiscoveredRoute {
        method: route.method,
        path,
        params,
        source: route.source,
        file: file.to_owned(),
        line: route.line,
        prefix,
    }
}

fn extract(kind: FileKind, components: &[String], src: &str) -> Result<Vec<RawRoute>, String> {
    match kind {
        FileKind::Js => {
            let source = Source::new(src, Lang::Js);
            let mut routes = next::extract(components, &source);
            routes.extend(node::extract(&source));
            Ok(routes)
        }
        FileKind::Rust => Ok(axum::extract(&Source::new(src, Lang::Rust))),
        FileKind::Go => Ok(go::extract(&Source::new(src, Lang::Go))),
        FileKind::Json => openapi::from_json(src),
        FileKind::Yaml => openapi::from_yaml(src),
    }
}

fn classify(name: &str) -> Option<FileKind> {
    let lower = name.to_ascii_lowercase();
    if LOCKFILES.contains(&lower.as_str())
        || [".d.ts", ".d.mts", ".d.cts", "_test.go"]
            .iter()
            .any(|suffix| lower.ends_with(suffix))
        || [".min.", ".test.", ".spec."]
            .iter()
            .any(|infix| lower.contains(infix))
    {
        return None;
    }
    let (_, ext) = lower.rsplit_once('.')?;
    match ext {
        "js" | "jsx" | "ts" | "tsx" | "mjs" | "cjs" | "mts" | "cts" => Some(FileKind::Js),
        "rs" => Some(FileKind::Rust),
        "go" => Some(FileKind::Go),
        "json" => Some(FileKind::Json),
        "yaml" | "yml" => Some(FileKind::Yaml),
        _ => None,
    }
}

fn is_skipped_dir(entry: &DirEntry) -> bool {
    entry.depth() > 0
        && entry.file_type().is_dir()
        && SKIP_DIRS.contains(&entry.file_name().to_string_lossy().as_ref())
}

fn resolve_root(input: &str) -> EngineResult<PathBuf> {
    let shown = input.trim();
    let invalid = |reason: &str| EngineError::InvalidScanRoot {
        path: shown.to_owned(),
        reason: reason.to_owned(),
    };
    // Explorer's "Copy as path" wraps the path in double quotes.
    let trimmed = shown.trim_matches(|c| c == '"' || c == '\'').trim();
    if trimmed.is_empty() {
        return Err(invalid("empty path"));
    }
    let path = Path::new(trimmed);
    // A relative path would resolve against the app's working directory, which the operator
    // neither sees nor controls.
    if !path.is_absolute() {
        return Err(invalid("path must be absolute"));
    }
    let canonical = std::fs::canonicalize(path).map_err(|err| invalid(&err.to_string()))?;
    if !canonical.is_dir() {
        return Err(invalid("not a directory"));
    }
    if canonical.parent().is_none() {
        return Err(invalid("refusing to scan a filesystem root"));
    }
    Ok(canonical)
}

/// Strips the Windows verbatim prefix `canonicalize` adds, which no operator types.
pub fn display_path(path: &Path) -> String {
    let raw = path.to_string_lossy();
    if let Some(unc) = raw.strip_prefix(r"\\?\UNC\") {
        return format!(r"\\{unc}");
    }
    raw.strip_prefix(r"\\?\").unwrap_or(&raw).to_owned()
}

fn relative(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .components()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

static COLON_PARAM: LazyLock<Option<Regex>> =
    LazyLock::new(|| compile(r":([A-Za-z_][A-Za-z0-9_]*)(?:\([^)]*\))?\??"));
static BRACE_PARAM: LazyLock<Option<Regex>> = LazyLock::new(|| compile(r"\{([^{}]+)\}"));

/// Normalizes every framework's path syntax to one template form: parameters as `{name}`,
/// catch-alls as `{*name}`. Returns the template and its parameter names in order.
pub fn normalize_path(raw: &str) -> (String, Vec<String>) {
    let mut params = Vec::new();
    let segments: Vec<String> = raw
        .split('/')
        .filter(|segment| !segment.is_empty())
        .filter_map(|segment| normalize_segment(segment, &mut params))
        .collect();
    (format!("/{}", segments.join("/")), params)
}

fn normalize_segment(segment: &str, params: &mut Vec<String>) -> Option<String> {
    let mut param = |name: &str, catch_all: bool| {
        params.push(name.to_owned());
        Some(if catch_all {
            format!("{{*{name}}}")
        } else {
            format!("{{{name}}}")
        })
    };

    // Go 1.22 `{$}` anchors the match to the exact path; it is not a URL segment.
    if segment == "{$}" {
        return None;
    }
    if let Some(name) = strip(segment, "[[...", "]]").or_else(|| strip(segment, "[...", "]")) {
        return param(name, true);
    }
    if let Some(name) = strip(segment, "[", "]") {
        return param(name, false);
    }
    if let Some(name) = segment.strip_prefix('*') {
        return param(if name.is_empty() { "wildcard" } else { name }, true);
    }
    if let Some(inner) = strip(segment, "{", "}").filter(|inner| !inner.contains(['{', '}'])) {
        if let Some(name) = inner.strip_prefix('*') {
            return param(name, true);
        }
        if let Some(name) = inner.strip_suffix("...") {
            return param(name, true);
        }
        return param(inner, false);
    }

    // Inline forms: `:id`, `:from-:to`, `:id(\d+)?`, and `{id}` embedded in a literal such
    // as `{id}.json`.
    let mut out = String::with_capacity(segment.len());
    let mut last = 0;
    if let Some(re) = COLON_PARAM.as_ref() {
        for caps in re.captures_iter(segment) {
            let (Some(whole), Some(name)) = (caps.get(0), caps.get(1)) else {
                continue;
            };
            out.push_str(&segment[last..whole.start()]);
            out.push_str(&format!("{{{}}}", name.as_str()));
            params.push(name.as_str().to_owned());
            last = whole.end();
        }
    }
    out.push_str(&segment[last..]);
    if let Some(re) = BRACE_PARAM.as_ref() {
        let embedded: Vec<String> = re
            .captures_iter(&out)
            .filter_map(|caps| caps.get(1))
            .map(|name| name.as_str().to_owned())
            .filter(|name| !params.contains(name))
            .collect();
        params.extend(embedded);
    }
    Some(out)
}

fn strip<'a>(segment: &'a str, prefix: &str, suffix: &str) -> Option<&'a str> {
    segment
        .strip_prefix(prefix)
        .and_then(|rest| rest.strip_suffix(suffix))
        .filter(|name| !name.is_empty())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::fs;

    use super::*;

    struct Fixture {
        root: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!("chaosproxy-scan-{}", Uuid::new_v4()));
            fs::create_dir_all(&root).unwrap();
            Self { root }
        }

        fn write(&self, rel: &str, content: &str) -> &Self {
            let path = self.root.join(rel);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, content).unwrap();
            self
        }

        fn scan(&self) -> RouteScanReport {
            scan(self.root.to_str().unwrap()).unwrap()
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn summary(report: &RouteScanReport) -> Vec<String> {
        report
            .routes
            .iter()
            .map(|r| {
                let method = serde_json::to_value(r.method).unwrap();
                format!(
                    "{} {} {}:{}",
                    method.as_str().unwrap(),
                    r.path,
                    r.file,
                    r.line
                )
            })
            .collect()
    }

    #[test]
    fn patterns_compile() {
        assert!(COLON_PARAM.is_some());
        assert!(BRACE_PARAM.is_some());
    }

    #[test]
    fn normalizes_every_dialect() {
        let cases = [
            ("/users/:id", "/users/{id}", vec!["id"]),
            ("/users/:id(\\d+)?/posts", "/users/{id}/posts", vec!["id"]),
            (
                "/flights/:from-:to",
                "/flights/{from}-{to}",
                vec!["from", "to"],
            ),
            (
                "/orders/[id]/items/[...rest]",
                "/orders/{id}/items/{*rest}",
                vec!["id", "rest"],
            ),
            ("/docs/[[...slug]]", "/docs/{*slug}", vec!["slug"]),
            ("/files/{path...}", "/files/{*path}", vec!["path"]),
            ("/assets/*", "/assets/{*wildcard}", vec!["wildcard"]),
            ("/assets/{*rest}", "/assets/{*rest}", vec!["rest"]),
            ("/exact/{$}", "/exact", vec![]),
            ("/reports/{id}.json", "/reports/{id}.json", vec!["id"]),
            ("//double//slash/", "/double/slash", vec![]),
            ("/", "/", vec![]),
        ];
        for (raw, expected, params) in cases {
            let (path, found) = normalize_path(raw);
            assert_eq!(path, expected, "{raw}");
            assert_eq!(found, params, "{raw}");
        }
    }

    #[test]
    fn classifies_by_extension_and_exclusions() {
        assert_eq!(classify("route.ts"), Some(FileKind::Js));
        assert_eq!(classify("server.MJS"), Some(FileKind::Js));
        assert_eq!(classify("main.rs"), Some(FileKind::Rust));
        assert_eq!(classify("openapi.YML"), Some(FileKind::Yaml));
        assert_eq!(classify("types.d.ts"), None);
        assert_eq!(classify("app.test.ts"), None);
        assert_eq!(classify("vendor.min.js"), None);
        assert_eq!(classify("handler_test.go"), None);
        assert_eq!(classify("package-lock.json"), None);
        assert_eq!(classify("README.md"), None);
    }

    #[test]
    fn scans_a_mixed_project_and_skips_generated_trees() {
        let fx = Fixture::new();
        fx.write(
            "web/src/app/api/orders/[id]/route.ts",
            "export async function GET() {}\nexport async function DELETE() {}\n",
        )
        .write(
            "web/pages/api/health.ts",
            "export default function h(req, res) {}\n",
        )
        .write(
            "api/server.js",
            "const app = require('express')();\napp.post('/login', login);\n",
        )
        .write(
            "svc/src/main.rs",
            "let app = Router::new()\n    .route(\"/items/{id}\", get(show).patch(update));\n",
        )
        .write("gosvc/main.go", "mux.HandleFunc(\"GET /ping\", ping)\n")
        .write(
            "spec/openapi.yaml",
            "openapi: 3.0.3\npaths:\n  /pets:\n    get:\n      summary: x\n",
        );
        for skipped in SKIP_DIRS.iter().take(5) {
            fx.write(
                &format!("web/{skipped}/lib/server.js"),
                "app.get('/should-not-appear', h);\n",
            );
        }

        let report = fx.scan();
        assert_eq!(
            summary(&report),
            [
                "ANY /api/health web/pages/api/health.ts:1",
                "GET /api/orders/{id} web/src/app/api/orders/[id]/route.ts:1",
                "DELETE /api/orders/{id} web/src/app/api/orders/[id]/route.ts:2",
                "GET /items/{id} svc/src/main.rs:2",
                "PATCH /items/{id} svc/src/main.rs:2",
                "POST /login api/server.js:2",
                "GET /pets spec/openapi.yaml:4",
                "GET /ping gosvc/main.go:1",
            ]
        );
        assert!(!report.truncated);
        assert_eq!(report.files_parsed, 6);
        assert!(report.issues.is_empty(), "{:?}", report.issues);
        let orders = report
            .routes
            .iter()
            .find(|r| r.path == "/api/orders/{id}")
            .unwrap();
        assert_eq!(orders.params, ["id"]);
        assert_eq!(orders.source, RouteSource::NextAppRouter);
    }

    #[test]
    fn mount_prefixes_reach_the_report_normalized() {
        let fx = Fixture::new();
        fx.write(
            "api/server.js",
            "const app = express();\nconst users = express.Router();\nusers.get('/:id', show);\napp.use('/orgs/:org/users/', users);\n",
        );
        let report = fx.scan();
        assert_eq!(report.routes.len(), 1);
        let route = &report.routes[0];
        assert_eq!(route.path, "/orgs/{org}/users/{id}");
        assert_eq!(route.params, ["org", "id"]);
        assert_eq!(route.prefix.as_deref(), Some("/orgs/{org}/users"));
        assert_eq!((route.file.as_str(), route.line), ("api/server.js", 3));
    }

    #[test]
    fn rejects_unusable_roots() {
        let fx = Fixture::new();
        fx.write("file.txt", "x");
        let code = |input: &str| scan(input).unwrap_err().code();
        assert_eq!(code(""), "INVALID_SCAN_ROOT");
        assert_eq!(code("relative/path"), "INVALID_SCAN_ROOT");
        assert_eq!(
            code(fx.root.join("missing").to_str().unwrap()),
            "INVALID_SCAN_ROOT"
        );
        assert_eq!(
            code(fx.root.join("file.txt").to_str().unwrap()),
            "INVALID_SCAN_ROOT"
        );
        let quoted = format!("\"{}\"", fx.root.display());
        assert!(scan(&quoted).is_ok());
        let fs_root = fx
            .root
            .ancestors()
            .last()
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        assert_eq!(code(&fs_root), "INVALID_SCAN_ROOT");
    }

    #[test]
    fn verbatim_prefix_is_hidden() {
        assert_eq!(display_path(Path::new(r"\\?\C:\work\app")), r"C:\work\app");
        assert_eq!(
            display_path(Path::new(r"\\?\UNC\host\share")),
            r"\\host\share"
        );
        assert_eq!(display_path(Path::new("/home/dev/app")), "/home/dev/app");
    }
}
