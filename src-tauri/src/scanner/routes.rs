//! Filesystem route scanner.
//!
//! Walks a project tree and extracts HTTP route declarations with per-framework lexical
//! extractors. Mount prefixes are resolved when the mount and the router it mounts are
//! declared in the same file (`app.use("/api", router)`, Hono `basePath` and
//! `.route("/p", sub)`, Axum `.nest("/p", ..)`); composition across files is invisible to a
//! lexical pass, so such routes are reported as written at their declaration site.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock};
use std::time::Instant;

use regex::Regex;
use uuid::Uuid;
use walkdir::{DirEntry, WalkDir};

use super::audit::{self, Project};
use super::lex::{Lang, Source};
use super::tsconfig::{self, PathAliases, SubpathImports};
use super::{axum, go, next, node, openapi};
use crate::engine::error::{EngineError, EngineResult};
use crate::engine::types::{
    DiscoveredRoute, ResponseContract, RouteMethod, RouteRisk, RouteScanReport, RouteSource,
    ScanIssue,
};

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
pub(super) const MAX_SOURCE_BYTES: u64 = 1024 * 1024;
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
    /// Pretty-printed JSON request body derived from an OpenAPI definition.
    pub sample_body: Option<String>,
    /// Documented responses of an OpenAPI operation.
    pub contract: Option<ResponseContract>,
    /// Static reliability findings in the handler's source (`audit.rs`).
    pub risks: Vec<RouteRisk>,
}

impl RawRoute {
    pub fn new(method: RouteMethod, path: String, source: RouteSource, line: u32) -> Self {
        Self {
            method,
            path,
            source,
            line,
            prefix: None,
            sample_body: None,
            contract: None,
            risks: Vec::new(),
        }
    }

    pub fn with_sample(mut self, sample_body: Option<String>) -> Self {
        self.sample_body = sample_body;
        self
    }

    pub fn with_contract(mut self, contract: Option<ResponseContract>) -> Self {
        self.contract = contract;
        self
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
    /// Express major version by source directory, from the nearest `package.json`.
    express: HashMap<PathBuf, Option<u32>>,
    /// Path aliases by source directory, from the nearest `tsconfig.json` / `jsconfig.json`.
    aliases: HashMap<PathBuf, Option<Arc<PathAliases>>>,
    /// Each config parsed once, however many directories it governs.
    configs: HashMap<PathBuf, Option<Arc<PathAliases>>>,
    /// `package.json` subpath imports by source directory, from the nearest manifest.
    imports: HashMap<PathBuf, Option<Arc<SubpathImports>>>,
    /// Each manifest parsed once.
    manifests: HashMap<PathBuf, Option<Arc<SubpathImports>>>,
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
        let dir = entry.path().parent().unwrap_or(root);
        let express_native_async = kind == FileKind::Js
            && self
                .express_major(root, dir)
                .is_some_and(|major| major >= 5);
        let aliases = match kind {
            FileKind::Js => self.aliases(root, dir),
            _ => None,
        };
        let imports = match kind {
            FileKind::Js => self.imports(root, dir),
            _ => None,
        };
        let project = Project {
            root,
            dir,
            express_native_async,
            aliases: aliases.as_deref(),
            imports: imports.as_deref(),
        };

        match extract(kind, &components, src, Some(&project)) {
            Ok(raw) => {
                self.routes
                    .extend(raw.into_iter().map(|route| discovered(route, &file)));
            }
            Err(reason) => self.issue(file, reason),
        }
    }

    /// Express major version the nearest `package.json` at or above `dir` declares. A
    /// manifest without Express defers to the next one up (a workspace package inside a
    /// monorepo whose root declares it).
    fn express_major(&mut self, root: &Path, dir: &Path) -> Option<u32> {
        if let Some(known) = self.express.get(dir) {
            return *known;
        }
        let mut found = None;
        for ancestor in dir.ancestors() {
            if !ancestor.starts_with(root) {
                break;
            }
            if let Some(known) = self.express.get(ancestor) {
                found = *known;
                break;
            }
            if let Some(major) = declared_express_major(&ancestor.join("package.json")) {
                found = Some(major);
                break;
            }
        }
        self.express.insert(dir.to_path_buf(), found);
        found
    }

    /// `paths` / `baseUrl` aliases of the nearest TypeScript or JavaScript config at or above
    /// `dir`, inside the scan root.
    fn aliases(&mut self, root: &Path, dir: &Path) -> Option<Arc<PathAliases>> {
        if let Some(known) = self.aliases.get(dir) {
            return known.clone();
        }
        let found = tsconfig::nearest_config(root, dir).and_then(|config| {
            self.configs
                .entry(config)
                .or_insert_with_key(|config| tsconfig::load(root, config).map(Arc::new))
                .clone()
        });
        self.aliases.insert(dir.to_path_buf(), found.clone());
        found
    }

    /// Subpath `imports` of the nearest `package.json` at or above `dir`, inside the scan
    /// root: the package scope Node resolves `#name` specifiers in.
    fn imports(&mut self, root: &Path, dir: &Path) -> Option<Arc<SubpathImports>> {
        if let Some(known) = self.imports.get(dir) {
            return known.clone();
        }
        let found = tsconfig::nearest_manifest(root, dir).and_then(|manifest| {
            self.manifests
                .entry(manifest)
                .or_insert_with_key(|manifest| tsconfig::load_imports(root, manifest).map(Arc::new))
                .clone()
        });
        self.imports.insert(dir.to_path_buf(), found.clone());
        found
    }
}

fn declared_express_major(manifest: &Path) -> Option<u32> {
    let meta = std::fs::metadata(manifest).ok()?;
    if !meta.is_file() || meta.len() > MAX_SOURCE_BYTES {
        return None;
    }
    let value: serde_json::Value = serde_json::from_slice(&std::fs::read(manifest).ok()?).ok()?;
    ["dependencies", "devDependencies", "peerDependencies"]
        .iter()
        .find_map(|section| value.get(section)?.get("express")?.as_str())
        .and_then(express_range_major)
}

/// Major version a dependency range starts at: `^5.1.0`, `~5`, `>=5 <6`, `5.0.0-beta.3`,
/// `npm:express@5.1.0`. Tags and workspace links (`latest`, `workspace:*`) yield `None`.
fn express_range_major(range: &str) -> Option<u32> {
    let range = range.rsplit_once('@').map_or(range, |(_, version)| version);
    let digits: String = range
        .trim_start_matches(|c: char| !c.is_ascii_digit())
        .chars()
        .take_while(char::is_ascii_digit)
        .collect();
    digits.parse().ok()
}

/// Routes of an in-memory OpenAPI JSON document, reported like a one-file scan rooted at
/// `root`. Used for specs the engine serves itself, which have no file on disk.
pub fn spec_report(root: &str, file: &str, document: &str) -> RouteScanReport {
    let started = Instant::now();
    let (routes, issues) = match openapi::from_json(document) {
        Ok(raw) => (
            raw.into_iter()
                .map(|route| discovered(route, file))
                .collect(),
            Vec::new(),
        ),
        Err(reason) => (
            Vec::new(),
            vec![ScanIssue {
                file: file.to_owned(),
                reason,
            }],
        ),
    };
    RouteScanReport {
        id: Uuid::new_v4(),
        root: root.to_owned(),
        files_visited: 1,
        files_parsed: 1,
        elapsed_us: u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
        truncated: false,
        routes,
        issues,
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
        sample_body: route.sample_body,
        contract: route.contract,
        risks: route.risks,
    }
}

fn extract(
    kind: FileKind,
    components: &[String],
    src: &str,
    project: Option<&Project<'_>>,
) -> Result<Vec<RawRoute>, String> {
    match kind {
        FileKind::Js => {
            let source = Source::new(src, Lang::Js);
            let mut routes = next::extract(components, &source);
            routes.extend(node::extract(&source));
            audit::annotate(&source, Lang::Js, &mut routes, project);
            Ok(routes)
        }
        FileKind::Rust => {
            let source = Source::new(src, Lang::Rust);
            let mut routes = axum::extract(&source);
            audit::annotate(&source, Lang::Rust, &mut routes, project);
            Ok(routes)
        }
        FileKind::Go => {
            let source = Source::new(src, Lang::Go);
            let mut routes = go::extract(&source);
            audit::annotate(&source, Lang::Go, &mut routes, project);
            Ok(routes)
        }
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

pub(super) fn relative(root: &Path, path: &Path) -> String {
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
            let root = std::env::temp_dir().join(format!("zproxy-scan-{}", Uuid::new_v4()));
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

    fn risks(report: &RouteScanReport) -> Vec<String> {
        report
            .routes
            .iter()
            .flat_map(|route| {
                let method = serde_json::to_value(route.method).unwrap();
                route.risks.iter().map(move |risk| {
                    format!(
                        "{} {}: {:?}@{}:{}",
                        method.as_str().unwrap_or_default(),
                        route.path,
                        risk.kind,
                        risk.file.as_deref().unwrap_or(&route.file),
                        risk.line
                    )
                })
            })
            .collect()
    }

    #[test]
    fn imported_handlers_are_audited_in_their_own_module() {
        let fx = Fixture::new();
        fx.write("package.json", r#"{"dependencies":{"express":"^4.21.2"}}"#)
            .write(
                "src/routes/orders.js",
                "const express = require(\"express\");\nconst router = express.Router();\nconst { createOrder } = require(\"../controllers/orders\");\nimport * as users from \"../controllers/users.js\";\n\nrouter.post(\"/orders\", createOrder);\nrouter.put(\"/users/:id\", users.update);\n\nmodule.exports = router;\n",
            )
            .write(
                "src/controllers/orders.js",
                "exports.createOrder = async (req, res) => {\n  const order = await db.order.create({ data: req.body });\n  await db.coupon.update({ where: { code: req.body.code }, data: { used: 1 } });\n  res.status(201).json(order);\n};\n",
            )
            .write(
                "src/controllers/users.ts",
                "export async function update(req, res, next) {\n  try {\n    const { name } = req.body;\n    const rows = await pool.query(`UPDATE users SET name = '${name}' WHERE id = ${req.params.id}`);\n    res.json(rows);\n  } catch (err) {\n    next(err);\n  }\n}\n",
            );
        assert_eq!(
            risks(&fx.scan()),
            [
                "POST /orders: UnvalidatedMutation@src/controllers/orders.js:2",
                "POST /orders: FloatingAsync@src/controllers/orders.js:1",
                "POST /orders: NonAtomicMultiWrite@src/controllers/orders.js:2",
                "PUT /users/{id}: UnvalidatedMutation@src/controllers/users.ts:3",
                "PUT /users/{id}: UnsafeSqlInterpolation@src/controllers/users.ts:4",
            ]
        );

        // Express 5 forwards the rejected promise to the error middleware by itself.
        fx.write("package.json", r#"{"dependencies":{"express":"^5.1.0"}}"#);
        let report = fx.scan();
        assert!(
            risks(&report)
                .iter()
                .all(|risk| !risk.contains("FloatingAsync")),
            "{:?}",
            risks(&report)
        );
        assert_eq!(risks(&report).len(), 4);
    }

    #[test]
    fn imports_never_leave_the_scan_root() {
        let handler = |name: &str| {
            format!("exports.{name} = async (req, res, next) => {{\n  try {{\n    await db.a.create({{ data: req.body }});\n    await db.b.create({{ data: req.body }});\n  }} catch (err) {{\n    next(err);\n  }}\n}};\n")
        };
        let outside = Fixture::new();
        outside.write("handlers.js", &handler("leak"));
        let fx = Fixture::new();
        let escape = format!(
            "{}/handlers",
            outside.root.to_string_lossy().replace('\\', "/")
        );
        let relative_escape = pathdiff_up(&fx.root, &escape);
        fx.write("handlers.js", &handler("local")).write(
            "server.js",
            &format!(
                "const {{ leak }} = require(\"{relative_escape}\");\nconst {{ local }} = require(\"./handlers\");\napp.post(\"/x\", leak);\napp.post(\"/y\", local);\n"
            ),
        );
        // The same handler is audited inside the root and ignored outside it.
        assert_eq!(
            risks(&fx.scan()),
            [
                "POST /y: UnvalidatedMutation@handlers.js:3",
                "POST /y: NonAtomicMultiWrite@handlers.js:3",
            ]
        );
    }

    #[test]
    fn aliases_reexports_and_class_controllers_resolve_across_files() {
        let fx = Fixture::new();
        fx.write(
            "tsconfig.base.json",
            "{\n  // shared by every package\n  \"compilerOptions\": {\n    \"baseUrl\": \".\",\n    \"paths\": {\n      \"@/*\": [\"src/*\"],\n      \"~/*\": [\"./*\"],\n    },\n  },\n}\n",
        )
        .write(
            "tsconfig.json",
            "{\n  \"extends\": \"./tsconfig.base\",\n  /* the app itself */\n  \"compilerOptions\": { \"strict\": true },\n}\n",
        )
        .write(
            "src/app/api/orders/route.ts",
            "export { POST } from \"@/handlers/orders\";\n",
        )
        .write(
            "src/app/api/carts/route.ts",
            "import { removeCart } from \"~/src/handlers/carts\";\n\nexport { removeCart as DELETE };\n",
        )
        .write(
            "src/app/api/quotes/route.ts",
            "import { quote } from \"src/handlers/quotes\";\n\nexport const PUT = withAuth(quote);\n",
        )
        .write(
            "src/handlers/orders.ts",
            "export async function POST(request: Request) {\n  const body = await request.json();\n  await db.order.create({ data: body });\n  await db.ledger.create({ data: { order: body.id } });\n  return Response.json(body, { status: 201 });\n}\n",
        )
        .write(
            "src/handlers/carts.ts",
            "export async function removeCart(request: Request) {\n  const { items } = await request.json();\n  for (const item of items) {\n    await db.cartItem.delete({ where: { id: item.id } });\n  }\n  return new Response(null, { status: 204 });\n}\n",
        )
        .write(
            "src/handlers/quotes.ts",
            "export const quote = async (request: Request) => {\n  const input = await request.json();\n  return Response.json(await sql.query(`SELECT * FROM quotes WHERE sku = '${input.sku}' LIMIT 1`));\n};\n",
        )
        .write(
            "src/routes/orders.ts",
            "import { Router } from \"express\";\nimport { OrdersController } from \"@/controllers/orders.controller\";\n\nconst router = Router();\nconst controller = new OrdersController();\nrouter.post(\"/v2/orders\", controller.create);\n\nexport default router;\n",
        )
        .write(
            "src/controllers/orders.controller.ts",
            "export class OrdersController {\n  create = async (req: Request, res: Response, next: NextFunction) => {\n    try {\n      await prisma.order\n        .create({ data: req.body });\n      await prisma.coupon\n        .update({ where: { code: req.body.code }, data: { used: 1 } });\n      res.sendStatus(201);\n    } catch (err) {\n      next(err);\n    }\n  };\n}\n",
        )
        .write(
            "src/routes/users.ts",
            "import usersController from \"@/controllers/users.controller\";\n\nrouter.put(\"/v2/users/:id\", usersController.update);\n",
        )
        .write(
            "src/controllers/users.controller.ts",
            "class UsersController {\n  async update(req, res, next) {\n    try {\n      const { name } = req.body;\n      await pool.query(`UPDATE users SET name = '${name}' WHERE id = ${req.params.id}`);\n      res.sendStatus(204);\n    } catch (err) {\n      next(err);\n    }\n  }\n}\n\nexport default new UsersController();\n",
        );
        assert_eq!(
            risks(&fx.scan()),
            [
                "DELETE /api/carts: UnvalidatedMutation@src/handlers/carts.ts:2",
                "DELETE /api/carts: NonAtomicMultiWrite@src/handlers/carts.ts:4",
                "POST /api/orders: UnvalidatedMutation@src/handlers/orders.ts:2",
                "POST /api/orders: NonAtomicMultiWrite@src/handlers/orders.ts:3",
                "PUT /api/quotes: UnvalidatedMutation@src/handlers/quotes.ts:2",
                "PUT /api/quotes: UnsafeSqlInterpolation@src/handlers/quotes.ts:3",
                "POST /v2/orders: UnvalidatedMutation@src/controllers/orders.controller.ts:5",
                "POST /v2/orders: NonAtomicMultiWrite@src/controllers/orders.controller.ts:4",
                "PUT /v2/users/{id}: UnvalidatedMutation@src/controllers/users.controller.ts:4",
                "PUT /v2/users/{id}: UnsafeSqlInterpolation@src/controllers/users.controller.ts:5",
            ]
        );

        // Without the config the aliases resolve to nothing; relative imports still work.
        fs::remove_file(fx.root.join("tsconfig.json")).unwrap();
        let unresolved = risks(&fx.scan());
        assert!(
            unresolved
                .iter()
                .all(|risk| !risk.contains("@src/handlers/orders.ts")),
            "{unresolved:?}"
        );
    }

    #[test]
    fn subpath_imports_barrels_and_imported_instances_resolve() {
        let fx = Fixture::new();
        fx.write(
            "package.json",
            r##"{"type":"module","imports":{"#controllers/*":"./src/controllers/*.js","#handlers":{"types":"./types/handlers.d.ts","node":"./src/handlers/index.js"}},"dependencies":{"express":"^4.21.2"}}"##,
        )
        .write(
            "src/routes/orders.js",
            "import express from \"express\";\nimport { ordersController } from \"#controllers/index\";\nimport { updateUser, refundOrder } from \"#handlers\";\n\nconst router = express.Router();\nrouter.post(\"/orders\", ordersController.create);\nrouter.put(\"/users/:id\", updateUser);\nrouter.post(\"/refunds\", refundOrder);\n\nexport default router;\n",
        )
        // The route's module holds only an instance; its class lives one module further.
        .write(
            "src/controllers/index.js",
            "import { OrdersController } from \"./orders.controller.js\";\n\nexport const ordersController = new OrdersController();\n",
        )
        .write(
            "src/controllers/orders.controller.ts",
            "export class OrdersController {\n  create = async (req, res, next) => {\n    try {\n      await db.order.create({ data: req.body });\n      await db.ledger.create({ data: { order: req.body.id } });\n      res.sendStatus(201);\n    } catch (err) {\n      next(err);\n    }\n  };\n}\n",
        )
        .write(
            "src/handlers/index.js",
            "export * from \"./users.js\";\nexport { refund as refundOrder } from \"./payments.js\";\n",
        )
        .write(
            "src/handlers/users.js",
            "export async function updateUser(req, res, next) {\n  try {\n    const { name } = req.body;\n    await pool.query(`UPDATE users SET name = '${name}' WHERE id = ${req.params.id}`);\n    res.sendStatus(204);\n  } catch (err) {\n    next(err);\n  }\n}\n",
        )
        .write(
            "src/handlers/payments.js",
            "export async function refund(req, res, next) {\n  try {\n    const tx = await db.begin();\n    await tx.query(\"UPDATE orders SET refunded = true WHERE id = $1\", [req.body.id]);\n    await db.query(\"INSERT INTO ledger (order_id) VALUES ($1)\", [req.body.id]);\n    await tx.commit();\n    res.sendStatus(204);\n  } catch (err) {\n    next(err);\n  }\n}\n",
        );
        assert_eq!(
            risks(&fx.scan()),
            [
                "POST /orders: UnvalidatedMutation@src/controllers/orders.controller.ts:4",
                "POST /orders: NonAtomicMultiWrite@src/controllers/orders.controller.ts:4",
                "POST /refunds: UnvalidatedMutation@src/handlers/payments.js:4",
                "POST /refunds: NonAtomicMultiWrite@src/handlers/payments.js:5",
                "PUT /users/{id}: UnvalidatedMutation@src/handlers/users.js:3",
                "PUT /users/{id}: UnsafeSqlInterpolation@src/handlers/users.js:4",
            ]
        );

        // Without the manifest's `imports` the `#` specifiers resolve to nothing.
        fx.write(
            "package.json",
            r#"{"type":"module","dependencies":{"express":"^4.21.2"}}"#,
        );
        assert!(risks(&fx.scan()).is_empty());
    }

    /// `../../...` from `root` to the absolute `target` (forward slashes).
    fn pathdiff_up(root: &Path, target: &str) -> String {
        let depth = root.components().count();
        let target = target
            .trim_start_matches(|c: char| c != '/')
            .trim_start_matches('/');
        format!("{}{}", "../".repeat(depth), target)
    }

    #[test]
    fn express_ranges_resolve_to_a_major() {
        for (range, major) in [
            ("^5.1.0", Some(5)),
            ("~4.21.2", Some(4)),
            (">=5 <6", Some(5)),
            ("5.0.0-beta.3", Some(5)),
            ("npm:express@5.1.0", Some(5)),
            ("latest", None),
            ("workspace:*", None),
        ] {
            assert_eq!(express_range_major(range), major, "{range}");
        }
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
    fn lab_document_reports_routes_with_synthesized_bodies() {
        let document = crate::engine::lab::openapi_document(Some("http://127.0.0.1:17480"));
        let report = spec_report("target-lab", "openapi.json", &document);
        assert!(report.issues.is_empty());
        let listed: Vec<String> = report
            .routes
            .iter()
            .map(|r| {
                let method = serde_json::to_value(r.method).unwrap();
                format!("{} {}", method.as_str().unwrap(), r.path)
            })
            .collect();
        assert_eq!(
            listed,
            [
                "GET /api/v1/health",
                "POST /api/v1/coupons/redeem",
                "POST /api/v1/orders/checkout",
                "GET /api/v1/orders/{orderId}",
                "GET /api/v1/orders",
                "GET /api/v1/lab/openapi.json",
            ]
        );
        let lookup = &report.routes[3];
        assert_eq!(lookup.params, ["orderId"]);
        assert_eq!(lookup.sample_body, None);
        let contract = lookup.contract.as_ref().unwrap();
        assert_eq!(contract.statuses, [200, 404, 422]);
        assert_eq!(contract.body_status, Some(200));
        let total = contract
            .fields
            .iter()
            .find(|f| f.pointer == "/totalCents")
            .unwrap();
        assert!(total.required);
        assert_eq!(total.kinds, [crate::engine::types::JsonKind::Integer]);
        let body = |path: &str| -> serde_json::Value {
            let route = report.routes.iter().find(|r| r.path == path).unwrap();
            serde_json::from_str(route.sample_body.as_deref().unwrap()).unwrap()
        };
        assert_eq!(
            body("/api/v1/coupons/redeem"),
            serde_json::json!({ "code": "LAB-SINGLE-USE", "userId": "u-1001" })
        );
        // `orderId` is readOnly and must not appear in the request sample.
        assert_eq!(
            body("/api/v1/orders/checkout"),
            serde_json::json!({
                "sku": "LAB-KB-01",
                "quantity": 2,
                "customer": { "email": "operator@lab.local", "name": "Lab Operator" },
                "note": "leave at loading dock",
                "giftWrap": false
            })
        );
        assert!(report
            .routes
            .iter()
            .all(|r| r.file == "openapi.json" && r.line > 1));
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
