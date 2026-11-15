//! Next.js App Router (`app/**/route.ts`) and Pages API (`pages/api/**`) extraction.
//!
//! The route path comes from the file location, so these extractors take the root-relative
//! path components alongside the comment-masked source.

use std::sync::LazyLock;

use regex::Regex;

use super::lex::Source;
use super::routes::{compile, method_from_token, RawRoute};
use crate::engine::types::{RouteMethod, RouteSource};

const ROUTE_EXTENSIONS: [&str; 5] = ["ts", "tsx", "js", "jsx", "mjs"];

static EXPORT_DECL: LazyLock<Option<Regex>> = LazyLock::new(|| {
    compile(
        r"(?-u:\b)export\s+(?:(?:async\s+)?function\s*\*?\s*|(?:const|let|var)\s+)(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)(?-u:\b)",
    )
});
static EXPORT_LIST: LazyLock<Option<Regex>> =
    LazyLock::new(|| compile(r"(?-u:\b)export\s*\{([^}]*)\}"));
static METHOD_CHECK: LazyLock<Option<Regex>> = LazyLock::new(|| {
    compile(
        r#"(?-u:\b)req(?:uest)?\.method\s*[!=]==?\s*['"](GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)['"]|(?-u:\b)case\s+['"](GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)['"]\s*:"#,
    )
});
static DEFAULT_EXPORT: LazyLock<Option<Regex>> =
    LazyLock::new(|| compile(r"(?-u:\b)export\s+default(?-u:\b)|(?-u:\b)module\.exports(?-u:\b)"));

/// `components` is the root-relative path split on separators, file name last.
pub fn extract(components: &[String], source: &Source) -> Vec<RawRoute> {
    let Some((file, dirs)) = components.split_last() else {
        return Vec::new();
    };
    let Some((stem, ext)) = file.rsplit_once('.') else {
        return Vec::new();
    };
    if !ROUTE_EXTENSIONS.contains(&ext) || stem.ends_with(".d") {
        return Vec::new();
    }
    if stem == "route" {
        if let Some(app) = dirs.iter().position(|dir| dir == "app") {
            return app_route(&dirs[app + 1..], source);
        }
    }
    if let Some(pages) = dirs
        .windows(2)
        .position(|pair| pair[0] == "pages" && pair[1] == "api")
    {
        return pages_api(&dirs[pages + 1..], stem, source);
    }
    Vec::new()
}

fn app_route(segments: &[String], source: &Source) -> Vec<RawRoute> {
    let src = source.text.as_str();
    // Folders prefixed with `_` are private and opt out of routing entirely.
    if segments.iter().any(|segment| segment.starts_with('_')) {
        return Vec::new();
    }
    let path = segments
        .iter()
        .filter_map(|segment| app_segment(segment))
        .collect::<Vec<_>>()
        .join("/");
    let path = format!("/{path}");

    let mut found: Vec<(RouteMethod, usize)> = Vec::new();
    if let Some(re) = EXPORT_DECL.as_ref() {
        for name in re.captures_iter(src).filter_map(|caps| caps.get(1)) {
            if source.in_string(name.start()) {
                continue;
            }
            if let Some(method) = method_from_token(name.as_str()) {
                found.push((method, name.start()));
            }
        }
    }
    if let Some(re) = EXPORT_LIST.as_ref() {
        for caps in re.captures_iter(src) {
            let Some(list) = caps.get(1).filter(|list| !source.in_string(list.start())) else {
                continue;
            };
            let mut offset = list.start();
            for item in list.as_str().split(',') {
                let exported = item.rsplit(" as ").next().unwrap_or(item).trim();
                if let Some(method) = method_from_token(exported).filter(|_| is_upper(exported)) {
                    found.push((method, offset + item.len() - item.trim_start().len()));
                }
                offset += item.len() + 1;
            }
        }
    }

    found.sort_by_key(|&(_, at)| at);
    let mut seen = Vec::new();
    found.retain(|(method, _)| {
        let first = !seen.contains(method);
        seen.push(*method);
        first
    });
    found
        .into_iter()
        .map(|(method, at)| {
            RawRoute::new(
                method,
                path.clone(),
                RouteSource::NextAppRouter,
                source.lines.line(at),
            )
        })
        .collect()
}

/// Route groups `(name)` and parallel slots `@name` do not appear in the URL; intercepting
/// markers `(.)`, `(..)`, `(...)` are stripped from the segment they prefix.
fn app_segment(segment: &str) -> Option<String> {
    if segment.starts_with('@') || (segment.starts_with('(') && segment.ends_with(')')) {
        return None;
    }
    if segment.starts_with("(.") {
        return segment.split_once(')').map(|(_, rest)| rest.to_owned());
    }
    Some(segment.to_owned())
}

fn pages_api(segments: &[String], stem: &str, source: &Source) -> Vec<RawRoute> {
    let src = source.text.as_str();
    if stem.starts_with('_') {
        return Vec::new();
    }
    let mut parts: Vec<&str> = segments.iter().map(String::as_str).collect();
    if stem != "index" {
        parts.push(stem);
    }
    let path = format!("/{}", parts.join("/"));

    let mut found: Vec<(RouteMethod, usize)> = Vec::new();
    if let Some(re) = METHOD_CHECK.as_ref() {
        for caps in re.captures_iter(src) {
            let Some(token) = caps.get(1).or_else(|| caps.get(2)) else {
                continue;
            };
            if caps
                .get(0)
                .is_some_and(|whole| source.in_string(whole.start()))
            {
                continue;
            }
            if let Some(method) = method_from_token(token.as_str()) {
                if !found.iter().any(|(seen, _)| *seen == method) {
                    found.push((method, token.start()));
                }
            }
        }
    }
    if found.is_empty() {
        let at = DEFAULT_EXPORT
            .as_ref()
            .and_then(|re| re.find(src))
            .map_or(0, |m| m.start());
        found.push((RouteMethod::Any, at));
    }

    found
        .into_iter()
        .map(|(method, at)| {
            RawRoute::new(
                method,
                path.clone(),
                RouteSource::NextPagesApi,
                source.lines.line(at),
            )
        })
        .collect()
}

fn is_upper(token: &str) -> bool {
    token.bytes().all(|byte| byte.is_ascii_uppercase())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn run(path: &str, src: &str) -> Vec<(RouteMethod, String, u32)> {
        let components: Vec<String> = path.split('/').map(str::to_owned).collect();
        extract(
            &components,
            &Source::new(src, crate::scanner::lex::Lang::Js),
        )
        .into_iter()
        .map(|route| (route.method, route.path, route.line))
        .collect()
    }

    #[test]
    fn app_router_exports_in_every_form() {
        let src = "import x from 'y';\n\
                   export async function GET(req) {}\n\
                   export const POST = handler;\n\
                   const h = () => {};\n\
                   export { h as DELETE, helper };\n";
        let routes = run("src/app/(shop)/api/orders/[id]/route.ts", src);
        assert_eq!(
            routes,
            vec![
                (RouteMethod::Get, "/api/orders/[id]".to_owned(), 2),
                (RouteMethod::Post, "/api/orders/[id]".to_owned(), 3),
                (RouteMethod::Delete, "/api/orders/[id]".to_owned(), 5),
            ]
        );
    }

    #[test]
    fn app_router_skips_private_slots_and_non_handlers() {
        assert!(run("app/_lib/route.ts", "export function GET() {}").is_empty());
        assert!(run("app/api/route.ts", "export function get() {}").is_empty());
        assert_eq!(
            run("app/@modal/(.)photo/route.ts", "export function GET() {}"),
            vec![(RouteMethod::Get, "/photo".to_owned(), 1)]
        );
    }

    #[test]
    fn pages_api_methods_from_request_checks() {
        let src = "export default function handler(req, res) {\n\
                   if (req.method !== 'POST') return res.status(405).end();\n\
                   switch (req.method) { case \"PUT\": break; }\n}";
        assert_eq!(
            run("pages/api/users/[id].ts", src),
            vec![
                (RouteMethod::Post, "/api/users/[id]".to_owned(), 2),
                (RouteMethod::Put, "/api/users/[id]".to_owned(), 3),
            ]
        );
    }

    #[test]
    fn pages_api_without_checks_is_any() {
        let src = "// handler\nexport default async function handler(req, res) {}";
        assert_eq!(
            run("src/pages/api/index.js", src),
            vec![(RouteMethod::Any, "/api".to_owned(), 2)]
        );
        assert!(run("pages/api/_middleware.ts", src).is_empty());
    }
}
