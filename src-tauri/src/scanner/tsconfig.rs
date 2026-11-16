//! `compilerOptions.paths` and `baseUrl` of the nearest `tsconfig.json` / `jsconfig.json`.
//!
//! Only what module resolution needs is read: the two options, through relative `extends`
//! chains, in the JSON-with-comments dialect TypeScript accepts. Packages named in `extends`
//! are not followed; they live under `node_modules`, which the scan never enters. Every
//! config read must sit inside the scan root.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use serde_json::{Map, Value};

use super::routes::MAX_SOURCE_BYTES;

/// Checked in this order in each directory; TypeScript prefers `tsconfig.json`.
const CONFIG_FILES: [&str; 2] = ["tsconfig.json", "jsconfig.json"];
/// `extends` links followed from one config; also bounds a cycle the visited set misses.
const MAX_EXTENDS: usize = 4;
const MAX_PATTERNS: usize = 64;
const MAX_TARGETS: usize = 8;

#[derive(Debug, PartialEq, Eq)]
pub struct PathAliases {
    /// Directory `paths` substitutions resolve against: `baseUrl` when set, else the
    /// directory of the config that declares `paths`.
    paths_base: PathBuf,
    /// `baseUrl`, which also resolves bare specifiers (`src/handlers/orders`).
    base_url: Option<PathBuf>,
    patterns: Vec<Pattern>,
}

#[derive(Debug, PartialEq, Eq)]
struct Pattern {
    prefix: String,
    /// Text after the `*`; `None` for an exact pattern.
    suffix: Option<String>,
    targets: Vec<String>,
}

impl PathAliases {
    /// Paths a non-relative specifier may name, before extension probing, in the order
    /// TypeScript tries them: the substitutions of the best `paths` match (an exact pattern,
    /// else the wildcard pattern with the longest prefix), then `baseUrl`.
    pub fn candidates(&self, spec: &str) -> Vec<PathBuf> {
        let exact = self
            .patterns
            .iter()
            .find(|pattern| pattern.suffix.is_none() && pattern.prefix == spec)
            .map(|pattern| (pattern, ""));
        let matched = exact.or_else(|| {
            self.patterns
                .iter()
                .filter_map(|pattern| {
                    let suffix = pattern.suffix.as_deref()?;
                    let star = spec
                        .strip_prefix(pattern.prefix.as_str())?
                        .strip_suffix(suffix)?;
                    Some((pattern, star))
                })
                .max_by_key(|(pattern, _)| pattern.prefix.len())
        });
        let mut out = Vec::with_capacity(MAX_TARGETS + 1);
        if let Some((pattern, star)) = matched {
            out.extend(
                pattern
                    .targets
                    .iter()
                    .map(|target| self.paths_base.join(target.replacen('*', star, 1))),
            );
        }
        if let Some(base) = &self.base_url {
            out.push(base.join(spec));
        }
        out
    }
}

/// The nearest config at or above `dir`, not above `root`.
pub fn nearest_config(root: &Path, dir: &Path) -> Option<PathBuf> {
    dir.ancestors()
        .take_while(|ancestor| ancestor.starts_with(root))
        .find_map(|ancestor| {
            CONFIG_FILES
                .iter()
                .map(|name| ancestor.join(name))
                .find(|path| path.is_file())
        })
}

/// Aliases `config` declares or inherits; `None` when it sets neither option or cannot be
/// read. `root` must be canonical.
pub fn load(root: &Path, config: &Path) -> Option<PathAliases> {
    let options = resolve(root, config, &mut HashSet::new(), 0)?;
    let (paths, paths_dir) = options
        .paths
        .map_or((None, None), |(paths, dir)| (Some(paths), Some(dir)));
    let paths_base = options.base_url.clone().or(paths_dir)?;
    let patterns = paths
        .iter()
        .flatten()
        .take(MAX_PATTERNS)
        .filter_map(|(key, targets)| {
            let targets: Vec<String> = targets
                .as_array()?
                .iter()
                .filter_map(Value::as_str)
                .take(MAX_TARGETS)
                .map(str::to_owned)
                .collect();
            let (prefix, suffix) = match key.split_once('*') {
                // TypeScript rejects a pattern with two wildcards.
                Some((_, suffix)) if suffix.contains('*') => return None,
                Some((prefix, suffix)) => (prefix.to_owned(), Some(suffix.to_owned())),
                None => (key.clone(), None),
            };
            (!targets.is_empty()).then_some(Pattern {
                prefix,
                suffix,
                targets,
            })
        })
        .collect();
    Some(PathAliases {
        paths_base,
        base_url: options.base_url,
        patterns,
    })
}

struct Options {
    /// Already joined to the directory of the config that set it.
    base_url: Option<PathBuf>,
    /// `paths` and the directory of the config that declared it.
    paths: Option<(Map<String, Value>, PathBuf)>,
}

fn resolve(
    root: &Path,
    config: &Path,
    seen: &mut HashSet<PathBuf>,
    depth: usize,
) -> Option<Options> {
    let canonical = std::fs::canonicalize(config).ok()?;
    if !canonical.starts_with(root) || !seen.insert(canonical.clone()) {
        return None;
    }
    let value = read_jsonc(&canonical)?;
    let dir = canonical.parent()?.to_path_buf();
    let mut options = Options {
        base_url: None,
        paths: None,
    };
    if depth < MAX_EXTENDS {
        // Later entries of an `extends` array override earlier ones, and the config itself
        // overrides them all.
        for parent in extended(&value, &dir) {
            if let Some(inherited) = resolve(root, &parent, seen, depth + 1) {
                if inherited.base_url.is_some() {
                    options.base_url = inherited.base_url;
                }
                if inherited.paths.is_some() {
                    options.paths = inherited.paths;
                }
            }
        }
    }
    let compiler = value.get("compilerOptions").and_then(Value::as_object);
    if let Some(base) = compiler
        .and_then(|c| c.get("baseUrl"))
        .and_then(Value::as_str)
    {
        options.base_url = Some(dir.join(base));
    }
    if let Some(paths) = compiler
        .and_then(|c| c.get("paths"))
        .and_then(Value::as_object)
    {
        options.paths = Some((paths.clone(), dir));
    }
    Some(options)
}

/// Relative `extends` targets, with `.json` appended when the name has no such extension.
fn extended(value: &Value, dir: &Path) -> Vec<PathBuf> {
    let specs: Vec<&str> = match value.get("extends") {
        Some(Value::String(spec)) => vec![spec.as_str()],
        Some(Value::Array(items)) => items.iter().filter_map(Value::as_str).collect(),
        _ => Vec::new(),
    };
    specs
        .into_iter()
        .filter(|spec| spec.starts_with('.'))
        .map(|spec| {
            let path = dir.join(spec);
            if spec.ends_with(".json") {
                path
            } else {
                let mut name = path.into_os_string();
                name.push(".json");
                PathBuf::from(name)
            }
        })
        .collect()
}

fn read_jsonc(path: &Path) -> Option<Value> {
    if std::fs::metadata(path).ok()?.len() > MAX_SOURCE_BYTES {
        return None;
    }
    let text = String::from_utf8(std::fs::read(path).ok()?).ok()?;
    let text = text.strip_prefix('\u{feff}').unwrap_or(&text);
    serde_json::from_str(&strict_json(text)).ok()
}

/// JSON with comments and trailing commas, as TypeScript reads its configs, to strict JSON.
/// Strings are copied whole and comments removed whole, so the output stays valid UTF-8.
fn strict_json(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while let Some(&byte) = bytes.get(at) {
        match byte {
            b'"' => {
                let end = string_end(bytes, at);
                out.extend_from_slice(bytes.get(at..end).unwrap_or_default());
                at = end;
            }
            b'/' if matches!(bytes.get(at + 1), Some(b'/' | b'*')) => at = comment_end(bytes, at),
            b',' if matches!(bytes.get(significant(bytes, at + 1)), Some(b'}' | b']')) => {
                at += 1;
            }
            _ => {
                out.push(byte);
                at += 1;
            }
        }
    }
    String::from_utf8(out).unwrap_or_default()
}

/// Offset after the string opening at `at`, escape-aware; the end of input if unterminated.
fn string_end(bytes: &[u8], at: usize) -> usize {
    let mut cursor = at + 1;
    while let Some(&byte) = bytes.get(cursor) {
        match byte {
            b'\\' => cursor += 2,
            b'"' => return cursor + 1,
            _ => cursor += 1,
        }
    }
    bytes.len()
}

/// Offset after the `//` or `/* */` comment opening at `at`; a line comment keeps its newline.
fn comment_end(bytes: &[u8], at: usize) -> usize {
    let rest = bytes.get(at..).unwrap_or_default();
    if bytes.get(at + 1) == Some(&b'/') {
        rest.iter()
            .position(|&byte| byte == b'\n')
            .map_or(bytes.len(), |offset| at + offset)
    } else {
        rest.get(2..)
            .and_then(|body| body.windows(2).position(|pair| pair == b"*/"))
            .map_or(bytes.len(), |offset| at + 2 + offset + 2)
    }
}

/// First offset at or after `at` that is neither whitespace nor inside a comment.
fn significant(bytes: &[u8], mut at: usize) -> usize {
    loop {
        match bytes.get(at) {
            Some(byte) if byte.is_ascii_whitespace() => at += 1,
            Some(b'/') if matches!(bytes.get(at + 1), Some(b'/' | b'*')) => {
                at = comment_end(bytes, at);
            }
            _ => return at,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn comments_and_trailing_commas_are_accepted() {
        let text = "{\n  // note, with a comma\n  \"a\": \"x // not a comment\", /* block, */\n  \"b\": [1, 2, ],\n  \"c\": { \"d\": \"\\\",\" , },\n}\n";
        let value: Value = serde_json::from_str(&strict_json(text)).unwrap();
        assert_eq!(value["a"], "x // not a comment");
        assert_eq!(value["b"], serde_json::json!([1, 2]));
        assert_eq!(value["c"]["d"], "\",");
    }

    fn aliases(base_url: Option<&str>, patterns: &[(&str, &[&str])]) -> PathAliases {
        let parse = |key: &str| match key.split_once('*') {
            Some((prefix, suffix)) => (prefix.to_owned(), Some(suffix.to_owned())),
            None => (key.to_owned(), None),
        };
        PathAliases {
            paths_base: PathBuf::from("/p"),
            base_url: base_url.map(PathBuf::from),
            patterns: patterns
                .iter()
                .map(|(key, targets)| {
                    let (prefix, suffix) = parse(key);
                    Pattern {
                        prefix,
                        suffix,
                        targets: targets.iter().map(|t| (*t).to_owned()).collect(),
                    }
                })
                .collect(),
        }
    }

    #[test]
    fn exact_patterns_win_then_the_longest_prefix() {
        let set = aliases(
            Some("/p"),
            &[
                ("@/*", &["src/*"]),
                ("@/lib/*", &["vendor/lib/*", "src/lib/*"]),
                ("@db", &["src/db/index.ts"]),
                ("*.css", &["styles/*.css"]),
            ],
        );
        assert_eq!(
            set.candidates("@/lib/http"),
            [
                PathBuf::from("/p/vendor/lib/http"),
                PathBuf::from("/p/src/lib/http"),
                PathBuf::from("/p/@/lib/http"),
            ]
        );
        assert_eq!(
            set.candidates("@/handlers/orders")[0],
            PathBuf::from("/p/src/handlers/orders")
        );
        assert_eq!(
            set.candidates("@db")[0],
            PathBuf::from("/p/src/db/index.ts")
        );
        assert_eq!(set.candidates("express"), [PathBuf::from("/p/express")]);
        let no_base = aliases(None, &[("~/*", &["./*"])]);
        assert_eq!(no_base.candidates("~/a/b"), [PathBuf::from("/p/./a/b")]);
        assert!(no_base.candidates("express").is_empty());
    }
}
