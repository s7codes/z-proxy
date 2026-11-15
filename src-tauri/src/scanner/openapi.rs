//! OpenAPI 3.x and Swagger 2.0 `paths` extraction from JSON and YAML documents.
//!
//! JSON is parsed with serde_json and lines are recovered by locating the key text; YAML is
//! read through yaml-rust2's event stream, whose markers carry exact lines. Swagger
//! `basePath` and the path component of the first OpenAPI `servers[].url` are prefixed so
//! the reported path is what a client actually requests. Operations with a JSON request body
//! carry a sample payload (`schema.rs`).

use std::sync::LazyLock;

use regex::Regex;
use serde_json::{Number, Value};
use yaml_rust2::parser::{Event, MarkedEventReceiver, Parser};
use yaml_rust2::scanner::{Marker, TScalarStyle};

use super::lex::LineIndex;
use super::routes::{compile, RawRoute};
use super::schema;
use crate::engine::types::{RouteMethod, RouteSource};

static YAML_SPEC: LazyLock<Option<Regex>> =
    LazyLock::new(|| compile(r#"(?m)^["']?(?:openapi|swagger)["']?\s*:"#));

/// Empty when the document is not an OpenAPI/Swagger spec. Unparseable JSON is treated as
/// a non-spec (JSONC configs and fixtures mention the keys too), so this never fails; the
/// `Result` keeps the signature aligned with `from_yaml`.
pub fn from_json(src: &str) -> Result<Vec<RawRoute>, String> {
    if !src.contains("\"openapi\"") && !src.contains("\"swagger\"") {
        return Ok(Vec::new());
    }
    let Ok(root) = serde_json::from_str::<Value>(src) else {
        return Ok(Vec::new());
    };
    let Some(paths) = spec_paths(&root) else {
        return Ok(Vec::new());
    };
    let base = base_path(&root);
    let lines = LineIndex::new(src);
    let paths_at = find_key(src, "paths", 0).unwrap_or(0);

    let mut routes = Vec::new();
    for (path, item) in paths {
        let Some(item) = item.as_object() else {
            continue;
        };
        let path_at = find_key(src, path, paths_at);
        for (key, op) in item {
            let Some(method) = operation(key) else {
                continue;
            };
            let at = path_at
                .and_then(|from| find_key(src, key, from))
                .or(path_at)
                .unwrap_or(paths_at);
            routes.push(
                RawRoute::new(
                    method,
                    format!("{base}{path}"),
                    RouteSource::OpenApi,
                    lines.line(at),
                )
                .with_sample(schema::request_sample(&root, op)),
            );
        }
    }
    routes.sort_by_key(|route| route.line);
    Ok(routes)
}

pub fn from_yaml(src: &str) -> Result<Vec<RawRoute>, String> {
    if !YAML_SPEC.as_ref().is_some_and(|re| re.is_match(src)) {
        return Ok(Vec::new());
    }
    let mut builder = TreeBuilder::default();
    Parser::new_from_str(src)
        .load(&mut builder, false)
        .map_err(|err| format!("invalid YAML: {err}"))?;
    let Some(marked_root) = builder.root else {
        return Ok(Vec::new());
    };
    let Node::Map(root) = &marked_root.node else {
        return Ok(Vec::new());
    };
    if lookup(root, "openapi").is_none() && lookup(root, "swagger").is_none() {
        return Ok(Vec::new());
    }
    let base = yaml_base_path(root);
    let Some(Node::Map(paths)) = lookup(root, "paths").map(|marked| &marked.node) else {
        return Ok(Vec::new());
    };
    // Lines come from the marked tree; body samples need typed values and `$ref` targets
    // anywhere in the document, so they read a JSON view of the same tree.
    let document = to_json(&marked_root);

    let mut routes = Vec::new();
    for (key, item) in paths {
        let (Node::Scalar(path), Node::Map(operations)) = (&key.node, &item.node) else {
            continue;
        };
        if !path.starts_with('/') {
            continue;
        }
        for (op_key, _) in operations {
            let Node::Scalar(name) = &op_key.node else {
                continue;
            };
            if let Some(method) = operation(name) {
                let sample = document
                    .get("paths")
                    .and_then(|paths| paths.get(path))
                    .and_then(|item| item.get(name))
                    .and_then(|op| schema::request_sample(&document, op));
                routes.push(
                    RawRoute::new(
                        method,
                        format!("{base}{path}"),
                        RouteSource::OpenApi,
                        op_key.line,
                    )
                    .with_sample(sample),
                );
            }
        }
    }
    Ok(routes)
}

fn spec_paths(root: &Value) -> Option<&serde_json::Map<String, Value>> {
    let object = root.as_object()?;
    let versioned = object.get("openapi").or_else(|| object.get("swagger"))?;
    versioned.as_str()?;
    object.get("paths")?.as_object()
}

/// `trace` has no `RouteMethod` counterpart and no use against a loopback target; the
/// remaining keys of a path item (`parameters`, `summary`, `$ref`, ...) are not operations.
fn operation(key: &str) -> Option<RouteMethod> {
    match key {
        "get" => Some(RouteMethod::Get),
        "post" => Some(RouteMethod::Post),
        "put" => Some(RouteMethod::Put),
        "patch" => Some(RouteMethod::Patch),
        "delete" => Some(RouteMethod::Delete),
        "head" => Some(RouteMethod::Head),
        "options" => Some(RouteMethod::Options),
        _ => None,
    }
}

fn base_path(root: &Value) -> String {
    if let Some(base) = root.get("basePath").and_then(Value::as_str) {
        return clean_base(base);
    }
    root.get("servers")
        .and_then(|servers| servers.get(0))
        .and_then(|server| server.get("url"))
        .and_then(Value::as_str)
        .map(server_path)
        .unwrap_or_default()
}

fn yaml_base_path(root: &[(Marked, Marked)]) -> String {
    if let Some(Node::Scalar(base)) = lookup(root, "basePath").map(|marked| &marked.node) {
        return clean_base(base);
    }
    let Some(Node::Seq(servers)) = lookup(root, "servers").map(|marked| &marked.node) else {
        return String::new();
    };
    match servers.first().map(|marked| &marked.node) {
        Some(Node::Map(server)) => match lookup(server, "url").map(|marked| &marked.node) {
            Some(Node::Scalar(url)) => server_path(url),
            _ => String::new(),
        },
        _ => String::new(),
    }
}

/// Path component of a server URL. Unresolved server variables make the prefix unknowable,
/// so they yield no prefix rather than a literal `{basePath}`.
fn server_path(url: &str) -> String {
    if url.contains('{') {
        return String::new();
    }
    if url.starts_with('/') {
        return clean_base(url);
    }
    url::Url::parse(url)
        .map(|parsed| clean_base(parsed.path()))
        .unwrap_or_default()
}

fn clean_base(base: &str) -> String {
    let trimmed = base.trim().trim_end_matches('/');
    if trimmed.is_empty() || !trimmed.starts_with('/') {
        String::new()
    } else {
        trimmed.to_owned()
    }
}

/// Offset of `"key"` used as an object key (followed by `:`) at or after `from`.
fn find_key(src: &str, key: &str, from: usize) -> Option<usize> {
    let needle = serde_json::to_string(key).ok()?;
    let tail = src.get(from..)?;
    tail.match_indices(&needle).find_map(|(offset, _)| {
        let after = tail[offset + needle.len()..].trim_start();
        after.starts_with(':').then_some(from + offset)
    })
}

// ---- YAML event tree ------------------------------------------------------------------

#[derive(Debug)]
enum Node {
    Scalar(String),
    Map(Vec<(Marked, Marked)>),
    Seq(Vec<Marked>),
    Alias,
}

#[derive(Debug)]
struct Marked {
    node: Node,
    line: u32,
    /// Plain (unquoted) scalar: typed by the YAML core schema, so `1` is a number and
    /// `"1"` a string.
    plain: bool,
}

impl Marked {
    fn new(node: Node, line: u32) -> Self {
        Self {
            node,
            line,
            plain: false,
        }
    }
}

enum Frame {
    Map {
        line: u32,
        entries: Vec<(Marked, Marked)>,
        key: Option<Marked>,
    },
    Seq {
        line: u32,
        items: Vec<Marked>,
    },
}

#[derive(Default)]
struct TreeBuilder {
    stack: Vec<Frame>,
    root: Option<Marked>,
}

impl TreeBuilder {
    fn push(&mut self, value: Marked) {
        match self.stack.last_mut() {
            None => {
                if self.root.is_none() {
                    self.root = Some(value);
                }
            }
            Some(Frame::Map { entries, key, .. }) => match key.take() {
                Some(k) => entries.push((k, value)),
                None => *key = Some(value),
            },
            Some(Frame::Seq { items, .. }) => items.push(value),
        }
    }
}

impl MarkedEventReceiver for TreeBuilder {
    fn on_event(&mut self, event: Event, mark: Marker) {
        let line = u32::try_from(mark.line()).unwrap_or(u32::MAX);
        match event {
            Event::Scalar(value, style, ..) => self.push(Marked {
                node: Node::Scalar(value),
                line,
                plain: style == TScalarStyle::Plain,
            }),
            // Anchored nodes are rare in OpenAPI and never carry `paths` keys themselves.
            Event::Alias(_) => self.push(Marked::new(Node::Alias, line)),
            Event::MappingStart(..) => self.stack.push(Frame::Map {
                line,
                entries: Vec::new(),
                key: None,
            }),
            Event::SequenceStart(..) => self.stack.push(Frame::Seq {
                line,
                items: Vec::new(),
            }),
            Event::MappingEnd | Event::SequenceEnd => {
                let marked = match self.stack.pop() {
                    Some(Frame::Map { line, entries, .. }) => Marked::new(Node::Map(entries), line),
                    Some(Frame::Seq { line, items }) => Marked::new(Node::Seq(items), line),
                    None => return,
                };
                self.push(marked);
            }
            _ => {}
        }
    }
}

fn lookup<'a>(entries: &'a [(Marked, Marked)], name: &str) -> Option<&'a Marked> {
    entries.iter().find_map(|(key, value)| match &key.node {
        Node::Scalar(key) if key == name => Some(value),
        _ => None,
    })
}

fn to_json(marked: &Marked) -> Value {
    match &marked.node {
        Node::Scalar(text) if marked.plain => plain_scalar(text),
        Node::Scalar(text) => Value::String(text.clone()),
        Node::Map(entries) => Value::Object(
            entries
                .iter()
                .filter_map(|(key, value)| match &key.node {
                    Node::Scalar(key) => Some((key.clone(), to_json(value))),
                    _ => None,
                })
                .collect(),
        ),
        Node::Seq(items) => Value::Array(items.iter().map(to_json).collect()),
        Node::Alias => Value::Null,
    }
}

/// YAML 1.2 core schema resolution of a plain scalar.
fn plain_scalar(text: &str) -> Value {
    match text {
        "" | "~" | "null" | "Null" | "NULL" => return Value::Null,
        "true" | "True" | "TRUE" => return Value::Bool(true),
        "false" | "False" | "FALSE" => return Value::Bool(false),
        _ => {}
    }
    if let Ok(int) = text.parse::<i64>() {
        return Value::from(int);
    }
    // `parse::<f64>` also accepts `inf` and `NaN`; neither is a JSON number.
    let numeric = text.bytes().any(|b| b.is_ascii_digit())
        && text
            .bytes()
            .all(|b| b.is_ascii_digit() || matches!(b, b'.' | b'-' | b'+' | b'e' | b'E'));
    match text
        .parse::<f64>()
        .ok()
        .filter(|_| numeric)
        .and_then(Number::from_f64)
    {
        Some(number) => Value::Number(number),
        None => Value::String(text.to_owned()),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn summary(routes: Vec<RawRoute>) -> Vec<(RouteMethod, String, u32)> {
        routes
            .into_iter()
            .map(|route| (route.method, route.path, route.line))
            .collect()
    }

    #[test]
    fn yaml_spec_with_server_prefix_and_exact_lines() {
        let src = "openapi: 3.1.0\n\
                   info: { title: Shop, version: '1' }\n\
                   servers:\n  - url: http://localhost:8080/v1/\n\
                   paths:\n\
                   \x20 /orders:\n\
                   \x20   parameters: []\n\
                   \x20   get:\n\
                   \x20     summary: list\n\
                   \x20   post:\n\
                   \x20     summary: create\n\
                   \x20 '/orders/{id}':\n\
                   \x20   delete: {}\n\
                   \x20   trace: {}\n";
        assert_eq!(
            summary(from_yaml(src).unwrap()),
            vec![
                (RouteMethod::Get, "/v1/orders".to_owned(), 8),
                (RouteMethod::Post, "/v1/orders".to_owned(), 10),
                (RouteMethod::Delete, "/v1/orders/{id}".to_owned(), 13),
            ]
        );
    }

    fn body_of(routes: &[RawRoute], method: RouteMethod) -> Option<Value> {
        let route = routes.iter().find(|route| route.method == method).unwrap();
        route
            .sample_body
            .as_deref()
            .map(|text| serde_json::from_str(text).unwrap())
    }

    #[test]
    fn json_request_bodies_become_samples() {
        let src = r##"{
  "openapi": "3.0.3",
  "paths": {
    "/orders": {
      "post": { "requestBody": { "content": { "application/json": {
        "schema": { "$ref": "#/components/schemas/Order" }
      } } } },
      "get": {}
    }
  },
  "components": { "schemas": { "Order": { "type": "object", "properties": {
    "sku": { "type": "string", "example": "KB-1" },
    "quantity": { "type": "integer", "minimum": 1 }
  } } } }
}"##;
        let routes = from_json(src).unwrap();
        let post = routes
            .iter()
            .find(|route| route.method == RouteMethod::Post)
            .unwrap();
        assert_eq!(
            post.sample_body.as_deref(),
            Some("{\n  \"sku\": \"KB-1\",\n  \"quantity\": 1\n}")
        );
        assert_eq!(body_of(&routes, RouteMethod::Get), None);
    }

    #[test]
    fn yaml_request_bodies_keep_scalar_types() {
        let src = "openapi: 3.0.3\n\
                   paths:\n\
                   \x20 /pets:\n\
                   \x20   post:\n\
                   \x20     requestBody:\n\
                   \x20       content:\n\
                   \x20         application/json:\n\
                   \x20           example:\n\
                   \x20             name: Rex\n\
                   \x20             age: 3\n\
                   \x20             weight: 4.5\n\
                   \x20             tag: '7'\n\
                   \x20             vaccinated: true\n\
                   \x20             owner: ~\n\
                   \x20   put:\n\
                   \x20     requestBody:\n\
                   \x20       $ref: '#/components/requestBodies/Pet'\n\
                   components:\n\
                   \x20 requestBodies:\n\
                   \x20   Pet:\n\
                   \x20     content:\n\
                   \x20       application/json:\n\
                   \x20         schema:\n\
                   \x20           type: object\n\
                   \x20           properties:\n\
                   \x20             name: { type: string, maxLength: 3 }\n\
                   \x20             age: { type: integer, minimum: 0 }\n";
        let routes = from_yaml(src).unwrap();
        assert_eq!(
            body_of(&routes, RouteMethod::Post),
            Some(serde_json::json!({
                "name": "Rex", "age": 3, "weight": 4.5, "tag": "7", "vaccinated": true, "owner": null
            }))
        );
        assert_eq!(
            body_of(&routes, RouteMethod::Put),
            Some(serde_json::json!({ "name": "str", "age": 0 }))
        );
    }

    #[test]
    fn plain_scalars_follow_the_core_schema() {
        use serde_json::json;
        let cases = [
            ("1", json!(1)),
            ("+5", json!(5)),
            ("-2", json!(-2)),
            ("1.5", json!(1.5)),
            ("1e3", json!(1000.0)),
            ("null", Value::Null),
            ("~", Value::Null),
            ("True", json!(true)),
            ("FALSE", json!(false)),
            ("inf", json!("inf")),
            (".nan", json!(".nan")),
            ("3.0.3", json!("3.0.3")),
            ("0x1F", json!("0x1F")),
            ("1-2", json!("1-2")),
        ];
        for (text, expected) in cases {
            assert_eq!(plain_scalar(text), expected, "{text}");
        }
    }

    #[test]
    fn json_swagger_with_base_path() {
        let src = r#"{
  "swagger": "2.0",
  "basePath": "/api/",
  "paths": {
    "/pets/{petId}": {
      "get": { "summary": "\"paths\" mention" },
      "put": {}
    },
    "/pets": {
      "post": {}
    }
  }
}"#;
        assert_eq!(
            summary(from_json(src).unwrap()),
            vec![
                (RouteMethod::Get, "/api/pets/{petId}".to_owned(), 6),
                (RouteMethod::Put, "/api/pets/{petId}".to_owned(), 7),
                (RouteMethod::Post, "/api/pets".to_owned(), 10),
            ]
        );
    }

    #[test]
    fn non_specs_are_ignored() {
        assert!(
            from_json(r#"{"name":"app","dependencies":{"swagger-ui-express":"5"}}"#)
                .unwrap()
                .is_empty()
        );
        assert!(from_json("{ \"openapi\": // comment\n }")
            .unwrap()
            .is_empty());
        assert!(from_yaml("services:\n  web:\n    image: x\n")
            .unwrap()
            .is_empty());
        assert!(from_yaml("openapi: [unclosed").is_err());
    }

    #[test]
    fn server_variables_yield_no_prefix() {
        assert_eq!(server_path("https://{host}/v2"), "");
        assert_eq!(server_path("/"), "");
        assert_eq!(server_path("/v3/"), "/v3");
        assert_eq!(server_path("http://127.0.0.1:3000"), "");
    }
}
