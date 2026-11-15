//! Sample JSON request bodies from OpenAPI / Swagger request body definitions.
//!
//! Literal examples win (media `example`, the first `examples` entry, then schema `example`,
//! `default`, `const`, `enum`); otherwise a value is synthesized from the schema shape, with
//! numeric bounds and string lengths respected. The goal is a baseline the service accepts,
//! so the fuzzer's mutations exercise field handling rather than the first validation check.

use serde_json::{json, Map, Number, Value};

const MAX_DEPTH: usize = 8;
const MAX_PROPERTIES: usize = 32;
const MAX_STRING_LEN: usize = 1024;
const MAX_SAMPLE_BYTES: usize = 64 * 1024;

/// Pretty-printed JSON sample for the request body of `operation`; `root` is the whole
/// document, used to resolve local `$ref`s. `None` when no JSON body is declared.
pub fn request_sample(root: &Value, operation: &Value) -> Option<String> {
    let value = openapi3_body(root, operation).or_else(|| swagger2_body(root, operation))?;
    let text = serde_json::to_string_pretty(&value).ok()?;
    (text.len() <= MAX_SAMPLE_BYTES).then_some(text)
}

fn openapi3_body(root: &Value, operation: &Value) -> Option<Value> {
    let body = resolve(root, operation.get("requestBody")?)?;
    let content = body.get("content")?.as_object()?;
    let media = content
        .iter()
        .find(|(media_type, _)| essence(media_type) == "application/json")
        .or_else(|| content.iter().find(|(media_type, _)| is_json(media_type)))
        .map(|(_, media)| media)?;
    if let Some(example) = media.get("example") {
        return Some(example.clone());
    }
    let named = media
        .get("examples")
        .and_then(Value::as_object)
        .and_then(|examples| {
            examples
                .values()
                .find_map(|entry| resolve(root, entry)?.get("value").cloned())
        });
    if named.is_some() {
        return named;
    }
    Some(synthesize(root, media.get("schema")?, 0, &mut Vec::new()))
}

/// Swagger 2.0 carries the body as a parameter with `in: body`.
fn swagger2_body(root: &Value, operation: &Value) -> Option<Value> {
    let body = operation
        .get("parameters")?
        .as_array()?
        .iter()
        .filter_map(|parameter| resolve(root, parameter))
        .find(|parameter| parameter.get("in").and_then(Value::as_str) == Some("body"))?;
    Some(synthesize(root, body.get("schema")?, 0, &mut Vec::new()))
}

fn essence(media_type: &str) -> String {
    media_type
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase()
}

fn is_json(media_type: &str) -> bool {
    let essence = essence(media_type);
    essence == "application/json" || essence.ends_with("+json")
}

/// Follows a chain of local `$ref`s; remote references are not fetched.
fn resolve<'a>(root: &'a Value, mut value: &'a Value) -> Option<&'a Value> {
    for _ in 0..MAX_DEPTH {
        match value.get("$ref").and_then(Value::as_str) {
            Some(reference) => value = root.pointer(reference.strip_prefix('#')?)?,
            None => return Some(value),
        }
    }
    None
}

fn synthesize(root: &Value, schema: &Value, depth: usize, refs: &mut Vec<String>) -> Value {
    let Some(object) = schema.as_object() else {
        return Value::Null;
    };
    if depth > MAX_DEPTH {
        return Value::Null;
    }
    if let Some(reference) = object.get("$ref").and_then(Value::as_str) {
        // A recursive schema (a tree node holding children of its own type) is cut at the
        // first repetition instead of expanding to the depth limit.
        if refs.iter().any(|seen| seen == reference) {
            return Value::Null;
        }
        let Some(target) = reference
            .strip_prefix('#')
            .and_then(|pointer| root.pointer(pointer))
        else {
            return Value::Null;
        };
        refs.push(reference.to_owned());
        let value = synthesize(root, target, depth + 1, refs);
        refs.pop();
        return value;
    }
    for key in ["example", "default", "const"] {
        if let Some(value) = object.get(key) {
            return value.clone();
        }
    }
    for key in ["examples", "enum"] {
        if let Some(first) = object
            .get(key)
            .and_then(Value::as_array)
            .and_then(|values| values.first())
        {
            return first.clone();
        }
    }
    if let Some(parts) = object.get("allOf").and_then(Value::as_array) {
        let mut merged = Map::new();
        for part in parts {
            match synthesize(root, part, depth + 1, refs) {
                Value::Object(fields) => merged.extend(fields),
                scalar if parts.len() == 1 => return scalar,
                _ => {}
            }
        }
        merged.extend(properties(root, object, depth, refs));
        return Value::Object(merged);
    }
    for key in ["oneOf", "anyOf"] {
        if let Some(first) = object
            .get(key)
            .and_then(Value::as_array)
            .and_then(|variants| variants.first())
        {
            return synthesize(root, first, depth + 1, refs);
        }
    }
    match schema_type(object) {
        Some("object") => Value::Object(properties(root, object, depth, refs)),
        Some("array") => Value::Array(
            object
                .get("items")
                .map(|items| vec![synthesize(root, items, depth + 1, refs)])
                .unwrap_or_default(),
        ),
        Some("string") => Value::String(string_sample(object)),
        Some("integer") => number_sample(object, true),
        Some("number") => number_sample(object, false),
        Some("boolean") => Value::Bool(true),
        _ => Value::Null,
    }
}

fn schema_type(object: &Map<String, Value>) -> Option<&str> {
    match object.get("type") {
        Some(Value::String(kind)) => Some(kind.as_str()),
        // OpenAPI 3.1 type unions such as `["string", "null"]`.
        Some(Value::Array(kinds)) => kinds
            .iter()
            .filter_map(Value::as_str)
            .find(|kind| *kind != "null"),
        _ if object.contains_key("properties") => Some("object"),
        _ if object.contains_key("items") => Some("array"),
        _ => None,
    }
}

fn properties(
    root: &Value,
    object: &Map<String, Value>,
    depth: usize,
    refs: &mut Vec<String>,
) -> Map<String, Value> {
    let mut out = Map::new();
    let Some(properties) = object.get("properties").and_then(Value::as_object) else {
        return out;
    };
    for (name, property) in properties {
        if out.len() >= MAX_PROPERTIES {
            break;
        }
        // `readOnly` properties exist in responses only; sending one is itself a validation
        // error in strict services.
        let read_only = resolve(root, property)
            .and_then(|resolved| resolved.get("readOnly"))
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if !read_only {
            out.insert(name.clone(), synthesize(root, property, depth + 1, refs));
        }
    }
    out
}

fn string_sample(object: &Map<String, Value>) -> String {
    let base = match object.get("format").and_then(Value::as_str).unwrap_or("") {
        "email" | "idn-email" => "user@example.com",
        "uuid" => "00000000-0000-4000-8000-000000000000",
        "date-time" => "2026-01-01T00:00:00Z",
        "date" => "2026-01-01",
        "time" => "00:00:00Z",
        "uri" | "url" | "iri" | "uri-reference" => "http://127.0.0.1/",
        "hostname" | "idn-hostname" => "localhost",
        "ipv4" => "127.0.0.1",
        "ipv6" => "::1",
        "byte" => "AA==",
        "password" => "password",
        _ => "string",
    };
    let bound = |key: &str| {
        object
            .get(key)
            .and_then(Value::as_u64)
            .and_then(|n| usize::try_from(n).ok())
            .map(|n| n.min(MAX_STRING_LEN))
    };
    let mut value = base.to_owned();
    if let Some(min) = bound("minLength") {
        if value.len() < min {
            value.push_str(&"x".repeat(min - value.len()));
        }
    }
    if let Some(max) = bound("maxLength") {
        // Every base sample is ASCII, so any byte offset is a char boundary.
        value.truncate(max);
    }
    value
}

/// Smallest value inside the declared bounds, defaulting to 1: quantities, counts and ids
/// commonly reject 0.
fn number_sample(object: &Map<String, Value>, integer: bool) -> Value {
    let step = if integer { 1.0 } else { 0.5 };
    let minimum = object.get("minimum").and_then(Value::as_f64);
    let maximum = object.get("maximum").and_then(Value::as_f64);
    let lower = match object.get("exclusiveMinimum") {
        Some(Value::Number(bound)) => bound.as_f64().map(|b| b + step),
        Some(Value::Bool(true)) => minimum.map(|m| m + step),
        _ => minimum,
    };
    let upper = match object.get("exclusiveMaximum") {
        Some(Value::Number(bound)) => bound.as_f64().map(|b| b - step),
        Some(Value::Bool(true)) => maximum.map(|m| m - step),
        _ => maximum,
    };
    let mut value = lower.unwrap_or(1.0);
    if integer {
        value = value.ceil();
    }
    if let Some(upper) = upper {
        if value > upper {
            value = if integer { upper.floor() } else { upper };
        }
    }
    if value.fract() == 0.0 && value.abs() < 9.0e15 {
        // Integral and inside the exactly representable range, so the cast is lossless.
        return json!(value as i64);
    }
    Number::from_f64(value).map_or(Value::Null, Value::Number)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn sample(root: &Value, path: &str, method: &str) -> Option<Value> {
        let operation = root.get("paths")?.get(path)?.get(method)?;
        request_sample(root, operation).map(|text| serde_json::from_str(&text).unwrap())
    }

    #[test]
    fn media_examples_win_over_schemas() {
        let root = json!({
            "openapi": "3.0.3",
            "paths": {
                "/a": { "post": { "requestBody": { "content": { "application/json": {
                    "example": { "literal": true },
                    "schema": { "type": "object", "properties": { "x": { "type": "string" } } }
                } } } } },
                "/b": { "post": { "requestBody": { "content": { "application/json; charset=utf-8": {
                    "examples": {
                        "first": { "$ref": "#/components/examples/Named" },
                        "second": { "value": { "n": 2 } }
                    }
                } } } } },
                "/c": { "post": { "requestBody": { "content": { "text/plain": {
                    "schema": { "type": "string" }
                } } } } },
                "/d": { "get": {} }
            },
            "components": { "examples": { "Named": { "value": { "n": 1 } } } }
        });
        assert_eq!(
            sample(&root, "/a", "post"),
            Some(json!({ "literal": true }))
        );
        assert_eq!(sample(&root, "/b", "post"), Some(json!({ "n": 1 })));
        assert_eq!(sample(&root, "/c", "post"), None);
        assert_eq!(sample(&root, "/d", "get"), None);
    }

    #[test]
    fn schemas_synthesize_with_refs_bounds_and_formats() {
        let root = json!({
            "openapi": "3.1.0",
            "paths": { "/orders": { "post": { "requestBody": { "$ref": "#/components/requestBodies/Order" } } } },
            "components": {
                "requestBodies": { "Order": { "content": { "application/vnd.api+json": {
                    "schema": { "$ref": "#/components/schemas/Order" }
                } } } },
                "schemas": {
                    "Order": {
                        "allOf": [
                            { "$ref": "#/components/schemas/Base" },
                            { "type": "object", "properties": {
                                "quantity": { "type": "integer", "minimum": 1, "maximum": 10000 },
                                "discount": { "type": "number", "exclusiveMinimum": 0, "maximum": 1 },
                                "tier": { "type": "integer", "minimum": 0, "exclusiveMinimum": true },
                                "status": { "type": "string", "enum": ["pending", "paid"] },
                                "email": { "type": "string", "format": "email" },
                                "code": { "type": "string", "minLength": 8, "maxLength": 10 },
                                "tags": { "type": "array", "items": { "type": "string", "maxLength": 3 } },
                                "note": { "type": ["string", "null"], "default": "n/a" },
                                "parent": { "$ref": "#/components/schemas/Order" },
                                "shipping": { "oneOf": [ { "$ref": "#/components/schemas/Address" }, { "type": "null" } ] },
                                "gift": { "type": "boolean" }
                            } }
                        ]
                    },
                    "Base": { "type": "object", "properties": {
                        "id": { "type": "string", "format": "uuid", "readOnly": true },
                        "sku": { "type": "string", "example": "LAB-KB-01" }
                    } },
                    "Address": { "properties": { "city": { "type": "string" }, "zip": { "type": "integer", "maximum": 0 } } }
                }
            }
        });
        assert_eq!(
            sample(&root, "/orders", "post"),
            Some(json!({
                "sku": "LAB-KB-01",
                "quantity": 1,
                "discount": 0.5,
                "tier": 1,
                "status": "pending",
                "email": "user@example.com",
                "code": "stringxx",
                "tags": ["str"],
                "note": "n/a",
                "parent": null,
                "shipping": { "city": "string", "zip": 0 },
                "gift": true
            }))
        );
    }

    #[test]
    fn swagger_body_parameters() {
        let root = json!({
            "swagger": "2.0",
            "paths": { "/pets": { "post": { "parameters": [
                { "in": "query", "name": "dry", "type": "boolean" },
                { "$ref": "#/parameters/PetBody" }
            ] } } },
            "parameters": { "PetBody": { "in": "body", "name": "pet", "schema": { "$ref": "#/definitions/Pet" } } },
            "definitions": { "Pet": { "type": "object", "properties": { "name": { "type": "string" }, "age": { "type": "integer", "minimum": 0 } } } }
        });
        assert_eq!(
            sample(&root, "/pets", "post"),
            Some(json!({ "name": "string", "age": 0 }))
        );
    }

    #[test]
    fn broken_and_remote_refs_degrade_to_null() {
        let root = json!({
            "openapi": "3.0.0",
            "paths": { "/x": { "put": { "requestBody": { "content": { "application/json": {
                "schema": { "type": "object", "properties": {
                    "remote": { "$ref": "https://example.com/schema.json" },
                    "missing": { "$ref": "#/components/schemas/Nope" }
                } }
            } } } } } }
        });
        assert_eq!(
            sample(&root, "/x", "put"),
            Some(json!({ "remote": null, "missing": null }))
        );
        let text = request_sample(&root, &root["paths"]["/x"]["put"]).unwrap();
        assert!(text.contains("\n  \"remote\": null"), "{text}");
    }
}
