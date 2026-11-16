//! Information-disclosure signatures in response bodies.
//!
//! Each pattern requires structure (a frame with `file:line`, a traceback header, a
//! goroutine header, a vendor-specific SQL error phrase) rather than a bare keyword, so
//! prose that merely mentions "panic" or "SQL" does not match. Bodies are usually JSON, where
//! a multi-line trace arrives with `\n` escapes instead of line breaks; frame patterns accept
//! either separator.
//!
//! Sensitive fields are found by `field_leak`, a byte-level walk of a JSON body that tracks
//! the path to each value on a fixed stack. It reads keys and string values in place and
//! allocates only for the leak it reports, so the proxy can run it on every 2xx JSON
//! response; a truncated preview is walked as far as it goes.

use std::sync::LazyLock;

use regex::Regex;

use super::types::{Disclosure, DisclosureKind};

const EVIDENCE_CHARS: usize = 160;

/// Field names (lowercased, `_` and `-` removed) whose value is credential material: never
/// part of a response, whatever the route.
const CREDENTIAL_FIELDS: [&str; 15] = [
    "password",
    "passwordhash",
    "hashedpassword",
    "passworddigest",
    "encryptedpassword",
    "salt",
    "passwordsalt",
    "twofactorsecret",
    "otpsecret",
    "totpsecret",
    "mfasecret",
    "privatekey",
    "resettoken",
    "passwordresettoken",
    "recoverycodes",
];
/// Credentials a route may issue once (an OAuth client, an API key, a token refresh); a
/// leak only outside such a route.
const ISSUED_FIELDS: [&str; 4] = ["secret", "clientsecret", "apikey", "refreshtoken"];
/// Path segments of routes that issue the credentials above.
const ISSUING_SEGMENTS: [&str; 17] = [
    "token",
    "tokens",
    "oauth",
    "oauth2",
    "auth",
    "login",
    "signin",
    "sign-in",
    "session",
    "sessions",
    "refresh",
    "keys",
    "api-keys",
    "apikeys",
    "credentials",
    "clients",
    "secrets",
];
/// Containers tracked for the reported pointer; deeper values are still scanned.
const MAX_LEAK_DEPTH: usize = 32;
/// Prefixes of the password-hash formats in common use: bcrypt (`$2a$` / `$2b$` / `$2x$` /
/// `$2y$`), argon2 (`$argon2id$` and siblings), scrypt and the PBKDF2 encodings of passlib,
/// Django and Werkzeug.
const HASH_PREFIXES: [&str; 9] = [
    "$2a$",
    "$2b$",
    "$2x$",
    "$2y$",
    "$argon2",
    "$scrypt$",
    "$pbkdf2",
    "pbkdf2_sha",
    "pbkdf2:sha",
];
/// Shortest value read as a hash: every listed format carries a salt and digest past this.
const MIN_HASH_LEN: usize = 20;

struct Signature {
    kind: DisclosureKind,
    pattern: LazyLock<Option<Regex>>,
}

/// Runtime traces precede database errors: a Python traceback that ends in a psycopg2
/// error is reported as the traceback, which also leaks file paths and source lines.
static SIGNATURES: [Signature; 7] = [
    Signature {
        kind: DisclosureKind::NodeStackTrace,
        pattern: LazyLock::new(|| {
            compile(
                r#"(?:^|\s|\\n)at (?:async )?(?:new )?(?:[\w$.<>\[\]]+ )?\(?(?:file://)?(?:[A-Za-z]:)?[^\s()"']+\.(?:[cm]?js|[cm]?ts|jsx|tsx):\d+:\d+\)?|\(node:[\w/]+:\d+:\d+\)"#,
            )
        }),
    },
    Signature {
        kind: DisclosureKind::PythonTraceback,
        pattern: LazyLock::new(|| {
            compile(
                r#"Traceback \(most recent call last\)|File \\?"[^"\\]+\.py\\?", line \d+, in "#,
            )
        }),
    },
    Signature {
        kind: DisclosureKind::RustPanic,
        pattern: LazyLock::new(|| compile(r#"panicked at (?:'[^']*', )?[^\s:'"]+\.rs:\d+:\d+"#)),
    },
    Signature {
        kind: DisclosureKind::GoPanic,
        pattern: LazyLock::new(|| {
            compile(r"goroutine \d+ \[[a-z ,0-9]{1,40}\]:|panic: runtime error: ")
        }),
    },
    Signature {
        kind: DisclosureKind::JvmStackTrace,
        pattern: LazyLock::new(|| {
            compile(r"(?:^|\s|\\n)at [\w$]+(?:\.[\w$<>]+)+\([\w$]+\.(?:java|kt|scala):\d+\)")
        }),
    },
    Signature {
        kind: DisclosureKind::DotNetStackTrace,
        pattern: LazyLock::new(|| {
            compile(r#"(?:^|\s|\\n)at [\w.<>`\[\]+]+\([^)\n]*\) in [^\n"]+?:line \d+"#)
        }),
    },
    Signature {
        kind: DisclosureKind::SqlError,
        pattern: LazyLock::new(|| {
            compile(concat!(
                r"(?i:you have an error in your sql syntax)",
                r"|syntax error at or near ",
                r"|unterminated quoted string at or near",
                r"|invalid input syntax for (?:type )?[a-z ]+",
                r#"|(?:column|relation) \\?"[^"\\]+\\?" does not exist"#,
                r"|value too long for type character varying",
                r"|(?:LIMIT|OFFSET) must not be negative",
                r#"|value \\?"[^"\\]*\\?" is out of range for type (?:bigint|integer|smallint|numeric)"#,
                r"|SQLSTATE\[[0-9A-Z]{5}\]",
                r"|ORA-\d{5}:",
                r"|SQLITE_ERROR|sqlite3\.OperationalError",
                r"|psycopg2\.errors\.[A-Za-z]+",
                r"|org\.postgresql\.util\.PSQLException",
                r"|Unclosed quotation mark after the character string",
            ))
        }),
    },
];

fn compile(pattern: &str) -> Option<Regex> {
    Regex::new(pattern).ok()
}

/// Operator-facing name; mirrors `DISCLOSURE_LABEL` in `src/lib/disclosure.ts`.
pub fn label(kind: DisclosureKind) -> &'static str {
    match kind {
        DisclosureKind::NodeStackTrace => "Node.js stack trace",
        DisclosureKind::PythonTraceback => "Python traceback",
        DisclosureKind::RustPanic => "Rust panic",
        DisclosureKind::GoPanic => "Go panic",
        DisclosureKind::JvmStackTrace => "JVM stack trace",
        DisclosureKind::DotNetStackTrace => ".NET stack trace",
        DisclosureKind::SqlError => "SQL error",
        DisclosureKind::SensitiveFieldLeak => "Sensitive field",
    }
}

/// A sensitive field found in a JSON body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldLeak {
    /// Credential material (a password, its hash or salt, a private key, a reset or
    /// two-factor secret), as opposed to a credential some route legitimately issues.
    pub credential: bool,
    /// `SensitiveFieldLeak` with `pointer = shape` evidence; the value itself is never
    /// copied, only its hash parameters or length.
    pub disclosure: Disclosure,
}

#[derive(Clone, Copy)]
enum Frame {
    /// Byte range of the key whose value is being read, once its `:` was seen.
    Object(Option<(usize, usize)>),
    Array(usize),
}

/// First credential-material field of a JSON `body`, else its first issued-credential field
/// when `path` is not a route that issues one; `None` for a clean body. Only string values
/// count, and masked ones (`"********"`, `"[redacted]"`) do not.
pub fn field_leak(body: &[u8], path: &str) -> Option<FieldLeak> {
    let issuing = path.split(['/', '?']).any(|segment| {
        ISSUING_SEGMENTS
            .iter()
            .any(|s| segment.eq_ignore_ascii_case(s))
    });
    let mut stack = [Frame::Array(0); MAX_LEAK_DEPTH];
    let mut depth = 0usize;
    let mut issued: Option<FieldLeak> = None;
    let mut at = 0usize;
    while let Some(&byte) = body.get(at) {
        match byte {
            b'"' => {
                // An unterminated string ends a truncated preview.
                let Some(end) = string_end(body, at) else {
                    return issued;
                };
                let content = (at + 1, end - 1);
                let after = skip_ws(body, end);
                let top = depth.checked_sub(1).and_then(|i| stack.get(i)).copied();
                if matches!(top, Some(Frame::Object(_))) && body.get(after) == Some(&b':') {
                    if let Some(slot) = depth.checked_sub(1).and_then(|i| stack.get_mut(i)) {
                        *slot = Frame::Object(Some(content));
                    }
                    at = after + 1;
                    continue;
                }
                let key = match top {
                    Some(Frame::Object(Some((start, stop)))) => body.get(start..stop),
                    _ => None,
                };
                let value = body.get(content.0..content.1).unwrap_or_default();
                if let Some(leak) = classify(key, value, issuing) {
                    let found = FieldLeak {
                        credential: leak.credential,
                        disclosure: Disclosure {
                            kind: DisclosureKind::SensitiveFieldLeak,
                            evidence: format!("{} = {}", pointer(body, &stack, depth), leak.shape),
                        },
                    };
                    if found.credential {
                        return Some(found);
                    }
                    issued = issued.or(Some(found));
                }
                at = end;
                continue;
            }
            b'{' | b'[' => {
                if let Some(slot) = stack.get_mut(depth) {
                    *slot = if byte == b'{' {
                        Frame::Object(None)
                    } else {
                        Frame::Array(0)
                    };
                }
                depth += 1;
            }
            b'}' | b']' => depth = depth.saturating_sub(1),
            b',' => match depth.checked_sub(1).and_then(|i| stack.get_mut(i)) {
                Some(Frame::Array(index)) => *index += 1,
                Some(Frame::Object(key)) => *key = None,
                None => {}
            },
            _ => {}
        }
        at += 1;
    }
    issued
}

struct Classified {
    credential: bool,
    shape: String,
}

fn classify(key: Option<&[u8]>, value: &[u8], issuing: bool) -> Option<Classified> {
    let text = std::str::from_utf8(value).ok()?;
    if masked(text) {
        return None;
    }
    if text.len() >= MIN_HASH_LEN && HASH_PREFIXES.iter().any(|p| text.starts_with(p)) {
        return Some(Classified {
            credential: true,
            shape: format!("\"{}...\" ({} chars)", hash_parameters(text), text.len()),
        });
    }
    let key = key?;
    let credential = CREDENTIAL_FIELDS.iter().any(|name| field_named(key, name));
    let issued = !issuing && ISSUED_FIELDS.iter().any(|name| field_named(key, name));
    (credential || issued).then(|| Classified {
        credential,
        shape: format!("<redacted, {} chars>", text.chars().count()),
    })
}

/// `key` spells `name` ignoring ASCII case, `_` and `-`: `password_hash`, `passwordHash`
/// and `Password-Hash` all name `passwordhash`.
fn field_named(key: &[u8], name: &str) -> bool {
    let mut wanted = name.bytes();
    for byte in key.iter().filter(|b| !matches!(b, b'_' | b'-')) {
        if wanted.next() != Some(byte.to_ascii_lowercase()) {
            return false;
        }
    }
    wanted.next().is_none()
}

/// Empty, a mask (`****`, `xxxx`, bullets) or a redaction marker.
fn masked(text: &str) -> bool {
    let trimmed = text.trim().trim_matches(['[', ']', '<', '>', '(', ')']);
    trimmed.is_empty()
        || trimmed.chars().all(|c| {
            matches!(
                c,
                '*' | 'x' | 'X' | '.' | '-' | '_' | ' ' | '\u{2022}' | '\u{25CF}'
            )
        })
        || ["redacted", "filtered", "hidden", "masked"]
            .iter()
            .any(|marker| trimmed.eq_ignore_ascii_case(marker))
}

/// The non-secret head of a hash: algorithm and cost parameters, up to the salt.
fn hash_parameters(text: &str) -> &str {
    // argon2 `$argon2id$v=19$m=65536,t=3,p=4$`, bcrypt `$2b$12$`, scrypt `$scrypt$ln=16,r=8,p=1$`,
    // passlib `$pbkdf2-sha256$29000$`, Werkzeug `pbkdf2:sha256:600000$`, Django
    // `pbkdf2_sha256$600000$`.
    let dollars = if text.starts_with("$argon2") {
        4
    } else if text.starts_with('$') {
        3
    } else if text.starts_with("pbkdf2:") {
        1
    } else {
        2
    };
    let end = text
        .match_indices('$')
        .nth(dollars - 1)
        .map_or(text.len().min(12), |(at, _)| at + 1);
    text.get(..end).unwrap_or_default()
}

/// RFC 6901 pointer of the value under the open containers, from the raw key bytes.
fn pointer(body: &[u8], stack: &[Frame], depth: usize) -> String {
    let mut out = String::new();
    for frame in stack.iter().take(depth.min(MAX_LEAK_DEPTH)) {
        out.push('/');
        match frame {
            Frame::Object(Some((start, stop))) => {
                let key = String::from_utf8_lossy(body.get(*start..*stop).unwrap_or_default());
                out.push_str(&key.replace('~', "~0").replace('/', "~1"));
            }
            Frame::Object(None) => {}
            Frame::Array(index) => out.push_str(&index.to_string()),
        }
    }
    if depth > MAX_LEAK_DEPTH {
        out.push_str("/...");
    }
    out
}

/// Offset after the closing quote of the string opening at `at`; `None` if unterminated.
fn string_end(bytes: &[u8], at: usize) -> Option<usize> {
    let mut i = at + 1;
    while let Some(byte) = bytes.get(i) {
        match byte {
            b'\\' => i += 2,
            b'"' => return Some(i + 1),
            _ => i += 1,
        }
    }
    None
}

fn skip_ws(bytes: &[u8], mut at: usize) -> usize {
    while bytes
        .get(at)
        .is_some_and(|b| matches!(b, b' ' | b'\t' | b'\n' | b'\r'))
    {
        at += 1;
    }
    at
}

/// First disclosure signature found in `text`, with the matched fragment as evidence.
pub fn detect(text: &str) -> Option<Disclosure> {
    SIGNATURES.iter().find_map(|signature| {
        let found = signature.pattern.as_ref()?.find(text)?;
        Some(Disclosure {
            kind: signature.kind,
            evidence: evidence(found.as_str()),
        })
    })
}

fn evidence(fragment: &str) -> String {
    let trimmed = fragment
        .trim_start_matches(|c: char| c.is_whitespace())
        .trim_start_matches("\\n")
        .trim();
    match trimmed.char_indices().nth(EVIDENCE_CHARS) {
        Some((cut, _)) => format!("{}...", &trimmed[..cut]),
        None => trimmed.to_owned(),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn kind(text: &str) -> Option<DisclosureKind> {
        detect(text).map(|found| found.kind)
    }

    #[test]
    fn signatures_compile() {
        for signature in &SIGNATURES {
            assert!(signature.pattern.is_some(), "{:?}", signature.kind);
        }
    }

    #[test]
    fn node_frames_in_plain_and_json_bodies() {
        let plain = "TypeError: Cannot read properties of null (reading 'trim')\n    at normalizeSku (/srv/lab/src/orders/checkout.js:42:17)\n    at Layer.handle (/srv/node_modules/express/lib/router/layer.js:95:5)";
        let found = detect(plain).unwrap();
        assert_eq!(found.kind, DisclosureKind::NodeStackTrace);
        assert_eq!(
            found.evidence,
            "at normalizeSku (/srv/lab/src/orders/checkout.js:42:17)"
        );

        let json = r#"{"error":"TypeError: x is not a function\n    at async handler (C:\\srv\\api\\orders.ts:9:3)"}"#;
        assert_eq!(kind(json), Some(DisclosureKind::NodeStackTrace));
        assert_eq!(
            kind("at Module._compile (node:internal/modules/cjs/loader:1256:14)"),
            Some(DisclosureKind::NodeStackTrace)
        );
        assert_eq!(
            kind("    at /srv/app/index.mjs:3:9"),
            Some(DisclosureKind::NodeStackTrace)
        );
    }

    #[test]
    fn python_rust_go_jvm_and_dotnet_traces() {
        assert_eq!(
            kind("Traceback (most recent call last):\n  File \"/srv/inventory.py\", line 57, in reserve"),
            Some(DisclosureKind::PythonTraceback)
        );
        assert_eq!(
            kind(r#"{"trace":"  File \"/srv/app/views.py\", line 12, in checkout"}"#),
            Some(DisclosureKind::PythonTraceback)
        );
        assert_eq!(
            kind("thread 'tokio-runtime-worker' panicked at src/pricing.rs:88:21:\nindex out of bounds"),
            Some(DisclosureKind::RustPanic)
        );
        assert_eq!(
            kind("thread 'main' panicked at 'called `Option::unwrap()` on a `None` value', src/main.rs:4:37"),
            Some(DisclosureKind::RustPanic)
        );
        assert_eq!(
            kind("panic: runtime error: index out of range [-1]\n\ngoroutine 37 [running]:\nmain.reserve()"),
            Some(DisclosureKind::GoPanic)
        );
        assert_eq!(
            kind("goroutine 1 [chan receive, 2 minutes]:"),
            Some(DisclosureKind::GoPanic)
        );
        assert_eq!(
            kind("java.lang.NullPointerException\n\tat com.acme.orders.OrderService.create(OrderService.java:42)"),
            Some(DisclosureKind::JvmStackTrace)
        );
        assert_eq!(
            kind("System.NullReferenceException\n   at Lab.Orders.Checkout(Order order) in C:\\src\\Orders.cs:line 42"),
            Some(DisclosureKind::DotNetStackTrace)
        );
    }

    #[test]
    fn database_errors() {
        for text in [
            "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version",
            "ERROR:  syntax error at or near \"FROM\"",
            r#"{"detail":"ERROR: invalid input syntax for type integer: \"NaN\""}"#,
            "pq: column \"qty\" does not exist",
            r#"{"message":"value \"9223372036854775808\" is out of range for type bigint","code":"22003"}"#,
            "ERROR:  value \"70000\" is out of range for type smallint",
            r#"{"code":"2201W","message":"LIMIT must not be negative"}"#,
            "ERROR:  OFFSET must not be negative",
            r#"{"e":"relation \"orders\" does not exist"}"#,
            "SQLSTATE[42000]: Syntax error or access violation",
            "ORA-00933: SQL command not properly ended",
            "sqlite3.OperationalError: near \"x\": syntax error",
            "Unclosed quotation mark after the character string 'abc'.",
        ] {
            assert_eq!(kind(text), Some(DisclosureKind::SqlError), "{text}");
        }
    }

    #[test]
    fn traceback_wins_over_its_database_error() {
        let text = "Traceback (most recent call last):\n  File \"/srv/db.py\", line 3, in insert\npsycopg2.errors.StringDataRightTruncation: value too long for type character varying(64)";
        assert_eq!(kind(text), Some(DisclosureKind::PythonTraceback));
    }

    #[test]
    fn clean_bodies_and_prose_do_not_match() {
        for text in [
            r#"{"error":"validation_failed","violations":[{"pointer":"/quantity","reason":"must be between 1 and 10000"}]}"#,
            r#"{"error":"malformed_json","detail":"EOF while parsing an object at line 1 column 41"}"#,
            "Do not panic: the SQL layer retries at most 3 times.",
            "meet us at noon (room 4:30)",
            r#"{"error":"invalid_path_parameter","parameter":"orderId","reason":"integer between 1 and 999999"}"#,
            "the value is out of range for this field",
            "see traceback in the logs",
            "",
        ] {
            assert_eq!(kind(text), None, "{text}");
        }
    }

    const LAB_HASH: &str = "$2b$12$ZproxyLabFixtureSalt00NotARealCredentialOnlyAFixture0";

    fn leak(body: &str, path: &str) -> Option<(bool, String)> {
        field_leak(body.as_bytes(), path).map(|found| {
            assert_eq!(found.disclosure.kind, DisclosureKind::SensitiveFieldLeak);
            (found.credential, found.disclosure.evidence)
        })
    }

    #[test]
    fn sensitive_fields_in_json_bodies() {
        let order = format!(
            r#"{{"id":7,"customer":{{"accountId":"acct-1001","email":"operator@lab.local","passwordHash":"{LAB_HASH}","resetToken":null}}}}"#
        );
        assert_eq!(
            leak(&order, "/api/v1/orders/7"),
            Some((
                true,
                r#"/customer/passwordHash = "$2b$12$..." (60 chars)"#.to_owned()
            ))
        );
        // snake_case keys inside arrays; a masked value is not a leak.
        assert_eq!(
            leak(
                r#"{"items":[{"id":1,"password_hash":"********"},{"id":2,"salt":"c2FsdHNhbHQ="}]}"#,
                "/users"
            ),
            Some((true, "/items/1/salt = <redacted, 12 chars>".to_owned()))
        );
        // A password-hash format is credential material under any key.
        let argon = "$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA";
        assert_eq!(
            leak(&format!(r#"{{"digest":"{argon}"}}"#), "/x"),
            Some((
                true,
                format!(
                    r#"/digest = "$argon2id$v=19$m=65536,t=3,p=4$..." ({} chars)"#,
                    argon.len()
                )
            ))
        );
        assert_eq!(
            hash_parameters("pbkdf2:sha256:600000$c2FsdA$aGFzaA"),
            "pbkdf2:sha256:600000$"
        );
        assert_eq!(
            hash_parameters("pbkdf2_sha256$600000$c2FsdA$aGFzaA"),
            "pbkdf2_sha256$600000$"
        );
        // An issued credential is a leak only outside a route that issues it.
        let client = r#"{"name":"ci","clientSecret":"cs-7d1f2a9b"}"#;
        assert_eq!(leak(client, "/api/oauth/clients"), None);
        assert_eq!(
            leak(client, "/api/projects/7"),
            Some((false, "/clientSecret = <redacted, 11 chars>".to_owned()))
        );
        // Credential material outranks an issued credential seen earlier.
        assert_eq!(
            leak(
                r#"{"apiKey":"k-1234567890","user":{"password":"plaintext-pw"}}"#,
                "/api/users/1"
            ),
            Some((true, "/user/password = <redacted, 12 chars>".to_owned()))
        );
        // A preview cut inside a string still reports what came before it.
        assert_eq!(
            leak(
                r#"{"apiKey":"k-1234567890","user":{"passwordHash":"$2b$1"#,
                "/x"
            ),
            Some((false, "/apiKey = <redacted, 12 chars>".to_owned()))
        );
    }

    #[test]
    fn look_alike_and_masked_fields_are_clean() {
        for body in [
            r#"{"passwordChangedAt":"2026-11-01","hasPassword":true,"secretQuestionSet":false}"#,
            r#"{"token":"opaque","accessToken":"opaque","idToken":"opaque"}"#,
            r#"{"password":"","salt":null,"privateKey":"[REDACTED]"}"#,
            r#"{"note":"rotate $2b$ hashes yearly","sku":"O'Reilly & Sons"}"#,
            "[{\"secret\":\"\u{2022}\u{2022}\u{2022}\u{2022}\"},{\"apiKey\":\"xxxx-xxxx\"}]",
            r#"{"apiKey": "redacted", "password": "<hidden>"}"#,
            "",
            "not json at all",
        ] {
            assert_eq!(leak(body, "/api/projects/7"), None, "{body}");
        }
        assert!(field_named(b"Password-Hash", "passwordhash"));
        assert!(field_named(b"two_factor_secret", "twofactorsecret"));
        assert!(!field_named(b"passwords", "password"));
        assert!(!field_named(b"pass", "password"));
    }

    #[test]
    fn evidence_is_trimmed_and_bounded() {
        let long = format!("  at f (/srv/{}.js:1:1)", "a".repeat(400));
        let found = detect(&long).unwrap();
        assert!(found.evidence.starts_with("at f (/srv/aaa"));
        assert!(found.evidence.ends_with("..."));
        assert_eq!(found.evidence.chars().count(), EVIDENCE_CHARS + 3);
        let json = r#"x\n    at h (/a.js:1:2)"#;
        assert_eq!(detect(json).unwrap().evidence, "at h (/a.js:1:2)");
    }
}
