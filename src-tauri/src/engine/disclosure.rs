//! Information-disclosure signatures in response bodies.
//!
//! Each pattern requires structure (a frame with `file:line`, a traceback header, a
//! goroutine header, a vendor-specific SQL error phrase) rather than a bare keyword, so
//! prose that merely mentions "panic" or "SQL" does not match. Bodies are usually JSON, where
//! a multi-line trace arrives with `\n` escapes instead of line breaks; frame patterns accept
//! either separator.

use std::sync::LazyLock;

use regex::Regex;

use super::types::{Disclosure, DisclosureKind};

const EVIDENCE_CHARS: usize = 160;

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
    }
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
