//! Passive audit of proxied traffic.
//!
//! Runs on every proxied exchange, so the response checks are allocation-free on a clean
//! response: JSON bodies are walked by a byte-level skimmer that counts collection items and
//! reads top-level keys without building values, header checks borrow the header map, and
//! the disclosure scan reads a bounded, borrowed UTF-8 prefix. Findings are allocated only
//! when one is reported.
//!
//! N+1 detection is the only stateful check. Windows are sharded by route template behind
//! short `std::sync::Mutex` sections (no await, no allocation once a template is known), so
//! concurrent exchanges contend only when they hit the same shard.

use std::collections::VecDeque;
use std::hash::{DefaultHasher, Hasher};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use axum::http::header::{self, HeaderMap, HeaderName};

use super::disclosure;
use super::types::{Severity, TrafficFinding, TrafficFindingKind};

/// Distinct GETs to one template inside this window are an N+1 burst.
pub const N_PLUS_ONE_WINDOW: Duration = Duration::from_millis(250);
pub const N_PLUS_ONE_THRESHOLD: usize = 8;
/// A JSON collection above this many items needs pagination metadata.
pub const COLLECTION_LIMIT: usize = 250;
pub const LARGE_JSON_BYTES: usize = 1024 * 1024;
/// Leading body bytes searched for disclosure signatures; traces start near the top.
const DISCLOSURE_SCAN_BYTES: usize = 8 * 1024;
const SHARDS: usize = 16;
/// Templates tracked per shard; the least recently seen is evicted first.
const TEMPLATES_PER_SHARD: usize = 64;
/// Distinct paths remembered per template. Only the threshold matters for detection; the
/// headroom keeps the count exact while hits arrive out of order.
const MAX_HITS: usize = 4 * N_PLUS_ONE_THRESHOLD;

const COLLECTION_KEYS: [&str; 3] = ["data", "items", "results"];
const PAGINATION_KEYS: [&str; 26] = [
    "total",
    "totalCount",
    "total_count",
    "count",
    "page",
    "pageSize",
    "page_size",
    "perPage",
    "per_page",
    "limit",
    "offset",
    "cursor",
    "nextCursor",
    "next_cursor",
    "next",
    "nextPage",
    "next_page",
    "hasMore",
    "has_more",
    "hasNextPage",
    "pageInfo",
    "page_info",
    "pagination",
    "meta",
    "links",
    "_links",
];
const PAGINATION_HEADERS: [&str; 6] = [
    "x-total-count",
    "x-next-cursor",
    "x-next-page",
    "x-pagination",
    "x-continuation-token",
    "content-range",
];
/// Route segments whose GET responses carry account or session state.
const SENSITIVE_SEGMENTS: [&str; 16] = [
    "account", "accounts", "auth", "billing", "login", "me", "oauth", "password", "payment",
    "payments", "profile", "session", "sessions", "signin", "token", "tokens",
];

// ---- N+1 bursts -----------------------------------------------------------------------

pub struct TrafficLinter {
    shards: [Mutex<Shard>; SHARDS],
}

impl Default for TrafficLinter {
    fn default() -> Self {
        Self {
            shards: std::array::from_fn(|_| Mutex::new(Shard::default())),
        }
    }
}

impl TrafficLinter {
    /// Records a GET that arrived at `arrived`; returns a finding on the request that brings
    /// a template to the threshold. The rest of the same burst is not reported again: the
    /// template stays quiet until a full window passes without a new path.
    pub fn track(
        &self,
        arrived: Instant,
        method: &str,
        path_and_query: &str,
    ) -> Option<TrafficFinding> {
        if method != "GET" {
            return None;
        }
        let path = path_and_query
            .split_once('?')
            .map_or(path_and_query, |(path, _)| path);
        let shape = RouteShape::of(path)?;
        let index = usize::try_from(shape.route % SHARDS as u64).unwrap_or(0);
        let (count, span) = {
            let mut shard = self
                .shards
                .get(index)?
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            shard.observe(arrived, shape.route, shape.concrete)?
        };
        let template = template(path);
        Some(TrafficFinding {
            kind: TrafficFindingKind::NPlusOneBurst,
            severity: Severity::Warn,
            detail: format!(
                "{count} distinct GET requests to {template} within {} ms; load the collection in one request",
                span.as_millis()
            ),
            evidence: Some(template),
        })
    }
}

/// Fingerprints of a request path: `route` with identifier segments folded to `{id}`,
/// `concrete` as sent. `None` when no segment is an identifier, so polling one fixed URL is
/// never mistaken for a fan-out.
struct RouteShape {
    route: u64,
    concrete: u64,
}

impl RouteShape {
    fn of(path: &str) -> Option<Self> {
        let mut route = DefaultHasher::new();
        let mut concrete = DefaultHasher::new();
        let mut identified = false;
        for segment in path.split('/').filter(|s| !s.is_empty()) {
            concrete.write(segment.as_bytes());
            concrete.write_u8(b'/');
            if is_identifier(segment) {
                identified = true;
                route.write(b"{id}");
            } else {
                route.write(segment.as_bytes());
            }
            route.write_u8(b'/');
        }
        identified.then(|| Self {
            route: route.finish(),
            concrete: concrete.finish(),
        })
    }
}

fn template(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    for segment in path.split('/').filter(|s| !s.is_empty()) {
        out.push('/');
        out.push_str(if is_identifier(segment) {
            "{id}"
        } else {
            segment
        });
    }
    if out.is_empty() {
        out.push('/');
    }
    out
}

/// Numeric ids, UUIDs, long hex keys (ObjectId), prefixed keys (`ord-000123`, `usr_8f2k`)
/// and long opaque tokens mixing letters and digits (ULID, nanoid).
fn is_identifier(segment: &str) -> bool {
    let bytes = segment.as_bytes();
    let digits = bytes.iter().filter(|b| b.is_ascii_digit()).count();
    if digits == 0 {
        return false;
    }
    if digits == bytes.len() {
        return true;
    }
    if is_uuid(bytes) {
        return true;
    }
    if bytes.len() >= 12 && bytes.iter().all(u8::is_ascii_hexdigit) {
        return true;
    }
    if let Some(split) = bytes.iter().position(|b| matches!(b, b'-' | b'_')) {
        let (prefix, rest) = (&bytes[..split], &bytes[split + 1..]);
        if (2..=5).contains(&prefix.len())
            && prefix.iter().all(u8::is_ascii_alphabetic)
            && rest.len() >= 4
            && rest.iter().all(u8::is_ascii_alphanumeric)
        {
            return true;
        }
    }
    bytes.len() >= 16
        && bytes.iter().any(u8::is_ascii_alphabetic)
        && bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
}

fn is_uuid(bytes: &[u8]) -> bool {
    bytes.len() == 36
        && bytes.iter().enumerate().all(|(i, b)| match i {
            8 | 13 | 18 | 23 => *b == b'-',
            _ => b.is_ascii_hexdigit(),
        })
}

#[derive(Default)]
struct Shard {
    windows: Vec<Window>,
}

impl Shard {
    fn observe(&mut self, now: Instant, route: u64, concrete: u64) -> Option<(usize, Duration)> {
        let index = match self.windows.iter().position(|w| w.route == route) {
            Some(index) => index,
            None => {
                if self.windows.len() >= TEMPLATES_PER_SHARD {
                    let stale = self
                        .windows
                        .iter()
                        .enumerate()
                        .min_by_key(|(_, w)| w.last_seen)
                        .map(|(index, _)| index);
                    if let Some(stale) = stale {
                        self.windows.swap_remove(stale);
                    }
                }
                self.windows.push(Window {
                    route,
                    hits: VecDeque::with_capacity(N_PLUS_ONE_THRESHOLD),
                    quiet_until: None,
                    last_seen: now,
                });
                self.windows.len() - 1
            }
        };
        self.windows.get_mut(index)?.observe(now, concrete)
    }
}

struct Window {
    route: u64,
    /// Arrival instant and fingerprint of each distinct path inside the window. Exchanges
    /// complete out of order, so instants are not sorted.
    hits: VecDeque<(Instant, u64)>,
    quiet_until: Option<Instant>,
    last_seen: Instant,
}

impl Window {
    fn observe(&mut self, now: Instant, concrete: u64) -> Option<(usize, Duration)> {
        self.last_seen = self.last_seen.max(now);
        let newest = self.last_seen;
        if let Some(floor) = newest.checked_sub(N_PLUS_ONE_WINDOW) {
            self.hits.retain(|(at, _)| *at >= floor);
            if now < floor {
                return None;
            }
        }
        if !self.hits.iter().any(|(_, seen)| *seen == concrete) {
            if self.hits.len() == MAX_HITS {
                self.hits.pop_front();
            }
            self.hits.push_back((now, concrete));
        }
        if let Some(quiet) = self.quiet_until {
            if now <= quiet {
                self.quiet_until = Some(quiet.max(now + N_PLUS_ONE_WINDOW));
                return None;
            }
            self.quiet_until = None;
        }
        if self.hits.len() < N_PLUS_ONE_THRESHOLD {
            return None;
        }
        self.quiet_until = Some(newest + N_PLUS_ONE_WINDOW);
        let first = self.hits.iter().map(|(at, _)| *at).min()?;
        let last = self.hits.iter().map(|(at, _)| *at).max()?;
        Some((self.hits.len(), last.saturating_duration_since(first)))
    }
}

// ---- response checks ------------------------------------------------------------------

/// One forwarded exchange as the response checks see it.
pub struct ResponseView<'a> {
    pub method: &'a str,
    pub path: &'a str,
    /// The request carried `Authorization` or `Cookie`.
    pub credentialed: bool,
    pub status: u16,
    pub headers: &'a HeaderMap,
    pub body: &'a [u8],
}

pub fn inspect(view: &ResponseView<'_>) -> Vec<TrafficFinding> {
    let mut findings = Vec::new();
    cors(view.headers, &mut findings);
    // The proxy client does not decompress, so an encoded body is opaque bytes here and only
    // the header checks apply.
    let encoded = header(view.headers, &header::CONTENT_ENCODING)
        .is_some_and(|e| !e.eq_ignore_ascii_case("identity"));
    if !encoded && !view.body.is_empty() {
        let media = header(view.headers, &header::CONTENT_TYPE).map(essence);
        let json_media = media.is_some_and(is_json_media);
        let json_body = is_json_document(view.body);
        content_type(media, json_media, json_body, view.body, &mut findings);
        if (200..300).contains(&view.status) && (json_media || json_body) {
            collection(view, &mut findings);
        }
        if media.is_none_or(is_textual) {
            leak(view, &mut findings);
        }
    }
    cache_control(view, &mut findings);
    findings
}

fn header<'a>(headers: &'a HeaderMap, name: &HeaderName) -> Option<&'a str> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
}

fn essence(content_type: &str) -> &str {
    content_type.split(';').next().unwrap_or_default().trim()
}

fn ends_with_ignore_case(text: &str, suffix: &str) -> bool {
    text.len() >= suffix.len()
        && text.as_bytes()[text.len() - suffix.len()..].eq_ignore_ascii_case(suffix.as_bytes())
}

fn is_json_media(media: &str) -> bool {
    media.eq_ignore_ascii_case("application/json") || ends_with_ignore_case(media, "+json")
}

fn is_textual(media: &str) -> bool {
    let lower_starts = |prefix: &str| {
        media.len() >= prefix.len()
            && media.as_bytes()[..prefix.len()].eq_ignore_ascii_case(prefix.as_bytes())
    };
    lower_starts("text/")
        || is_json_media(media)
        || ends_with_ignore_case(media, "xml")
        || ends_with_ignore_case(media, "javascript")
        || media.eq_ignore_ascii_case("application/problem")
}

/// A complete JSON object or array, nothing but whitespace after it.
fn is_json_document(body: &[u8]) -> bool {
    let at = skim::skip_ws(body, 0);
    matches!(body.get(at), Some(b'{' | b'['))
        && skim::value_end(body, at).is_some_and(|end| skim::skip_ws(body, end) == body.len())
}

fn finding(
    kind: TrafficFindingKind,
    severity: Severity,
    detail: String,
    evidence: Option<String>,
) -> TrafficFinding {
    TrafficFinding {
        kind,
        severity,
        detail,
        evidence,
    }
}

fn cors(headers: &HeaderMap, out: &mut Vec<TrafficFinding>) {
    let Some(origin) = header(headers, &header::ACCESS_CONTROL_ALLOW_ORIGIN) else {
        return;
    };
    let credentials = header(headers, &header::ACCESS_CONTROL_ALLOW_CREDENTIALS)
        .is_some_and(|value| value.eq_ignore_ascii_case("true"));
    if !credentials {
        return;
    }
    if origin == "*" {
        out.push(finding(
            TrafficFindingKind::HeaderMisconfiguration,
            Severity::Warn,
            "Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true; browsers reject credentialed wildcard responses".to_owned(),
            Some("Access-Control-Allow-Origin: *".to_owned()),
        ));
    } else if origin.eq_ignore_ascii_case("null") {
        out.push(finding(
            TrafficFindingKind::HeaderMisconfiguration,
            Severity::Fault,
            "Access-Control-Allow-Origin: null with credentials; sandboxed iframes and file: documents send Origin: null".to_owned(),
            Some("Access-Control-Allow-Origin: null".to_owned()),
        ));
    }
}

fn content_type(
    media: Option<&str>,
    json_media: bool,
    json_body: bool,
    body: &[u8],
    out: &mut Vec<TrafficFinding>,
) {
    let detail = match media {
        None if json_body => "JSON body without a Content-Type".to_owned(),
        Some(media) if json_body && !json_media => format!("JSON body served as {media}"),
        Some(media) if json_media && body.get(skim::skip_ws(body, 0)) == Some(&b'<') => {
            format!("markup body served as {media}")
        }
        _ => return,
    };
    out.push(finding(
        TrafficFindingKind::HeaderMisconfiguration,
        Severity::Warn,
        detail,
        media.map(|media| format!("Content-Type: {media}")),
    ));
}

fn collection(view: &ResponseView<'_>, out: &mut Vec<TrafficFinding>) {
    if view.body.len() > LARGE_JSON_BYTES {
        out.push(finding(
            TrafficFindingKind::UnboundedCollection,
            Severity::Warn,
            format!(
                "JSON body of {:.1} MiB; page or stream payloads above 1 MiB",
                view.body.len() as f64 / (1024.0 * 1024.0)
            ),
            None,
        ));
    }
    if paginated_by_headers(view.headers) {
        return;
    }
    let Some(found) = skim::collection(view.body) else {
        return;
    };
    if found.items <= COLLECTION_LIMIT || found.paginated {
        return;
    }
    let (detail, evidence) = match found.key {
        Some(key) => (
            format!(
                "`{key}` holds {} items and the body carries no pagination metadata",
                found.items
            ),
            Some(key.to_owned()),
        ),
        None => (
            format!(
                "top-level JSON array of {} items without pagination",
                found.items
            ),
            None,
        ),
    };
    out.push(finding(
        TrafficFindingKind::UnboundedCollection,
        Severity::Warn,
        detail,
        evidence,
    ));
}

fn paginated_by_headers(headers: &HeaderMap) -> bool {
    let next_link = headers
        .get_all(header::LINK)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .any(|value| {
            value
                .split(';')
                .any(|param| matches!(param.trim(), "rel=\"next\"" | "rel=next"))
        });
    next_link
        || PAGINATION_HEADERS
            .iter()
            .any(|name| headers.contains_key(*name))
}

fn leak(view: &ResponseView<'_>, out: &mut Vec<TrafficFinding>) {
    let prefix = &view.body[..view.body.len().min(DISCLOSURE_SCAN_BYTES)];
    // The cut may split a multi-byte character; scan the valid part instead of copying.
    let text = match std::str::from_utf8(prefix) {
        Ok(text) => text,
        Err(err) => std::str::from_utf8(&prefix[..err.valid_up_to()]).unwrap_or_default(),
    };
    let Some(found) = disclosure::detect(text) else {
        return;
    };
    out.push(finding(
        TrafficFindingKind::PassiveDisclosure,
        if view.status >= 500 {
            Severity::Fault
        } else {
            Severity::Warn
        },
        format!(
            "{} in a {} response",
            disclosure::label(found.kind),
            view.status
        ),
        Some(found.evidence),
    ));
}

fn cache_control(view: &ResponseView<'_>, out: &mut Vec<TrafficFinding>) {
    // Responses to other methods are not stored without explicit freshness (RFC 9111 4).
    if !matches!(view.method, "GET" | "HEAD") || !(200..300).contains(&view.status) {
        return;
    }
    let path = view
        .path
        .split_once('?')
        .map_or(view.path, |(path, _)| path);
    let reason = if view.credentialed {
        "a credentialed request"
    } else if view.headers.contains_key(header::SET_COOKIE) {
        "a request that sets a cookie"
    } else if path.split('/').any(|segment| {
        SENSITIVE_SEGMENTS
            .iter()
            .any(|sensitive| segment.eq_ignore_ascii_case(sensitive))
    }) {
        "an account or session route"
    } else {
        return;
    };
    let detail = match header(view.headers, &header::CACHE_CONTROL) {
        None => format!("GET response to {reason} without Cache-Control; send no-store or private"),
        Some(value) => {
            let directive = |name: &str| {
                value.split(',').any(|d| {
                    d.trim()
                        .split('=')
                        .next()
                        .is_some_and(|d| d.trim().eq_ignore_ascii_case(name))
                })
            };
            if directive("public") && !directive("private") && !directive("no-store") {
                format!("Cache-Control: public on the response to {reason}")
            } else {
                return;
            }
        }
    };
    out.push(finding(
        TrafficFindingKind::HeaderMisconfiguration,
        Severity::Warn,
        detail,
        Some(view.path.to_owned()),
    ));
}

/// Byte-level JSON walking: well-formedness to the extent the checks need, item counts and
/// top-level keys, with no allocation. Containers are skipped with a depth counter rather
/// than recursion, so a deeply nested body cannot exhaust the stack.
mod skim {
    use super::{COLLECTION_KEYS, PAGINATION_KEYS};

    pub struct Collection {
        /// `None` for a top-level array.
        pub key: Option<&'static str>,
        pub items: usize,
        pub paginated: bool,
    }

    pub fn skip_ws(bytes: &[u8], mut at: usize) -> usize {
        while bytes
            .get(at)
            .is_some_and(|b| matches!(b, b' ' | b'\t' | b'\n' | b'\r'))
        {
            at += 1;
        }
        at
    }

    /// Offset after the closing quote of the string opening at `at`.
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

    /// Offset after the value starting at `at` (leading whitespace allowed).
    pub fn value_end(bytes: &[u8], at: usize) -> Option<usize> {
        let at = skip_ws(bytes, at);
        match bytes.get(at)? {
            b'"' => string_end(bytes, at),
            b'{' | b'[' => {
                let mut depth = 0usize;
                let mut i = at;
                while let Some(byte) = bytes.get(i) {
                    match byte {
                        b'"' => {
                            i = string_end(bytes, i)?;
                            continue;
                        }
                        b'{' | b'[' => depth += 1,
                        b'}' | b']' => {
                            depth = depth.checked_sub(1)?;
                            if depth == 0 {
                                return Some(i + 1);
                            }
                        }
                        _ => {}
                    }
                    i += 1;
                }
                None
            }
            _ => {
                let mut i = at;
                while bytes
                    .get(i)
                    .is_some_and(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'))
                {
                    i += 1;
                }
                (i > at).then_some(i)
            }
        }
    }

    /// Item count of the array opening at `at`, and the offset after it.
    pub fn array_len(bytes: &[u8], at: usize) -> Option<(usize, usize)> {
        let mut i = skip_ws(bytes, at + 1);
        if bytes.get(i) == Some(&b']') {
            return Some((0, i + 1));
        }
        let mut items = 0;
        loop {
            i = skip_ws(bytes, value_end(bytes, i)?);
            items += 1;
            match bytes.get(i)? {
                b',' => i += 1,
                b']' => return Some((items, i + 1)),
                _ => return None,
            }
        }
    }

    /// Calls `visit` with each top-level key (raw, unescaped bytes) of the object opening at
    /// `at` and the offset of its value; returns the offset after the object.
    fn object_entries(
        bytes: &[u8],
        at: usize,
        mut visit: impl FnMut(&[u8], usize),
    ) -> Option<usize> {
        let mut i = skip_ws(bytes, at + 1);
        if bytes.get(i) == Some(&b'}') {
            return Some(i + 1);
        }
        loop {
            if bytes.get(i) != Some(&b'"') {
                return None;
            }
            let key_end = string_end(bytes, i)?;
            let key = bytes.get(i + 1..key_end - 1)?;
            i = skip_ws(bytes, key_end);
            if bytes.get(i) != Some(&b':') {
                return None;
            }
            let value_at = skip_ws(bytes, i + 1);
            visit(key, value_at);
            i = skip_ws(bytes, value_end(bytes, value_at)?);
            match bytes.get(i)? {
                b',' => i = skip_ws(bytes, i + 1),
                b'}' => return Some(i + 1),
                _ => return None,
            }
        }
    }

    /// The largest collection the body exposes: a top-level array, or the biggest of the
    /// `data` / `items` / `results` arrays of a top-level object.
    pub fn collection(body: &[u8]) -> Option<Collection> {
        let at = skip_ws(body, 0);
        match body.get(at)? {
            b'[' => {
                let (items, _) = array_len(body, at)?;
                Some(Collection {
                    key: None,
                    items,
                    paginated: false,
                })
            }
            b'{' => {
                let mut largest: Option<(&'static str, usize)> = None;
                let mut paginated = false;
                object_entries(body, at, |key, value_at| {
                    if let Some(name) = COLLECTION_KEYS.iter().find(|name| name.as_bytes() == key) {
                        if body.get(value_at) == Some(&b'[') {
                            if let Some((items, _)) = array_len(body, value_at) {
                                if largest.is_none_or(|(_, most)| items > most) {
                                    largest = Some((name, items));
                                }
                            }
                        }
                    } else if PAGINATION_KEYS.iter().any(|name| name.as_bytes() == key) {
                        paginated = true;
                    }
                })?;
                let (key, items) = largest?;
                Some(Collection {
                    key: Some(key),
                    items,
                    paginated,
                })
            }
            _ => None,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use axum::http::HeaderValue;

    use super::*;

    fn kinds(findings: &[TrafficFinding]) -> Vec<(TrafficFindingKind, Severity)> {
        findings.iter().map(|f| (f.kind, f.severity)).collect()
    }

    #[test]
    fn identifier_segments() {
        for id in [
            "7",
            "000123",
            "123e4567-e89b-12d3-a456-426614174000",
            "507f1f77bcf86cd799439011",
            "ord-000001",
            "usr_8f2kq9",
            "01ARZ3NDEKTSV4RRFFQ69G5FAV",
            "V1StGXR8_Z5jdHi6B-myT",
        ] {
            assert!(is_identifier(id), "{id}");
        }
        for literal in [
            "orders",
            "v1",
            "api",
            "checkout",
            "2fa-setup",
            "health",
            "my-post-title",
            "deadbeef",
        ] {
            assert!(!is_identifier(literal), "{literal}");
        }
        assert_eq!(
            template("/api/v1/orders/42/items/ord-000001"),
            "/api/v1/orders/{id}/items/{id}"
        );
        assert!(RouteShape::of("/api/v1/health").is_none());
    }

    fn at(base: Instant, ms: u64) -> Instant {
        base + Duration::from_millis(ms)
    }

    #[test]
    fn n_plus_one_is_reported_once_per_burst() {
        let linter = TrafficLinter::default();
        let base = Instant::now();
        let mut reported = Vec::new();
        for n in 1..=12u64 {
            if let Some(f) =
                linter.track(at(base, n * 10), "GET", &format!("/api/items/{n}?expand=1"))
            {
                reported.push((n, f));
            }
        }
        assert_eq!(reported.len(), 1, "one finding per burst");
        let (n, finding) = &reported[0];
        assert_eq!(*n, 8);
        assert_eq!(finding.kind, TrafficFindingKind::NPlusOneBurst);
        assert_eq!(finding.evidence.as_deref(), Some("/api/items/{id}"));
        assert_eq!(
            finding.detail,
            "8 distinct GET requests to /api/items/{id} within 70 ms; load the collection in one request"
        );

        // A quiet window ends the burst; the next fan-out is reported again.
        let later = at(base, 1_000);
        let again = (1..=8u64)
            .filter_map(|n| {
                linter.track(
                    later + Duration::from_millis(n),
                    "GET",
                    &format!("/api/items/{}", 100 + n),
                )
            })
            .count();
        assert_eq!(again, 1);
    }

    #[test]
    fn repeats_slow_fanouts_and_other_methods_are_not_bursts() {
        let linter = TrafficLinter::default();
        let base = Instant::now();
        // The same member eight times is polling, not N+1.
        assert!((0..8).all(|n| linter.track(at(base, n), "GET", "/api/items/1").is_none()));
        // Eight members spread over more than the window.
        assert!((0..8u64).all(|n| linter
            .track(at(base, 1_000 + n * 40), "GET", &format!("/a/{n}"))
            .is_none()));
        assert!((0..8u64).all(|n| linter
            .track(at(base, 5_000 + n), "POST", &format!("/b/{n}"))
            .is_none()));
        assert!((0..8u64).all(|n| linter
            .track(at(base, 6_000 + n), "GET", "/static/app.js")
            .is_none()));
    }

    #[test]
    fn out_of_order_completions_use_arrival_instants() {
        let linter = TrafficLinter::default();
        let base = Instant::now();
        let order = [7u64, 2, 5, 0, 6, 1, 4, 3];
        let found: Vec<TrafficFinding> = order
            .iter()
            .filter_map(|n| linter.track(at(base, *n), "GET", &format!("/users/{n}/avatar")))
            .collect();
        assert_eq!(found.len(), 1);
        assert!(
            found[0].detail.contains("within 7 ms"),
            "{}",
            found[0].detail
        );
    }

    fn headers(pairs: &[(&'static str, &'static str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.append(*name, HeaderValue::from_static(value));
        }
        map
    }

    fn inspect_with(
        method: &str,
        path: &str,
        status: u16,
        pairs: &[(&'static str, &'static str)],
        body: &[u8],
    ) -> Vec<TrafficFinding> {
        let headers = headers(pairs);
        inspect(&ResponseView {
            method,
            path,
            credentialed: false,
            status,
            headers: &headers,
            body,
        })
    }

    const JSON: (&str, &str) = ("content-type", "application/json; charset=utf-8");

    fn array(items: usize) -> String {
        let item = r#"{"id":1,"tags":["a","b]"],"note":"x\"y{"}"#;
        format!("[{}]", vec![item; items].join(","))
    }

    #[test]
    fn clean_responses_produce_nothing() {
        assert!(inspect_with("GET", "/api/items", 200, &[JSON], array(10).as_bytes()).is_empty());
        assert!(inspect_with(
            "GET",
            "/",
            200,
            &[("content-type", "text/html")],
            b"<html></html>"
        )
        .is_empty());
        assert!(inspect_with("POST", "/api/items", 201, &[JSON], b"{\"id\":1}").is_empty());
        assert!(inspect_with(
            "GET",
            "/img",
            200,
            &[("content-type", "image/png")],
            b"\x89PNG at x (/a.js:1:2)"
        )
        .is_empty());
    }

    #[test]
    fn unbounded_collections_need_pagination() {
        let big = array(COLLECTION_LIMIT + 1);
        assert_eq!(
            kinds(&inspect_with(
                "GET",
                "/api/items",
                200,
                &[JSON],
                big.as_bytes()
            )),
            [(TrafficFindingKind::UnboundedCollection, Severity::Warn)]
        );
        assert!(inspect_with(
            "GET",
            "/api/items",
            200,
            &[JSON],
            array(COLLECTION_LIMIT).as_bytes()
        )
        .is_empty());
        assert!(inspect_with(
            "GET",
            "/api/items",
            200,
            &[JSON, ("link", "</api/items?page=2>; rel=\"next\"")],
            big.as_bytes()
        )
        .is_empty());
        assert!(inspect_with("GET", "/api/items", 500, &[JSON], big.as_bytes()).is_empty());

        let keyed = format!(r#"{{"status":"ok","items":{big},"data":[1,2]}}"#);
        let found = inspect_with("GET", "/api/items", 200, &[JSON], keyed.as_bytes());
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].evidence.as_deref(), Some("items"));
        assert_eq!(
            found[0].detail,
            "`items` holds 251 items and the body carries no pagination metadata"
        );
        let paged = format!(r#"{{"results":{big},"nextCursor":"abc"}}"#);
        assert!(inspect_with("GET", "/api/items", 200, &[JSON], paged.as_bytes()).is_empty());
        let truncated = &big.as_bytes()[..big.len() - 1];
        assert!(inspect_with("GET", "/api/items", 200, &[JSON], truncated)
            .iter()
            .all(|f| f.kind != TrafficFindingKind::UnboundedCollection));
    }

    #[test]
    fn large_json_bodies_are_reported() {
        let body = format!(r#"{{"blob":"{}"}}"#, "x".repeat(LARGE_JSON_BYTES));
        let found = inspect_with("GET", "/export", 200, &[JSON], body.as_bytes());
        assert_eq!(
            kinds(&found),
            [(TrafficFindingKind::UnboundedCollection, Severity::Warn)]
        );
        assert!(
            found[0].detail.starts_with("JSON body of 1.0 MiB"),
            "{}",
            found[0].detail
        );
    }

    #[test]
    fn content_type_must_match_the_body() {
        let misconfig = |pairs: &[(&'static str, &'static str)], body: &[u8]| {
            inspect_with("POST", "/x", 200, pairs, body)
                .into_iter()
                .map(|f| f.detail)
                .collect::<Vec<_>>()
        };
        assert_eq!(
            misconfig(&[], b" {\"a\":1}\n"),
            ["JSON body without a Content-Type"]
        );
        assert_eq!(
            misconfig(&[("content-type", "text/html; charset=utf-8")], b"[1,2]"),
            ["JSON body served as text/html"]
        );
        assert_eq!(
            misconfig(&[JSON], b"<!doctype html><p>502</p>"),
            ["markup body served as application/json"]
        );
        assert!(misconfig(&[("content-type", "text/plain")], b"[INFO] started").is_empty());
        assert!(misconfig(&[("content-type", "application/problem+json")], b"{}").is_empty());
    }

    #[test]
    fn credentialed_cors_wildcards() {
        let wildcard = inspect_with(
            "GET",
            "/x",
            200,
            &[
                ("access-control-allow-origin", "*"),
                ("access-control-allow-credentials", "true"),
            ],
            b"",
        );
        assert_eq!(
            kinds(&wildcard),
            [(TrafficFindingKind::HeaderMisconfiguration, Severity::Warn)]
        );
        let null = inspect_with(
            "GET",
            "/x",
            200,
            &[
                ("access-control-allow-origin", "null"),
                ("access-control-allow-credentials", "TRUE"),
            ],
            b"",
        );
        assert_eq!(
            kinds(&null),
            [(TrafficFindingKind::HeaderMisconfiguration, Severity::Fault)]
        );
        assert!(inspect_with(
            "GET",
            "/x",
            200,
            &[("access-control-allow-origin", "*")],
            b""
        )
        .is_empty());
        assert!(inspect_with(
            "GET",
            "/x",
            200,
            &[
                ("access-control-allow-origin", "http://localhost:5173"),
                ("access-control-allow-credentials", "true")
            ],
            b""
        )
        .is_empty());
    }

    #[test]
    fn sensitive_get_responses_need_cache_control() {
        let detail = |method: &str,
                      path: &str,
                      credentialed: bool,
                      pairs: &[(&'static str, &'static str)]| {
            let headers = headers(pairs);
            inspect(&ResponseView {
                method,
                path,
                credentialed,
                status: 200,
                headers: &headers,
                body: b"",
            })
            .into_iter()
            .map(|f| f.detail)
            .collect::<Vec<_>>()
        };
        assert_eq!(
            detail("GET", "/api/orders", true, &[]),
            ["GET response to a credentialed request without Cache-Control; send no-store or private"]
        );
        assert_eq!(
            detail(
                "GET",
                "/api/me?x=1",
                false,
                &[("cache-control", "public, max-age=600")]
            ),
            ["Cache-Control: public on the response to an account or session route"]
        );
        assert_eq!(
            detail("GET", "/", false, &[("set-cookie", "sid=1")]).len(),
            1
        );
        assert!(detail(
            "GET",
            "/api/me",
            false,
            &[("cache-control", "private, max-age=60")]
        )
        .is_empty());
        assert!(detail("GET", "/api/me", true, &[("cache-control", "no-store")]).is_empty());
        assert!(detail("POST", "/api/login", true, &[]).is_empty());
        assert!(detail("GET", "/api/catalog", false, &[]).is_empty());
    }

    #[test]
    fn disclosures_in_passing_traffic() {
        let trace = b"TypeError: Cannot read properties of null (reading 'trim')\n    at normalizeSku (/srv/app/checkout.js:42:17)";
        let found = inspect_with(
            "POST",
            "/checkout",
            500,
            &[("content-type", "text/plain")],
            trace,
        );
        assert_eq!(
            kinds(&found),
            [(TrafficFindingKind::PassiveDisclosure, Severity::Fault)]
        );
        assert_eq!(found[0].detail, "Node.js stack trace in a 500 response");
        assert_eq!(
            found[0].evidence.as_deref(),
            Some("at normalizeSku (/srv/app/checkout.js:42:17)")
        );
        let sql = br#"{"error":"ERROR:  syntax error at or near \"FROM\""}"#;
        assert_eq!(
            kinds(&inspect_with("GET", "/q", 400, &[JSON], sql)),
            [(TrafficFindingKind::PassiveDisclosure, Severity::Warn)]
        );
        // A multi-byte character cut at the scan limit does not hide the trace before it.
        let mut cut = trace.to_vec();
        cut.resize(DISCLOSURE_SCAN_BYTES - 1, b' ');
        cut.extend_from_slice("\u{00e9}".as_bytes());
        assert_eq!(inspect_with("GET", "/q", 500, &[], &cut).len(), 1);
    }

    #[test]
    fn compressed_bodies_get_header_checks_only() {
        let found = inspect_with(
            "GET",
            "/api/items",
            200,
            &[
                ("content-encoding", "gzip"),
                ("access-control-allow-origin", "*"),
                ("access-control-allow-credentials", "true"),
            ],
            b"\x1f\x8b at x (/a.js:1:2)",
        );
        assert_eq!(
            kinds(&found),
            [(TrafficFindingKind::HeaderMisconfiguration, Severity::Warn)]
        );
    }

    #[test]
    fn skimmer_handles_escapes_nesting_and_garbage() {
        assert_eq!(
            skim::array_len(br#"[ "a\"]", [1,[2,]], {"k":"]"} ]"#, 0).map(|r| r.0),
            Some(3)
        );
        assert_eq!(skim::array_len(b"[]", 0), Some((0, 2)));
        assert_eq!(skim::array_len(b"[1 2]", 0), None);
        assert!(skim::value_end(b"[[[", 0).is_none());
        assert!(skim::value_end(b"]", 0).is_none());
        assert!(!is_json_document(b"{\"a\":1} trailing"));
        assert!(is_json_document(b"\n[1, {\"b\": [true, null]}]  "));
        let deep = format!("{}{}", "[".repeat(100_000), "]".repeat(100_000));
        assert!(is_json_document(deep.as_bytes()));
    }
}
