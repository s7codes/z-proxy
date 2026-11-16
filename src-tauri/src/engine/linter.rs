//! Passive audit of proxied traffic.
//!
//! Runs on every proxied exchange, so the response checks are allocation-free on a clean
//! response: JSON bodies are walked by a byte-level skimmer that counts collection items and
//! reads top-level keys without building values, header checks borrow the header map, and
//! the disclosure scan reads a bounded, borrowed UTF-8 prefix. Findings are allocated only
//! when one is reported.
//!
//! Four checks are stateful: N+1 fan-outs, retry storms, retries that ignore a 429 / 503
//! (and its `Retry-After`), and latency regressions. Their windows are sharded by key behind
//! short `std::sync::Mutex` sections (no await, no allocation once a key is known; an
//! evicted slot's buffers are reused), so concurrent exchanges contend only when they hit
//! the same shard.
//!
//! Encoded bodies are inflated before the checks (gzip, deflate, br, zstd) into a buffer
//! capped at 1 MiB, so a compressed decompression bomb costs at most that much output and
//! the time to produce it. The brotli decoder's ring buffer is bounded by the stream's
//! window, at most 16 MiB under RFC 7932; large-window streams are refused as corrupt, as
//! browsers refuse them. A zstd frame's window is read from its header before the decoder
//! allocates anything, and one above the 8 MiB that RFC 9659 allows a `zstd` content coding
//! is refused the same way.

use std::collections::VecDeque;
use std::hash::{DefaultHasher, Hasher};
use std::io::{self, Read};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use axum::http::header::{self, HeaderMap, HeaderName};
use brotli_decompressor::Decompressor;
use flate2::read::{DeflateDecoder, MultiGzDecoder, ZlibDecoder};
use ruzstd::decoding::StreamingDecoder;

use super::disclosure;
use super::types::{Severity, TrafficFinding, TrafficFindingKind};

/// Distinct GETs to one template inside this window are an N+1 burst.
pub const N_PLUS_ONE_WINDOW: Duration = Duration::from_millis(250);
pub const N_PLUS_ONE_THRESHOLD: usize = 8;
/// One exact request (method, path and query) repeated this often inside the window is a
/// retry storm: an effect re-running on every render, or a retry loop without backoff.
pub const RETRY_STORM_WINDOW: Duration = Duration::from_millis(250);
pub const RETRY_STORM_THRESHOLD: usize = 10;
/// A retry of the same request this soon after a 429 or 503 answer to it ignored the
/// answer, as does one sent before the answer's `Retry-After` elapsed; this many such retries
/// in a row are a storm. Any real backoff, even the first step of an exponential one, waits
/// longer than the window.
pub const THROTTLE_RETRY_WINDOW: Duration = Duration::from_millis(100);
pub const THROTTLE_RETRY_THRESHOLD: usize = 4;
/// `Retry-After` delta-seconds above a day are read as a day.
const MAX_RETRY_AFTER_SECS: u64 = 86_400;
/// Read buffer the brotli decoder pulls compressed input through.
const BROTLI_BUFFER_BYTES: usize = 4 * 1024;
/// RFC 9659 caps the window of a `zstd` content coding at 8 MiB, so no compliant sender
/// needs more history; a larger one would make the decoder reserve it before the output cap
/// could stop anything.
const ZSTD_MAX_WINDOW: u64 = 8 * 1024 * 1024;
const ZSTD_MAGIC: u32 = 0xFD2F_B528;
/// Skippable frames (RFC 8878 3.1.2) carry metadata, never content.
const ZSTD_SKIPPABLE: std::ops::RangeInclusive<u32> = 0x184D_2A50..=0x184D_2A5F;
/// Upstream latencies kept per route template for the rolling median.
pub const LATENCY_WINDOW: usize = 32;
/// Responses a template needs before a regression can be judged against its median.
pub const LATENCY_MIN_SAMPLES: usize = 8;
pub const LATENCY_FACTOR: u64 = 4;
/// A response faster than this is never a regression under the general rule, whatever its
/// ratio: loopback medians of a few milliseconds would otherwise turn scheduler jitter into
/// findings.
pub const LATENCY_FLOOR: Duration = Duration::from_millis(250);
/// The loopback rule applies to templates whose rolling median is at least this: handlers
/// that do real work (a query, a file read), not in-memory answers whose median is jitter.
pub const LOOPBACK_MEDIAN: Duration = Duration::from_millis(2);
pub const LOOPBACK_FACTOR: u64 = 8;
/// Above two ticks of the 15.6 ms Windows timer, so a descheduled handler is not a finding.
pub const LOOPBACK_FLOOR: Duration = Duration::from_millis(35);
/// Decoded body cap for the audit; larger output stops the inflater and skips body checks.
pub const MAX_DECODED_BYTES: usize = 1024 * 1024;
/// Request evidence (`METHOD /path?query`) is cut to this many characters.
const EVIDENCE_CHARS: usize = 160;
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
/// Exact requests tracked per shard for retry storms, and arrivals kept per request.
const REQUESTS_PER_SHARD: usize = 64;
const MAX_REPEATS: usize = 4 * RETRY_STORM_THRESHOLD;

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
    repeats: [Mutex<RepeatShard>; SHARDS],
    throttles: [Mutex<ThrottleShard>; SHARDS],
    latencies: [Mutex<LatencyShard>; SHARDS],
}

impl Default for TrafficLinter {
    fn default() -> Self {
        Self {
            shards: std::array::from_fn(|_| Mutex::new(Shard::default())),
            repeats: std::array::from_fn(|_| Mutex::new(RepeatShard::default())),
            throttles: std::array::from_fn(|_| Mutex::new(ThrottleShard::default())),
            latencies: std::array::from_fn(|_| Mutex::new(LatencyShard::default())),
        }
    }
}

fn shard_of(key: u64) -> usize {
    usize::try_from(key % SHARDS as u64).unwrap_or(0)
}

/// One exact request line: method, path and query.
fn request_key(method: &str, path_and_query: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    hasher.write(method.as_bytes());
    hasher.write_u8(b' ');
    hasher.write(path_and_query.as_bytes());
    hasher.finish()
}

/// `METHOD /path?query`, cut to `EVIDENCE_CHARS` characters.
fn request_evidence(method: &str, path_and_query: &str) -> String {
    let mut evidence = format!("{method} {path_and_query}");
    if let Some((cut, _)) = evidence.char_indices().nth(EVIDENCE_CHARS) {
        evidence.truncate(cut);
        evidence.push_str("...");
    }
    evidence
}

impl TrafficLinter {
    /// Records any request that arrived at `arrived`; returns a finding on the request that
    /// brings one exact request line to the storm threshold. Like N+1 bursts, one storm is
    /// reported once and the request stays quiet until a full window passes without it.
    pub fn repeat(
        &self,
        arrived: Instant,
        method: &str,
        path_and_query: &str,
    ) -> Option<TrafficFinding> {
        let key = request_key(method, path_and_query);
        let (count, span) = {
            let mut shard = self
                .repeats
                .get(shard_of(key))?
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            shard.observe(arrived, key)?
        };
        Some(TrafficFinding {
            kind: TrafficFindingKind::RetryStorm,
            severity: Severity::Warn,
            detail: format!(
                "{count} identical {method} requests within {} ms; an effect re-running on every render or a retry loop without backoff",
                span.as_millis()
            ),
            evidence: Some(request_evidence(method, path_and_query)),
        })
    }

    /// Follows one exact request through 429 / 503 answers. A retry that arrives within
    /// `THROTTLE_RETRY_WINDOW` of the previous throttled answer, or before the `Retry-After`
    /// that answer set, ignored it; the `THROTTLE_RETRY_THRESHOLD`th such retry in a row is
    /// reported, once per storm, with the advertised interval it broke. A retry after a longer
    /// pause, or any other answer, ends the storm. A request that arrived before the
    /// throttled answer went out ran concurrently and is not a retry. `status` and
    /// `retry_after` are what the client received, so an injected 429 / 503 exposes the
    /// client's retry policy as well as an upstream one.
    pub fn throttled_retry(
        &self,
        arrived: Instant,
        answered: Instant,
        method: &str,
        path_and_query: &str,
        status: Option<u16>,
        retry_after: Option<Duration>,
    ) -> Option<TrafficFinding> {
        let key = request_key(method, path_and_query);
        let storm = {
            let mut shard = self
                .throttles
                .get(shard_of(key))?
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            shard.observe(key, arrived, answered, status, retry_after)?
        };
        let ThrottleStorm {
            retries,
            status,
            retry_after,
            longest_gap,
        } = storm;
        let detail = match retry_after {
            Some(advertised) => format!(
                "retry storm after 429/503 ignoring Retry-After: {retries} retries in a row, each sent at most {} ms after a {status} answer that set Retry-After: {} s; wait the advertised interval before retrying",
                longest_gap.as_millis(),
                advertised.as_secs()
            ),
            None => format!(
                "immediate retry storm after 429/503 without backoff: {retries} retries in a row, each sent within {} ms of a {status} answer; honour Retry-After or back off exponentially",
                THROTTLE_RETRY_WINDOW.as_millis()
            ),
        };
        Some(TrafficFinding {
            kind: TrafficFindingKind::RetryStorm,
            severity: Severity::Warn,
            detail,
            evidence: Some(request_evidence(method, path_and_query)),
        })
    }

    /// Feeds the upstream latency of a 2xx response into its route template's window;
    /// returns a finding when the response took `LATENCY_FACTOR` times the template's
    /// rolling median and at least `LATENCY_FLOOR`, or, on a template whose median is at
    /// least `LOOPBACK_MEDIAN`, `LOOPBACK_FACTOR` times the median, at least
    /// `LOOPBACK_FLOOR` and more than twice the window's p95. The second rule is what a fast
    /// loopback service needs: an N+1 or a blocking call that turns 3 ms into 40 ms never
    /// reaches 250 ms, and the p95 guard keeps a route whose normal tail is already that slow
    /// quiet.
    pub fn latency(
        &self,
        method: &str,
        path_and_query: &str,
        status: u16,
        upstream_us: u64,
    ) -> Option<TrafficFinding> {
        if !(200..300).contains(&status) {
            return None;
        }
        let path = path_and_query
            .split_once('?')
            .map_or(path_and_query, |(path, _)| path);
        let key = template_key(method, path);
        let regression = {
            let mut shard = self
                .latencies
                .get(shard_of(key))?
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            shard.observe(key, upstream_us)?
        };
        let template = template(path);
        let ms = |us: u64| us as f64 / 1_000.0;
        let Regression {
            median_us,
            p95_us,
            samples,
            loopback,
        } = regression;
        let mut detail = format!(
            "{method} {template} answered in {:.1} ms, {:.1}x its rolling median of {:.1} ms over {samples} responses",
            ms(upstream_us),
            upstream_us as f64 / median_us.max(1) as f64,
            ms(median_us),
        );
        if loopback {
            detail.push_str(&format!(
                " (p95 {:.1} ms); past the loopback threshold of {LOOPBACK_FACTOR}x and {} ms",
                ms(p95_us),
                LOOPBACK_FLOOR.as_millis()
            ));
        }
        Some(TrafficFinding {
            kind: TrafficFindingKind::LatencyRegression,
            severity: Severity::Warn,
            detail,
            evidence: Some(format!("{method} {template}")),
        })
    }

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

// ---- retry storms ---------------------------------------------------------------------

#[derive(Default)]
struct RepeatShard {
    requests: Vec<Repeats>,
}

struct Repeats {
    key: u64,
    /// Arrival instants inside the window; unsorted, exchanges complete out of order.
    hits: VecDeque<Instant>,
    quiet_until: Option<Instant>,
    last_seen: Instant,
}

impl RepeatShard {
    fn observe(&mut self, now: Instant, key: u64) -> Option<(usize, Duration)> {
        let index = match self.requests.iter().position(|r| r.key == key) {
            Some(index) => index,
            None if self.requests.len() < REQUESTS_PER_SHARD => {
                self.requests.push(Repeats {
                    key,
                    hits: VecDeque::with_capacity(RETRY_STORM_THRESHOLD),
                    quiet_until: None,
                    last_seen: now,
                });
                self.requests.len() - 1
            }
            None => {
                // Distinct requests are the common case; the least recently seen slot is
                // reset in place so its buffer is reused instead of reallocated.
                let stale = self
                    .requests
                    .iter()
                    .enumerate()
                    .min_by_key(|(_, r)| r.last_seen)
                    .map(|(index, _)| index)?;
                let slot = self.requests.get_mut(stale)?;
                slot.key = key;
                slot.hits.clear();
                slot.quiet_until = None;
                slot.last_seen = now;
                stale
            }
        };
        self.requests.get_mut(index)?.observe(now)
    }
}

impl Repeats {
    fn observe(&mut self, now: Instant) -> Option<(usize, Duration)> {
        self.last_seen = self.last_seen.max(now);
        let newest = self.last_seen;
        if let Some(floor) = newest.checked_sub(RETRY_STORM_WINDOW) {
            self.hits.retain(|at| *at >= floor);
            if now < floor {
                return None;
            }
        }
        if self.hits.len() == MAX_REPEATS {
            self.hits.pop_front();
        }
        self.hits.push_back(now);
        if let Some(quiet) = self.quiet_until {
            if now <= quiet {
                self.quiet_until = Some(quiet.max(now + RETRY_STORM_WINDOW));
                return None;
            }
            self.quiet_until = None;
        }
        if self.hits.len() < RETRY_STORM_THRESHOLD {
            return None;
        }
        self.quiet_until = Some(newest + RETRY_STORM_WINDOW);
        let first = self.hits.iter().min()?;
        let last = self.hits.iter().max()?;
        Some((self.hits.len(), last.saturating_duration_since(*first)))
    }
}

// ---- retries after 429 / 503 ----------------------------------------------------------

#[derive(Default)]
struct ThrottleShard {
    requests: Vec<Throttle>,
}

struct Throttle {
    key: u64,
    /// When the latest 429 / 503 to this request was answered; `None` after any other answer.
    throttled_at: Option<Instant>,
    /// Status of that answer, for the finding.
    status: u16,
    /// Non-zero `Retry-After` of that answer.
    retry_after: Option<Duration>,
    /// Consecutive retries that arrived too soon after the previous throttled answer.
    retries: usize,
    /// Longest gap among those retries, for the finding.
    longest_gap: Duration,
    reported: bool,
    last_seen: Instant,
}

/// A completed storm as the finding reports it.
struct ThrottleStorm {
    retries: usize,
    status: u16,
    /// The advertised interval the retries broke; `None` when the answer set none.
    retry_after: Option<Duration>,
    longest_gap: Duration,
}

impl ThrottleShard {
    fn observe(
        &mut self,
        key: u64,
        arrived: Instant,
        answered: Instant,
        status: Option<u16>,
        retry_after: Option<Duration>,
    ) -> Option<ThrottleStorm> {
        let throttled = status.filter(|status| matches!(status, 429 | 503));
        // `Retry-After: 0` permits an immediate retry; only the window rule applies then.
        let retry_after = retry_after.filter(|interval| !interval.is_zero());
        let Some(index) = self.requests.iter().position(|r| r.key == key) else {
            // Only a throttled answer opens a slot: an unthrottled request costs one scan.
            let status = throttled?;
            let fresh = Throttle {
                key,
                throttled_at: Some(answered),
                status,
                retry_after,
                retries: 0,
                longest_gap: Duration::ZERO,
                reported: false,
                last_seen: answered,
            };
            if self.requests.len() < REQUESTS_PER_SHARD {
                self.requests.push(fresh);
            } else {
                let stale = self
                    .requests
                    .iter()
                    .enumerate()
                    .min_by_key(|(_, r)| r.last_seen)
                    .map(|(index, _)| index)?;
                *self.requests.get_mut(stale)? = fresh;
            }
            return None;
        };
        self.requests
            .get_mut(index)?
            .observe(arrived, answered, throttled, retry_after)
    }
}

impl Throttle {
    fn observe(
        &mut self,
        arrived: Instant,
        answered: Instant,
        throttled: Option<u16>,
        retry_after: Option<Duration>,
    ) -> Option<ThrottleStorm> {
        self.last_seen = self.last_seen.max(answered);
        let mut storm = None;
        if let Some(previous) = self.throttled_at {
            // Judged against the answer this request retried, not the one it receives.
            let too_soon = |gap: Duration| {
                gap <= THROTTLE_RETRY_WINDOW || self.retry_after.is_some_and(|ra| gap < ra)
            };
            match arrived.checked_duration_since(previous) {
                Some(gap) if too_soon(gap) => {
                    self.retries += 1;
                    self.longest_gap = self.longest_gap.max(gap);
                    if self.retries >= THROTTLE_RETRY_THRESHOLD && !self.reported {
                        self.reported = true;
                        storm = Some(ThrottleStorm {
                            retries: self.retries,
                            status: self.status,
                            retry_after: self.retry_after,
                            longest_gap: self.longest_gap,
                        });
                    }
                }
                Some(_) => self.calm(),
                None => {}
            }
        }
        match throttled {
            Some(status) => {
                self.throttled_at = Some(self.throttled_at.map_or(answered, |t| t.max(answered)));
                self.status = status;
                self.retry_after = retry_after;
            }
            None => {
                self.throttled_at = None;
                self.retry_after = None;
                self.calm();
            }
        }
        storm
    }

    fn calm(&mut self) {
        self.retries = 0;
        self.longest_gap = Duration::ZERO;
        self.reported = false;
    }
}

/// `Retry-After` as delta-seconds (RFC 9110 10.2.3). An HTTP-date is not read: it needs a
/// clock agreement with the server that a loopback audit cannot assume.
pub fn retry_after(headers: &HeaderMap) -> Option<Duration> {
    let value = header(headers, &header::RETRY_AFTER)?;
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let secs = value.parse::<u64>().unwrap_or(MAX_RETRY_AFTER_SECS);
    Some(Duration::from_secs(secs.min(MAX_RETRY_AFTER_SECS)))
}

// ---- latency regressions --------------------------------------------------------------

/// Method plus the path with identifier segments folded, so `/orders/7` and `/orders/8`
/// share one latency history while `GET` and `DELETE` of a route keep separate ones.
fn template_key(method: &str, path: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    hasher.write(method.as_bytes());
    hasher.write_u8(b' ');
    for segment in path.split('/').filter(|s| !s.is_empty()) {
        hasher.write(if is_identifier(segment) {
            b"{id}"
        } else {
            segment.as_bytes()
        });
        hasher.write_u8(b'/');
    }
    hasher.finish()
}

#[derive(Default)]
struct LatencyShard {
    routes: Vec<LatencyWindow>,
    /// Monotonic use counter for least-recently-used eviction.
    tick: u64,
}

/// Fixed ring of the latest upstream latencies of one template; no heap per window.
struct LatencyWindow {
    key: u64,
    samples: [u64; LATENCY_WINDOW],
    len: usize,
    next: usize,
    used: u64,
}

/// A sample judged against its template's window as it stood before the sample.
struct Regression {
    median_us: u64,
    p95_us: u64,
    samples: usize,
    /// Only the loopback rule fired.
    loopback: bool,
}

impl LatencyShard {
    fn observe(&mut self, key: u64, sample_us: u64) -> Option<Regression> {
        self.tick += 1;
        let tick = self.tick;
        let index = match self.routes.iter().position(|w| w.key == key) {
            Some(index) => index,
            None if self.routes.len() < TEMPLATES_PER_SHARD => {
                self.routes.push(LatencyWindow::new(key));
                self.routes.len() - 1
            }
            None => {
                let stale = self
                    .routes
                    .iter()
                    .enumerate()
                    .min_by_key(|(_, w)| w.used)
                    .map(|(index, _)| index)?;
                *self.routes.get_mut(stale)? = LatencyWindow::new(key);
                stale
            }
        };
        let window = self.routes.get_mut(index)?;
        window.used = tick;
        let verdict = window.regression(sample_us);
        window.push(sample_us);
        verdict
    }
}

impl LatencyWindow {
    fn new(key: u64) -> Self {
        Self {
            key,
            samples: [0; LATENCY_WINDOW],
            len: 0,
            next: 0,
            used: 0,
        }
    }

    fn push(&mut self, sample_us: u64) {
        if let Some(slot) = self.samples.get_mut(self.next) {
            *slot = sample_us;
        }
        self.next = (self.next + 1) % LATENCY_WINDOW;
        self.len = (self.len + 1).min(LATENCY_WINDOW);
    }

    fn regression(&self, sample_us: u64) -> Option<Regression> {
        let micros = |d: Duration| u64::try_from(d.as_micros()).unwrap_or(u64::MAX);
        if self.len < LATENCY_MIN_SAMPLES || sample_us < micros(LOOPBACK_FLOOR) {
            return None;
        }
        // One sort on a stack copy serves both statistics; the ring itself stays in order.
        let mut sorted = self.samples;
        let window = sorted.get_mut(..self.len)?;
        window.sort_unstable();
        let median = median(window)?;
        let p95 = nearest_rank(window, 95)?;
        let general =
            sample_us >= micros(LATENCY_FLOOR) && sample_us > median.saturating_mul(LATENCY_FACTOR);
        let loopback = median >= micros(LOOPBACK_MEDIAN)
            && sample_us >= median.saturating_mul(LOOPBACK_FACTOR)
            && sample_us > p95.saturating_mul(2);
        (general || loopback).then_some(Regression {
            median_us: median,
            p95_us: p95,
            samples: self.len,
            loopback: !general,
        })
    }
}

fn median(sorted: &[u64]) -> Option<u64> {
    let mid = sorted.len() / 2;
    if sorted.len() % 2 == 1 {
        sorted.get(mid).copied()
    } else {
        let (low, high) = (*sorted.get(mid.checked_sub(1)?)?, *sorted.get(mid)?);
        Some(low / 2 + high / 2 + (low % 2 + high % 2) / 2)
    }
}

/// Nearest-rank percentile, the definition the burst statistics use.
fn nearest_rank(sorted: &[u64], percentile: usize) -> Option<u64> {
    let rank = (sorted.len() * percentile).div_ceil(100).max(1);
    sorted.get(rank - 1).copied()
}

// ---- content decoding -----------------------------------------------------------------

/// A response body as the audit sees it after `Content-Encoding` is undone.
pub enum Decoded<'a> {
    /// No coding, or only `identity`.
    Identity(&'a [u8]),
    /// Inflated gzip, deflate, brotli or zstd, at most `MAX_DECODED_BYTES`.
    Inflated(Vec<u8>),
    /// A coding this build does not inflate (`compress`, dictionary codings): headers only.
    Unsupported,
    /// Declared gzip, deflate, br or zstd, but the bytes are not a valid stream of it.
    Corrupt(&'static str),
    /// The inflated output passed `MAX_DECODED_BYTES`.
    OverLimit,
}

impl Decoded<'_> {
    pub fn bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Identity(body) => Some(body),
            Self::Inflated(body) => Some(body),
            Self::Unsupported | Self::Corrupt(_) | Self::OverLimit => None,
        }
    }
}

#[derive(Clone, Copy)]
enum Coding {
    Gzip,
    Deflate,
    Brotli,
    Zstd,
}

/// Undoes `Content-Encoding`, last applied coding first. An empty body is never inflated:
/// HEAD responses and 204/304 carry the header without a stream.
pub fn decode<'a>(headers: &HeaderMap, body: &'a [u8]) -> Decoded<'a> {
    let mut codings = Vec::new();
    for value in headers.get_all(header::CONTENT_ENCODING) {
        let Ok(value) = value.to_str() else {
            return Decoded::Unsupported;
        };
        for token in value.split(',').map(str::trim).filter(|t| !t.is_empty()) {
            if token.eq_ignore_ascii_case("identity") {
                continue;
            }
            if token.eq_ignore_ascii_case("gzip") || token.eq_ignore_ascii_case("x-gzip") {
                codings.push(Coding::Gzip);
            } else if token.eq_ignore_ascii_case("deflate") {
                codings.push(Coding::Deflate);
            } else if token.eq_ignore_ascii_case("br") {
                codings.push(Coding::Brotli);
            } else if token.eq_ignore_ascii_case("zstd") {
                codings.push(Coding::Zstd);
            } else {
                return Decoded::Unsupported;
            }
        }
    }
    if codings.is_empty() || body.is_empty() {
        return Decoded::Identity(body);
    }
    let mut current: Vec<u8> = Vec::new();
    for (layer, coding) in codings.iter().rev().enumerate() {
        let input = if layer == 0 { body } else { current.as_slice() };
        match inflate(*coding, input) {
            Ok(output) => current = output,
            Err(failure) => return failure,
        }
    }
    Decoded::Inflated(current)
}

fn inflate(coding: Coding, input: &[u8]) -> Result<Vec<u8>, Decoded<'static>> {
    // `take` stops the inflater one byte past the cap: output beyond it is never produced.
    let limit = u64::try_from(MAX_DECODED_BYTES).unwrap_or(u64::MAX) + 1;
    let mut output = Vec::with_capacity(input.len().saturating_mul(4).min(MAX_DECODED_BYTES));
    let read = match coding {
        Coding::Gzip => MultiGzDecoder::new(input)
            .take(limit)
            .read_to_end(&mut output),
        // RFC 9110 `deflate` is zlib-wrapped; servers that send a raw deflate stream are
        // common enough to accept both. A zlib header is two bytes with CM = 8 whose
        // big-endian value is a multiple of 31.
        Coding::Deflate if is_zlib_header(input) => {
            ZlibDecoder::new(input).take(limit).read_to_end(&mut output)
        }
        Coding::Deflate => DeflateDecoder::new(input)
            .take(limit)
            .read_to_end(&mut output),
        // The decoder reports truncation, trailing bytes and large-window streams as
        // errors, so a stream it accepts is one a browser decodes too. Bytes after the end
        // of the stream surface only on the read after the one that returned 0, which
        // `read_to_end` never makes.
        Coding::Brotli => {
            let mut decoder = Decompressor::new(input, BROTLI_BUFFER_BYTES);
            match decoder.by_ref().take(limit).read_to_end(&mut output) {
                Ok(read) if output.len() <= MAX_DECODED_BYTES => {
                    decoder.read(&mut [0u8; 1]).map(|_| read)
                }
                other => other,
            }
        }
        Coding::Zstd => inflate_zstd(input, limit, &mut output).map(|()| output.len()),
    };
    match read {
        Ok(_) if output.len() > MAX_DECODED_BYTES => Err(Decoded::OverLimit),
        Ok(_) => Ok(output),
        Err(_) => Err(Decoded::Corrupt(match coding {
            Coding::Gzip => "gzip",
            Coding::Deflate => "deflate",
            Coding::Brotli => "br",
            Coding::Zstd => "zstd",
        })),
    }
}

/// Every frame of a zstd stream in order (RFC 8878 3.1: a stream may hold several, and
/// skippable frames between them), into `output` until it holds `limit` bytes. Each frame's
/// window is read from its header and checked first; a declared checksum is verified.
fn inflate_zstd(mut input: &[u8], limit: u64, output: &mut Vec<u8>) -> io::Result<()> {
    let corrupt = || io::Error::from(io::ErrorKind::InvalidData);
    while !input.is_empty() {
        let magic = input
            .get(..4)
            .and_then(|bytes| bytes.try_into().ok())
            .map(u32::from_le_bytes)
            .ok_or_else(corrupt)?;
        if ZSTD_SKIPPABLE.contains(&magic) {
            let size = input
                .get(4..8)
                .and_then(|bytes| bytes.try_into().ok())
                .map(u32::from_le_bytes)
                .ok_or_else(corrupt)?;
            let end = usize::try_from(size)
                .ok()
                .and_then(|size| size.checked_add(8))
                .ok_or_else(corrupt)?;
            input = input.get(end..).ok_or_else(corrupt)?;
            continue;
        }
        if magic != ZSTD_MAGIC || zstd_window(input).is_none_or(|window| window > ZSTD_MAX_WINDOW) {
            return Err(corrupt());
        }
        let budget = limit.saturating_sub(u64::try_from(output.len()).unwrap_or(u64::MAX));
        let mut frame = StreamingDecoder::new(&mut input).map_err(io::Error::other)?;
        (&mut frame).take(budget).read_to_end(output)?;
        if u64::try_from(output.len()).unwrap_or(u64::MAX) >= limit {
            return Ok(());
        }
        let decoder = &frame.decoder;
        let checksum_matches = match (
            decoder.get_checksum_from_data(),
            decoder.get_calculated_checksum(),
        ) {
            (Some(sent), Some(computed)) => sent == computed,
            _ => true,
        };
        if !decoder.is_finished() || !checksum_matches {
            return Err(corrupt());
        }
    }
    Ok(())
}

/// Window size a zstd frame header declares (RFC 8878 3.1.1.1.2): from the window
/// descriptor, or the frame content size for a single-segment frame. `None` for a header
/// cut short.
fn zstd_window(frame: &[u8]) -> Option<u64> {
    let descriptor = *frame.get(4)?;
    if descriptor & 0x20 == 0 {
        let window = *frame.get(5)?;
        let base = 1u64 << (10 + u32::from(window >> 3));
        return Some(base + base / 8 * u64::from(window & 0x07));
    }
    let dictionary_bytes = [0, 1, 2, 4][usize::from(descriptor & 0x03)];
    let size_bytes = [1, 2, 4, 8][usize::from(descriptor >> 6)];
    let start = 5 + dictionary_bytes;
    let field = frame.get(start..start + size_bytes)?;
    let size = field
        .iter()
        .enumerate()
        .fold(0u64, |size, (i, byte)| size | u64::from(*byte) << (8 * i));
    Some(if size_bytes == 2 { size + 256 } else { size })
}

fn is_zlib_header(input: &[u8]) -> bool {
    match input {
        [cmf, flg, ..] => cmf & 0x0F == 8 && (u16::from(*cmf) << 8 | u16::from(*flg)) % 31 == 0,
        _ => false,
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
    /// The body after `decode`; an undecodable body limits the audit to headers.
    pub body: &'a Decoded<'a>,
}

pub fn inspect(view: &ResponseView<'_>) -> Vec<TrafficFinding> {
    let mut findings = Vec::new();
    cors(view.headers, &mut findings);
    let media = header(view.headers, &header::CONTENT_TYPE).map(essence);
    match view.body {
        Decoded::Identity(body) => body_checks(view, media, body, &mut findings),
        Decoded::Inflated(body) => body_checks(view, media, body, &mut findings),
        Decoded::Corrupt(coding) => findings.push(finding(
            TrafficFindingKind::HeaderMisconfiguration,
            Severity::Warn,
            format!(
                "Content-Encoding: {coding} on a body that is not a valid {coding} stream; clients fail to decode it"
            ),
            Some(format!("Content-Encoding: {coding}")),
        )),
        Decoded::OverLimit => {
            if (200..300).contains(&view.status) && media.is_some_and(is_json_media) {
                findings.push(finding(
                    TrafficFindingKind::UnboundedCollection,
                    Severity::Warn,
                    "compressed JSON body inflates past 1 MiB; page or stream payloads that large"
                        .to_owned(),
                    None,
                ));
            }
        }
        Decoded::Unsupported => {}
    }
    cache_control(view, &mut findings);
    findings
}

fn body_checks(
    view: &ResponseView<'_>,
    media: Option<&str>,
    body: &[u8],
    out: &mut Vec<TrafficFinding>,
) {
    if body.is_empty() {
        return;
    }
    let json_media = media.is_some_and(is_json_media);
    let json_body = is_json_document(body);
    content_type(media, json_media, json_body, body, out);
    if (200..300).contains(&view.status) && (json_media || json_body) {
        collection(view.headers, body, out);
        field_leak(view, body, out);
    }
    if media.is_none_or(is_textual) {
        leak(view.status, body, out);
    }
}

/// A stored-model field in a successful JSON response: credential material is a fault, a
/// credential returned outside a route that issues it a warning.
fn field_leak(view: &ResponseView<'_>, body: &[u8], out: &mut Vec<TrafficFinding>) {
    let Some(found) = disclosure::field_leak(body, view.path) else {
        return;
    };
    out.push(finding(
        TrafficFindingKind::PassiveDisclosure,
        if found.credential {
            Severity::Fault
        } else {
            Severity::Warn
        },
        format!(
            "{} in a {} JSON response; project the stored model onto a response DTO",
            disclosure::label(found.disclosure.kind),
            view.status
        ),
        Some(found.disclosure.evidence),
    ));
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

fn collection(headers: &HeaderMap, body: &[u8], out: &mut Vec<TrafficFinding>) {
    if body.len() > LARGE_JSON_BYTES {
        out.push(finding(
            TrafficFindingKind::UnboundedCollection,
            Severity::Warn,
            format!(
                "JSON body of {:.1} MiB; page or stream payloads above 1 MiB",
                body.len() as f64 / (1024.0 * 1024.0)
            ),
            None,
        ));
    }
    if paginated_by_headers(headers) {
        return;
    }
    let Some(found) = skim::collection(body) else {
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

fn leak(status: u16, body: &[u8], out: &mut Vec<TrafficFinding>) {
    let prefix = &body[..body.len().min(DISCLOSURE_SCAN_BYTES)];
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
        if status >= 500 {
            Severity::Fault
        } else {
            Severity::Warn
        },
        format!("{} in a {status} response", disclosure::label(found.kind)),
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
        let decoded = decode(&headers, body);
        inspect(&ResponseView {
            method,
            path,
            credentialed: false,
            status,
            headers: &headers,
            body: &decoded,
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
                body: &Decoded::Identity(b""),
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
    fn sensitive_fields_in_successful_json_responses() {
        let order = br#"{"id":7,"customer":{"email":"operator@lab.local","passwordHash":"$2b$12$ZproxyLabFixtureSalt00NotARealCredentialOnlyAFixture0"}}"#;
        let found = inspect_with("GET", "/api/v1/orders/7", 200, &[JSON], order);
        assert_eq!(
            kinds(&found),
            [(TrafficFindingKind::PassiveDisclosure, Severity::Fault)]
        );
        assert_eq!(
            found[0].detail,
            "Sensitive field in a 200 JSON response; project the stored model onto a response DTO"
        );
        assert_eq!(
            found[0].evidence.as_deref(),
            Some(r#"/customer/passwordHash = "$2b$12$..." (60 chars)"#)
        );
        // An issued credential is expected from the route that issues it, a warning elsewhere;
        // error responses are not judged.
        let issued = br#"{"clientId":"ci","clientSecret":"cs-7d1f2a9b"}"#;
        assert!(inspect_with("POST", "/api/oauth/clients", 201, &[JSON], issued).is_empty());
        assert_eq!(
            kinds(&inspect_with(
                "GET",
                "/api/projects/7",
                200,
                &[JSON],
                issued
            )),
            [(TrafficFindingKind::PassiveDisclosure, Severity::Warn)]
        );
        assert!(inspect_with("GET", "/api/v1/orders/7", 404, &[JSON], order).is_empty());
    }

    fn gzip(bytes: &[u8]) -> Vec<u8> {
        use std::io::Write;
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(bytes).unwrap();
        encoder.finish().unwrap()
    }

    #[test]
    fn encoded_bodies_are_audited_after_inflating() {
        let trace = b"TypeError: Cannot read properties of null (reading 'trim')\n    at normalizeSku (/srv/app/checkout.js:42:17)";
        let found = inspect_with(
            "POST",
            "/checkout",
            500,
            &[("content-type", "text/plain"), ("content-encoding", "gzip")],
            &gzip(trace),
        );
        assert_eq!(
            kinds(&found),
            [(TrafficFindingKind::PassiveDisclosure, Severity::Fault)]
        );

        use std::io::Write;
        let mut zlib = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
        zlib.write_all(b"[1,2,3]").unwrap();
        let zlib = zlib.finish().unwrap();
        let mut raw = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::fast());
        raw.write_all(b"[1,2,3]").unwrap();
        let raw = raw.finish().unwrap();
        for body in [zlib, raw] {
            let headers = headers(&[("content-encoding", "deflate")]);
            assert_eq!(decode(&headers, &body).bytes(), Some(&b"[1,2,3]"[..]));
        }
        // Stacked codings are undone last-applied first.
        let twice = gzip(&gzip(b"{}"));
        let headers = headers(&[("content-encoding", "gzip, x-gzip")]);
        assert_eq!(decode(&headers, &twice).bytes(), Some(&b"{}"[..]));
        let identity = headers_identity();
        assert!(matches!(decode(&identity, b"{}"), Decoded::Identity(b"{}")));
    }

    fn headers_identity() -> HeaderMap {
        headers(&[("content-encoding", "identity")])
    }

    #[test]
    fn undecodable_bodies_limit_the_audit_to_headers() {
        let cors = [
            ("access-control-allow-origin", "*"),
            ("access-control-allow-credentials", "true"),
        ];
        let compress = inspect_with(
            "GET",
            "/api/items",
            200,
            &[cors[0], cors[1], ("content-encoding", "compress")],
            b"\x1f\x9d at x (/a.js:1:2)",
        );
        assert_eq!(
            kinds(&compress),
            [(TrafficFindingKind::HeaderMisconfiguration, Severity::Warn)]
        );
        let corrupt = inspect_with(
            "GET",
            "/api/items",
            200,
            &[("content-encoding", "gzip")],
            b"\x1f\x8b at x (/a.js:1:2)",
        );
        assert_eq!(corrupt.len(), 1);
        assert_eq!(
            corrupt[0].detail,
            "Content-Encoding: gzip on a body that is not a valid gzip stream; clients fail to decode it"
        );
        // HEAD and 204 responses carry the header without a stream.
        assert!(inspect_with("GET", "/x", 204, &[("content-encoding", "gzip")], b"").is_empty());
    }

    #[test]
    fn decompression_bombs_stop_at_the_cap() {
        let bomb = gzip(&vec![b' '; 2 * MAX_DECODED_BYTES]);
        assert!(bomb.len() < 64 * 1024, "{} compressed bytes", bomb.len());
        let headers = headers(&[("content-encoding", "gzip")]);
        assert!(matches!(decode(&headers, &bomb), Decoded::OverLimit));
        let exact = gzip(&vec![b' '; MAX_DECODED_BYTES]);
        assert_eq!(
            decode(&headers, &exact).bytes().map(<[u8]>::len),
            Some(MAX_DECODED_BYTES)
        );
        let found = inspect_with(
            "GET",
            "/export",
            200,
            &[JSON, ("content-encoding", "gzip")],
            &bomb,
        );
        assert_eq!(
            kinds(&found),
            [(TrafficFindingKind::UnboundedCollection, Severity::Warn)]
        );
    }

    fn br(bytes: &[u8]) -> Vec<u8> {
        use std::io::Write;
        let mut writer = brotli::CompressorWriter::new(Vec::new(), 4096, 5, 22);
        writer.write_all(bytes).unwrap();
        writer.into_inner()
    }

    #[test]
    fn brotli_bodies_are_inflated_under_the_same_cap() {
        let trace = b"TypeError: Cannot read properties of null (reading 'trim')\n    at normalizeSku (/srv/app/checkout.js:42:17)";
        let found = inspect_with(
            "POST",
            "/checkout",
            500,
            &[("content-type", "text/plain"), ("content-encoding", "br")],
            &br(trace),
        );
        assert_eq!(
            kinds(&found),
            [(TrafficFindingKind::PassiveDisclosure, Severity::Fault)]
        );
        // `br, gzip`: brotli applied first, so gzip is undone first.
        let stacked = gzip(&br(b"{\"items\":[]}"));
        let headers = headers(&[("content-encoding", "BR, gzip")]);
        assert_eq!(
            decode(&headers, &stacked).bytes(),
            Some(&b"{\"items\":[]}"[..])
        );

        let br_only = headers_br();
        let bomb = br(&vec![b' '; 2 * MAX_DECODED_BYTES]);
        assert!(bomb.len() < 64 * 1024, "{} compressed bytes", bomb.len());
        assert!(matches!(decode(&br_only, &bomb), Decoded::OverLimit));
        let exact = br(&vec![b' '; MAX_DECODED_BYTES]);
        assert_eq!(
            decode(&br_only, &exact).bytes().map(<[u8]>::len),
            Some(MAX_DECODED_BYTES)
        );

        // A stream cut short, or followed by stray bytes, is not something a client decodes.
        let whole = br(trace);
        let truncated = &whole[..whole.len() / 2];
        let mut trailing = whole.clone();
        trailing.extend_from_slice(b"tail");
        for body in [truncated, trailing.as_slice()] {
            let found = inspect_with(
                "GET",
                "/api/items",
                200,
                &[("content-encoding", "br")],
                body,
            );
            assert_eq!(found.len(), 1, "{found:?}");
            assert_eq!(
                found[0].detail,
                "Content-Encoding: br on a body that is not a valid br stream; clients fail to decode it"
            );
        }
    }

    fn headers_br() -> HeaderMap {
        headers(&[("content-encoding", "br")])
    }

    fn zstd(bytes: &[u8]) -> Vec<u8> {
        ruzstd::encoding::compress_to_vec(bytes, ruzstd::encoding::CompressionLevel::Fastest)
    }

    #[test]
    fn zstd_bodies_are_inflated_under_the_same_cap() {
        let trace = b"TypeError: Cannot read properties of null (reading 'trim')\n    at normalizeSku (/srv/app/checkout.js:42:17)";
        let found = inspect_with(
            "POST",
            "/checkout",
            500,
            &[("content-type", "text/plain"), ("content-encoding", "zstd")],
            &zstd(trace),
        );
        assert_eq!(
            kinds(&found),
            [(TrafficFindingKind::PassiveDisclosure, Severity::Fault)]
        );
        // `zstd, gzip`: zstd applied first, so gzip is undone first.
        let stacked = gzip(&zstd(b"{\"items\":[]}"));
        let layered = headers(&[("content-encoding", "ZSTD, gzip")]);
        assert_eq!(
            decode(&layered, &stacked).bytes(),
            Some(&b"{\"items\":[]}"[..])
        );

        // Two frames with a skippable frame between them are one stream.
        let zstd_only = headers(&[("content-encoding", "zstd")]);
        let mut frames = zstd(b"[1,");
        frames.extend_from_slice(&[0x50, 0x2A, 0x4D, 0x18, 3, 0, 0, 0, b'x', b'y', b'z']);
        frames.extend(zstd(b"2]"));
        assert_eq!(decode(&zstd_only, &frames).bytes(), Some(&b"[1,2]"[..]));

        let bomb = zstd(&vec![b' '; 2 * MAX_DECODED_BYTES]);
        assert!(bomb.len() < 64 * 1024, "{} compressed bytes", bomb.len());
        assert!(matches!(decode(&zstd_only, &bomb), Decoded::OverLimit));
        let exact = zstd(&vec![b' '; MAX_DECODED_BYTES]);
        assert_eq!(
            decode(&zstd_only, &exact).bytes().map(<[u8]>::len),
            Some(MAX_DECODED_BYTES)
        );

        // Cut short, followed by stray bytes, a wrong checksum, or a header asking for a
        // 1 GiB window (exponent 20, past RFC 9659's 8 MiB): none is a stream a client takes.
        let whole = zstd(trace);
        let truncated = whole[..whole.len() / 2].to_vec();
        let mut trailing = whole.clone();
        trailing.extend_from_slice(b"tail");
        let mut checksum = whole.clone();
        if let Some(last) = checksum.last_mut() {
            *last ^= 0xFF;
        }
        let wide = vec![0x28, 0xB5, 0x2F, 0xFD, 0x00, 0xA0, 0x01, 0x00, 0x00];
        assert_eq!(zstd_window(&wide), Some(1 << 30));
        for body in [truncated, trailing, checksum, wide] {
            let found = inspect_with(
                "GET",
                "/api/items",
                200,
                &[("content-encoding", "zstd")],
                &body,
            );
            assert_eq!(found.len(), 1, "{found:?}");
            assert_eq!(
                found[0].detail,
                "Content-Encoding: zstd on a body that is not a valid zstd stream; clients fail to decode it"
            );
        }
        // Single-segment headers declare their window through the content size.
        assert_eq!(zstd_window(&[0x28, 0xB5, 0x2F, 0xFD, 0x20, 0x09]), Some(9));
        assert_eq!(
            zstd_window(&[0x28, 0xB5, 0x2F, 0xFD, 0x60, 0x00, 0x01]),
            Some(256 + 256)
        );
        assert_eq!(zstd_window(&[0x28, 0xB5, 0x2F, 0xFD, 0xA0]), None);
    }

    #[test]
    fn retries_inside_retry_after_break_the_advertised_interval() {
        let linter = TrafficLinter::default();
        let base = Instant::now();
        let retry_after = Some(Duration::from_secs(2));
        // A client with a fixed 500 ms pause: past the 100 ms window, inside Retry-After.
        let paced = |linter: &TrafficLinter, start: u64, pause: u64| {
            (0..6u64)
                .filter_map(|n| {
                    let arrived = at(base, start + n * (pause + 5));
                    linter
                        .throttled_retry(
                            arrived,
                            arrived + Duration::from_millis(5),
                            "POST",
                            "/api/v1/quotes",
                            Some(429),
                            retry_after,
                        )
                        .map(|f| (n, f))
                })
                .collect::<Vec<_>>()
        };
        let found = paced(&linter, 0, 500);
        assert_eq!(found.len(), 1, "one finding per storm");
        let (n, finding) = &found[0];
        assert_eq!(*n, THROTTLE_RETRY_THRESHOLD as u64);
        assert_eq!(
            finding.detail,
            "retry storm after 429/503 ignoring Retry-After: 4 retries in a row, each sent at most 500 ms after a 429 answer that set Retry-After: 2 s; wait the advertised interval before retrying"
        );
        // Waiting out the advertised interval is compliant, however many retries it takes.
        assert!(paced(&TrafficLinter::default(), 0, 2_000).is_empty());
        // `Retry-After: 0` allows an immediate retry; the 500 ms pause is then a backoff.
        let zero = TrafficLinter::default();
        let quiet = (0..6u64).all(|n| {
            let arrived = at(base, n * 505);
            zero.throttled_retry(
                arrived,
                arrived + Duration::from_millis(5),
                "POST",
                "/api/v1/quotes",
                Some(429),
                Some(Duration::ZERO),
            )
            .is_none()
        });
        assert!(quiet);

        assert_eq!(
            retry_after_of(&[("retry-after", "120")]),
            Some(Duration::from_secs(120))
        );
        assert_eq!(
            retry_after_of(&[("retry-after", "99999999999")]),
            Some(Duration::from_secs(MAX_RETRY_AFTER_SECS))
        );
        assert_eq!(
            retry_after_of(&[("retry-after", "Wed, 21 Oct 2026 07:28:00 GMT")]),
            None
        );
        assert_eq!(retry_after_of(&[("retry-after", "-1")]), None);
        assert_eq!(retry_after_of(&[]), None);
    }

    fn retry_after_of(pairs: &[(&'static str, &'static str)]) -> Option<Duration> {
        retry_after(&headers(pairs))
    }

    #[test]
    fn loopback_regressions_below_the_general_floor() {
        let us = |n: u64| n * 100;
        // A query-backed route: 2.8 to 3.4 ms.
        let linter = TrafficLinter::default();
        for n in 0..15u64 {
            assert!(linter
                .latency("GET", &format!("/api/orders/{n}"), 200, us(28 + n % 7))
                .is_none());
        }
        let found = linter
            .latency("GET", "/api/orders/78", 200, us(420))
            .expect("loopback regression");
        assert_eq!(found.kind, TrafficFindingKind::LatencyRegression);
        assert_eq!(
            found.detail,
            "GET /api/orders/{id} answered in 42.0 ms, 13.5x its rolling median of 3.1 ms over 15 responses (p95 3.4 ms); past the loopback threshold of 8x and 35 ms"
        );
        // 30 ms is 9x the median but inside two ticks of the Windows timer.
        assert!(linter
            .latency("GET", "/api/orders/77", 200, us(300))
            .is_none());

        // An in-memory route whose median is jitter is held to the general rule.
        let trivial = TrafficLinter::default();
        for _ in 0..16 {
            assert!(trivial.latency("GET", "/api/health", 200, us(4)).is_none());
        }
        assert!(trivial
            .latency("GET", "/api/health", 200, us(400))
            .is_none());
        // A route whose normal tail already reaches 40 ms is not reported at 45 ms.
        let bimodal = TrafficLinter::default();
        for n in 0..16u64 {
            let sample = if n % 4 == 0 { us(400) } else { us(30) };
            assert!(bimodal.latency("GET", "/api/search", 200, sample).is_none());
        }
        assert!(bimodal
            .latency("GET", "/api/search", 200, us(450))
            .is_none());
    }

    #[test]
    fn retries_that_ignore_a_throttled_answer() {
        let linter = TrafficLinter::default();
        let base = Instant::now();
        // Answered 5 ms after arrival, retried 25 ms after the answer, six times.
        let quick = |linter: &TrafficLinter, start: u64, path: &str, status: u16| {
            (0..6u64)
                .filter_map(|n| {
                    let arrived = at(base, start + n * 30);
                    linter
                        .throttled_retry(
                            arrived,
                            arrived + Duration::from_millis(5),
                            "POST",
                            path,
                            Some(status),
                            None,
                        )
                        .map(|f| (n, f))
                })
                .collect::<Vec<_>>()
        };
        let found = quick(&linter, 0, "/api/v1/orders", 429);
        assert_eq!(found.len(), 1, "one finding per storm");
        let (n, finding) = &found[0];
        assert_eq!(
            *n, THROTTLE_RETRY_THRESHOLD as u64,
            "the original plus four retries"
        );
        assert_eq!(finding.kind, TrafficFindingKind::RetryStorm);
        assert_eq!(finding.severity, Severity::Warn);
        assert_eq!(finding.evidence.as_deref(), Some("POST /api/v1/orders"));
        assert_eq!(
            finding.detail,
            "immediate retry storm after 429/503 without backoff: 4 retries in a row, each sent within 100 ms of a 429 answer; honour Retry-After or back off exponentially"
        );
        assert_eq!(quick(&linter, 1_000, "/api/v1/quote", 503).len(), 1);
        // Other statuses never start tracking.
        assert!(quick(&linter, 2_000, "/api/v1/stock", 500).is_empty());

        // Exponential backoff: every retry waits longer than the window.
        let mut arrived = at(base, 5_000);
        for pause in [120u64, 240, 480, 960, 1_920] {
            let answered = arrived + Duration::from_millis(5);
            assert!(linter
                .throttled_retry(arrived, answered, "GET", "/api/v1/cart", Some(429), None)
                .is_none());
            arrived = answered + Duration::from_millis(pause);
        }

        // A success ends the storm: three quick retries (the third answered 200), then a
        // fresh 503 and three more quick retries; neither run reaches four.
        let slow = TrafficLinter::default();
        let statuses = [429u16, 429, 429, 200, 503, 503, 503, 503];
        let found: Vec<TrafficFinding> = statuses
            .iter()
            .enumerate()
            .filter_map(|(n, status)| {
                let arrived = at(base, n as u64 * 20);
                slow.throttled_retry(
                    arrived,
                    arrived + Duration::from_millis(2),
                    "PUT",
                    "/api/v1/profile",
                    Some(*status),
                    None,
                )
            })
            .collect();
        assert!(found.is_empty(), "{found:?}");

        // Requests that arrived before the throttled answer went out ran concurrently.
        let burst = TrafficLinter::default();
        let concurrent = (0..8u64)
            .filter_map(|n| {
                burst.throttled_retry(
                    base,
                    at(base, 50 + n),
                    "POST",
                    "/api/v1/redeem",
                    Some(429),
                    None,
                )
            })
            .count();
        assert_eq!(concurrent, 0);
    }

    #[test]
    fn retry_storms_are_reported_once_per_storm() {
        let linter = TrafficLinter::default();
        let base = Instant::now();
        let reported: Vec<(u64, TrafficFinding)> = (1..=14u64)
            .filter_map(|n| {
                linter
                    .repeat(at(base, n * 15), "GET", "/api/v1/cart?user=7")
                    .map(|f| (n, f))
            })
            .collect();
        assert_eq!(reported.len(), 1, "one finding per storm");
        let (n, finding) = &reported[0];
        assert_eq!(*n, RETRY_STORM_THRESHOLD as u64);
        assert_eq!(finding.kind, TrafficFindingKind::RetryStorm);
        assert_eq!(finding.evidence.as_deref(), Some("GET /api/v1/cart?user=7"));
        assert_eq!(
            finding.detail,
            "10 identical GET requests within 135 ms; an effect re-running on every render or a retry loop without backoff"
        );

        // Another query string or method is another request; a slow repeat is no storm.
        assert!((0..9u64).all(|n| linter
            .repeat(at(base, 2_000 + n), "GET", "/api/v1/cart?user=8")
            .is_none()));
        assert!((0..20u64).all(|n| linter
            .repeat(at(base, 3_000 + n * 30), "POST", "/api/v1/cart")
            .is_none()));
        // After a quiet window the same request storms again.
        let again = (0..10u64)
            .filter_map(|n| linter.repeat(at(base, 9_000 + n), "GET", "/api/v1/cart?user=7"))
            .count();
        assert_eq!(again, 1);
    }

    #[test]
    fn latency_regressions_against_the_rolling_median() {
        let linter = TrafficLinter::default();
        let ms = |n: u64| n * 1_000;
        for id in 1..=LATENCY_MIN_SAMPLES as u64 {
            assert!(linter
                .latency("GET", &format!("/api/orders/{id}"), 200, ms(20 + id))
                .is_none());
        }
        let found = linter
            .latency("GET", "/api/orders/99?expand=1", 200, ms(400))
            .expect("regression");
        assert_eq!(found.kind, TrafficFindingKind::LatencyRegression);
        assert_eq!(found.evidence.as_deref(), Some("GET /api/orders/{id}"));
        assert_eq!(
            found.detail,
            "GET /api/orders/{id} answered in 400.0 ms, 16.3x its rolling median of 24.5 ms over 8 responses"
        );
        // Below the floor, below the factor, a failure, another method: none is a regression.
        assert!(linter
            .latency("GET", "/api/orders/5", 200, ms(200))
            .is_none());
        assert!(linter
            .latency("GET", "/api/orders/5", 200, ms(26))
            .is_none());
        assert!(linter
            .latency("GET", "/api/orders/5", 503, ms(2_000))
            .is_none());
        assert!(linter
            .latency("DELETE", "/api/orders/5", 204, ms(2_000))
            .is_none());
        // A template with too little history is not judged.
        let fresh = TrafficLinter::default();
        for _ in 0..LATENCY_MIN_SAMPLES - 1 {
            assert!(fresh.latency("GET", "/health", 200, ms(1)).is_none());
        }
        assert!(fresh.latency("GET", "/health", 200, ms(900)).is_none());
        assert!(fresh.latency("GET", "/health", 200, ms(900)).is_some());
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
