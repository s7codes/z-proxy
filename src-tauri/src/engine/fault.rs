//! Fault decision model.
//!
//! Pure and synchronous so the proxy can take a decision under a short lock and tests can
//! replay exact sequences from a seeded RNG. A request is matched against the route rules in
//! order; the first match supplies the profile, otherwise the global profile applies.

use std::time::Duration;

use axum::http::StatusCode;
use fastrand::Rng;
use regex::Regex;
use serde::{Deserialize, Serialize};

use super::error::{EngineError, EngineResult};
use super::types::RouteMethod;

pub const MAX_LATENCY_MS: u32 = 30_000;
pub const MAX_JITTER_MS: u32 = 10_000;
/// The proxy buffers at most 16 MiB of a response; a cut point beyond that never applies.
pub const MAX_PARTIAL_DROP_BYTES: u32 = 16 * 1024 * 1024;
const MAX_RATE: u8 = 100;
pub const MAX_RULES: usize = 64;
const MAX_PATTERN_LEN: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum StatusMutation {
    #[default]
    #[serde(rename = "none")]
    None,
    #[serde(rename = "429")]
    TooManyRequests,
    #[serde(rename = "500")]
    InternalServerError,
    #[serde(rename = "502")]
    BadGateway,
    #[serde(rename = "503")]
    ServiceUnavailable,
    #[serde(rename = "504")]
    GatewayTimeout,
}

impl StatusMutation {
    pub fn status(self) -> Option<StatusCode> {
        match self {
            Self::None => None,
            Self::TooManyRequests => Some(StatusCode::TOO_MANY_REQUESTS),
            Self::InternalServerError => Some(StatusCode::INTERNAL_SERVER_ERROR),
            Self::BadGateway => Some(StatusCode::BAD_GATEWAY),
            Self::ServiceUnavailable => Some(StatusCode::SERVICE_UNAVAILABLE),
            Self::GatewayTimeout => Some(StatusCode::GATEWAY_TIMEOUT),
        }
    }
}

/// Rates are integer percentages; the UI exposes 1% steps and finer granularity has no
/// practical meaning at loopback request volumes.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FaultProfile {
    pub latency_ms: u32,
    pub jitter_ms: u32,
    pub drop_rate: u8,
    pub status_mutation: StatusMutation,
    pub mutation_rate: u8,
    /// Share of forwarded responses cut mid-body: the head and leading bytes reach the
    /// client, then the connection is reset. `None` is 0.
    pub partial_drop_rate: Option<u8>,
    /// Body bytes written before the reset; `None` cuts at half the body. Always at least one
    /// byte short of a non-empty body.
    pub partial_drop_bytes: Option<u32>,
}

impl FaultProfile {
    pub fn validate(&self) -> EngineResult<()> {
        if self.latency_ms > MAX_LATENCY_MS {
            return Err(invalid("latencyMs", format!("must be <= {MAX_LATENCY_MS}")));
        }
        if self.jitter_ms > MAX_JITTER_MS {
            return Err(invalid("jitterMs", format!("must be <= {MAX_JITTER_MS}")));
        }
        if self.drop_rate > MAX_RATE {
            return Err(invalid("dropRate", format!("must be <= {MAX_RATE}")));
        }
        if self.mutation_rate > MAX_RATE {
            return Err(invalid("mutationRate", format!("must be <= {MAX_RATE}")));
        }
        if self.partial_drop_rate.is_some_and(|rate| rate > MAX_RATE) {
            return Err(invalid("partialDropRate", format!("must be <= {MAX_RATE}")));
        }
        if self
            .partial_drop_bytes
            .is_some_and(|bytes| bytes > MAX_PARTIAL_DROP_BYTES)
        {
            return Err(invalid(
                "partialDropBytes",
                format!("must be <= {MAX_PARTIAL_DROP_BYTES}"),
            ));
        }
        Ok(())
    }
}

/// Binds a profile to one route. Matched against the path the upstream receives (upstream
/// base path included), which is the path the route scanner reports.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FaultRule {
    /// `None` or `ANY` matches every method.
    pub method: Option<RouteMethod>,
    /// Route template in scanner syntax: literal segments, `{name}` for one segment (also
    /// embedded, as in `{id}.json`), `{*name}` for the remainder as the last segment.
    pub path_pattern: String,
    pub profile: FaultProfile,
}

/// Anchored regex compiled from a route template. Request paths are compared after
/// collapsing empty segments, so `/orders/7/` and `//orders/7` match `/orders/{id}`.
#[derive(Debug, Clone)]
pub struct PathMatcher {
    regex: Regex,
}

impl PathMatcher {
    pub fn compile(pattern: &str) -> Result<Self, String> {
        if !pattern.starts_with('/') {
            return Err("must start with `/`".to_owned());
        }
        if pattern.len() > MAX_PATTERN_LEN {
            return Err(format!("exceeds {MAX_PATTERN_LEN} bytes"));
        }
        let segments: Vec<&str> = pattern.split('/').filter(|s| !s.is_empty()).collect();
        let mut source = String::from("^");
        for (index, segment) in segments.iter().enumerate() {
            if let Some(name) = segment.strip_prefix("{*").and_then(|s| s.strip_suffix('}')) {
                if name.is_empty() || index + 1 != segments.len() {
                    return Err(format!(
                        "catch-all `{segment}` must be a named, final segment"
                    ));
                }
                source.push_str("(?:/.*)?");
                continue;
            }
            source.push('/');
            let mut rest = *segment;
            while let Some(open) = rest.find('{') {
                let close = rest[open..]
                    .find('}')
                    .map(|offset| open + offset)
                    .ok_or_else(|| format!("unclosed `{{` in `{segment}`"))?;
                let name = &rest[open + 1..close];
                if name.is_empty() || name.contains(['*', '{']) {
                    return Err(format!("invalid parameter `{{{name}}}` in `{segment}`"));
                }
                source.push_str(&regex::escape(&rest[..open]));
                source.push_str("[^/]+");
                rest = &rest[close + 1..];
            }
            if rest.contains('}') {
                return Err(format!("unmatched `}}` in `{segment}`"));
            }
            source.push_str(&regex::escape(rest));
        }
        if segments.is_empty() {
            source.push('/');
        }
        source.push('$');
        Regex::new(&source)
            .map(|regex| Self { regex })
            .map_err(|err| err.to_string())
    }

    pub fn matches(&self, path: &str) -> bool {
        self.matches_collapsed(&collapse_path(path))
    }

    /// Match against a path already passed through `collapse_path`, so a caller testing one
    /// request against many templates normalizes it once.
    pub fn matches_collapsed(&self, collapsed: &str) -> bool {
        self.regex.is_match(collapsed)
    }
}

/// `/a//b/` as `/a/b`: the form `PathMatcher` regexes are anchored on.
pub fn collapse_path(path: &str) -> String {
    let mut out = String::with_capacity(path.len() + 1);
    for segment in path.split('/').filter(|s| !s.is_empty()) {
        out.push('/');
        out.push_str(segment);
    }
    if out.is_empty() {
        out.push('/');
    }
    out
}

#[derive(Debug, Clone)]
pub struct CompiledRule {
    pub rule: FaultRule,
    matcher: PathMatcher,
}

impl CompiledRule {
    pub fn matches(&self, method: &str, path: &str) -> bool {
        let method_ok = match self.rule.method {
            None | Some(RouteMethod::Any) => true,
            Some(expected) => method_token(expected) == method,
        };
        method_ok && self.matcher.matches(path)
    }

    /// `POST /orders/{id}`, the form telemetry reports a match with.
    pub fn label(&self) -> String {
        let method = self.rule.method.map_or("ANY", method_token);
        format!("{method} {}", self.rule.path_pattern)
    }
}

pub fn method_token(method: RouteMethod) -> &'static str {
    match method {
        RouteMethod::Get => "GET",
        RouteMethod::Post => "POST",
        RouteMethod::Put => "PUT",
        RouteMethod::Patch => "PATCH",
        RouteMethod::Delete => "DELETE",
        RouteMethod::Head => "HEAD",
        RouteMethod::Options => "OPTIONS",
        RouteMethod::Any => "ANY",
    }
}

/// Validates and compiles a rule set; the whole set is rejected on the first invalid rule so
/// a partially applied list never reaches traffic.
pub fn compile_rules(rules: Vec<FaultRule>) -> EngineResult<Vec<CompiledRule>> {
    if rules.len() > MAX_RULES {
        return Err(EngineError::InvalidFaultRule {
            index: MAX_RULES,
            reason: format!("at most {MAX_RULES} rules"),
        });
    }
    rules
        .into_iter()
        .enumerate()
        .map(|(index, rule)| {
            let rejected = |reason: String| EngineError::InvalidFaultRule { index, reason };
            rule.profile
                .validate()
                .map_err(|err| rejected(err.to_string()))?;
            let matcher = PathMatcher::compile(&rule.path_pattern)
                .map_err(|reason| rejected(format!("pathPattern {reason}")))?;
            Ok(CompiledRule { rule, matcher })
        })
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct FaultState {
    pub armed: bool,
    pub profile: FaultProfile,
    pub rules: Vec<CompiledRule>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultAction {
    Forward,
    Mutate(StatusCode),
    Drop,
    /// Forward, then cut the response body after `after` bytes (`None`: half the body).
    PartialDrop {
        after: Option<u32>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FaultPlan {
    pub delay: Duration,
    pub action: FaultAction,
    /// Index of the route rule that supplied the profile; `None` for the global profile.
    pub rule: Option<usize>,
}

impl FaultPlan {
    pub const PASSTHROUGH: Self = Self {
        delay: Duration::ZERO,
        action: FaultAction::Forward,
        rule: None,
    };
}

/// Latency applies to every outcome, including drops: a connection that hangs and then
/// resets is the failure shape clients most often mishandle. Rules only apply while armed:
/// the arm switch is the single control that stops all injection.
///
/// Precedence is drop, status mutation, partial drop. A rate of 0 draws nothing from the
/// RNG, so a seeded sequence without partial drops is unchanged by their existence.
pub fn plan(state: &FaultState, method: &str, path: &str, rng: &mut Rng) -> FaultPlan {
    if !state.armed {
        return FaultPlan::PASSTHROUGH;
    }
    let rule = state
        .rules
        .iter()
        .position(|rule| rule.matches(method, path));
    let profile = rule
        .and_then(|index| state.rules.get(index))
        .map_or(&state.profile, |matched| &matched.rule.profile);
    let delay = Duration::from_millis(jittered_ms(profile.latency_ms, profile.jitter_ms, rng));

    let action = if roll(profile.drop_rate, rng) {
        FaultAction::Drop
    } else if let Some(status) = profile
        .status_mutation
        .status()
        .filter(|_| roll(profile.mutation_rate, rng))
    {
        FaultAction::Mutate(status)
    } else if roll(profile.partial_drop_rate.unwrap_or(0), rng) {
        FaultAction::PartialDrop {
            after: profile.partial_drop_bytes,
        }
    } else {
        FaultAction::Forward
    };

    FaultPlan {
        delay,
        action,
        rule,
    }
}

fn jittered_ms(base: u32, jitter: u32, rng: &mut Rng) -> u64 {
    if jitter == 0 {
        return u64::from(base);
    }
    let spread = i64::from(jitter);
    let value = i64::from(base) + rng.i64(-spread..=spread);
    u64::try_from(value).unwrap_or(0)
}

fn roll(rate: u8, rng: &mut Rng) -> bool {
    rate > 0 && rng.u8(0..MAX_RATE) < rate
}

fn invalid(field: &'static str, reason: String) -> EngineError {
    EngineError::InvalidFaultProfile { field, reason }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn armed(profile: FaultProfile) -> FaultState {
        FaultState {
            armed: true,
            profile,
            rules: Vec::new(),
        }
    }

    /// Global-profile decision for tests that do not exercise route rules.
    fn plan(state: &FaultState, rng: &mut Rng) -> FaultPlan {
        super::plan(state, "GET", "/", rng)
    }

    fn rule(method: Option<RouteMethod>, pattern: &str, profile: FaultProfile) -> FaultRule {
        FaultRule {
            method,
            path_pattern: pattern.to_owned(),
            profile,
        }
    }

    fn mutating(status: StatusMutation) -> FaultProfile {
        FaultProfile {
            status_mutation: status,
            mutation_rate: 100,
            ..FaultProfile::default()
        }
    }

    #[test]
    fn path_templates_match_segments_and_catch_alls() {
        let cases: [(&str, &[&str], &[&str]); 6] = [
            (
                "/orders/{id}",
                &["/orders/7", "/orders/7/", "//orders//abc"],
                &["/orders", "/orders/7/items", "/Orders/7"],
            ),
            (
                "/reports/{id}.json",
                &["/reports/q3.json"],
                &["/reports/q3.xml", "/reports/.json"],
            ),
            (
                "/files/{*rest}",
                &["/files", "/files/a", "/files/a/b/c.txt"],
                &["/filesystem", "/"],
            ),
            ("/", &["/", ""], &["/a"]),
            ("/{*all}", &["/", "/a/b"], &[]),
            (
                "/api/v1/coupons/redeem",
                &["/api/v1/coupons/redeem"],
                &["/api/v1/coupons/redeem/x", "/api/v1/coupons"],
            ),
        ];
        for (pattern, hits, misses) in cases {
            let matcher = PathMatcher::compile(pattern).unwrap();
            for path in hits {
                assert!(matcher.matches(path), "{pattern} should match {path}");
            }
            for path in misses {
                assert!(!matcher.matches(path), "{pattern} should not match {path}");
            }
        }
        assert!(PathMatcher::compile("/a.b/(x)+")
            .unwrap()
            .matches("/a.b/(x)+"));
        assert!(!PathMatcher::compile("/a.b").unwrap().matches("/aXb"));
    }

    #[test]
    fn invalid_templates_are_rejected() {
        for pattern in [
            "orders",
            "/files/{*rest}/tail",
            "/files/{*}",
            "/a/{id",
            "/a/id}",
            "/a/{}",
            "/a/x{*rest}",
        ] {
            assert!(PathMatcher::compile(pattern).is_err(), "{pattern}");
        }
        assert!(PathMatcher::compile(&format!("/{}", "a".repeat(MAX_PATTERN_LEN))).is_err());
    }

    #[test]
    fn first_matching_rule_supplies_the_profile() {
        let rules = compile_rules(vec![
            rule(
                Some(RouteMethod::Post),
                "/orders/{id}",
                mutating(StatusMutation::ServiceUnavailable),
            ),
            rule(
                None,
                "/orders/{*rest}",
                mutating(StatusMutation::BadGateway),
            ),
            rule(
                Some(RouteMethod::Any),
                "/health",
                mutating(StatusMutation::TooManyRequests),
            ),
        ])
        .unwrap();
        let state = FaultState {
            armed: true,
            profile: mutating(StatusMutation::InternalServerError),
            rules,
        };
        let mut rng = Rng::with_seed(9);
        let decide = |method: &str, path: &str, rng: &mut Rng| {
            let plan = super::plan(&state, method, path, rng);
            (plan.rule, plan.action)
        };
        let status = |code: StatusCode| FaultAction::Mutate(code);
        assert_eq!(
            decide("POST", "/orders/7", &mut rng),
            (Some(0), status(StatusCode::SERVICE_UNAVAILABLE))
        );
        assert_eq!(
            decide("GET", "/orders/7", &mut rng),
            (Some(1), status(StatusCode::BAD_GATEWAY))
        );
        assert_eq!(
            decide("DELETE", "/health", &mut rng),
            (Some(2), status(StatusCode::TOO_MANY_REQUESTS))
        );
        assert_eq!(
            decide("GET", "/users", &mut rng),
            (None, status(StatusCode::INTERNAL_SERVER_ERROR))
        );
        assert_eq!(state.rules[1].label(), "ANY /orders/{*rest}");
        assert_eq!(state.rules[0].label(), "POST /orders/{id}");

        let disarmed = FaultState {
            armed: false,
            ..state.clone()
        };
        assert_eq!(
            super::plan(&disarmed, "POST", "/orders/7", &mut rng),
            FaultPlan::PASSTHROUGH
        );
    }

    #[test]
    fn rule_sets_are_validated_as_a_whole() {
        let reject = |rules: Vec<FaultRule>| match compile_rules(rules) {
            Err(EngineError::InvalidFaultRule { index, reason }) => (index, reason),
            other => panic!("expected rejection, got {other:?}"),
        };
        let ok = rule(None, "/a", FaultProfile::default());
        let (index, reason) = reject(vec![ok.clone(), rule(None, "b", FaultProfile::default())]);
        assert_eq!(index, 1);
        assert!(
            reason.starts_with("pathPattern must start with"),
            "{reason}"
        );
        let (index, reason) = reject(vec![rule(
            None,
            "/a",
            FaultProfile {
                drop_rate: 101,
                ..FaultProfile::default()
            },
        )]);
        assert_eq!(index, 0);
        assert!(reason.contains("dropRate"), "{reason}");
        let (index, _) = reject(vec![ok.clone(); MAX_RULES + 1]);
        assert_eq!(index, MAX_RULES);
        assert_eq!(compile_rules(vec![ok; MAX_RULES]).unwrap().len(), MAX_RULES);
        assert!(compile_rules(Vec::new()).unwrap().is_empty());

        let parsed: FaultRule = serde_json::from_str(
            r#"{"method":"POST","pathPattern":"/x/{id}","profile":{"latencyMs":0,"jitterMs":0,"dropRate":0,"statusMutation":"503","mutationRate":100}}"#,
        )
        .unwrap();
        assert_eq!(parsed.method, Some(RouteMethod::Post));
        let any: FaultRule = serde_json::from_str(
            r#"{"method":null,"pathPattern":"/","profile":{"latencyMs":0,"jitterMs":0,"dropRate":0,"statusMutation":"none","mutationRate":0}}"#,
        )
        .unwrap();
        assert_eq!(any.method, None);
    }

    #[test]
    fn disarmed_state_is_passthrough_regardless_of_profile() {
        let state = FaultState {
            armed: false,
            profile: FaultProfile {
                latency_ms: 500,
                jitter_ms: 100,
                drop_rate: 100,
                status_mutation: StatusMutation::BadGateway,
                mutation_rate: 100,
                partial_drop_rate: Some(100),
                partial_drop_bytes: Some(8),
            },
            rules: Vec::new(),
        };
        let mut rng = Rng::with_seed(7);
        for _ in 0..100 {
            assert_eq!(plan(&state, &mut rng), FaultPlan::PASSTHROUGH);
        }
    }

    #[test]
    fn partial_drop_yields_to_resets_and_mutations() {
        let mut rng = Rng::with_seed(13);
        let partial = FaultProfile {
            partial_drop_rate: Some(100),
            partial_drop_bytes: Some(16),
            ..FaultProfile::default()
        };
        assert_eq!(
            plan(&armed(partial.clone()), &mut rng).action,
            FaultAction::PartialDrop { after: Some(16) }
        );
        let halved = FaultProfile {
            partial_drop_bytes: None,
            ..partial.clone()
        };
        assert_eq!(
            plan(&armed(halved), &mut rng).action,
            FaultAction::PartialDrop { after: None }
        );
        let reset = FaultProfile {
            drop_rate: 100,
            ..partial.clone()
        };
        assert_eq!(plan(&armed(reset), &mut rng).action, FaultAction::Drop);
        let mutated = FaultProfile {
            status_mutation: StatusMutation::BadGateway,
            mutation_rate: 100,
            ..partial
        };
        assert_eq!(
            plan(&armed(mutated), &mut rng).action,
            FaultAction::Mutate(StatusCode::BAD_GATEWAY)
        );

        // A zero rate consumes no randomness: the seeded mutation sequence is unchanged.
        let sequence = |profile: FaultProfile| {
            let mut rng = Rng::with_seed(21);
            (0..64)
                .map(|_| plan(&armed(profile.clone()), &mut rng).action)
                .collect::<Vec<_>>()
        };
        let base = FaultProfile {
            status_mutation: StatusMutation::InternalServerError,
            mutation_rate: 40,
            ..FaultProfile::default()
        };
        assert_eq!(
            sequence(base.clone()),
            sequence(FaultProfile {
                partial_drop_rate: Some(0),
                ..base
            })
        );
    }

    #[test]
    fn jitter_stays_within_bounds_and_clamps_at_zero() {
        let mut rng = Rng::with_seed(11);
        let state = armed(FaultProfile {
            latency_ms: 50,
            jitter_ms: 20,
            ..FaultProfile::default()
        });
        for _ in 0..1_000 {
            let ms = plan(&state, &mut rng).delay.as_millis();
            assert!((30..=70).contains(&ms), "{ms}");
        }

        let state = armed(FaultProfile {
            latency_ms: 5,
            jitter_ms: 50,
            ..FaultProfile::default()
        });
        let mut saw_zero = false;
        for _ in 0..1_000 {
            let ms = plan(&state, &mut rng).delay.as_millis();
            assert!(ms <= 55, "{ms}");
            saw_zero |= ms == 0;
        }
        assert!(saw_zero, "negative jitter should clamp to zero");
    }

    #[test]
    fn full_rates_are_deterministic_and_drop_wins() {
        let mut rng = Rng::with_seed(3);
        let both = armed(FaultProfile {
            drop_rate: 100,
            status_mutation: StatusMutation::ServiceUnavailable,
            mutation_rate: 100,
            ..FaultProfile::default()
        });
        assert_eq!(plan(&both, &mut rng).action, FaultAction::Drop);

        let mutate = armed(FaultProfile {
            status_mutation: StatusMutation::TooManyRequests,
            mutation_rate: 100,
            ..FaultProfile::default()
        });
        assert_eq!(
            plan(&mutate, &mut rng).action,
            FaultAction::Mutate(StatusCode::TOO_MANY_REQUESTS)
        );
    }

    #[test]
    fn mutation_rate_without_status_is_inert() {
        let mut rng = Rng::with_seed(5);
        let state = armed(FaultProfile {
            mutation_rate: 100,
            ..FaultProfile::default()
        });
        assert_eq!(plan(&state, &mut rng).action, FaultAction::Forward);
    }

    #[test]
    fn partial_rate_tracks_probability() {
        let mut rng = Rng::with_seed(42);
        let state = armed(FaultProfile {
            status_mutation: StatusMutation::InternalServerError,
            mutation_rate: 25,
            ..FaultProfile::default()
        });
        let hits = (0..10_000)
            .filter(|_| plan(&state, &mut rng).action != FaultAction::Forward)
            .count();
        assert!((2_200..=2_800).contains(&hits), "{hits}");
    }

    #[test]
    fn validation_rejects_out_of_range_fields() {
        let cases = [
            (
                FaultProfile {
                    latency_ms: MAX_LATENCY_MS + 1,
                    ..FaultProfile::default()
                },
                "latencyMs",
            ),
            (
                FaultProfile {
                    jitter_ms: MAX_JITTER_MS + 1,
                    ..FaultProfile::default()
                },
                "jitterMs",
            ),
            (
                FaultProfile {
                    drop_rate: 101,
                    ..FaultProfile::default()
                },
                "dropRate",
            ),
            (
                FaultProfile {
                    mutation_rate: 101,
                    ..FaultProfile::default()
                },
                "mutationRate",
            ),
            (
                FaultProfile {
                    partial_drop_rate: Some(101),
                    ..FaultProfile::default()
                },
                "partialDropRate",
            ),
            (
                FaultProfile {
                    partial_drop_bytes: Some(MAX_PARTIAL_DROP_BYTES + 1),
                    ..FaultProfile::default()
                },
                "partialDropBytes",
            ),
        ];
        for (profile, expected) in cases {
            match profile.validate() {
                Err(EngineError::InvalidFaultProfile { field, .. }) => assert_eq!(field, expected),
                other => panic!("expected {expected} rejection, got {other:?}"),
            }
        }
        assert!(FaultProfile::default().validate().is_ok());
    }

    #[test]
    fn status_mutation_wire_format_matches_frontend() {
        let json = serde_json::to_string(&StatusMutation::ServiceUnavailable).unwrap();
        assert_eq!(json, "\"503\"");
        let parsed: StatusMutation = serde_json::from_str("\"none\"").unwrap();
        assert_eq!(parsed, StatusMutation::None);
    }
}
