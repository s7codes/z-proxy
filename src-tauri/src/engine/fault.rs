//! Fault decision model.
//!
//! Pure and synchronous so the proxy can take a decision under a short lock and tests can
//! replay exact sequences from a seeded RNG.

use std::time::Duration;

use axum::http::StatusCode;
use fastrand::Rng;
use serde::{Deserialize, Serialize};

use super::error::{EngineError, EngineResult};

pub const MAX_LATENCY_MS: u32 = 30_000;
pub const MAX_JITTER_MS: u32 = 10_000;
const MAX_RATE: u8 = 100;

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
        Ok(())
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FaultState {
    pub armed: bool,
    pub profile: FaultProfile,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultAction {
    Forward,
    Mutate(StatusCode),
    Drop,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FaultPlan {
    pub delay: Duration,
    pub action: FaultAction,
}

impl FaultPlan {
    pub const PASSTHROUGH: Self = Self {
        delay: Duration::ZERO,
        action: FaultAction::Forward,
    };
}

/// Latency applies to every outcome, including drops: a connection that hangs and then
/// resets is the failure shape clients most often mishandle.
pub fn plan(state: &FaultState, rng: &mut Rng) -> FaultPlan {
    if !state.armed {
        return FaultPlan::PASSTHROUGH;
    }
    let profile = &state.profile;
    let delay = Duration::from_millis(jittered_ms(profile.latency_ms, profile.jitter_ms, rng));

    let action = if roll(profile.drop_rate, rng) {
        FaultAction::Drop
    } else {
        match profile.status_mutation.status() {
            Some(status) if roll(profile.mutation_rate, rng) => FaultAction::Mutate(status),
            _ => FaultAction::Forward,
        }
    };

    FaultPlan { delay, action }
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
        }
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
            },
        };
        let mut rng = Rng::with_seed(7);
        for _ in 0..100 {
            assert_eq!(plan(&state, &mut rng), FaultPlan::PASSTHROUGH);
        }
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
