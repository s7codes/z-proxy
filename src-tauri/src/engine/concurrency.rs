//! Barrier-synchronized concurrency burst runner.
//!
//! Each worker opens and handshakes its own HTTP/1.1 connection before the barrier, so the
//! only work left after release is writing the request. Dispatch spread is then bounded by
//! task wake-up latency (microseconds) rather than TCP connect time (milliseconds), which is
//! what makes narrow race windows reproducible.
//!
//! `LastByte` goes one step further: everything but the final request byte is already on
//! the wire when the barrier opens, so release is a single-byte write from the worker's own
//! task and the server's parsers complete every request within one write's latency.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use axum::body::Bytes;
use axum::http::header::{self, HeaderName, HeaderValue};
use axum::http::Request;
use http_body_util::Full;
use hyper::client::conn::http1::SendRequest;
use tokio::io::AsyncWriteExt;
use tokio::sync::Barrier;
use tokio::task::JoinSet;
use uuid::Uuid;

use super::contract;
use super::error::{EngineError, EngineResult};
use super::guard::GuardedTarget;
use super::http1::{self, RequestTemplate, SplitConnection, CONNECT_TIMEOUT};
use super::net;
use super::pathparam;
use super::types::{
    Anomaly, AnomalyKind, BurstMethod, BurstReport, BurstSpec, BurstSyncMode, HeaderPair,
    LatencyStats, ResponseContract, Severity, SizeStats, StatusBucket, TelemetryEvent,
    WorkerSample,
};
use crate::telemetry::{now_us, TelemetryHub};

pub const MAX_WORKERS: u16 = 100;
const MAX_TIMEOUT_MS: u32 = 60_000;
const USER_AGENT: &str = concat!("z-proxy-burst/", env!("CARGO_PKG_VERSION"));
const WORKER_HEADER: &str = "x-zproxy-burst-worker";
pub const IDEMPOTENCY_HEADER: &str = "idempotency-key";

/// Statuses that mean a request lost a uniqueness, precondition or idempotency check.
const CONFLICT_STATUSES: [u16; 6] = [409, 412, 422, 423, 425, 429];
/// Body bytes a worker keeps for the contract check; a longer body is checked by status
/// only. Bounds a 100-worker burst at 6.4 MiB of retained bodies.
const CONTRACT_BODY_BYTES: usize = 64 * 1024;

struct Prepared {
    template: RequestTemplate,
    body: Bytes,
    timeout: Duration,
    expected_max_successes: Option<u16>,
    idempotency_key: Option<String>,
    sync_mode: BurstSyncMode,
    contract: Option<ResponseContract>,
}

/// A worker's sample and the body it captured for the contract check, which the collector
/// runs after the timed section so parsing never delays another worker's I/O.
struct Finished {
    sample: WorkerSample,
    /// The complete body; `None` without a contract, without a response, or when the body
    /// outgrew `CONTRACT_BODY_BYTES`.
    body: Option<Vec<u8>>,
}

impl Prepared {
    fn preview_limit(&self) -> usize {
        if self.contract.is_some() {
            CONTRACT_BODY_BYTES
        } else {
            0
        }
    }

    fn request(&self, worker: u16) -> Request<Full<Bytes>> {
        let mut request = self.template.request(self.body.clone());
        let headers = request.headers_mut();
        headers
            .entry(header::USER_AGENT)
            .or_insert(HeaderValue::from_static(USER_AGENT));
        headers.insert(
            HeaderName::from_static(WORKER_HEADER),
            HeaderValue::from(worker),
        );
        request
    }
}

pub async fn run(spec: BurstSpec, hub: &TelemetryHub) -> EngineResult<BurstReport> {
    let prepared = Arc::new(prepare(&spec)?);
    let id = Uuid::new_v4();
    let workers = spec.workers;

    hub.publish(TelemetryEvent::BurstStarted {
        seq: hub.next_seq(),
        id,
        ts_us: now_us(),
        target: prepared.template.label.clone(),
        method: spec.method,
        workers,
        sync_mode: prepared.sync_mode,
        idempotency_key: prepared.idempotency_key.clone(),
    });
    tracing::info!(%id, target = %prepared.template.label, workers, sync = ?prepared.sync_mode, idempotent = prepared.idempotency_key.is_some(), "concurrency burst started");

    let barrier = Arc::new(Barrier::new(usize::from(workers)));
    let release = Arc::new(OnceLock::new());
    let started = Instant::now();
    let mut tasks = JoinSet::new();
    for worker in 1..=workers {
        tasks.spawn(run_worker(
            worker,
            Arc::clone(&prepared),
            Arc::clone(&barrier),
            Arc::clone(&release),
        ));
    }

    let mut samples = Vec::with_capacity(usize::from(workers));
    while let Some(joined) = tasks.join_next().await {
        match joined {
            Ok(Finished { mut sample, body }) => {
                if let (Some(contract), Some(status)) = (&prepared.contract, sample.status) {
                    sample.violations = contract::check(contract, status, body.as_deref());
                }
                hub.publish(TelemetryEvent::BurstSample {
                    seq: hub.next_seq(),
                    id,
                    ts_us: now_us(),
                    sample: sample.clone(),
                });
                samples.push(sample);
            }
            Err(err) => tracing::error!(%id, error = %err, "burst worker task failed"),
        }
    }
    samples.sort_by_key(|sample| sample.worker);

    let report = analyze(
        ReportMeta {
            id,
            target: prepared.template.label.clone(),
            method: spec.method,
            workers,
            sync_mode: prepared.sync_mode,
            wall_us: net::elapsed_us(started),
            expected_max_successes: prepared.expected_max_successes,
            idempotency_key: prepared.idempotency_key.clone(),
        },
        samples,
    );

    let errors = report.samples.iter().filter(|s| s.status.is_none()).count();
    hub.publish(TelemetryEvent::BurstCompleted {
        seq: hub.next_seq(),
        id,
        ts_us: now_us(),
        wall_us: report.wall_us,
        sync_mode: report.sync_mode,
        dispatch_spread_us: report.dispatch_spread_us,
        anomalies: count_u32(report.anomalies.len()),
        errors: count_u32(errors),
    });
    tracing::info!(
        %id,
        wall_us = report.wall_us,
        sync = ?report.sync_mode,
        spread_us = ?report.dispatch_spread_us,
        anomalies = report.anomalies.len(),
        "concurrency burst completed"
    );
    Ok(report)
}

fn prepare(spec: &BurstSpec) -> EngineResult<Prepared> {
    if spec.workers == 0 || spec.workers > MAX_WORKERS {
        return Err(invalid(
            "workers",
            format!("must be between 1 and {MAX_WORKERS}"),
        ));
    }
    if spec.timeout_ms == 0 || spec.timeout_ms > MAX_TIMEOUT_MS {
        return Err(invalid(
            "timeoutMs",
            format!("must be between 1 and {MAX_TIMEOUT_MS}"),
        ));
    }

    let mut headers = spec.headers.clone();
    let idempotency_key = if spec.idempotency_mode {
        if !matches!(
            spec.method,
            BurstMethod::Post | BurstMethod::Put | BurstMethod::Patch
        ) {
            return Err(invalid(
                "idempotencyMode",
                "replays a write; use POST, PUT or PATCH".to_owned(),
            ));
        }
        // An operator-supplied key is replayed as given, so a key already known to the
        // service (a retried checkout) can be tested too.
        let supplied = spec
            .headers
            .iter()
            .find(|pair| pair.name.trim().eq_ignore_ascii_case(IDEMPOTENCY_HEADER));
        Some(match supplied {
            Some(pair) => pair.value.clone(),
            None => {
                let key = Uuid::new_v4().to_string();
                headers.push(HeaderPair {
                    name: IDEMPOTENCY_HEADER.to_owned(),
                    value: key.clone(),
                });
                key
            }
        })
    } else {
        None
    };

    Ok(Prepared {
        template: RequestTemplate::new(
            &pathparam::resolve(&spec.target)?.target,
            spec.method,
            &headers,
            invalid,
        )?,
        body: spec.body.clone().map(Bytes::from).unwrap_or_default(),
        timeout: Duration::from_millis(u64::from(spec.timeout_ms)),
        expected_max_successes: spec.expected_max_successes,
        idempotency_key,
        sync_mode: spec.sync_mode.unwrap_or_default(),
        contract: spec.contract.clone(),
    })
}

async fn run_worker(
    worker: u16,
    prepared: Arc<Prepared>,
    barrier: Arc<Barrier>,
    release: Arc<OnceLock<Instant>>,
) -> Finished {
    match prepared.sync_mode {
        BurstSyncMode::PreConnected => pre_connected(worker, &prepared, &barrier, &release).await,
        BurstSyncMode::LastByte => last_byte(worker, &prepared, &barrier, &release).await,
    }
}

async fn pre_connected(
    worker: u16,
    prepared: &Prepared,
    barrier: &Barrier,
    release: &OnceLock<Instant>,
) -> Finished {
    let connection = tokio::time::timeout(CONNECT_TIMEOUT, http1::open(&prepared.template.target))
        .await
        .map_or_else(
            |_| Err(connect_timeout()),
            |opened| opened.map_err(|err| err.to_string()),
        );
    let request = prepared.request(worker);

    // Workers whose connect failed still wait here; skipping the barrier would leave every
    // other worker parked forever.
    barrier.wait().await;

    let mut sender = match connection {
        Ok(sender) => sender,
        Err(error) => return failed(worker, None, 0, error).into(),
    };

    let fired = Instant::now();
    let epoch = *release.get_or_init(|| fired);
    let dispatch_offset_us = Some(duration_us(fired.saturating_duration_since(epoch)));
    let outcome = tokio::time::timeout(
        prepared.timeout,
        exchange(&mut sender, request, prepared.preview_limit()),
    )
    .await;
    let latency_us = net::elapsed_us(fired);
    sample(
        worker,
        prepared,
        fired,
        dispatch_offset_us,
        latency_us,
        outcome,
    )
}

/// The server can finish parsing no request before its final byte, so holding that byte
/// back aligns the requests at the server's parser rather than at the client's scheduler.
async fn last_byte(
    worker: u16,
    prepared: &Prepared,
    barrier: &Barrier,
    release: &OnceLock<Instant>,
) -> Finished {
    let request = prepared.request(worker);
    let wire = http1::encode(&request, &prepared.body);
    let staged = tokio::time::timeout(CONNECT_TIMEOUT, stage(&prepared.template.target, &wire))
        .await
        .unwrap_or_else(|_| Err(connect_timeout()))
        .map(|(mut connection, last)| {
            // Queued now so hyper has consumed its copy and armed the read side before the
            // response can exist.
            let pending = connection.sender.send_request(request);
            (connection, last, pending)
        });

    barrier.wait().await;

    let (mut connection, last, pending) = match staged {
        Ok(staged) => staged,
        Err(error) => return failed(worker, None, 0, error).into(),
    };

    let fired = Instant::now();
    let epoch = *release.get_or_init(|| fired);
    let dispatch_offset_us = Some(duration_us(fired.saturating_duration_since(epoch)));
    let written = connection.writer.write_all(&[last]).await;
    let outcome = tokio::time::timeout(
        prepared.timeout,
        http1::exchange_pending(pending, prepared.preview_limit()),
    )
    .await;
    let latency_us = net::elapsed_us(fired);
    drop(connection);
    // A server may answer and close before the final byte (431, 413); its response wins
    // over the failed write.
    let outcome = match (outcome, written) {
        (Ok(Err(err)), Err(write)) => Ok(Err(format!("{err}; final byte write failed: {write}"))),
        (outcome, _) => outcome.map(|received| received.map_err(|err| err.to_string())),
    };
    sample(
        worker,
        prepared,
        fired,
        dispatch_offset_us,
        latency_us,
        outcome,
    )
}

/// Opens a split connection and writes every request byte but the last.
async fn stage(target: &GuardedTarget, wire: &[u8]) -> Result<(SplitConnection, u8), String> {
    let Some((&last, held)) = wire.split_last() else {
        return Err("request encoded to zero bytes".to_owned());
    };
    let mut connection = http1::open_split(target)
        .await
        .map_err(|err| err.to_string())?;
    connection
        .writer
        .write_all(held)
        .await
        .map_err(|err| format!("request write failed: {err}"))?;
    connection
        .writer
        .flush()
        .await
        .map_err(|err| format!("request flush failed: {err}"))?;
    Ok((connection, last))
}

fn sample(
    worker: u16,
    prepared: &Prepared,
    fired: Instant,
    dispatch_offset_us: Option<u64>,
    latency_us: u64,
    outcome: Result<Result<http1::Received, String>, tokio::time::error::Elapsed>,
) -> Finished {
    match outcome {
        Ok(Ok(received)) => {
            let complete = u64::try_from(received.preview.len()).ok() == Some(received.bytes);
            let body = (prepared.contract.is_some() && complete).then_some(received.preview);
            Finished {
                sample: WorkerSample {
                    worker,
                    status: Some(received.status),
                    dispatch_offset_us,
                    ttfb_us: Some(duration_us(
                        received.head_at.saturating_duration_since(fired),
                    )),
                    latency_us,
                    bytes: received.bytes,
                    body_hash: Some(received.hash),
                    error: None,
                    violations: Vec::new(),
                },
                body,
            }
        }
        Ok(Err(error)) => failed(worker, dispatch_offset_us, latency_us, error).into(),
        Err(_) => failed(
            worker,
            dispatch_offset_us,
            latency_us,
            format!("timed out after {} ms", prepared.timeout.as_millis()),
        )
        .into(),
    }
}

impl From<WorkerSample> for Finished {
    fn from(sample: WorkerSample) -> Self {
        Self { sample, body: None }
    }
}

fn connect_timeout() -> String {
    format!("connect timed out after {} ms", CONNECT_TIMEOUT.as_millis())
}

async fn exchange(
    sender: &mut SendRequest<Full<Bytes>>,
    request: Request<Full<Bytes>>,
    preview_limit: usize,
) -> Result<http1::Received, String> {
    http1::exchange(sender, request, preview_limit)
        .await
        .map_err(|err| err.to_string())
}

fn failed(
    worker: u16,
    dispatch_offset_us: Option<u64>,
    latency_us: u64,
    error: String,
) -> WorkerSample {
    WorkerSample {
        worker,
        status: None,
        dispatch_offset_us,
        ttfb_us: None,
        latency_us,
        bytes: 0,
        body_hash: None,
        error: Some(error),
        violations: Vec::new(),
    }
}

// ---- analysis -------------------------------------------------------------------------

struct ReportMeta {
    id: Uuid,
    target: String,
    method: BurstMethod,
    workers: u16,
    sync_mode: BurstSyncMode,
    wall_us: u64,
    expected_max_successes: Option<u16>,
    idempotency_key: Option<String>,
}

fn analyze(meta: ReportMeta, samples: Vec<WorkerSample>) -> BurstReport {
    let mut by_status: BTreeMap<Option<u16>, Vec<u16>> = BTreeMap::new();
    for sample in &samples {
        by_status
            .entry(sample.status)
            .or_default()
            .push(sample.worker);
    }

    let mut status_histogram: Vec<StatusBucket> = by_status
        .iter()
        .map(|(status, workers)| StatusBucket {
            status: *status,
            count: count_u32(workers.len()),
        })
        .collect();
    status_histogram.sort_by(|a, b| b.count.cmp(&a.count).then(a.status.cmp(&b.status)));

    let responded: Vec<&WorkerSample> = samples.iter().filter(|s| s.status.is_some()).collect();
    let latency = latency_stats(responded.iter().map(|s| s.latency_us).collect());
    let ttfb = latency_stats(responded.iter().filter_map(|s| s.ttfb_us).collect());
    let size = responded
        .iter()
        .map(|s| s.bytes)
        .min()
        .zip(responded.iter().map(|s| s.bytes).max())
        .map(|(min_bytes, max_bytes)| SizeStats {
            min_bytes,
            max_bytes,
        });
    let distinct_bodies = responded
        .iter()
        .filter_map(|s| s.body_hash.as_deref())
        .collect::<HashSet<_>>()
        .len();

    let offsets = samples.iter().filter_map(|s| s.dispatch_offset_us);
    let dispatch_spread_us = offsets
        .clone()
        .max()
        .zip(offsets.min())
        .map(|(max, min)| max - min);

    let anomalies = detect_anomalies(
        &samples,
        &by_status,
        meta.expected_max_successes,
        meta.idempotency_key.is_some(),
    );

    BurstReport {
        id: meta.id,
        target: meta.target,
        method: meta.method,
        workers: meta.workers,
        sync_mode: meta.sync_mode,
        wall_us: meta.wall_us,
        dispatch_spread_us,
        status_histogram,
        latency,
        ttfb,
        size,
        distinct_bodies: count_u32(distinct_bodies),
        expected_max_successes: meta.expected_max_successes,
        idempotency_key: meta.idempotency_key,
        contract_violations: count_u32(samples.iter().filter(|s| !s.violations.is_empty()).count()),
        anomalies,
        samples,
    }
}

/// `idempotent`: every worker sent the same `Idempotency-Key`. Several 2xx responses are
/// then legitimate replays, so the race analysis gives way to a body comparison.
fn detect_anomalies(
    samples: &[WorkerSample],
    by_status: &BTreeMap<Option<u16>, Vec<u16>>,
    expected_max_successes: Option<u16>,
    idempotent: bool,
) -> Vec<Anomaly> {
    let total = samples.len();
    let mut anomalies = Vec::new();

    if let Some(failed) = by_status.get(&None) {
        let first_error = samples
            .iter()
            .find_map(|s| s.error.as_deref())
            .unwrap_or("unknown error");
        anomalies.push(Anomaly {
            kind: AnomalyKind::TransportErrors,
            severity: if failed.len() == total {
                Severity::Fault
            } else {
                Severity::Warn
            },
            detail: format!(
                "{}/{total} workers produced no response; first error: {first_error}",
                failed.len()
            ),
            workers: failed.clone(),
        });
    }

    let responded: Vec<(u16, &Vec<u16>)> = by_status
        .iter()
        .filter_map(|(status, workers)| status.map(|s| (s, workers)))
        .collect();
    let is_success = |status: u16| (200..300).contains(&status);
    let is_conflict = |status: u16| CONFLICT_STATUSES.contains(&status);

    let successes: Vec<u16> = responded
        .iter()
        .filter(|(status, _)| is_success(*status))
        .flat_map(|(_, workers)| workers.iter().copied())
        .collect();
    let conflicts: usize = responded
        .iter()
        .filter(|(status, _)| is_conflict(*status))
        .map(|(_, workers)| workers.len())
        .sum();

    // One winner plus conflicts is correct serialization. More than one winner means two
    // requests passed the same uniqueness check before either committed. Without conflicts
    // the responses alone cannot tell a race from an operation that admits everyone, so only
    // an operator quota turns surplus successes into a finding.
    let allowed = expected_max_successes.map_or(1, usize::from);
    if idempotent {
        anomalies.extend(idempotency_violation(samples));
    } else if successes.len() > allowed && (expected_max_successes.is_some() || conflicts > 0) {
        let detail = match expected_max_successes {
            Some(limit) if conflicts > 0 => format!(
                "{} of {total} requests succeeded alongside {conflicts} conflict responses; the expected maximum is {limit}",
                successes.len()
            ),
            Some(limit) => format!(
                "{} of {total} requests succeeded with no conflict response; the expected maximum is {limit}",
                successes.len()
            ),
            None => format!(
                "{} of {total} requests succeeded alongside {conflicts} conflict responses; a serialized handler admits at most one",
                successes.len()
            ),
        };
        anomalies.push(Anomaly {
            kind: AnomalyKind::RaceWindow,
            severity: Severity::Fault,
            detail,
            workers: successes,
        });
    }

    if responded.len() > 1 {
        // With conflicts present the success/conflict mix is already explained above; only
        // statuses outside that model are divergence. Without conflicts, everything outside
        // the majority bucket is.
        let outliers: Vec<(u16, &Vec<u16>)> = if conflicts > 0 {
            responded
                .iter()
                .filter(|(status, _)| !is_success(*status) && !is_conflict(*status))
                .copied()
                .collect()
        } else {
            let majority = responded
                .iter()
                .max_by(|a, b| a.1.len().cmp(&b.1.len()).then(b.0.cmp(&a.0)))
                .map(|(status, _)| *status);
            responded
                .iter()
                .filter(|(status, _)| Some(*status) != majority)
                .copied()
                .collect()
        };
        if !outliers.is_empty() {
            let mut split: Vec<(u16, usize)> =
                responded.iter().map(|(s, w)| (*s, w.len())).collect();
            split.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
            let split = split
                .iter()
                .map(|(status, count)| format!("{count}x{status}"))
                .collect::<Vec<_>>()
                .join(", ");
            let mut workers: Vec<u16> = outliers
                .iter()
                .flat_map(|(_, w)| w.iter().copied())
                .collect();
            workers.sort_unstable();
            anomalies.push(Anomaly {
                kind: AnomalyKind::StatusDivergence,
                severity: if outliers.iter().any(|(status, _)| *status >= 500) {
                    Severity::Fault
                } else {
                    Severity::Warn
                },
                detail: format!("status split: {split}"),
                workers,
            });
        }
    }

    for (status, workers) in &responded {
        // Divergent 2xx bodies under one key are the idempotency finding above.
        if workers.len() < 2 || (idempotent && is_success(*status)) {
            continue;
        }
        let mut groups: HashMap<&str, Vec<u16>> = HashMap::new();
        for sample in samples.iter().filter(|s| s.status == Some(*status)) {
            if let Some(hash) = sample.body_hash.as_deref() {
                groups.entry(hash).or_default().push(sample.worker);
            }
        }
        if groups.len() < 2 {
            continue;
        }
        let majority = groups
            .iter()
            .max_by(|a, b| a.1.len().cmp(&b.1.len()).then(b.0.cmp(a.0)))
            .map(|(hash, _)| *hash);
        let mut outliers: Vec<u16> = groups
            .iter()
            .filter(|(hash, _)| Some(**hash) != majority)
            .flat_map(|(_, w)| w.iter().copied())
            .collect();
        outliers.sort_unstable();
        anomalies.push(Anomaly {
            kind: AnomalyKind::BodyDivergence,
            severity: Severity::Warn,
            detail: format!(
                "{} distinct bodies across {} responses with status {status}",
                groups.len(),
                workers.len()
            ),
            workers: outliers,
        });
    }

    anomalies.extend(contract_drift(samples));
    anomalies
}

/// Responses that broke the documented contract. Under concurrency the typical shape is a
/// counter read before a concurrent commit and written back past its bound (a balance of
/// `-1`), or a body assembled from a half-applied update. A drifted 2xx is a fault: the
/// client took it as success. Drift on refusals alone (an undocumented 409) is a warning.
fn contract_drift(samples: &[WorkerSample]) -> Option<Anomaly> {
    let drifted: Vec<&WorkerSample> = samples
        .iter()
        .filter(|s| !s.violations.is_empty())
        .collect();
    if drifted.is_empty() {
        return None;
    }
    let successes = drifted
        .iter()
        .filter(|s| s.status.is_some_and(|status| (200..300).contains(&status)))
        .count();

    // The most widespread violation, by location and expectation; offending values differ
    // per worker (-1, -2, ...), so they are listed rather than grouped on.
    let mut groups: BTreeMap<(Option<&str>, &str), DriftGroup<'_>> = BTreeMap::new();
    for violation in drifted.iter().flat_map(|s| s.violations.iter()) {
        let group = groups
            .entry((violation.pointer.as_deref(), violation.expected.as_str()))
            .or_default();
        group.count += 1;
        if !group.actuals.contains(&violation.actual.as_str()) {
            group.actuals.push(violation.actual.as_str());
        }
    }
    let headline = groups
        .iter()
        .max_by(|a, b| a.1.count.cmp(&b.1.count).then(b.0.cmp(a.0)))
        .map(|((pointer, expected), group)| describe_drift(*pointer, expected, &group.actuals))
        .unwrap_or_default();
    let others = groups.len().saturating_sub(1);
    let mut workers: Vec<u16> = drifted.iter().map(|s| s.worker).collect();
    workers.sort_unstable();
    Some(Anomaly {
        kind: AnomalyKind::ContractDrift,
        severity: if successes > 0 {
            Severity::Fault
        } else {
            Severity::Warn
        },
        detail: format!(
            "{} of {} responses broke the response contract, {successes} of them 2xx; {headline}{}",
            drifted.len(),
            samples.iter().filter(|s| s.status.is_some()).count(),
            if others > 0 {
                format!(
                    " (+{others} other violation{})",
                    if others == 1 { "" } else { "s" }
                )
            } else {
                String::new()
            }
        ),
        workers,
    })
}

/// Occurrences of one (location, expectation) pair and the distinct values that broke it.
#[derive(Default)]
struct DriftGroup<'a> {
    count: usize,
    actuals: Vec<&'a str>,
}

fn describe_drift(pointer: Option<&str>, expected: &str, actuals: &[&str]) -> String {
    const LISTED: usize = 4;
    let mut values = actuals
        .iter()
        .take(LISTED)
        .copied()
        .collect::<Vec<_>>()
        .join(", ");
    if actuals.len() > LISTED {
        values.push_str(", ...");
    }
    match pointer {
        None => format!("status {values} not documented ({expected})"),
        Some("") => format!("body: expected {expected}, got {values}"),
        Some(pointer) => format!("{pointer}: expected {expected}, got {values}"),
    }
}

/// A deduplicating handler answers every request carrying one key with the stored response
/// of the first, so all 2xx bodies share one fingerprint. More than one fingerprint means
/// the operation ran again for some requests: a second order, a second charge.
fn idempotency_violation(samples: &[WorkerSample]) -> Option<Anomaly> {
    let mut groups: HashMap<&str, Vec<u16>> = HashMap::new();
    let mut successes = 0usize;
    for sample in samples
        .iter()
        .filter(|s| s.status.is_some_and(|status| (200..300).contains(&status)))
    {
        if let Some(hash) = sample.body_hash.as_deref() {
            groups.entry(hash).or_default().push(sample.worker);
            successes += 1;
        }
    }
    if groups.len() < 2 {
        return None;
    }
    let majority = groups
        .iter()
        .max_by(|a, b| a.1.len().cmp(&b.1.len()).then(b.0.cmp(a.0)))
        .map(|(hash, _)| *hash);
    let mut workers: Vec<u16> = groups
        .iter()
        .filter(|(hash, _)| Some(**hash) != majority)
        .flat_map(|(_, workers)| workers.iter().copied())
        .collect();
    workers.sort_unstable();
    Some(Anomaly {
        kind: AnomalyKind::IdempotencyViolation,
        severity: Severity::Fault,
        detail: format!(
            "{successes} 2xx responses to one Idempotency-Key carried {} distinct bodies; a deduplicating handler replays the first response",
            groups.len()
        ),
        workers,
    })
}

fn latency_stats(mut values: Vec<u64>) -> Option<LatencyStats> {
    values.sort_unstable();
    let min_us = *values.first()?;
    let max_us = *values.last()?;
    let sum: u128 = values.iter().map(|&v| u128::from(v)).sum();
    let count = u128::try_from(values.len()).unwrap_or(u128::MAX);
    Some(LatencyStats {
        min_us,
        max_us,
        mean_us: u64::try_from(sum / count).unwrap_or(u64::MAX),
        p50_us: percentile(&values, 50),
        p95_us: percentile(&values, 95),
        p99_us: percentile(&values, 99),
    })
}

/// Nearest-rank percentile over an ascending slice.
fn percentile(sorted: &[u64], p: usize) -> u64 {
    let rank = (p * sorted.len()).div_ceil(100).max(1);
    sorted.get(rank - 1).copied().unwrap_or(0)
}

fn duration_us(duration: Duration) -> u64 {
    u64::try_from(duration.as_micros()).unwrap_or(u64::MAX)
}

fn count_u32(n: usize) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
}

fn invalid(field: &'static str, reason: String) -> EngineError {
    EngineError::InvalidBurstSpec { field, reason }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    use axum::extract::{Request, State};
    use axum::http::StatusCode;
    use axum::response::{IntoResponse, Response};
    use axum::Router;
    use tokio::net::TcpListener;

    use super::*;
    use crate::engine::types::{ContractViolation, ContractViolationKind, HeaderPair};

    async fn serve(router: Router) -> SocketAddr {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        addr
    }

    fn spec(target: String, workers: u16) -> BurstSpec {
        BurstSpec {
            target,
            method: BurstMethod::Get,
            workers,
            headers: Vec::new(),
            body: None,
            timeout_ms: 5_000,
            expected_max_successes: None,
            idempotency_mode: false,
            sync_mode: None,
            contract: None,
        }
    }

    fn sample(worker: u16, status: Option<u16>, latency_us: u64, hash: &str) -> WorkerSample {
        WorkerSample {
            worker,
            status,
            dispatch_offset_us: status.map(|_| u64::from(worker)),
            ttfb_us: status.map(|_| latency_us / 2),
            latency_us,
            bytes: 10,
            body_hash: status.map(|_| hash.to_owned()),
            error: status.is_none().then(|| "connection refused".to_owned()),
            violations: Vec::new(),
        }
    }

    fn drifted(
        mut sample: WorkerSample,
        pointer: Option<&str>,
        expected: &str,
        actual: &str,
    ) -> WorkerSample {
        sample.violations.push(ContractViolation {
            kind: if pointer.is_some() {
                ContractViolationKind::ConstraintViolation
            } else {
                ContractViolationKind::UndocumentedStatus
            },
            pointer: pointer.map(str::to_owned),
            expected: expected.to_owned(),
            actual: actual.to_owned(),
        });
        sample
    }

    #[test]
    fn contract_drift_under_load() {
        let mut samples = vec![sample(1, Some(200), 100, "a")];
        samples.extend((2..=3).map(|w| {
            drifted(
                sample(w, Some(200), 100, &format!("b{w}")),
                Some("/remainingUses"),
                ">= 0",
                &format!("-{}", w - 1),
            )
        }));
        samples.extend((4..=10).map(|w| sample(w, Some(409), 100, "c")));
        let report = analyze(meta(10), samples);
        let drift = report
            .anomalies
            .iter()
            .find(|a| a.kind == AnomalyKind::ContractDrift)
            .expect("contract drift");
        assert_eq!(drift.severity, Severity::Fault);
        assert_eq!(drift.workers, [2, 3]);
        assert_eq!(
            drift.detail,
            "2 of 10 responses broke the response contract, 2 of them 2xx; /remainingUses: expected >= 0, got -1, -2"
        );
        assert_eq!(report.contract_violations, 2);

        // Only refusals drifted: the contract is incomplete, the service did not misbehave.
        let mut refusals = vec![sample(1, Some(201), 100, "a")];
        refusals.extend((2..=5).map(|w| {
            drifted(
                sample(w, Some(409), 100, "c"),
                None,
                "one of 201, 422",
                "409",
            )
        }));
        let report = analyze(meta(5), refusals);
        assert_eq!(kinds(&report), [AnomalyKind::ContractDrift]);
        assert_eq!(report.anomalies[0].severity, Severity::Warn);
        assert_eq!(
            report.anomalies[0].detail,
            "4 of 5 responses broke the response contract, 0 of them 2xx; status 409 not documented (one of 201, 422)"
        );

        let clean = analyze(
            meta(3),
            (1..=3).map(|w| sample(w, Some(200), 1, "x")).collect(),
        );
        assert!(clean.anomalies.is_empty());
        assert_eq!(clean.contract_violations, 0);
    }

    fn meta(workers: u16) -> ReportMeta {
        ReportMeta {
            id: Uuid::nil(),
            target: "http://127.0.0.1/".to_owned(),
            method: BurstMethod::Post,
            workers,
            sync_mode: BurstSyncMode::PreConnected,
            wall_us: 1,
            expected_max_successes: None,
            idempotency_key: None,
        }
    }

    fn quota(workers: u16, limit: u16) -> ReportMeta {
        ReportMeta {
            expected_max_successes: Some(limit),
            ..meta(workers)
        }
    }

    fn kinds(report: &BurstReport) -> Vec<AnomalyKind> {
        report.anomalies.iter().map(|a| a.kind).collect()
    }

    #[test]
    fn nearest_rank_percentiles() {
        let values: Vec<u64> = (1..=100).collect();
        assert_eq!(percentile(&values, 50), 50);
        assert_eq!(percentile(&values, 95), 95);
        assert_eq!(percentile(&values, 99), 99);
        assert_eq!(percentile(&[7], 99), 7);
        assert_eq!(percentile(&[1, 2, 3, 4], 50), 2);

        let stats = latency_stats(vec![40, 10, 30, 20]).unwrap();
        assert_eq!((stats.min_us, stats.max_us, stats.mean_us), (10, 40, 25));
        assert!(latency_stats(Vec::new()).is_none());
    }

    #[test]
    fn single_winner_with_conflicts_is_correct_serialization() {
        let mut samples = vec![sample(1, Some(201), 100, "a")];
        samples.extend((2..=10).map(|w| sample(w, Some(409), 100, "c")));
        let report = analyze(meta(10), samples);
        assert!(report.anomalies.is_empty(), "{:?}", report.anomalies);
        assert_eq!(
            report.status_histogram,
            [
                StatusBucket {
                    status: Some(409),
                    count: 9
                },
                StatusBucket {
                    status: Some(201),
                    count: 1
                },
            ]
        );
        assert_eq!(report.distinct_bodies, 2);
        assert_eq!(report.dispatch_spread_us, Some(9));
    }

    #[test]
    fn multiple_winners_alongside_conflicts_is_a_race_window() {
        let mut samples: Vec<WorkerSample> =
            (1..=18).map(|w| sample(w, Some(409), 100, "c")).collect();
        samples.push(sample(19, Some(200), 100, "ok"));
        samples.push(sample(20, Some(200), 100, "ok"));
        let report = analyze(meta(20), samples);
        assert_eq!(kinds(&report), [AnomalyKind::RaceWindow]);
        let race = &report.anomalies[0];
        assert_eq!(race.severity, Severity::Fault);
        assert_eq!(race.workers, [19, 20]);
        assert!(
            race.detail
                .starts_with("2 of 20 requests succeeded alongside 18 conflict"),
            "{}",
            race.detail
        );
    }

    #[test]
    fn quota_flags_surplus_successes_without_any_conflict() {
        let winners = || (1..=20).map(|w| sample(w, Some(200), 100, "ok")).collect();
        let unbounded = analyze(meta(20), winners());
        assert!(unbounded.anomalies.is_empty(), "{:?}", unbounded.anomalies);
        assert_eq!(unbounded.expected_max_successes, None);

        let report = analyze(quota(20, 1), winners());
        assert_eq!(kinds(&report), [AnomalyKind::RaceWindow]);
        let race = &report.anomalies[0];
        assert_eq!(race.severity, Severity::Fault);
        assert_eq!(race.workers, (1..=20).collect::<Vec<u16>>());
        assert_eq!(
            race.detail,
            "20 of 20 requests succeeded with no conflict response; the expected maximum is 1"
        );
        assert_eq!(report.expected_max_successes, Some(1));
    }

    #[test]
    fn quota_replaces_the_single_winner_assumption() {
        let mixed = || {
            let mut samples: Vec<WorkerSample> =
                (1..=3).map(|w| sample(w, Some(200), 100, "ok")).collect();
            samples.extend((4..=20).map(|w| sample(w, Some(409), 100, "c")));
            samples
        };
        assert_eq!(
            kinds(&analyze(meta(20), mixed())),
            [AnomalyKind::RaceWindow]
        );
        assert!(analyze(quota(20, 3), mixed()).anomalies.is_empty());
        assert!(analyze(quota(20, 5), mixed()).anomalies.is_empty());

        let over = analyze(quota(20, 2), mixed());
        assert_eq!(kinds(&over), [AnomalyKind::RaceWindow]);
        assert_eq!(
            over.anomalies[0].detail,
            "3 of 20 requests succeeded alongside 17 conflict responses; the expected maximum is 2"
        );

        // A zero quota asserts the operation must not succeed at all (an already spent coupon).
        let mut spent = vec![sample(1, Some(200), 100, "ok")];
        spent.extend((2..=10).map(|w| sample(w, Some(409), 100, "c")));
        let report = analyze(quota(10, 0), spent);
        assert_eq!(kinds(&report), [AnomalyKind::RaceWindow]);
        assert_eq!(report.anomalies[0].workers, [1]);
    }

    #[test]
    fn ttfb_stats_cover_responded_workers_only() {
        let samples = vec![
            sample(1, Some(200), 400, "ok"),
            sample(2, None, 9_999, ""),
            sample(3, Some(200), 200, "ok"),
        ];
        let report = analyze(meta(3), samples);
        let ttfb = report.ttfb.unwrap();
        assert_eq!((ttfb.min_us, ttfb.max_us, ttfb.mean_us), (100, 200, 150));
        assert!(analyze(meta(1), vec![sample(1, None, 5, "")])
            .ttfb
            .is_none());
    }

    #[test]
    fn server_errors_under_load_are_fault_divergence() {
        let mut samples: Vec<WorkerSample> =
            (1..=8).map(|w| sample(w, Some(200), 100, "ok")).collect();
        samples.push(sample(9, Some(500), 100, "e"));
        samples.push(sample(10, Some(500), 100, "e"));
        let report = analyze(meta(10), samples);
        assert_eq!(kinds(&report), [AnomalyKind::StatusDivergence]);
        let divergence = &report.anomalies[0];
        assert_eq!(divergence.severity, Severity::Fault);
        assert_eq!(divergence.workers, [9, 10]);
        assert_eq!(divergence.detail, "status split: 8x200, 2x500");
    }

    #[test]
    fn body_divergence_flags_minority_fingerprints() {
        let mut samples: Vec<WorkerSample> =
            (1..=4).map(|w| sample(w, Some(200), 100, "same")).collect();
        samples.push(sample(5, Some(200), 100, "odd"));
        let report = analyze(meta(5), samples);
        assert_eq!(kinds(&report), [AnomalyKind::BodyDivergence]);
        assert_eq!(report.anomalies[0].workers, [5]);
        assert_eq!(report.anomalies[0].severity, Severity::Warn);
    }

    fn idempotent(workers: u16) -> ReportMeta {
        ReportMeta {
            idempotency_key: Some("k-1".to_owned()),
            ..meta(workers)
        }
    }

    #[test]
    fn one_key_must_replay_one_body() {
        let replays = || {
            (1..=20)
                .map(|w| sample(w, Some(201), 100, "order-1"))
                .collect()
        };
        let report = analyze(idempotent(20), replays());
        assert!(report.anomalies.is_empty(), "{:?}", report.anomalies);
        assert_eq!(report.idempotency_key.as_deref(), Some("k-1"));

        // In-flight duplicates refused with 409 next to replays of the stored response.
        let mut mixed: Vec<WorkerSample> = (1..=3)
            .map(|w| sample(w, Some(201), 100, "order-1"))
            .collect();
        mixed.extend((4..=20).map(|w| sample(w, Some(409), 100, "busy")));
        assert!(analyze(idempotent(20), mixed).anomalies.is_empty());

        let mut doubled: Vec<WorkerSample> = (1..=18)
            .map(|w| sample(w, Some(201), 100, "order-1"))
            .collect();
        doubled.push(sample(19, Some(201), 100, "order-2"));
        doubled.push(sample(20, Some(200), 100, "order-3"));
        let report = analyze(idempotent(20), doubled);
        assert_eq!(
            kinds(&report),
            [
                AnomalyKind::IdempotencyViolation,
                AnomalyKind::StatusDivergence
            ]
        );
        let violation = &report.anomalies[0];
        assert_eq!(violation.severity, Severity::Fault);
        assert_eq!(violation.workers, [19, 20]);
        assert_eq!(
            violation.detail,
            "20 2xx responses to one Idempotency-Key carried 3 distinct bodies; a deduplicating handler replays the first response"
        );
    }

    #[test]
    fn transport_errors_are_reported_and_excluded_from_latency() {
        let samples = vec![
            sample(1, Some(200), 300, "ok"),
            sample(2, None, 9_999, ""),
            sample(3, Some(200), 100, "ok"),
        ];
        let report = analyze(meta(3), samples);
        assert_eq!(kinds(&report), [AnomalyKind::TransportErrors]);
        assert_eq!(report.anomalies[0].severity, Severity::Warn);
        assert_eq!(report.anomalies[0].workers, [2]);
        let latency = report.latency.unwrap();
        assert_eq!((latency.min_us, latency.max_us), (100, 300));
        assert_eq!(
            report.status_histogram[0],
            StatusBucket {
                status: Some(200),
                count: 2
            }
        );
    }

    #[tokio::test]
    async fn rejects_invalid_specs_before_connecting() {
        let hub = TelemetryHub::new();
        let ok = "http://127.0.0.1:9".to_owned();
        let cases: Vec<(BurstSpec, &str)> = vec![
            (spec(ok.clone(), 0), "INVALID_BURST_SPEC"),
            (spec(ok.clone(), MAX_WORKERS + 1), "INVALID_BURST_SPEC"),
            (
                BurstSpec {
                    timeout_ms: 0,
                    ..spec(ok.clone(), 1)
                },
                "INVALID_BURST_SPEC",
            ),
            (
                spec("http://10.0.0.1:80".to_owned(), 5),
                "NON_LOOPBACK_TARGET_REJECTED",
            ),
            (
                spec("https://127.0.0.1:8443".to_owned(), 5),
                "PLAINTEXT_ONLY",
            ),
            (
                BurstSpec {
                    headers: vec![HeaderPair {
                        name: "Host".to_owned(),
                        value: "evil.test".to_owned(),
                    }],
                    ..spec(ok.clone(), 1)
                },
                "INVALID_BURST_SPEC",
            ),
            (
                BurstSpec {
                    headers: vec![HeaderPair {
                        name: "bad name".to_owned(),
                        value: "x".to_owned(),
                    }],
                    ..spec(ok.clone(), 1)
                },
                "INVALID_BURST_SPEC",
            ),
            (
                BurstSpec {
                    idempotency_mode: true,
                    ..spec(ok.clone(), 2)
                },
                "INVALID_BURST_SPEC",
            ),
        ];
        for (spec, code) in cases {
            let target = spec.target.clone();
            let err = run(spec, &hub).await.unwrap_err();
            assert_eq!(err.code(), code, "{target}");
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn barrier_releases_all_workers_together() {
        let arrivals: Arc<Mutex<Vec<Instant>>> = Arc::default();
        let router = Router::new()
            .fallback(
                |State(arrivals): State<Arc<Mutex<Vec<Instant>>>>| async move {
                    arrivals.lock().unwrap().push(Instant::now());
                    "ok"
                },
            )
            .with_state(Arc::clone(&arrivals));
        let addr = serve(router).await;

        let hub = TelemetryHub::new();
        let mut events = hub.subscribe();
        let report = run(
            spec(format!("http://127.0.0.1:{}/ping?n=1", addr.port()), 50),
            &hub,
        )
        .await
        .unwrap();

        assert_eq!(report.samples.len(), 50);
        for sample in &report.samples {
            let ttfb = sample.ttfb_us.expect("responded worker has a ttfb");
            assert!(ttfb <= sample.latency_us, "{sample:?}");
        }
        assert_eq!(
            report.ttfb.map(|t| t.min_us <= t.max_us),
            Some(true),
            "{:?}",
            report.ttfb
        );
        assert_eq!(
            report.status_histogram,
            [StatusBucket {
                status: Some(200),
                count: 50
            }]
        );
        assert!(report.anomalies.is_empty(), "{:?}", report.anomalies);
        assert_eq!(report.distinct_bodies, 1);

        // Loose bounds: CI schedulers and the Windows timer can stall a thread for a full
        // quantum. The point is that dispatch is not serialized behind 50 TCP handshakes.
        let spread = report.dispatch_spread_us.unwrap();
        assert!(spread < 250_000, "dispatch spread {spread} us");
        let arrivals = arrivals.lock().unwrap().clone();
        assert_eq!(arrivals.len(), 50);
        let first = arrivals.iter().min().unwrap();
        let last = arrivals.iter().max().unwrap();
        assert!(last.duration_since(*first) < Duration::from_millis(250));

        let mut started = 0;
        let mut samples = 0;
        let mut completed = 0;
        while let Ok(event) = events.try_recv() {
            match event {
                TelemetryEvent::BurstStarted { workers, .. } => {
                    assert_eq!(workers, 50);
                    started += 1;
                }
                TelemetryEvent::BurstSample { .. } => samples += 1,
                TelemetryEvent::BurstCompleted {
                    anomalies, errors, ..
                } => {
                    assert_eq!((anomalies, errors), (0, 0));
                    completed += 1;
                }
                _ => {}
            }
        }
        assert_eq!((started, samples, completed), (1, 50, 1));
    }

    async fn write_all(stream: &tokio::net::TcpStream, mut bytes: &[u8]) {
        while !bytes.is_empty() {
            stream.writable().await.unwrap();
            match stream.try_write(bytes) {
                Ok(n) => bytes = &bytes[n..],
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(err) => panic!("write failed: {err}"),
            }
        }
    }

    /// Writes the response head as soon as the request head is read, then holds the body
    /// back for `stall`: a handler that commits headers before its slow work.
    async fn serve_split_response(stall: Duration) -> SocketAddr {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                tokio::spawn(async move {
                    let mut seen = Vec::new();
                    let mut buf = [0u8; 1024];
                    while !seen.windows(4).any(|w| w == b"\r\n\r\n") {
                        stream.readable().await.unwrap();
                        match stream.try_read(&mut buf) {
                            Ok(0) => return,
                            Ok(n) => seen.extend_from_slice(&buf[..n]),
                            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {}
                            Err(_) => return,
                        }
                    }
                    write_all(&stream, b"HTTP/1.1 200 OK\r\ncontent-length: 4\r\n\r\n").await;
                    tokio::time::sleep(stall).await;
                    write_all(&stream, b"done").await;
                });
            }
        });
        addr
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn ttfb_separates_the_response_head_from_a_stalled_body() {
        let stall = Duration::from_millis(150);
        let addr = serve_split_response(stall).await;
        let hub = TelemetryHub::new();
        let report = run(
            spec(format!("http://127.0.0.1:{}/slow", addr.port()), 4),
            &hub,
        )
        .await
        .unwrap();

        assert_eq!(
            report.status_histogram,
            [StatusBucket {
                status: Some(200),
                count: 4
            }]
        );
        // The stall sits between head and body, so it must show up in total latency and not
        // in TTFB. 100 ms of the 150 ms stall is the margin left for timer coarseness.
        for sample in &report.samples {
            let ttfb = sample.ttfb_us.unwrap();
            assert!(
                sample.latency_us >= ttfb + 100_000,
                "ttfb {ttfb} us, latency {} us",
                sample.latency_us
            );
            assert_eq!(sample.bytes, 4);
        }
        let (ttfb, latency) = (report.ttfb.unwrap(), report.latency.unwrap());
        assert!(
            latency.p50_us >= ttfb.p50_us + 100_000,
            "{ttfb:?} {latency:?}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn detects_double_spend_against_racy_handler() {
        #[derive(Clone, Default)]
        struct Racy {
            calls: Arc<AtomicUsize>,
            keys_seen: Arc<AtomicUsize>,
        }
        async fn handler(State(racy): State<Racy>, request: Request) -> Response {
            if request.headers().contains_key("idempotency-key") {
                racy.keys_seen.fetch_add(1, Ordering::SeqCst);
            }
            // Two requests pass the check before the first one commits.
            if racy.calls.fetch_add(1, Ordering::SeqCst) < 2 {
                (StatusCode::OK, "charged").into_response()
            } else {
                (StatusCode::CONFLICT, "duplicate").into_response()
            }
        }
        let racy = Racy::default();
        let addr = serve(Router::new().fallback(handler).with_state(racy.clone())).await;

        let hub = TelemetryHub::new();
        let report = run(
            BurstSpec {
                method: BurstMethod::Post,
                headers: vec![HeaderPair {
                    name: "Idempotency-Key".to_owned(),
                    value: "order-42".to_owned(),
                }],
                body: Some(r#"{"amount":100}"#.to_owned()),
                ..spec(format!("localhost:{}/charge", addr.port()), 20)
            },
            &hub,
        )
        .await
        .unwrap();

        assert_eq!(racy.keys_seen.load(Ordering::SeqCst), 20);
        let winners: Vec<u16> = report
            .samples
            .iter()
            .filter(|s| s.status == Some(200))
            .map(|s| s.worker)
            .collect();
        assert_eq!(winners.len(), 2);
        let race = report
            .anomalies
            .iter()
            .find(|a| a.kind == AnomalyKind::RaceWindow)
            .expect("race window anomaly");
        assert_eq!(race.workers, winners);
        assert_eq!(race.severity, Severity::Fault);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn idempotency_mode_sends_one_key_from_every_worker() {
        let keys: Arc<Mutex<Vec<String>>> = Arc::default();
        let router = Router::new()
            .fallback(
                |State(keys): State<Arc<Mutex<Vec<String>>>>, request: Request| async move {
                    let key = request
                        .headers()
                        .get(IDEMPOTENCY_HEADER)
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("-")
                        .to_owned();
                    keys.lock().unwrap().push(key);
                    (StatusCode::CREATED, "order-1")
                },
            )
            .with_state(Arc::clone(&keys));
        let addr = serve(router).await;
        let idempotent = |headers: Vec<HeaderPair>| BurstSpec {
            method: BurstMethod::Post,
            headers,
            idempotency_mode: true,
            ..spec(format!("http://127.0.0.1:{}/checkout", addr.port()), 12)
        };

        let report = run(idempotent(Vec::new()), &TelemetryHub::new())
            .await
            .unwrap();
        let key = report.idempotency_key.clone().unwrap();
        assert!(Uuid::parse_str(&key).is_ok(), "{key}");
        assert!(report.anomalies.is_empty(), "{:?}", report.anomalies);
        let seen = std::mem::take(&mut *keys.lock().unwrap());
        assert_eq!(seen.len(), 12);
        assert!(seen.iter().all(|k| *k == key), "{seen:?}");

        let supplied = vec![HeaderPair {
            name: "Idempotency-Key".to_owned(),
            value: "retry-7".to_owned(),
        }];
        let report = run(idempotent(supplied), &TelemetryHub::new())
            .await
            .unwrap();
        assert_eq!(report.idempotency_key.as_deref(), Some("retry-7"));
        assert!(keys.lock().unwrap().iter().all(|k| k == "retry-7"));
    }

    /// Accepts one connection, records every request byte, and answers once `expected` bytes
    /// have arrived.
    fn serve_recording(listener: TcpListener, expected: usize) -> Arc<Mutex<Vec<u8>>> {
        let received: Arc<Mutex<Vec<u8>>> = Arc::default();
        let log = Arc::clone(&received);
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4096];
            while log.lock().unwrap().len() < expected {
                stream.readable().await.unwrap();
                match stream.try_read(&mut buf) {
                    Ok(0) => return,
                    Ok(n) => log.lock().unwrap().extend_from_slice(&buf[..n]),
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(_) => return,
                }
            }
            write_all(&stream, b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok").await;
            // Held open until the client is done reading.
            tokio::time::sleep(Duration::from_secs(5)).await;
        });
        received
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn last_byte_mode_holds_the_final_byte_until_release() {
        let body = r#"{"code":"LAB-SINGLE-USE"}"#;
        let spec_for = |port: u16| BurstSpec {
            method: BurstMethod::Post,
            body: Some(body.to_owned()),
            sync_mode: Some(BurstSyncMode::LastByte),
            ..spec(format!("http://127.0.0.1:{port}/redeem"), 1)
        };
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let prepared = Arc::new(prepare(&spec_for(port)).unwrap());
        let expected = http1::encode(&prepared.request(1), &prepared.body).len();
        let received = serve_recording(listener, expected);
        let barrier = Arc::new(Barrier::new(2));
        let release = Arc::new(OnceLock::new());
        let worker = tokio::spawn({
            let (prepared, barrier, release) = (
                Arc::clone(&prepared),
                Arc::clone(&barrier),
                Arc::clone(&release),
            );
            async move { last_byte(1, &prepared, &barrier, &release).await }
        });

        let staged = async {
            while received.lock().unwrap().len() < expected - 1 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        };
        tokio::time::timeout(Duration::from_secs(5), staged)
            .await
            .expect("every byte but the last is written before the barrier");
        // The worker is parked at the barrier the test still holds: nothing more can arrive.
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(received.lock().unwrap().len(), expected - 1);

        barrier.wait().await;
        let sample = tokio::time::timeout(Duration::from_secs(5), worker)
            .await
            .unwrap()
            .unwrap()
            .sample;
        assert_eq!(sample.status, Some(200), "{sample:?}");
        assert_eq!(sample.bytes, 2);
        assert_eq!(sample.dispatch_offset_us, Some(0));
        let wire = received.lock().unwrap().clone();
        assert_eq!(wire.len(), expected);
        assert!(wire.ends_with(body.as_bytes()));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn last_byte_burst_delivers_complete_requests() {
        let lengths: Arc<Mutex<Vec<usize>>> = Arc::default();
        let router = Router::new()
            .fallback(
                |State(lengths): State<Arc<Mutex<Vec<usize>>>>, body: Bytes| async move {
                    lengths.lock().unwrap().push(body.len());
                    (StatusCode::CREATED, "made")
                },
            )
            .with_state(Arc::clone(&lengths));
        let addr = serve(router).await;
        let body = r#"{"sku":"LAB-KB-01","quantity":2}"#;
        let report = run(
            BurstSpec {
                method: BurstMethod::Post,
                body: Some(body.to_owned()),
                sync_mode: Some(BurstSyncMode::LastByte),
                ..spec(format!("http://127.0.0.1:{}/orders", addr.port()), 24)
            },
            &TelemetryHub::new(),
        )
        .await
        .unwrap();

        assert_eq!(report.sync_mode, BurstSyncMode::LastByte);
        assert_eq!(
            report.status_histogram,
            [StatusBucket {
                status: Some(201),
                count: 24
            }]
        );
        assert!(report.anomalies.is_empty(), "{:?}", report.anomalies);
        let lengths = lengths.lock().unwrap().clone();
        assert_eq!(lengths.len(), 24);
        assert!(lengths.iter().all(|len| *len == body.len()), "{lengths:?}");
        let spread = report.dispatch_spread_us.unwrap();
        assert!(spread < 250_000, "dispatch spread {spread} us");
        for sample in &report.samples {
            assert!(sample.ttfb_us.unwrap() <= sample.latency_us, "{sample:?}");
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn path_placeholders_are_sent_as_the_default_identifier() {
        let router = Router::new().route(
            "/items/{id}/parts/{part}",
            axum::routing::get(
                |axum::extract::Path((id, part)): axum::extract::Path<(String, String)>| async move {
                    if id == "1" && part == "1" {
                        StatusCode::OK
                    } else {
                        StatusCode::BAD_REQUEST
                    }
                },
            ),
        );
        let addr = serve(router).await;
        let port = addr.port();
        let report = run(
            spec(
                format!("http://127.0.0.1:{port}/items/{{id}}/parts/{{part}}"),
                3,
            ),
            &TelemetryHub::new(),
        )
        .await
        .unwrap();
        assert_eq!(
            report.target,
            format!("http://127.0.0.1:{port}/items/1/parts/1")
        );
        assert_eq!(
            report.status_histogram,
            [StatusBucket {
                status: Some(200),
                count: 3
            }]
        );
    }

    #[tokio::test]
    async fn unreachable_target_completes_without_deadlock() {
        let port = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let hub = TelemetryHub::new();
        let report = tokio::time::timeout(
            CONNECT_TIMEOUT + Duration::from_secs(3),
            run(spec(format!("http://127.0.0.1:{port}"), 10), &hub),
        )
        .await
        .expect("burst must not deadlock on connect failures")
        .unwrap();

        assert_eq!(
            report.status_histogram,
            [StatusBucket {
                status: None,
                count: 10
            }]
        );
        assert!(report.latency.is_none());
        assert_eq!(report.dispatch_spread_us, None);
        assert_eq!(kinds(&report), [AnomalyKind::TransportErrors]);
        assert_eq!(report.anomalies[0].severity, Severity::Fault);
    }
}
