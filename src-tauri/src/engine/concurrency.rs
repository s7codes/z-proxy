//! Barrier-synchronized concurrency burst runner.
//!
//! Each worker opens and handshakes its own HTTP/1.1 connection before the barrier, so the
//! only work left after release is writing the request. Dispatch spread is then bounded by
//! task wake-up latency (microseconds) rather than TCP connect time (milliseconds), which is
//! what makes narrow race windows reproducible.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use axum::body::Bytes;
use axum::http::header::{self, HeaderName, HeaderValue};
use axum::http::Request;
use http_body_util::Full;
use hyper::client::conn::http1::SendRequest;
use tokio::sync::Barrier;
use tokio::task::JoinSet;
use uuid::Uuid;

use super::error::{EngineError, EngineResult};
use super::http1::{self, RequestTemplate, CONNECT_TIMEOUT};
use super::net;
use super::types::{
    Anomaly, AnomalyKind, BurstMethod, BurstReport, BurstSpec, LatencyStats, Severity, SizeStats,
    StatusBucket, TelemetryEvent, WorkerSample,
};
use crate::telemetry::{now_us, TelemetryHub};

pub const MAX_WORKERS: u16 = 100;
const MAX_TIMEOUT_MS: u32 = 60_000;
const USER_AGENT: &str = concat!("chaosproxy-burst/", env!("CARGO_PKG_VERSION"));
const WORKER_HEADER: &str = "x-chaosproxy-burst-worker";

/// Statuses that mean a request lost a uniqueness, precondition or idempotency check.
const CONFLICT_STATUSES: [u16; 6] = [409, 412, 422, 423, 425, 429];

struct Prepared {
    template: RequestTemplate,
    body: Bytes,
    timeout: Duration,
}

impl Prepared {
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
    });
    tracing::info!(%id, target = %prepared.template.label, workers, "concurrency burst started");

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
            Ok(sample) => {
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
            wall_us: net::elapsed_us(started),
        },
        samples,
    );

    let errors = report.samples.iter().filter(|s| s.status.is_none()).count();
    hub.publish(TelemetryEvent::BurstCompleted {
        seq: hub.next_seq(),
        id,
        ts_us: now_us(),
        wall_us: report.wall_us,
        dispatch_spread_us: report.dispatch_spread_us,
        anomalies: count_u32(report.anomalies.len()),
        errors: count_u32(errors),
    });
    tracing::info!(
        %id,
        wall_us = report.wall_us,
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

    Ok(Prepared {
        template: RequestTemplate::new(&spec.target, spec.method, &spec.headers, invalid)?,
        body: spec.body.clone().map(Bytes::from).unwrap_or_default(),
        timeout: Duration::from_millis(u64::from(spec.timeout_ms)),
    })
}

async fn run_worker(
    worker: u16,
    prepared: Arc<Prepared>,
    barrier: Arc<Barrier>,
    release: Arc<OnceLock<Instant>>,
) -> WorkerSample {
    let connection = tokio::time::timeout(CONNECT_TIMEOUT, http1::open(&prepared.template.target))
        .await
        .map_or_else(
            |_| {
                Err(format!(
                    "connect timed out after {} ms",
                    CONNECT_TIMEOUT.as_millis()
                ))
            },
            |opened| opened.map_err(|err| err.to_string()),
        );
    let request = prepared.request(worker);

    // Workers whose connect failed still wait here; skipping the barrier would leave every
    // other worker parked forever.
    barrier.wait().await;

    let mut sender = match connection {
        Ok(sender) => sender,
        Err(error) => return failed(worker, None, 0, error),
    };

    let fired = Instant::now();
    let epoch = *release.get_or_init(|| fired);
    let dispatch_offset_us = Some(duration_us(fired.saturating_duration_since(epoch)));
    let outcome = tokio::time::timeout(prepared.timeout, exchange(&mut sender, request)).await;
    let latency_us = net::elapsed_us(fired);

    match outcome {
        Ok(Ok(received)) => WorkerSample {
            worker,
            status: Some(received.status),
            dispatch_offset_us,
            latency_us,
            bytes: received.bytes,
            body_hash: Some(received.hash),
            error: None,
        },
        Ok(Err(error)) => failed(worker, dispatch_offset_us, latency_us, error),
        Err(_) => failed(
            worker,
            dispatch_offset_us,
            latency_us,
            format!("timed out after {} ms", prepared.timeout.as_millis()),
        ),
    }
}

async fn exchange(
    sender: &mut SendRequest<Full<Bytes>>,
    request: Request<Full<Bytes>>,
) -> Result<http1::Received, String> {
    http1::exchange(sender, request, 0)
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
        latency_us,
        bytes: 0,
        body_hash: None,
        error: Some(error),
    }
}

// ---- analysis -------------------------------------------------------------------------

struct ReportMeta {
    id: Uuid,
    target: String,
    method: BurstMethod,
    workers: u16,
    wall_us: u64,
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

    let anomalies = detect_anomalies(&samples, &by_status);

    BurstReport {
        id: meta.id,
        target: meta.target,
        method: meta.method,
        workers: meta.workers,
        wall_us: meta.wall_us,
        dispatch_spread_us,
        status_histogram,
        latency,
        size,
        distinct_bodies: count_u32(distinct_bodies),
        anomalies,
        samples,
    }
}

fn detect_anomalies(
    samples: &[WorkerSample],
    by_status: &BTreeMap<Option<u16>, Vec<u16>>,
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
    // requests passed the same uniqueness check before either committed.
    if conflicts > 0 && successes.len() > 1 {
        anomalies.push(Anomaly {
            kind: AnomalyKind::RaceWindow,
            severity: Severity::Fault,
            detail: format!(
                "{} of {total} requests succeeded alongside {conflicts} conflict responses; a serialized handler admits at most one",
                successes.len()
            ),
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
        if workers.len() < 2 {
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

    anomalies
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
    use crate::engine::types::HeaderPair;

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
        }
    }

    fn sample(worker: u16, status: Option<u16>, latency_us: u64, hash: &str) -> WorkerSample {
        WorkerSample {
            worker,
            status,
            dispatch_offset_us: status.map(|_| u64::from(worker)),
            latency_us,
            bytes: 10,
            body_hash: status.map(|_| hash.to_owned()),
            error: status.is_none().then(|| "connection refused".to_owned()),
        }
    }

    fn meta(workers: u16) -> ReportMeta {
        ReportMeta {
            id: Uuid::nil(),
            target: "http://127.0.0.1/".to_owned(),
            method: BurstMethod::Post,
            workers,
            wall_us: 1,
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
