use tauri::ipc::Channel;
use tauri::{State, Webview};
use uuid::Uuid;

use crate::engine::concurrency;
use crate::engine::error::EngineError;
use crate::engine::fault::FaultProfile;
use crate::engine::guard;
use crate::engine::net;
use crate::engine::types::{
    BurstReport, BurstSpec, EngineStatus, ProbeResult, ProxyConfig, ProxyStatus, TelemetryEvent,
    ValidatedTarget, Verdict,
};
use crate::state::AppState;
use crate::telemetry::{now_us, uptime_ms};

#[tauri::command]
pub async fn validate_target(
    state: State<'_, AppState>,
    input: String,
) -> Result<ValidatedTarget, EngineError> {
    let hub = &state.hub;
    let id = Uuid::new_v4();

    let target = match guard::validate_url(&input) {
        Ok(target) => target,
        Err(err) => {
            let host = match &err {
                EngineError::NonLoopbackTargetRejected { host } => Some(host.clone()),
                _ => None,
            };
            tracing::info!(%input, code = err.code(), "guard rejected target");
            hub.publish(TelemetryEvent::GuardDecision {
                seq: hub.next_seq(),
                id,
                ts_us: now_us(),
                input,
                verdict: Verdict::Rejected,
                host,
                code: Some(err.code()),
            });
            return Err(err);
        }
    };

    hub.publish(TelemetryEvent::GuardDecision {
        seq: hub.next_seq(),
        id,
        ts_us: now_us(),
        input: input.clone(),
        verdict: Verdict::Accepted,
        host: Some(target.host.clone()),
        code: None,
    });

    let probe = net::probe(&state.probe_client, &target).await;
    tracing::debug!(url = %target.url, ?probe, "guard accepted target");
    let (status, latency_us, error) = match &probe {
        ProbeResult::Reachable { status, latency_us } => (Some(*status), *latency_us, None),
        ProbeResult::Unreachable { reason, latency_us } => {
            (None, *latency_us, Some(reason.clone()))
        }
    };
    hub.publish(TelemetryEvent::ProbeCompleted {
        seq: hub.next_seq(),
        id,
        ts_us: now_us(),
        url: target.url.to_string(),
        status,
        latency_us,
        error,
    });

    Ok(ValidatedTarget {
        input,
        normalized: target.url.to_string(),
        scheme: target.url.scheme().to_owned(),
        host: target.host,
        host_kind: target.host_kind,
        port: target.port,
        probe,
    })
}

#[tauri::command]
pub async fn get_engine_status(state: State<'_, AppState>) -> Result<EngineStatus, EngineError> {
    Ok(EngineStatus {
        version: env!("CARGO_PKG_VERSION"),
        uptime_ms: uptime_ms(state.started_at),
        telemetry_subscribers: state.hub.subscriber_count(),
        guard_mode: "strict",
        allowlist: guard::ALLOWLIST,
        proxy_listener: state.proxy.status().await.listener,
    })
}

// Tauri requires async commands that borrow `State` to return `Result`, hence the
// infallible `Result` wrappers below.

#[tauri::command]
pub async fn start_proxy(
    state: State<'_, AppState>,
    config: ProxyConfig,
) -> Result<ProxyStatus, EngineError> {
    state.proxy.start(config).await
}

#[tauri::command]
pub async fn stop_proxy(state: State<'_, AppState>) -> Result<ProxyStatus, EngineError> {
    Ok(state.proxy.stop().await)
}

#[tauri::command]
pub async fn get_proxy_status(state: State<'_, AppState>) -> Result<ProxyStatus, EngineError> {
    Ok(state.proxy.status().await)
}

#[tauri::command]
pub async fn set_fault_profile(
    state: State<'_, AppState>,
    armed: bool,
    profile: FaultProfile,
) -> Result<ProxyStatus, EngineError> {
    state.proxy.set_faults(armed, profile).await
}

#[tauri::command]
pub async fn run_concurrency_burst(
    state: State<'_, AppState>,
    spec: BurstSpec,
) -> Result<BurstReport, EngineError> {
    concurrency::run(spec, &state.hub).await
}

#[tauri::command]
pub fn subscribe_telemetry(
    webview: Webview,
    state: State<'_, AppState>,
    on_event: Channel<TelemetryEvent>,
) -> u64 {
    state.hub.attach(webview.label().to_owned(), on_event)
}

#[tauri::command]
pub fn unsubscribe_telemetry(
    webview: Webview,
    state: State<'_, AppState>,
    subscription_id: u64,
) -> bool {
    state.hub.detach(webview.label(), subscription_id)
}
