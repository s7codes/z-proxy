use tauri::ipc::Channel;
use tauri::{State, Webview};
use uuid::Uuid;

use crate::engine::error::EngineError;
use crate::engine::guard;
use crate::engine::net;
use crate::engine::types::{EngineStatus, ProbeResult, TelemetryEvent, ValidatedTarget, Verdict};
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

    let probe = net::probe(&state.client, &target).await;
    tracing::debug!(url = %target.url, ?probe, "guard accepted target");
    let (status, latency_us, error) = match &probe {
        ProbeResult::Reachable { status, latency_us } => (Some(*status), *latency_us, None),
        ProbeResult::Unreachable { reason, latency_us } => (None, *latency_us, Some(reason.clone())),
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
pub fn get_engine_status(state: State<'_, AppState>) -> EngineStatus {
    EngineStatus {
        version: env!("CARGO_PKG_VERSION"),
        uptime_ms: uptime_ms(state.started_at),
        telemetry_subscribers: state.hub.subscriber_count(),
        guard_mode: "strict",
        allowlist: guard::ALLOWLIST,
        proxy_listener: None,
    }
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
