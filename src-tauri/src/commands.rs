use tauri::ipc::Channel;
use tauri::{State, Webview, WebviewWindow};
use tauri_plugin_dialog::DialogExt;
use uuid::Uuid;

use crate::engine::concurrency;
use crate::engine::error::EngineError;
use crate::engine::fault::{FaultProfile, FaultRule};
use crate::engine::fuzzer;
use crate::engine::guard;
use crate::engine::lab;
use crate::engine::net;
use crate::engine::types::{
    BurstReport, BurstSpec, EngineStatus, FuzzCasePayload, FuzzCaseRef, FuzzReport, FuzzSpec,
    LabConfig, LabMode, LabStatus, ProbeResult, ProxyConfig, ProxyStatus, ReportFormat,
    RouteScanReport, TelemetryEvent, ValidatedTarget, Verdict,
};
use crate::report;
use crate::scanner::routes;
use crate::state::AppState;
use crate::telemetry::{now_us, uptime_ms};

/// Root label of the lab's route report; it has no directory on disk.
const LAB_ROOT: &str = "target-lab";

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

/// Replaces the route rule set; rules apply while faults are armed, first match first.
#[tauri::command]
pub async fn set_fault_rules(
    state: State<'_, AppState>,
    rules: Vec<FaultRule>,
) -> Result<ProxyStatus, EngineError> {
    state.proxy.set_rules(rules).await
}

#[tauri::command]
pub async fn run_concurrency_burst(
    state: State<'_, AppState>,
    spec: BurstSpec,
) -> Result<BurstReport, EngineError> {
    concurrency::run(spec, &state.hub).await
}

#[tauri::command]
pub async fn run_fuzzer_suite(
    state: State<'_, AppState>,
    spec: FuzzSpec,
) -> Result<FuzzReport, EngineError> {
    fuzzer::run(spec, &state.hub, &state.fuzzer).await
}

/// Rebuilds one case's request body for replay in the burst runner or as a new base payload.
#[tauri::command]
pub async fn materialize_fuzz_case(reference: FuzzCaseRef) -> Result<FuzzCasePayload, EngineError> {
    fuzzer::materialize(&reference)
}

/// Resolves `true` when a running suite was asked to stop; it ends after the in-flight case.
#[tauri::command]
pub async fn cancel_fuzzer_suite(state: State<'_, AppState>) -> Result<bool, EngineError> {
    Ok(state.fuzzer.cancel())
}

#[tauri::command]
pub async fn scan_project_routes(
    state: State<'_, AppState>,
    root: String,
) -> Result<RouteScanReport, EngineError> {
    // Directory walking and file reads are blocking I/O; keep them off the async workers
    // that drive the proxy and telemetry fan-out.
    let report = tokio::task::spawn_blocking(move || routes::scan(&root))
        .await
        .map_err(|err| EngineError::InternalTask {
            reason: format!("route scan aborted: {err}"),
        })??;

    let hub = &state.hub;
    hub.publish(TelemetryEvent::RouteScanCompleted {
        seq: hub.next_seq(),
        id: report.id,
        ts_us: now_us(),
        root: report.root.clone(),
        routes: u32::try_from(report.routes.len()).unwrap_or(u32::MAX),
        files_visited: report.files_visited,
        elapsed_us: report.elapsed_us,
        truncated: report.truncated,
    });
    tracing::info!(
        root = %report.root,
        routes = report.routes.len(),
        files = report.files_visited,
        elapsed_us = report.elapsed_us,
        "route scan completed"
    );
    Ok(report)
}

#[tauri::command]
pub async fn start_lab_server(
    state: State<'_, AppState>,
    config: LabConfig,
) -> Result<LabStatus, EngineError> {
    state.lab.start(config).await
}

#[tauri::command]
pub async fn stop_lab_server(state: State<'_, AppState>) -> Result<LabStatus, EngineError> {
    Ok(state.lab.stop().await)
}

/// Takes effect on the next request without a restart; clears the coupon ledger.
#[tauri::command]
pub async fn set_lab_mode(
    state: State<'_, AppState>,
    mode: LabMode,
) -> Result<LabStatus, EngineError> {
    Ok(state.lab.set_mode(mode).await)
}

#[tauri::command]
pub async fn reset_lab_state(state: State<'_, AppState>) -> Result<LabStatus, EngineError> {
    Ok(state.lab.reset().await)
}

#[tauri::command]
pub async fn get_lab_status(state: State<'_, AppState>) -> Result<LabStatus, EngineError> {
    Ok(state.lab.status().await)
}

/// The lab's routes, parsed from the OpenAPI document it serves, so the route list and the
/// request panels treat it like any scanned project.
#[tauri::command]
pub async fn get_lab_routes(state: State<'_, AppState>) -> Result<RouteScanReport, EngineError> {
    let status = state.lab.status().await;
    let document = lab::openapi_document(status.base_url.as_deref());
    Ok(routes::spec_report(LAB_ROOT, lab::SPEC_FILE, &document))
}

/// Native folder picker. Opened from Rust so the webview needs no `dialog:*` capability;
/// cancelling resolves to `None`.
#[tauri::command]
pub async fn pick_project_root(window: WebviewWindow) -> Result<Option<String>, EngineError> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    window
        .dialog()
        .file()
        .set_parent(&window)
        .set_title("Select project root")
        .pick_folder(move |picked| {
            // The receiver is only gone if the command future was dropped; nothing to report.
            let _ = tx.send(picked);
        });
    let picked = rx.await.map_err(|_| EngineError::InternalTask {
        reason: "folder dialog closed without a result".to_owned(),
    })?;
    Ok(picked
        .and_then(|path| path.into_path().ok())
        .map(|path| routes::display_path(&path)))
}

/// Native save dialog for an audit report the UI rendered; writes it and resolves to the
/// written path, or `None` when the operator cancels.
#[tauri::command]
pub async fn save_audit_report(
    window: WebviewWindow,
    format: ReportFormat,
    file_name: String,
    contents: String,
) -> Result<Option<String>, EngineError> {
    report::check_size(&contents)?;
    let (tx, rx) = tokio::sync::oneshot::channel();
    window
        .dialog()
        .file()
        .set_parent(&window)
        .set_title("Export audit report")
        .set_file_name(report::file_name(format, &file_name))
        .add_filter(format.filter_label(), &[format.extension()])
        .save_file(move |picked| {
            // The receiver is only gone if the command future was dropped; nothing to report.
            let _ = tx.send(picked);
        });
    let picked = rx.await.map_err(|_| EngineError::InternalTask {
        reason: "save dialog closed without a result".to_owned(),
    })?;
    let Some(path) = picked.and_then(|path| path.into_path().ok()) else {
        return Ok(None);
    };
    let shown = routes::display_path(&path);
    // Synchronous file I/O stays off the async runtime's worker threads.
    tokio::task::spawn_blocking(move || report::write(&path, contents.as_bytes()))
        .await
        .map_err(|err| EngineError::InternalTask {
            reason: err.to_string(),
        })??;
    tracing::info!(path = %shown, "audit report exported");
    Ok(Some(shown))
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
