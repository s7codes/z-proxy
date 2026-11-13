mod commands;
mod engine;
mod state;
mod telemetry;

use tauri::Manager;
use tracing_subscriber::EnvFilter;

use crate::state::AppState;

pub fn run() {
    init_tracing();

    let result = tauri::Builder::default()
        .setup(|app| {
            let state = AppState::new()?;
            let hub = state.hub.clone();
            let started_at = state.started_at;
            app.manage(state);
            tauri::async_runtime::spawn(telemetry::run_heartbeat(hub, started_at));
            tracing::info!(allowlist = ?engine::guard::ALLOWLIST, "engine started");
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::validate_target,
            commands::get_engine_status,
            commands::subscribe_telemetry,
            commands::unsubscribe_telemetry,
        ])
        .run(tauri::generate_context!());

    if let Err(err) = result {
        tracing::error!(error = %err, "tauri runtime terminated");
        std::process::exit(1);
    }
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("warn,chaosproxy_lib=info"));
    if let Err(err) = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .try_init()
    {
        eprintln!("tracing subscriber already installed: {err}");
    }
}
