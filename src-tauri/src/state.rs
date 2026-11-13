use std::sync::Arc;
use std::time::Instant;

use reqwest::Client;

use crate::engine::error::EngineResult;
use crate::engine::net;
use crate::telemetry::TelemetryHub;

pub struct AppState {
    pub started_at: Instant,
    pub hub: Arc<TelemetryHub>,
    pub client: Client,
}

impl AppState {
    pub fn new() -> EngineResult<Self> {
        Ok(Self {
            started_at: Instant::now(),
            hub: Arc::new(TelemetryHub::new()),
            client: net::guarded_client()?,
        })
    }
}
