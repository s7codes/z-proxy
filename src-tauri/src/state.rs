use std::sync::Arc;
use std::time::Instant;

use reqwest::Client;

use crate::engine::error::EngineResult;
use crate::engine::fuzzer::FuzzerSlot;
use crate::engine::net;
use crate::engine::proxy::ProxyManager;
use crate::telemetry::TelemetryHub;

pub struct AppState {
    pub started_at: Instant,
    pub hub: Arc<TelemetryHub>,
    pub probe_client: Client,
    pub proxy: ProxyManager,
    pub fuzzer: FuzzerSlot,
}

impl AppState {
    pub fn new() -> EngineResult<Self> {
        let hub = Arc::new(TelemetryHub::new());
        Ok(Self {
            started_at: Instant::now(),
            proxy: ProxyManager::new(Arc::clone(&hub))?,
            hub,
            probe_client: net::probe_client()?,
            fuzzer: FuzzerSlot::default(),
        })
    }
}
