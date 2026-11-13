//! Telemetry fan-out from the engine to webview `Channel`s.
//!
//! A single `broadcast` sender decouples producers from IPC: producers never block on a slow
//! webview, and a lagging subscriber drops its oldest events instead of growing memory.
//! Subscriptions are keyed by webview label so a page reload or React StrictMode re-mount
//! replaces the previous forwarder instead of leaking it.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tauri::async_runtime::{self, JoinHandle};
use tauri::ipc::Channel;
use tokio::sync::broadcast::{self, error::RecvError};
use tokio::time::MissedTickBehavior;

use crate::engine::types::TelemetryEvent;

const BUFFER: usize = 4096;
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(1);

struct Subscription {
    id: u64,
    task: JoinHandle<()>,
}

pub struct TelemetryHub {
    tx: broadcast::Sender<TelemetryEvent>,
    seq: AtomicU64,
    next_subscription: AtomicU64,
    subscriptions: Mutex<HashMap<String, Subscription>>,
}

impl TelemetryHub {
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(BUFFER);
        Self {
            tx,
            seq: AtomicU64::new(0),
            next_subscription: AtomicU64::new(1),
            subscriptions: Mutex::new(HashMap::new()),
        }
    }

    pub fn next_seq(&self) -> u64 {
        self.seq.fetch_add(1, Ordering::Relaxed) + 1
    }

    pub fn publish(&self, event: TelemetryEvent) {
        // `send` only fails when there are no receivers, which is a normal idle state.
        let _ = self.tx.send(event);
    }

    pub fn subscriber_count(&self) -> u32 {
        u32::try_from(self.lock().len()).unwrap_or(u32::MAX)
    }

    pub fn attach(&self, owner: String, channel: Channel<TelemetryEvent>) -> u64 {
        let id = self.next_subscription.fetch_add(1, Ordering::Relaxed);
        let mut rx = self.tx.subscribe();
        let label = owner.clone();

        let task = async_runtime::spawn(async move {
            loop {
                match rx.recv().await {
                    Ok(event) => {
                        if let TelemetryEvent::EngineHeartbeat { seq, .. } = &event {
                            tracing::trace!(webview = %label, seq, "heartbeat forwarded");
                        }
                        if let Err(err) = channel.send(event) {
                            tracing::debug!(webview = %label, error = %err, "telemetry channel closed");
                            break;
                        }
                    }
                    Err(RecvError::Lagged(skipped)) => {
                        tracing::warn!(webview = %label, skipped, "telemetry subscriber lagged");
                    }
                    Err(RecvError::Closed) => break,
                }
            }
        });

        tracing::debug!(webview = %owner, subscription = id, "telemetry subscriber attached");
        if let Some(previous) = self.lock().insert(owner, Subscription { id, task }) {
            previous.task.abort();
        }
        id
    }

    pub fn detach(&self, owner: &str, id: u64) -> bool {
        let mut subs = self.lock();
        // Only remove when ids match: a stale unsubscribe from an earlier mount must not
        // tear down the subscription that replaced it.
        if subs.get(owner).is_some_and(|sub| sub.id == id) {
            if let Some(sub) = subs.remove(owner) {
                sub.task.abort();
            }
            return true;
        }
        false
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<String, Subscription>> {
        self.subscriptions
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }
}

pub fn now_us() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_micros()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

pub fn uptime_ms(started_at: Instant) -> u64 {
    u64::try_from(started_at.elapsed().as_millis()).unwrap_or(u64::MAX)
}

pub async fn run_heartbeat(hub: std::sync::Arc<TelemetryHub>, started_at: Instant) {
    let mut ticker = tokio::time::interval(HEARTBEAT_INTERVAL);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        ticker.tick().await;
        hub.publish(TelemetryEvent::EngineHeartbeat {
            seq: hub.next_seq(),
            ts_us: now_us(),
            uptime_ms: uptime_ms(started_at),
            subscribers: hub.subscriber_count(),
        });
    }
}
