#![forbid(unsafe_code)]

use crate::{
    TangleRuntimeStartupReport,
    config::BaseRelayRuntimeConfig,
    errors::BaseRelayError,
    event_bus::TangleEventBus,
    ops::BaseRelayReadinessState,
    relay::{
        auth::BaseAuthState,
        core::{BaseRelay, BaseRelayShutdownReport},
    },
};
use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    time::Instant,
};
use tokio::sync::watch;

pub struct TangleRuntime {
    config: BaseRelayRuntimeConfig,
    relay: BaseRelay,
    readiness: BaseRelayReadinessState,
    limits: TangleRuntimeLimits,
    event_bus: TangleEventBus,
    metrics: TangleRuntimeMetrics,
    shutdown: TangleShutdownSignal,
}

impl TangleRuntime {
    pub fn open(config: BaseRelayRuntimeConfig) -> Result<Self, BaseRelayError> {
        let limits = TangleRuntimeLimits::from_config(&config)?;
        let relay = config.open_relay()?;
        let readiness = relay.readiness_state();
        Ok(Self {
            config,
            relay,
            readiness,
            event_bus: TangleEventBus::new(limits.event_bus_capacity())?,
            metrics: TangleRuntimeMetrics::new(),
            limits,
            shutdown: TangleShutdownSignal::new(),
        })
    }

    pub fn config(&self) -> &BaseRelayRuntimeConfig {
        &self.config
    }

    pub fn relay(&self) -> &BaseRelay {
        &self.relay
    }

    pub fn relay_mut(&mut self) -> &mut BaseRelay {
        &mut self.relay
    }

    pub fn auth_state(&self) -> Result<BaseAuthState, BaseRelayError> {
        self.config.auth_state()
    }

    pub fn readiness_state(&self) -> &BaseRelayReadinessState {
        &self.readiness
    }

    pub fn limits(&self) -> TangleRuntimeLimits {
        self.limits
    }

    pub fn event_bus(&self) -> &TangleEventBus {
        &self.event_bus
    }

    pub fn metrics(&self) -> &TangleRuntimeMetrics {
        &self.metrics
    }

    pub fn shutdown_signal(&self) -> &TangleShutdownSignal {
        &self.shutdown
    }

    pub fn startup_report(&self) -> TangleRuntimeStartupReport {
        TangleRuntimeStartupReport::new(
            self.config.relay_url(),
            self.config.pocket_config().data_directory().to_path_buf(),
            self.config.groups().enabled(),
            self.readiness.clone(),
        )
    }

    pub fn shutdown(&mut self) -> Result<BaseRelayShutdownReport, BaseRelayError> {
        self.shutdown.request_shutdown();
        self.relay.shutdown()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TangleRuntimeLimits {
    max_pending_events: usize,
    event_bus_capacity: usize,
    outbound_queue_capacity: usize,
}

impl TangleRuntimeLimits {
    pub fn new(
        max_pending_events: usize,
        event_bus_capacity: usize,
        outbound_queue_capacity: usize,
    ) -> Result<Self, BaseRelayError> {
        if max_pending_events == 0 {
            return Err(BaseRelayError::invalid(
                "runtime max pending events must be greater than zero",
            ));
        }
        if event_bus_capacity == 0 {
            return Err(BaseRelayError::invalid(
                "runtime event bus capacity must be greater than zero",
            ));
        }
        if outbound_queue_capacity == 0 {
            return Err(BaseRelayError::invalid(
                "runtime outbound queue capacity must be greater than zero",
            ));
        }
        Ok(Self {
            max_pending_events,
            event_bus_capacity,
            outbound_queue_capacity,
        })
    }

    pub fn from_config(config: &BaseRelayRuntimeConfig) -> Result<Self, BaseRelayError> {
        Self::new(
            config.max_pending_events(),
            config.max_pending_events(),
            config.max_pending_events(),
        )
    }

    pub fn max_pending_events(self) -> usize {
        self.max_pending_events
    }

    pub fn event_bus_capacity(self) -> usize {
        self.event_bus_capacity
    }

    pub fn outbound_queue_capacity(self) -> usize {
        self.outbound_queue_capacity
    }
}

#[derive(Debug, Clone)]
pub struct TangleRuntimeMetrics {
    inner: Arc<TangleRuntimeMetricsInner>,
}

#[derive(Debug)]
struct TangleRuntimeMetricsInner {
    started_at: Instant,
    active_sessions: AtomicUsize,
    stored_event_offsets: AtomicU64,
}

impl TangleRuntimeMetrics {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(TangleRuntimeMetricsInner {
                started_at: Instant::now(),
                active_sessions: AtomicUsize::new(0),
                stored_event_offsets: AtomicU64::new(0),
            }),
        }
    }

    pub fn started_at(&self) -> Instant {
        self.inner.started_at
    }

    pub fn active_sessions(&self) -> usize {
        self.inner.active_sessions.load(Ordering::Relaxed)
    }

    pub fn increment_active_sessions(&self) -> usize {
        self.inner.active_sessions.fetch_add(1, Ordering::Relaxed) + 1
    }

    pub fn decrement_active_sessions(&self) -> usize {
        self.inner.active_sessions.fetch_sub(1, Ordering::Relaxed) - 1
    }

    pub fn stored_event_offsets(&self) -> u64 {
        self.inner.stored_event_offsets.load(Ordering::Relaxed)
    }

    pub fn record_stored_event_offset(&self) -> u64 {
        self.inner
            .stored_event_offsets
            .fetch_add(1, Ordering::Relaxed)
            + 1
    }
}

impl Default for TangleRuntimeMetrics {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct TangleShutdownSignal {
    sender: watch::Sender<bool>,
}

impl TangleShutdownSignal {
    pub fn new() -> Self {
        let (sender, _) = watch::channel(false);
        Self { sender }
    }

    pub fn subscribe(&self) -> watch::Receiver<bool> {
        self.sender.subscribe()
    }

    pub fn request_shutdown(&self) {
        let _ = self.sender.send(true);
    }

    pub fn requested(&self) -> bool {
        *self.sender.borrow()
    }
}

impl Default for TangleShutdownSignal {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::{TangleRuntime, TangleRuntimeLimits};
    use crate::config::{BaseRelayRuntimeConfig, parse_base_relay_runtime_config_json};
    use crate::event_bus::TangleEventBus;
    use serde_json::json;
    use std::path::{Path, PathBuf};
    use tangle_groups::StoreOffset;

    #[test]
    fn tangle_runtime_opens_owned_process_shell_from_config() {
        let root = temp_root("owned-runtime");
        let _ = std::fs::remove_dir_all(&root);
        let config = runtime_config(&root, 8);

        let mut runtime = TangleRuntime::open(config).expect("runtime");
        let mut offsets = runtime.event_bus().subscribe();
        let shutdown = runtime.shutdown_signal().subscribe();

        assert_eq!(runtime.config().relay_url(), "wss://relay.radroots.test");
        assert_eq!(runtime.config().listen_addr().to_string(), "127.0.0.1:0");
        assert_eq!(runtime.limits().max_pending_events(), 8);
        assert_eq!(runtime.limits().event_bus_capacity(), 8);
        assert_eq!(runtime.limits().outbound_queue_capacity(), 8);
        assert_eq!(runtime.event_bus().capacity(), 8);
        assert_eq!(runtime.event_bus().receiver_count(), 1);
        assert_eq!(runtime.metrics().active_sessions(), 0);
        assert_eq!(runtime.metrics().stored_event_offsets(), 0);
        assert!(runtime.relay().groups_enabled());
        assert!(runtime.readiness_state().is_ready());
        assert!(!*shutdown.borrow());

        assert_eq!(runtime.event_bus().publish(StoreOffset::new(42)), 1);
        assert_eq!(offsets.try_recv().expect("offset"), StoreOffset::new(42));
        assert_eq!(
            runtime
                .auth_state()
                .expect("auth")
                .authenticated_pubkeys()
                .len(),
            0
        );
        assert_eq!(
            runtime.startup_report().data_directory(),
            Path::new(&root).join("pocket")
        );

        assert_eq!(runtime.metrics().increment_active_sessions(), 1);
        assert_eq!(runtime.metrics().active_sessions(), 1);
        assert_eq!(runtime.metrics().decrement_active_sessions(), 0);
        assert_eq!(runtime.metrics().active_sessions(), 0);
        assert_eq!(runtime.metrics().record_stored_event_offset(), 1);
        assert_eq!(runtime.metrics().stored_event_offsets(), 1);

        let report = runtime.shutdown().expect("shutdown");

        assert_eq!(report.closed_subscriptions(), 0);
        assert!(runtime.shutdown_signal().requested());
        assert!(*shutdown.borrow());

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn runtime_limits_and_event_bus_reject_zero_capacity() {
        assert!(TangleRuntimeLimits::new(0, 1, 1).is_err());
        assert!(TangleRuntimeLimits::new(1, 0, 1).is_err());
        assert!(TangleRuntimeLimits::new(1, 1, 0).is_err());
        assert!(TangleEventBus::new(0).is_err());
    }

    fn runtime_config(root: &Path, max_pending_events: usize) -> BaseRelayRuntimeConfig {
        let raw = json!({
            "server": {
                "listen_addr": "127.0.0.1:0",
                "relay_url": "wss://relay.radroots.test"
            },
            "pocket": {
                "data_directory": root.join("pocket"),
                "map_size_bytes": 1073741824_u64,
                "reader_slots": 128,
                "sync_policy": "flush_on_shutdown"
            },
            "groups": {
                "enabled": true,
                "canonical_relay_url": "wss://relay.radroots.test",
                "relay_secret": "7777777777777777777777777777777777777777777777777777777777777777",
                "owner_pubkeys": ["0202020202020202020202020202020202020202020202020202020202020202"]
            },
            "auth": {
                "challenge_ttl_seconds": 300
            },
            "limits": {
                "max_pending_events": max_pending_events
            }
        })
        .to_string();
        parse_base_relay_runtime_config_json(&raw).expect("config")
    }

    fn temp_root(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("tangle-runtime-{name}-{}", std::process::id()))
    }
}
