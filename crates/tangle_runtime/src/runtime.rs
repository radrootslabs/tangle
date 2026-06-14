#![forbid(unsafe_code)]

use crate::{
    config::BaseRelayRuntimeConfig,
    errors::BaseRelayError,
    ops::BaseRelayReadinessState,
    relay::core::{BaseRelay, BaseRelayShutdownReport},
};
use std::sync::{
    Arc,
    atomic::{AtomicU64, AtomicUsize, Ordering},
};
use tangle_groups::StoreOffset;
use tokio::sync::{broadcast, watch};

pub struct TangleRuntime {
    config: BaseRelayRuntimeConfig,
    relay: BaseRelay,
    readiness: BaseRelayReadinessState,
    limits: TangleRuntimeLimits,
    event_bus: TangleRuntimeEventBus,
    metrics: Arc<TangleRuntimeMetrics>,
    shutdown: TangleShutdownSignal,
}

impl TangleRuntime {
    pub fn open(config: BaseRelayRuntimeConfig) -> Result<Self, BaseRelayError> {
        let limits = TangleRuntimeLimits::from_config(&config);
        let relay = config.open_relay()?;
        let readiness = relay.readiness_state();
        Ok(Self {
            config,
            relay,
            readiness,
            event_bus: TangleRuntimeEventBus::new(limits.event_bus_capacity())?,
            metrics: Arc::new(TangleRuntimeMetrics::default()),
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

    pub fn readiness(&self) -> &BaseRelayReadinessState {
        &self.readiness
    }

    pub fn limits(&self) -> TangleRuntimeLimits {
        self.limits
    }

    pub fn event_bus(&self) -> &TangleRuntimeEventBus {
        &self.event_bus
    }

    pub fn metrics(&self) -> &Arc<TangleRuntimeMetrics> {
        &self.metrics
    }

    pub fn shutdown_signal(&self) -> &TangleShutdownSignal {
        &self.shutdown
    }

    pub fn shutdown(&mut self) -> Result<BaseRelayShutdownReport, BaseRelayError> {
        self.shutdown.request();
        self.relay.shutdown()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TangleRuntimeLimits {
    max_pending_events: usize,
    event_bus_capacity: usize,
}

impl TangleRuntimeLimits {
    pub fn new(max_pending_events: usize) -> Result<Self, BaseRelayError> {
        if max_pending_events == 0 {
            return Err(BaseRelayError::invalid(
                "limits.max_pending_events must be greater than zero",
            ));
        }
        Ok(Self {
            max_pending_events,
            event_bus_capacity: max_pending_events,
        })
    }

    pub fn from_config(config: &BaseRelayRuntimeConfig) -> Self {
        Self::new(config.max_pending_events())
            .expect("runtime config validates pending event limit")
    }

    pub fn max_pending_events(self) -> usize {
        self.max_pending_events
    }

    pub fn event_bus_capacity(self) -> usize {
        self.event_bus_capacity
    }
}

#[derive(Debug, Clone)]
pub struct TangleRuntimeEventBus {
    sender: broadcast::Sender<StoreOffset>,
}

impl TangleRuntimeEventBus {
    pub fn new(capacity: usize) -> Result<Self, BaseRelayError> {
        if capacity == 0 {
            return Err(BaseRelayError::invalid(
                "runtime event bus capacity must be greater than zero",
            ));
        }
        let (sender, _) = broadcast::channel(capacity);
        Ok(Self { sender })
    }

    pub fn subscribe(&self) -> broadcast::Receiver<StoreOffset> {
        self.sender.subscribe()
    }

    pub fn publish(&self, offset: StoreOffset) -> Result<usize, BaseRelayError> {
        self.sender
            .send(offset)
            .map_err(|error| BaseRelayError::error(error.to_string()))
    }

    pub fn receiver_count(&self) -> usize {
        self.sender.receiver_count()
    }
}

#[derive(Debug, Default)]
pub struct TangleRuntimeMetrics {
    active_sessions: AtomicUsize,
    stored_event_offsets: AtomicU64,
}

impl TangleRuntimeMetrics {
    pub fn active_sessions(&self) -> usize {
        self.active_sessions.load(Ordering::Relaxed)
    }

    pub fn stored_event_offsets(&self) -> u64 {
        self.stored_event_offsets.load(Ordering::Relaxed)
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

    pub fn requested(&self) -> bool {
        *self.sender.borrow()
    }

    pub fn request(&self) {
        let _ = self.sender.send(true);
    }
}

impl Default for TangleShutdownSignal {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::{TangleRuntime, TangleRuntimeEventBus, TangleRuntimeLimits};
    use crate::config::parse_base_relay_runtime_config_json;
    use std::{env, fs, process};
    use tangle_groups::StoreOffset;

    #[test]
    fn tangle_runtime_opens_owner_boundary_and_signals_shutdown() {
        let config = runtime_config("owner");
        let mut runtime = TangleRuntime::open(config).expect("runtime");
        let mut offsets = runtime.event_bus().subscribe();
        let shutdown = runtime.shutdown_signal().subscribe();

        assert_eq!(runtime.config().relay_url(), "wss://relay.radroots.test");
        assert_eq!(runtime.limits().max_pending_events(), 8);
        assert_eq!(runtime.limits().event_bus_capacity(), 8);
        assert_eq!(runtime.metrics().active_sessions(), 0);
        assert_eq!(runtime.metrics().stored_event_offsets(), 0);
        assert!(runtime.relay().groups_enabled());
        assert!(runtime.readiness().is_ready());
        assert!(!*shutdown.borrow());

        assert_eq!(
            runtime
                .event_bus()
                .publish(StoreOffset::new(7))
                .expect("publish"),
            1
        );
        assert_eq!(offsets.try_recv().expect("offset"), StoreOffset::new(7));

        let report = runtime.shutdown().expect("shutdown");

        assert_eq!(report.closed_subscriptions(), 0);
        assert!(runtime.shutdown_signal().requested());
        assert!(*shutdown.borrow());
    }

    #[test]
    fn runtime_limits_and_event_bus_reject_zero_capacity() {
        assert!(TangleRuntimeLimits::new(0).is_err());
        assert!(TangleRuntimeEventBus::new(0).is_err());
    }

    fn runtime_config(name: &str) -> crate::config::BaseRelayRuntimeConfig {
        let root = env::temp_dir().join(format!("tangle-runtime-{name}-{}", process::id()));
        let _ = fs::remove_dir_all(&root);
        parse_base_relay_runtime_config_json(&format!(
            r#"{{
                "server": {{
                    "listen_addr": "127.0.0.1:0",
                    "relay_url": "wss://relay.radroots.test"
                }},
                "pocket": {{
                    "data_directory": "{}",
                    "map_size_bytes": 10485760,
                    "reader_slots": 32,
                    "sync_policy": "flush_on_shutdown"
                }},
                "groups": {{
                    "enabled": true,
                    "canonical_relay_url": "wss://relay.radroots.test",
                    "relay_secret": "{}",
                    "owner_pubkeys": ["{}"]
                }},
                "auth": {{
                    "challenge_ttl_seconds": 300
                }},
                "limits": {{
                    "max_pending_events": 8
                }}
            }}"#,
            root.join("pocket").display(),
            "7".repeat(64),
            "02".repeat(32)
        ))
        .expect("config")
    }
}
