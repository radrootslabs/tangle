#![forbid(unsafe_code)]

use crate::{
    config::{TangleHostLimitsConfig, TangleHostRuntimeConfigSet, TenantRuntimeConfig},
    errors::BaseRelayError,
    ops::BaseRelayReadinessCheckStatus,
    runtime::{TangleShutdownSignal, TenantRuntime, TenantRuntimeHandle},
    tenant::{CanonicalHost, TenantId, TenantRelayUrl, TenantSchema},
};
use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

#[derive(Debug, Clone)]
pub struct TangleHostRuntime {
    config: TangleHostRuntimeConfigSet,
    registry: TenantRegistry,
    resources: TangleHostResourceLimiter,
    shutdown: TangleShutdownSignal,
}

impl TangleHostRuntime {
    pub fn open(config: TangleHostRuntimeConfigSet) -> Result<Self, BaseRelayError> {
        let resources = TangleHostResourceLimiter::new(config.host().limits());
        let registry = TenantRegistry::open(&config)?;
        Ok(Self {
            config,
            registry,
            resources,
            shutdown: TangleShutdownSignal::new(),
        })
    }

    pub fn config(&self) -> &TangleHostRuntimeConfigSet {
        &self.config
    }

    pub fn registry(&self) -> &TenantRegistry {
        &self.registry
    }

    pub fn resources(&self) -> TangleHostResourceLimiter {
        self.resources.clone()
    }

    pub fn shutdown_signal(&self) -> &TangleShutdownSignal {
        &self.shutdown
    }

    pub fn readiness_state(&self) -> TangleHostReadinessState {
        TangleHostReadinessState::new(
            BaseRelayReadinessCheckStatus::Ready,
            registry_ready(self.registry.active_tenant_count()),
            active_tenants_ready(&self.registry),
            self.shutdown.requested(),
        )
    }

    pub fn metrics_snapshot(&self) -> TangleHostMetricsSnapshot {
        TangleHostMetricsSnapshot::new(
            self.config.tenants().len(),
            self.registry.active_tenant_count(),
            self.config
                .tenants()
                .iter()
                .filter(|tenant| tenant.inactive())
                .count(),
            self.resources.active_connections(),
            self.resources.active_subscriptions(),
            self.config.host().limits().max_total_connections(),
            self.config.host().limits().max_total_subscriptions(),
        )
    }

    pub async fn shutdown(&self) -> Result<TangleHostShutdownReport, BaseRelayError> {
        self.shutdown.request_shutdown();
        let mut closed_subscriptions = 0;
        for tenant in self.registry.active_tenants() {
            closed_subscriptions += tenant.runtime().shutdown().await?.closed_subscriptions();
        }
        Ok(TangleHostShutdownReport::new(
            self.registry.active_tenant_count(),
            closed_subscriptions,
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TangleHostReadinessState {
    config: BaseRelayReadinessCheckStatus,
    tenant_registry: BaseRelayReadinessCheckStatus,
    active_tenants: BaseRelayReadinessCheckStatus,
    shutdown_requested: bool,
}

impl TangleHostReadinessState {
    pub fn new(
        config: BaseRelayReadinessCheckStatus,
        tenant_registry: BaseRelayReadinessCheckStatus,
        active_tenants: BaseRelayReadinessCheckStatus,
        shutdown_requested: bool,
    ) -> Self {
        Self {
            config,
            tenant_registry,
            active_tenants,
            shutdown_requested,
        }
    }

    pub fn is_ready(&self) -> bool {
        !self.shutdown_requested
            && self.config.is_ready()
            && self.tenant_registry.is_ready()
            && self.active_tenants.is_ready()
    }

    pub fn config(&self) -> BaseRelayReadinessCheckStatus {
        self.config
    }

    pub fn tenant_registry(&self) -> BaseRelayReadinessCheckStatus {
        self.tenant_registry
    }

    pub fn active_tenants(&self) -> BaseRelayReadinessCheckStatus {
        self.active_tenants
    }

    pub fn shutdown_requested(&self) -> bool {
        self.shutdown_requested
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TangleHostMetricsSnapshot {
    configured_tenants: usize,
    active_tenants: usize,
    inactive_tenants: usize,
    active_connections: usize,
    active_subscriptions: usize,
    max_total_connections: usize,
    max_total_subscriptions: usize,
}

impl TangleHostMetricsSnapshot {
    pub fn new(
        configured_tenants: usize,
        active_tenants: usize,
        inactive_tenants: usize,
        active_connections: usize,
        active_subscriptions: usize,
        max_total_connections: usize,
        max_total_subscriptions: usize,
    ) -> Self {
        Self {
            configured_tenants,
            active_tenants,
            inactive_tenants,
            active_connections,
            active_subscriptions,
            max_total_connections,
            max_total_subscriptions,
        }
    }

    pub fn configured_tenants(&self) -> usize {
        self.configured_tenants
    }

    pub fn active_tenants(&self) -> usize {
        self.active_tenants
    }

    pub fn inactive_tenants(&self) -> usize {
        self.inactive_tenants
    }

    pub fn active_connections(&self) -> usize {
        self.active_connections
    }

    pub fn active_subscriptions(&self) -> usize {
        self.active_subscriptions
    }

    pub fn max_total_connections(&self) -> usize {
        self.max_total_connections
    }

    pub fn max_total_subscriptions(&self) -> usize {
        self.max_total_subscriptions
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TangleHostShutdownReport {
    tenants_shutdown: usize,
    closed_subscriptions: usize,
}

impl TangleHostShutdownReport {
    pub fn new(tenants_shutdown: usize, closed_subscriptions: usize) -> Self {
        Self {
            tenants_shutdown,
            closed_subscriptions,
        }
    }

    pub fn tenants_shutdown(&self) -> usize {
        self.tenants_shutdown
    }

    pub fn closed_subscriptions(&self) -> usize {
        self.closed_subscriptions
    }
}

#[derive(Debug, Clone)]
pub struct TenantRegistry {
    tenants_by_host: BTreeMap<CanonicalHost, TenantRuntimeEntry>,
    host_by_tenant_id: BTreeMap<TenantId, CanonicalHost>,
}

impl TenantRegistry {
    pub fn open(config: &TangleHostRuntimeConfigSet) -> Result<Self, BaseRelayError> {
        let mut entries = Vec::new();
        let concurrency = config.host().limits().tenant_startup_concurrency();
        let active_tenants = config.active_tenants().cloned().collect::<Vec<_>>();
        for chunk in active_tenants.chunks(concurrency) {
            for tenant in chunk {
                entries.push(open_tenant_runtime(config, tenant)?);
            }
        }
        Self::new(entries)
    }

    pub fn new(entries: Vec<TenantRuntimeEntry>) -> Result<Self, BaseRelayError> {
        let mut tenants_by_host = BTreeMap::new();
        let mut host_by_tenant_id = BTreeMap::new();
        for entry in entries {
            if tenants_by_host.contains_key(entry.host()) {
                return Err(BaseRelayError::invalid(format!(
                    "duplicate active tenant host: {}",
                    entry.host()
                )));
            }
            if host_by_tenant_id
                .insert(entry.tenant_id().clone(), entry.host().clone())
                .is_some()
            {
                return Err(BaseRelayError::invalid(format!(
                    "duplicate active tenant id: {}",
                    entry.tenant_id()
                )));
            }
            tenants_by_host.insert(entry.host().clone(), entry);
        }
        Ok(Self {
            tenants_by_host,
            host_by_tenant_id,
        })
    }

    pub fn active_tenant_count(&self) -> usize {
        self.tenants_by_host.len()
    }

    pub fn active_tenants(&self) -> impl Iterator<Item = &TenantRuntimeEntry> {
        self.tenants_by_host.values()
    }

    pub fn tenant_by_host(&self, host: &CanonicalHost) -> Option<&TenantRuntimeEntry> {
        self.tenants_by_host.get(host)
    }

    pub fn tenant_by_id(&self, tenant_id: &TenantId) -> Option<&TenantRuntimeEntry> {
        self.host_by_tenant_id
            .get(tenant_id)
            .and_then(|host| self.tenants_by_host.get(host))
    }
}

#[derive(Clone)]
pub struct TenantRuntimeEntry {
    config: TenantRuntimeConfig,
    runtime: TenantRuntimeHandle,
}

impl TenantRuntimeEntry {
    pub fn new(config: TenantRuntimeConfig, runtime: TenantRuntimeHandle) -> Self {
        Self { config, runtime }
    }

    pub fn config(&self) -> &TenantRuntimeConfig {
        &self.config
    }

    pub fn tenant_id(&self) -> &TenantId {
        self.config.tenant_id()
    }

    pub fn tenant_schema(&self) -> &TenantSchema {
        self.config.tenant_schema()
    }

    pub fn host(&self) -> &CanonicalHost {
        self.config.host()
    }

    pub fn relay_url(&self) -> &TenantRelayUrl {
        self.config.relay_url()
    }

    pub fn runtime(&self) -> &TenantRuntimeHandle {
        &self.runtime
    }
}

impl std::fmt::Debug for TenantRuntimeEntry {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TenantRuntimeEntry")
            .field("tenant_id", self.tenant_id())
            .field("tenant_schema", self.tenant_schema())
            .field("host", self.host())
            .field("relay_url", self.relay_url())
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone)]
pub struct TangleHostResourceLimiter {
    inner: Arc<TangleHostResourceLimiterInner>,
}

#[derive(Debug)]
struct TangleHostResourceLimiterInner {
    max_total_connections: usize,
    max_total_subscriptions: usize,
    active_connections: AtomicUsize,
    active_subscriptions: AtomicUsize,
}

impl TangleHostResourceLimiter {
    pub fn new(limits: TangleHostLimitsConfig) -> Self {
        Self {
            inner: Arc::new(TangleHostResourceLimiterInner {
                max_total_connections: limits.max_total_connections(),
                max_total_subscriptions: limits.max_total_subscriptions(),
                active_connections: AtomicUsize::new(0),
                active_subscriptions: AtomicUsize::new(0),
            }),
        }
    }

    pub fn try_open_connection(&self) -> Result<TangleHostConnectionPermit, BaseRelayError> {
        increment_with_limit(
            &self.inner.active_connections,
            1,
            self.inner.max_total_connections,
            "host total connection limit exceeded",
        )?;
        Ok(TangleHostConnectionPermit {
            resources: self.inner.clone(),
            released: false,
        })
    }

    pub fn try_open_subscriptions(
        &self,
        count: usize,
    ) -> Result<TangleHostSubscriptionPermit, BaseRelayError> {
        if count == 0 {
            return Err(BaseRelayError::invalid(
                "subscription reservation count must be greater than zero",
            ));
        }
        increment_with_limit(
            &self.inner.active_subscriptions,
            count,
            self.inner.max_total_subscriptions,
            "host total subscription limit exceeded",
        )?;
        Ok(TangleHostSubscriptionPermit {
            resources: self.inner.clone(),
            count,
            released: false,
        })
    }

    pub fn active_connections(&self) -> usize {
        self.inner.active_connections.load(Ordering::Relaxed)
    }

    pub fn active_subscriptions(&self) -> usize {
        self.inner.active_subscriptions.load(Ordering::Relaxed)
    }

    pub fn max_total_connections(&self) -> usize {
        self.inner.max_total_connections
    }

    pub fn max_total_subscriptions(&self) -> usize {
        self.inner.max_total_subscriptions
    }
}

#[derive(Debug)]
pub struct TangleHostConnectionPermit {
    resources: Arc<TangleHostResourceLimiterInner>,
    released: bool,
}

impl TangleHostConnectionPermit {
    pub fn release(mut self) {
        self.release_inner();
    }

    fn release_inner(&mut self) {
        if !self.released {
            self.resources
                .active_connections
                .fetch_sub(1, Ordering::Relaxed);
            self.released = true;
        }
    }
}

impl Drop for TangleHostConnectionPermit {
    fn drop(&mut self) {
        self.release_inner();
    }
}

#[derive(Debug)]
pub struct TangleHostSubscriptionPermit {
    resources: Arc<TangleHostResourceLimiterInner>,
    count: usize,
    released: bool,
}

impl TangleHostSubscriptionPermit {
    pub fn release(mut self) {
        self.release_inner();
    }

    fn release_inner(&mut self) {
        if !self.released {
            self.resources
                .active_subscriptions
                .fetch_sub(self.count, Ordering::Relaxed);
            self.released = true;
        }
    }
}

impl Drop for TangleHostSubscriptionPermit {
    fn drop(&mut self) {
        self.release_inner();
    }
}

fn open_tenant_runtime(
    config: &TangleHostRuntimeConfigSet,
    tenant: &TenantRuntimeConfig,
) -> Result<TenantRuntimeEntry, BaseRelayError> {
    let runtime_config = tenant
        .to_base_relay_runtime_config(config.host().listen_addr(), config.host().tracing().clone());
    let runtime = TenantRuntime::open(runtime_config).map_err(|error| {
        BaseRelayError::error(format!(
            "failed to open active tenant `{}`: {}",
            tenant.tenant_id(),
            error.prefixed_message()
        ))
    })?;
    Ok(TenantRuntimeEntry::new(
        tenant.clone(),
        TenantRuntimeHandle::new(runtime),
    ))
}

fn registry_ready(active_tenant_count: usize) -> BaseRelayReadinessCheckStatus {
    if active_tenant_count == 0 {
        BaseRelayReadinessCheckStatus::NotReady
    } else {
        BaseRelayReadinessCheckStatus::Ready
    }
}

fn active_tenants_ready(registry: &TenantRegistry) -> BaseRelayReadinessCheckStatus {
    if registry
        .active_tenants()
        .all(|tenant| tenant.runtime().readiness_handle().snapshot().is_ready())
    {
        BaseRelayReadinessCheckStatus::Ready
    } else {
        BaseRelayReadinessCheckStatus::NotReady
    }
}

fn increment_with_limit(
    counter: &AtomicUsize,
    amount: usize,
    limit: usize,
    message: &'static str,
) -> Result<(), BaseRelayError> {
    let mut current = counter.load(Ordering::Relaxed);
    loop {
        let Some(next) = current.checked_add(amount) else {
            return Err(BaseRelayError::restricted(message));
        };
        if next > limit {
            return Err(BaseRelayError::restricted(message));
        }
        match counter.compare_exchange(current, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return Ok(()),
            Err(actual) => current = actual,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{TangleHostResourceLimiter, TangleHostRuntime};
    use crate::{
        config::{
            TangleHostLimitsConfig, TangleHostRuntimeConfigSet,
            parse_tangle_host_runtime_config_json, parse_tenant_runtime_config_json,
        },
        ops::BaseRelayReadinessCheckStatus,
        tenant::{CanonicalHost, TenantId},
    };
    use serde_json::json;
    use std::{
        fs,
        path::{Path, PathBuf},
        time::{SystemTime, UNIX_EPOCH},
    };
    use tangle_test_support::FixtureKey;

    #[test]
    fn host_runtime_opens_two_active_tenants_with_distinct_serving_maps() {
        let root = temp_root("two-active-tenants");
        let _ = fs::remove_dir_all(&root);
        let config = config_set(
            &root,
            vec![
                tenant_config(&root, "alpha", "alpha_schema", "alpha.relay.test", false, 9),
                tenant_config(&root, "beta", "beta_schema", "beta.relay.test", false, 10),
            ],
        );

        let host = TangleHostRuntime::open(config).expect("host");
        let alpha_host = CanonicalHost::new("alpha.relay.test").expect("alpha host");
        let beta_id = TenantId::new("beta").expect("beta id");

        assert_eq!(host.registry().active_tenant_count(), 2);
        assert_eq!(
            host.registry()
                .tenant_by_host(&alpha_host)
                .expect("alpha")
                .tenant_id()
                .as_str(),
            "alpha"
        );
        assert_eq!(
            host.registry()
                .tenant_by_id(&beta_id)
                .expect("beta")
                .host()
                .as_str(),
            "beta.relay.test"
        );
        assert!(root.join("alpha/pocket").exists());
        assert!(root.join("beta/pocket").exists());
        assert_eq!(host.metrics_snapshot().configured_tenants(), 2);
        assert_eq!(host.metrics_snapshot().active_tenants(), 2);
        assert_eq!(host.metrics_snapshot().inactive_tenants(), 0);

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn inactive_tenants_validate_without_serving_or_storage() {
        let root = temp_root("inactive-tenant");
        let _ = fs::remove_dir_all(&root);
        let config = config_set(
            &root,
            vec![
                tenant_config(
                    &root,
                    "active",
                    "active_schema",
                    "active.relay.test",
                    false,
                    9,
                ),
                tenant_config(
                    &root,
                    "inactive",
                    "inactive_schema",
                    "inactive.relay.test",
                    true,
                    10,
                ),
            ],
        );

        let host = TangleHostRuntime::open(config).expect("host");
        let inactive_host = CanonicalHost::new("inactive.relay.test").expect("inactive host");
        let inactive_id = TenantId::new("inactive").expect("inactive id");
        let active_id = TenantId::new("active").expect("active id");

        assert_eq!(host.registry().active_tenant_count(), 1);
        assert!(host.registry().tenant_by_host(&inactive_host).is_none());
        assert!(host.registry().tenant_by_id(&inactive_id).is_none());
        assert!(host.registry().tenant_by_id(&active_id).is_some());
        assert!(!root.join("inactive/pocket").exists());
        assert_eq!(host.metrics_snapshot().configured_tenants(), 2);
        assert_eq!(host.metrics_snapshot().inactive_tenants(), 1);

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn active_tenant_open_failure_fails_host_startup() {
        let root = temp_root("active-open-failure");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).expect("root");
        fs::write(root.join("broken-pocket"), "not a directory").expect("file");
        let config = config_set(
            &root,
            vec![tenant_config_with_pocket_path(
                &root,
                "broken",
                "broken_schema",
                "broken.relay.test",
                false,
                9,
                root.join("broken-pocket"),
            )],
        );

        let error = TangleHostRuntime::open(config).expect_err("open failure");
        assert!(error.message().contains("failed to open active tenant"));
        assert!(error.message().contains("broken"));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn host_readiness_requires_all_active_tenants_and_ignores_inactive_tenants() {
        let root = temp_root("host-readiness");
        let _ = fs::remove_dir_all(&root);
        let config = config_set(
            &root,
            vec![
                tenant_config(&root, "alpha", "alpha_schema", "alpha-ready.test", false, 9),
                tenant_config(&root, "beta", "beta_schema", "beta-ready.test", false, 10),
                tenant_config(
                    &root,
                    "paused",
                    "paused_schema",
                    "paused-ready.test",
                    true,
                    11,
                ),
            ],
        );
        let host = TangleHostRuntime::open(config).expect("host");
        let alpha = TenantId::new("alpha").expect("alpha id");
        let beta = TenantId::new("beta").expect("beta id");

        assert!(!host.readiness_state().is_ready());
        host.registry()
            .tenant_by_id(&alpha)
            .expect("alpha")
            .runtime()
            .readiness_handle()
            .set_server_bind(BaseRelayReadinessCheckStatus::Ready);
        assert!(!host.readiness_state().is_ready());
        host.registry()
            .tenant_by_id(&beta)
            .expect("beta")
            .runtime()
            .readiness_handle()
            .set_server_bind(BaseRelayReadinessCheckStatus::Ready);
        let readiness = host.readiness_state();
        assert!(readiness.is_ready());
        assert_eq!(
            readiness.active_tenants(),
            BaseRelayReadinessCheckStatus::Ready
        );

        let _ = fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn host_shutdown_drains_all_active_tenant_runtimes() {
        let root = temp_root("host-shutdown");
        let _ = fs::remove_dir_all(&root);
        let config = config_set(
            &root,
            vec![
                tenant_config(
                    &root,
                    "alpha",
                    "alpha_schema",
                    "alpha-shutdown.test",
                    false,
                    9,
                ),
                tenant_config(
                    &root,
                    "beta",
                    "beta_schema",
                    "beta-shutdown.test",
                    false,
                    10,
                ),
            ],
        );
        let host = TangleHostRuntime::open(config).expect("host");

        let report = host.shutdown().await.expect("shutdown");

        assert!(host.shutdown_signal().requested());
        assert_eq!(report.tenants_shutdown(), 2);
        assert_eq!(report.closed_subscriptions(), 0);
        assert!(!host.readiness_state().is_ready());

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn host_caps_reject_aggregate_connection_and_subscription_limits() {
        let resources =
            TangleHostResourceLimiter::new(TangleHostLimitsConfig::new(1, 2, 4).expect("limits"));

        let connection = resources.try_open_connection().expect("connection");
        assert_eq!(resources.active_connections(), 1);
        assert!(resources.try_open_connection().is_err());
        drop(connection);
        assert_eq!(resources.active_connections(), 0);
        let connection = resources.try_open_connection().expect("connection again");
        connection.release();
        assert_eq!(resources.active_connections(), 0);

        let subscriptions = resources.try_open_subscriptions(2).expect("subscriptions");
        assert_eq!(resources.active_subscriptions(), 2);
        assert!(resources.try_open_subscriptions(1).is_err());
        drop(subscriptions);
        assert_eq!(resources.active_subscriptions(), 0);
        let subscriptions = resources
            .try_open_subscriptions(1)
            .expect("subscriptions again");
        subscriptions.release();
        assert_eq!(resources.active_subscriptions(), 0);
    }

    fn config_set(
        root: &Path,
        tenants: Vec<crate::config::TenantRuntimeConfig>,
    ) -> TangleHostRuntimeConfigSet {
        let host = parse_tangle_host_runtime_config_json(
            &json!({
                "listen_addr": "127.0.0.1:0",
                "tenant_config_dir": root.join("tenants"),
                "limits": {
                    "max_total_connections": 16,
                    "max_total_subscriptions": 32,
                    "tenant_startup_concurrency": 2
                },
                "ops": {
                    "enabled": true,
                    "expose_tenant_inventory": true
                },
                "trusted_proxy": {
                    "enabled": false,
                    "trusted_peers": []
                }
            })
            .to_string(),
        )
        .expect("host config");
        TangleHostRuntimeConfigSet::new(host, tenants).expect("config set")
    }

    fn tenant_config(
        root: &Path,
        tenant_id: &str,
        tenant_schema: &str,
        host: &str,
        inactive: bool,
        secret_byte: u8,
    ) -> crate::config::TenantRuntimeConfig {
        tenant_config_with_pocket_path(
            root,
            tenant_id,
            tenant_schema,
            host,
            inactive,
            secret_byte,
            root.join(tenant_id).join("pocket"),
        )
    }

    fn tenant_config_with_pocket_path(
        root: &Path,
        tenant_id: &str,
        tenant_schema: &str,
        host: &str,
        inactive: bool,
        secret_byte: u8,
        pocket_path: PathBuf,
    ) -> crate::config::TenantRuntimeConfig {
        let relay_url = format!("wss://{host}");
        let secret = format!("{secret_byte:02x}").repeat(32);
        let raw = json!({
            "tenant_id": tenant_id,
            "tenant_schema": tenant_schema,
            "host": host,
            "relay_url": relay_url,
            "inactive": inactive,
            "info": {
                "name": format!("tenant {tenant_id}")
            },
            "pocket": {
                "data_directory": pocket_path,
                "sync_policy": "flush_on_shutdown"
            },
            "pocket_query": {
                "allow_scraping": false,
                "allow_scrape_if_limited_to": 100,
                "allow_scrape_if_max_seconds": 3600
            },
            "groups": {
                "enabled": true,
                "canonical_relay_url": relay_url,
                "relay_secret": secret,
                "owner_pubkeys": [FixtureKey::Owner.public_key().as_str()]
            },
            "auth": {
                "challenge_ttl_seconds": 300,
                "created_at_skew_seconds": 600
            },
            "limits": {
                "max_message_length": 1048576,
                "max_subid_length": 64,
                "max_subscriptions_per_connection": 64,
                "max_filters_per_request": 10,
                "max_tag_values_per_filter": 100,
                "max_query_complexity": 2048,
                "max_limit": 500,
                "default_limit": 100,
                "max_event_tags": 200,
                "max_content_length": 65536,
                "broadcast_channel_capacity": 8,
                "per_connection_outbound_queue": 8
            },
            "rate_limits": {
                "auth": {
                    "per_ip": {"window_seconds": 60, "max_hits": 120},
                    "per_pubkey": {"window_seconds": 60, "max_hits": 30},
                    "failures": {"window_seconds": 300, "max_hits": 5},
                    "failures_per_ip": {"window_seconds": 300, "max_hits": 20}
                },
                "event": {
                    "per_ip": {"window_seconds": 60, "max_hits": 600},
                    "per_pubkey": {"window_seconds": 60, "max_hits": 120},
                    "per_kind": {"window_seconds": 60, "max_hits": 1000}
                },
                "group": {
                    "write_per_ip": {"window_seconds": 60, "max_hits": 300},
                    "write_per_pubkey": {"window_seconds": 60, "max_hits": 60},
                    "write_per_group": {"window_seconds": 60, "max_hits": 90},
                    "write_per_kind": {"window_seconds": 60, "max_hits": 300},
                    "join_flow": {"window_seconds": 300, "max_hits": 10},
                    "join_flow_per_ip": {"window_seconds": 300, "max_hits": 30}
                },
                "req": {
                    "per_ip": {"window_seconds": 60, "max_hits": 600},
                    "per_connection": {"window_seconds": 60, "max_hits": 120},
                    "per_pubkey": {"window_seconds": 60, "max_hits": 240},
                    "per_group": {"window_seconds": 60, "max_hits": 240},
                    "per_kind": {"window_seconds": 60, "max_hits": 500},
                    "broad": {"window_seconds": 60, "max_hits": 30}
                },
                "count": {
                    "per_ip": {"window_seconds": 60, "max_hits": 300},
                    "per_connection": {"window_seconds": 60, "max_hits": 60},
                    "per_pubkey": {"window_seconds": 60, "max_hits": 120},
                    "per_group": {"window_seconds": 60, "max_hits": 120},
                    "per_kind": {"window_seconds": 60, "max_hits": 240},
                    "broad": {"window_seconds": 60, "max_hits": 20}
                }
            }
        })
        .to_string();
        let tenant = parse_tenant_runtime_config_json(&raw).expect("tenant config");
        assert!(tenant.pocket_config().data_directory().starts_with(root));
        tenant
    }

    fn temp_root(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        std::env::temp_dir().join(format!("tangle-host-{name}-{nanos}"))
    }
}
