#![forbid(unsafe_code)]

use crate::{
    errors::BaseRelayError,
    rate_limits::{
        TangleAuthRateLimitConfig, TangleEventRateLimitConfig, TangleGroupRateLimitConfig,
        TangleQueryRateLimitConfig, TangleRateLimitConfig, TangleRateLimitRule,
    },
    relay::{
        auth::BaseAuthState,
        core::{BaseRelay, BaseRelayLimitSettings, BaseRelayLimits},
    },
    tenant::{CanonicalHost, TenantId, TenantRelayUrl, TenantSchema},
};
use serde::Deserialize;
use std::{
    collections::BTreeSet,
    net::SocketAddr,
    path::{Component, Path, PathBuf},
};
use tangle_crypto::RelaySigner;
use tangle_groups::GroupRuntimeConfig;
use tangle_protocol::{PublicKeyHex, SubscriptionId};
use tangle_store_pocket::{PocketQueryConfig, PocketStoreConfig, PocketSyncPolicy};

const MAX_POCKET_QUERY_SCRAPE_WINDOW_SECONDS: u64 = 86_400;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TangleHostRuntimeConfig {
    listen_addr: SocketAddr,
    tenant_config_dir: PathBuf,
    limits: TangleHostLimitsConfig,
    ops: TangleHostOpsConfig,
    trusted_proxy: TangleTrustedProxyConfig,
    tracing: BaseRelayTracingConfig,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TangleHostRuntimeConfigSet {
    host: TangleHostRuntimeConfig,
    tenants: Vec<TenantRuntimeConfig>,
}

impl TangleHostRuntimeConfigSet {
    pub fn new(
        host: TangleHostRuntimeConfig,
        tenants: Vec<TenantRuntimeConfig>,
    ) -> Result<Self, BaseRelayError> {
        validate_tenant_config_set(&tenants)?;
        Ok(Self { host, tenants })
    }

    pub fn host(&self) -> &TangleHostRuntimeConfig {
        &self.host
    }

    pub fn tenants(&self) -> &[TenantRuntimeConfig] {
        &self.tenants
    }

    pub fn active_tenants(&self) -> impl Iterator<Item = &TenantRuntimeConfig> {
        self.tenants.iter().filter(|tenant| !tenant.inactive())
    }
}

impl TangleHostRuntimeConfig {
    pub fn listen_addr(&self) -> SocketAddr {
        self.listen_addr
    }

    pub fn tenant_config_dir(&self) -> &std::path::Path {
        &self.tenant_config_dir
    }

    pub fn limits(&self) -> TangleHostLimitsConfig {
        self.limits
    }

    pub fn ops(&self) -> TangleHostOpsConfig {
        self.ops
    }

    pub fn trusted_proxy(&self) -> &TangleTrustedProxyConfig {
        &self.trusted_proxy
    }

    pub fn tracing(&self) -> &BaseRelayTracingConfig {
        &self.tracing
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TangleHostLimitsConfig {
    max_total_connections: usize,
    max_total_subscriptions: usize,
    tenant_startup_concurrency: usize,
}

impl TangleHostLimitsConfig {
    pub fn new(
        max_total_connections: usize,
        max_total_subscriptions: usize,
        tenant_startup_concurrency: usize,
    ) -> Result<Self, BaseRelayError> {
        require_positive("limits.max_total_connections", max_total_connections)?;
        require_positive("limits.max_total_subscriptions", max_total_subscriptions)?;
        require_positive(
            "limits.tenant_startup_concurrency",
            tenant_startup_concurrency,
        )?;
        Ok(Self {
            max_total_connections,
            max_total_subscriptions,
            tenant_startup_concurrency,
        })
    }

    pub fn max_total_connections(self) -> usize {
        self.max_total_connections
    }

    pub fn max_total_subscriptions(self) -> usize {
        self.max_total_subscriptions
    }

    pub fn tenant_startup_concurrency(self) -> usize {
        self.tenant_startup_concurrency
    }
}

impl Default for TangleHostLimitsConfig {
    fn default() -> Self {
        Self::new(10_000, 25_000, 4).expect("default host limits are valid")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TangleHostOpsConfig {
    enabled: bool,
    expose_tenant_inventory: bool,
}

impl TangleHostOpsConfig {
    pub fn new(enabled: bool, expose_tenant_inventory: bool) -> Self {
        Self {
            enabled,
            expose_tenant_inventory,
        }
    }

    pub fn enabled(self) -> bool {
        self.enabled
    }

    pub fn expose_tenant_inventory(self) -> bool {
        self.expose_tenant_inventory
    }
}

impl Default for TangleHostOpsConfig {
    fn default() -> Self {
        Self::new(true, true)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TangleTrustedProxyConfig {
    enabled: bool,
    trusted_peers: Vec<String>,
}

impl TangleTrustedProxyConfig {
    pub fn new(enabled: bool, trusted_peers: Vec<String>) -> Result<Self, BaseRelayError> {
        for peer in &trusted_peers {
            if peer.trim().is_empty() || peer.trim() != peer {
                return Err(BaseRelayError::invalid(
                    "trusted_proxy.trusted_peers entries must not be empty or padded",
                ));
            }
        }
        Ok(Self {
            enabled,
            trusted_peers,
        })
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    pub fn trusted_peers(&self) -> &[String] {
        &self.trusted_peers
    }
}

impl Default for TangleTrustedProxyConfig {
    fn default() -> Self {
        Self::new(false, Vec::new()).expect("default trusted proxy config is valid")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantRelayInfoConfig {
    name: String,
    description: Option<String>,
    contact: Option<String>,
    icon: Option<String>,
}

impl TenantRelayInfoConfig {
    pub fn new(
        name: impl Into<String>,
        description: Option<String>,
        contact: Option<String>,
        icon: Option<String>,
    ) -> Result<Self, BaseRelayError> {
        let name = name.into();
        if name.trim().is_empty() || name.trim() != name {
            return Err(BaseRelayError::invalid(
                "info.name must not be empty or padded",
            ));
        }
        Ok(Self {
            name,
            description: validate_optional_text("info.description", description)?,
            contact: validate_optional_text("info.contact", contact)?,
            icon: validate_optional_text("info.icon", icon)?,
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }

    pub fn contact(&self) -> Option<&str> {
        self.contact.as_deref()
    }

    pub fn icon(&self) -> Option<&str> {
        self.icon.as_deref()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TenantBackupExportConfig {
    backup_enabled: bool,
    export_enabled: bool,
}

impl TenantBackupExportConfig {
    pub fn new(backup_enabled: bool, export_enabled: bool) -> Self {
        Self {
            backup_enabled,
            export_enabled,
        }
    }

    pub fn backup_enabled(self) -> bool {
        self.backup_enabled
    }

    pub fn export_enabled(self) -> bool {
        self.export_enabled
    }
}

impl Default for TenantBackupExportConfig {
    fn default() -> Self {
        Self::new(true, true)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantRuntimeConfig {
    tenant_id: TenantId,
    tenant_schema: TenantSchema,
    host: CanonicalHost,
    relay_url: TenantRelayUrl,
    inactive: bool,
    info: TenantRelayInfoConfig,
    pocket: PocketStoreConfig,
    pocket_query: PocketQueryConfig,
    groups: GroupRuntimeConfig,
    auth_ttl_seconds: u64,
    auth_created_at_skew_seconds: u64,
    limits: BaseRelayRuntimeLimitsConfig,
    rate_limits: TangleRateLimitConfig,
    backup_export: TenantBackupExportConfig,
}

impl TenantRuntimeConfig {
    pub fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    pub fn tenant_schema(&self) -> &TenantSchema {
        &self.tenant_schema
    }

    pub fn host(&self) -> &CanonicalHost {
        &self.host
    }

    pub fn relay_url(&self) -> &TenantRelayUrl {
        &self.relay_url
    }

    pub fn inactive(&self) -> bool {
        self.inactive
    }

    pub fn info(&self) -> &TenantRelayInfoConfig {
        &self.info
    }

    pub fn pocket_config(&self) -> &PocketStoreConfig {
        &self.pocket
    }

    pub fn pocket_query_config(&self) -> PocketQueryConfig {
        self.pocket_query
    }

    pub fn groups(&self) -> &GroupRuntimeConfig {
        &self.groups
    }

    pub fn relay_self_pubkey(&self) -> Result<Option<PublicKeyHex>, BaseRelayError> {
        self.groups
            .relay_secret()
            .map(|secret| RelaySigner::from_secret_hex(secret.expose_for_signing()))
            .transpose()
            .map(|signer| signer.map(|signer| signer.public_key().clone()))
            .map_err(BaseRelayError::invalid)
    }

    pub fn auth_ttl_seconds(&self) -> u64 {
        self.auth_ttl_seconds
    }

    pub fn auth_created_at_skew_seconds(&self) -> u64 {
        self.auth_created_at_skew_seconds
    }

    pub fn limits(&self) -> BaseRelayRuntimeLimitsConfig {
        self.limits
    }

    pub fn rate_limits(&self) -> TangleRateLimitConfig {
        self.rate_limits
    }

    pub fn backup_export(&self) -> TenantBackupExportConfig {
        self.backup_export
    }

    pub fn to_base_relay_runtime_config(
        &self,
        listen_addr: SocketAddr,
        tracing: BaseRelayTracingConfig,
    ) -> BaseRelayRuntimeConfig {
        BaseRelayRuntimeConfig {
            listen_addr,
            relay_url: self.relay_url.as_str().to_owned(),
            pocket: self.pocket.clone(),
            pocket_query: self.pocket_query,
            groups: self.groups.clone(),
            auth_ttl_seconds: self.auth_ttl_seconds,
            auth_created_at_skew_seconds: self.auth_created_at_skew_seconds,
            limits: self.limits,
            rate_limits: self.rate_limits,
            tracing,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaseRelayRuntimeConfig {
    listen_addr: SocketAddr,
    relay_url: String,
    pocket: PocketStoreConfig,
    pocket_query: PocketQueryConfig,
    groups: GroupRuntimeConfig,
    auth_ttl_seconds: u64,
    auth_created_at_skew_seconds: u64,
    limits: BaseRelayRuntimeLimitsConfig,
    rate_limits: TangleRateLimitConfig,
    tracing: BaseRelayTracingConfig,
}

impl BaseRelayRuntimeConfig {
    pub fn listen_addr(&self) -> SocketAddr {
        self.listen_addr
    }

    pub fn relay_url(&self) -> &str {
        &self.relay_url
    }

    pub fn pocket_config(&self) -> &PocketStoreConfig {
        &self.pocket
    }

    pub fn pocket_query_config(&self) -> PocketQueryConfig {
        self.pocket_query
    }

    pub fn groups(&self) -> &GroupRuntimeConfig {
        &self.groups
    }

    pub fn auth_ttl_seconds(&self) -> u64 {
        self.auth_ttl_seconds
    }

    pub fn auth_created_at_skew_seconds(&self) -> u64 {
        self.auth_created_at_skew_seconds
    }

    pub fn limits(&self) -> BaseRelayRuntimeLimitsConfig {
        self.limits
    }

    pub fn rate_limits(&self) -> TangleRateLimitConfig {
        self.rate_limits
    }

    pub fn tracing(&self) -> &BaseRelayTracingConfig {
        &self.tracing
    }

    pub fn open_relay(&self) -> Result<BaseRelay, BaseRelayError> {
        BaseRelay::open_with_groups(
            &self.pocket,
            self.limits.base_relay_limits()?,
            &self.groups,
            self.pocket_query,
        )
    }

    pub fn auth_state(&self) -> Result<BaseAuthState, BaseRelayError> {
        BaseAuthState::new(
            self.relay_url.clone(),
            self.auth_ttl_seconds,
            self.auth_created_at_skew_seconds,
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BaseRelayTracingFormat {
    Compact,
    Json,
}

impl BaseRelayTracingFormat {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Compact => "compact",
            Self::Json => "json",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaseRelayTracingConfig {
    enabled: bool,
    filter: String,
    format: BaseRelayTracingFormat,
}

impl BaseRelayTracingConfig {
    pub fn new(
        enabled: bool,
        filter: impl Into<String>,
        format: BaseRelayTracingFormat,
    ) -> Result<Self, BaseRelayError> {
        let filter = filter.into();
        if filter.trim().is_empty() {
            return Err(BaseRelayError::invalid(
                "observability.tracing.filter must not be empty",
            ));
        }
        Ok(Self {
            enabled,
            filter: filter.trim().to_owned(),
            format,
        })
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    pub fn filter(&self) -> &str {
        &self.filter
    }

    pub fn format(&self) -> BaseRelayTracingFormat {
        self.format
    }
}

impl Default for BaseRelayTracingConfig {
    fn default() -> Self {
        Self::new(
            true,
            "info,tangle=info,tangle_runtime=info,tangle_groups=info,tangle_store_pocket=info",
            BaseRelayTracingFormat::Json,
        )
        .expect("default tracing config is valid")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BaseRelayRuntimeLimitsConfig {
    max_message_length: usize,
    max_subid_length: usize,
    max_subscriptions_per_connection: usize,
    max_filters_per_request: usize,
    max_tag_values_per_filter: usize,
    max_query_complexity: usize,
    max_limit: u64,
    default_limit: u64,
    max_event_tags: usize,
    max_content_length: usize,
    broadcast_channel_capacity: usize,
    per_connection_outbound_queue: usize,
}

impl BaseRelayRuntimeLimitsConfig {
    fn from_document(document: BaseRelayRuntimeLimitsDocument) -> Result<Self, BaseRelayError> {
        require_positive("limits.max_message_length", document.max_message_length)?;
        require_positive("limits.max_subid_length", document.max_subid_length)?;
        require_positive(
            "limits.max_subscriptions_per_connection",
            document.max_subscriptions_per_connection,
        )?;
        require_positive(
            "limits.max_filters_per_request",
            document.max_filters_per_request,
        )?;
        require_positive(
            "limits.max_tag_values_per_filter",
            document.max_tag_values_per_filter,
        )?;
        require_positive("limits.max_query_complexity", document.max_query_complexity)?;
        require_positive_u64("limits.max_limit", document.max_limit)?;
        require_positive_u64("limits.default_limit", document.default_limit)?;
        require_positive("limits.max_event_tags", document.max_event_tags)?;
        require_positive("limits.max_content_length", document.max_content_length)?;
        require_positive(
            "limits.broadcast_channel_capacity",
            document.broadcast_channel_capacity,
        )?;
        require_positive(
            "limits.per_connection_outbound_queue",
            document.per_connection_outbound_queue,
        )?;
        if document.max_subid_length > SubscriptionId::MAX_LENGTH {
            return Err(BaseRelayError::invalid(format!(
                "limits.max_subid_length must be less than or equal to {}",
                SubscriptionId::MAX_LENGTH
            )));
        }
        if document.default_limit > document.max_limit {
            return Err(BaseRelayError::invalid(
                "limits.default_limit must be less than or equal to limits.max_limit",
            ));
        }
        Ok(Self {
            max_message_length: document.max_message_length,
            max_subid_length: document.max_subid_length,
            max_subscriptions_per_connection: document.max_subscriptions_per_connection,
            max_filters_per_request: document.max_filters_per_request,
            max_tag_values_per_filter: document.max_tag_values_per_filter,
            max_query_complexity: document.max_query_complexity,
            max_limit: document.max_limit,
            default_limit: document.default_limit,
            max_event_tags: document.max_event_tags,
            max_content_length: document.max_content_length,
            broadcast_channel_capacity: document.broadcast_channel_capacity,
            per_connection_outbound_queue: document.per_connection_outbound_queue,
        })
    }

    pub fn max_message_length(self) -> usize {
        self.max_message_length
    }

    pub fn max_subid_length(self) -> usize {
        self.max_subid_length
    }

    pub fn max_subscriptions_per_connection(self) -> usize {
        self.max_subscriptions_per_connection
    }

    pub fn max_filters_per_request(self) -> usize {
        self.max_filters_per_request
    }

    pub fn max_tag_values_per_filter(self) -> usize {
        self.max_tag_values_per_filter
    }

    pub fn max_query_complexity(self) -> usize {
        self.max_query_complexity
    }

    pub fn max_limit(self) -> u64 {
        self.max_limit
    }

    pub fn default_limit(self) -> u64 {
        self.default_limit
    }

    pub fn max_event_tags(self) -> usize {
        self.max_event_tags
    }

    pub fn max_content_length(self) -> usize {
        self.max_content_length
    }

    pub fn broadcast_channel_capacity(self) -> usize {
        self.broadcast_channel_capacity
    }

    pub fn per_connection_outbound_queue(self) -> usize {
        self.per_connection_outbound_queue
    }

    pub fn base_relay_limits(self) -> Result<BaseRelayLimits, BaseRelayError> {
        BaseRelayLimits::new(BaseRelayLimitSettings {
            max_pending_events: self.per_connection_outbound_queue,
            max_subscription_id_length: self.max_subid_length,
            max_subscriptions: self.max_subscriptions_per_connection,
            max_filters_per_request: self.max_filters_per_request,
            max_tag_values_per_filter: self.max_tag_values_per_filter,
            max_query_complexity: self.max_query_complexity,
            max_event_tags: self.max_event_tags,
            max_content_length: self.max_content_length,
            max_limit: self.max_limit,
            default_limit: self.default_limit,
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TangleHostRuntimeConfigDocument {
    listen_addr: String,
    tenant_config_dir: String,
    #[serde(default)]
    limits: TangleHostLimitsConfigDocument,
    #[serde(default)]
    ops: TangleHostOpsConfigDocument,
    #[serde(default)]
    trusted_proxy: TangleTrustedProxyConfigDocument,
    #[serde(default)]
    observability: BaseRelayObservabilityConfigDocument,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TangleHostLimitsConfigDocument {
    max_total_connections: usize,
    max_total_subscriptions: usize,
    tenant_startup_concurrency: usize,
}

impl Default for TangleHostLimitsConfigDocument {
    fn default() -> Self {
        let defaults = TangleHostLimitsConfig::default();
        Self {
            max_total_connections: defaults.max_total_connections(),
            max_total_subscriptions: defaults.max_total_subscriptions(),
            tenant_startup_concurrency: defaults.tenant_startup_concurrency(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TangleHostOpsConfigDocument {
    enabled: bool,
    expose_tenant_inventory: bool,
}

impl Default for TangleHostOpsConfigDocument {
    fn default() -> Self {
        let defaults = TangleHostOpsConfig::default();
        Self {
            enabled: defaults.enabled(),
            expose_tenant_inventory: defaults.expose_tenant_inventory(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TangleTrustedProxyConfigDocument {
    enabled: bool,
    #[serde(default)]
    trusted_peers: Vec<String>,
}

impl Default for TangleTrustedProxyConfigDocument {
    fn default() -> Self {
        let defaults = TangleTrustedProxyConfig::default();
        Self {
            enabled: defaults.enabled(),
            trusted_peers: defaults.trusted_peers().to_vec(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TenantRuntimeConfigDocument {
    tenant_id: String,
    tenant_schema: String,
    host: String,
    relay_url: String,
    #[serde(default)]
    inactive: bool,
    info: TenantRelayInfoConfigDocument,
    pocket: TenantPocketConfigDocument,
    pocket_query: BaseRelayPocketQueryConfigDocument,
    groups: serde_json::Value,
    auth: BaseRelayAuthConfigDocument,
    limits: BaseRelayRuntimeLimitsDocument,
    rate_limits: BaseRelayRateLimitsDocument,
    #[serde(default)]
    backup_export: TenantBackupExportConfigDocument,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TenantRelayInfoConfigDocument {
    name: String,
    description: Option<String>,
    contact: Option<String>,
    icon: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TenantPocketConfigDocument {
    data_directory: String,
    sync_policy: BaseRelayPocketSyncPolicyDocument,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TenantBackupExportConfigDocument {
    backup_enabled: bool,
    export_enabled: bool,
}

impl Default for TenantBackupExportConfigDocument {
    fn default() -> Self {
        let defaults = TenantBackupExportConfig::default();
        Self {
            backup_enabled: defaults.backup_enabled(),
            export_enabled: defaults.export_enabled(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BaseRelayRuntimeConfigDocument {
    server: BaseRelayServerConfigDocument,
    pocket: BaseRelayPocketConfigDocument,
    groups: serde_json::Value,
    auth: BaseRelayAuthConfigDocument,
    limits: BaseRelayRuntimeLimitsDocument,
    rate_limits: BaseRelayRateLimitsDocument,
    #[serde(default)]
    observability: BaseRelayObservabilityConfigDocument,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BaseRelayServerConfigDocument {
    listen_addr: String,
    relay_url: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BaseRelayPocketConfigDocument {
    data_directory: String,
    sync_policy: BaseRelayPocketSyncPolicyDocument,
    query: BaseRelayPocketQueryConfigDocument,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BaseRelayPocketQueryConfigDocument {
    allow_scraping: bool,
    allow_scrape_if_limited_to: u32,
    allow_scrape_if_max_seconds: u64,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum BaseRelayPocketSyncPolicyDocument {
    FlushOnWrite,
    FlushOnShutdown,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BaseRelayAuthConfigDocument {
    challenge_ttl_seconds: u64,
    created_at_skew_seconds: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BaseRelayRuntimeLimitsDocument {
    max_message_length: usize,
    max_subid_length: usize,
    max_subscriptions_per_connection: usize,
    max_filters_per_request: usize,
    max_tag_values_per_filter: usize,
    max_query_complexity: usize,
    max_limit: u64,
    default_limit: u64,
    max_event_tags: usize,
    max_content_length: usize,
    broadcast_channel_capacity: usize,
    per_connection_outbound_queue: usize,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BaseRelayRateLimitsDocument {
    auth: BaseRelayAuthRateLimitsDocument,
    event: BaseRelayEventRateLimitsDocument,
    group: BaseRelayGroupRateLimitsDocument,
    req: BaseRelayQueryRateLimitsDocument,
    count: BaseRelayQueryRateLimitsDocument,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BaseRelayAuthRateLimitsDocument {
    per_ip: BaseRelayRateLimitRuleDocument,
    per_pubkey: BaseRelayRateLimitRuleDocument,
    failures: BaseRelayRateLimitRuleDocument,
    failures_per_ip: BaseRelayRateLimitRuleDocument,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BaseRelayEventRateLimitsDocument {
    per_ip: BaseRelayRateLimitRuleDocument,
    per_pubkey: BaseRelayRateLimitRuleDocument,
    per_kind: BaseRelayRateLimitRuleDocument,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BaseRelayGroupRateLimitsDocument {
    write_per_ip: BaseRelayRateLimitRuleDocument,
    write_per_pubkey: BaseRelayRateLimitRuleDocument,
    write_per_group: BaseRelayRateLimitRuleDocument,
    write_per_kind: BaseRelayRateLimitRuleDocument,
    join_flow: BaseRelayRateLimitRuleDocument,
    join_flow_per_ip: BaseRelayRateLimitRuleDocument,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BaseRelayQueryRateLimitsDocument {
    per_ip: BaseRelayRateLimitRuleDocument,
    per_connection: BaseRelayRateLimitRuleDocument,
    per_pubkey: BaseRelayRateLimitRuleDocument,
    per_group: BaseRelayRateLimitRuleDocument,
    per_kind: BaseRelayRateLimitRuleDocument,
    broad: BaseRelayRateLimitRuleDocument,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
struct BaseRelayRateLimitRuleDocument {
    window_seconds: u64,
    max_hits: u64,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct BaseRelayObservabilityConfigDocument {
    #[serde(default)]
    tracing: BaseRelayTracingConfigDocument,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct BaseRelayTracingConfigDocument {
    enabled: Option<bool>,
    filter: Option<String>,
    format: Option<BaseRelayTracingFormatDocument>,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum BaseRelayTracingFormatDocument {
    Compact,
    Json,
}

pub fn parse_tangle_host_runtime_config_json(
    raw: &str,
) -> Result<TangleHostRuntimeConfig, BaseRelayError> {
    reject_legacy_single_relay_config(raw)?;
    let document =
        serde_json::from_str::<TangleHostRuntimeConfigDocument>(raw).map_err(|error| {
            BaseRelayError::invalid(format!(
                "tangle host runtime config JSON is invalid: {error}"
            ))
        })?;
    let listen_addr = document
        .listen_addr
        .parse::<SocketAddr>()
        .map_err(|error| BaseRelayError::invalid(format!("listen_addr is invalid: {error}")))?;
    if document.tenant_config_dir.trim().is_empty()
        || document.tenant_config_dir.trim() != document.tenant_config_dir
    {
        return Err(BaseRelayError::invalid(
            "tenant_config_dir must not be empty or padded",
        ));
    }
    Ok(TangleHostRuntimeConfig {
        listen_addr,
        tenant_config_dir: PathBuf::from(document.tenant_config_dir),
        limits: TangleHostLimitsConfig::new(
            document.limits.max_total_connections,
            document.limits.max_total_subscriptions,
            document.limits.tenant_startup_concurrency,
        )?,
        ops: TangleHostOpsConfig::new(document.ops.enabled, document.ops.expose_tenant_inventory),
        trusted_proxy: TangleTrustedProxyConfig::new(
            document.trusted_proxy.enabled,
            document.trusted_proxy.trusted_peers,
        )?,
        tracing: base_relay_tracing_config_from_document(document.observability.tracing)?,
    })
}

pub fn parse_tenant_runtime_config_json(raw: &str) -> Result<TenantRuntimeConfig, BaseRelayError> {
    reject_legacy_single_relay_config(raw)?;
    let document = serde_json::from_str::<TenantRuntimeConfigDocument>(raw).map_err(|error| {
        BaseRelayError::invalid(format!("tenant runtime config JSON is invalid: {error}"))
    })?;
    let tenant_id = TenantId::new(document.tenant_id)?;
    let tenant_schema = TenantSchema::new(document.tenant_schema)?;
    let host = CanonicalHost::new(document.host)?;
    let relay_url = TenantRelayUrl::new(document.relay_url)?;
    let pocket = PocketStoreConfig::new(
        PathBuf::from(document.pocket.data_directory),
        match document.pocket.sync_policy {
            BaseRelayPocketSyncPolicyDocument::FlushOnWrite => PocketSyncPolicy::FlushOnWrite,
            BaseRelayPocketSyncPolicyDocument::FlushOnShutdown => PocketSyncPolicy::FlushOnShutdown,
        },
    )
    .map_err(|error| BaseRelayError::invalid(error.to_string()))?;
    let groups_raw = serde_json::to_string(&document.groups).map_err(|error| {
        BaseRelayError::invalid(format!("groups config JSON is invalid: {error}"))
    })?;
    let groups = tangle_groups::parse_group_runtime_config_json(&groups_raw)
        .map_err(|error| BaseRelayError::invalid(error.to_string()))?;
    if let Some(group_relay_url) = groups.canonical_relay_url()
        && group_relay_url.as_str() != relay_url.as_str()
    {
        return Err(BaseRelayError::invalid(
            "groups.canonical_relay_url must match relay_url",
        ));
    }
    let limits = BaseRelayRuntimeLimitsConfig::from_document(document.limits)?;
    let pocket_query = pocket_query_config_from_document(document.pocket_query, limits)?;
    if document.auth.created_at_skew_seconds == 0 {
        return Err(BaseRelayError::invalid(
            "auth.created_at_skew_seconds must be greater than zero",
        ));
    }
    Ok(TenantRuntimeConfig {
        tenant_id,
        tenant_schema,
        host,
        relay_url,
        inactive: document.inactive,
        info: TenantRelayInfoConfig::new(
            document.info.name,
            document.info.description,
            document.info.contact,
            document.info.icon,
        )?,
        pocket,
        pocket_query,
        groups,
        auth_ttl_seconds: document.auth.challenge_ttl_seconds,
        auth_created_at_skew_seconds: document.auth.created_at_skew_seconds,
        limits,
        rate_limits: base_relay_rate_limits_from_document(document.rate_limits)?,
        backup_export: TenantBackupExportConfig::new(
            document.backup_export.backup_enabled,
            document.backup_export.export_enabled,
        ),
    })
}

fn reject_legacy_single_relay_config(raw: &str) -> Result<(), BaseRelayError> {
    let value = serde_json::from_str::<serde_json::Value>(raw)
        .map_err(|error| BaseRelayError::invalid(format!("config JSON is invalid: {error}")))?;
    if value
        .as_object()
        .is_some_and(|object| object.contains_key("server"))
    {
        return Err(BaseRelayError::invalid(
            "legacy single-relay config is not supported",
        ));
    }
    Ok(())
}

pub fn parse_base_relay_runtime_config_json(
    raw: &str,
) -> Result<BaseRelayRuntimeConfig, BaseRelayError> {
    let document =
        serde_json::from_str::<BaseRelayRuntimeConfigDocument>(raw).map_err(|error| {
            BaseRelayError::invalid(format!(
                "base relay runtime config JSON is invalid: {error}"
            ))
        })?;
    let listen_addr = document
        .server
        .listen_addr
        .parse::<SocketAddr>()
        .map_err(|error| {
            BaseRelayError::invalid(format!("server.listen_addr is invalid: {error}"))
        })?;
    let pocket_document = document.pocket;
    let pocket = PocketStoreConfig::new(
        PathBuf::from(pocket_document.data_directory),
        match pocket_document.sync_policy {
            BaseRelayPocketSyncPolicyDocument::FlushOnWrite => PocketSyncPolicy::FlushOnWrite,
            BaseRelayPocketSyncPolicyDocument::FlushOnShutdown => PocketSyncPolicy::FlushOnShutdown,
        },
    )
    .map_err(|error| BaseRelayError::invalid(error.to_string()))?;
    let groups_raw = serde_json::to_string(&document.groups).map_err(|error| {
        BaseRelayError::invalid(format!("groups config JSON is invalid: {error}"))
    })?;
    let groups = tangle_groups::parse_group_runtime_config_json(&groups_raw)
        .map_err(|error| BaseRelayError::invalid(error.to_string()))?;
    let limits = BaseRelayRuntimeLimitsConfig::from_document(document.limits)?;
    let pocket_query = pocket_query_config_from_document(pocket_document.query, limits)?;
    let rate_limits = base_relay_rate_limits_from_document(document.rate_limits)?;
    if document.auth.created_at_skew_seconds == 0 {
        return Err(BaseRelayError::invalid(
            "auth.created_at_skew_seconds must be greater than zero",
        ));
    }
    let tracing = base_relay_tracing_config_from_document(document.observability.tracing)?;
    Ok(BaseRelayRuntimeConfig {
        listen_addr,
        relay_url: document.server.relay_url,
        pocket,
        pocket_query,
        groups,
        auth_ttl_seconds: document.auth.challenge_ttl_seconds,
        auth_created_at_skew_seconds: document.auth.created_at_skew_seconds,
        limits,
        rate_limits,
        tracing,
    })
}

fn pocket_query_config_from_document(
    document: BaseRelayPocketQueryConfigDocument,
    limits: BaseRelayRuntimeLimitsConfig,
) -> Result<PocketQueryConfig, BaseRelayError> {
    if u64::from(document.allow_scrape_if_limited_to) > limits.max_limit() {
        return Err(BaseRelayError::invalid(
            "pocket.query.allow_scrape_if_limited_to must be less than or equal to limits.max_limit",
        ));
    }
    if document.allow_scrape_if_max_seconds > MAX_POCKET_QUERY_SCRAPE_WINDOW_SECONDS {
        return Err(BaseRelayError::invalid(format!(
            "pocket.query.allow_scrape_if_max_seconds must be less than or equal to {MAX_POCKET_QUERY_SCRAPE_WINDOW_SECONDS}"
        )));
    }
    Ok(PocketQueryConfig::new(
        document.allow_scraping,
        document.allow_scrape_if_limited_to,
        document.allow_scrape_if_max_seconds,
    ))
}

fn require_positive(field: &str, value: usize) -> Result<(), BaseRelayError> {
    if value == 0 {
        return Err(BaseRelayError::invalid(format!(
            "{field} must be greater than zero"
        )));
    }
    Ok(())
}

fn require_positive_u64(field: &str, value: u64) -> Result<(), BaseRelayError> {
    if value == 0 {
        return Err(BaseRelayError::invalid(format!(
            "{field} must be greater than zero"
        )));
    }
    Ok(())
}

fn base_relay_rate_limits_from_document(
    document: BaseRelayRateLimitsDocument,
) -> Result<TangleRateLimitConfig, BaseRelayError> {
    Ok(TangleRateLimitConfig::new(
        TangleAuthRateLimitConfig::new(
            base_relay_rate_limit_rule_from_document(
                "rate_limits.auth.per_ip",
                document.auth.per_ip,
            )?,
            base_relay_rate_limit_rule_from_document(
                "rate_limits.auth.per_pubkey",
                document.auth.per_pubkey,
            )?,
            base_relay_rate_limit_rule_from_document(
                "rate_limits.auth.failures",
                document.auth.failures,
            )?,
            base_relay_rate_limit_rule_from_document(
                "rate_limits.auth.failures_per_ip",
                document.auth.failures_per_ip,
            )?,
        ),
        TangleEventRateLimitConfig::new(
            base_relay_rate_limit_rule_from_document(
                "rate_limits.event.per_ip",
                document.event.per_ip,
            )?,
            base_relay_rate_limit_rule_from_document(
                "rate_limits.event.per_pubkey",
                document.event.per_pubkey,
            )?,
            base_relay_rate_limit_rule_from_document(
                "rate_limits.event.per_kind",
                document.event.per_kind,
            )?,
        ),
        TangleGroupRateLimitConfig::new(
            base_relay_rate_limit_rule_from_document(
                "rate_limits.group.write_per_ip",
                document.group.write_per_ip,
            )?,
            base_relay_rate_limit_rule_from_document(
                "rate_limits.group.write_per_pubkey",
                document.group.write_per_pubkey,
            )?,
            base_relay_rate_limit_rule_from_document(
                "rate_limits.group.write_per_group",
                document.group.write_per_group,
            )?,
            base_relay_rate_limit_rule_from_document(
                "rate_limits.group.write_per_kind",
                document.group.write_per_kind,
            )?,
            base_relay_rate_limit_rule_from_document(
                "rate_limits.group.join_flow",
                document.group.join_flow,
            )?,
            base_relay_rate_limit_rule_from_document(
                "rate_limits.group.join_flow_per_ip",
                document.group.join_flow_per_ip,
            )?,
        ),
        base_relay_query_rate_limits_from_document("rate_limits.req", document.req)?,
        base_relay_query_rate_limits_from_document("rate_limits.count", document.count)?,
    ))
}

fn base_relay_query_rate_limits_from_document(
    field: &str,
    document: BaseRelayQueryRateLimitsDocument,
) -> Result<TangleQueryRateLimitConfig, BaseRelayError> {
    Ok(TangleQueryRateLimitConfig::new(
        base_relay_rate_limit_rule_from_document(&format!("{field}.per_ip"), document.per_ip)?,
        base_relay_rate_limit_rule_from_document(
            &format!("{field}.per_connection"),
            document.per_connection,
        )?,
        base_relay_rate_limit_rule_from_document(
            &format!("{field}.per_pubkey"),
            document.per_pubkey,
        )?,
        base_relay_rate_limit_rule_from_document(
            &format!("{field}.per_group"),
            document.per_group,
        )?,
        base_relay_rate_limit_rule_from_document(&format!("{field}.per_kind"), document.per_kind)?,
        base_relay_rate_limit_rule_from_document(&format!("{field}.broad"), document.broad)?,
    ))
}

fn base_relay_rate_limit_rule_from_document(
    field: &str,
    document: BaseRelayRateLimitRuleDocument,
) -> Result<TangleRateLimitRule, BaseRelayError> {
    require_positive_u64(&format!("{field}.window_seconds"), document.window_seconds)?;
    require_positive_u64(&format!("{field}.max_hits"), document.max_hits)?;
    TangleRateLimitRule::new(document.window_seconds, document.max_hits)
}

fn base_relay_tracing_config_from_document(
    document: BaseRelayTracingConfigDocument,
) -> Result<BaseRelayTracingConfig, BaseRelayError> {
    BaseRelayTracingConfig::new(
        document.enabled.unwrap_or(true),
        document.filter.unwrap_or_else(|| {
            "info,tangle=info,tangle_runtime=info,tangle_groups=info,tangle_store_pocket=info"
                .to_owned()
        }),
        match document
            .format
            .unwrap_or(BaseRelayTracingFormatDocument::Json)
        {
            BaseRelayTracingFormatDocument::Compact => BaseRelayTracingFormat::Compact,
            BaseRelayTracingFormatDocument::Json => BaseRelayTracingFormat::Json,
        },
    )
}

fn validate_optional_text(
    field: &str,
    value: Option<String>,
) -> Result<Option<String>, BaseRelayError> {
    if let Some(value) = value {
        if value.trim().is_empty() || value.trim() != value {
            return Err(BaseRelayError::invalid(format!(
                "{field} must not be empty or padded"
            )));
        }
        Ok(Some(value))
    } else {
        Ok(None)
    }
}

fn validate_tenant_config_set(tenants: &[TenantRuntimeConfig]) -> Result<(), BaseRelayError> {
    if tenants.iter().all(TenantRuntimeConfig::inactive) {
        return Err(BaseRelayError::invalid(
            "at least one active tenant is required",
        ));
    }
    let mut tenant_ids = BTreeSet::new();
    let mut tenant_schemas = BTreeSet::new();
    let mut hosts = BTreeSet::new();
    let mut relay_urls = BTreeSet::new();
    let mut relay_self_pubkeys = BTreeSet::new();
    let mut store_paths = BTreeSet::new();
    for tenant in tenants {
        insert_unique("tenant_id", tenant.tenant_id().as_str(), &mut tenant_ids)?;
        insert_unique(
            "tenant_schema",
            tenant.tenant_schema().as_str(),
            &mut tenant_schemas,
        )?;
        insert_unique("host", tenant.host().as_str(), &mut hosts)?;
        insert_unique("relay_url", tenant.relay_url().as_str(), &mut relay_urls)?;
        if let Some(pubkey) = tenant.relay_self_pubkey()? {
            insert_unique(
                "relay self pubkey",
                pubkey.as_str(),
                &mut relay_self_pubkeys,
            )?;
        }
        let store_path = canonical_path_key(tenant.pocket_config().data_directory());
        insert_unique("pocket data directory", &store_path, &mut store_paths)?;
    }
    Ok(())
}

fn insert_unique(
    field: &str,
    value: impl Into<String>,
    values: &mut BTreeSet<String>,
) -> Result<(), BaseRelayError> {
    let value = value.into();
    if values.insert(value.clone()) {
        Ok(())
    } else {
        Err(BaseRelayError::invalid(format!(
            "duplicate tenant {field}: {value}"
        )))
    }
}

fn canonical_path_key(path: &Path) -> String {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            Component::Normal(part) => normalized.push(part),
            Component::RootDir | Component::Prefix(_) => normalized.push(component.as_os_str()),
        }
    }
    normalized.to_string_lossy().into_owned()
}

#[cfg(test)]
mod tests {
    use super::{
        BaseRelayTracingFormat, TangleHostRuntimeConfigSet, TenantRuntimeConfig,
        parse_base_relay_runtime_config_json, parse_tangle_host_runtime_config_json,
        parse_tenant_runtime_config_json,
    };
    use serde_json::{Value, json};
    use std::path::Path;
    use tangle_store_pocket::PocketSyncPolicy;

    #[test]
    fn tangle_host_runtime_config_parses_v1_mvp_example() {
        let config = parse_tangle_host_runtime_config_json(include_str!(
            "../../../config/tangle.host.example.json"
        ))
        .expect("host config");

        assert_eq!(config.listen_addr().to_string(), "0.0.0.0:7000");
        assert_eq!(config.tenant_config_dir(), Path::new("tenants"));
        assert_eq!(config.limits().max_total_connections(), 10_000);
        assert_eq!(config.limits().max_total_subscriptions(), 25_000);
        assert_eq!(config.limits().tenant_startup_concurrency(), 4);
        assert!(config.ops().enabled());
        assert!(config.ops().expose_tenant_inventory());
        assert!(!config.trusted_proxy().enabled());
        assert!(config.trusted_proxy().trusted_peers().is_empty());
        assert!(config.tracing().enabled());
        assert_eq!(config.tracing().format(), BaseRelayTracingFormat::Json);
    }

    #[test]
    fn tenant_runtime_config_parses_v1_mvp_example() {
        let config = parse_tenant_runtime_config_json(include_str!(
            "../../../config/tenants/farmers_market.example.json"
        ))
        .expect("tenant config");

        assert_eq!(config.tenant_id().as_str(), "farmers-market");
        assert_eq!(config.tenant_schema().as_str(), "farmers_market");
        assert_eq!(config.host().as_str(), "relay.radroots.test");
        assert_eq!(config.relay_url().as_str(), "wss://relay.radroots.test");
        assert!(!config.inactive());
        assert_eq!(config.info().name(), "Radroots Farmers Market");
        assert_eq!(
            config.info().description(),
            Some("Tangle virtual relay tenant for the Radroots farmers market")
        );
        assert_eq!(
            config.pocket_config().data_directory(),
            Path::new("runtime/tenants/farmers_market/pocket")
        );
        assert_eq!(
            config.pocket_config().sync_policy(),
            PocketSyncPolicy::FlushOnShutdown
        );
        assert!(config.groups().enabled());
        assert_eq!(config.auth_ttl_seconds(), 300);
        assert_eq!(config.auth_created_at_skew_seconds(), 600);
        assert_eq!(config.limits().max_subscriptions_per_connection(), 64);
        assert_eq!(config.rate_limits().auth().per_ip().max_hits(), 120);
        assert!(config.backup_export().backup_enabled());
        assert!(config.backup_export().export_enabled());
        assert!(config.relay_self_pubkey().expect("relay self").is_some());
    }

    #[test]
    fn tangle_v1_mvp_config_rejects_legacy_single_relay_shape() {
        let raw = include_str!("../../../config/tangle.example.json");

        assert_eq!(
            parse_tangle_host_runtime_config_json(raw)
                .expect_err("legacy host config")
                .prefixed_message(),
            "invalid: legacy single-relay config is not supported"
        );
        assert_eq!(
            parse_tenant_runtime_config_json(raw)
                .expect_err("legacy tenant config")
                .prefixed_message(),
            "invalid: legacy single-relay config is not supported"
        );
    }

    #[test]
    fn tangle_host_runtime_config_set_rejects_invalid_tenant_sets() {
        let host = parse_tangle_host_runtime_config_json(include_str!(
            "../../../config/tangle.host.example.json"
        ))
        .expect("host config");
        let first = tenant_from_value(first_tenant_value());
        let second = tenant_from_value(second_tenant_value());
        TangleHostRuntimeConfigSet::new(host.clone(), vec![first.clone(), second.clone()])
            .expect("unique tenants");

        assert!(
            TangleHostRuntimeConfigSet::new(
                host.clone(),
                vec![first.clone(), mutate_second("tenant_id", "farmers-market")]
            )
            .expect_err("tenant id")
            .prefixed_message()
            .contains("duplicate tenant tenant_id")
        );
        assert!(
            TangleHostRuntimeConfigSet::new(
                host.clone(),
                vec![
                    first.clone(),
                    mutate_second("tenant_schema", "farmers_market")
                ]
            )
            .expect_err("schema")
            .prefixed_message()
            .contains("duplicate tenant tenant_schema")
        );
        assert!(
            TangleHostRuntimeConfigSet::new(
                host.clone(),
                vec![first.clone(), mutate_second("host", "relay.radroots.test")]
            )
            .expect_err("host")
            .prefixed_message()
            .contains("duplicate tenant host")
        );
        assert!(
            TangleHostRuntimeConfigSet::new(
                host.clone(),
                vec![
                    first.clone(),
                    mutate_second("relay_url", "wss://relay.radroots.test")
                ]
            )
            .expect_err("relay url")
            .prefixed_message()
            .contains("duplicate tenant relay_url")
        );
        assert!(
            TangleHostRuntimeConfigSet::new(
                host.clone(),
                vec![first.clone(), second_with_group_secret("7")]
            )
            .expect_err("relay self")
            .prefixed_message()
            .contains("duplicate tenant relay self pubkey")
        );
        assert!(
            TangleHostRuntimeConfigSet::new(
                host.clone(),
                vec![
                    first.clone(),
                    second_with_store_path("./runtime/tenants/farmers_market/pocket")
                ]
            )
            .expect_err("store")
            .prefixed_message()
            .contains("duplicate tenant pocket data directory")
        );
        assert_eq!(
            TangleHostRuntimeConfigSet::new(
                host,
                vec![inactive_first_tenant(), inactive_second_tenant()]
            )
            .expect_err("active tenants")
            .prefixed_message(),
            "invalid: at least one active tenant is required"
        );
    }

    fn first_tenant_value() -> Value {
        serde_json::from_str(include_str!(
            "../../../config/tenants/farmers_market.example.json"
        ))
        .expect("tenant json")
    }

    fn second_tenant_value() -> Value {
        let mut value = first_tenant_value();
        value["tenant_id"] = json!("seed-coop");
        value["tenant_schema"] = json!("seed_coop");
        value["host"] = json!("seed.relay.radroots.test");
        value["relay_url"] = json!("wss://seed.relay.radroots.test");
        value["pocket"]["data_directory"] = json!("runtime/tenants/seed_coop/pocket");
        value["groups"]["canonical_relay_url"] = json!("wss://seed.relay.radroots.test");
        value["groups"]["relay_secret"] =
            json!("8888888888888888888888888888888888888888888888888888888888888888");
        value
    }

    fn tenant_from_value(value: Value) -> TenantRuntimeConfig {
        parse_tenant_runtime_config_json(&value.to_string()).expect("tenant")
    }

    fn mutate_second(field: &str, field_value: &str) -> TenantRuntimeConfig {
        let mut value = second_tenant_value();
        value[field] = json!(field_value);
        if field == "relay_url" {
            value["groups"]["canonical_relay_url"] = json!(field_value);
        }
        tenant_from_value(value)
    }

    fn second_with_group_secret(nibble: &str) -> TenantRuntimeConfig {
        let mut value = second_tenant_value();
        value["groups"]["relay_secret"] = json!(nibble.repeat(64));
        tenant_from_value(value)
    }

    fn second_with_store_path(path: &str) -> TenantRuntimeConfig {
        let mut value = second_tenant_value();
        value["pocket"]["data_directory"] = json!(path);
        tenant_from_value(value)
    }

    fn inactive_first_tenant() -> TenantRuntimeConfig {
        let mut value = first_tenant_value();
        value["inactive"] = json!(true);
        tenant_from_value(value)
    }

    fn inactive_second_tenant() -> TenantRuntimeConfig {
        let mut value = second_tenant_value();
        value["inactive"] = json!(true);
        tenant_from_value(value)
    }

    #[test]
    fn base_relay_runtime_config_parses_v2_production_example() {
        let config = parse_base_relay_runtime_config_json(include_str!(
            "../../../config/tangle.example.json"
        ))
        .expect("config");

        assert_eq!(config.listen_addr().to_string(), "0.0.0.0:7000");
        assert_eq!(config.relay_url(), "wss://relay.radroots.test");
        assert_eq!(
            config.pocket_config().data_directory(),
            Path::new("runtime/pocket")
        );
        assert_eq!(
            config.pocket_config().sync_policy(),
            PocketSyncPolicy::FlushOnShutdown
        );
        assert!(!config.pocket_query_config().allow_scraping());
        assert_eq!(
            config.pocket_query_config().allow_scrape_if_limited_to(),
            100
        );
        assert_eq!(
            config.pocket_query_config().allow_scrape_if_max_seconds(),
            3_600
        );
        assert!(config.groups().enabled());
        assert!(!config.groups().policy().public_join());
        assert!(!config.groups().policy().invites_enabled());
        assert_eq!(config.auth_ttl_seconds(), 300);
        assert_eq!(config.auth_created_at_skew_seconds(), 600);
        assert_eq!(config.limits().max_message_length(), 1_048_576);
        assert_eq!(config.limits().max_subid_length(), 64);
        assert_eq!(config.limits().max_subscriptions_per_connection(), 64);
        assert_eq!(config.limits().max_filters_per_request(), 10);
        assert_eq!(config.limits().max_tag_values_per_filter(), 100);
        assert_eq!(config.limits().max_query_complexity(), 2_048);
        assert_eq!(config.limits().max_limit(), 500);
        assert_eq!(config.limits().default_limit(), 100);
        assert_eq!(config.limits().max_event_tags(), 200);
        assert_eq!(config.limits().max_content_length(), 65_536);
        assert_eq!(config.limits().broadcast_channel_capacity(), 4_096);
        assert_eq!(config.limits().per_connection_outbound_queue(), 256);
        assert_eq!(config.rate_limits().auth().per_ip().max_hits(), 120);
        assert_eq!(config.rate_limits().auth().per_pubkey().max_hits(), 30);
        assert_eq!(config.rate_limits().auth().failures().max_hits(), 5);
        assert_eq!(config.rate_limits().auth().failures_per_ip().max_hits(), 20);
        assert_eq!(config.rate_limits().event().per_ip().max_hits(), 600);
        assert_eq!(config.rate_limits().event().per_pubkey().max_hits(), 120);
        assert_eq!(config.rate_limits().event().per_kind().max_hits(), 1_000);
        assert_eq!(config.rate_limits().group().write_per_ip().max_hits(), 300);
        assert_eq!(
            config.rate_limits().group().write_per_pubkey().max_hits(),
            60
        );
        assert_eq!(
            config.rate_limits().group().write_per_group().max_hits(),
            90
        );
        assert_eq!(
            config.rate_limits().group().write_per_kind().max_hits(),
            300
        );
        assert_eq!(config.rate_limits().group().join_flow().max_hits(), 10);
        assert_eq!(
            config.rate_limits().group().join_flow_per_ip().max_hits(),
            30
        );
        assert_eq!(config.rate_limits().req().per_ip().max_hits(), 600);
        assert_eq!(config.rate_limits().req().per_connection().max_hits(), 120);
        assert_eq!(config.rate_limits().req().per_pubkey().max_hits(), 240);
        assert_eq!(config.rate_limits().req().per_group().max_hits(), 240);
        assert_eq!(config.rate_limits().req().per_kind().max_hits(), 500);
        assert_eq!(config.rate_limits().req().broad().max_hits(), 30);
        assert_eq!(config.rate_limits().count().per_ip().max_hits(), 300);
        assert_eq!(config.rate_limits().count().per_connection().max_hits(), 60);
        assert_eq!(config.rate_limits().count().per_pubkey().max_hits(), 120);
        assert_eq!(config.rate_limits().count().per_group().max_hits(), 120);
        assert_eq!(config.rate_limits().count().per_kind().max_hits(), 240);
        assert_eq!(config.rate_limits().count().broad().max_hits(), 20);
        assert!(config.tracing().enabled());
        assert_eq!(config.tracing().format(), BaseRelayTracingFormat::Json);
        config.auth_state().expect("auth");
    }

    #[test]
    fn base_relay_runtime_config_rejects_zero_auth_skew() {
        let raw = r#"{
            "server": {
                "listen_addr": "127.0.0.1:0",
                "relay_url": "wss://relay.radroots.test"
            },
            "pocket": {
                "data_directory": "runtime/pocket",
                "sync_policy": "flush_on_shutdown",
                "query": {
                  "allow_scraping": false,
                  "allow_scrape_if_limited_to": 100,
                  "allow_scrape_if_max_seconds": 3600
                }
            },
            "groups": {
                "enabled": false
            },
            "auth": {
                "challenge_ttl_seconds": 300,
                "created_at_skew_seconds": 0
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
                "broadcast_channel_capacity": 4096,
                "per_connection_outbound_queue": 256
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
        }"#;

        assert_eq!(
            parse_base_relay_runtime_config_json(raw)
                .expect_err("zero skew")
                .prefixed_message(),
            "invalid: auth.created_at_skew_seconds must be greater than zero"
        );
    }

    #[test]
    fn base_relay_runtime_config_rejects_unknown_fields() {
        let unknown_top_level = r#"{
            "server": {
                "listen_addr": "127.0.0.1:0",
                "relay_url": "wss://relay.radroots.test"
            },
            "pocket": {
                "data_directory": "runtime/pocket",
                "sync_policy": "flush_on_shutdown",
                "query": {
                  "allow_scraping": false,
                  "allow_scrape_if_limited_to": 100,
                  "allow_scrape_if_max_seconds": 3600
                }
            },
            "groups": {
                "enabled": false
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
                "broadcast_channel_capacity": 4096,
                "per_connection_outbound_queue": 256
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
            },
            "ignored": true
        }"#;
        assert!(
            parse_base_relay_runtime_config_json(unknown_top_level)
                .expect_err("unknown top-level field")
                .prefixed_message()
                .contains("unknown field `ignored`")
        );

        let unknown_nested = r#"{
            "server": {
                "listen_addr": "127.0.0.1:0",
                "relay_url": "wss://relay.radroots.test"
            },
            "pocket": {
                "data_directory": "runtime/pocket",
                "sync_policy": "flush_on_shutdown",
                "query": {
                  "allow_scraping": false,
                  "allow_scrape_if_limited_to": 100,
                  "allow_scrape_if_max_seconds": 3600
                }
            },
            "groups": {
                "enabled": false
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
                "broadcast_channel_capacity": 4096,
                "per_connection_outbound_queue": 256,
                "max_unimplemented_limit": 99
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
        }"#;
        assert!(
            parse_base_relay_runtime_config_json(unknown_nested)
                .expect_err("unknown nested field")
                .prefixed_message()
                .contains("unknown field `max_unimplemented_limit`")
        );
    }

    #[test]
    fn base_relay_runtime_config_rejects_removed_pocket_options() {
        let raw = include_str!("../../../config/tangle.example.json").replace(
            "    \"data_directory\": \"runtime/pocket\",\n",
            "    \"data_directory\": \"runtime/pocket\",\n    \"map_size_bytes\": 1073741824,\n",
        );
        assert!(
            parse_base_relay_runtime_config_json(&raw)
                .expect_err("removed map size")
                .prefixed_message()
                .contains("unknown field `map_size_bytes`")
        );

        let raw = include_str!("../../../config/tangle.example.json").replace(
            "    \"data_directory\": \"runtime/pocket\",\n",
            "    \"data_directory\": \"runtime/pocket\",\n    \"reader_slots\": 128,\n",
        );
        assert!(
            parse_base_relay_runtime_config_json(&raw)
                .expect_err("removed readers")
                .prefixed_message()
                .contains("unknown field `reader_slots`")
        );
    }

    #[test]
    fn base_relay_runtime_config_validates_pocket_query_controls() {
        let raw = include_str!("../../../config/tangle.example.json").replace(
            "    \"allow_scrape_if_limited_to\": 100,\n",
            "    \"allow_scrape_if_limited_to\": 501,\n",
        );
        assert_eq!(
            parse_base_relay_runtime_config_json(&raw)
                .expect_err("query scrape limit")
                .prefixed_message(),
            "invalid: pocket.query.allow_scrape_if_limited_to must be less than or equal to limits.max_limit"
        );

        let raw = include_str!("../../../config/tangle.example.json").replace(
            "    \"allow_scrape_if_max_seconds\": 3600\n",
            "    \"allow_scrape_if_max_seconds\": 86401\n",
        );
        assert_eq!(
            parse_base_relay_runtime_config_json(&raw)
                .expect_err("query scrape window")
                .prefixed_message(),
            "invalid: pocket.query.allow_scrape_if_max_seconds must be less than or equal to 86400"
        );
    }

    #[test]
    fn base_relay_runtime_config_requires_explicit_query_complexity() {
        let raw = include_str!("../../../config/tangle.example.json")
            .replace("    \"max_query_complexity\": 2048,\n", "");
        assert!(
            parse_base_relay_runtime_config_json(&raw)
                .expect_err("missing query complexity")
                .prefixed_message()
                .contains("missing field `max_query_complexity`")
        );
    }

    #[test]
    fn base_relay_runtime_config_requires_ip_scoped_rate_limits() {
        let raw = include_str!("../../../config/tangle.example.json").replace(
            "      \"per_ip\": {\n        \"window_seconds\": 60,\n        \"max_hits\": 120\n      },\n",
            "",
        );
        assert!(
            parse_base_relay_runtime_config_json(&raw)
                .expect_err("missing auth ip")
                .prefixed_message()
                .contains("missing field `per_ip`")
        );

        let raw = include_str!("../../../config/tangle.example.json").replace(
            "      \"failures\": {\n        \"window_seconds\": 300,\n        \"max_hits\": 5\n      },\n      \"failures_per_ip\": {\n        \"window_seconds\": 300,\n        \"max_hits\": 20\n      }\n",
            "      \"failures\": {\n        \"window_seconds\": 300,\n        \"max_hits\": 5\n      }\n",
        );
        assert!(
            parse_base_relay_runtime_config_json(&raw)
                .expect_err("missing auth failure ip")
                .prefixed_message()
                .contains("missing field `failures_per_ip`")
        );

        let raw = include_str!("../../../config/tangle.example.json").replace(
            "      \"per_ip\": {\n        \"window_seconds\": 60,\n        \"max_hits\": 600\n      },\n",
            "",
        );
        assert!(
            parse_base_relay_runtime_config_json(&raw)
                .expect_err("missing event ip")
                .prefixed_message()
                .contains("missing field `per_ip`")
        );

        let raw = include_str!("../../../config/tangle.example.json").replace(
            "      \"write_per_ip\": {\n        \"window_seconds\": 60,\n        \"max_hits\": 300\n      },\n",
            "",
        );
        assert!(
            parse_base_relay_runtime_config_json(&raw)
                .expect_err("missing group write ip")
                .prefixed_message()
                .contains("missing field `write_per_ip`")
        );

        let raw = include_str!("../../../config/tangle.example.json").replace(
            "      \"join_flow\": {\n        \"window_seconds\": 300,\n        \"max_hits\": 10\n      },\n      \"join_flow_per_ip\": {\n        \"window_seconds\": 300,\n        \"max_hits\": 30\n      }\n",
            "      \"join_flow\": {\n        \"window_seconds\": 300,\n        \"max_hits\": 10\n      }\n",
        );
        assert!(
            parse_base_relay_runtime_config_json(&raw)
                .expect_err("missing group join ip")
                .prefixed_message()
                .contains("missing field `join_flow_per_ip`")
        );
    }
}
