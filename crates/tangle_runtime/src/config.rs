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
};
use serde::Deserialize;
use std::{net::SocketAddr, path::PathBuf};
use tangle_groups::GroupRuntimeConfig;
use tangle_protocol::SubscriptionId;
use tangle_store_pocket::{PocketStoreConfig, PocketSyncPolicy};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaseRelayRuntimeConfig {
    listen_addr: SocketAddr,
    relay_url: String,
    pocket: PocketStoreConfig,
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
        BaseRelay::open_with_groups(&self.pocket, self.limits.base_relay_limits()?, &self.groups)
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
    map_size_bytes: u64,
    reader_slots: u32,
    sync_policy: BaseRelayPocketSyncPolicyDocument,
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
    let pocket = PocketStoreConfig::new(
        PathBuf::from(document.pocket.data_directory),
        document.pocket.map_size_bytes,
        document.pocket.reader_slots,
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
    let limits = BaseRelayRuntimeLimitsConfig::from_document(document.limits)?;
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
        groups,
        auth_ttl_seconds: document.auth.challenge_ttl_seconds,
        auth_created_at_skew_seconds: document.auth.created_at_skew_seconds,
        limits,
        rate_limits,
        tracing,
    })
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

#[cfg(test)]
mod tests {
    use super::{BaseRelayTracingFormat, parse_base_relay_runtime_config_json};
    use std::path::Path;
    use tangle_store_pocket::PocketSyncPolicy;

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
        assert_eq!(config.pocket_config().map_size_bytes(), 1_099_511_627_776);
        assert_eq!(config.pocket_config().reader_slots(), 512);
        assert_eq!(
            config.pocket_config().sync_policy(),
            PocketSyncPolicy::FlushOnShutdown
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
                "map_size_bytes": 1073741824,
                "reader_slots": 128,
                "sync_policy": "flush_on_shutdown"
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
                "map_size_bytes": 1073741824,
                "reader_slots": 128,
                "sync_policy": "flush_on_shutdown"
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
                "map_size_bytes": 1073741824,
                "reader_slots": 128,
                "sync_policy": "flush_on_shutdown"
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
