#![forbid(unsafe_code)]

use crate::{
    errors::BaseRelayError,
    relay::{auth::BaseAuthState, core::BaseRelay},
};
use serde::Deserialize;
use std::{net::SocketAddr, path::PathBuf};
use tangle_groups::GroupRuntimeConfig;
use tangle_store_pocket::{PocketStoreConfig, PocketSyncPolicy};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaseRelayRuntimeConfig {
    listen_addr: SocketAddr,
    relay_url: String,
    pocket: PocketStoreConfig,
    groups: GroupRuntimeConfig,
    auth_ttl_seconds: u64,
    max_pending_events: usize,
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

    pub fn max_pending_events(&self) -> usize {
        self.max_pending_events
    }

    pub fn tracing(&self) -> &BaseRelayTracingConfig {
        &self.tracing
    }

    pub fn open_relay(&self) -> Result<BaseRelay, BaseRelayError> {
        BaseRelay::open_with_groups(&self.pocket, self.max_pending_events, &self.groups)
    }

    pub fn auth_state(&self) -> Result<BaseAuthState, BaseRelayError> {
        BaseAuthState::new(self.relay_url.clone(), self.auth_ttl_seconds)
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

#[derive(Debug, Deserialize)]
struct BaseRelayRuntimeConfigDocument {
    server: BaseRelayServerConfigDocument,
    pocket: BaseRelayPocketConfigDocument,
    groups: serde_json::Value,
    auth: BaseRelayAuthConfigDocument,
    limits: BaseRelayRuntimeLimitsDocument,
    #[serde(default)]
    observability: BaseRelayObservabilityConfigDocument,
}

#[derive(Debug, Deserialize)]
struct BaseRelayServerConfigDocument {
    listen_addr: String,
    relay_url: String,
}

#[derive(Debug, Deserialize)]
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
struct BaseRelayAuthConfigDocument {
    challenge_ttl_seconds: u64,
}

#[derive(Debug, Deserialize)]
struct BaseRelayRuntimeLimitsDocument {
    max_pending_events: usize,
}

#[derive(Debug, Default, Deserialize)]
struct BaseRelayObservabilityConfigDocument {
    #[serde(default)]
    tracing: BaseRelayTracingConfigDocument,
}

#[derive(Debug, Default, Deserialize)]
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
    if document.limits.max_pending_events == 0 {
        return Err(BaseRelayError::invalid(
            "limits.max_pending_events must be greater than zero",
        ));
    }
    let tracing = base_relay_tracing_config_from_document(document.observability.tracing)?;
    Ok(BaseRelayRuntimeConfig {
        listen_addr,
        relay_url: document.server.relay_url,
        pocket,
        groups,
        auth_ttl_seconds: document.auth.challenge_ttl_seconds,
        max_pending_events: document.limits.max_pending_events,
        tracing,
    })
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
            "../../../ops/production/tangle-v2.example.json"
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
        assert_eq!(config.auth_ttl_seconds(), 300);
        assert_eq!(config.max_pending_events(), 1024);
        assert!(config.tracing().enabled());
        assert_eq!(config.tracing().format(), BaseRelayTracingFormat::Json);
        config.auth_state().expect("auth");
    }
}
