#![forbid(unsafe_code)]

use crate::{
    config::{BaseRelayRuntimeConfig, BaseRelayRuntimeLimitsConfig},
    errors::BaseRelayError,
};
use axum::{
    Json, Router,
    extract::State,
    response::{IntoResponse, Response},
    routing::get,
};
use http::{HeaderMap, HeaderValue, StatusCode, header};
use serde::{Deserialize, Serialize};
use tangle_crypto::RelaySigner;
use tangle_groups::GroupRuntimeConfig;
use tangle_protocol::PublicKeyHex;

const ALWAYS_SUPPORTED_NIPS: [u16; 5] = [1, 11, 42, 45, 70];
const GROUP_SUPPORTED_NIP: u16 = 29;

pub fn supported_nips_for_runtime(runtime: &BaseRelayRuntimeConfig) -> Vec<u16> {
    supported_nips_for_group_capability(runtime.groups().enabled())
}

pub fn supported_nips_for_group_capability(groups_enabled: bool) -> Vec<u16> {
    let mut supported_nips = ALWAYS_SUPPORTED_NIPS.to_vec();
    if groups_enabled {
        supported_nips.push(GROUP_SUPPORTED_NIP);
        supported_nips.sort_unstable();
    }
    supported_nips
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaseRelayInfoConfig {
    name: String,
    description: Option<String>,
    contact: Option<String>,
    icon: Option<String>,
    groups: GroupRuntimeConfig,
    limits: BaseRelayRuntimeLimitsConfig,
    software: String,
    version: String,
    payment_required: bool,
    restricted_writes: bool,
    supported_nips: Vec<u16>,
}

impl BaseRelayInfoConfig {
    pub fn new(
        name: impl Into<String>,
        runtime: &BaseRelayRuntimeConfig,
    ) -> Result<Self, BaseRelayError> {
        let name = name.into();
        if name.trim().is_empty() {
            return Err(BaseRelayError::invalid("relay name must not be empty"));
        }
        Ok(Self {
            name,
            description: None,
            contact: None,
            icon: None,
            groups: runtime.groups().clone(),
            limits: runtime.limits(),
            software: crate::TANGLE_RELAY_SOFTWARE.to_owned(),
            version: crate::TANGLE_RELAY_VERSION.to_owned(),
            payment_required: false,
            restricted_writes: true,
            supported_nips: supported_nips_for_runtime(runtime),
        })
    }

    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    pub fn with_contact(mut self, contact: impl Into<String>) -> Self {
        self.contact = Some(contact.into());
        self
    }

    pub fn with_icon(mut self, icon: impl Into<String>) -> Self {
        self.icon = Some(icon.into());
        self
    }

    pub fn build_document(&self) -> Result<BaseRelayInfoDocument, BaseRelayError> {
        let relay_self = relay_self_from_groups(&self.groups)?;
        Ok(BaseRelayInfoDocument {
            name: self.name.clone(),
            description: self.description.clone(),
            contact: self.contact.clone(),
            icon: self.icon.clone(),
            relay_self: relay_self.map(|pubkey| pubkey.as_str().to_owned()),
            supported_nips: self.supported_nips.clone(),
            software: self.software.clone(),
            version: self.version.clone(),
            limitation: BaseRelayInfoLimitationDocument {
                max_message_length: self.limits.max_message_length(),
                max_subscriptions: self.limits.max_subscriptions_per_connection(),
                max_filters: self.limits.max_filters_per_request(),
                max_limit: self.limits.max_limit(),
                max_query_complexity: self.limits.max_query_complexity(),
                max_subid_length: self.limits.max_subid_length(),
                max_event_tags: self.limits.max_event_tags(),
                max_content_length: self.limits.max_content_length(),
                auth_required: false,
                payment_required: self.payment_required,
                restricted_writes: self.restricted_writes,
                default_limit: self.limits.default_limit(),
            },
            retention: BaseRelayInfoRetentionDocument::tangle_default(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BaseRelayInfoDocument {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contact: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icon: Option<String>,
    #[serde(rename = "self", skip_serializing_if = "Option::is_none")]
    pub relay_self: Option<String>,
    pub supported_nips: Vec<u16>,
    pub software: String,
    pub version: String,
    pub limitation: BaseRelayInfoLimitationDocument,
    pub retention: BaseRelayInfoRetentionDocument,
}

impl BaseRelayInfoDocument {
    pub fn relay_self(&self) -> Option<&str> {
        self.relay_self.as_deref()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BaseRelayInfoLimitationDocument {
    pub max_message_length: usize,
    pub max_subscriptions: usize,
    pub max_filters: usize,
    pub max_limit: u64,
    pub max_query_complexity: usize,
    pub max_subid_length: usize,
    pub max_event_tags: usize,
    pub max_content_length: usize,
    pub auth_required: bool,
    pub payment_required: bool,
    pub restricted_writes: bool,
    pub default_limit: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BaseRelayInfoRetentionDocument {
    pub accepted_events: String,
    pub relay_generated_events: String,
    pub group_visibility: String,
    pub physical_erasure: bool,
    pub compaction_guarantee: bool,
}

impl BaseRelayInfoRetentionDocument {
    fn tangle_default() -> Self {
        Self {
            accepted_events: "accepted events are retained in canonical storage without a time-based expiration policy".to_owned(),
            relay_generated_events: "relay-generated group state events are retained with their source events".to_owned(),
            group_visibility: "private and hidden group policy gates visibility without implying physical deletion".to_owned(),
            physical_erasure: false,
            compaction_guarantee: false,
        }
    }
}

pub fn base_relay_info_router(document: BaseRelayInfoDocument) -> Router {
    Router::new()
        .route("/", get(base_relay_info))
        .with_state(document)
}

async fn base_relay_info(
    State(document): State<BaseRelayInfoDocument>,
    headers: HeaderMap,
) -> Response {
    base_relay_info_response(document, headers)
}

pub fn base_relay_info_response(document: BaseRelayInfoDocument, headers: HeaderMap) -> Response {
    if !accepts_nostr_json(headers.get(header::ACCEPT)) {
        return (
            StatusCode::NOT_FOUND,
            "relay information requires application/nostr+json",
        )
            .into_response();
    }
    (
        StatusCode::OK,
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/nostr+json"),
            ),
            (
                header::ACCESS_CONTROL_ALLOW_ORIGIN,
                HeaderValue::from_static("*"),
            ),
            (
                header::ACCESS_CONTROL_ALLOW_HEADERS,
                HeaderValue::from_static("*"),
            ),
            (
                header::ACCESS_CONTROL_ALLOW_METHODS,
                HeaderValue::from_static("*"),
            ),
        ],
        Json(document),
    )
        .into_response()
}

fn relay_self_from_groups(
    groups: &GroupRuntimeConfig,
) -> Result<Option<PublicKeyHex>, BaseRelayError> {
    groups
        .relay_secret()
        .map(|secret| RelaySigner::from_secret_hex(secret.expose_for_signing()))
        .transpose()
        .map(|signer| signer.map(|signer| signer.public_key().clone()))
        .map_err(BaseRelayError::invalid)
}

fn accepts_nostr_json(value: Option<&HeaderValue>) -> bool {
    value
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value.split(',').any(|item| {
                let item = item.trim();
                item == "*/*" || item.starts_with("application/nostr+json")
            })
        })
}

#[cfg(test)]
mod tests {
    use super::{BaseRelayInfoConfig, base_relay_info_response, base_relay_info_router};
    use crate::config::{BaseRelayRuntimeConfig, parse_base_relay_runtime_config_json};
    use axum::body::to_bytes;
    use http::{HeaderMap, HeaderValue, Request, StatusCode, header};
    use serde_json::{Value, json};
    use tangle_crypto::RelaySigner;
    use tower::ServiceExt;

    #[test]
    fn nip11_builder_reports_groups_and_relay_self_only_when_configured() {
        let config = runtime_config(enabled_groups());
        let disabled_config = runtime_config(json!({"enabled": false}));
        let document = BaseRelayInfoConfig::new("tangle", &config)
            .expect("config")
            .with_description("Tangle v2 relay")
            .build_document()
            .expect("document");
        let disabled = BaseRelayInfoConfig::new("tangle", &disabled_config)
            .expect("config")
            .build_document()
            .expect("disabled");

        assert_eq!(document.supported_nips, vec![1, 11, 29, 42, 45, 70]);
        assert!(document.relay_self().is_some());
        assert_eq!(document.description.as_deref(), Some("Tangle v2 relay"));
        assert_eq!(document.limitation.max_message_length, 1_048_576);
        assert_eq!(document.limitation.max_subscriptions, 64);
        assert_eq!(document.limitation.max_filters, 10);
        assert_eq!(document.limitation.max_limit, 500);
        assert_eq!(document.limitation.max_query_complexity, 2_048);
        assert_eq!(document.limitation.max_subid_length, 64);
        assert_eq!(document.limitation.max_event_tags, 200);
        assert_eq!(document.limitation.max_content_length, 65_536);
        assert!(!document.limitation.auth_required);
        assert!(!document.limitation.payment_required);
        assert!(document.limitation.restricted_writes);
        assert_eq!(document.limitation.default_limit, 100);
        assert_eq!(
            document.retention.accepted_events,
            "accepted events are retained in canonical storage without a time-based expiration policy"
        );
        assert_eq!(
            document.retention.group_visibility,
            "private and hidden group policy gates visibility without implying physical deletion"
        );
        assert!(!document.retention.physical_erasure);
        assert!(!document.retention.compaction_guarantee);
        assert_eq!(disabled.supported_nips, vec![1, 11, 42, 45, 70]);
        assert!(disabled.relay_self().is_none());
    }

    #[tokio::test]
    async fn nip11_preserves_chorus_relay_information_parity() {
        let config = runtime_config(enabled_groups());
        let disabled_config = runtime_config(json!({"enabled": false}));
        let document = BaseRelayInfoConfig::new("tangle", &config)
            .expect("config")
            .with_description("Tangle relay")
            .with_contact("ops@radroots.test")
            .with_icon("https://relay.radroots.test/icon.png")
            .build_document()
            .expect("document");
        let disabled = BaseRelayInfoConfig::new("tangle", &disabled_config)
            .expect("disabled config")
            .build_document()
            .expect("disabled");
        let relay_self = RelaySigner::from_secret_hex(&"7".repeat(64))
            .expect("relay signer")
            .public_key()
            .clone();

        assert_eq!(document.name, "tangle");
        assert_eq!(document.description.as_deref(), Some("Tangle relay"));
        assert_eq!(document.contact.as_deref(), Some("ops@radroots.test"));
        assert_eq!(
            document.icon.as_deref(),
            Some("https://relay.radroots.test/icon.png")
        );
        assert_eq!(document.relay_self(), Some(relay_self.as_str()));
        assert_eq!(document.supported_nips, vec![1, 11, 29, 42, 45, 70]);
        for absent in [50, 77, 86, 98, 99] {
            assert!(!document.supported_nips.contains(&absent));
        }
        assert_eq!(disabled.supported_nips, vec![1, 11, 42, 45, 70]);
        assert!(disabled.relay_self().is_none());
        assert_eq!(document.software, crate::TANGLE_RELAY_SOFTWARE);
        assert_eq!(document.version, crate::TANGLE_RELAY_VERSION);
        assert_eq!(document.limitation.max_message_length, 1_048_576);
        assert_eq!(document.limitation.max_subscriptions, 64);
        assert_eq!(document.limitation.max_filters, 10);
        assert_eq!(document.limitation.max_limit, 500);
        assert_eq!(document.limitation.max_query_complexity, 2_048);
        assert_eq!(document.limitation.max_subid_length, 64);
        assert_eq!(document.limitation.max_event_tags, 200);
        assert_eq!(document.limitation.max_content_length, 65_536);
        assert!(!document.limitation.auth_required);
        assert!(!document.limitation.payment_required);
        assert!(document.limitation.restricted_writes);
        assert_eq!(document.limitation.default_limit, 100);
        assert_eq!(
            document.retention.accepted_events,
            "accepted events are retained in canonical storage without a time-based expiration policy"
        );
        assert_eq!(
            document.retention.relay_generated_events,
            "relay-generated group state events are retained with their source events"
        );
        assert_eq!(
            document.retention.group_visibility,
            "private and hidden group policy gates visibility without implying physical deletion"
        );
        assert!(!document.retention.physical_erasure);
        assert!(!document.retention.compaction_guarantee);

        let mut headers = HeaderMap::new();
        headers.insert(
            header::ACCEPT,
            HeaderValue::from_static("application/nostr+json; q=1"),
        );
        let response = base_relay_info_response(document.clone(), headers);
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).expect("type"),
            "application/nostr+json"
        );
        assert_eq!(
            response
                .headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .expect("origin"),
            "*"
        );
        assert_eq!(
            response
                .headers()
                .get(header::ACCESS_CONTROL_ALLOW_HEADERS)
                .expect("headers"),
            "*"
        );
        assert_eq!(
            response
                .headers()
                .get(header::ACCESS_CONTROL_ALLOW_METHODS)
                .expect("methods"),
            "*"
        );
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        let value = serde_json::from_slice::<Value>(&body).expect("json");
        assert_eq!(value["software"], crate::TANGLE_RELAY_SOFTWARE);
        assert_eq!(value["version"], crate::TANGLE_RELAY_VERSION);
        assert_eq!(value["supported_nips"], json!([1, 11, 29, 42, 45, 70]));
        assert_eq!(value["retention"]["physical_erasure"], false);
        assert_eq!(value["retention"]["compaction_guarantee"], false);

        let rejected = base_relay_info_response(document, HeaderMap::new());
        assert_eq!(rejected.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn nip11_router_serves_nostr_json_only_for_nostr_accept() {
        let config = runtime_config(enabled_groups());
        let document = BaseRelayInfoConfig::new("tangle", &config)
            .expect("config")
            .build_document()
            .expect("document");
        let response = base_relay_info_router(document.clone())
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header(header::ACCEPT, "application/nostr+json")
                    .body(axum::body::Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).expect("type"),
            "application/nostr+json"
        );
        assert_eq!(
            response
                .headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .expect("origin"),
            "*"
        );
        assert_eq!(
            response
                .headers()
                .get(header::ACCESS_CONTROL_ALLOW_HEADERS)
                .expect("headers"),
            "*"
        );
        assert_eq!(
            response
                .headers()
                .get(header::ACCESS_CONTROL_ALLOW_METHODS)
                .expect("methods"),
            "*"
        );
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        let value = serde_json::from_slice::<serde_json::Value>(&body).expect("json");
        assert_eq!(value["name"], document.name);
        assert!(value["self"].as_str().is_some());
        assert_eq!(value["retention"]["physical_erasure"], false);
        assert_eq!(value["retention"]["compaction_guarantee"], false);
        assert_eq!(
            value["retention"]["group_visibility"],
            "private and hidden group policy gates visibility without implying physical deletion"
        );

        let rejected = base_relay_info_router(document)
            .oneshot(
                Request::builder()
                    .uri("/")
                    .body(axum::body::Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(rejected.status(), StatusCode::NOT_FOUND);
    }

    fn enabled_groups() -> Value {
        let owner = RelaySigner::from_secret_hex(&"8".repeat(64))
            .expect("owner")
            .public_key()
            .clone();
        json!({
            "enabled": true,
            "canonical_relay_url": "wss://relay.radroots.test",
            "relay_secret": "7".repeat(64),
            "owner_pubkeys": [owner.as_str()]
        })
    }

    fn runtime_config(groups: Value) -> BaseRelayRuntimeConfig {
        parse_base_relay_runtime_config_json(
            &json!({
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
                "groups": groups,
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
                }
            })
            .to_string(),
        )
        .expect("runtime config")
    }
}
