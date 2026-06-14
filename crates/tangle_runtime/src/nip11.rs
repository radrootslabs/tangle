#![forbid(unsafe_code)]

use crate::errors::BaseRelayError;
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

pub const BASE_RELAY_SUPPORTED_NIPS: [u16; 5] = [1, 11, 42, 45, 70];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaseRelayInfoConfig {
    name: String,
    description: Option<String>,
    contact: Option<String>,
    icon: Option<String>,
    groups: GroupRuntimeConfig,
    software: String,
    version: String,
    payment_required: bool,
    restricted_writes: bool,
}

impl BaseRelayInfoConfig {
    pub fn new(
        name: impl Into<String>,
        groups: GroupRuntimeConfig,
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
            groups,
            software: crate::TANGLE_RELAY_SOFTWARE.to_owned(),
            version: crate::TANGLE_RELAY_VERSION.to_owned(),
            payment_required: false,
            restricted_writes: true,
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
        let mut supported_nips = BASE_RELAY_SUPPORTED_NIPS.to_vec();
        if self.groups.enabled() {
            supported_nips.push(29);
            supported_nips.sort_unstable();
        }
        Ok(BaseRelayInfoDocument {
            name: self.name.clone(),
            description: self.description.clone(),
            contact: self.contact.clone(),
            icon: self.icon.clone(),
            relay_self: relay_self.map(|pubkey| pubkey.as_str().to_owned()),
            supported_nips,
            software: self.software.clone(),
            version: self.version.clone(),
            limitation: BaseRelayInfoLimitationDocument {
                payment_required: self.payment_required,
                restricted_writes: self.restricted_writes,
            },
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
}

impl BaseRelayInfoDocument {
    pub fn relay_self(&self) -> Option<&str> {
        self.relay_self.as_deref()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BaseRelayInfoLimitationDocument {
    pub payment_required: bool,
    pub restricted_writes: bool,
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
    if !accepts_nostr_json(headers.get(header::ACCEPT)) {
        return (
            StatusCode::NOT_FOUND,
            "relay information requires application/nostr+json",
        )
            .into_response();
    }
    (
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/nostr+json"),
        )],
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
    use super::{BaseRelayInfoConfig, base_relay_info_router};
    use axum::body::to_bytes;
    use http::{Request, StatusCode, header};
    use tangle_crypto::RelaySigner;
    use tangle_groups::parse_group_runtime_config_json;
    use tower::ServiceExt;

    #[test]
    fn nip11_builder_reports_groups_and_relay_self_only_when_configured() {
        let groups = enabled_groups();
        let document = BaseRelayInfoConfig::new("tangle", groups)
            .expect("config")
            .with_description("Tangle v2 relay")
            .build_document()
            .expect("document");
        let disabled = BaseRelayInfoConfig::new("tangle", disabled_groups())
            .expect("config")
            .build_document()
            .expect("disabled");

        assert!(document.supported_nips.contains(&29));
        assert!(document.supported_nips.contains(&45));
        assert!(document.relay_self().is_some());
        assert_eq!(document.description.as_deref(), Some("Tangle v2 relay"));
        assert!(!disabled.supported_nips.contains(&29));
        assert!(disabled.relay_self().is_none());
    }

    #[tokio::test]
    async fn nip11_router_serves_nostr_json_only_for_nostr_accept() {
        let document = BaseRelayInfoConfig::new("tangle", enabled_groups())
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
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        let value = serde_json::from_slice::<serde_json::Value>(&body).expect("json");
        assert_eq!(value["name"], document.name);
        assert!(value["self"].as_str().is_some());

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

    fn enabled_groups() -> tangle_groups::GroupRuntimeConfig {
        let owner = RelaySigner::from_secret_hex(&"8".repeat(64))
            .expect("owner")
            .public_key()
            .clone();
        parse_group_runtime_config_json(&format!(
            r#"{{
                "enabled": true,
                "canonical_relay_url": "wss://relay.radroots.test",
                "relay_secret": "{}",
                "owner_pubkeys": ["{}"]
            }}"#,
            "7".repeat(64),
            owner.as_str()
        ))
        .expect("groups")
    }

    fn disabled_groups() -> tangle_groups::GroupRuntimeConfig {
        parse_group_runtime_config_json(r#"{"enabled": false}"#).expect("groups")
    }
}
