use axum::{
    Json, Router,
    extract::State,
    response::{IntoResponse, Response},
    routing::get,
};
use core::fmt;
use http::{HeaderMap, HeaderValue, StatusCode, header};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, collections::BTreeSet, str};
use tangle_crypto::{RelaySigner, verify_event_signature};
use tangle_groups::GroupRuntimeConfig;
use tangle_nips::parse_relay_auth_event;
use tangle_protocol::{
    ClientMessage, Event, EventId, Filter, PublicKeyHex, RelayMessage, SubscriptionId,
    UnixTimestamp, event_to_value, filter_to_value, parse_event_json,
};
use tangle_store_pocket::{
    PocketEvent, PocketEventId, PocketOwnedEvent, PocketOwnedFilter, PocketStoreConfig,
    PocketStoreHandle, parse_pocket_event_json, parse_pocket_filter_json,
};

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaseAuthState {
    relay_url: String,
    ttl_seconds: u64,
    challenge: Option<BaseAuthChallenge>,
    authenticated_pubkeys: BTreeSet<PublicKeyHex>,
}

impl BaseAuthState {
    pub fn new(relay_url: impl Into<String>, ttl_seconds: u64) -> Result<Self, BaseRelayError> {
        let relay_url = relay_url.into();
        if relay_url.trim().is_empty() {
            return Err(BaseRelayError::invalid("auth relay URL must not be empty"));
        }
        if ttl_seconds == 0 {
            return Err(BaseRelayError::invalid(
                "auth challenge ttl must be greater than zero",
            ));
        }
        Ok(Self {
            relay_url,
            ttl_seconds,
            challenge: None,
            authenticated_pubkeys: BTreeSet::new(),
        })
    }

    pub fn issue_challenge(
        &mut self,
        challenge: impl Into<String>,
        issued_at: UnixTimestamp,
    ) -> Result<RelayMessage, BaseRelayError> {
        let challenge = challenge.into();
        if challenge.is_empty() {
            return Err(BaseRelayError::invalid("auth challenge must not be empty"));
        }
        self.challenge = Some(BaseAuthChallenge {
            value: challenge.clone(),
            issued_at,
        });
        Ok(RelayMessage::Auth(challenge))
    }

    pub fn authenticate(
        &mut self,
        event: &Event,
        now: UnixTimestamp,
    ) -> Result<PublicKeyHex, BaseRelayError> {
        verify_event_signature(event).map_err(BaseRelayError::invalid)?;
        let auth = parse_relay_auth_event(event)
            .map_err(BaseRelayError::invalid)?
            .ok_or_else(|| BaseRelayError::invalid("AUTH message must contain kind 22242"))?;
        let challenge = self
            .challenge
            .as_ref()
            .ok_or_else(|| BaseRelayError::auth_required("auth challenge is missing"))?;
        if auth.relay() != self.relay_url {
            return Err(BaseRelayError::auth_required(
                "auth relay does not match canonical relay URL",
            ));
        }
        if auth.challenge() != challenge.value {
            return Err(BaseRelayError::auth_required(
                "auth challenge does not match",
            ));
        }
        if now.as_u64()
            > challenge
                .issued_at
                .as_u64()
                .saturating_add(self.ttl_seconds)
        {
            return Err(BaseRelayError::auth_required("auth challenge expired"));
        }
        let pubkey = auth.pubkey().clone();
        self.authenticated_pubkeys.insert(pubkey.clone());
        Ok(pubkey)
    }

    pub fn authenticated_pubkeys(&self) -> &BTreeSet<PublicKeyHex> {
        &self.authenticated_pubkeys
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BaseAuthChallenge {
    value: String,
    issued_at: UnixTimestamp,
}

pub struct BaseRelay {
    store: PocketStoreHandle,
    subscriptions: LiveSubscriptionSet,
}

impl BaseRelay {
    pub fn open(
        config: &PocketStoreConfig,
        max_pending_events: usize,
    ) -> Result<Self, BaseRelayError> {
        let store = PocketStoreHandle::open(config).map_err(BaseRelayError::from)?;
        Self::new(store, max_pending_events)
    }

    pub fn new(
        store: PocketStoreHandle,
        max_pending_events: usize,
    ) -> Result<Self, BaseRelayError> {
        Ok(Self {
            store,
            subscriptions: LiveSubscriptionSet::new(max_pending_events)?,
        })
    }

    pub fn handle_client_message(
        &mut self,
        message: ClientMessage,
        auth: &mut BaseAuthState,
        now: UnixTimestamp,
    ) -> Result<Vec<RelayMessage>, BaseRelayError> {
        match message {
            ClientMessage::Event(event) => self.handle_event(event).map(|message| vec![message]),
            ClientMessage::Req {
                subscription_id,
                filters,
            } => self.handle_req(subscription_id, filters),
            ClientMessage::Count {
                subscription_id,
                filters,
            } => self
                .handle_count(subscription_id, filters)
                .map(|message| vec![message]),
            ClientMessage::Close(subscription_id) => {
                self.handle_close(&subscription_id);
                Ok(Vec::new())
            }
            ClientMessage::Auth(event) => auth
                .authenticate(&event, now)
                .map(|_| {
                    vec![RelayMessage::Ok {
                        event_id: event.id().clone(),
                        accepted: true,
                        message: String::new(),
                    }]
                })
                .or_else(|error| {
                    Ok(vec![RelayMessage::Ok {
                        event_id: event.id().clone(),
                        accepted: false,
                        message: error.prefixed_message(),
                    }])
                }),
        }
    }

    pub fn handle_event(&self, event: Event) -> Result<RelayMessage, BaseRelayError> {
        let event_id = event.id().clone();
        if let Err(error) = verify_event_signature(&event) {
            return Ok(ok_rejected(event_id, format!("invalid: {error}")));
        }
        if is_nip29_group_event(&event) {
            return Ok(ok_rejected(
                event_id,
                "blocked: NIP-29 group events are not accepted before group service".to_owned(),
            ));
        }
        if event.unsigned().kind().is_ephemeral() {
            return Ok(ok_accepted(event_id, String::new()));
        }
        if self
            .store
            .event_by_id(pocket_event_id(&event_id)?)?
            .is_some()
        {
            return Ok(ok_accepted(
                event_id,
                "duplicate: already have this event".to_owned(),
            ));
        }
        let pocket_event = tangle_event_to_pocket(&event)?;
        self.store.store_event(&pocket_event)?;
        self.store.sync()?;
        Ok(ok_accepted(event_id, String::new()))
    }

    pub fn handle_req(
        &mut self,
        subscription_id: SubscriptionId,
        filters: Vec<Filter>,
    ) -> Result<Vec<RelayMessage>, BaseRelayError> {
        self.subscriptions
            .subscribe(subscription_id.clone(), filters.clone())?;
        let mut messages = self
            .query_events(&filters)?
            .into_iter()
            .map(|event| RelayMessage::Event {
                subscription_id: subscription_id.clone(),
                event,
            })
            .collect::<Vec<_>>();
        messages.push(RelayMessage::Eose(subscription_id));
        Ok(messages)
    }

    pub fn handle_count(
        &self,
        subscription_id: SubscriptionId,
        filters: Vec<Filter>,
    ) -> Result<RelayMessage, BaseRelayError> {
        Ok(RelayMessage::Count {
            subscription_id,
            count: self.query_events(&filters)?.len() as u64,
        })
    }

    pub fn handle_close(&mut self, subscription_id: &SubscriptionId) -> CloseResult {
        self.subscriptions.close(subscription_id)
    }

    pub fn fanout(&mut self, event: &Event) -> Vec<RelayMessage> {
        self.subscriptions.fanout(event)
    }

    pub fn mark_delivered(&mut self, subscription_id: &SubscriptionId) {
        self.subscriptions.mark_delivered(subscription_id);
    }

    pub fn active_subscription_count(&self) -> usize {
        self.subscriptions.active_count()
    }

    fn query_events(&self, filters: &[Filter]) -> Result<Vec<Event>, BaseRelayError> {
        let mut seen = BTreeSet::new();
        let mut output = Vec::new();
        for filter in filters {
            let pocket_filter = tangle_filter_to_pocket(filter)?;
            for pocket_event in self.store.find_events(&pocket_filter)? {
                let event = pocket_event_to_tangle(&pocket_event)?;
                if seen.insert(event.id().clone()) {
                    output.push(event);
                }
            }
        }
        Ok(output)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveSubscriptionSet {
    subscriptions: BTreeMap<SubscriptionId, Vec<Filter>>,
    pending: BTreeMap<SubscriptionId, usize>,
    max_pending_events: usize,
}

impl LiveSubscriptionSet {
    pub fn new(max_pending_events: usize) -> Result<Self, BaseRelayError> {
        if max_pending_events == 0 {
            return Err(BaseRelayError::invalid(
                "live subscription pending event limit must be greater than zero",
            ));
        }
        Ok(Self {
            subscriptions: BTreeMap::new(),
            pending: BTreeMap::new(),
            max_pending_events,
        })
    }

    pub fn subscribe(
        &mut self,
        subscription_id: SubscriptionId,
        filters: Vec<Filter>,
    ) -> Result<(), BaseRelayError> {
        if filters.is_empty() {
            return Err(BaseRelayError::invalid(
                "subscription must include at least one filter",
            ));
        }
        self.subscriptions.insert(subscription_id.clone(), filters);
        self.pending.insert(subscription_id, 0);
        Ok(())
    }

    pub fn close(&mut self, subscription_id: &SubscriptionId) -> CloseResult {
        self.pending.remove(subscription_id);
        if self.subscriptions.remove(subscription_id).is_some() {
            CloseResult::Closed
        } else {
            CloseResult::NotFound
        }
    }

    pub fn fanout(&mut self, event: &Event) -> Vec<RelayMessage> {
        let matched = self
            .subscriptions
            .iter()
            .filter_map(|(subscription_id, filters)| {
                filters
                    .iter()
                    .any(|filter| filter.matches(event))
                    .then(|| subscription_id.clone())
            })
            .collect::<Vec<_>>();
        let mut messages = Vec::new();
        for subscription_id in matched {
            let pending = self.pending.entry(subscription_id.clone()).or_insert(0);
            *pending += 1;
            if *pending > self.max_pending_events {
                self.close(&subscription_id);
                messages.push(RelayMessage::Closed {
                    subscription_id,
                    message: "error: subscription lagged; resync required".to_owned(),
                });
            } else {
                messages.push(RelayMessage::Event {
                    subscription_id,
                    event: event.clone(),
                });
            }
        }
        messages
    }

    pub fn mark_delivered(&mut self, subscription_id: &SubscriptionId) {
        if let Some(pending) = self.pending.get_mut(subscription_id) {
            *pending = 0;
        }
    }

    pub fn active_count(&self) -> usize {
        self.subscriptions.len()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseResult {
    Closed,
    NotFound,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaseRelayError {
    prefix: &'static str,
    message: String,
}

impl BaseRelayError {
    pub fn invalid(message: impl Into<String>) -> Self {
        Self {
            prefix: "invalid",
            message: message.into(),
        }
    }

    pub fn auth_required(message: impl Into<String>) -> Self {
        Self {
            prefix: "auth-required",
            message: message.into(),
        }
    }

    pub fn error(message: impl Into<String>) -> Self {
        Self {
            prefix: "error",
            message: message.into(),
        }
    }

    pub fn prefixed_message(&self) -> String {
        format!("{}: {}", self.prefix, self.message)
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for BaseRelayError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.prefixed_message())
    }
}

impl std::error::Error for BaseRelayError {}

impl From<tangle_store_pocket::PocketStoreError> for BaseRelayError {
    fn from(error: tangle_store_pocket::PocketStoreError) -> Self {
        Self::error(error.to_string())
    }
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

fn ok_accepted(event_id: EventId, message: String) -> RelayMessage {
    RelayMessage::Ok {
        event_id,
        accepted: true,
        message,
    }
}

fn ok_rejected(event_id: EventId, message: String) -> RelayMessage {
    RelayMessage::Ok {
        event_id,
        accepted: false,
        message,
    }
}

fn is_nip29_group_event(event: &Event) -> bool {
    matches!(event.unsigned().kind().as_u32(), 39_000..=39_004)
        || event
            .unsigned()
            .tags()
            .iter()
            .any(|tag| tag.indexed_pair().is_some_and(|(name, _)| name == "h"))
}

fn tangle_event_to_pocket(event: &Event) -> Result<PocketOwnedEvent, BaseRelayError> {
    let raw = event_to_value(event).to_string();
    parse_pocket_event_json(raw.as_bytes()).map_err(BaseRelayError::from)
}

fn tangle_filter_to_pocket(filter: &Filter) -> Result<PocketOwnedFilter, BaseRelayError> {
    let raw = filter_to_value(filter).to_string();
    parse_pocket_filter_json(raw.as_bytes()).map_err(BaseRelayError::from)
}

fn pocket_event_to_tangle(event: &PocketEvent) -> Result<Event, BaseRelayError> {
    let raw = event
        .as_json()
        .map_err(|error| BaseRelayError::error(error.to_string()))?;
    let raw = str::from_utf8(&raw).map_err(|error| BaseRelayError::error(error.to_string()))?;
    let raw = tangle_protocol::RawEventJson::new(raw)
        .map_err(|error| BaseRelayError::error(error.to_string()))?;
    parse_event_json(&raw).map_err(|error| BaseRelayError::error(error.to_string()))
}

fn pocket_event_id(event_id: &EventId) -> Result<PocketEventId, BaseRelayError> {
    PocketEventId::read_hex(event_id.as_str().as_bytes())
        .map_err(|error| BaseRelayError::error(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::{
        BaseAuthState, BaseRelay, BaseRelayInfoConfig, CloseResult, base_relay_info_router,
    };
    use axum::body::to_bytes;
    use http::{Request, StatusCode, header};
    use tangle_crypto::RelaySigner;
    use tangle_groups::parse_group_runtime_config_json;
    use tangle_protocol::{
        ClientMessage, Event, Filter, Kind, RelayMessage, SubscriptionId, Tag, UnixTimestamp,
        UnsignedEvent, filter_from_value,
    };
    use tangle_store_pocket::{PocketStoreConfig, PocketSyncPolicy};
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

    #[test]
    fn auth_state_issues_challenges_and_accepts_multiple_pubkeys() {
        let mut auth = BaseAuthState::new("wss://relay.radroots.test", 60).expect("auth state");
        let issued = UnixTimestamp::new(100);

        assert_eq!(
            auth.issue_challenge("challenge-a", issued)
                .expect("challenge"),
            RelayMessage::Auth("challenge-a".to_owned())
        );

        let first = signed_auth_event(7, "challenge-a", 120);
        let second = signed_auth_event(8, "challenge-a", 130);

        let first_pubkey = auth
            .authenticate(&first, UnixTimestamp::new(120))
            .expect("first");
        let second_pubkey = auth
            .authenticate(&second, UnixTimestamp::new(130))
            .expect("second");

        assert_ne!(first_pubkey, second_pubkey);
        assert!(auth.authenticated_pubkeys().contains(&first_pubkey));
        assert!(auth.authenticated_pubkeys().contains(&second_pubkey));
        assert_eq!(auth.authenticated_pubkeys().len(), 2);
        assert_eq!(
            auth.authenticate(&signed_auth_event(9, "wrong", 130), UnixTimestamp::new(130))
                .expect_err("wrong")
                .prefixed_message(),
            "auth-required: auth challenge does not match"
        );
    }

    #[test]
    fn base_relay_stores_queries_counts_closes_and_fans_out_public_events() {
        let mut relay = test_relay("base-relay-public", 4);
        let event = signed_public_event(7, 1, Vec::new(), "hello");
        let subscription_id = SubscriptionId::new("sub-a").expect("sub");
        let filter = filter_from_value(&serde_json::json!({"kinds":[1]})).expect("filter");

        assert_eq!(
            relay.handle_event(event.clone()).expect("event"),
            RelayMessage::Ok {
                event_id: event.id().clone(),
                accepted: true,
                message: String::new()
            }
        );
        assert_eq!(
            relay.handle_event(event.clone()).expect("duplicate"),
            RelayMessage::Ok {
                event_id: event.id().clone(),
                accepted: true,
                message: "duplicate: already have this event".to_owned()
            }
        );

        let messages = relay
            .handle_req(subscription_id.clone(), vec![filter.clone()])
            .expect("req");
        assert!(
            matches!(&messages[0], RelayMessage::Event { event: found, .. } if found.id() == event.id())
        );
        assert_eq!(messages[1], RelayMessage::Eose(subscription_id.clone()));
        assert_eq!(
            relay
                .handle_count(subscription_id.clone(), vec![filter])
                .expect("count"),
            RelayMessage::Count {
                subscription_id: subscription_id.clone(),
                count: 1
            }
        );
        assert!(matches!(
            relay.fanout(&event).as_slice(),
            [RelayMessage::Event { subscription_id: delivered, event: found }]
                if delivered == &subscription_id && found.id() == event.id()
        ));
        assert_eq!(relay.handle_close(&subscription_id), CloseResult::Closed);
        assert_eq!(relay.active_subscription_count(), 0);
        assert!(relay.fanout(&event).is_empty());
    }

    #[test]
    fn base_relay_rejects_group_marked_events_before_group_service() {
        let relay = test_relay("base-relay-group-reject", 4);
        let event = signed_public_event(
            7,
            1,
            vec![Tag::from_parts("h", &["public-group"]).expect("group")],
            "hello",
        );

        assert_eq!(
            relay.handle_event(event.clone()).expect("event"),
            RelayMessage::Ok {
                event_id: event.id().clone(),
                accepted: false,
                message: "blocked: NIP-29 group events are not accepted before group service"
                    .to_owned()
            }
        );
    }

    #[test]
    fn live_subscription_lag_closes_subscription_for_resync() {
        let mut relay = test_relay("base-relay-lag", 1);
        let subscription_id = SubscriptionId::new("sub-lag").expect("sub");
        let filter = filter_from_value(&serde_json::json!({"kinds":[1]})).expect("filter");
        relay
            .handle_req(subscription_id.clone(), vec![filter])
            .expect("req");
        let first = signed_public_event(7, 1, Vec::new(), "first");
        let second = signed_public_event(7, 1, Vec::new(), "second");

        assert!(matches!(
            relay.fanout(&first).as_slice(),
            [RelayMessage::Event { .. }]
        ));
        assert_eq!(
            relay.fanout(&second),
            vec![RelayMessage::Closed {
                subscription_id: subscription_id.clone(),
                message: "error: subscription lagged; resync required".to_owned()
            }]
        );
        assert_eq!(relay.active_subscription_count(), 0);
    }

    #[test]
    fn base_relay_client_message_dispatch_handles_count_and_auth() {
        let mut relay = test_relay("base-relay-dispatch", 4);
        let mut auth = BaseAuthState::new("wss://relay.radroots.test", 60).expect("auth state");
        auth.issue_challenge("challenge-a", UnixTimestamp::new(100))
            .expect("challenge");
        let auth_event = signed_auth_event(7, "challenge-a", 120);
        let count_id = SubscriptionId::new("count-a").expect("sub");

        assert_eq!(
            relay
                .handle_client_message(
                    ClientMessage::Auth(auth_event.clone()),
                    &mut auth,
                    UnixTimestamp::new(120)
                )
                .expect("auth"),
            vec![RelayMessage::Ok {
                event_id: auth_event.id().clone(),
                accepted: true,
                message: String::new()
            }]
        );
        assert_eq!(
            relay
                .handle_client_message(
                    ClientMessage::Count {
                        subscription_id: count_id.clone(),
                        filters: vec![Filter::empty()]
                    },
                    &mut auth,
                    UnixTimestamp::new(130)
                )
                .expect("count"),
            vec![RelayMessage::Count {
                subscription_id: count_id,
                count: 0
            }]
        );
    }

    fn test_relay(name: &str, max_pending_events: usize) -> BaseRelay {
        let root = std::env::temp_dir().join(format!("tangle-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let config = PocketStoreConfig::new(
            root.join("pocket"),
            1024 * 1024 * 1024,
            128,
            PocketSyncPolicy::FlushOnShutdown,
        )
        .expect("config");
        BaseRelay::open(&config, max_pending_events).expect("relay")
    }

    fn enabled_groups() -> tangle_groups::GroupRuntimeConfig {
        parse_group_runtime_config_json(&format!(
            r#"{{
                "enabled": true,
                "canonical_relay_url": "wss://relay.radroots.test",
                "relay_secret": "{}"
            }}"#,
            "7".repeat(64)
        ))
        .expect("groups")
    }

    fn disabled_groups() -> tangle_groups::GroupRuntimeConfig {
        parse_group_runtime_config_json(r#"{"enabled": false}"#).expect("groups")
    }

    fn signed_auth_event(secret_byte: u8, challenge: &str, created_at: u64) -> Event {
        signed_event_at(
            secret_byte,
            22_242,
            vec![
                Tag::from_parts("relay", &["wss://relay.radroots.test"]).expect("relay"),
                Tag::from_parts("challenge", &[challenge]).expect("challenge"),
            ],
            "",
            created_at,
        )
    }

    fn signed_public_event(secret_byte: u8, kind: u64, tags: Vec<Tag>, content: &str) -> Event {
        signed_event_at(secret_byte, kind, tags, content, 1_714_124_433)
    }

    fn signed_event_at(
        secret_byte: u8,
        kind: u64,
        tags: Vec<Tag>,
        content: &str,
        created_at: u64,
    ) -> Event {
        let secret = format!("{:02x}", secret_byte).repeat(32);
        let signer = RelaySigner::from_secret_hex(&secret).expect("signer");
        let unsigned = UnsignedEvent::new(
            signer.public_key().clone(),
            UnixTimestamp::new(created_at),
            Kind::new(kind).expect("kind"),
            tags,
            content,
        );
        signer.sign_unsigned_event(unsigned)
    }
}
