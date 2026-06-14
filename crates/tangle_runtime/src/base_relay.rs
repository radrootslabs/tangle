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
use tangle_groups::{
    GroupAuthContext, GroupAuthority, GroupError, GroupErrorKind, GroupEventClass,
    GroupEventDeletion, GroupGeneratedEventBuilder, GroupId, GroupLimitsConfig, GroupOutbox,
    GroupOutboxEffect, GroupOutboxKey, GroupOutboxPayload, GroupOutboxRecord, GroupProjection,
    GroupReadDecision, GroupReadGate, GroupRuntimeConfig, GroupState, GroupTombstone,
    KIND_GROUP_CREATE_GROUP, KIND_GROUP_DELETE_EVENT, KIND_GROUP_EDIT_METADATA,
    KIND_GROUP_JOIN_REQUEST, KIND_GROUP_LEAVE_REQUEST, KIND_GROUP_MEMBERS, KIND_GROUP_PUT_USER,
    KIND_GROUP_REMOVE_USER, MemberState, ProjectedRoleDefinition, ProjectionCheckpoint,
    StoreOffset, event_deletion_key, group_current_key, member_current_key,
    projection_checkpoint_key, role_current_key, tombstone_key,
    validate_client_group_event_structure,
};
use tangle_nips::parse_relay_auth_event;
use tangle_protocol::{
    ClientMessage, Event, EventId, Filter, PublicKeyHex, RelayMessage, SubscriptionId,
    UnixTimestamp, event_to_value, filter_to_value, parse_event_json,
};
use tangle_store_pocket::{
    PocketEvent, PocketEventId, PocketOwnedEvent, PocketOwnedFilter, PocketStoreConfig,
    PocketStoreHandle, TANGLE_GROUP_CHECKPOINT_TABLE, TANGLE_GROUP_OUTBOX_TABLE,
    TANGLE_GROUP_PROJECTION_TABLE, parse_pocket_event_json, parse_pocket_filter_json,
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
    groups: Option<GroupService>,
}

impl BaseRelay {
    pub fn open(
        config: &PocketStoreConfig,
        max_pending_events: usize,
    ) -> Result<Self, BaseRelayError> {
        let store = PocketStoreHandle::open(config).map_err(BaseRelayError::from)?;
        Self::new(store, max_pending_events)
    }

    pub fn open_with_groups(
        config: &PocketStoreConfig,
        max_pending_events: usize,
        groups: &GroupRuntimeConfig,
    ) -> Result<Self, BaseRelayError> {
        let store = PocketStoreHandle::open(config).map_err(BaseRelayError::from)?;
        Self::new_with_groups(store, max_pending_events, groups)
    }

    pub fn new(
        store: PocketStoreHandle,
        max_pending_events: usize,
    ) -> Result<Self, BaseRelayError> {
        Self::new_with_groups(store, max_pending_events, &GroupRuntimeConfig::disabled())
    }

    pub fn new_with_groups(
        store: PocketStoreHandle,
        max_pending_events: usize,
        groups: &GroupRuntimeConfig,
    ) -> Result<Self, BaseRelayError> {
        let groups = GroupService::from_config(&store, groups)?;
        Ok(Self {
            store,
            subscriptions: LiveSubscriptionSet::new(max_pending_events)?,
            groups,
        })
    }

    pub fn handle_client_message(
        &mut self,
        message: ClientMessage,
        auth: &mut BaseAuthState,
        now: UnixTimestamp,
    ) -> Result<Vec<RelayMessage>, BaseRelayError> {
        match message {
            ClientMessage::Event(event) => self
                .handle_event_with_auth(event, auth)
                .map(|message| vec![message]),
            ClientMessage::Req {
                subscription_id,
                filters,
            } => self.handle_req_with_auth(subscription_id, filters, auth),
            ClientMessage::Count {
                subscription_id,
                filters,
            } => self
                .handle_count_with_auth(subscription_id, filters, auth)
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

    pub fn handle_event(&mut self, event: Event) -> Result<RelayMessage, BaseRelayError> {
        self.handle_event_with_group_auth(event, &GroupAuthContext::unauthenticated())
    }

    pub fn handle_event_with_auth(
        &mut self,
        event: Event,
        auth: &BaseAuthState,
    ) -> Result<RelayMessage, BaseRelayError> {
        self.handle_event_with_group_auth(
            event,
            &GroupAuthContext::new(auth.authenticated_pubkeys().iter().cloned()),
        )
    }

    pub fn groups_enabled(&self) -> bool {
        self.groups.is_some()
    }

    pub fn group_projection(&self) -> Option<&GroupProjection> {
        self.groups.as_ref().map(|groups| groups.projection())
    }

    fn handle_event_with_group_auth(
        &mut self,
        event: Event,
        auth: &GroupAuthContext,
    ) -> Result<RelayMessage, BaseRelayError> {
        let event_id = event.id().clone();
        if let Err(error) = verify_event_signature(&event) {
            return Ok(ok_rejected(event_id, format!("invalid: {error}")));
        }
        let group_limits = self
            .groups
            .as_ref()
            .map(GroupService::limits)
            .unwrap_or_default();
        let class = match validate_client_group_event_structure(&event, group_limits) {
            Ok(class) => class,
            Err(error) => return Ok(ok_rejected(event_id, error.prefixed_message())),
        };
        if !matches!(class, GroupEventClass::NonGroup) {
            let Some(groups) = self.groups.as_ref() else {
                return Ok(ok_rejected(
                    event_id,
                    "blocked: NIP-29 group events are not accepted before group service".to_owned(),
                ));
            };
            if let Err(error) = groups.check_event(&self.store, &event, &class, auth) {
                return Ok(ok_rejected(event_id, error.prefixed_message()));
            }
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
        let store_offset = StoreOffset::new(self.store.store_event(&pocket_event)?);
        if !matches!(class, GroupEventClass::NonGroup)
            && let Some(groups) = self.groups.as_mut()
        {
            groups.after_source_event_stored(&self.store, &event, &class, store_offset)?;
        }
        self.store.sync()?;
        Ok(ok_accepted(event_id, String::new()))
    }

    pub fn handle_req(
        &mut self,
        subscription_id: SubscriptionId,
        filters: Vec<Filter>,
    ) -> Result<Vec<RelayMessage>, BaseRelayError> {
        self.handle_req_with_group_auth(
            subscription_id,
            filters,
            &GroupAuthContext::unauthenticated(),
        )
    }

    pub fn handle_req_with_auth(
        &mut self,
        subscription_id: SubscriptionId,
        filters: Vec<Filter>,
        auth: &BaseAuthState,
    ) -> Result<Vec<RelayMessage>, BaseRelayError> {
        self.handle_req_with_group_auth(
            subscription_id,
            filters,
            &GroupAuthContext::new(auth.authenticated_pubkeys().iter().cloned()),
        )
    }

    fn handle_req_with_group_auth(
        &mut self,
        subscription_id: SubscriptionId,
        filters: Vec<Filter>,
        auth: &GroupAuthContext,
    ) -> Result<Vec<RelayMessage>, BaseRelayError> {
        self.subscriptions
            .subscribe(subscription_id.clone(), filters.clone(), auth.clone())?;
        let mut messages = self
            .query_events(&filters, auth)?
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
        self.handle_count_with_group_auth(
            subscription_id,
            filters,
            &GroupAuthContext::unauthenticated(),
        )
    }

    pub fn handle_count_with_auth(
        &self,
        subscription_id: SubscriptionId,
        filters: Vec<Filter>,
        auth: &BaseAuthState,
    ) -> Result<RelayMessage, BaseRelayError> {
        self.handle_count_with_group_auth(
            subscription_id,
            filters,
            &GroupAuthContext::new(auth.authenticated_pubkeys().iter().cloned()),
        )
    }

    fn handle_count_with_group_auth(
        &self,
        subscription_id: SubscriptionId,
        filters: Vec<Filter>,
        auth: &GroupAuthContext,
    ) -> Result<RelayMessage, BaseRelayError> {
        Ok(RelayMessage::Count {
            subscription_id,
            count: self.query_events(&filters, auth)?.len() as u64,
        })
    }

    pub fn handle_close(&mut self, subscription_id: &SubscriptionId) -> CloseResult {
        self.subscriptions.close(subscription_id)
    }

    pub fn fanout(&mut self, event: &Event) -> Vec<RelayMessage> {
        self.subscriptions.fanout(event, self.groups.as_ref())
    }

    pub fn mark_delivered(&mut self, subscription_id: &SubscriptionId) {
        self.subscriptions.mark_delivered(subscription_id);
    }

    pub fn active_subscription_count(&self) -> usize {
        self.subscriptions.active_count()
    }

    fn query_events(
        &self,
        filters: &[Filter],
        auth: &GroupAuthContext,
    ) -> Result<Vec<Event>, BaseRelayError> {
        let mut seen = BTreeSet::new();
        let mut output = Vec::new();
        for filter in filters {
            let pocket_filter = tangle_filter_to_pocket(filter)?;
            for pocket_event in self.store.find_events(&pocket_filter)? {
                let event = pocket_event_to_tangle(&pocket_event)?;
                if seen.insert(event.id().clone()) && self.event_visible_to_auth(&event, auth)? {
                    output.push(event);
                }
            }
        }
        Ok(output)
    }

    fn event_visible_to_auth(
        &self,
        event: &Event,
        auth: &GroupAuthContext,
    ) -> Result<bool, BaseRelayError> {
        self.groups
            .as_ref()
            .map(|groups| groups.event_visible_to_auth(event, auth))
            .unwrap_or(Ok(true))
            .map_err(BaseRelayError::from)
    }
}

struct GroupService {
    builder: GroupGeneratedEventBuilder,
    authority: GroupAuthority,
    projection: GroupProjection,
    outbox: GroupOutbox,
    limits: GroupLimitsConfig,
    member_snapshot_cap: u32,
}

impl GroupService {
    fn from_config(
        store: &PocketStoreHandle,
        config: &GroupRuntimeConfig,
    ) -> Result<Option<Self>, BaseRelayError> {
        if !config.enabled() {
            return Ok(None);
        }
        let relay_secret = config
            .relay_secret()
            .ok_or_else(|| BaseRelayError::invalid("groups.relay_secret is required"))?;
        let signer = RelaySigner::from_secret_hex(relay_secret.expose_for_signing())
            .map_err(BaseRelayError::invalid)?;
        Ok(Some(Self {
            builder: GroupGeneratedEventBuilder::new(signer),
            authority: GroupAuthority::new(
                config.owner_pubkeys().iter().cloned(),
                config.admin_pubkeys().iter().cloned(),
            ),
            projection: load_group_projection(store)?,
            outbox: load_group_outbox(store)?,
            limits: config.limits(),
            member_snapshot_cap: config.limits().max_member_list_pubkeys(),
        }))
    }

    fn projection(&self) -> &GroupProjection {
        &self.projection
    }

    fn limits(&self) -> GroupLimitsConfig {
        self.limits
    }

    fn check_event(
        &self,
        store: &PocketStoreHandle,
        event: &Event,
        class: &GroupEventClass,
        auth: &GroupAuthContext,
    ) -> Result<(), GroupError> {
        tangle_groups::GroupWritePolicy::new(&self.projection, &self.authority)
            .check_event(event, class, auth)
            .map(|_| ())?;
        self.check_runtime_write_constraints(store, event, class)
    }

    fn check_runtime_write_constraints(
        &self,
        store: &PocketStoreHandle,
        event: &Event,
        class: &GroupEventClass,
    ) -> Result<(), GroupError> {
        if let GroupEventClass::Moderation { kind, group_id } = class
            && kind.as_u32() == KIND_GROUP_DELETE_EVENT
        {
            self.check_delete_event_target(store, event, group_id)?;
        }
        Ok(())
    }

    fn check_delete_event_target(
        &self,
        store: &PocketStoreHandle,
        event: &Event,
        group_id: &GroupId,
    ) -> Result<(), GroupError> {
        let target_id = delete_target_event_id(event)?;
        let Some(target) = store
            .event_by_id(
                pocket_event_id(&target_id)
                    .map_err(|error| GroupError::internal(error.prefixed_message()))?,
            )
            .map_err(|error| GroupError::internal(error.to_string()))?
        else {
            return Err(GroupError::invalid(
                GroupErrorKind::MalformedTargetTag,
                "delete target event is unavailable",
            ));
        };
        let target = pocket_event_to_tangle(&target)
            .map_err(|error| GroupError::internal(error.prefixed_message()))?;
        let target_class = tangle_groups::classify_group_event(&target, self.limits)?;
        if target_class.group_id() != Some(group_id) {
            return Err(GroupError::invalid(
                GroupErrorKind::MalformedTargetTag,
                "delete target event is not in group",
            ));
        }
        Ok(())
    }

    fn event_visible_to_auth(
        &self,
        event: &Event,
        auth: &GroupAuthContext,
    ) -> Result<bool, GroupError> {
        let gate = GroupReadGate::new(&self.projection, &self.authority);
        if auth.authenticated_pubkeys().is_empty() {
            return gate
                .screen_event(event, None, self.limits)
                .map(|decision| decision == GroupReadDecision::Visible);
        }
        for pubkey in auth.authenticated_pubkeys() {
            if gate.screen_event(event, Some(pubkey), self.limits)? == GroupReadDecision::Visible {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn after_source_event_stored(
        &mut self,
        store: &PocketStoreHandle,
        event: &Event,
        class: &GroupEventClass,
        store_offset: StoreOffset,
    ) -> Result<(), BaseRelayError> {
        self.projection
            .apply_canonical_event(event, store_offset, self.limits)?;
        if let Some(group_id) = class_group_id(class) {
            self.persist_group_projection(store, group_id)?;
        }
        for record in self.plan_outbox_records(event, class)? {
            let inserted = self.outbox.insert_idempotent(record.clone())?;
            if inserted {
                persist_outbox_record(store, &record)?;
            }
        }
        self.materialize_outbox(store)
    }

    fn plan_outbox_records(
        &self,
        event: &Event,
        class: &GroupEventClass,
    ) -> Result<Vec<GroupOutboxRecord>, GroupError> {
        let created_at = event.unsigned().created_at();
        match class {
            GroupEventClass::Moderation { kind, group_id } => match kind.as_u32() {
                KIND_GROUP_CREATE_GROUP => {
                    let group = self.require_group(group_id)?;
                    Ok(vec![
                        self.pending_record(
                            event,
                            GroupOutboxEffect::MetadataSnapshot,
                            group_id,
                            None,
                            GroupGeneratedEventBuilder::metadata_snapshot_payload(
                                group, created_at,
                            )?,
                        ),
                        self.pending_record(
                            event,
                            GroupOutboxEffect::AdminListSnapshot,
                            group_id,
                            None,
                            GroupGeneratedEventBuilder::admin_list_snapshot_payload(
                                group_id,
                                &self.projection,
                                &self.authority,
                                created_at,
                            )?,
                        ),
                    ])
                }
                KIND_GROUP_EDIT_METADATA => {
                    let group = self.require_group(group_id)?;
                    Ok(vec![self.pending_record(
                        event,
                        GroupOutboxEffect::MetadataSnapshot,
                        group_id,
                        None,
                        GroupGeneratedEventBuilder::metadata_snapshot_payload(group, created_at)?,
                    )])
                }
                KIND_GROUP_PUT_USER | KIND_GROUP_REMOVE_USER => {
                    Ok(self.member_snapshot_record(event, group_id, created_at)?)
                }
                _ => Ok(Vec::new()),
            },
            GroupEventClass::Normal { group_id } => match event.unsigned().kind().as_u32() {
                KIND_GROUP_JOIN_REQUEST => Ok(vec![self.pending_record(
                    event,
                    GroupOutboxEffect::JoinAccepted,
                    group_id,
                    Some(event.unsigned().pubkey().clone()),
                    GroupGeneratedEventBuilder::join_accepted_payload(
                        group_id,
                        event.unsigned().pubkey(),
                        created_at,
                    ),
                )]),
                KIND_GROUP_LEAVE_REQUEST => Ok(vec![self.pending_record(
                    event,
                    GroupOutboxEffect::LeaveAccepted,
                    group_id,
                    Some(event.unsigned().pubkey().clone()),
                    GroupGeneratedEventBuilder::leave_accepted_payload(
                        group_id,
                        event.unsigned().pubkey(),
                        created_at,
                    ),
                )]),
                _ => Ok(Vec::new()),
            },
            GroupEventClass::NonGroup | GroupEventClass::RelayGeneratedSnapshot { .. } => {
                Ok(Vec::new())
            }
        }
    }

    fn member_snapshot_record(
        &self,
        event: &Event,
        group_id: &GroupId,
        created_at: UnixTimestamp,
    ) -> Result<Vec<GroupOutboxRecord>, GroupError> {
        let key = GroupOutboxKey::new(
            event.id().clone(),
            GroupOutboxEffect::MemberListSnapshot,
            group_id.clone(),
            None,
        );
        let payload = GroupGeneratedEventBuilder::member_list_snapshot_payload(
            group_id,
            &self.projection,
            created_at,
            self.member_snapshot_cap,
        )?;
        Ok(vec![match payload {
            Some(payload) => GroupOutboxRecord::pending(key, payload),
            None => {
                let mut record = GroupOutboxRecord::pending(
                    key,
                    GroupOutboxPayload::new(
                        KIND_GROUP_MEMBERS,
                        created_at,
                        vec![vec!["d".to_owned(), group_id.as_str().to_owned()]],
                        "",
                    ),
                );
                record.mark_skipped("member snapshot exceeds configured cap");
                record
            }
        }])
    }

    fn pending_record(
        &self,
        event: &Event,
        effect: GroupOutboxEffect,
        group_id: &GroupId,
        target_pubkey: Option<PublicKeyHex>,
        payload: GroupOutboxPayload,
    ) -> GroupOutboxRecord {
        GroupOutboxRecord::pending(
            GroupOutboxKey::new(event.id().clone(), effect, group_id.clone(), target_pubkey),
            payload,
        )
    }

    fn materialize_outbox(&mut self, store: &PocketStoreHandle) -> Result<(), BaseRelayError> {
        let records = self.outbox.replay_plan().records().to_vec();
        for record in records {
            self.materialize_record(store, record)?;
        }
        Ok(())
    }

    fn materialize_record(
        &mut self,
        store: &PocketStoreHandle,
        mut record: GroupOutboxRecord,
    ) -> Result<(), BaseRelayError> {
        if matches!(
            record.key().effect(),
            GroupOutboxEffect::RoleListSnapshot | GroupOutboxEffect::State39004Snapshot
        ) {
            record.mark_skipped("generated group effect is not supported");
            self.outbox.update(record.clone());
            persist_outbox_record(store, &record)?;
            return Ok(());
        }
        match self.store_generated_event(store, &record) {
            Ok(generated_event_id) => {
                record.mark_stored(generated_event_id);
                self.outbox.update(record.clone());
                persist_outbox_record(store, &record)?;
                Ok(())
            }
            Err(error) => {
                record.mark_failed(true, error.prefixed_message());
                self.outbox.update(record.clone());
                persist_outbox_record(store, &record)?;
                Err(error)
            }
        }
    }

    fn store_generated_event(
        &mut self,
        store: &PocketStoreHandle,
        record: &GroupOutboxRecord,
    ) -> Result<EventId, BaseRelayError> {
        let event = self.builder.sign_payload(record.payload())?;
        if store.event_by_id(pocket_event_id(event.id())?)?.is_some() {
            return Ok(event.id().clone());
        }
        let pocket_event = tangle_event_to_pocket(&event)?;
        let offset = StoreOffset::new(store.store_event(&pocket_event)?);
        self.projection
            .apply_canonical_event(&event, offset, self.limits)?;
        self.persist_group_projection(store, record.key().group_id())?;
        Ok(event.id().clone())
    }

    fn persist_group_projection(
        &self,
        store: &PocketStoreHandle,
        group_id: &GroupId,
    ) -> Result<(), BaseRelayError> {
        if let Some(group) = self.projection.group(group_id) {
            store.put_extra_record(
                TANGLE_GROUP_PROJECTION_TABLE,
                &group_current_key(group_id),
                &group.to_json_bytes()?,
            )?;
        }
        for ((candidate_group, pubkey), member) in self.projection.members() {
            if candidate_group == group_id {
                store.put_extra_record(
                    TANGLE_GROUP_PROJECTION_TABLE,
                    &member_current_key(group_id, pubkey),
                    &member.to_json_bytes()?,
                )?;
            }
        }
        for ((candidate_group, role_name), role) in self.projection.roles() {
            if candidate_group == group_id {
                store.put_extra_record(
                    TANGLE_GROUP_PROJECTION_TABLE,
                    &role_current_key(group_id, role_name),
                    &role.to_json_bytes()?,
                )?;
            }
        }
        if let Some(tombstone) = self.projection.tombstone(group_id) {
            store.put_extra_record(
                TANGLE_GROUP_PROJECTION_TABLE,
                &tombstone_key(group_id),
                &tombstone.to_json_bytes()?,
            )?;
        }
        for (target_event_id, deletion) in self.projection.event_deletions() {
            if deletion.group_id() == group_id {
                store.put_extra_record(
                    TANGLE_GROUP_PROJECTION_TABLE,
                    &event_deletion_key(target_event_id),
                    &deletion.to_json_bytes()?,
                )?;
            }
        }
        Ok(())
    }

    fn require_group(&self, group_id: &GroupId) -> Result<&GroupState, GroupError> {
        self.projection
            .group(group_id)
            .ok_or_else(|| GroupError::internal("group projection is missing after accepted write"))
    }
}

fn load_group_projection(store: &PocketStoreHandle) -> Result<GroupProjection, BaseRelayError> {
    let mut projection = GroupProjection::new();
    for (key, value) in store.scan_extra_records(TANGLE_GROUP_PROJECTION_TABLE)? {
        match projection_key_parts(&key)?.as_slice() {
            ["group", _] => projection.put_group(GroupState::from_json_bytes(&value)?),
            ["member", group_id, _] => projection.put_member(
                GroupId::new(group_id)?,
                MemberState::from_json_bytes(&value)?,
            ),
            ["role", group_id, _] => projection.put_role(
                GroupId::new(group_id)?,
                ProjectedRoleDefinition::from_json_bytes(&value)?,
            ),
            ["tombstone", _] => projection.put_tombstone(GroupTombstone::from_json_bytes(&value)?),
            ["event_deletion", _] => {
                projection.put_event_deletion(GroupEventDeletion::from_json_bytes(&value)?)
            }
            _ => {}
        }
    }
    if let Some(raw) =
        store.get_extra_record(TANGLE_GROUP_CHECKPOINT_TABLE, &projection_checkpoint_key())?
    {
        projection.set_checkpoint(ProjectionCheckpoint::from_json_bytes(&raw)?);
    }
    Ok(projection)
}

fn load_group_outbox(store: &PocketStoreHandle) -> Result<GroupOutbox, BaseRelayError> {
    let mut outbox = GroupOutbox::new();
    for (_, value) in store.scan_extra_records(TANGLE_GROUP_OUTBOX_TABLE)? {
        outbox.update(GroupOutboxRecord::from_json_bytes(&value)?);
    }
    Ok(outbox)
}

fn projection_key_parts(key: &[u8]) -> Result<Vec<&str>, BaseRelayError> {
    let key = str::from_utf8(key).map_err(|error| BaseRelayError::error(error.to_string()))?;
    Ok(key.split('\0').collect())
}

fn persist_outbox_record(
    store: &PocketStoreHandle,
    record: &GroupOutboxRecord,
) -> Result<(), BaseRelayError> {
    store.put_extra_record(
        TANGLE_GROUP_OUTBOX_TABLE,
        &record.key().storage_key(),
        &record.to_json_bytes()?,
    )?;
    Ok(())
}

fn class_group_id(class: &GroupEventClass) -> Option<&GroupId> {
    match class {
        GroupEventClass::Moderation { group_id, .. }
        | GroupEventClass::Normal { group_id }
        | GroupEventClass::RelayGeneratedSnapshot { group_id, .. } => Some(group_id),
        GroupEventClass::NonGroup => None,
    }
}

fn delete_target_event_id(event: &Event) -> Result<EventId, GroupError> {
    for tag in event.unsigned().tags() {
        if !tag.values().first().is_some_and(|name| name == "e") {
            continue;
        }
        let Some((_, value)) = tag.indexed_pair() else {
            return Err(GroupError::invalid(
                GroupErrorKind::MalformedTargetTag,
                "malformed e target tag",
            ));
        };
        return EventId::new(value).map_err(|reason| {
            GroupError::invalid(
                GroupErrorKind::MalformedTargetTag,
                format!("malformed e target tag: {reason}"),
            )
        });
    }
    Err(GroupError::invalid(
        GroupErrorKind::MissingTargetTag,
        "missing e target tag",
    ))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveSubscriptionSet {
    subscriptions: BTreeMap<SubscriptionId, LiveSubscription>,
    pending: BTreeMap<SubscriptionId, usize>,
    max_pending_events: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LiveSubscription {
    filters: Vec<Filter>,
    auth: GroupAuthContext,
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
        auth: GroupAuthContext,
    ) -> Result<(), BaseRelayError> {
        if filters.is_empty() {
            return Err(BaseRelayError::invalid(
                "subscription must include at least one filter",
            ));
        }
        self.subscriptions
            .insert(subscription_id.clone(), LiveSubscription { filters, auth });
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

    fn fanout(&mut self, event: &Event, groups: Option<&GroupService>) -> Vec<RelayMessage> {
        let matched = self
            .subscriptions
            .iter()
            .filter_map(|(subscription_id, subscription)| {
                if !subscription
                    .filters
                    .iter()
                    .any(|filter| filter.matches(event))
                {
                    return None;
                }
                if groups
                    .map(|groups| {
                        groups
                            .event_visible_to_auth(event, &subscription.auth)
                            .unwrap_or(false)
                    })
                    .unwrap_or(true)
                {
                    Some(subscription_id.clone())
                } else {
                    None
                }
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

impl From<GroupError> for BaseRelayError {
    fn from(error: GroupError) -> Self {
        Self::error(error.prefixed_message())
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
    use tangle_groups::{
        GroupId, KIND_GROUP_ADMINS, KIND_GROUP_CREATE_GROUP, KIND_GROUP_CREATE_INVITE,
        KIND_GROUP_DELETE_EVENT, KIND_GROUP_DELETE_GROUP, KIND_GROUP_EDIT_METADATA,
        KIND_GROUP_JOIN_REQUEST, KIND_GROUP_LEAVE_REQUEST, KIND_GROUP_MEMBERS, KIND_GROUP_METADATA,
        KIND_GROUP_PUT_USER, KIND_GROUP_REMOVE_USER, MemberStatus, parse_group_runtime_config_json,
    };
    use tangle_protocol::{
        ClientMessage, Event, EventId, Filter, Kind, PublicKeyHex, RelayMessage, SubscriptionId,
        Tag, UnixTimestamp, UnsignedEvent, filter_from_value,
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
        let mut relay = test_relay("base-relay-group-reject", 4);
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
    fn base_relay_rejects_client_submitted_relay_generated_group_state() {
        let mut relay = test_relay("base-relay-generated-group-reject", 4);
        let event = signed_public_event(
            7,
            39_000,
            vec![Tag::from_parts("d", &["public-group"]).expect("group")],
            "",
        );

        assert_eq!(
            relay.handle_event(event.clone()).expect("event"),
            RelayMessage::Ok {
                event_id: event.id().clone(),
                accepted: false,
                message:
                    "blocked: relay-generated group state events cannot be submitted by clients"
                        .to_owned()
            }
        );
    }

    #[test]
    fn base_relay_initializes_group_service_from_config() {
        let owner = signer(7).public_key().clone();
        let relay = test_relay_with_groups(
            "base-relay-groups-enabled",
            4,
            &enabled_groups_for_owner(&owner),
        );
        let disabled = test_relay_with_groups("base-relay-groups-disabled", 4, &disabled_groups());

        assert!(relay.groups_enabled());
        assert!(
            relay
                .group_projection()
                .expect("projection")
                .groups()
                .is_empty()
        );
        assert!(!disabled.groups_enabled());
        assert!(disabled.group_projection().is_none());
    }

    #[test]
    fn group_event_write_requires_auth_before_storage() {
        let owner = signer(7).public_key().clone();
        let mut relay = test_relay_with_groups(
            "base-relay-group-auth-required",
            4,
            &enabled_groups_for_owner(&owner),
        );
        let auth = BaseAuthState::new("wss://relay.radroots.test", 60).expect("auth");
        let event = signed_group_create_event(7, "Farm");

        assert_eq!(
            relay
                .handle_event_with_auth(event.clone(), &auth)
                .expect("event"),
            RelayMessage::Ok {
                event_id: event.id().clone(),
                accepted: false,
                message: "auth-required: group event author must authenticate with AUTH".to_owned()
            }
        );
        assert!(
            relay
                .group_projection()
                .expect("projection")
                .group(&GroupId::new("Farm").expect("group"))
                .is_none()
        );
        assert_eq!(count_kind(&relay, KIND_GROUP_CREATE_GROUP), 0);
    }

    #[test]
    fn group_create_updates_projection_and_stores_generated_snapshots() {
        let owner = signer(7).public_key().clone();
        let mut relay = test_relay_with_groups(
            "base-relay-group-create",
            4,
            &enabled_groups_for_owner(&owner),
        );
        let auth = authenticated_state(7);
        let event = signed_group_create_event(7, "Farm");

        assert_eq!(
            relay
                .handle_event_with_auth(event.clone(), &auth)
                .expect("event"),
            RelayMessage::Ok {
                event_id: event.id().clone(),
                accepted: true,
                message: String::new()
            }
        );

        let group_id = GroupId::new("Farm").expect("group");
        assert!(
            relay
                .group_projection()
                .expect("projection")
                .group(&group_id)
                .is_some()
        );
        assert_eq!(count_kind(&relay, KIND_GROUP_CREATE_GROUP), 1);
        assert_eq!(count_kind(&relay, KIND_GROUP_METADATA), 1);
        assert_eq!(count_kind(&relay, KIND_GROUP_ADMINS), 1);
    }

    #[test]
    fn group_join_materializes_relay_membership_event() {
        let owner = signer(7).public_key().clone();
        let joiner = signer(8).public_key().clone();
        let mut relay = test_relay_with_groups(
            "base-relay-group-join",
            4,
            &enabled_groups_for_owner(&owner),
        );
        let create = signed_group_create_event(7, "Farm");
        relay
            .handle_event_with_auth(create, &authenticated_state(7))
            .expect("create");
        let join = signed_event_at(
            8,
            KIND_GROUP_JOIN_REQUEST.into(),
            vec![Tag::from_parts("h", &["Farm"]).expect("h")],
            "",
            1_714_124_434,
        );

        assert_eq!(
            relay
                .handle_event_with_auth(join.clone(), &authenticated_state(8))
                .expect("join"),
            RelayMessage::Ok {
                event_id: join.id().clone(),
                accepted: true,
                message: String::new()
            }
        );

        assert_eq!(count_kind(&relay, KIND_GROUP_PUT_USER), 1);
        assert_eq!(
            relay
                .group_projection()
                .expect("projection")
                .member(&GroupId::new("Farm").expect("group"), &joiner)
                .expect("member")
                .status(),
            MemberStatus::Member
        );
    }

    #[test]
    fn group_metadata_edit_replaces_generated_metadata_snapshot() {
        let owner = signer(7).public_key().clone();
        let mut relay = test_relay_with_groups(
            "base-relay-group-metadata-edit",
            4,
            &enabled_groups_for_owner(&owner),
        );
        let auth = authenticated_state(7);
        let create = signed_group_create_event(7, "Farm");
        assert_accepted(
            relay
                .handle_event_with_auth(create.clone(), &auth)
                .expect("create"),
            &create,
        );
        let edit = signed_event_at(
            7,
            KIND_GROUP_EDIT_METADATA.into(),
            vec![h("Farm"), name("Market")],
            "",
            1_714_124_436,
        );
        assert_accepted(
            relay
                .handle_event_with_auth(edit.clone(), &auth)
                .expect("edit"),
            &edit,
        );

        let group_id = GroupId::new("Farm").expect("group");
        let group = relay
            .group_projection()
            .expect("projection")
            .group(&group_id)
            .expect("group");
        assert_eq!(group.metadata().name(), Some("Market"));
        let metadata = query_filter(
            &mut relay,
            "metadata-edit",
            filter_group_tag(KIND_GROUP_METADATA, "d", "Farm"),
        );
        assert_eq!(metadata.len(), 1);
        assert!(has_tag(&metadata[0], "d", &["Farm"]));
        assert!(has_tag(&metadata[0], "name", &["Market"]));
        assert_eq!(count_kind(&relay, KIND_GROUP_METADATA), 1);
    }

    #[test]
    fn group_member_moderation_join_leave_and_snapshots_flow() {
        let owner = signer(7).public_key().clone();
        let member = signer(8).public_key().clone();
        let target = signer(9).public_key().clone();
        let mut relay = test_relay_with_groups(
            "base-relay-group-member-flow",
            4,
            &enabled_groups_for_owner(&owner),
        );
        let owner_auth = authenticated_state(7);
        let member_auth = authenticated_state(8);
        let target_auth = authenticated_state(9);
        relay
            .handle_event_with_auth(signed_group_create_event(7, "Farm"), &owner_auth)
            .expect("create");
        let rejected_add = signed_event_at(
            9,
            KIND_GROUP_PUT_USER.into(),
            vec![h("Farm"), p(&target)],
            "",
            1_714_124_434,
        );
        assert_eq!(
            rejected_message(
                relay
                    .handle_event_with_auth(rejected_add.clone(), &target_auth)
                    .expect("rejected add")
            ),
            "restricted: missing group capability manage_members"
        );
        let add = signed_event_at(
            7,
            KIND_GROUP_PUT_USER.into(),
            vec![h("Farm"), p(&member)],
            "",
            1_714_124_435,
        );
        assert_accepted(
            relay
                .handle_event_with_auth(add.clone(), &owner_auth)
                .expect("add"),
            &add,
        );
        assert_member_status(&relay, "Farm", &member, MemberStatus::Member);
        assert_eq!(count_kind(&relay, KIND_GROUP_MEMBERS), 1);

        let remove = signed_event_at(
            7,
            KIND_GROUP_REMOVE_USER.into(),
            vec![h("Farm"), p(&member)],
            "",
            1_714_124_436,
        );
        assert_accepted(
            relay
                .handle_event_with_auth(remove.clone(), &owner_auth)
                .expect("remove"),
            &remove,
        );
        assert_member_status(&relay, "Farm", &member, MemberStatus::Removed);
        assert_eq!(count_kind(&relay, KIND_GROUP_MEMBERS), 1);

        let join = signed_event_at(
            8,
            KIND_GROUP_JOIN_REQUEST.into(),
            vec![h("Farm")],
            "",
            1_714_124_437,
        );
        assert_accepted(
            relay
                .handle_event_with_auth(join.clone(), &member_auth)
                .expect("join"),
            &join,
        );
        assert_member_status(&relay, "Farm", &member, MemberStatus::Member);
        let duplicate_join = signed_event_at(
            8,
            KIND_GROUP_JOIN_REQUEST.into(),
            vec![h("Farm")],
            "",
            1_714_124_438,
        );
        assert_eq!(
            rejected_message(
                relay
                    .handle_event_with_auth(duplicate_join, &member_auth)
                    .expect("duplicate join")
            ),
            "invalid: group member already exists"
        );

        let leave = signed_event_at(
            8,
            KIND_GROUP_LEAVE_REQUEST.into(),
            vec![h("Farm")],
            "",
            1_714_124_439,
        );
        assert_accepted(
            relay
                .handle_event_with_auth(leave.clone(), &member_auth)
                .expect("leave"),
            &leave,
        );
        assert_member_status(&relay, "Farm", &member, MemberStatus::Removed);
        assert_eq!(count_kind(&relay, KIND_GROUP_REMOVE_USER), 2);
        let duplicate_leave = signed_event_at(
            8,
            KIND_GROUP_LEAVE_REQUEST.into(),
            vec![h("Farm")],
            "",
            1_714_124_440,
        );
        assert_eq!(
            rejected_message(
                relay
                    .handle_event_with_auth(duplicate_leave, &member_auth)
                    .expect("duplicate leave")
            ),
            "invalid: group member does not exist"
        );
    }

    #[test]
    fn group_delete_event_moderation_hides_target_and_validates_group() {
        let owner = signer(7).public_key().clone();
        let outsider_auth = authenticated_state(8);
        let owner_auth = authenticated_state(7);
        let mut relay = test_relay_with_groups(
            "base-relay-group-delete-event",
            4,
            &enabled_groups_for_owner(&owner),
        );
        relay
            .handle_event_with_auth(signed_group_create_event(7, "Farm"), &owner_auth)
            .expect("create farm");
        relay
            .handle_event_with_auth(signed_group_create_event(7, "Other"), &owner_auth)
            .expect("create other");
        let target = signed_event_at(7, 1, vec![h("Farm")], "harvest", 1_714_124_434);
        let other = signed_event_at(7, 1, vec![h("Other")], "other", 1_714_124_435);
        relay
            .handle_event_with_auth(target.clone(), &owner_auth)
            .expect("target");
        relay
            .handle_event_with_auth(other.clone(), &owner_auth)
            .expect("other");

        let wrong_group = signed_event_at(
            7,
            KIND_GROUP_DELETE_EVENT.into(),
            vec![h("Farm"), e(other.id())],
            "",
            1_714_124_436,
        );
        assert_eq!(
            rejected_message(
                relay
                    .handle_event_with_auth(wrong_group, &owner_auth)
                    .expect("wrong group")
            ),
            "invalid: delete target event is not in group"
        );
        let unauthorized = signed_event_at(
            8,
            KIND_GROUP_DELETE_EVENT.into(),
            vec![h("Farm"), e(target.id())],
            "",
            1_714_124_437,
        );
        assert_eq!(
            rejected_message(
                relay
                    .handle_event_with_auth(unauthorized, &outsider_auth)
                    .expect("unauthorized")
            ),
            "restricted: missing group capability delete_events"
        );
        assert_eq!(
            count_filter(
                &relay,
                "target-before-delete",
                filter_group_tag(1, "h", "Farm")
            ),
            1
        );

        let delete = signed_event_at(
            7,
            KIND_GROUP_DELETE_EVENT.into(),
            vec![h("Farm"), e(target.id())],
            "",
            1_714_124_438,
        );
        assert_accepted(
            relay
                .handle_event_with_auth(delete.clone(), &owner_auth)
                .expect("delete"),
            &delete,
        );

        assert_eq!(
            count_filter(
                &relay,
                "target-after-delete",
                filter_group_tag(1, "h", "Farm")
            ),
            0
        );
        assert_eq!(
            count_filter(
                &relay,
                "delete-event-marker",
                filter_group_tag(KIND_GROUP_DELETE_EVENT, "h", "Farm")
            ),
            1
        );
    }

    #[test]
    fn group_delete_tombstone_hides_events_and_rejects_future_writes() {
        let owner = signer(7).public_key().clone();
        let auth = authenticated_state(7);
        let mut relay = test_relay_with_groups(
            "base-relay-group-delete-tombstone",
            4,
            &enabled_groups_for_owner(&owner),
        );
        relay
            .handle_event_with_auth(signed_group_create_event(7, "Farm"), &auth)
            .expect("create");
        let normal = signed_event_at(7, 1, vec![h("Farm")], "harvest", 1_714_124_434);
        relay.handle_event_with_auth(normal, &auth).expect("normal");
        let delete_group = signed_event_at(
            7,
            KIND_GROUP_DELETE_GROUP.into(),
            vec![h("Farm")],
            "",
            1_714_124_435,
        );
        assert_accepted(
            relay
                .handle_event_with_auth(delete_group.clone(), &auth)
                .expect("delete group"),
            &delete_group,
        );

        let future = signed_event_at(7, 1, vec![h("Farm")], "future", 1_714_124_436);
        assert_eq!(
            rejected_message(relay.handle_event_with_auth(future, &auth).expect("future")),
            "blocked: group is deleted"
        );
        assert_eq!(
            count_filter(
                &relay,
                "deleted-group-normal",
                filter_group_tag(1, "h", "Farm")
            ),
            0
        );
        assert_eq!(
            count_filter(
                &relay,
                "deleted-group-marker",
                filter_group_tag(KIND_GROUP_DELETE_GROUP, "h", "Farm")
            ),
            1
        );
    }

    #[test]
    fn strict_closed_restricted_hidden_and_disabled_invite_flows() {
        let owner = signer(7).public_key().clone();
        let outsider_auth = authenticated_state(8);
        let owner_auth = authenticated_state(7);
        let mut relay = test_relay_with_groups(
            "base-relay-group-strict-policy-flow",
            4,
            &enabled_groups_for_owner(&owner),
        );
        relay
            .handle_event_with_auth(
                signed_group_create_event_with_tags(7, "Restricted", vec![restricted()], 1),
                &owner_auth,
            )
            .expect("restricted create");
        let restricted_write =
            signed_event_at(8, 1, vec![h("Restricted")], "restricted", 1_714_124_434);
        assert_eq!(
            rejected_message(
                relay
                    .handle_event_with_auth(restricted_write, &outsider_auth)
                    .expect("restricted write")
            ),
            "restricted: group is unavailable"
        );

        relay
            .handle_event_with_auth(
                signed_group_create_event_with_tags(7, "Closed", vec![closed()], 2),
                &owner_auth,
            )
            .expect("closed create");
        let closed_join = signed_event_at(
            8,
            KIND_GROUP_JOIN_REQUEST.into(),
            vec![h("Closed")],
            "",
            1_714_124_435,
        );
        assert_eq!(
            rejected_message(
                relay
                    .handle_event_with_auth(closed_join, &outsider_auth)
                    .expect("closed join")
            ),
            "restricted: group is unavailable"
        );
        let closed_normal = signed_event_at(8, 1, vec![h("Closed")], "open", 1_714_124_436);
        assert_accepted(
            relay
                .handle_event_with_auth(closed_normal.clone(), &outsider_auth)
                .expect("closed normal"),
            &closed_normal,
        );

        relay
            .handle_event_with_auth(
                signed_group_create_event_with_tags(7, "Hidden", vec![hidden()], 3),
                &owner_auth,
            )
            .expect("hidden create");
        assert_eq!(
            count_filter(
                &relay,
                "hidden-unauth",
                filter_group_tag(KIND_GROUP_METADATA, "d", "Hidden")
            ),
            0
        );
        assert_eq!(
            count_filter_with_auth(
                &relay,
                "hidden-owner",
                filter_group_tag(KIND_GROUP_METADATA, "d", "Hidden"),
                &owner_auth
            ),
            1
        );

        let invite = signed_event_at(
            7,
            KIND_GROUP_CREATE_INVITE.into(),
            vec![h("Closed")],
            "",
            1_714_124_437,
        );
        assert_eq!(
            rejected_message(
                relay
                    .handle_event_with_auth(invite, &owner_auth)
                    .expect("invite")
            ),
            "restricted: invites not enabled"
        );
    }

    #[test]
    fn private_group_req_and_count_use_reader_auth() {
        let owner = signer(7).public_key().clone();
        let auth = authenticated_state(7);
        let mut relay = test_relay_with_groups(
            "base-relay-private-read",
            4,
            &enabled_groups_for_owner(&owner),
        );
        relay
            .handle_event_with_auth(signed_private_group_create_event(7, "Farm"), &auth)
            .expect("create");
        let private_event = signed_event_at(
            7,
            1,
            vec![Tag::from_parts("h", &["Farm"]).expect("h")],
            "private harvest",
            1_714_124_435,
        );
        relay
            .handle_event_with_auth(private_event.clone(), &auth)
            .expect("private event");

        let unauth_sub = SubscriptionId::new("private-unauth").expect("sub");
        let auth_sub = SubscriptionId::new("private-auth").expect("sub");
        assert_eq!(
            relay
                .handle_req(unauth_sub.clone(), vec![filter_kind(1)])
                .expect("unauth req"),
            vec![RelayMessage::Eose(unauth_sub)]
        );
        assert!(matches!(
            relay
                .handle_req_with_auth(auth_sub.clone(), vec![filter_kind(1)], &auth)
                .expect("auth req")
                .as_slice(),
            [RelayMessage::Event { subscription_id, event }, RelayMessage::Eose(eose)]
                if subscription_id == &auth_sub && event.id() == private_event.id() && eose == &auth_sub
        ));
        assert_eq!(count_kind(&relay, 1), 0);
        assert_eq!(count_kind_with_auth(&relay, 1, &auth), 1);
        assert_eq!(count_kind(&relay, KIND_GROUP_METADATA), 0);
        assert_eq!(count_kind_with_auth(&relay, KIND_GROUP_METADATA, &auth), 1);
    }

    #[test]
    fn private_group_live_fanout_uses_subscription_auth() {
        let owner = signer(7).public_key().clone();
        let auth = authenticated_state(7);
        let mut relay = test_relay_with_groups(
            "base-relay-private-fanout",
            4,
            &enabled_groups_for_owner(&owner),
        );
        relay
            .handle_event_with_auth(signed_private_group_create_event(7, "Farm"), &auth)
            .expect("create");
        let unauth_sub = SubscriptionId::new("fanout-unauth").expect("sub");
        let auth_sub = SubscriptionId::new("fanout-auth").expect("sub");
        relay
            .handle_req(unauth_sub, vec![filter_kind(1)])
            .expect("unauth sub");
        relay
            .handle_req_with_auth(auth_sub.clone(), vec![filter_kind(1)], &auth)
            .expect("auth sub");
        let private_event = signed_event_at(
            7,
            1,
            vec![Tag::from_parts("h", &["Farm"]).expect("h")],
            "private harvest",
            1_714_124_435,
        );
        relay
            .handle_event_with_auth(private_event.clone(), &auth)
            .expect("private event");

        assert!(matches!(
            relay.fanout(&private_event).as_slice(),
            [RelayMessage::Event { subscription_id, event }]
                if subscription_id == &auth_sub && event.id() == private_event.id()
        ));
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
        let config = test_store_config(name);
        BaseRelay::open(&config, max_pending_events).expect("relay")
    }

    fn test_relay_with_groups(
        name: &str,
        max_pending_events: usize,
        groups: &tangle_groups::GroupRuntimeConfig,
    ) -> BaseRelay {
        let config = test_store_config(name);
        BaseRelay::open_with_groups(&config, max_pending_events, groups).expect("relay")
    }

    fn test_store_config(name: &str) -> PocketStoreConfig {
        let root = std::env::temp_dir().join(format!("tangle-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        PocketStoreConfig::new(
            root.join("pocket"),
            1024 * 1024 * 1024,
            128,
            PocketSyncPolicy::FlushOnShutdown,
        )
        .expect("config")
    }

    fn enabled_groups() -> tangle_groups::GroupRuntimeConfig {
        let owner = signer(7).public_key().clone();
        enabled_groups_for_owner(&owner)
    }

    fn enabled_groups_for_owner(owner: &PublicKeyHex) -> tangle_groups::GroupRuntimeConfig {
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

    fn signed_group_create_event(secret_byte: u8, group_id: &str) -> Event {
        signed_group_create_event_with_tags(secret_byte, group_id, Vec::new(), 1_714_124_433)
    }

    fn signed_group_create_event_with_tags(
        secret_byte: u8,
        group_id: &str,
        mut extra_tags: Vec<Tag>,
        created_at: u64,
    ) -> Event {
        let mut tags = vec![h(group_id), name(group_id)];
        tags.append(&mut extra_tags);
        signed_event_at(
            secret_byte,
            KIND_GROUP_CREATE_GROUP.into(),
            tags,
            "",
            created_at,
        )
    }

    fn signed_private_group_create_event(secret_byte: u8, group_id: &str) -> Event {
        signed_event_at(
            secret_byte,
            KIND_GROUP_CREATE_GROUP.into(),
            vec![h(group_id), name(group_id), private()],
            "",
            1_714_124_433,
        )
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

    fn authenticated_state(secret_byte: u8) -> BaseAuthState {
        let mut auth = BaseAuthState::new("wss://relay.radroots.test", 60).expect("auth state");
        auth.issue_challenge("challenge-a", UnixTimestamp::new(100))
            .expect("challenge");
        let event = signed_auth_event(secret_byte, "challenge-a", 120);
        auth.authenticate(&event, UnixTimestamp::new(120))
            .expect("authenticate");
        auth
    }

    fn count_kind(relay: &BaseRelay, kind: u32) -> u64 {
        let subscription_id = SubscriptionId::new(&format!("count-{kind}")).expect("sub");
        let filter = filter_kind(kind);
        match relay
            .handle_count(subscription_id, vec![filter])
            .expect("count")
        {
            RelayMessage::Count { count, .. } => count,
            _ => panic!("count response expected"),
        }
    }

    fn count_kind_with_auth(relay: &BaseRelay, kind: u32, auth: &BaseAuthState) -> u64 {
        let subscription_id = SubscriptionId::new(&format!("count-auth-{kind}")).expect("sub");
        match relay
            .handle_count_with_auth(subscription_id, vec![filter_kind(kind)], auth)
            .expect("count")
        {
            RelayMessage::Count { count, .. } => count,
            _ => panic!("count response expected"),
        }
    }

    fn count_filter(relay: &BaseRelay, subscription_id: &str, filter: Filter) -> u64 {
        match relay
            .handle_count(
                SubscriptionId::new(subscription_id).expect("sub"),
                vec![filter],
            )
            .expect("count")
        {
            RelayMessage::Count { count, .. } => count,
            _ => panic!("count response expected"),
        }
    }

    fn count_filter_with_auth(
        relay: &BaseRelay,
        subscription_id: &str,
        filter: Filter,
        auth: &BaseAuthState,
    ) -> u64 {
        match relay
            .handle_count_with_auth(
                SubscriptionId::new(subscription_id).expect("sub"),
                vec![filter],
                auth,
            )
            .expect("count")
        {
            RelayMessage::Count { count, .. } => count,
            _ => panic!("count response expected"),
        }
    }

    fn query_filter(relay: &mut BaseRelay, subscription_id: &str, filter: Filter) -> Vec<Event> {
        relay
            .handle_req(
                SubscriptionId::new(subscription_id).expect("sub"),
                vec![filter],
            )
            .expect("query")
            .into_iter()
            .filter_map(|message| match message {
                RelayMessage::Event { event, .. } => Some(event),
                _ => None,
            })
            .collect()
    }

    fn filter_kind(kind: u32) -> Filter {
        filter_from_value(&serde_json::json!({"kinds":[kind]})).expect("filter")
    }

    fn filter_group_tag(kind: u32, tag: &str, group_id: &str) -> Filter {
        let mut value = serde_json::json!({"kinds":[kind]});
        value
            .as_object_mut()
            .expect("object")
            .insert(format!("#{tag}"), serde_json::json!([group_id]));
        filter_from_value(&value).expect("filter")
    }

    fn assert_accepted(message: RelayMessage, event: &Event) {
        assert_eq!(
            message,
            RelayMessage::Ok {
                event_id: event.id().clone(),
                accepted: true,
                message: String::new()
            }
        );
    }

    fn rejected_message(message: RelayMessage) -> String {
        match message {
            RelayMessage::Ok {
                accepted: false,
                message,
                ..
            } => message,
            _ => panic!("rejected OK expected"),
        }
    }

    fn assert_member_status(
        relay: &BaseRelay,
        group_id: &str,
        pubkey: &PublicKeyHex,
        status: MemberStatus,
    ) {
        assert_eq!(
            relay
                .group_projection()
                .expect("projection")
                .member(&GroupId::new(group_id).expect("group"), pubkey)
                .expect("member")
                .status(),
            status
        );
    }

    fn has_tag(event: &Event, name: &str, values: &[&str]) -> bool {
        event.unsigned().tags().iter().any(|tag| {
            tag.values().first().is_some_and(|value| value == name)
                && tag.values().len() == values.len() + 1
                && values.iter().enumerate().all(|(index, expected)| {
                    tag.values()
                        .get(index + 1)
                        .is_some_and(|value| value == expected)
                })
        })
    }

    fn h(group_id: &str) -> Tag {
        Tag::from_parts("h", &[group_id]).expect("h")
    }

    fn p(pubkey: &PublicKeyHex) -> Tag {
        Tag::from_parts("p", &[pubkey.as_str()]).expect("p")
    }

    fn e(event_id: &EventId) -> Tag {
        Tag::from_parts("e", &[event_id.as_str()]).expect("e")
    }

    fn name(value: &str) -> Tag {
        Tag::from_parts("name", &[value]).expect("name")
    }

    fn private() -> Tag {
        Tag::from_parts("private", &[]).expect("private")
    }

    fn restricted() -> Tag {
        Tag::from_parts("restricted", &[]).expect("restricted")
    }

    fn hidden() -> Tag {
        Tag::from_parts("hidden", &[]).expect("hidden")
    }

    fn closed() -> Tag {
        Tag::from_parts("closed", &[]).expect("closed")
    }

    fn signer(secret_byte: u8) -> RelaySigner {
        RelaySigner::from_secret_hex(&format!("{:02x}", secret_byte).repeat(32)).expect("signer")
    }
}
