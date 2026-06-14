use crate::errors::{BaseRelayError, ok_accepted, ok_rejected};
use crate::groups::GroupService;
use crate::ops::BaseRelayReadinessState;
use crate::pocket_conversion::{
    pocket_event_id, pocket_event_to_tangle, tangle_event_to_pocket, tangle_filter_to_pocket,
};
use crate::relay::{
    auth::BaseAuthState,
    live::{CloseResult, LiveSubscriptionSet},
};
use std::collections::BTreeSet;
use tangle_crypto::verify_event_signature;
use tangle_groups::{
    GroupAuthContext, GroupEventClass, GroupProjection, GroupRuntimeConfig, StoreOffset,
    validate_client_group_event_structure,
};
use tangle_protocol::{ClientMessage, Event, Filter, RelayMessage, SubscriptionId, UnixTimestamp};
use tangle_store_pocket::{PocketStoreConfig, PocketStoreHandle};

pub struct BaseRelay {
    store: PocketStoreHandle,
    subscriptions: LiveSubscriptionSet,
    groups: Option<GroupService>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BaseRelayShutdownReport {
    closed_subscriptions: usize,
}

impl BaseRelayShutdownReport {
    pub fn new(closed_subscriptions: usize) -> Self {
        Self {
            closed_subscriptions,
        }
    }

    pub fn closed_subscriptions(self) -> usize {
        self.closed_subscriptions
    }
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
            ClientMessage::Auth(event) => Ok(self.handle_auth_message(event, auth, now)),
        }
    }

    pub(crate) fn query_req_with_auth(
        &self,
        subscription_id: SubscriptionId,
        filters: Vec<Filter>,
        auth: &BaseAuthState,
    ) -> Result<Vec<RelayMessage>, BaseRelayError> {
        self.query_req_with_group_auth(
            subscription_id,
            filters,
            &GroupAuthContext::new(auth.authenticated_pubkeys().iter().cloned()),
        )
    }

    fn handle_auth_message(
        &self,
        event: Event,
        auth: &mut BaseAuthState,
        now: UnixTimestamp,
    ) -> Vec<RelayMessage> {
        auth.authenticate(&event, now)
            .map(|_| {
                vec![RelayMessage::Ok {
                    event_id: event.id().clone(),
                    accepted: true,
                    message: String::new(),
                }]
            })
            .unwrap_or_else(|error| {
                vec![RelayMessage::Ok {
                    event_id: event.id().clone(),
                    accepted: false,
                    message: error.prefixed_message(),
                }]
            })
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

    pub fn readiness_state(&self) -> BaseRelayReadinessState {
        BaseRelayReadinessState::ready()
    }

    pub fn shutdown(&mut self) -> Result<BaseRelayShutdownReport, BaseRelayError> {
        let closed = self.subscriptions.close_all();
        self.store.sync()?;
        Ok(BaseRelayShutdownReport::new(closed))
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
        self.query_req_with_group_auth(subscription_id, filters, auth)
    }

    fn query_req_with_group_auth(
        &self,
        subscription_id: SubscriptionId,
        filters: Vec<Filter>,
        auth: &GroupAuthContext,
    ) -> Result<Vec<RelayMessage>, BaseRelayError> {
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
        let groups = self.groups.as_ref();
        self.subscriptions.fanout(event, |event, auth| {
            groups
                .map(|groups| groups.event_visible_to_auth(event, auth).unwrap_or(false))
                .unwrap_or(true)
        })
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

#[cfg(test)]
mod tests {
    use super::BaseRelay;
    use crate::relay::auth::BaseAuthState;
    use crate::relay::live::CloseResult;
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
        let auth = BaseAuthState::new("wss://relay.radroots.test", 60, 600).expect("auth");
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
    fn base_relay_shutdown_closes_live_subscriptions_and_syncs_store() {
        let config = test_store_config("base-relay-shutdown");
        let mut relay = BaseRelay::open(&config, 4).expect("relay");
        let event = signed_public_event(7, 1, Vec::new(), "shutdown");
        let subscription_id = SubscriptionId::new("sub-shutdown").expect("sub");

        assert_accepted(relay.handle_event(event.clone()).expect("event"), &event);
        relay
            .handle_req(subscription_id, vec![filter_kind(1)])
            .expect("req");

        assert_eq!(relay.active_subscription_count(), 1);

        let report = relay.shutdown().expect("shutdown");

        assert_eq!(report.closed_subscriptions(), 1);
        assert_eq!(relay.active_subscription_count(), 0);
        assert!(relay.fanout(&event).is_empty());

        let reopened = BaseRelay::open(&config, 4).expect("reopened");
        assert_eq!(count_kind(&reopened, 1), 1);
    }

    #[test]
    fn base_relay_client_message_dispatch_handles_count_and_auth() {
        let mut relay = test_relay("base-relay-dispatch", 4);
        let mut auth =
            BaseAuthState::new("wss://relay.radroots.test", 60, 600).expect("auth state");
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
        let mut auth =
            BaseAuthState::new("wss://relay.radroots.test", 60, 600).expect("auth state");
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
