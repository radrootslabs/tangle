#![forbid(unsafe_code)]

use crate::{errors::BaseRelayError, pocket_conversion::pocket_event_id};
use std::{
    ops::Deref,
    str,
    sync::{Arc, RwLock, RwLockReadGuard},
    time::{SystemTime, UNIX_EPOCH},
};
use tangle_crypto::RelaySigner;
use tangle_groups::{
    CanonicalGroupEvent, GroupAuthContext, GroupAuthority, GroupError, GroupErrorKind,
    GroupEventClass, GroupEventDeletion, GroupGeneratedEventBuilder, GroupId, GroupLimitsConfig,
    GroupOutbox, GroupOutboxEffect, GroupOutboxKey, GroupOutboxPayload, GroupOutboxRecord,
    GroupPolicyConfig, GroupProjection, GroupReadDecision, GroupReadGate, GroupRuntimeConfig,
    GroupState, GroupTombstone, KIND_GROUP_CREATE_GROUP, KIND_GROUP_DELETE_EVENT,
    KIND_GROUP_EDIT_METADATA, KIND_GROUP_JOIN_REQUEST, KIND_GROUP_LEAVE_REQUEST,
    KIND_GROUP_MEMBERS, KIND_GROUP_PUT_USER, KIND_GROUP_REMOVE_USER, MemberState, MemberStatus,
    ProjectedRoleDefinition, ProjectionCheckpoint, RoleName, StoreOffset, event_deletion_key,
    event_view::GroupEventView, group_current_key, member_current_key, projection_checkpoint_key,
    rebuild_group_projection, role_current_key, tombstone_key,
};
#[cfg(test)]
use tangle_protocol::Event;
use tangle_protocol::{EventId, PublicKeyHex, UnixTimestamp};
use tangle_store_pocket::{
    PocketEvent, PocketEventId, PocketOwnedEvent, PocketStoreHandle, TANGLE_GROUP_CHECKPOINT_TABLE,
    TANGLE_GROUP_OUTBOX_TABLE, TANGLE_GROUP_PROJECTION_TABLE,
};

#[derive(Clone)]
pub(crate) struct GroupServiceHandle {
    state: Arc<RwLock<GroupServiceState>>,
}

pub(crate) enum GroupEventWrite {
    Stored(Vec<StoreOffset>),
    Duplicate,
}

pub(crate) enum GroupEventWriteError {
    Rejected(GroupError),
    Storage(BaseRelayError),
}

struct GeneratedGroupStorageEvent {
    event: PocketOwnedEvent,
}

impl GeneratedGroupStorageEvent {
    fn build(
        builder: &GroupGeneratedEventBuilder,
        payload: &GroupOutboxPayload,
    ) -> Result<Self, BaseRelayError> {
        let event = builder.sign_payload_pocket(payload)?;
        Ok(Self { event })
    }

    fn event(&self) -> &PocketEvent {
        &self.event
    }

    fn event_id(&self) -> Result<EventId, BaseRelayError> {
        EventId::new(&self.event().id().as_hex_string()).map_err(BaseRelayError::error)
    }
}

impl From<BaseRelayError> for GroupEventWriteError {
    fn from(error: BaseRelayError) -> Self {
        Self::Storage(error)
    }
}

pub struct GroupProjectionReadGuard<'a> {
    state: RwLockReadGuard<'a, GroupServiceState>,
}

impl Deref for GroupProjectionReadGuard<'_> {
    type Target = GroupProjection;

    fn deref(&self) -> &Self::Target {
        &self.state.projection
    }
}

pub(crate) struct GroupServiceState {
    builder: GroupGeneratedEventBuilder,
    authority: GroupAuthority,
    projection: GroupProjection,
    outbox: GroupOutbox,
    policy: GroupPolicyConfig,
    limits: GroupLimitsConfig,
    member_snapshot_cap: u32,
    outbox_replay_batch_cap: u32,
}

impl GroupServiceHandle {
    pub(crate) fn from_config(
        store: &PocketStoreHandle,
        config: &GroupRuntimeConfig,
    ) -> Result<Option<Self>, BaseRelayError> {
        GroupServiceState::from_config(store, config).map(|state| {
            state.map(|state| Self {
                state: Arc::new(RwLock::new(state)),
            })
        })
    }

    pub(crate) fn projection(&self) -> GroupProjectionReadGuard<'_> {
        GroupProjectionReadGuard {
            state: self
                .state
                .read()
                .expect("group service state lock is not poisoned"),
        }
    }

    pub(crate) fn limits(&self) -> GroupLimitsConfig {
        self.state
            .read()
            .expect("group service state lock is not poisoned")
            .limits()
    }

    pub(crate) fn outbox_pending_events(&self) -> usize {
        self.state
            .read()
            .expect("group service state lock is not poisoned")
            .outbox_pending_events()
    }

    pub(crate) fn event_visible_to_auth(
        &self,
        event: &(impl GroupEventView + ?Sized),
        auth: &GroupAuthContext,
    ) -> Result<bool, GroupError> {
        self.state
            .read()
            .map_err(|_| GroupError::internal("group service state lock is poisoned"))?
            .event_visible_to_auth(event, auth)
    }

    pub(crate) fn store_group_pocket_event(
        &self,
        store: &PocketStoreHandle,
        event: &PocketEvent,
        class: &GroupEventClass,
        auth: &GroupAuthContext,
    ) -> Result<GroupEventWrite, GroupEventWriteError> {
        self.state
            .write()
            .map_err(|_| BaseRelayError::error("group service state lock is poisoned"))?
            .store_group_pocket_event(store, event, class, auth)
    }

    #[cfg(test)]
    pub(crate) fn store_group_event(
        &self,
        store: &PocketStoreHandle,
        event: &Event,
        class: &GroupEventClass,
        auth: &GroupAuthContext,
    ) -> Result<GroupEventWrite, GroupEventWriteError> {
        self.state
            .write()
            .map_err(|_| BaseRelayError::error("group service state lock is poisoned"))?
            .store_group_event(store, event, class, auth)
    }
}

impl GroupServiceState {
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
        let storage = load_group_storage(store, config.limits())?;
        let mut state = Self {
            builder: GroupGeneratedEventBuilder::new(signer),
            authority: GroupAuthority::new(
                config.owner_pubkeys().iter().cloned(),
                config.admin_pubkeys().iter().cloned(),
            ),
            projection: storage.projection,
            outbox: storage.outbox,
            policy: config.policy(),
            limits: config.limits(),
            member_snapshot_cap: config.limits().max_member_list_pubkeys(),
            outbox_replay_batch_cap: config.limits().max_outbox_replay_batch(),
        };
        state.derive_missing_outbox_records(store)?;
        state.materialize_outbox(store)?;
        Ok(Some(state))
    }

    fn limits(&self) -> GroupLimitsConfig {
        self.limits
    }

    fn outbox_pending_events(&self) -> usize {
        self.outbox.replay_plan().records().len()
    }

    fn check_event(
        &self,
        store: &PocketStoreHandle,
        event: &(impl GroupEventView + ?Sized),
        class: &GroupEventClass,
        auth: &GroupAuthContext,
    ) -> Result<(), GroupError> {
        tangle_groups::GroupWritePolicy::new(&self.projection, &self.authority, self.policy)
            .check_event(event, class, auth)
            .map(|_| ())?;
        self.check_runtime_write_constraints(store, event, class)
    }

    fn check_runtime_write_constraints(
        &self,
        store: &PocketStoreHandle,
        event: &(impl GroupEventView + ?Sized),
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
        event: &(impl GroupEventView + ?Sized),
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
        let target_class = tangle_groups::classify_group_event(&target, self.limits)?;
        if target_class.group_id() != Some(group_id) {
            return Err(GroupError::invalid(
                GroupErrorKind::MalformedTargetTag,
                "delete target event is not in group",
            ));
        }
        Ok(())
    }

    fn store_group_pocket_event(
        &mut self,
        store: &PocketStoreHandle,
        event: &PocketEvent,
        class: &GroupEventClass,
        auth: &GroupAuthContext,
    ) -> Result<GroupEventWrite, GroupEventWriteError> {
        self.check_event(store, event, class, auth)
            .map_err(GroupEventWriteError::Rejected)?;
        if store
            .event_by_id(event.id())
            .map_err(BaseRelayError::from)?
            .is_some()
        {
            return Ok(GroupEventWrite::Duplicate);
        }
        let store_offset =
            StoreOffset::new(store.store_event(event).map_err(BaseRelayError::from)?);
        let mut stored_offsets = vec![store_offset];
        stored_offsets.extend(self.after_source_event_stored(store, event, class, store_offset)?);
        Ok(GroupEventWrite::Stored(stored_offsets))
    }

    #[cfg(test)]
    fn store_group_event(
        &mut self,
        store: &PocketStoreHandle,
        event: &Event,
        class: &GroupEventClass,
        auth: &GroupAuthContext,
    ) -> Result<GroupEventWrite, GroupEventWriteError> {
        self.check_event(store, event, class, auth)
            .map_err(GroupEventWriteError::Rejected)?;
        if store
            .event_by_id(pocket_event_id(event.id())?)
            .map_err(BaseRelayError::from)?
            .is_some()
        {
            return Ok(GroupEventWrite::Duplicate);
        }
        let pocket_event = crate::pocket_conversion::tangle_event_to_pocket(event)?;
        let store_offset = StoreOffset::new(
            store
                .store_event(&pocket_event)
                .map_err(BaseRelayError::from)?,
        );
        let mut stored_offsets = vec![store_offset];
        stored_offsets.extend(self.after_source_event_stored(store, event, class, store_offset)?);
        Ok(GroupEventWrite::Stored(stored_offsets))
    }

    fn event_visible_to_auth(
        &self,
        event: &(impl GroupEventView + ?Sized),
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
        event: &(impl GroupEventView + ?Sized),
        class: &GroupEventClass,
        store_offset: StoreOffset,
    ) -> Result<Vec<StoreOffset>, BaseRelayError> {
        let before_membership_admin =
            membership_admin_snapshot_state(&self.projection, event, class)?;
        self.projection
            .apply_canonical_event(event, store_offset, self.limits)?;
        if let Some(group_id) = class_group_id(class) {
            self.persist_group_projection(store, group_id)?;
        }
        for record in self.plan_outbox_records(event, class, before_membership_admin)? {
            let inserted = self.outbox.merge_idempotent(record.clone())?;
            if inserted {
                persist_outbox_record(store, &record)?;
            }
        }
        if let Some(group_id) = class_group_id(class) {
            return self.materialize_outbox_for_group(store, group_id);
        }
        Ok(Vec::new())
    }

    fn plan_outbox_records(
        &self,
        event: &(impl GroupEventView + ?Sized),
        class: &GroupEventClass,
        before_membership_admin: Option<bool>,
    ) -> Result<Vec<GroupOutboxRecord>, GroupError> {
        plan_group_outbox_records(
            event,
            class,
            &self.projection,
            &self.authority,
            self.member_snapshot_cap,
            before_membership_admin,
        )
    }

    fn derive_missing_outbox_records(
        &mut self,
        store: &PocketStoreHandle,
    ) -> Result<(), BaseRelayError> {
        let relay_pubkey = self.builder.relay_pubkey().clone();
        let scan = scan_canonical_group_events(store, self.limits)?;
        let mut projection = GroupProjection::new();
        let mut events = scan.into_events();
        events.sort_by_key(CanonicalGroupEvent::tuple);
        for item in events {
            let class = tangle_groups::classify_group_event(item.event(), self.limits)?;
            let before_membership_admin =
                membership_admin_snapshot_state(&projection, item.event(), &class)?;
            projection.apply_canonical_event(item.event(), item.store_offset(), self.limits)?;
            if item.event().pubkey().as_hex_string() == relay_pubkey.as_str() {
                continue;
            }
            for record in plan_group_outbox_records(
                item.event(),
                &class,
                &projection,
                &self.authority,
                self.member_snapshot_cap,
                before_membership_admin,
            )? {
                let inserted = self.outbox.merge_idempotent(record.clone())?;
                if inserted {
                    persist_outbox_record(store, &record)?;
                }
            }
        }
        Ok(())
    }

    fn materialize_outbox(
        &mut self,
        store: &PocketStoreHandle,
    ) -> Result<Vec<StoreOffset>, BaseRelayError> {
        let mut stored_offsets = Vec::new();
        loop {
            let records = self
                .outbox
                .replay_plan()
                .records()
                .iter()
                .take(self.outbox_replay_batch_cap())
                .cloned()
                .collect::<Vec<_>>();
            if records.is_empty() {
                break;
            }
            stored_offsets.extend(self.materialize_records(store, records)?);
        }
        Ok(stored_offsets)
    }

    fn materialize_outbox_for_group(
        &mut self,
        store: &PocketStoreHandle,
        group_id: &GroupId,
    ) -> Result<Vec<StoreOffset>, BaseRelayError> {
        let mut stored_offsets = Vec::new();
        loop {
            let records = self
                .outbox
                .replay_plan_for_group(group_id)
                .records()
                .iter()
                .take(self.outbox_replay_batch_cap())
                .cloned()
                .collect::<Vec<_>>();
            if records.is_empty() {
                break;
            }
            stored_offsets.extend(self.materialize_records(store, records)?);
        }
        Ok(stored_offsets)
    }

    fn outbox_replay_batch_cap(&self) -> usize {
        usize::try_from(self.outbox_replay_batch_cap)
            .expect("u32 outbox replay batch cap fits usize")
    }

    fn materialize_records(
        &mut self,
        store: &PocketStoreHandle,
        records: Vec<GroupOutboxRecord>,
    ) -> Result<Vec<StoreOffset>, BaseRelayError> {
        let mut stored_offsets = Vec::new();
        for record in records {
            if let Some(offset) = self.materialize_record(store, record)? {
                stored_offsets.push(offset);
            }
        }
        Ok(stored_offsets)
    }

    fn materialize_record(
        &mut self,
        store: &PocketStoreHandle,
        mut record: GroupOutboxRecord,
    ) -> Result<Option<StoreOffset>, BaseRelayError> {
        if matches!(
            record.key().effect(),
            GroupOutboxEffect::RoleListSnapshot | GroupOutboxEffect::State39004Snapshot
        ) {
            record.mark_skipped("generated group effect is not supported");
            self.outbox.update(record.clone());
            persist_outbox_record(store, &record)?;
            return Ok(None);
        }
        match self.store_generated_event(store, &record) {
            Ok((generated_event_id, stored_offset)) => {
                record.mark_stored(generated_event_id);
                self.outbox.update(record.clone());
                persist_outbox_record(store, &record)?;
                Ok(stored_offset)
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
    ) -> Result<(EventId, Option<StoreOffset>), BaseRelayError> {
        let generated = GeneratedGroupStorageEvent::build(&self.builder, record.payload())?;
        let event_id = generated.event_id()?;
        if generated_event_already_stored(store, generated.event().id())? {
            return Ok((event_id, None));
        }
        let offset = StoreOffset::new(store.store_event(generated.event())?);
        self.projection
            .apply_canonical_event(generated.event(), offset, self.limits)?;
        self.persist_group_projection(store, record.key().group_id())?;
        Ok((event_id, Some(offset)))
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
}

fn plan_group_outbox_records(
    event: &(impl GroupEventView + ?Sized),
    class: &GroupEventClass,
    projection: &GroupProjection,
    authority: &GroupAuthority,
    member_snapshot_cap: u32,
    before_membership_admin: Option<bool>,
) -> Result<Vec<GroupOutboxRecord>, GroupError> {
    let created_at = event.created_at();
    match class {
        GroupEventClass::Moderation { kind, group_id } => match kind.as_u32() {
            KIND_GROUP_CREATE_GROUP => {
                let group = require_projected_group(projection, group_id)?;
                Ok(vec![
                    pending_record(
                        event,
                        GroupOutboxEffect::MetadataSnapshot,
                        group_id,
                        None,
                        GroupGeneratedEventBuilder::metadata_snapshot_payload(group, created_at)?,
                    )?,
                    pending_record(
                        event,
                        GroupOutboxEffect::AdminListSnapshot,
                        group_id,
                        None,
                        GroupGeneratedEventBuilder::admin_list_snapshot_payload(
                            group_id, projection, authority, created_at,
                        )?,
                    )?,
                ])
            }
            KIND_GROUP_EDIT_METADATA => {
                let group = require_projected_group(projection, group_id)?;
                Ok(vec![pending_record(
                    event,
                    GroupOutboxEffect::MetadataSnapshot,
                    group_id,
                    None,
                    GroupGeneratedEventBuilder::metadata_snapshot_payload(group, created_at)?,
                )?])
            }
            KIND_GROUP_PUT_USER | KIND_GROUP_REMOVE_USER => member_snapshot_records(
                event,
                group_id,
                projection,
                authority,
                created_at,
                member_snapshot_cap,
                before_membership_admin,
            ),
            _ => Ok(Vec::new()),
        },
        GroupEventClass::Normal { group_id } => match event.kind_u32() {
            KIND_GROUP_JOIN_REQUEST => Ok(vec![pending_record(
                event,
                GroupOutboxEffect::JoinAccepted,
                group_id,
                Some(event.pubkey()?),
                GroupGeneratedEventBuilder::join_accepted_payload(
                    group_id,
                    &event.pubkey()?,
                    created_at,
                ),
            )?]),
            KIND_GROUP_LEAVE_REQUEST => Ok(vec![pending_record(
                event,
                GroupOutboxEffect::LeaveAccepted,
                group_id,
                Some(event.pubkey()?),
                GroupGeneratedEventBuilder::leave_accepted_payload(
                    group_id,
                    &event.pubkey()?,
                    created_at,
                ),
            )?]),
            _ => Ok(Vec::new()),
        },
        GroupEventClass::NonGroup | GroupEventClass::RelayGeneratedSnapshot { .. } => {
            Ok(Vec::new())
        }
    }
}

fn member_snapshot_records(
    event: &(impl GroupEventView + ?Sized),
    group_id: &GroupId,
    projection: &GroupProjection,
    authority: &GroupAuthority,
    created_at: UnixTimestamp,
    member_snapshot_cap: u32,
    before_membership_admin: Option<bool>,
) -> Result<Vec<GroupOutboxRecord>, GroupError> {
    let mut records =
        member_snapshot_record(event, group_id, projection, created_at, member_snapshot_cap)?;
    if let Some(before) = before_membership_admin {
        let target = membership_target_pubkey(event)?;
        let after = member_is_relay_override_admin(projection, group_id, &target);
        if before != after {
            records.push(pending_record(
                event,
                GroupOutboxEffect::AdminListSnapshot,
                group_id,
                None,
                GroupGeneratedEventBuilder::admin_list_snapshot_payload(
                    group_id, projection, authority, created_at,
                )?,
            )?);
        }
    }
    Ok(records)
}

fn member_snapshot_record(
    event: &(impl GroupEventView + ?Sized),
    group_id: &GroupId,
    projection: &GroupProjection,
    created_at: UnixTimestamp,
    member_snapshot_cap: u32,
) -> Result<Vec<GroupOutboxRecord>, GroupError> {
    let key = GroupOutboxKey::new(
        event.id()?,
        GroupOutboxEffect::MemberListSnapshot,
        group_id.clone(),
        None,
    );
    let payload = GroupGeneratedEventBuilder::member_list_snapshot_payload(
        group_id,
        projection,
        created_at,
        member_snapshot_cap,
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

fn membership_admin_snapshot_state(
    projection: &GroupProjection,
    event: &(impl GroupEventView + ?Sized),
    class: &GroupEventClass,
) -> Result<Option<bool>, GroupError> {
    match class {
        GroupEventClass::Moderation { kind, group_id }
            if matches!(kind.as_u32(), KIND_GROUP_PUT_USER | KIND_GROUP_REMOVE_USER) =>
        {
            let target = membership_target_pubkey(event)?;
            Ok(Some(member_is_relay_override_admin(
                projection, group_id, &target,
            )))
        }
        _ => Ok(None),
    }
}

fn member_is_relay_override_admin(
    projection: &GroupProjection,
    group_id: &GroupId,
    pubkey: &PublicKeyHex,
) -> bool {
    projection
        .member(group_id, pubkey)
        .filter(|member| member.status() == MemberStatus::Member)
        .is_some_and(|member| {
            member
                .roles()
                .contains(&RoleName::permanent_relay_override())
        })
}

fn membership_target_pubkey(
    event: &(impl GroupEventView + ?Sized),
) -> Result<PublicKeyHex, GroupError> {
    let mut target = None;
    event.visit_tags(|tag| {
        if tag.first_value().is_none_or(|name| name != "p") {
            return Ok(());
        }
        let Some((_, value)) = tag.indexed_pair() else {
            return Err(GroupError::invalid(
                GroupErrorKind::MalformedTargetTag,
                "malformed p target tag",
            ));
        };
        target = Some(PublicKeyHex::new(value).map_err(|reason| {
            GroupError::invalid(
                GroupErrorKind::MalformedTargetTag,
                format!("malformed p target tag: {reason}"),
            )
        })?);
        Ok(())
    })?;
    target.ok_or_else(|| {
        GroupError::invalid(GroupErrorKind::MissingTargetTag, "missing p target tag")
    })
}

fn pending_record(
    event: &(impl GroupEventView + ?Sized),
    effect: GroupOutboxEffect,
    group_id: &GroupId,
    target_pubkey: Option<PublicKeyHex>,
    payload: GroupOutboxPayload,
) -> Result<GroupOutboxRecord, GroupError> {
    Ok(GroupOutboxRecord::pending(
        GroupOutboxKey::new(event.id()?, effect, group_id.clone(), target_pubkey),
        payload,
    ))
}

fn require_projected_group<'a>(
    projection: &'a GroupProjection,
    group_id: &GroupId,
) -> Result<&'a GroupState, GroupError> {
    projection
        .group(group_id)
        .ok_or_else(|| GroupError::internal("group projection is missing after accepted write"))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GroupStorageState {
    projection: GroupProjection,
    outbox: GroupOutbox,
}

fn load_group_storage(
    store: &PocketStoreHandle,
    limits: GroupLimitsConfig,
) -> Result<GroupStorageState, BaseRelayError> {
    let checkpoint_status = validate_group_checkpoint(store)?;
    let outbox_records = store.scan_extra_records(TANGLE_GROUP_OUTBOX_TABLE)?;
    if checkpoint_status.requires_rebuild() {
        let scan = scan_canonical_group_events(store, limits)?;
        let report =
            rebuild_group_projection(scan.into_events(), limits, projection_rebuilt_at()?)?;
        persist_group_projection_snapshot(store, report.projection())?;
        validate_rebuilt_group_projection(store)?;
        return Ok(GroupStorageState {
            projection: report.into_projection(),
            outbox: load_group_outbox(outbox_records)?,
        });
    }
    let checkpoint = checkpoint_status.checkpoint().cloned();
    let projection_records = store.scan_extra_records(TANGLE_GROUP_PROJECTION_TABLE)?;
    let mut projection = load_group_projection(projection_records, checkpoint)?;
    apply_canonical_events_after_checkpoint(store, &mut projection, limits)?;
    Ok(GroupStorageState {
        projection,
        outbox: load_group_outbox(outbox_records)?,
    })
}

fn load_group_projection(
    records: Vec<(Vec<u8>, Vec<u8>)>,
    checkpoint: Option<ProjectionCheckpoint>,
) -> Result<GroupProjection, BaseRelayError> {
    let mut projection = GroupProjection::new();
    for (key, value) in records {
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
            _ => {
                return Err(BaseRelayError::error(format!(
                    "unknown group projection extra-table key: {}",
                    projection_key_label(&key)
                )));
            }
        }
    }
    if let Some(checkpoint) = checkpoint {
        projection.set_checkpoint(checkpoint);
    }
    Ok(projection)
}

fn load_group_outbox(records: Vec<(Vec<u8>, Vec<u8>)>) -> Result<GroupOutbox, BaseRelayError> {
    let mut outbox = GroupOutbox::new();
    for (_, value) in records {
        outbox.update(GroupOutboxRecord::from_json_bytes(&value)?);
    }
    Ok(outbox)
}

fn apply_canonical_events_after_checkpoint(
    store: &PocketStoreHandle,
    projection: &mut GroupProjection,
    limits: GroupLimitsConfig,
) -> Result<(), BaseRelayError> {
    let last_offset = projection
        .checkpoint()
        .and_then(ProjectionCheckpoint::last_offset);
    let scan = scan_canonical_group_events_after(store, last_offset, limits)?;
    if scan.events().is_empty() {
        return Ok(());
    }
    let mut events = scan.into_events();
    let next_offset = events.iter().map(CanonicalGroupEvent::store_offset).max();
    events.sort_by_key(CanonicalGroupEvent::tuple);
    for item in events {
        projection.apply_canonical_event(item.event(), item.store_offset(), limits)?;
    }
    projection.set_checkpoint(ProjectionCheckpoint::current(
        next_offset,
        projection_rebuilt_at()?,
    ));
    persist_group_projection_snapshot(store, projection)?;
    validate_rebuilt_group_projection(store)
}

fn persist_group_projection_snapshot(
    store: &PocketStoreHandle,
    projection: &GroupProjection,
) -> Result<(), BaseRelayError> {
    clear_extra_table(store, TANGLE_GROUP_PROJECTION_TABLE)?;
    for (group_id, group) in projection.groups() {
        store.put_extra_record(
            TANGLE_GROUP_PROJECTION_TABLE,
            &group_current_key(group_id),
            &group.to_json_bytes()?,
        )?;
    }
    for ((group_id, pubkey), member) in projection.members() {
        store.put_extra_record(
            TANGLE_GROUP_PROJECTION_TABLE,
            &member_current_key(group_id, pubkey),
            &member.to_json_bytes()?,
        )?;
    }
    for ((group_id, role_name), role) in projection.roles() {
        store.put_extra_record(
            TANGLE_GROUP_PROJECTION_TABLE,
            &role_current_key(group_id, role_name),
            &role.to_json_bytes()?,
        )?;
    }
    for (group_id, tombstone) in projection.tombstones() {
        store.put_extra_record(
            TANGLE_GROUP_PROJECTION_TABLE,
            &tombstone_key(group_id),
            &tombstone.to_json_bytes()?,
        )?;
    }
    for (target_event_id, deletion) in projection.event_deletions() {
        store.put_extra_record(
            TANGLE_GROUP_PROJECTION_TABLE,
            &event_deletion_key(target_event_id),
            &deletion.to_json_bytes()?,
        )?;
    }
    let checkpoint = projection
        .checkpoint()
        .ok_or_else(|| BaseRelayError::error("group projection rebuild checkpoint is missing"))?;
    store.put_extra_record(
        TANGLE_GROUP_CHECKPOINT_TABLE,
        &projection_checkpoint_key(),
        &checkpoint.to_json_bytes()?,
    )?;
    Ok(())
}

fn clear_extra_table(store: &PocketStoreHandle, table: &'static str) -> Result<(), BaseRelayError> {
    for (key, _) in store.scan_extra_records(table)? {
        store.delete_extra_record(table, &key)?;
    }
    Ok(())
}

fn validate_rebuilt_group_projection(store: &PocketStoreHandle) -> Result<(), BaseRelayError> {
    let validation = validate_group_extra_tables(store)?;
    if validation.checkpoint_status().requires_rebuild() {
        return Err(BaseRelayError::error(
            "group projection checkpoint is not current after rebuild",
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupExtraTableValidation {
    projection_records: usize,
    outbox_records: usize,
    checkpoint_status: GroupCheckpointStatus,
}

impl GroupExtraTableValidation {
    pub fn projection_records(&self) -> usize {
        self.projection_records
    }

    pub fn outbox_records(&self) -> usize {
        self.outbox_records
    }

    pub fn checkpoint_status(&self) -> &GroupCheckpointStatus {
        &self.checkpoint_status
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GroupCheckpointStatus {
    Missing,
    Current { checkpoint: ProjectionCheckpoint },
    Stale { checkpoint: ProjectionCheckpoint },
}

impl GroupCheckpointStatus {
    pub fn requires_rebuild(&self) -> bool {
        !matches!(self, Self::Current { .. })
    }

    pub fn checkpoint(&self) -> Option<&ProjectionCheckpoint> {
        match self {
            Self::Missing => None,
            Self::Current { checkpoint } | Self::Stale { checkpoint } => Some(checkpoint),
        }
    }
}

pub fn validate_group_extra_tables(
    store: &PocketStoreHandle,
) -> Result<GroupExtraTableValidation, BaseRelayError> {
    let projection_records = validate_group_projection_records(store)?;
    let outbox_records = validate_group_outbox_records(store)?;
    let checkpoint_status = validate_group_checkpoint(store)?;
    Ok(GroupExtraTableValidation {
        projection_records,
        outbox_records,
        checkpoint_status,
    })
}

fn validate_group_projection_records(store: &PocketStoreHandle) -> Result<usize, BaseRelayError> {
    let records = store.scan_extra_records(TANGLE_GROUP_PROJECTION_TABLE)?;
    let count = records.len();
    for (key, value) in records {
        match projection_key_parts(&key)?.as_slice() {
            ["group", _] => {
                GroupState::from_json_bytes(&value)?;
            }
            ["member", _, _] => {
                MemberState::from_json_bytes(&value)?;
            }
            ["role", _, _] => {
                ProjectedRoleDefinition::from_json_bytes(&value)?;
            }
            ["tombstone", _] => {
                GroupTombstone::from_json_bytes(&value)?;
            }
            ["event_deletion", _] => {
                GroupEventDeletion::from_json_bytes(&value)?;
            }
            _ => {
                return Err(BaseRelayError::error(format!(
                    "unknown group projection extra-table key: {}",
                    projection_key_label(&key)
                )));
            }
        }
    }
    Ok(count)
}

fn validate_group_outbox_records(store: &PocketStoreHandle) -> Result<usize, BaseRelayError> {
    let records = store.scan_extra_records(TANGLE_GROUP_OUTBOX_TABLE)?;
    let count = records.len();
    for (_, value) in records {
        GroupOutboxRecord::from_json_bytes(&value)?;
    }
    Ok(count)
}

fn validate_group_checkpoint(
    store: &PocketStoreHandle,
) -> Result<GroupCheckpointStatus, BaseRelayError> {
    let Some(raw) =
        store.get_extra_record(TANGLE_GROUP_CHECKPOINT_TABLE, &projection_checkpoint_key())?
    else {
        return Ok(GroupCheckpointStatus::Missing);
    };
    let checkpoint = ProjectionCheckpoint::from_json_bytes(&raw)?;
    if checkpoint.matches_current_versions() {
        Ok(GroupCheckpointStatus::Current { checkpoint })
    } else {
        Ok(GroupCheckpointStatus::Stale { checkpoint })
    }
}

fn projection_rebuilt_at() -> Result<UnixTimestamp, BaseRelayError> {
    Ok(UnixTimestamp::new(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| {
                BaseRelayError::error(format!("system clock is before UNIX epoch: {error}"))
            })?
            .as_secs(),
    ))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalGroupEventScan {
    events: Vec<CanonicalGroupEvent>,
    scanned_events: usize,
    skipped_events: usize,
}

impl CanonicalGroupEventScan {
    pub fn events(&self) -> &[CanonicalGroupEvent] {
        &self.events
    }

    pub fn into_events(self) -> Vec<CanonicalGroupEvent> {
        self.events
    }

    pub fn scanned_events(&self) -> usize {
        self.scanned_events
    }

    pub fn skipped_events(&self) -> usize {
        self.skipped_events
    }
}

pub fn scan_canonical_group_events(
    store: &PocketStoreHandle,
    limits: GroupLimitsConfig,
) -> Result<CanonicalGroupEventScan, BaseRelayError> {
    scan_canonical_group_events_after(store, None, limits)
}

pub fn scan_canonical_group_events_after(
    store: &PocketStoreHandle,
    last_offset: Option<StoreOffset>,
    limits: GroupLimitsConfig,
) -> Result<CanonicalGroupEventScan, BaseRelayError> {
    let stored_events = store.scan_events_after(last_offset.map(StoreOffset::as_u64))?;
    let scanned_events = stored_events.len();
    let mut events = Vec::new();
    let mut skipped_events = 0;
    for stored in stored_events {
        match tangle_groups::classify_group_event(stored.event(), limits)? {
            GroupEventClass::NonGroup => skipped_events += 1,
            GroupEventClass::Normal { .. }
            | GroupEventClass::Moderation { .. }
            | GroupEventClass::RelayGeneratedSnapshot { .. } => {
                let store_offset = StoreOffset::new(stored.store_offset());
                events.push(CanonicalGroupEvent::new(stored.into_event(), store_offset));
            }
        }
    }
    Ok(CanonicalGroupEventScan {
        events,
        scanned_events,
        skipped_events,
    })
}

fn projection_key_parts(key: &[u8]) -> Result<Vec<&str>, BaseRelayError> {
    let key = str::from_utf8(key).map_err(|error| BaseRelayError::error(error.to_string()))?;
    Ok(key.split('\0').collect())
}

fn projection_key_label(key: &[u8]) -> String {
    String::from_utf8_lossy(key).replace('\0', "\\0")
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

fn generated_event_already_stored(
    store: &PocketStoreHandle,
    event_id: PocketEventId,
) -> Result<bool, BaseRelayError> {
    if store.event_by_id(event_id)?.is_some() {
        return Ok(true);
    }
    for stored in store.scan_events()? {
        if stored.event().id() == event_id {
            return Ok(true);
        }
    }
    Ok(false)
}

fn class_group_id(class: &GroupEventClass) -> Option<&GroupId> {
    match class {
        GroupEventClass::Moderation { group_id, .. }
        | GroupEventClass::Normal { group_id }
        | GroupEventClass::RelayGeneratedSnapshot { group_id, .. } => Some(group_id),
        GroupEventClass::NonGroup => None,
    }
}

fn delete_target_event_id(event: &(impl GroupEventView + ?Sized)) -> Result<EventId, GroupError> {
    let mut target = None;
    event.visit_tags(|tag| {
        if tag.first_value().is_none_or(|name| name != "e") {
            return Ok(());
        }
        let Some((_, value)) = tag.indexed_pair() else {
            return Err(GroupError::invalid(
                GroupErrorKind::MalformedTargetTag,
                "malformed e target tag",
            ));
        };
        target = Some(EventId::new(value).map_err(|reason| {
            GroupError::invalid(
                GroupErrorKind::MalformedTargetTag,
                format!("malformed e target tag: {reason}"),
            )
        })?);
        Ok(())
    })?;
    target.ok_or_else(|| {
        GroupError::invalid(GroupErrorKind::MissingTargetTag, "missing e target tag")
    })
}

#[cfg(test)]
mod tests {
    use super::{
        GeneratedGroupStorageEvent, GroupCheckpointStatus, GroupServiceHandle,
        scan_canonical_group_events, scan_canonical_group_events_after,
        validate_group_extra_tables,
    };
    use crate::pocket_conversion::tangle_event_to_pocket;
    use tangle_crypto::RelaySigner;
    use tangle_groups::{
        GroupGeneratedEventBuilder, GroupId, GroupRuntimeConfig, KIND_GROUP_METADATA,
        KIND_GROUP_PUT_USER, ProjectionCheckpoint, StoreOffset, projection_checkpoint_key,
    };
    use tangle_protocol::{Tag, UnixTimestamp};
    use tangle_store_pocket::{
        PocketEvent, PocketStoreConfig, PocketStoreHandle, PocketSyncPolicy,
        TANGLE_GROUP_CHECKPOINT_TABLE, TANGLE_GROUP_PROJECTION_TABLE,
    };
    use tangle_test_support::{
        FixtureKey, tangle_v2_event, tangle_v2_group_create_event, tangle_v2_group_event,
    };

    #[test]
    fn generated_group_storage_event_adapter_preserves_pocket_id_signature_and_tags() {
        let builder = GroupGeneratedEventBuilder::new(
            RelaySigner::from_secret_hex(&"7".repeat(64)).expect("key"),
        );
        let group_id = GroupId::new("PocketFarm").expect("group");
        let member = FixtureKey::Member.public_key();
        let payload = GroupGeneratedEventBuilder::join_accepted_payload(
            &group_id,
            &member,
            UnixTimestamp::new(1_714_124_433),
        );
        let generated = GeneratedGroupStorageEvent::build(&builder, &payload).expect("generated");

        assert_eq!(
            generated.event().id().as_hex_string(),
            generated.event_id().expect("event id").as_str()
        );
        assert_eq!(
            generated.event().pubkey().as_hex_string(),
            builder.relay_pubkey().as_str()
        );
        assert_eq!(
            u32::from(generated.event().kind().as_u16()),
            KIND_GROUP_PUT_USER
        );
        assert!(has_pocket_tag(generated.event(), &["h", "PocketFarm"]));
        assert!(has_pocket_tag(generated.event(), &["p", member.as_str()]));
        generated.event().verify().expect("signature");
    }

    #[test]
    fn group_service_from_disabled_config_is_absent() {
        let root = std::env::temp_dir().join(format!(
            "tangle-group-service-disabled-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let config = PocketStoreConfig::new(root.join("pocket"), PocketSyncPolicy::FlushOnShutdown)
            .expect("config");
        let store = PocketStoreHandle::open(&config).expect("store");

        assert!(
            GroupServiceHandle::from_config(&store, &GroupRuntimeConfig::disabled())
                .expect("service")
                .is_none()
        );
    }

    #[test]
    fn canonical_group_event_scanner_returns_group_events_with_offsets() {
        let root = std::env::temp_dir().join(format!(
            "tangle-canonical-group-scan-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let config = PocketStoreConfig::new(root.join("pocket"), PocketSyncPolicy::FlushOnShutdown)
            .expect("config");
        let store = PocketStoreHandle::open(&config).expect("store");
        let public =
            tangle_v2_event(FixtureKey::Member, 1, 1, Vec::new(), "public").expect("public");
        let normal =
            tangle_v2_group_event(FixtureKey::Member, "ScanFarm", 2, 1, "normal").expect("normal");
        let group =
            tangle_v2_group_create_event(FixtureKey::Owner, "ScanFarm", 3, &[]).expect("group");
        let generated = tangle_v2_event(
            FixtureKey::Owner,
            4,
            KIND_GROUP_METADATA.into(),
            vec![Tag::from_parts("d", &["ScanFarm"]).expect("d")],
            "",
        )
        .expect("generated");
        let public_offset = store
            .store_event(&tangle_event_to_pocket(&public).expect("public pocket"))
            .expect("store public");
        let normal_offset = store
            .store_event(&tangle_event_to_pocket(&normal).expect("normal pocket"))
            .expect("store normal");
        let group_offset = store
            .store_event(&tangle_event_to_pocket(&group).expect("group pocket"))
            .expect("store group");
        let generated_offset = store
            .store_event(&tangle_event_to_pocket(&generated).expect("generated pocket"))
            .expect("store generated");

        let scan = scan_canonical_group_events(&store, Default::default()).expect("scan");
        let after_public = scan_canonical_group_events_after(
            &store,
            Some(StoreOffset::new(public_offset)),
            Default::default(),
        )
        .expect("after public");

        assert_eq!(scan.scanned_events(), 4);
        assert_eq!(scan.skipped_events(), 1);
        assert_eq!(
            scan.events()
                .iter()
                .map(|event| event.event().id().as_hex_string())
                .collect::<Vec<_>>(),
            vec![
                normal.id().as_str().to_owned(),
                group.id().as_str().to_owned(),
                generated.id().as_str().to_owned(),
            ]
        );
        assert_eq!(
            scan.events()
                .iter()
                .map(|event| event.store_offset())
                .collect::<Vec<_>>(),
            vec![
                StoreOffset::new(normal_offset),
                StoreOffset::new(group_offset),
                StoreOffset::new(generated_offset),
            ]
        );
        assert_eq!(after_public.scanned_events(), 3);
        assert_eq!(after_public.skipped_events(), 0);
        assert_eq!(
            after_public
                .events()
                .iter()
                .map(|event| event.event().id().as_hex_string())
                .collect::<Vec<_>>(),
            vec![
                normal.id().as_str().to_owned(),
                group.id().as_str().to_owned(),
                generated.id().as_str().to_owned(),
            ]
        );

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn group_extra_table_validation_reports_checkpoint_version_status() {
        let (root, store) = test_store("tangle-group-extra-version");
        let missing = validate_group_extra_tables(&store).expect("missing");

        assert_eq!(missing.projection_records(), 0);
        assert_eq!(missing.outbox_records(), 0);
        assert_eq!(missing.checkpoint_status(), &GroupCheckpointStatus::Missing);
        assert!(missing.checkpoint_status().requires_rebuild());

        let current =
            ProjectionCheckpoint::current(Some(StoreOffset::new(42)), UnixTimestamp::new(100));
        store
            .put_extra_record(
                TANGLE_GROUP_CHECKPOINT_TABLE,
                &projection_checkpoint_key(),
                &current.to_json_bytes().expect("current bytes"),
            )
            .expect("put current");
        let current_validation = validate_group_extra_tables(&store).expect("current");
        assert_eq!(
            current_validation.checkpoint_status(),
            &GroupCheckpointStatus::Current {
                checkpoint: current.clone()
            }
        );
        assert!(!current_validation.checkpoint_status().requires_rebuild());
        assert_eq!(
            current_validation.checkpoint_status().checkpoint(),
            Some(&current)
        );

        let stale =
            ProjectionCheckpoint::new(0, 0, Some(StoreOffset::new(42)), UnixTimestamp::new(101));
        store
            .put_extra_record(
                TANGLE_GROUP_CHECKPOINT_TABLE,
                &projection_checkpoint_key(),
                &stale.to_json_bytes().expect("stale bytes"),
            )
            .expect("put stale");
        let stale_validation = validate_group_extra_tables(&store).expect("stale");
        assert_eq!(
            stale_validation.checkpoint_status(),
            &GroupCheckpointStatus::Stale {
                checkpoint: stale.clone()
            }
        );
        assert!(stale_validation.checkpoint_status().requires_rebuild());

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn group_extra_table_validation_rejects_bad_projection_schema() {
        let (unknown_root, unknown_store) = test_store("tangle-group-extra-unknown");
        unknown_store
            .put_extra_record(TANGLE_GROUP_PROJECTION_TABLE, b"unknown\0Farm", b"{}")
            .expect("put unknown");
        assert_eq!(
            validate_group_extra_tables(&unknown_store)
                .expect_err("unknown")
                .prefixed_message(),
            "error: unknown group projection extra-table key: unknown\\0Farm"
        );
        let _ = std::fs::remove_dir_all(unknown_root);

        let (corrupt_root, corrupt_store) = test_store("tangle-group-extra-corrupt");
        corrupt_store
            .put_extra_record(TANGLE_GROUP_PROJECTION_TABLE, b"group\0Farm", b"not-json")
            .expect("put corrupt");
        assert!(
            validate_group_extra_tables(&corrupt_store)
                .expect_err("corrupt")
                .prefixed_message()
                .contains("group state JSON decode failed")
        );
        let _ = std::fs::remove_dir_all(corrupt_root);
    }

    fn test_store(name: &str) -> (std::path::PathBuf, PocketStoreHandle) {
        let root = std::env::temp_dir().join(format!("{}-{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let config = PocketStoreConfig::new(root.join("pocket"), PocketSyncPolicy::FlushOnShutdown)
            .expect("config");
        let store = PocketStoreHandle::open(&config).expect("store");
        (root, store)
    }

    fn has_pocket_tag(event: &PocketEvent, expected: &[&str]) -> bool {
        event.tags().expect("tags").iter().any(|tag| {
            tag.map(|value| std::str::from_utf8(value).expect("utf8"))
                .eq(expected.iter().copied())
        })
    }
}
