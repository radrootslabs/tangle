#![forbid(unsafe_code)]

use crate::{
    errors::BaseRelayError,
    pocket_conversion::{pocket_event_id, pocket_event_to_tangle, tangle_event_to_pocket},
};
use std::{
    str,
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
    KIND_GROUP_MEMBERS, KIND_GROUP_PUT_USER, KIND_GROUP_REMOVE_USER, MemberState,
    ProjectedRoleDefinition, ProjectionCheckpoint, StoreOffset, event_deletion_key,
    event_view::GroupEventView, group_current_key, member_current_key, projection_checkpoint_key,
    rebuild_group_projection, role_current_key, tombstone_key,
};
use tangle_protocol::{Event, EventId, PublicKeyHex, UnixTimestamp};
use tangle_store_pocket::{
    PocketStoreHandle, TANGLE_GROUP_CHECKPOINT_TABLE, TANGLE_GROUP_OUTBOX_TABLE,
    TANGLE_GROUP_PROJECTION_TABLE,
};

pub(crate) struct GroupService {
    builder: GroupGeneratedEventBuilder,
    authority: GroupAuthority,
    projection: GroupProjection,
    outbox: GroupOutbox,
    policy: GroupPolicyConfig,
    limits: GroupLimitsConfig,
    member_snapshot_cap: u32,
}

impl GroupService {
    pub(crate) fn from_config(
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
        let mut service = Self {
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
        };
        service.materialize_outbox(store)?;
        store.sync()?;
        Ok(Some(service))
    }

    pub(crate) fn projection(&self) -> &GroupProjection {
        &self.projection
    }

    pub(crate) fn limits(&self) -> GroupLimitsConfig {
        self.limits
    }

    pub(crate) fn check_event(
        &self,
        store: &PocketStoreHandle,
        event: &Event,
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
        let target_class = tangle_groups::classify_group_event(&target, self.limits)?;
        if target_class.group_id() != Some(group_id) {
            return Err(GroupError::invalid(
                GroupErrorKind::MalformedTargetTag,
                "delete target event is not in group",
            ));
        }
        Ok(())
    }

    pub(crate) fn event_visible_to_auth(
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

    pub(crate) fn after_source_event_stored(
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
    Ok(GroupStorageState {
        projection: load_group_projection(projection_records, checkpoint)?,
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
                events.push(CanonicalGroupEvent::new(
                    pocket_event_to_tangle(stored.event())?,
                    StoreOffset::new(stored.store_offset()),
                ));
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
        if tag.values().first().is_none_or(|name| name != "e") {
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

#[cfg(test)]
mod tests {
    use super::{
        GroupCheckpointStatus, GroupService, scan_canonical_group_events,
        scan_canonical_group_events_after, validate_group_extra_tables,
    };
    use crate::pocket_conversion::tangle_event_to_pocket;
    use tangle_groups::{
        GroupRuntimeConfig, KIND_GROUP_METADATA, ProjectionCheckpoint, StoreOffset,
        projection_checkpoint_key,
    };
    use tangle_protocol::{Tag, UnixTimestamp};
    use tangle_store_pocket::{
        PocketStoreConfig, PocketStoreHandle, PocketSyncPolicy, TANGLE_GROUP_CHECKPOINT_TABLE,
        TANGLE_GROUP_PROJECTION_TABLE,
    };
    use tangle_test_support::{
        FixtureKey, tangle_v2_event, tangle_v2_group_create_event, tangle_v2_group_event,
    };

    #[test]
    fn group_service_from_disabled_config_is_absent() {
        let root = std::env::temp_dir().join(format!(
            "tangle-group-service-disabled-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let config = PocketStoreConfig::new(
            root.join("pocket"),
            1024 * 1024 * 1024,
            128,
            PocketSyncPolicy::FlushOnShutdown,
        )
        .expect("config");
        let store = PocketStoreHandle::open(&config).expect("store");

        assert!(
            GroupService::from_config(&store, &GroupRuntimeConfig::disabled())
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
        let config = PocketStoreConfig::new(
            root.join("pocket"),
            1024 * 1024 * 1024,
            128,
            PocketSyncPolicy::FlushOnShutdown,
        )
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
                .map(|event| event.event().id())
                .collect::<Vec<_>>(),
            vec![normal.id(), group.id(), generated.id()]
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
                .map(|event| event.event().id())
                .collect::<Vec<_>>(),
            vec![normal.id(), group.id(), generated.id()]
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
        let config = PocketStoreConfig::new(
            root.join("pocket"),
            1024 * 1024 * 1024,
            128,
            PocketSyncPolicy::FlushOnShutdown,
        )
        .expect("config");
        let store = PocketStoreHandle::open(&config).expect("store");
        (root, store)
    }
}
