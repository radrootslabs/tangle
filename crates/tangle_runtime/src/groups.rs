#![forbid(unsafe_code)]

use crate::{
    base_relay::{pocket_event_id, pocket_event_to_tangle, tangle_event_to_pocket},
    errors::BaseRelayError,
};
use std::str;
use tangle_crypto::RelaySigner;
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
        let mut service = Self {
            builder: GroupGeneratedEventBuilder::new(signer),
            authority: GroupAuthority::new(
                config.owner_pubkeys().iter().cloned(),
                config.admin_pubkeys().iter().cloned(),
            ),
            projection: load_group_projection(store)?,
            outbox: load_group_outbox(store)?,
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

    pub(crate) fn event_visible_to_auth(
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
    use super::GroupService;
    use tangle_groups::GroupRuntimeConfig;
    use tangle_store_pocket::{PocketStoreConfig, PocketStoreHandle, PocketSyncPolicy};

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
}
