use std::collections::{BTreeMap, BTreeSet};

use crate::{
    CapabilitySet, GroupError, GroupErrorKind, GroupEventClass, GroupId, GroupLimitsConfig,
    GroupMetadata, RoleDefinition, RoleName, SupportedKinds, classify_group_event,
    parse_group_metadata,
};
use serde::{Deserialize, Serialize};
use tangle_protocol::{Event, EventId, Kind, PublicKeyHex, Tag, UnixTimestamp};

pub const GROUP_PROJECTION_SCHEMA_VERSION: u32 = 1;
pub const GROUP_POLICY_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StoreOffset(u64);

impl StoreOffset {
    pub fn new(value: u64) -> Self {
        Self(value)
    }

    pub fn as_u64(self) -> u64 {
        self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProjectionOrderTuple {
    created_at: UnixTimestamp,
    event_id: EventId,
    store_offset: StoreOffset,
}

impl ProjectionOrderTuple {
    pub fn new(created_at: UnixTimestamp, event_id: EventId, store_offset: StoreOffset) -> Self {
        Self {
            created_at,
            event_id,
            store_offset,
        }
    }

    pub fn from_event(event: &Event, store_offset: StoreOffset) -> Self {
        Self::new(
            event.unsigned().created_at(),
            event.id().clone(),
            store_offset,
        )
    }

    pub fn created_at(&self) -> UnixTimestamp {
        self.created_at
    }

    pub fn event_id(&self) -> &EventId {
        &self.event_id
    }

    pub fn store_offset(&self) -> StoreOffset {
        self.store_offset
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupLifecycleState {
    Active,
    Deleted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemberStatus {
    Member,
    Removed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupSnapshotIds {
    metadata: Option<EventId>,
    admins: Option<EventId>,
    members: Option<EventId>,
    roles: Option<EventId>,
    state_39004: Option<EventId>,
}

impl GroupSnapshotIds {
    pub fn empty() -> Self {
        Self {
            metadata: None,
            admins: None,
            members: None,
            roles: None,
            state_39004: None,
        }
    }

    pub fn metadata(&self) -> Option<&EventId> {
        self.metadata.as_ref()
    }

    pub fn admins(&self) -> Option<&EventId> {
        self.admins.as_ref()
    }

    pub fn members(&self) -> Option<&EventId> {
        self.members.as_ref()
    }

    pub fn roles(&self) -> Option<&EventId> {
        self.roles.as_ref()
    }

    pub fn state_39004(&self) -> Option<&EventId> {
        self.state_39004.as_ref()
    }

    fn set_for_kind(&mut self, kind: Kind, event_id: EventId) {
        match kind.as_u32() {
            crate::KIND_GROUP_METADATA => self.metadata = Some(event_id),
            crate::KIND_GROUP_ADMINS => self.admins = Some(event_id),
            crate::KIND_GROUP_MEMBERS => self.members = Some(event_id),
            crate::KIND_GROUP_ROLES => self.roles = Some(event_id),
            crate::KIND_GROUP_STATE_39004 => self.state_39004 = Some(event_id),
            _ => {}
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupState {
    id: GroupId,
    lifecycle: GroupLifecycleState,
    metadata: GroupMetadata,
    created_by: PublicKeyHex,
    created_event_id: EventId,
    created_tuple: ProjectionOrderTuple,
    metadata_tuple: ProjectionOrderTuple,
    deleted_at: Option<UnixTimestamp>,
    delete_event_id: Option<EventId>,
    deleted_tuple: Option<ProjectionOrderTuple>,
    snapshots: GroupSnapshotIds,
}

impl GroupState {
    pub fn new(
        id: GroupId,
        metadata: GroupMetadata,
        created_by: PublicKeyHex,
        created_event_id: EventId,
        created_tuple: ProjectionOrderTuple,
    ) -> Self {
        Self {
            id,
            lifecycle: GroupLifecycleState::Active,
            metadata,
            created_by,
            created_event_id,
            metadata_tuple: created_tuple.clone(),
            created_tuple,
            deleted_at: None,
            delete_event_id: None,
            deleted_tuple: None,
            snapshots: GroupSnapshotIds::empty(),
        }
    }

    pub fn id(&self) -> &GroupId {
        &self.id
    }

    pub fn lifecycle(&self) -> GroupLifecycleState {
        self.lifecycle
    }

    pub fn metadata(&self) -> &GroupMetadata {
        &self.metadata
    }

    pub fn created_by(&self) -> &PublicKeyHex {
        &self.created_by
    }

    pub fn created_event_id(&self) -> &EventId {
        &self.created_event_id
    }

    pub fn created_tuple(&self) -> &ProjectionOrderTuple {
        &self.created_tuple
    }

    pub fn metadata_tuple(&self) -> &ProjectionOrderTuple {
        &self.metadata_tuple
    }

    pub fn deleted_at(&self) -> Option<UnixTimestamp> {
        self.deleted_at
    }

    pub fn delete_event_id(&self) -> Option<&EventId> {
        self.delete_event_id.as_ref()
    }

    pub fn snapshots(&self) -> &GroupSnapshotIds {
        &self.snapshots
    }

    pub fn to_json_bytes(&self) -> Result<Vec<u8>, GroupError> {
        serde_json::to_vec(&GroupStateDocument::from_state(self)).map_err(|error| {
            GroupError::internal(format!("group state JSON encode failed: {error}"))
        })
    }

    pub fn from_json_bytes(raw: &[u8]) -> Result<Self, GroupError> {
        let document = serde_json::from_slice::<GroupStateDocument>(raw).map_err(|error| {
            GroupError::internal(format!("group state JSON decode failed: {error}"))
        })?;
        document.into_state()
    }

    fn update_metadata(&mut self, metadata: GroupMetadata, tuple: ProjectionOrderTuple) {
        if tuple >= self.metadata_tuple {
            self.metadata = metadata;
            self.metadata_tuple = tuple;
        }
    }

    fn mark_deleted(
        &mut self,
        deleted_at: UnixTimestamp,
        delete_event_id: EventId,
        tuple: ProjectionOrderTuple,
    ) {
        if self
            .deleted_tuple
            .as_ref()
            .is_none_or(|current| &tuple >= current)
        {
            self.lifecycle = GroupLifecycleState::Deleted;
            self.deleted_at = Some(deleted_at);
            self.delete_event_id = Some(delete_event_id);
            self.deleted_tuple = Some(tuple);
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberState {
    pubkey: PublicKeyHex,
    status: MemberStatus,
    roles: BTreeSet<RoleName>,
    last_event_id: EventId,
    last_tuple: ProjectionOrderTuple,
}

impl MemberState {
    pub fn new(
        pubkey: PublicKeyHex,
        status: MemberStatus,
        roles: BTreeSet<RoleName>,
        last_event_id: EventId,
        last_tuple: ProjectionOrderTuple,
    ) -> Self {
        Self {
            pubkey,
            status,
            roles,
            last_event_id,
            last_tuple,
        }
    }

    pub fn pubkey(&self) -> &PublicKeyHex {
        &self.pubkey
    }

    pub fn status(&self) -> MemberStatus {
        self.status
    }

    pub fn roles(&self) -> &BTreeSet<RoleName> {
        &self.roles
    }

    pub fn last_event_id(&self) -> &EventId {
        &self.last_event_id
    }

    pub fn last_tuple(&self) -> &ProjectionOrderTuple {
        &self.last_tuple
    }

    pub fn to_json_bytes(&self) -> Result<Vec<u8>, GroupError> {
        serde_json::to_vec(&MemberStateDocument::from_state(self)).map_err(|error| {
            GroupError::internal(format!("member state JSON encode failed: {error}"))
        })
    }

    pub fn from_json_bytes(raw: &[u8]) -> Result<Self, GroupError> {
        let document = serde_json::from_slice::<MemberStateDocument>(raw).map_err(|error| {
            GroupError::internal(format!("member state JSON decode failed: {error}"))
        })?;
        document.into_state()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectedRoleDefinition {
    definition: RoleDefinition,
    last_event_id: EventId,
    last_tuple: ProjectionOrderTuple,
}

impl ProjectedRoleDefinition {
    pub fn new(
        definition: RoleDefinition,
        last_event_id: EventId,
        last_tuple: ProjectionOrderTuple,
    ) -> Self {
        Self {
            definition,
            last_event_id,
            last_tuple,
        }
    }

    pub fn definition(&self) -> &RoleDefinition {
        &self.definition
    }

    pub fn last_event_id(&self) -> &EventId {
        &self.last_event_id
    }

    pub fn last_tuple(&self) -> &ProjectionOrderTuple {
        &self.last_tuple
    }

    pub fn to_json_bytes(&self) -> Result<Vec<u8>, GroupError> {
        serde_json::to_vec(&ProjectedRoleDefinitionDocument::from_role(self)).map_err(|error| {
            GroupError::internal(format!("role state JSON encode failed: {error}"))
        })
    }

    pub fn from_json_bytes(raw: &[u8]) -> Result<Self, GroupError> {
        let document =
            serde_json::from_slice::<ProjectedRoleDefinitionDocument>(raw).map_err(|error| {
                GroupError::internal(format!("role state JSON decode failed: {error}"))
            })?;
        document.into_role()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupTombstone {
    group_id: GroupId,
    delete_event_id: EventId,
    deleted_at: UnixTimestamp,
    deleted_by: PublicKeyHex,
    last_tuple: ProjectionOrderTuple,
}

impl GroupTombstone {
    pub fn new(
        group_id: GroupId,
        delete_event_id: EventId,
        deleted_at: UnixTimestamp,
        deleted_by: PublicKeyHex,
        last_tuple: ProjectionOrderTuple,
    ) -> Self {
        Self {
            group_id,
            delete_event_id,
            deleted_at,
            deleted_by,
            last_tuple,
        }
    }

    pub fn group_id(&self) -> &GroupId {
        &self.group_id
    }

    pub fn delete_event_id(&self) -> &EventId {
        &self.delete_event_id
    }

    pub fn deleted_at(&self) -> UnixTimestamp {
        self.deleted_at
    }

    pub fn deleted_by(&self) -> &PublicKeyHex {
        &self.deleted_by
    }

    pub fn last_tuple(&self) -> &ProjectionOrderTuple {
        &self.last_tuple
    }

    pub fn to_json_bytes(&self) -> Result<Vec<u8>, GroupError> {
        serde_json::to_vec(&GroupTombstoneDocument::from_tombstone(self))
            .map_err(|error| GroupError::internal(format!("tombstone JSON encode failed: {error}")))
    }

    pub fn from_json_bytes(raw: &[u8]) -> Result<Self, GroupError> {
        let document = serde_json::from_slice::<GroupTombstoneDocument>(raw).map_err(|error| {
            GroupError::internal(format!("tombstone JSON decode failed: {error}"))
        })?;
        document.into_tombstone()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupEventDeletion {
    group_id: GroupId,
    target_event_id: EventId,
    delete_event_id: EventId,
    deleted_at: UnixTimestamp,
    deleted_by: PublicKeyHex,
    last_tuple: ProjectionOrderTuple,
}

impl GroupEventDeletion {
    pub fn new(
        group_id: GroupId,
        target_event_id: EventId,
        delete_event_id: EventId,
        deleted_at: UnixTimestamp,
        deleted_by: PublicKeyHex,
        last_tuple: ProjectionOrderTuple,
    ) -> Self {
        Self {
            group_id,
            target_event_id,
            delete_event_id,
            deleted_at,
            deleted_by,
            last_tuple,
        }
    }

    pub fn group_id(&self) -> &GroupId {
        &self.group_id
    }

    pub fn target_event_id(&self) -> &EventId {
        &self.target_event_id
    }

    pub fn delete_event_id(&self) -> &EventId {
        &self.delete_event_id
    }

    pub fn deleted_at(&self) -> UnixTimestamp {
        self.deleted_at
    }

    pub fn deleted_by(&self) -> &PublicKeyHex {
        &self.deleted_by
    }

    pub fn last_tuple(&self) -> &ProjectionOrderTuple {
        &self.last_tuple
    }

    pub fn to_json_bytes(&self) -> Result<Vec<u8>, GroupError> {
        serde_json::to_vec(&GroupEventDeletionDocument::from_deletion(self)).map_err(|error| {
            GroupError::internal(format!("event deletion JSON encode failed: {error}"))
        })
    }

    pub fn from_json_bytes(raw: &[u8]) -> Result<Self, GroupError> {
        let document =
            serde_json::from_slice::<GroupEventDeletionDocument>(raw).map_err(|error| {
                GroupError::internal(format!("event deletion JSON decode failed: {error}"))
            })?;
        document.into_deletion()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectionCheckpoint {
    projection_version: u32,
    policy_version: u32,
    last_offset: Option<StoreOffset>,
    rebuilt_at: UnixTimestamp,
}

impl ProjectionCheckpoint {
    pub fn new(
        projection_version: u32,
        policy_version: u32,
        last_offset: Option<StoreOffset>,
        rebuilt_at: UnixTimestamp,
    ) -> Self {
        Self {
            projection_version,
            policy_version,
            last_offset,
            rebuilt_at,
        }
    }

    pub fn current(last_offset: Option<StoreOffset>, rebuilt_at: UnixTimestamp) -> Self {
        Self::new(
            GROUP_PROJECTION_SCHEMA_VERSION,
            GROUP_POLICY_VERSION,
            last_offset,
            rebuilt_at,
        )
    }

    pub fn projection_version(&self) -> u32 {
        self.projection_version
    }

    pub fn policy_version(&self) -> u32 {
        self.policy_version
    }

    pub fn last_offset(&self) -> Option<StoreOffset> {
        self.last_offset
    }

    pub fn rebuilt_at(&self) -> UnixTimestamp {
        self.rebuilt_at
    }

    pub fn matches_current_versions(&self) -> bool {
        self.projection_version == GROUP_PROJECTION_SCHEMA_VERSION
            && self.policy_version == GROUP_POLICY_VERSION
    }

    pub fn to_json_bytes(&self) -> Result<Vec<u8>, GroupError> {
        serde_json::to_vec(&ProjectionCheckpointDocument::from_checkpoint(self)).map_err(|error| {
            GroupError::internal(format!("checkpoint JSON encode failed: {error}"))
        })
    }

    pub fn from_json_bytes(raw: &[u8]) -> Result<Self, GroupError> {
        let document =
            serde_json::from_slice::<ProjectionCheckpointDocument>(raw).map_err(|error| {
                GroupError::internal(format!("checkpoint JSON decode failed: {error}"))
            })?;
        Ok(document.into_checkpoint())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GroupProjection {
    groups: BTreeMap<GroupId, GroupState>,
    members: BTreeMap<(GroupId, PublicKeyHex), MemberState>,
    roles: BTreeMap<(GroupId, RoleName), ProjectedRoleDefinition>,
    tombstones: BTreeMap<GroupId, GroupTombstone>,
    event_deletions: BTreeMap<EventId, GroupEventDeletion>,
    checkpoint: Option<ProjectionCheckpoint>,
}

impl GroupProjection {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn group(&self, group_id: &GroupId) -> Option<&GroupState> {
        self.groups.get(group_id)
    }

    pub fn member(&self, group_id: &GroupId, pubkey: &PublicKeyHex) -> Option<&MemberState> {
        self.members.get(&(group_id.clone(), pubkey.clone()))
    }

    pub fn role(
        &self,
        group_id: &GroupId,
        role_name: &RoleName,
    ) -> Option<&ProjectedRoleDefinition> {
        self.roles.get(&(group_id.clone(), role_name.clone()))
    }

    pub fn tombstone(&self, group_id: &GroupId) -> Option<&GroupTombstone> {
        self.tombstones.get(group_id)
    }

    pub fn event_deletion(&self, event_id: &EventId) -> Option<&GroupEventDeletion> {
        self.event_deletions.get(event_id)
    }

    pub fn groups(&self) -> &BTreeMap<GroupId, GroupState> {
        &self.groups
    }

    pub fn members(&self) -> &BTreeMap<(GroupId, PublicKeyHex), MemberState> {
        &self.members
    }

    pub fn roles(&self) -> &BTreeMap<(GroupId, RoleName), ProjectedRoleDefinition> {
        &self.roles
    }

    pub fn tombstones(&self) -> &BTreeMap<GroupId, GroupTombstone> {
        &self.tombstones
    }

    pub fn event_deletions(&self) -> &BTreeMap<EventId, GroupEventDeletion> {
        &self.event_deletions
    }

    pub fn checkpoint(&self) -> Option<&ProjectionCheckpoint> {
        self.checkpoint.as_ref()
    }

    pub fn set_checkpoint(&mut self, checkpoint: ProjectionCheckpoint) {
        self.checkpoint = Some(checkpoint);
    }

    pub fn put_group(&mut self, state: GroupState) {
        self.groups.insert(state.id().clone(), state);
    }

    pub fn put_member(&mut self, group_id: GroupId, state: MemberState) {
        let key = (group_id, state.pubkey().clone());
        if self
            .members
            .get(&key)
            .is_none_or(|current| state.last_tuple() >= current.last_tuple())
        {
            self.members.insert(key, state);
        }
    }

    pub fn put_role(&mut self, group_id: GroupId, role: ProjectedRoleDefinition) {
        let key = (group_id, role.definition().name().clone());
        if self
            .roles
            .get(&key)
            .is_none_or(|current| role.last_tuple() >= current.last_tuple())
        {
            self.roles.insert(key, role);
        }
    }

    pub fn put_tombstone(&mut self, tombstone: GroupTombstone) {
        if self
            .tombstones
            .get(tombstone.group_id())
            .is_none_or(|current| tombstone.last_tuple() >= current.last_tuple())
        {
            self.tombstones
                .insert(tombstone.group_id().clone(), tombstone);
        }
    }

    pub fn put_event_deletion(&mut self, deletion: GroupEventDeletion) {
        if self
            .event_deletions
            .get(deletion.target_event_id())
            .is_none_or(|current| deletion.last_tuple() >= current.last_tuple())
        {
            self.event_deletions
                .insert(deletion.target_event_id().clone(), deletion);
        }
    }

    pub fn apply_canonical_event(
        &mut self,
        event: &Event,
        store_offset: StoreOffset,
        limits: GroupLimitsConfig,
    ) -> Result<ProjectionApplyOutcome, GroupError> {
        let class = classify_group_event(event, limits)?;
        let tuple = ProjectionOrderTuple::from_event(event, store_offset);
        match class {
            GroupEventClass::NonGroup => Ok(ProjectionApplyOutcome::Skipped),
            GroupEventClass::Normal { .. } => Ok(ProjectionApplyOutcome::Ignored),
            GroupEventClass::Moderation { group_id, .. } => {
                self.apply_moderation_event(group_id, event, tuple, limits)
            }
            GroupEventClass::RelayGeneratedSnapshot { kind, group_id } => {
                self.apply_snapshot_event(group_id, kind, event, tuple, limits)
            }
        }
    }

    fn apply_moderation_event(
        &mut self,
        group_id: GroupId,
        event: &Event,
        tuple: ProjectionOrderTuple,
        limits: GroupLimitsConfig,
    ) -> Result<ProjectionApplyOutcome, GroupError> {
        match event.unsigned().kind().as_u32() {
            crate::KIND_GROUP_CREATE_GROUP => {
                let state = GroupState::new(
                    group_id.clone(),
                    parse_group_metadata(event.unsigned().tags(), limits)?,
                    event.unsigned().pubkey().clone(),
                    event.id().clone(),
                    tuple,
                );
                if self
                    .group(&group_id)
                    .is_none_or(|current| state.created_tuple() >= current.created_tuple())
                {
                    self.put_group(state);
                    Ok(ProjectionApplyOutcome::Applied)
                } else {
                    Ok(ProjectionApplyOutcome::Ignored)
                }
            }
            crate::KIND_GROUP_EDIT_METADATA => {
                let Some(group) = self.groups.get_mut(&group_id) else {
                    return Ok(ProjectionApplyOutcome::Ignored);
                };
                group.update_metadata(
                    parse_group_metadata(event.unsigned().tags(), limits)?,
                    tuple,
                );
                Ok(ProjectionApplyOutcome::Applied)
            }
            crate::KIND_GROUP_PUT_USER => {
                self.apply_member_status(group_id, event, tuple, MemberStatus::Member)
            }
            crate::KIND_GROUP_REMOVE_USER => {
                self.apply_member_status(group_id, event, tuple, MemberStatus::Removed)
            }
            crate::KIND_GROUP_DELETE_EVENT => {
                let target_event_id = EventId::new(first_tag_value(event.unsigned().tags(), "e")?)
                    .map_err(|reason| {
                        GroupError::invalid(
                            GroupErrorKind::MalformedTargetTag,
                            format!("malformed e target tag: {reason}"),
                        )
                    })?;
                let deletion = GroupEventDeletion::new(
                    group_id,
                    target_event_id,
                    event.id().clone(),
                    event.unsigned().created_at(),
                    event.unsigned().pubkey().clone(),
                    tuple,
                );
                self.put_event_deletion(deletion);
                Ok(ProjectionApplyOutcome::Applied)
            }
            crate::KIND_GROUP_DELETE_GROUP => {
                let tombstone = GroupTombstone::new(
                    group_id.clone(),
                    event.id().clone(),
                    event.unsigned().created_at(),
                    event.unsigned().pubkey().clone(),
                    tuple.clone(),
                );
                if let Some(group) = self.groups.get_mut(&group_id) {
                    group.mark_deleted(
                        event.unsigned().created_at(),
                        event.id().clone(),
                        tuple.clone(),
                    );
                }
                if self
                    .tombstones
                    .get(&group_id)
                    .is_none_or(|current| &tuple >= current.last_tuple())
                {
                    self.tombstones.insert(group_id, tombstone);
                    Ok(ProjectionApplyOutcome::Applied)
                } else {
                    Ok(ProjectionApplyOutcome::Ignored)
                }
            }
            _ => Ok(ProjectionApplyOutcome::Ignored),
        }
    }

    fn apply_snapshot_event(
        &mut self,
        group_id: GroupId,
        kind: Kind,
        event: &Event,
        tuple: ProjectionOrderTuple,
        limits: GroupLimitsConfig,
    ) -> Result<ProjectionApplyOutcome, GroupError> {
        if kind.as_u32() == crate::KIND_GROUP_METADATA {
            let metadata = parse_group_metadata(event.unsigned().tags(), limits)?;
            if let Some(group) = self.groups.get_mut(&group_id) {
                group.update_metadata(metadata, tuple.clone());
                group.snapshots.set_for_kind(kind, event.id().clone());
            } else {
                let mut state = GroupState::new(
                    group_id.clone(),
                    metadata,
                    event.unsigned().pubkey().clone(),
                    event.id().clone(),
                    tuple.clone(),
                );
                state.snapshots.set_for_kind(kind, event.id().clone());
                self.put_group(state);
            }
        } else if let Some(group) = self.groups.get_mut(&group_id) {
            group.snapshots.set_for_kind(kind, event.id().clone());
        }
        Ok(ProjectionApplyOutcome::Applied)
    }

    fn apply_member_status(
        &mut self,
        group_id: GroupId,
        event: &Event,
        tuple: ProjectionOrderTuple,
        status: MemberStatus,
    ) -> Result<ProjectionApplyOutcome, GroupError> {
        let target = first_tag_value(event.unsigned().tags(), "p")?;
        let pubkey = PublicKeyHex::new(target).map_err(|reason| {
            GroupError::invalid(
                GroupErrorKind::MalformedTargetTag,
                format!("malformed p target tag: {reason}"),
            )
        })?;
        let roles = role_tags(event.unsigned().tags())?;
        let state = MemberState::new(pubkey, status, roles, event.id().clone(), tuple);
        self.put_member(group_id, state);
        Ok(ProjectionApplyOutcome::Applied)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProjectionApplyOutcome {
    Applied,
    Ignored,
    Skipped,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalGroupEvent {
    event: Event,
    store_offset: StoreOffset,
}

impl CanonicalGroupEvent {
    pub fn new(event: Event, store_offset: StoreOffset) -> Self {
        Self {
            event,
            store_offset,
        }
    }

    pub fn event(&self) -> &Event {
        &self.event
    }

    pub fn store_offset(&self) -> StoreOffset {
        self.store_offset
    }

    pub fn tuple(&self) -> ProjectionOrderTuple {
        ProjectionOrderTuple::from_event(&self.event, self.store_offset)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectionRebuildReport {
    projection: GroupProjection,
    applied_events: usize,
    ignored_events: usize,
    skipped_events: usize,
    last_offset: Option<StoreOffset>,
}

impl ProjectionRebuildReport {
    pub fn projection(&self) -> &GroupProjection {
        &self.projection
    }

    pub fn into_projection(self) -> GroupProjection {
        self.projection
    }

    pub fn applied_events(&self) -> usize {
        self.applied_events
    }

    pub fn ignored_events(&self) -> usize {
        self.ignored_events
    }

    pub fn skipped_events(&self) -> usize {
        self.skipped_events
    }

    pub fn last_offset(&self) -> Option<StoreOffset> {
        self.last_offset
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GroupRecoveryReadiness {
    Ready,
    FailedClosed { reason: String },
}

impl GroupRecoveryReadiness {
    pub fn from_projection_result<T>(result: &Result<T, GroupError>) -> Self {
        match result {
            Ok(_) => Self::Ready,
            Err(error) => Self::FailedClosed {
                reason: error.prefixed_message(),
            },
        }
    }
}

pub fn rebuild_group_projection(
    events: impl IntoIterator<Item = CanonicalGroupEvent>,
    limits: GroupLimitsConfig,
    rebuilt_at: UnixTimestamp,
) -> Result<ProjectionRebuildReport, GroupError> {
    let mut events = events.into_iter().collect::<Vec<_>>();
    events.sort_by_key(CanonicalGroupEvent::tuple);
    let mut projection = GroupProjection::new();
    let mut applied_events = 0;
    let mut ignored_events = 0;
    let mut skipped_events = 0;
    let mut last_offset = None;
    for item in events {
        last_offset = Some(item.store_offset());
        match projection.apply_canonical_event(item.event(), item.store_offset(), limits)? {
            ProjectionApplyOutcome::Applied => applied_events += 1,
            ProjectionApplyOutcome::Ignored => ignored_events += 1,
            ProjectionApplyOutcome::Skipped => skipped_events += 1,
        }
    }
    projection.set_checkpoint(ProjectionCheckpoint::current(last_offset, rebuilt_at));
    Ok(ProjectionRebuildReport {
        projection,
        applied_events,
        ignored_events,
        skipped_events,
        last_offset,
    })
}

pub fn group_current_key(group_id: &GroupId) -> Vec<u8> {
    prefixed_key("group", group_id.as_str(), None)
}

pub fn member_current_key(group_id: &GroupId, pubkey: &PublicKeyHex) -> Vec<u8> {
    prefixed_key("member", group_id.as_str(), Some(pubkey.as_str()))
}

pub fn role_current_key(group_id: &GroupId, role_name: &RoleName) -> Vec<u8> {
    prefixed_key("role", group_id.as_str(), Some(role_name.as_str()))
}

pub fn tombstone_key(group_id: &GroupId) -> Vec<u8> {
    prefixed_key("tombstone", group_id.as_str(), None)
}

pub fn event_deletion_key(event_id: &EventId) -> Vec<u8> {
    prefixed_key("event_deletion", event_id.as_str(), None)
}

pub fn projection_checkpoint_key() -> Vec<u8> {
    b"checkpoint\0groups".to_vec()
}

fn prefixed_key(prefix: &str, first: &str, second: Option<&str>) -> Vec<u8> {
    let mut key = Vec::new();
    key.extend_from_slice(prefix.as_bytes());
    key.push(0);
    key.extend_from_slice(first.as_bytes());
    if let Some(second) = second {
        key.push(0);
        key.extend_from_slice(second.as_bytes());
    }
    key
}

fn first_tag_value<'a>(tags: &'a [Tag], name: &str) -> Result<&'a str, GroupError> {
    for tag in tags {
        if !tag
            .values()
            .first()
            .is_some_and(|tag_name| tag_name == name)
        {
            continue;
        }
        let Some((_, value)) = tag.indexed_pair() else {
            return Err(GroupError::invalid(
                GroupErrorKind::MalformedTargetTag,
                format!("malformed {name} target tag"),
            ));
        };
        return Ok(value);
    }
    Err(GroupError::invalid(
        GroupErrorKind::MissingTargetTag,
        format!("missing {name} target tag"),
    ))
}

fn role_tags(tags: &[Tag]) -> Result<BTreeSet<RoleName>, GroupError> {
    let mut roles = BTreeSet::new();
    for tag in tags {
        if tag.values().first().is_some_and(|name| name == "role")
            && let Some(value) = tag.values().get(1)
        {
            roles.insert(RoleName::new(value)?);
        }
    }
    Ok(roles)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TupleDocument {
    created_at: u64,
    event_id: String,
    store_offset: u64,
}

impl TupleDocument {
    fn from_tuple(tuple: &ProjectionOrderTuple) -> Self {
        Self {
            created_at: tuple.created_at().as_u64(),
            event_id: tuple.event_id().as_str().to_owned(),
            store_offset: tuple.store_offset().as_u64(),
        }
    }

    fn into_tuple(self) -> Result<ProjectionOrderTuple, GroupError> {
        Ok(ProjectionOrderTuple::new(
            UnixTimestamp::new(self.created_at),
            EventId::new(&self.event_id).map_err(GroupError::internal)?,
            StoreOffset::new(self.store_offset),
        ))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MetadataDocument {
    name: Option<String>,
    picture: Option<String>,
    about: Option<String>,
    private: bool,
    restricted: bool,
    hidden: bool,
    closed: bool,
    supported_kinds: SupportedKindsDocument,
}

impl MetadataDocument {
    fn from_metadata(metadata: &GroupMetadata) -> Self {
        Self {
            name: metadata.name().map(str::to_owned),
            picture: metadata.picture().map(str::to_owned),
            about: metadata.about().map(str::to_owned),
            private: metadata.private(),
            restricted: metadata.restricted(),
            hidden: metadata.hidden(),
            closed: metadata.closed(),
            supported_kinds: SupportedKindsDocument::from_supported(metadata.supported_kinds()),
        }
    }

    fn into_metadata(self) -> Result<GroupMetadata, GroupError> {
        Ok(GroupMetadata::new(
            self.name,
            self.picture,
            self.about,
            self.private,
            self.restricted,
            self.hidden,
            self.closed,
            self.supported_kinds.into_supported()?,
        ))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "mode", content = "kinds")]
enum SupportedKindsDocument {
    UnspecifiedAll,
    None,
    Only(Vec<u32>),
}

impl SupportedKindsDocument {
    fn from_supported(value: &SupportedKinds) -> Self {
        match value {
            SupportedKinds::UnspecifiedAll => Self::UnspecifiedAll,
            SupportedKinds::None => Self::None,
            SupportedKinds::Only(kinds) => {
                Self::Only(kinds.iter().map(|kind| kind.as_u32()).collect())
            }
        }
    }

    fn into_supported(self) -> Result<SupportedKinds, GroupError> {
        match self {
            Self::UnspecifiedAll => Ok(SupportedKinds::UnspecifiedAll),
            Self::None => Ok(SupportedKinds::None),
            Self::Only(values) => values
                .into_iter()
                .map(|value| {
                    Kind::new(value.into()).map_err(|reason| {
                        GroupError::invalid(
                            GroupErrorKind::UnsupportedGroupKind,
                            format!("supported kind is invalid: {reason}"),
                        )
                    })
                })
                .collect::<Result<BTreeSet<_>, _>>()
                .map(SupportedKinds::Only),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SnapshotIdsDocument {
    metadata: Option<String>,
    admins: Option<String>,
    members: Option<String>,
    roles: Option<String>,
    state_39004: Option<String>,
}

impl SnapshotIdsDocument {
    fn from_snapshots(value: &GroupSnapshotIds) -> Self {
        Self {
            metadata: value.metadata().map(|id| id.as_str().to_owned()),
            admins: value.admins().map(|id| id.as_str().to_owned()),
            members: value.members().map(|id| id.as_str().to_owned()),
            roles: value.roles().map(|id| id.as_str().to_owned()),
            state_39004: value.state_39004().map(|id| id.as_str().to_owned()),
        }
    }

    fn into_snapshots(self) -> Result<GroupSnapshotIds, GroupError> {
        Ok(GroupSnapshotIds {
            metadata: parse_optional_event_id(self.metadata)?,
            admins: parse_optional_event_id(self.admins)?,
            members: parse_optional_event_id(self.members)?,
            roles: parse_optional_event_id(self.roles)?,
            state_39004: parse_optional_event_id(self.state_39004)?,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GroupStateDocument {
    id: String,
    lifecycle: String,
    metadata: MetadataDocument,
    created_by: String,
    created_event_id: String,
    created_tuple: TupleDocument,
    metadata_tuple: TupleDocument,
    deleted_at: Option<u64>,
    delete_event_id: Option<String>,
    deleted_tuple: Option<TupleDocument>,
    snapshots: SnapshotIdsDocument,
}

impl GroupStateDocument {
    fn from_state(state: &GroupState) -> Self {
        Self {
            id: state.id().as_str().to_owned(),
            lifecycle: lifecycle_label(state.lifecycle()),
            metadata: MetadataDocument::from_metadata(state.metadata()),
            created_by: state.created_by().as_str().to_owned(),
            created_event_id: state.created_event_id().as_str().to_owned(),
            created_tuple: TupleDocument::from_tuple(state.created_tuple()),
            metadata_tuple: TupleDocument::from_tuple(state.metadata_tuple()),
            deleted_at: state.deleted_at().map(UnixTimestamp::as_u64),
            delete_event_id: state.delete_event_id().map(|id| id.as_str().to_owned()),
            deleted_tuple: state.deleted_tuple.as_ref().map(TupleDocument::from_tuple),
            snapshots: SnapshotIdsDocument::from_snapshots(state.snapshots()),
        }
    }

    fn into_state(self) -> Result<GroupState, GroupError> {
        Ok(GroupState {
            id: GroupId::new(&self.id)?,
            lifecycle: parse_lifecycle(&self.lifecycle)?,
            metadata: self.metadata.into_metadata()?,
            created_by: PublicKeyHex::new(&self.created_by).map_err(GroupError::internal)?,
            created_event_id: EventId::new(&self.created_event_id).map_err(GroupError::internal)?,
            created_tuple: self.created_tuple.into_tuple()?,
            metadata_tuple: self.metadata_tuple.into_tuple()?,
            deleted_at: self.deleted_at.map(UnixTimestamp::new),
            delete_event_id: parse_optional_event_id(self.delete_event_id)?,
            deleted_tuple: self
                .deleted_tuple
                .map(TupleDocument::into_tuple)
                .transpose()?,
            snapshots: self.snapshots.into_snapshots()?,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MemberStateDocument {
    pubkey: String,
    status: String,
    roles: Vec<String>,
    last_event_id: String,
    last_tuple: TupleDocument,
}

impl MemberStateDocument {
    fn from_state(state: &MemberState) -> Self {
        Self {
            pubkey: state.pubkey().as_str().to_owned(),
            status: member_status_label(state.status()),
            roles: state
                .roles()
                .iter()
                .map(|role| role.as_str().to_owned())
                .collect(),
            last_event_id: state.last_event_id().as_str().to_owned(),
            last_tuple: TupleDocument::from_tuple(state.last_tuple()),
        }
    }

    fn into_state(self) -> Result<MemberState, GroupError> {
        Ok(MemberState::new(
            PublicKeyHex::new(&self.pubkey).map_err(GroupError::internal)?,
            parse_member_status(&self.status)?,
            self.roles
                .into_iter()
                .map(|role| RoleName::new(&role))
                .collect::<Result<BTreeSet<_>, _>>()?,
            EventId::new(&self.last_event_id).map_err(GroupError::internal)?,
            self.last_tuple.into_tuple()?,
        ))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ProjectedRoleDefinitionDocument {
    name: String,
    capabilities: Vec<String>,
    description: Option<String>,
    last_event_id: String,
    last_tuple: TupleDocument,
}

impl ProjectedRoleDefinitionDocument {
    fn from_role(role: &ProjectedRoleDefinition) -> Self {
        Self {
            name: role.definition().name().as_str().to_owned(),
            capabilities: role
                .definition()
                .capabilities()
                .labels()
                .into_iter()
                .map(str::to_owned)
                .collect(),
            description: role.definition().description().map(str::to_owned),
            last_event_id: role.last_event_id().as_str().to_owned(),
            last_tuple: TupleDocument::from_tuple(role.last_tuple()),
        }
    }

    fn into_role(self) -> Result<ProjectedRoleDefinition, GroupError> {
        Ok(ProjectedRoleDefinition::new(
            RoleDefinition::new(
                RoleName::new(&self.name)?,
                CapabilitySet::from_labels(&self.capabilities)?,
                self.description,
            ),
            EventId::new(&self.last_event_id).map_err(GroupError::internal)?,
            self.last_tuple.into_tuple()?,
        ))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GroupTombstoneDocument {
    group_id: String,
    delete_event_id: String,
    deleted_at: u64,
    deleted_by: String,
    last_tuple: TupleDocument,
}

impl GroupTombstoneDocument {
    fn from_tombstone(tombstone: &GroupTombstone) -> Self {
        Self {
            group_id: tombstone.group_id().as_str().to_owned(),
            delete_event_id: tombstone.delete_event_id().as_str().to_owned(),
            deleted_at: tombstone.deleted_at().as_u64(),
            deleted_by: tombstone.deleted_by().as_str().to_owned(),
            last_tuple: TupleDocument::from_tuple(tombstone.last_tuple()),
        }
    }

    fn into_tombstone(self) -> Result<GroupTombstone, GroupError> {
        Ok(GroupTombstone::new(
            GroupId::new(&self.group_id)?,
            EventId::new(&self.delete_event_id).map_err(GroupError::internal)?,
            UnixTimestamp::new(self.deleted_at),
            PublicKeyHex::new(&self.deleted_by).map_err(GroupError::internal)?,
            self.last_tuple.into_tuple()?,
        ))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GroupEventDeletionDocument {
    group_id: String,
    target_event_id: String,
    delete_event_id: String,
    deleted_at: u64,
    deleted_by: String,
    last_tuple: TupleDocument,
}

impl GroupEventDeletionDocument {
    fn from_deletion(deletion: &GroupEventDeletion) -> Self {
        Self {
            group_id: deletion.group_id().as_str().to_owned(),
            target_event_id: deletion.target_event_id().as_str().to_owned(),
            delete_event_id: deletion.delete_event_id().as_str().to_owned(),
            deleted_at: deletion.deleted_at().as_u64(),
            deleted_by: deletion.deleted_by().as_str().to_owned(),
            last_tuple: TupleDocument::from_tuple(deletion.last_tuple()),
        }
    }

    fn into_deletion(self) -> Result<GroupEventDeletion, GroupError> {
        Ok(GroupEventDeletion::new(
            GroupId::new(&self.group_id)?,
            EventId::new(&self.target_event_id).map_err(GroupError::internal)?,
            EventId::new(&self.delete_event_id).map_err(GroupError::internal)?,
            UnixTimestamp::new(self.deleted_at),
            PublicKeyHex::new(&self.deleted_by).map_err(GroupError::internal)?,
            self.last_tuple.into_tuple()?,
        ))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ProjectionCheckpointDocument {
    projection_version: u32,
    policy_version: u32,
    last_offset: Option<u64>,
    rebuilt_at: u64,
}

impl ProjectionCheckpointDocument {
    fn from_checkpoint(checkpoint: &ProjectionCheckpoint) -> Self {
        Self {
            projection_version: checkpoint.projection_version(),
            policy_version: checkpoint.policy_version(),
            last_offset: checkpoint.last_offset().map(StoreOffset::as_u64),
            rebuilt_at: checkpoint.rebuilt_at().as_u64(),
        }
    }

    fn into_checkpoint(self) -> ProjectionCheckpoint {
        ProjectionCheckpoint::new(
            self.projection_version,
            self.policy_version,
            self.last_offset.map(StoreOffset::new),
            UnixTimestamp::new(self.rebuilt_at),
        )
    }
}

fn lifecycle_label(value: GroupLifecycleState) -> String {
    match value {
        GroupLifecycleState::Active => "active",
        GroupLifecycleState::Deleted => "deleted",
    }
    .to_owned()
}

fn parse_lifecycle(value: &str) -> Result<GroupLifecycleState, GroupError> {
    match value {
        "active" => Ok(GroupLifecycleState::Active),
        "deleted" => Ok(GroupLifecycleState::Deleted),
        _ => Err(GroupError::internal(format!(
            "unknown group lifecycle {value}"
        ))),
    }
}

fn member_status_label(value: MemberStatus) -> String {
    match value {
        MemberStatus::Member => "member",
        MemberStatus::Removed => "removed",
    }
    .to_owned()
}

fn parse_member_status(value: &str) -> Result<MemberStatus, GroupError> {
    match value {
        "member" => Ok(MemberStatus::Member),
        "removed" => Ok(MemberStatus::Removed),
        _ => Err(GroupError::internal(format!(
            "unknown member status {value}"
        ))),
    }
}

fn parse_optional_event_id(value: Option<String>) -> Result<Option<EventId>, GroupError> {
    value
        .as_deref()
        .map(EventId::new)
        .transpose()
        .map_err(GroupError::internal)
}

#[cfg(test)]
mod tests {
    use super::{
        CanonicalGroupEvent, GroupEventDeletion, GroupLifecycleState, GroupProjection,
        GroupTombstone, MemberStatus, ProjectedRoleDefinition, ProjectionCheckpoint,
        ProjectionOrderTuple, StoreOffset, event_deletion_key, group_current_key,
        member_current_key, projection_checkpoint_key, rebuild_group_projection, role_current_key,
        tombstone_key,
    };
    use crate::{
        Capability, CapabilitySet, GroupId, GroupLimitsConfig, KIND_GROUP_CREATE_GROUP,
        KIND_GROUP_DELETE_EVENT, KIND_GROUP_DELETE_GROUP, KIND_GROUP_EDIT_METADATA,
        KIND_GROUP_METADATA, KIND_GROUP_PUT_USER, RoleDefinition, RoleName, SupportedKinds,
    };
    use tangle_protocol::{
        Event, EventId, Kind, PublicKeyHex, SignatureHex, Tag, UnixTimestamp, UnsignedEvent,
    };

    #[test]
    fn projection_order_tuple_sorts_by_created_event_and_offset() {
        let mut tuples = vec![
            tuple(2, "b", 1),
            tuple(1, "c", 2),
            tuple(1, "a", 3),
            tuple(1, "a", 1),
        ];

        tuples.sort();

        assert_eq!(tuples[0], tuple(1, "a", 1));
        assert_eq!(tuples[1], tuple(1, "a", 3));
        assert_eq!(tuples[2], tuple(1, "c", 2));
        assert_eq!(tuples[3], tuple(2, "b", 1));
    }

    #[test]
    fn projection_applies_create_metadata_member_delete_and_snapshots() {
        let mut projection = GroupProjection::new();
        projection
            .apply_canonical_event(
                &event(
                    KIND_GROUP_CREATE_GROUP,
                    "10",
                    10,
                    vec![
                        Tag::from_parts("h", &["Farm"]).expect("h"),
                        Tag::from_parts("name", &["Farmers"]).expect("name"),
                    ],
                ),
                StoreOffset::new(1),
                GroupLimitsConfig::default(),
            )
            .expect("create");
        projection
            .apply_canonical_event(
                &event(
                    KIND_GROUP_EDIT_METADATA,
                    "20",
                    20,
                    vec![
                        Tag::from_parts("h", &["Farm"]).expect("h"),
                        Tag::from_parts("name", &["Market"]).expect("name"),
                    ],
                ),
                StoreOffset::new(2),
                GroupLimitsConfig::default(),
            )
            .expect("metadata");
        projection
            .apply_canonical_event(
                &event(
                    KIND_GROUP_PUT_USER,
                    "30",
                    30,
                    vec![
                        Tag::from_parts("h", &["Farm"]).expect("h"),
                        Tag::from_parts("p", &[&"8".repeat(64)]).expect("p"),
                        Tag::from_parts("role", &["moderator"]).expect("role"),
                    ],
                ),
                StoreOffset::new(3),
                GroupLimitsConfig::default(),
            )
            .expect("member");
        projection
            .apply_canonical_event(
                &event(
                    KIND_GROUP_METADATA,
                    "40",
                    40,
                    vec![
                        Tag::from_parts("d", &["Farm"]).expect("d"),
                        Tag::from_parts("name", &["Snapshot"]).expect("name"),
                    ],
                ),
                StoreOffset::new(4),
                GroupLimitsConfig::default(),
            )
            .expect("snapshot");
        projection
            .apply_canonical_event(
                &event(
                    KIND_GROUP_DELETE_EVENT,
                    "45",
                    45,
                    vec![
                        Tag::from_parts("h", &["Farm"]).expect("h"),
                        Tag::from_parts("e", &[id("30")]).expect("e"),
                    ],
                ),
                StoreOffset::new(5),
                GroupLimitsConfig::default(),
            )
            .expect("event deletion");
        projection
            .apply_canonical_event(
                &event(
                    KIND_GROUP_DELETE_GROUP,
                    "50",
                    50,
                    vec![Tag::from_parts("h", &["Farm"]).expect("h")],
                ),
                StoreOffset::new(6),
                GroupLimitsConfig::default(),
            )
            .expect("delete");

        let group = projection
            .group(&GroupId::new("Farm").expect("group"))
            .expect("group");
        assert_eq!(group.metadata().name(), Some("Snapshot"));
        assert_eq!(group.lifecycle(), GroupLifecycleState::Deleted);
        assert_eq!(
            group.snapshots().metadata().expect("snapshot").as_str(),
            id("40")
        );
        let member = projection
            .member(
                &GroupId::new("Farm").expect("group"),
                &PublicKeyHex::new(&"8".repeat(64)).expect("pubkey"),
            )
            .expect("member");
        assert_eq!(member.status(), MemberStatus::Member);
        assert!(
            member
                .roles()
                .contains(&crate::RoleName::new("moderator").expect("role"))
        );
        assert!(
            projection
                .tombstone(&GroupId::new("Farm").expect("group"))
                .is_some()
        );
        assert!(
            projection
                .event_deletion(&EventId::new(id("30")).expect("event"))
                .is_some()
        );
    }

    #[test]
    fn projection_rebuild_sorts_before_applying_last_tuple_wins() {
        let report = rebuild_group_projection(
            [
                CanonicalGroupEvent::new(
                    event(
                        KIND_GROUP_EDIT_METADATA,
                        "30",
                        30,
                        vec![
                            Tag::from_parts("h", &["Farm"]).expect("h"),
                            Tag::from_parts("name", &["New"]).expect("name"),
                        ],
                    ),
                    StoreOffset::new(3),
                ),
                CanonicalGroupEvent::new(
                    event(
                        KIND_GROUP_CREATE_GROUP,
                        "10",
                        10,
                        vec![Tag::from_parts("h", &["Farm"]).expect("h")],
                    ),
                    StoreOffset::new(1),
                ),
                CanonicalGroupEvent::new(
                    event(
                        KIND_GROUP_EDIT_METADATA,
                        "20",
                        20,
                        vec![
                            Tag::from_parts("h", &["Farm"]).expect("h"),
                            Tag::from_parts("name", &["Old"]).expect("name"),
                        ],
                    ),
                    StoreOffset::new(2),
                ),
            ],
            GroupLimitsConfig::default(),
            UnixTimestamp::new(100),
        )
        .expect("rebuild");

        let group = report
            .projection()
            .group(&GroupId::new("Farm").expect("group"))
            .expect("group");

        assert_eq!(group.metadata().name(), Some("New"));
        assert_eq!(report.applied_events(), 3);
        assert_eq!(report.last_offset(), Some(StoreOffset::new(3)));
        assert!(
            report
                .projection()
                .checkpoint()
                .expect("checkpoint")
                .matches_current_versions()
        );
    }

    #[test]
    fn projection_records_round_trip_for_persistence() {
        let base_tuple = tuple(10, "10", 1);
        let state = super::GroupState::new(
            GroupId::new("Farm").expect("group"),
            crate::GroupMetadata::new(
                Some("Farmers".to_owned()),
                None,
                None,
                true,
                false,
                false,
                false,
                SupportedKinds::UnspecifiedAll,
            ),
            PublicKeyHex::new(&"1".repeat(64)).expect("pubkey"),
            EventId::new(id("10")).expect("id"),
            base_tuple.clone(),
        );
        let member = super::MemberState::new(
            PublicKeyHex::new(&"2".repeat(64)).expect("pubkey"),
            MemberStatus::Member,
            [RoleName::new("moderator").expect("role")]
                .into_iter()
                .collect(),
            EventId::new(id("20")).expect("id"),
            base_tuple,
        );
        let role = ProjectedRoleDefinition::new(
            RoleDefinition::new(
                RoleName::new("moderator").expect("role"),
                CapabilitySet::new([Capability::ManageMembers]),
                Some("member manager".to_owned()),
            ),
            EventId::new(id("30")).expect("id"),
            tuple(10, "30", 3),
        );
        let tombstone = GroupTombstone::new(
            GroupId::new("Farm").expect("group"),
            EventId::new(id("40")).expect("id"),
            UnixTimestamp::new(40),
            PublicKeyHex::new(&"3".repeat(64)).expect("pubkey"),
            tuple(40, "40", 4),
        );
        let deletion = GroupEventDeletion::new(
            GroupId::new("Farm").expect("group"),
            EventId::new(id("30")).expect("target"),
            EventId::new(id("45")).expect("delete"),
            UnixTimestamp::new(45),
            PublicKeyHex::new(&"3".repeat(64)).expect("pubkey"),
            tuple(45, "45", 5),
        );
        let checkpoint =
            ProjectionCheckpoint::current(Some(StoreOffset::new(25)), UnixTimestamp::new(99));

        assert_eq!(
            super::GroupState::from_json_bytes(&state.to_json_bytes().expect("bytes"))
                .expect("state"),
            state
        );
        assert_eq!(
            super::MemberState::from_json_bytes(&member.to_json_bytes().expect("bytes"))
                .expect("member"),
            member
        );
        assert_eq!(
            ProjectedRoleDefinition::from_json_bytes(&role.to_json_bytes().expect("bytes"))
                .expect("role"),
            role
        );
        assert_eq!(
            GroupTombstone::from_json_bytes(&tombstone.to_json_bytes().expect("bytes"))
                .expect("tombstone"),
            tombstone
        );
        assert_eq!(
            GroupEventDeletion::from_json_bytes(&deletion.to_json_bytes().expect("bytes"))
                .expect("deletion"),
            deletion
        );
        assert_eq!(
            ProjectionCheckpoint::from_json_bytes(&checkpoint.to_json_bytes().expect("bytes"))
                .expect("checkpoint"),
            checkpoint
        );
    }

    #[test]
    fn projection_storage_keys_are_deterministic() {
        let group = GroupId::new("Farm").expect("group");
        let pubkey = PublicKeyHex::new(&"4".repeat(64)).expect("pubkey");

        assert_eq!(group_current_key(&group), b"group\0Farm".to_vec());
        assert_eq!(
            member_current_key(&group, &pubkey),
            format!("member\0Farm\0{}", "4".repeat(64)).into_bytes()
        );
        assert_eq!(
            role_current_key(&group, &RoleName::new("moderator").expect("role")),
            b"role\0Farm\0moderator".to_vec()
        );
        assert_eq!(tombstone_key(&group), b"tombstone\0Farm".to_vec());
        assert_eq!(
            event_deletion_key(&EventId::new(id("30")).expect("event")),
            format!("event_deletion\0{}", id("30")).into_bytes()
        );
        assert_eq!(projection_checkpoint_key(), b"checkpoint\0groups".to_vec());
    }

    fn tuple(created_at: u64, event_suffix: &str, offset: u64) -> ProjectionOrderTuple {
        ProjectionOrderTuple::new(
            UnixTimestamp::new(created_at),
            EventId::new(id(event_suffix)).expect("id"),
            StoreOffset::new(offset),
        )
    }

    fn event(kind: u32, suffix: &str, created_at: u64, tags: Vec<Tag>) -> Event {
        Event::new(
            EventId::new(id(suffix)).expect("id"),
            UnsignedEvent::new(
                PublicKeyHex::new(&"1".repeat(64)).expect("pubkey"),
                UnixTimestamp::new(created_at),
                Kind::new(kind.into()).expect("kind"),
                tags,
                "",
            ),
            SignatureHex::new(&"2".repeat(128)).expect("sig"),
        )
    }

    fn id(suffix: &str) -> &'static str {
        match suffix {
            "10" => "0000000000000000000000000000000000000000000000000000000000000010",
            "20" => "0000000000000000000000000000000000000000000000000000000000000020",
            "30" => "0000000000000000000000000000000000000000000000000000000000000030",
            "40" => "0000000000000000000000000000000000000000000000000000000000000040",
            "45" => "0000000000000000000000000000000000000000000000000000000000000045",
            "50" => "0000000000000000000000000000000000000000000000000000000000000050",
            "a" => "000000000000000000000000000000000000000000000000000000000000000a",
            "b" => "000000000000000000000000000000000000000000000000000000000000000b",
            "c" => "000000000000000000000000000000000000000000000000000000000000000c",
            _ => "0000000000000000000000000000000000000000000000000000000000000001",
        }
    }
}
