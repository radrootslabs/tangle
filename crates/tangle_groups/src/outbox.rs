use std::collections::{BTreeMap, BTreeSet};

use crate::{GroupError, GroupId};
use serde::{Deserialize, Serialize};
use tangle_protocol::{EventId, PublicKeyHex, UnixTimestamp};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum GroupOutboxEffect {
    MetadataSnapshot,
    AdminListSnapshot,
    MemberListSnapshot,
    RoleListSnapshot,
    State39004Snapshot,
    JoinAccepted,
    LeaveAccepted,
}

impl GroupOutboxEffect {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MetadataSnapshot => "metadata_snapshot",
            Self::AdminListSnapshot => "admin_list_snapshot",
            Self::MemberListSnapshot => "member_list_snapshot",
            Self::RoleListSnapshot => "role_list_snapshot",
            Self::State39004Snapshot => "state_39004_snapshot",
            Self::JoinAccepted => "join_accepted",
            Self::LeaveAccepted => "leave_accepted",
        }
    }

    pub fn from_label(value: &str) -> Result<Self, GroupError> {
        match value {
            "metadata_snapshot" => Ok(Self::MetadataSnapshot),
            "admin_list_snapshot" => Ok(Self::AdminListSnapshot),
            "member_list_snapshot" => Ok(Self::MemberListSnapshot),
            "role_list_snapshot" => Ok(Self::RoleListSnapshot),
            "state_39004_snapshot" => Ok(Self::State39004Snapshot),
            "join_accepted" => Ok(Self::JoinAccepted),
            "leave_accepted" => Ok(Self::LeaveAccepted),
            _ => Err(GroupError::internal(format!(
                "unknown outbox effect {value}"
            ))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GroupOutboxKey {
    source_event_id: EventId,
    effect: GroupOutboxEffect,
    group_id: GroupId,
    target_pubkey: Option<PublicKeyHex>,
}

impl GroupOutboxKey {
    pub fn new(
        source_event_id: EventId,
        effect: GroupOutboxEffect,
        group_id: GroupId,
        target_pubkey: Option<PublicKeyHex>,
    ) -> Self {
        Self {
            source_event_id,
            effect,
            group_id,
            target_pubkey,
        }
    }

    pub fn source_event_id(&self) -> &EventId {
        &self.source_event_id
    }

    pub fn effect(&self) -> GroupOutboxEffect {
        self.effect
    }

    pub fn group_id(&self) -> &GroupId {
        &self.group_id
    }

    pub fn target_pubkey(&self) -> Option<&PublicKeyHex> {
        self.target_pubkey.as_ref()
    }

    pub fn storage_key(&self) -> Vec<u8> {
        let mut key = Vec::new();
        key.extend_from_slice(self.source_event_id.as_str().as_bytes());
        key.push(0);
        key.extend_from_slice(self.effect.as_str().as_bytes());
        key.push(0);
        key.extend_from_slice(self.group_id.as_str().as_bytes());
        key.push(0);
        if let Some(pubkey) = &self.target_pubkey {
            key.extend_from_slice(pubkey.as_str().as_bytes());
        }
        key
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GroupOutboxStatus {
    Pending,
    Stored { generated_event_id: EventId },
    Skipped { reason: String },
    Failed { retryable: bool },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupOutboxPayload {
    generated_kind: u32,
    generated_created_at: UnixTimestamp,
    tags: Vec<Vec<String>>,
    content: String,
}

impl GroupOutboxPayload {
    pub fn new(
        generated_kind: u32,
        generated_created_at: UnixTimestamp,
        tags: Vec<Vec<String>>,
        content: impl Into<String>,
    ) -> Self {
        Self {
            generated_kind,
            generated_created_at,
            tags,
            content: content.into(),
        }
    }

    pub fn generated_kind(&self) -> u32 {
        self.generated_kind
    }

    pub fn generated_created_at(&self) -> UnixTimestamp {
        self.generated_created_at
    }

    pub fn tags(&self) -> &[Vec<String>] {
        &self.tags
    }

    pub fn content(&self) -> &str {
        &self.content
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupOutboxRecord {
    key: GroupOutboxKey,
    status: GroupOutboxStatus,
    payload: GroupOutboxPayload,
    attempts: u32,
    last_error: Option<String>,
}

impl GroupOutboxRecord {
    pub fn pending(key: GroupOutboxKey, payload: GroupOutboxPayload) -> Self {
        Self {
            key,
            status: GroupOutboxStatus::Pending,
            payload,
            attempts: 0,
            last_error: None,
        }
    }

    pub fn key(&self) -> &GroupOutboxKey {
        &self.key
    }

    pub fn status(&self) -> &GroupOutboxStatus {
        &self.status
    }

    pub fn payload(&self) -> &GroupOutboxPayload {
        &self.payload
    }

    pub fn attempts(&self) -> u32 {
        self.attempts
    }

    pub fn last_error(&self) -> Option<&str> {
        self.last_error.as_deref()
    }

    pub fn mark_stored(&mut self, generated_event_id: EventId) {
        self.status = GroupOutboxStatus::Stored { generated_event_id };
        self.last_error = None;
    }

    pub fn mark_skipped(&mut self, reason: impl Into<String>) {
        self.status = GroupOutboxStatus::Skipped {
            reason: reason.into(),
        };
    }

    pub fn mark_failed(&mut self, retryable: bool, error: impl Into<String>) {
        self.status = GroupOutboxStatus::Failed { retryable };
        self.attempts = self.attempts.saturating_add(1);
        self.last_error = Some(error.into());
    }

    pub fn is_retryable(&self) -> bool {
        matches!(
            self.status,
            GroupOutboxStatus::Pending | GroupOutboxStatus::Failed { retryable: true }
        )
    }

    pub fn to_json_bytes(&self) -> Result<Vec<u8>, GroupError> {
        serde_json::to_vec(&GroupOutboxRecordDocument::from_record(self)).map_err(|error| {
            GroupError::internal(format!("outbox record JSON encode failed: {error}"))
        })
    }

    pub fn from_json_bytes(raw: &[u8]) -> Result<Self, GroupError> {
        let document =
            serde_json::from_slice::<GroupOutboxRecordDocument>(raw).map_err(|error| {
                GroupError::internal(format!("outbox record JSON decode failed: {error}"))
            })?;
        document.into_record()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GroupOutbox {
    records: BTreeMap<GroupOutboxKey, GroupOutboxRecord>,
}

impl GroupOutbox {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn merge_idempotent(&mut self, record: GroupOutboxRecord) -> Result<bool, GroupError> {
        if let Some(existing) = self.records.get(record.key()) {
            if existing.payload() == record.payload() {
                return Ok(false);
            }
            return Err(GroupError::internal(
                "outbox record key already exists with different payload",
            ));
        }
        self.records.insert(record.key().clone(), record);
        Ok(true)
    }

    pub fn get(&self, key: &GroupOutboxKey) -> Option<&GroupOutboxRecord> {
        self.records.get(key)
    }

    pub fn update(&mut self, record: GroupOutboxRecord) {
        self.records.insert(record.key().clone(), record);
    }

    pub fn replay_plan(&self) -> OutboxReplayPlan {
        self.replay_plan_matching(|_| true)
    }

    pub fn replay_plan_for_group(&self, group_id: &GroupId) -> OutboxReplayPlan {
        self.replay_plan_matching(|record| record.key().group_id() == group_id)
    }

    fn replay_plan_matching(
        &self,
        include: impl Fn(&GroupOutboxRecord) -> bool,
    ) -> OutboxReplayPlan {
        let mut records = self
            .records
            .values()
            .filter(|record| record.is_retryable() && include(record))
            .cloned()
            .collect::<Vec<_>>();
        records.sort_by(|left, right| {
            left.key()
                .group_id()
                .cmp(right.key().group_id())
                .then_with(|| {
                    left.payload()
                        .generated_created_at()
                        .cmp(&right.payload().generated_created_at())
                })
                .then_with(|| {
                    left.key()
                        .source_event_id()
                        .cmp(right.key().source_event_id())
                })
                .then_with(|| left.key().effect().cmp(&right.key().effect()))
                .then_with(|| left.key().target_pubkey().cmp(&right.key().target_pubkey()))
        });
        OutboxReplayPlan { records }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboxReplayPlan {
    records: Vec<GroupOutboxRecord>,
}

impl OutboxReplayPlan {
    pub fn records(&self) -> &[GroupOutboxRecord] {
        &self.records
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum GroupCrashPoint {
    SourceParsedBeforeStore,
    SourceStoreBeforeProjection,
    ProjectionUpdateBeforeOutboxPersist,
    OutboxPersistBeforeGeneratedStore,
    GeneratedStoreBeforeOutboxMark,
    OutboxMarkBeforeBroadcast,
    ProjectionRebuild,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GroupCrashHooks {
    fail_points: BTreeSet<GroupCrashPoint>,
}

impl GroupCrashHooks {
    pub fn disabled() -> Self {
        Self::default()
    }

    pub fn failing_at(points: impl IntoIterator<Item = GroupCrashPoint>) -> Self {
        Self {
            fail_points: points.into_iter().collect(),
        }
    }

    pub fn check(&self, point: GroupCrashPoint) -> Result<(), GroupError> {
        if self.fail_points.contains(&point) {
            return Err(GroupError::internal(format!(
                "injected group crash at {point:?}"
            )));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutboxRecoveryReadiness {
    Ready,
    FailedClosed { reason: String },
}

impl OutboxRecoveryReadiness {
    pub fn from_replay_result<T>(result: &Result<T, GroupError>) -> Self {
        match result {
            Ok(_) => Self::Ready,
            Err(error) => Self::FailedClosed {
                reason: error.prefixed_message(),
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GroupOutboxRecordDocument {
    key: GroupOutboxKeyDocument,
    status: GroupOutboxStatusDocument,
    payload: GroupOutboxPayloadDocument,
    attempts: u32,
    last_error: Option<String>,
}

impl GroupOutboxRecordDocument {
    fn from_record(record: &GroupOutboxRecord) -> Self {
        Self {
            key: GroupOutboxKeyDocument::from_key(record.key()),
            status: GroupOutboxStatusDocument::from_status(record.status()),
            payload: GroupOutboxPayloadDocument::from_payload(record.payload()),
            attempts: record.attempts(),
            last_error: record.last_error().map(str::to_owned),
        }
    }

    fn into_record(self) -> Result<GroupOutboxRecord, GroupError> {
        Ok(GroupOutboxRecord {
            key: self.key.into_key()?,
            status: self.status.into_status()?,
            payload: self.payload.into_payload(),
            attempts: self.attempts,
            last_error: self.last_error,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GroupOutboxKeyDocument {
    source_event_id: String,
    effect: String,
    group_id: String,
    target_pubkey: Option<String>,
}

impl GroupOutboxKeyDocument {
    fn from_key(key: &GroupOutboxKey) -> Self {
        Self {
            source_event_id: key.source_event_id().as_str().to_owned(),
            effect: key.effect().as_str().to_owned(),
            group_id: key.group_id().as_str().to_owned(),
            target_pubkey: key.target_pubkey().map(|pubkey| pubkey.as_str().to_owned()),
        }
    }

    fn into_key(self) -> Result<GroupOutboxKey, GroupError> {
        Ok(GroupOutboxKey::new(
            EventId::new(&self.source_event_id).map_err(GroupError::internal)?,
            GroupOutboxEffect::from_label(&self.effect)?,
            GroupId::new(&self.group_id)?,
            self.target_pubkey
                .as_deref()
                .map(PublicKeyHex::new)
                .transpose()
                .map_err(GroupError::internal)?,
        ))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "state")]
enum GroupOutboxStatusDocument {
    Pending,
    Stored { generated_event_id: String },
    Skipped { reason: String },
    Failed { retryable: bool },
}

impl GroupOutboxStatusDocument {
    fn from_status(status: &GroupOutboxStatus) -> Self {
        match status {
            GroupOutboxStatus::Pending => Self::Pending,
            GroupOutboxStatus::Stored { generated_event_id } => Self::Stored {
                generated_event_id: generated_event_id.as_str().to_owned(),
            },
            GroupOutboxStatus::Skipped { reason } => Self::Skipped {
                reason: reason.clone(),
            },
            GroupOutboxStatus::Failed { retryable } => Self::Failed {
                retryable: *retryable,
            },
        }
    }

    fn into_status(self) -> Result<GroupOutboxStatus, GroupError> {
        match self {
            Self::Pending => Ok(GroupOutboxStatus::Pending),
            Self::Stored { generated_event_id } => Ok(GroupOutboxStatus::Stored {
                generated_event_id: EventId::new(&generated_event_id)
                    .map_err(GroupError::internal)?,
            }),
            Self::Skipped { reason } => Ok(GroupOutboxStatus::Skipped { reason }),
            Self::Failed { retryable } => Ok(GroupOutboxStatus::Failed { retryable }),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GroupOutboxPayloadDocument {
    generated_kind: u32,
    generated_created_at: u64,
    tags: Vec<Vec<String>>,
    content: String,
}

impl GroupOutboxPayloadDocument {
    fn from_payload(payload: &GroupOutboxPayload) -> Self {
        Self {
            generated_kind: payload.generated_kind(),
            generated_created_at: payload.generated_created_at().as_u64(),
            tags: payload.tags().to_vec(),
            content: payload.content().to_owned(),
        }
    }

    fn into_payload(self) -> GroupOutboxPayload {
        GroupOutboxPayload::new(
            self.generated_kind,
            UnixTimestamp::new(self.generated_created_at),
            self.tags,
            self.content,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{
        GroupCrashHooks, GroupCrashPoint, GroupOutbox, GroupOutboxEffect, GroupOutboxKey,
        GroupOutboxPayload, GroupOutboxRecord, GroupOutboxStatus,
    };
    use crate::GroupId;
    use tangle_protocol::{EventId, PublicKeyHex, UnixTimestamp};

    #[test]
    fn outbox_keys_are_deterministic() {
        let key = key(Some(PublicKeyHex::new(&"2".repeat(64)).expect("pubkey")));

        assert_eq!(
            key.storage_key(),
            format!(
                "{}\0join_accepted\0Farm\0{}",
                "1".repeat(64),
                "2".repeat(64)
            )
            .into_bytes()
        );
    }

    #[test]
    fn outbox_merge_is_idempotent_for_same_payload() {
        let mut outbox = GroupOutbox::new();
        let record = GroupOutboxRecord::pending(key(None), payload(9_000));

        assert!(outbox.merge_idempotent(record.clone()).expect("insert"));
        assert!(!outbox.merge_idempotent(record).expect("same"));
        assert!(
            outbox
                .merge_idempotent(GroupOutboxRecord::pending(key(None), payload(9_001)))
                .is_err()
        );
    }

    #[test]
    fn outbox_merge_preserves_persisted_status_for_same_payload() {
        let mut outbox = GroupOutbox::new();
        let mut stored = GroupOutboxRecord::pending(key(None), payload(9_000));
        let generated_event_id = EventId::new(&"9".repeat(64)).expect("event");
        stored.mark_stored(generated_event_id.clone());

        assert!(outbox.merge_idempotent(stored.clone()).expect("stored"));
        assert!(
            !outbox
                .merge_idempotent(GroupOutboxRecord::pending(key(None), payload(9_000)))
                .expect("derived")
        );
        assert_eq!(
            outbox.get(stored.key()).expect("record").status(),
            &GroupOutboxStatus::Stored { generated_event_id }
        );
    }

    #[test]
    fn outbox_replay_plan_is_sorted_and_retryable_only() {
        let mut outbox = GroupOutbox::new();
        let mut stored = GroupOutboxRecord::pending(key(None), payload(9_000));
        stored.mark_stored(EventId::new(&"9".repeat(64)).expect("event"));
        let mut retryable = GroupOutboxRecord::pending(
            GroupOutboxKey::new(
                EventId::new(&"0".repeat(64)).expect("event"),
                GroupOutboxEffect::MetadataSnapshot,
                GroupId::new("Farm").expect("group"),
                None,
            ),
            payload(39_000),
        );
        retryable.mark_failed(true, "store failed");

        outbox.merge_idempotent(stored).expect("stored");
        outbox.merge_idempotent(retryable).expect("retryable");
        let plan = outbox.replay_plan();

        assert_eq!(plan.records().len(), 1);
        assert_eq!(plan.records()[0].payload().generated_kind(), 39_000);
        assert_eq!(plan.records()[0].attempts(), 1);
    }

    #[test]
    fn outbox_replay_plan_orders_retryable_records_by_group_and_source_time() {
        let mut outbox = GroupOutbox::new();
        let farm_early = replay_record(&"f".repeat(64), "Farm", 1);
        let farm_late = replay_record(&"0".repeat(64), "Farm", 2);
        let market_early = replay_record(&"1".repeat(64), "Market", 1);

        outbox
            .merge_idempotent(market_early.clone())
            .expect("market");
        outbox
            .merge_idempotent(farm_late.clone())
            .expect("farm late");
        outbox
            .merge_idempotent(farm_early.clone())
            .expect("farm early");
        let plan = outbox.replay_plan();

        assert_eq!(
            plan.records()
                .iter()
                .map(|record| record.key().source_event_id())
                .collect::<Vec<_>>(),
            vec![
                farm_early.key().source_event_id(),
                farm_late.key().source_event_id(),
                market_early.key().source_event_id()
            ]
        );
    }

    #[test]
    fn outbox_replay_plan_can_scope_retryable_records_to_one_group() {
        let mut outbox = GroupOutbox::new();
        let farm_early = replay_record(&"f".repeat(64), "Farm", 1);
        let farm_late = replay_record(&"0".repeat(64), "Farm", 2);
        let market_early = replay_record(&"1".repeat(64), "Market", 1);

        outbox
            .merge_idempotent(market_early.clone())
            .expect("market");
        outbox
            .merge_idempotent(farm_late.clone())
            .expect("farm late");
        outbox
            .merge_idempotent(farm_early.clone())
            .expect("farm early");
        let plan = outbox.replay_plan_for_group(&GroupId::new("Farm").expect("group"));

        assert_eq!(
            plan.records()
                .iter()
                .map(|record| record.key().source_event_id())
                .collect::<Vec<_>>(),
            vec![
                farm_early.key().source_event_id(),
                farm_late.key().source_event_id()
            ]
        );
    }

    #[test]
    fn outbox_records_round_trip_for_persistence() {
        let mut record = GroupOutboxRecord::pending(key(None), payload(39_000));
        record.mark_failed(true, "pending retry");

        let decoded = GroupOutboxRecord::from_json_bytes(&record.to_json_bytes().expect("bytes"))
            .expect("record");
        assert_eq!(decoded.payload().generated_kind(), 39_000);
        assert_eq!(
            decoded.payload().generated_created_at(),
            UnixTimestamp::new(1)
        );
        assert_eq!(
            decoded.payload().tags(),
            &[vec!["h".to_owned(), "Farm".to_owned()]]
        );
        assert_eq!(decoded.payload().content(), "");
        assert_eq!(decoded, record);
    }

    #[test]
    fn crash_hooks_fail_only_at_configured_points() {
        let hooks =
            GroupCrashHooks::failing_at([GroupCrashPoint::OutboxPersistBeforeGeneratedStore]);

        assert!(
            hooks
                .check(GroupCrashPoint::GeneratedStoreBeforeOutboxMark)
                .is_ok()
        );
        assert_eq!(
            hooks
                .check(GroupCrashPoint::OutboxPersistBeforeGeneratedStore)
                .expect_err("injected")
                .prefixed_message(),
            "error: injected group crash at OutboxPersistBeforeGeneratedStore"
        );
    }

    fn key(target_pubkey: Option<PublicKeyHex>) -> GroupOutboxKey {
        GroupOutboxKey::new(
            EventId::new(&"1".repeat(64)).expect("event"),
            GroupOutboxEffect::JoinAccepted,
            GroupId::new("Farm").expect("group"),
            target_pubkey,
        )
    }

    fn payload(kind: u32) -> GroupOutboxPayload {
        GroupOutboxPayload::new(
            kind,
            UnixTimestamp::new(1),
            vec![vec!["h".to_owned(), "Farm".to_owned()]],
            "",
        )
    }

    fn replay_record(source_event_id: &str, group_id: &str, created_at: u64) -> GroupOutboxRecord {
        let group_id = GroupId::new(group_id).expect("group");
        GroupOutboxRecord::pending(
            GroupOutboxKey::new(
                EventId::new(source_event_id).expect("event"),
                GroupOutboxEffect::MetadataSnapshot,
                group_id.clone(),
                None,
            ),
            GroupOutboxPayload::new(
                39_000,
                UnixTimestamp::new(created_at),
                vec![vec!["h".to_owned(), group_id.as_str().to_owned()]],
                "",
            ),
        )
    }
}
