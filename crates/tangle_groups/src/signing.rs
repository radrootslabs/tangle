use std::collections::BTreeSet;

use crate::{
    GroupAuthority, GroupError, GroupId, GroupMetadata, GroupOutboxPayload, GroupProjection,
    GroupState, KIND_GROUP_ADMINS, KIND_GROUP_MEMBERS, KIND_GROUP_METADATA, KIND_GROUP_PUT_USER,
    KIND_GROUP_REMOVE_USER, MemberStatus, RoleName, SupportedKinds,
};
use pocket_types::{
    Kind as PocketKind, OwnedEvent as PocketOwnedEvent, OwnedTags as PocketOwnedTags,
    Time as PocketTime,
};
use tangle_crypto::RelaySigner;
use tangle_protocol::{Event, Kind, PublicKeyHex, Tag, UnixTimestamp, UnsignedEvent};

pub struct GroupGeneratedEventBuilder {
    signer: RelaySigner,
}

impl GroupGeneratedEventBuilder {
    pub fn new(signer: RelaySigner) -> Self {
        Self { signer }
    }

    pub fn relay_pubkey(&self) -> &PublicKeyHex {
        self.signer.public_key()
    }

    pub fn metadata_snapshot_payload(
        group: &GroupState,
        created_at: UnixTimestamp,
    ) -> Result<GroupOutboxPayload, GroupError> {
        Ok(GroupOutboxPayload::new(
            KIND_GROUP_METADATA,
            created_at,
            metadata_tags(group.id(), group.metadata())?,
            "",
        ))
    }

    pub fn admin_list_snapshot_payload(
        group_id: &GroupId,
        projection: &GroupProjection,
        authority: &GroupAuthority,
        created_at: UnixTimestamp,
    ) -> Result<GroupOutboxPayload, GroupError> {
        let mut admins = BTreeSet::new();
        admins.extend(authority.owner_pubkeys().iter().cloned());
        admins.extend(authority.admin_pubkeys().iter().cloned());
        for ((candidate_group, pubkey), member) in projection.members() {
            if candidate_group == group_id
                && member.status() == MemberStatus::Member
                && member
                    .roles()
                    .contains(&RoleName::permanent_relay_override())
            {
                admins.insert(pubkey.clone());
            }
        }
        let mut tags = vec![tag_values(["d".to_owned(), group_id.as_str().to_owned()])];
        tags.extend(
            admins
                .into_iter()
                .map(|pubkey| tag_values(["p".to_owned(), pubkey.as_str().to_owned()])),
        );
        Ok(GroupOutboxPayload::new(
            KIND_GROUP_ADMINS,
            created_at,
            tags,
            "",
        ))
    }

    pub fn member_list_snapshot_payload(
        group_id: &GroupId,
        projection: &GroupProjection,
        created_at: UnixTimestamp,
        cap: u32,
    ) -> Result<Option<GroupOutboxPayload>, GroupError> {
        let mut members = projection
            .members()
            .iter()
            .filter(|((candidate_group, _), member)| {
                candidate_group == group_id && member.status() == MemberStatus::Member
            })
            .map(|((_, pubkey), _)| pubkey.clone())
            .collect::<Vec<_>>();
        members.sort();
        if members.len() > usize::try_from(cap).expect("u32 fits in usize on supported targets") {
            return Ok(None);
        }
        let mut tags = vec![tag_values(["d".to_owned(), group_id.as_str().to_owned()])];
        tags.extend(
            members
                .into_iter()
                .map(|pubkey| tag_values(["p".to_owned(), pubkey.as_str().to_owned()])),
        );
        Ok(Some(GroupOutboxPayload::new(
            KIND_GROUP_MEMBERS,
            created_at,
            tags,
            "",
        )))
    }

    pub fn join_accepted_payload(
        group_id: &GroupId,
        target_pubkey: &PublicKeyHex,
        created_at: UnixTimestamp,
    ) -> GroupOutboxPayload {
        membership_payload(KIND_GROUP_PUT_USER, group_id, target_pubkey, created_at)
    }

    pub fn leave_accepted_payload(
        group_id: &GroupId,
        target_pubkey: &PublicKeyHex,
        created_at: UnixTimestamp,
    ) -> GroupOutboxPayload {
        membership_payload(KIND_GROUP_REMOVE_USER, group_id, target_pubkey, created_at)
    }

    pub fn sign_payload(&self, payload: &GroupOutboxPayload) -> Result<Event, GroupError> {
        let tags = payload
            .tags()
            .iter()
            .cloned()
            .map(Tag::new)
            .collect::<Result<Vec<_>, _>>()
            .map_err(GroupError::internal)?;
        let unsigned = UnsignedEvent::new(
            self.signer.public_key().clone(),
            payload.generated_created_at(),
            Kind::new(payload.generated_kind().into()).map_err(GroupError::internal)?,
            tags,
            payload.content(),
        );
        Ok(self.signer.sign_unsigned_event(unsigned))
    }

    pub fn sign_payload_pocket(
        &self,
        payload: &GroupOutboxPayload,
    ) -> Result<PocketOwnedEvent, GroupError> {
        let kind = PocketKind::from_u16(
            u16::try_from(payload.generated_kind())
                .map_err(|_| GroupError::internal("generated event kind exceeds Pocket kind"))?,
        );
        let tags = PocketOwnedTags::new(payload.tags()).map_err(|error| {
            GroupError::internal(format!("generated Pocket tags are invalid: {error}"))
        })?;
        let event = self
            .signer
            .sign_pocket_event(
                kind,
                &tags,
                PocketTime::from_u64(payload.generated_created_at().as_u64()),
                payload.content().as_bytes(),
            )
            .map_err(GroupError::internal)?;
        event.verify().map_err(|error| {
            GroupError::internal(format!(
                "generated Pocket event failed verification: {error}"
            ))
        })?;
        Ok(event)
    }

    pub fn build_metadata_snapshot(
        &self,
        group: &GroupState,
        created_at: UnixTimestamp,
    ) -> Result<Event, GroupError> {
        self.sign_payload(&Self::metadata_snapshot_payload(group, created_at)?)
    }

    pub fn build_admin_list_snapshot(
        &self,
        group_id: &GroupId,
        projection: &GroupProjection,
        authority: &GroupAuthority,
        created_at: UnixTimestamp,
    ) -> Result<Event, GroupError> {
        self.sign_payload(&Self::admin_list_snapshot_payload(
            group_id, projection, authority, created_at,
        )?)
    }

    pub fn build_join_accepted(
        &self,
        group_id: &GroupId,
        target_pubkey: &PublicKeyHex,
        created_at: UnixTimestamp,
    ) -> Result<Event, GroupError> {
        self.sign_payload(&Self::join_accepted_payload(
            group_id,
            target_pubkey,
            created_at,
        ))
    }

    pub fn build_leave_accepted(
        &self,
        group_id: &GroupId,
        target_pubkey: &PublicKeyHex,
        created_at: UnixTimestamp,
    ) -> Result<Event, GroupError> {
        self.sign_payload(&Self::leave_accepted_payload(
            group_id,
            target_pubkey,
            created_at,
        ))
    }
}

fn metadata_tags(
    group_id: &GroupId,
    metadata: &GroupMetadata,
) -> Result<Vec<Vec<String>>, GroupError> {
    let mut tags = vec![tag_values(["d".to_owned(), group_id.as_str().to_owned()])];
    if let Some(name) = metadata.name() {
        tags.push(tag_values(["name".to_owned(), name.to_owned()]));
    }
    if let Some(picture) = metadata.picture() {
        tags.push(tag_values(["picture".to_owned(), picture.to_owned()]));
    }
    if let Some(about) = metadata.about() {
        tags.push(tag_values(["about".to_owned(), about.to_owned()]));
    }
    if metadata.private() {
        tags.push(tag_values(["private".to_owned()]));
    }
    if metadata.restricted() {
        tags.push(tag_values(["restricted".to_owned()]));
    }
    if metadata.hidden() {
        tags.push(tag_values(["hidden".to_owned()]));
    }
    if metadata.closed() {
        tags.push(tag_values(["closed".to_owned()]));
    }
    match metadata.supported_kinds() {
        SupportedKinds::UnspecifiedAll => {}
        SupportedKinds::None => tags.push(tag_values(["supported_kinds".to_owned()])),
        SupportedKinds::Only(kinds) => {
            let mut tag = vec!["supported_kinds".to_owned()];
            tag.extend(kinds.iter().map(|kind| kind.as_u32().to_string()));
            tags.push(tag);
        }
    }
    for tag in &tags {
        Tag::new(tag.clone()).map_err(GroupError::internal)?;
    }
    Ok(tags)
}

fn membership_payload(
    kind: u32,
    group_id: &GroupId,
    target_pubkey: &PublicKeyHex,
    created_at: UnixTimestamp,
) -> GroupOutboxPayload {
    GroupOutboxPayload::new(
        kind,
        created_at,
        vec![
            tag_values(["h".to_owned(), group_id.as_str().to_owned()]),
            tag_values(["p".to_owned(), target_pubkey.as_str().to_owned()]),
        ],
        "",
    )
}

fn tag_values<const N: usize>(values: [String; N]) -> Vec<String> {
    values.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::GroupGeneratedEventBuilder;
    use crate::{
        GroupAuthority, GroupId, GroupMetadata, GroupProjection, GroupState, KIND_GROUP_ADMINS,
        KIND_GROUP_MEMBERS, KIND_GROUP_METADATA, KIND_GROUP_PUT_USER, KIND_GROUP_REMOVE_USER,
        MemberState, MemberStatus, ProjectionOrderTuple, StoreOffset,
    };
    use tangle_crypto::{RelaySigner, verify_event_signature};
    use tangle_protocol::{EventId, PublicKeyHex, UnixTimestamp};

    #[test]
    fn generated_metadata_event_is_relay_signed() {
        let builder = builder();
        let group = group_state("Farm", GroupMetadata::empty());
        let event = builder
            .build_metadata_snapshot(&group, UnixTimestamp::new(20))
            .expect("event");

        assert_eq!(event.unsigned().kind().as_u32(), KIND_GROUP_METADATA);
        assert_eq!(event.unsigned().pubkey(), builder.relay_pubkey());
        assert!(has_tag(&event, &["d", "Farm"]));
        verify_event_signature(&event).expect("signature");
    }

    #[test]
    fn generated_admin_event_includes_configured_and_override_admins() {
        let builder = builder();
        let group_id = GroupId::new("Farm").expect("group");
        let owner = pubkey("1");
        let admin = pubkey("2");
        let override_member = pubkey("3");
        let mut projection = GroupProjection::new();
        projection.put_member(
            group_id.clone(),
            MemberState::new(
                override_member.clone(),
                MemberStatus::Member,
                [crate::RoleName::permanent_relay_override()]
                    .into_iter()
                    .collect(),
                event_id("30"),
                tuple(30, "30", 3),
            ),
        );
        let event = builder
            .build_admin_list_snapshot(
                &group_id,
                &projection,
                &GroupAuthority::new([owner.clone()], [admin.clone()]),
                UnixTimestamp::new(20),
            )
            .expect("event");

        assert_eq!(event.unsigned().kind().as_u32(), KIND_GROUP_ADMINS);
        for pubkey in [owner, admin, override_member] {
            assert!(has_tag(&event, &["p", pubkey.as_str()]));
        }
        verify_event_signature(&event).expect("signature");
    }

    #[test]
    fn generated_member_snapshot_is_capped() {
        let group_id = GroupId::new("Farm").expect("group");
        let mut projection = GroupProjection::new();
        projection.put_member(
            group_id.clone(),
            MemberState::new(
                pubkey("1"),
                MemberStatus::Member,
                Default::default(),
                event_id("10"),
                tuple(10, "10", 1),
            ),
        );

        let payload = GroupGeneratedEventBuilder::member_list_snapshot_payload(
            &group_id,
            &projection,
            UnixTimestamp::new(20),
            1,
        )
        .expect("payload")
        .expect("under cap");
        assert_eq!(payload.generated_kind(), KIND_GROUP_MEMBERS);
        assert!(
            GroupGeneratedEventBuilder::member_list_snapshot_payload(
                &group_id,
                &projection,
                UnixTimestamp::new(20),
                0
            )
            .expect("payload")
            .is_none()
        );
    }

    #[test]
    fn generated_membership_events_use_group_and_target_tags() {
        let builder = builder();
        let group_id = GroupId::new("Farm").expect("group");
        let member = pubkey("4");
        let join = builder
            .build_join_accepted(&group_id, &member, UnixTimestamp::new(20))
            .expect("join");
        let leave = builder
            .build_leave_accepted(&group_id, &member, UnixTimestamp::new(21))
            .expect("leave");

        assert_eq!(join.unsigned().kind().as_u32(), KIND_GROUP_PUT_USER);
        assert_eq!(leave.unsigned().kind().as_u32(), KIND_GROUP_REMOVE_USER);
        for event in [join, leave] {
            assert!(has_tag(&event, &["h", "Farm"]));
            assert!(has_tag(&event, &["p", member.as_str()]));
            verify_event_signature(&event).expect("signature");
        }
    }

    #[test]
    fn generated_pocket_events_have_stable_ids_and_verify() {
        let builder = builder();
        let group_id = GroupId::new("Farm").expect("group");
        let group = group_state("Farm", GroupMetadata::empty());
        let member = pubkey("4");
        let owner = pubkey("1");
        let admin = pubkey("2");
        let metadata = builder
            .sign_payload_pocket(
                &GroupGeneratedEventBuilder::metadata_snapshot_payload(
                    &group,
                    UnixTimestamp::new(20),
                )
                .expect("payload"),
            )
            .expect("metadata");
        let admins = builder
            .sign_payload_pocket(
                &GroupGeneratedEventBuilder::admin_list_snapshot_payload(
                    &group_id,
                    &GroupProjection::new(),
                    &GroupAuthority::new([owner.clone()], [admin.clone()]),
                    UnixTimestamp::new(20),
                )
                .expect("payload"),
            )
            .expect("admins");
        let mut projection = GroupProjection::new();
        projection.put_member(
            group_id.clone(),
            MemberState::new(
                member.clone(),
                MemberStatus::Member,
                Default::default(),
                event_id("30"),
                tuple(30, "30", 3),
            ),
        );
        let members = builder
            .sign_payload_pocket(
                &GroupGeneratedEventBuilder::member_list_snapshot_payload(
                    &group_id,
                    &projection,
                    UnixTimestamp::new(20),
                    1,
                )
                .expect("payload")
                .expect("members"),
            )
            .expect("members");
        let join = builder
            .sign_payload_pocket(&GroupGeneratedEventBuilder::join_accepted_payload(
                &group_id,
                &member,
                UnixTimestamp::new(20),
            ))
            .expect("join");
        let leave = builder
            .sign_payload_pocket(&GroupGeneratedEventBuilder::leave_accepted_payload(
                &group_id,
                &member,
                UnixTimestamp::new(21),
            ))
            .expect("leave");

        for (event, kind, event_id, expected_tags) in [
            (
                metadata,
                KIND_GROUP_METADATA,
                "b107997a285780bc383ee5aadc0a0eefc46734914103d80f765a46543622782a",
                vec![vec!["d", "Farm"]],
            ),
            (
                admins,
                KIND_GROUP_ADMINS,
                "f7a2e2a721877794dbd367208eec08bd487cf1955ad60cb615ad77e67b0f66e3",
                vec![
                    vec!["d", "Farm"],
                    vec!["p", owner.as_str()],
                    vec!["p", admin.as_str()],
                ],
            ),
            (
                members,
                KIND_GROUP_MEMBERS,
                "19aa593a5e6e34cda72286e75aef520c05b56eed07fdee71f0d63b3efee3f814",
                vec![vec!["d", "Farm"], vec!["p", member.as_str()]],
            ),
            (
                join,
                KIND_GROUP_PUT_USER,
                "fcea9360ebfcae11580ce179bffd235dbcdf8093c223986780c0635c9fd720e3",
                vec![vec!["h", "Farm"], vec!["p", member.as_str()]],
            ),
            (
                leave,
                KIND_GROUP_REMOVE_USER,
                "bcba4eb36d55752f9274bf8a3118822a5ac3479fdd23b86b592514c945bd7ee8",
                vec![vec!["h", "Farm"], vec!["p", member.as_str()]],
            ),
        ] {
            event.verify().expect("verify");
            assert_eq!(event.id().as_hex_string(), event_id);
            assert_eq!(u32::from(event.kind().as_u16()), kind);
            assert_eq!(
                event.pubkey().as_hex_string(),
                builder.relay_pubkey().as_str()
            );
            assert_eq!(event.content(), b"");
            for expected in expected_tags {
                assert!(has_pocket_tag(&event, &expected));
            }
        }
    }

    fn has_tag(event: &tangle_protocol::Event, expected: &[&str]) -> bool {
        event.unsigned().tags().iter().any(|tag| {
            tag.values()
                .iter()
                .map(String::as_str)
                .eq(expected.iter().copied())
        })
    }

    fn has_pocket_tag(event: &pocket_types::Event, expected: &[&str]) -> bool {
        event.tags().expect("tags").iter().any(|tag| {
            tag.map(|value| std::str::from_utf8(value).expect("tag"))
                .eq(expected.iter().copied())
        })
    }

    fn builder() -> GroupGeneratedEventBuilder {
        GroupGeneratedEventBuilder::new(RelaySigner::from_secret_hex(&"7".repeat(64)).expect("key"))
    }

    fn group_state(group_id: &str, metadata: GroupMetadata) -> GroupState {
        GroupState::new(
            GroupId::new(group_id).expect("group"),
            metadata,
            pubkey("9"),
            event_id("10"),
            tuple(10, "10", 1),
        )
    }

    fn pubkey(suffix: &str) -> PublicKeyHex {
        PublicKeyHex::new(&suffix.repeat(64)).expect("pubkey")
    }

    fn tuple(created_at: u64, suffix: &str, offset: u64) -> ProjectionOrderTuple {
        ProjectionOrderTuple::new(
            UnixTimestamp::new(created_at),
            event_id(suffix),
            StoreOffset::new(offset),
        )
    }

    fn event_id(suffix: &str) -> EventId {
        let mut value = "0".repeat(64 - suffix.len());
        value.push_str(suffix);
        EventId::new(&value).expect("event")
    }
}
