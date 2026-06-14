use crate::{
    GroupAuthority, GroupError, GroupEventClass, GroupId, GroupLimitsConfig, GroupProjection,
    KIND_GROUP_ADMINS, KIND_GROUP_DELETE_GROUP, KIND_GROUP_METADATA, MemberStatus,
    classify_group_event, event_view::GroupEventView, non_enumerating_group_error,
};
use tangle_protocol::{EventId, PublicKeyHex};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupReadDecision {
    Visible,
    Hidden,
}

#[derive(Debug, Clone, Copy)]
pub struct GroupReadGate<'a> {
    projection: &'a GroupProjection,
    authority: &'a GroupAuthority,
}

impl<'a> GroupReadGate<'a> {
    pub fn new(projection: &'a GroupProjection, authority: &'a GroupAuthority) -> Self {
        Self {
            projection,
            authority,
        }
    }

    pub fn screen_event(
        &self,
        event: &(impl GroupEventView + ?Sized),
        reader: Option<&PublicKeyHex>,
        limits: GroupLimitsConfig,
    ) -> Result<GroupReadDecision, GroupError> {
        let event_id = event.id()?;
        if self.projection.event_deletion(&event_id).is_some() {
            return Ok(GroupReadDecision::Hidden);
        }
        match classify_group_event(event, limits)? {
            GroupEventClass::NonGroup => Ok(GroupReadDecision::Visible),
            GroupEventClass::Normal { group_id } => self.screen_normal_event(&group_id, reader),
            GroupEventClass::Moderation { group_id, .. } => {
                if event.kind_u32() == KIND_GROUP_DELETE_GROUP {
                    self.screen_delete_group_marker(&event_id, &group_id, reader)
                } else {
                    self.screen_normal_event(&group_id, reader)
                }
            }
            GroupEventClass::RelayGeneratedSnapshot { kind, group_id } => {
                self.screen_snapshot_event(kind.as_u32(), &group_id, reader)
            }
        }
    }

    pub fn require_visible(
        &self,
        event: &(impl GroupEventView + ?Sized),
        reader: Option<&PublicKeyHex>,
        limits: GroupLimitsConfig,
    ) -> Result<(), GroupError> {
        match self.screen_event(event, reader, limits)? {
            GroupReadDecision::Visible => Ok(()),
            GroupReadDecision::Hidden => Err(non_enumerating_group_error()),
        }
    }

    fn screen_snapshot_event(
        &self,
        kind: u32,
        group_id: &GroupId,
        reader: Option<&PublicKeyHex>,
    ) -> Result<GroupReadDecision, GroupError> {
        let Some(group) = self.projection.group(group_id) else {
            return Ok(GroupReadDecision::Hidden);
        };
        if self.projection.tombstone(group_id).is_some() {
            return Ok(GroupReadDecision::Hidden);
        }
        if group.metadata().hidden() && !self.can_read_group(group_id, reader) {
            return Ok(GroupReadDecision::Hidden);
        }
        if group.metadata().private()
            && !is_public_when_private_snapshot(kind)
            && !self.can_read_group(group_id, reader)
        {
            return Ok(GroupReadDecision::Hidden);
        }
        Ok(GroupReadDecision::Visible)
    }

    fn screen_delete_group_marker(
        &self,
        event_id: &EventId,
        group_id: &GroupId,
        reader: Option<&PublicKeyHex>,
    ) -> Result<GroupReadDecision, GroupError> {
        let Some(group) = self.projection.group(group_id) else {
            return Ok(GroupReadDecision::Hidden);
        };
        if self
            .projection
            .tombstone(group_id)
            .is_none_or(|tombstone| tombstone.delete_event_id() != event_id)
        {
            return self.screen_normal_event(group_id, reader);
        }
        if (group.metadata().hidden() || group.metadata().private())
            && !self.can_read_group(group_id, reader)
        {
            return Ok(GroupReadDecision::Hidden);
        }
        Ok(GroupReadDecision::Visible)
    }

    fn screen_normal_event(
        &self,
        group_id: &GroupId,
        reader: Option<&PublicKeyHex>,
    ) -> Result<GroupReadDecision, GroupError> {
        let Some(group) = self.projection.group(group_id) else {
            return Ok(GroupReadDecision::Hidden);
        };
        if self.projection.tombstone(group_id).is_some() {
            return Ok(GroupReadDecision::Hidden);
        }
        if (group.metadata().hidden() || group.metadata().private())
            && !self.can_read_group(group_id, reader)
        {
            return Ok(GroupReadDecision::Hidden);
        }
        Ok(GroupReadDecision::Visible)
    }

    fn can_read_group(&self, group_id: &GroupId, reader: Option<&PublicKeyHex>) -> bool {
        let Some(reader) = reader else {
            return false;
        };
        if self.authority.is_admin(reader) {
            return true;
        }
        self.projection
            .member(group_id, reader)
            .is_some_and(|member| member.status() == MemberStatus::Member)
    }
}

fn is_public_when_private_snapshot(kind: u32) -> bool {
    matches!(kind, KIND_GROUP_METADATA | KIND_GROUP_ADMINS)
}

#[cfg(test)]
mod tests {
    use super::{GroupReadDecision, GroupReadGate};
    use crate::{
        GroupAuthority, GroupEventDeletion, GroupId, GroupMetadata, GroupMetadataFlags,
        GroupMetadataText, GroupProjection, GroupState, GroupTombstone, KIND_GROUP_ADMINS,
        KIND_GROUP_DELETE_GROUP, KIND_GROUP_MEMBERS, KIND_GROUP_METADATA, MemberState,
        MemberStatus, ProjectionOrderTuple, StoreOffset, SupportedKinds,
    };
    use pocket_types::Event as PocketEvent;
    use tangle_protocol::{
        Event, EventId, Kind, PublicKeyHex, SignatureHex, Tag, UnixTimestamp, UnsignedEvent,
        event_to_value,
    };

    #[test]
    fn read_gate_allows_public_group_events_and_hides_unknown_groups() {
        let owner = pubkey("1");
        let projection = projection_with_group("Farm", metadata(false, false, false, false), owner);
        let authority = GroupAuthority::empty();
        let gate = GroupReadGate::new(&projection, &authority);

        assert_eq!(
            gate.screen_event(&event(1, vec![h("Farm")]), None, Default::default())
                .expect("public"),
            GroupReadDecision::Visible
        );
        assert_eq!(
            gate.screen_event(&event(1, vec![h("Other")]), None, Default::default())
                .expect("unknown"),
            GroupReadDecision::Hidden
        );
    }

    #[test]
    fn read_gate_screens_pocket_events_through_event_view() {
        let owner = pubkey("1");
        let projection = projection_with_group("Farm", metadata(false, false, false, false), owner);
        let authority = GroupAuthority::empty();
        let gate = GroupReadGate::new(&projection, &authority);
        let event = event(1, vec![h("Farm")]);
        let mut buffer = vec![0; 4096];

        assert_eq!(
            gate.screen_event(pocket_event(&event, &mut buffer), None, Default::default())
                .expect("pocket"),
            GroupReadDecision::Visible
        );
    }

    #[test]
    fn read_gate_hides_hidden_and_private_group_events_from_non_members() {
        let owner = pubkey("1");
        let member = pubkey("2");
        let outsider = pubkey("3");
        let mut projection =
            projection_with_group("Farm", metadata(true, false, true, false), owner.clone());
        put_member(&mut projection, "Farm", member.clone());
        let authority = GroupAuthority::new([owner.clone()], Vec::<PublicKeyHex>::new());
        let gate = GroupReadGate::new(&projection, &authority);

        assert_eq!(
            gate.screen_event(
                &event(1, vec![h("Farm")]),
                Some(&outsider),
                Default::default()
            )
            .expect("outsider"),
            GroupReadDecision::Hidden
        );
        assert_eq!(
            gate.screen_event(
                &event(1, vec![h("Farm")]),
                Some(&member),
                Default::default()
            )
            .expect("member"),
            GroupReadDecision::Visible
        );
        assert_eq!(
            gate.screen_event(&event(1, vec![h("Farm")]), Some(&owner), Default::default())
                .expect("owner"),
            GroupReadDecision::Visible
        );
    }

    #[test]
    fn read_gate_splits_private_and_hidden_snapshot_visibility() {
        let owner = pubkey("1");
        let projection =
            projection_with_group("Farm", metadata(true, false, false, false), owner.clone());
        let authority = GroupAuthority::new([owner.clone()], Vec::<PublicKeyHex>::new());
        let gate = GroupReadGate::new(&projection, &authority);

        assert_eq!(
            gate.screen_event(
                &event(KIND_GROUP_METADATA, vec![d("Farm")]),
                None,
                Default::default()
            )
            .expect("private metadata"),
            GroupReadDecision::Visible
        );
        assert_eq!(
            gate.screen_event(
                &event(KIND_GROUP_ADMINS, vec![d("Farm")]),
                None,
                Default::default()
            )
            .expect("private admins"),
            GroupReadDecision::Visible
        );
        assert_eq!(
            gate.screen_event(
                &event(KIND_GROUP_MEMBERS, vec![d("Farm")]),
                None,
                Default::default()
            )
            .expect("private members"),
            GroupReadDecision::Hidden
        );
        assert_eq!(
            gate.screen_event(
                &event(KIND_GROUP_MEMBERS, vec![d("Farm")]),
                Some(&owner),
                Default::default()
            )
            .expect("owner members"),
            GroupReadDecision::Visible
        );

        let hidden_projection =
            projection_with_group("Hidden", metadata(false, false, true, false), owner.clone());
        let hidden_gate = GroupReadGate::new(&hidden_projection, &authority);
        assert_eq!(
            hidden_gate
                .screen_event(
                    &event(KIND_GROUP_METADATA, vec![d("Hidden")]),
                    None,
                    Default::default()
                )
                .expect("hidden metadata"),
            GroupReadDecision::Hidden
        );
    }

    #[test]
    fn require_visible_uses_non_enumerating_error() {
        let owner = pubkey("1");
        let projection = projection_with_group("Farm", metadata(true, false, true, false), owner);
        let authority = GroupAuthority::empty();
        let gate = GroupReadGate::new(&projection, &authority);

        assert_eq!(
            gate.require_visible(&event(1, vec![h("Farm")]), None, Default::default())
                .expect_err("hidden")
                .message(),
            "group is unavailable"
        );
    }

    #[test]
    fn read_gate_hides_deleted_target_events() {
        let owner = pubkey("1");
        let mut projection =
            projection_with_group("Farm", metadata(false, false, false, false), owner);
        let target = event(1, vec![h("Farm")]);
        projection.put_event_deletion(GroupEventDeletion::new(
            GroupId::new("Farm").expect("group"),
            target.id().clone(),
            event_id("20"),
            UnixTimestamp::new(20),
            pubkey("2"),
            tuple(20, "20", 2),
        ));
        let authority = GroupAuthority::empty();
        let gate = GroupReadGate::new(&projection, &authority);

        assert_eq!(
            gate.screen_event(&target, None, Default::default())
                .expect("deleted"),
            GroupReadDecision::Hidden
        );
    }

    #[test]
    fn read_gate_keeps_group_delete_marker_under_group_visibility_policy() {
        let owner = pubkey("1");
        let mut projection =
            projection_with_group("Farm", metadata(false, false, false, false), owner);
        let marker = event(KIND_GROUP_DELETE_GROUP, vec![h("Farm")]);
        projection.put_tombstone(GroupTombstone::new(
            GroupId::new("Farm").expect("group"),
            marker.id().clone(),
            marker.unsigned().created_at(),
            marker.unsigned().pubkey().clone(),
            tuple(30, "01", 3),
        ));
        let authority = GroupAuthority::empty();
        let gate = GroupReadGate::new(&projection, &authority);

        assert_eq!(
            gate.screen_event(&marker, None, Default::default())
                .expect("marker"),
            GroupReadDecision::Visible
        );
        assert_eq!(
            gate.screen_event(&event(1, vec![h("Farm")]), None, Default::default())
                .expect("normal"),
            GroupReadDecision::Hidden
        );
    }

    fn projection_with_group(
        group_id: &str,
        metadata: GroupMetadata,
        author: PublicKeyHex,
    ) -> GroupProjection {
        let mut projection = GroupProjection::new();
        projection.put_group(GroupState::new(
            GroupId::new(group_id).expect("group"),
            metadata,
            author,
            event_id("10"),
            tuple(10, "10", 1),
        ));
        projection
    }

    fn put_member(projection: &mut GroupProjection, group_id: &str, pubkey: PublicKeyHex) {
        projection.put_member(
            GroupId::new(group_id).expect("group"),
            MemberState::new(
                pubkey,
                MemberStatus::Member,
                Default::default(),
                event_id("20"),
                tuple(20, "20", 2),
            ),
        );
    }

    fn metadata(private: bool, restricted: bool, hidden: bool, closed: bool) -> GroupMetadata {
        GroupMetadata::from_parts(
            GroupMetadataText::empty(),
            GroupMetadataFlags::new(private, restricted, hidden, closed),
            SupportedKinds::UnspecifiedAll,
        )
    }

    fn event(kind_value: u32, tags: Vec<Tag>) -> Event {
        Event::new(
            event_id("01"),
            UnsignedEvent::new(
                pubkey("9"),
                UnixTimestamp::new(1),
                Kind::new(kind_value.into()).expect("kind"),
                tags,
                "",
            ),
            SignatureHex::new(&"2".repeat(128)).expect("sig"),
        )
    }

    fn pocket_event<'a>(event: &Event, buffer: &'a mut [u8]) -> &'a PocketEvent {
        let raw = event_to_value(event).to_string();
        let (_, pocket) = PocketEvent::from_json(raw.as_bytes(), buffer).expect("pocket");
        pocket
    }

    fn h(group_id: &str) -> Tag {
        Tag::from_parts("h", &[group_id]).expect("h")
    }

    fn d(group_id: &str) -> Tag {
        Tag::from_parts("d", &[group_id]).expect("d")
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
        EventId::new(&value).expect("id")
    }
}
