use std::collections::BTreeSet;

use crate::{
    Capability, CapabilitySet, GroupError, GroupErrorKind, GroupEventClass, GroupId,
    GroupLifecycleState, GroupProjection, KIND_GROUP_CREATE_GROUP, KIND_GROUP_CREATE_INVITE,
    KIND_GROUP_DELETE_EVENT, KIND_GROUP_DELETE_GROUP, KIND_GROUP_EDIT_METADATA,
    KIND_GROUP_JOIN_REQUEST, KIND_GROUP_LEAVE_REQUEST, KIND_GROUP_PUT_USER, KIND_GROUP_REMOVE_USER,
    MemberStatus, RoleDefinition, RoleName, SupportedKinds, event_view::GroupEventView,
    require_group_auth_as_author, resolve_capabilities,
};
use tangle_protocol::PublicKeyHex;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GroupAuthority {
    owner_pubkeys: BTreeSet<PublicKeyHex>,
    admin_pubkeys: BTreeSet<PublicKeyHex>,
}

impl GroupAuthority {
    pub fn new(
        owner_pubkeys: impl IntoIterator<Item = PublicKeyHex>,
        admin_pubkeys: impl IntoIterator<Item = PublicKeyHex>,
    ) -> Self {
        Self {
            owner_pubkeys: owner_pubkeys.into_iter().collect(),
            admin_pubkeys: admin_pubkeys.into_iter().collect(),
        }
    }

    pub fn empty() -> Self {
        Self::default()
    }

    pub fn is_owner(&self, pubkey: &PublicKeyHex) -> bool {
        self.owner_pubkeys.contains(pubkey)
    }

    pub fn owner_pubkeys(&self) -> &BTreeSet<PublicKeyHex> {
        &self.owner_pubkeys
    }

    pub fn admin_pubkeys(&self) -> &BTreeSet<PublicKeyHex> {
        &self.admin_pubkeys
    }

    pub fn is_admin(&self, pubkey: &PublicKeyHex) -> bool {
        self.admin_pubkeys.contains(pubkey) || self.is_owner(pubkey)
    }

    pub fn is_permanent_admin(&self, pubkey: &PublicKeyHex) -> bool {
        self.is_admin(pubkey)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupWriteDecision {
    Accept,
    IgnoreNonGroup,
}

#[derive(Debug, Clone, Copy)]
pub struct GroupWritePolicy<'a> {
    projection: &'a GroupProjection,
    authority: &'a GroupAuthority,
}

impl<'a> GroupWritePolicy<'a> {
    pub fn new(projection: &'a GroupProjection, authority: &'a GroupAuthority) -> Self {
        Self {
            projection,
            authority,
        }
    }

    pub fn check_event(
        &self,
        event: &(impl GroupEventView + ?Sized),
        class: &GroupEventClass,
        auth: &crate::GroupAuthContext,
    ) -> Result<GroupWriteDecision, GroupError> {
        require_group_auth_as_author(event, class, auth)?;
        match class {
            GroupEventClass::NonGroup => Ok(GroupWriteDecision::IgnoreNonGroup),
            GroupEventClass::RelayGeneratedSnapshot { .. } => Err(GroupError::blocked(
                GroupErrorKind::DirectRelayGeneratedSubmission,
                "relay-generated group state events cannot be submitted by clients",
            )),
            GroupEventClass::Moderation { kind, group_id } => {
                self.check_moderation_event(event, kind.as_u32(), group_id)
            }
            GroupEventClass::Normal { group_id } => self.check_normal_event(event, group_id),
        }
    }

    pub fn can_read_group(&self, group_id: &GroupId, reader: Option<&PublicKeyHex>) -> bool {
        let Some(reader) = reader else {
            return false;
        };
        self.authority.is_admin(reader) || self.is_current_member(group_id, reader)
    }

    pub fn has_relay_override(&self, group_id: &GroupId, pubkey: &PublicKeyHex) -> bool {
        if self.authority.is_admin(pubkey) {
            return true;
        }
        self.projection
            .member(group_id, pubkey)
            .filter(|member| member.status() == MemberStatus::Member)
            .is_some_and(|member| {
                member
                    .roles()
                    .contains(&RoleName::permanent_relay_override())
            })
    }

    fn check_moderation_event(
        &self,
        event: &(impl GroupEventView + ?Sized),
        kind: u32,
        group_id: &GroupId,
    ) -> Result<GroupWriteDecision, GroupError> {
        if kind == KIND_GROUP_CREATE_GROUP {
            return self.check_create_group(event, group_id);
        }
        let group = self.require_active_group(group_id)?;
        if kind == KIND_GROUP_CREATE_INVITE {
            return Err(GroupError::restricted(
                GroupErrorKind::MissingCapability,
                "invites not enabled",
            ));
        }
        let actor = event.pubkey()?;
        let required = required_capability(kind, event)?;
        if let Some(required) = required {
            self.require_capability(group_id, &actor, required)?;
        }
        if kind == KIND_GROUP_REMOVE_USER {
            let target = target_pubkey(event, "p")?;
            if self.is_protected_admin(group_id, &target) {
                return Err(GroupError::restricted(
                    GroupErrorKind::MissingCapability,
                    "permanent group admins cannot be removed",
                ));
            }
        }
        if kind == KIND_GROUP_EDIT_METADATA
            && group.metadata().hidden()
            && !self.can_read_group(group_id, Some(&actor))
        {
            return Err(non_enumerating_group_error());
        }
        Ok(GroupWriteDecision::Accept)
    }

    fn check_create_group(
        &self,
        event: &(impl GroupEventView + ?Sized),
        group_id: &GroupId,
    ) -> Result<GroupWriteDecision, GroupError> {
        if !self.authority.is_owner(&event.pubkey()?) {
            return Err(GroupError::restricted(
                GroupErrorKind::MissingCapability,
                "group creation is restricted to relay owners",
            ));
        }
        if self.projection.tombstone(group_id).is_some() {
            return Err(GroupError::blocked(
                GroupErrorKind::GroupDeleted,
                "group is deleted",
            ));
        }
        if self.projection.group(group_id).is_some() {
            return Err(GroupError::invalid(
                GroupErrorKind::GroupAlreadyExists,
                "group already exists",
            ));
        }
        Ok(GroupWriteDecision::Accept)
    }

    fn check_normal_event(
        &self,
        event: &(impl GroupEventView + ?Sized),
        group_id: &GroupId,
    ) -> Result<GroupWriteDecision, GroupError> {
        let group = self.require_active_group(group_id)?;
        match event.kind_u32() {
            KIND_GROUP_JOIN_REQUEST => self.check_join(event, group_id),
            KIND_GROUP_LEAVE_REQUEST => self.check_leave(event, group_id),
            _ => {
                let actor = event.pubkey()?;
                if group.metadata().restricted() && !self.can_read_group(group_id, Some(&actor)) {
                    return Err(non_enumerating_group_error());
                }
                let kind = event.kind()?;
                match group.metadata().supported_kinds() {
                    SupportedKinds::UnspecifiedAll => {}
                    SupportedKinds::None => {
                        return Err(GroupError::restricted(
                            GroupErrorKind::UnsupportedGroupKind,
                            "group does not accept normal event kinds",
                        ));
                    }
                    SupportedKinds::Only(kinds) => {
                        if !kinds.contains(&kind) {
                            return Err(GroupError::restricted(
                                GroupErrorKind::UnsupportedGroupKind,
                                "event kind is not supported by this group",
                            ));
                        }
                    }
                }
                Ok(GroupWriteDecision::Accept)
            }
        }
    }

    fn check_join(
        &self,
        event: &(impl GroupEventView + ?Sized),
        group_id: &GroupId,
    ) -> Result<GroupWriteDecision, GroupError> {
        let group = self.require_active_group(group_id)?;
        if self.is_current_member(group_id, &event.pubkey()?) {
            return Err(GroupError::invalid(
                GroupErrorKind::DuplicateMember,
                "group member already exists",
            ));
        }
        if group.metadata().closed() {
            return Err(non_enumerating_group_error());
        }
        Ok(GroupWriteDecision::Accept)
    }

    fn check_leave(
        &self,
        event: &(impl GroupEventView + ?Sized),
        group_id: &GroupId,
    ) -> Result<GroupWriteDecision, GroupError> {
        self.require_active_group(group_id)?;
        if !self.is_current_member(group_id, &event.pubkey()?) {
            return Err(GroupError::invalid(
                GroupErrorKind::DuplicateMember,
                "group member does not exist",
            ));
        }
        Ok(GroupWriteDecision::Accept)
    }

    fn require_active_group(&self, group_id: &GroupId) -> Result<&crate::GroupState, GroupError> {
        let Some(group) = self.projection.group(group_id) else {
            return Err(non_enumerating_group_error());
        };
        if group.lifecycle() == GroupLifecycleState::Deleted
            || self.projection.tombstone(group_id).is_some()
        {
            return Err(GroupError::blocked(
                GroupErrorKind::GroupDeleted,
                "group is deleted",
            ));
        }
        Ok(group)
    }

    fn require_capability(
        &self,
        group_id: &GroupId,
        actor: &PublicKeyHex,
        required: Capability,
    ) -> Result<(), GroupError> {
        if self.authority.is_admin(actor) {
            return Ok(());
        }
        let capabilities = self.actor_capabilities(group_id, actor)?;
        if capabilities.contains(required) {
            return Ok(());
        }
        Err(GroupError::restricted(
            GroupErrorKind::MissingCapability,
            format!("missing group capability {}", required.as_str()),
        ))
    }

    fn actor_capabilities(
        &self,
        group_id: &GroupId,
        actor: &PublicKeyHex,
    ) -> Result<CapabilitySet, GroupError> {
        let Some(member) = self.projection.member(group_id, actor) else {
            return Ok(CapabilitySet::empty());
        };
        if member.status() != MemberStatus::Member {
            return Ok(CapabilitySet::empty());
        }
        let definitions = self
            .projection
            .roles()
            .iter()
            .filter(|((candidate_group, _), _)| candidate_group == group_id)
            .map(|(_, role)| role.definition())
            .collect::<Vec<&RoleDefinition>>();
        resolve_capabilities(definitions, member.roles().iter())
    }

    fn is_current_member(&self, group_id: &GroupId, pubkey: &PublicKeyHex) -> bool {
        self.projection
            .member(group_id, pubkey)
            .is_some_and(|member| member.status() == MemberStatus::Member)
    }

    fn is_protected_admin(&self, group_id: &GroupId, pubkey: &PublicKeyHex) -> bool {
        self.authority.is_permanent_admin(pubkey) || self.has_relay_override(group_id, pubkey)
    }
}

pub fn non_enumerating_group_error() -> GroupError {
    GroupError::restricted(GroupErrorKind::GroupUnavailable, "group is unavailable")
}

fn required_capability(
    kind: u32,
    event: &(impl GroupEventView + ?Sized),
) -> Result<Option<Capability>, GroupError> {
    match kind {
        KIND_GROUP_PUT_USER => {
            if has_role_tag(event)? {
                Ok(Some(Capability::ManageRoles))
            } else {
                Ok(Some(Capability::ManageMembers))
            }
        }
        KIND_GROUP_REMOVE_USER => Ok(Some(Capability::ManageMembers)),
        KIND_GROUP_EDIT_METADATA => Ok(Some(Capability::ManageMetadata)),
        KIND_GROUP_DELETE_EVENT => Ok(Some(Capability::DeleteEvents)),
        KIND_GROUP_DELETE_GROUP => Ok(Some(Capability::DeleteGroup)),
        KIND_GROUP_CREATE_INVITE => Ok(Some(Capability::CreateInvites)),
        _ => Ok(None),
    }
}

fn has_role_tag(event: &(impl GroupEventView + ?Sized)) -> Result<bool, GroupError> {
    let mut found = false;
    event.visit_tags(|tag| {
        if tag.first_value().is_some_and(|name| name == "role") {
            found = true;
        }
        Ok(())
    })?;
    Ok(found)
}

fn target_pubkey(
    event: &(impl GroupEventView + ?Sized),
    tag_name: &str,
) -> Result<PublicKeyHex, GroupError> {
    let mut found = None;
    event.visit_tags(|tag| {
        if tag
            .first_value()
            .is_none_or(|candidate| candidate != tag_name)
        {
            return Ok(());
        }
        let Some((_, value)) = tag.indexed_pair() else {
            return Err(GroupError::invalid(
                GroupErrorKind::MalformedTargetTag,
                format!("malformed {tag_name} target tag"),
            ));
        };
        found = Some(PublicKeyHex::new(value).map_err(|reason| {
            GroupError::invalid(
                GroupErrorKind::MalformedTargetTag,
                format!("malformed {tag_name} target tag: {reason}"),
            )
        })?);
        Ok(())
    })?;
    found.ok_or_else(|| {
        GroupError::invalid(
            GroupErrorKind::MissingTargetTag,
            format!("missing {tag_name} target tag"),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::{GroupAuthority, GroupWriteDecision, GroupWritePolicy};
    use crate::{
        Capability, CapabilitySet, GroupAuthContext, GroupErrorKind, GroupEventClass, GroupId,
        GroupMetadata, GroupMetadataFlags, GroupMetadataText, GroupProjection, GroupState,
        KIND_GROUP_CREATE_GROUP, KIND_GROUP_CREATE_INVITE, KIND_GROUP_DELETE_GROUP,
        KIND_GROUP_JOIN_REQUEST, KIND_GROUP_LEAVE_REQUEST, KIND_GROUP_REMOVE_USER, MemberState,
        MemberStatus, ProjectedRoleDefinition, ProjectionOrderTuple, RoleDefinition, RoleName,
        StoreOffset, SupportedKinds,
    };
    use tangle_protocol::{
        Event, EventId, Kind, PublicKeyHex, SignatureHex, Tag, UnixTimestamp, UnsignedEvent,
    };

    #[test]
    fn group_create_requires_relay_owner_and_unused_group_id() {
        let projection = GroupProjection::new();
        let owner = pubkey("1");
        let author = pubkey("2");
        let authority = GroupAuthority::new([owner.clone()], Vec::<PublicKeyHex>::new());
        let policy = GroupWritePolicy::new(&projection, &authority);
        let create_by_non_owner = event(KIND_GROUP_CREATE_GROUP, author.clone(), vec![h("Farm")]);
        let class = GroupEventClass::Moderation {
            kind: create_by_non_owner.unsigned().kind(),
            group_id: group("Farm"),
        };

        assert_eq!(
            policy
                .check_event(
                    &create_by_non_owner,
                    &class,
                    &GroupAuthContext::new([author.clone()])
                )
                .expect_err("owner")
                .kind(),
            GroupErrorKind::MissingCapability
        );

        let owner_event = event(KIND_GROUP_CREATE_GROUP, owner.clone(), vec![h("Farm")]);
        assert_eq!(
            policy
                .check_event(
                    &owner_event,
                    &class,
                    &GroupAuthContext::new([owner.clone()])
                )
                .expect("accept"),
            GroupWriteDecision::Accept
        );
    }

    #[test]
    fn lifecycle_policy_rejects_nonexistent_deleted_and_duplicate_groups() {
        let owner = pubkey("1");
        let mut projection = projection_with_group(
            "Farm",
            metadata(false, false, false, false, SupportedKinds::UnspecifiedAll),
            owner.clone(),
        );
        let group_id = group("Farm");
        let class = GroupEventClass::Moderation {
            kind: kind(KIND_GROUP_CREATE_GROUP),
            group_id: group_id.clone(),
        };
        let authority = GroupAuthority::new([owner.clone()], Vec::<PublicKeyHex>::new());
        let policy = GroupWritePolicy::new(&projection, &authority);
        let create = event(KIND_GROUP_CREATE_GROUP, owner.clone(), vec![h("Farm")]);

        assert_eq!(
            policy
                .check_event(&create, &class, &GroupAuthContext::new([owner.clone()]))
                .expect_err("duplicate")
                .kind(),
            GroupErrorKind::GroupAlreadyExists
        );

        let delete = event(KIND_GROUP_DELETE_GROUP, owner.clone(), vec![h("Farm")]);
        projection
            .apply_canonical_event(&delete, StoreOffset::new(2), Default::default())
            .expect("delete");
        let authority = GroupAuthority::new([owner.clone()], Vec::<PublicKeyHex>::new());
        let policy = GroupWritePolicy::new(&projection, &authority);
        let normal = event(1, owner.clone(), vec![h("Farm")]);

        assert_eq!(
            policy
                .check_event(
                    &normal,
                    &GroupEventClass::Normal {
                        group_id: group_id.clone()
                    },
                    &GroupAuthContext::new([owner])
                )
                .expect_err("deleted")
                .kind(),
            GroupErrorKind::GroupDeleted
        );
    }

    #[test]
    fn restricted_and_supported_kind_rules_gate_normal_writes() {
        let owner = pubkey("1");
        let member = pubkey("2");
        let outsider = pubkey("3");
        let mut projection = projection_with_group(
            "Farm",
            metadata(
                true,
                false,
                false,
                false,
                SupportedKinds::Only([kind(1)].into_iter().collect()),
            ),
            owner.clone(),
        );
        put_member(&mut projection, "Farm", member.clone(), []);
        let authority = GroupAuthority::new([owner], Vec::<PublicKeyHex>::new());
        let policy = GroupWritePolicy::new(&projection, &authority);

        assert_eq!(
            policy
                .check_event(
                    &event(1, outsider.clone(), vec![h("Farm")]),
                    &GroupEventClass::Normal {
                        group_id: group("Farm")
                    },
                    &GroupAuthContext::new([outsider.clone()])
                )
                .expect_err("restricted")
                .kind(),
            GroupErrorKind::GroupUnavailable
        );
        assert_eq!(
            policy
                .check_event(
                    &event(7, member.clone(), vec![h("Farm")]),
                    &GroupEventClass::Normal {
                        group_id: group("Farm")
                    },
                    &GroupAuthContext::new([member])
                )
                .expect_err("kind")
                .kind(),
            GroupErrorKind::UnsupportedGroupKind
        );
    }

    #[test]
    fn moderation_policy_uses_roles_and_protects_permanent_admins() {
        let owner = pubkey("1");
        let moderator = pubkey("2");
        let protected = pubkey("3");
        let target = pubkey("4");
        let mut projection = projection_with_group(
            "Farm",
            metadata(false, false, false, false, SupportedKinds::UnspecifiedAll),
            owner.clone(),
        );
        let moderator_role = RoleName::new("moderator").expect("role");
        projection.put_role(
            group("Farm"),
            ProjectedRoleDefinition::new(
                RoleDefinition::new(
                    moderator_role.clone(),
                    CapabilitySet::new([Capability::ManageMembers]),
                    None,
                ),
                event_id("30"),
                tuple(30, "30", 3),
            ),
        );
        put_member(&mut projection, "Farm", moderator.clone(), [moderator_role]);
        let authority = GroupAuthority::new([owner], [protected.clone()]);
        let policy = GroupWritePolicy::new(&projection, &authority);

        assert_eq!(
            policy
                .check_event(
                    &event(
                        KIND_GROUP_REMOVE_USER,
                        moderator.clone(),
                        vec![h("Farm"), p(&target)]
                    ),
                    &GroupEventClass::Moderation {
                        kind: kind(KIND_GROUP_REMOVE_USER),
                        group_id: group("Farm")
                    },
                    &GroupAuthContext::new([moderator.clone()])
                )
                .expect("moderator"),
            GroupWriteDecision::Accept
        );
        assert_eq!(
            policy
                .check_event(
                    &event(
                        KIND_GROUP_REMOVE_USER,
                        moderator.clone(),
                        vec![h("Farm"), p(&protected)]
                    ),
                    &GroupEventClass::Moderation {
                        kind: kind(KIND_GROUP_REMOVE_USER),
                        group_id: group("Farm")
                    },
                    &GroupAuthContext::new([moderator])
                )
                .expect_err("protected")
                .kind(),
            GroupErrorKind::MissingCapability
        );
    }

    #[test]
    fn join_and_leave_policy_is_immediate_and_membership_based() {
        let owner = pubkey("1");
        let joiner = pubkey("2");
        let member = pubkey("3");
        let mut projection = projection_with_group(
            "Farm",
            metadata(false, false, false, false, SupportedKinds::UnspecifiedAll),
            owner.clone(),
        );
        put_member(&mut projection, "Farm", member.clone(), []);
        let authority = GroupAuthority::new([owner], Vec::<PublicKeyHex>::new());
        let policy = GroupWritePolicy::new(&projection, &authority);

        assert_eq!(
            policy
                .check_event(
                    &event(KIND_GROUP_JOIN_REQUEST, joiner.clone(), vec![h("Farm")]),
                    &GroupEventClass::Normal {
                        group_id: group("Farm")
                    },
                    &GroupAuthContext::new([joiner])
                )
                .expect("join"),
            GroupWriteDecision::Accept
        );
        assert_eq!(
            policy
                .check_event(
                    &event(KIND_GROUP_JOIN_REQUEST, member.clone(), vec![h("Farm")]),
                    &GroupEventClass::Normal {
                        group_id: group("Farm")
                    },
                    &GroupAuthContext::new([member.clone()])
                )
                .expect_err("duplicate join")
                .kind(),
            GroupErrorKind::DuplicateMember
        );
        assert_eq!(
            policy
                .check_event(
                    &event(KIND_GROUP_LEAVE_REQUEST, member.clone(), vec![h("Farm")]),
                    &GroupEventClass::Normal {
                        group_id: group("Farm")
                    },
                    &GroupAuthContext::new([member])
                )
                .expect("leave"),
            GroupWriteDecision::Accept
        );
    }

    #[test]
    fn closed_group_denies_public_join_strictly() {
        let owner = pubkey("1");
        let joiner = pubkey("2");
        let projection = projection_with_group(
            "Farm",
            metadata(false, false, false, true, SupportedKinds::UnspecifiedAll),
            owner.clone(),
        );
        let authority = GroupAuthority::new([owner], Vec::<PublicKeyHex>::new());
        let policy = GroupWritePolicy::new(&projection, &authority);

        assert_eq!(
            policy
                .check_event(
                    &event(KIND_GROUP_JOIN_REQUEST, joiner.clone(), vec![h("Farm")]),
                    &GroupEventClass::Normal {
                        group_id: group("Farm")
                    },
                    &GroupAuthContext::new([joiner])
                )
                .expect_err("closed")
                .kind(),
            GroupErrorKind::GroupUnavailable
        );
    }

    #[test]
    fn invite_creation_is_rejected_while_invites_are_disabled() {
        let owner = pubkey("1");
        let projection = projection_with_group(
            "Farm",
            metadata(false, false, false, false, SupportedKinds::UnspecifiedAll),
            owner.clone(),
        );
        let authority = GroupAuthority::new([owner.clone()], Vec::<PublicKeyHex>::new());
        let policy = GroupWritePolicy::new(&projection, &authority);
        let invite = event(KIND_GROUP_CREATE_INVITE, owner.clone(), vec![h("Farm")]);

        let error = policy
            .check_event(
                &invite,
                &GroupEventClass::Moderation {
                    kind: kind(KIND_GROUP_CREATE_INVITE),
                    group_id: group("Farm"),
                },
                &GroupAuthContext::new([owner]),
            )
            .expect_err("invite");

        assert_eq!(error.kind(), GroupErrorKind::MissingCapability);
        assert_eq!(error.prefixed_message(), "restricted: invites not enabled");
    }

    fn projection_with_group(
        group_id: &str,
        metadata: GroupMetadata,
        author: PublicKeyHex,
    ) -> GroupProjection {
        let mut projection = GroupProjection::new();
        projection.put_group(GroupState::new(
            group(group_id),
            metadata,
            author,
            event_id("10"),
            tuple(10, "10", 1),
        ));
        projection
    }

    fn put_member(
        projection: &mut GroupProjection,
        group_id: &str,
        pubkey: PublicKeyHex,
        roles: impl IntoIterator<Item = RoleName>,
    ) {
        projection.put_member(
            group(group_id),
            MemberState::new(
                pubkey,
                MemberStatus::Member,
                roles.into_iter().collect(),
                event_id("20"),
                tuple(20, "20", 2),
            ),
        );
    }

    fn metadata(
        restricted: bool,
        private: bool,
        hidden: bool,
        closed: bool,
        supported_kinds: SupportedKinds,
    ) -> GroupMetadata {
        GroupMetadata::from_parts(
            GroupMetadataText::empty(),
            GroupMetadataFlags::new(private, restricted, hidden, closed),
            supported_kinds,
        )
    }

    fn event(kind_value: u32, pubkey: PublicKeyHex, tags: Vec<Tag>) -> Event {
        Event::new(
            event_id("01"),
            UnsignedEvent::new(pubkey, UnixTimestamp::new(1), kind(kind_value), tags, ""),
            SignatureHex::new(&"2".repeat(128)).expect("sig"),
        )
    }

    fn h(group_id: &str) -> Tag {
        Tag::from_parts("h", &[group_id]).expect("h")
    }

    fn p(pubkey: &PublicKeyHex) -> Tag {
        Tag::from_parts("p", &[pubkey.as_str()]).expect("p")
    }

    fn group(value: &str) -> GroupId {
        GroupId::new(value).expect("group")
    }

    fn pubkey(suffix: &str) -> PublicKeyHex {
        PublicKeyHex::new(&suffix.repeat(64)).expect("pubkey")
    }

    fn kind(value: u32) -> Kind {
        Kind::new(value.into()).expect("kind")
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
