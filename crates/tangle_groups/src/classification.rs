use crate::{
    GroupLimitsConfig,
    errors::GroupError,
    ids::GroupId,
    kinds::{is_moderation_kind, is_relay_generated_kind, is_user_request_kind},
    tags::{GroupTagName, extract_group_tag, has_group_identity_tag, require_group_tag},
};
use tangle_protocol::{Event, Kind};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GroupEventClass {
    NonGroup,
    Normal { group_id: GroupId },
    Moderation { kind: Kind, group_id: GroupId },
    RelayGeneratedSnapshot { kind: Kind, group_id: GroupId },
}

impl GroupEventClass {
    pub fn group_id(&self) -> Option<&GroupId> {
        match self {
            Self::NonGroup => None,
            Self::Normal { group_id }
            | Self::Moderation { group_id, .. }
            | Self::RelayGeneratedSnapshot { group_id, .. } => Some(group_id),
        }
    }

    pub fn is_group(&self) -> bool {
        !matches!(self, Self::NonGroup)
    }
}

pub fn classify_group_event(
    event: &Event,
    limits: GroupLimitsConfig,
) -> Result<GroupEventClass, GroupError> {
    let kind = event.unsigned().kind();
    if is_relay_generated_kind(kind) {
        let group_id = require_group_tag(event.unsigned().tags(), GroupTagName::D, limits)?
            .group_id()
            .clone();
        return Ok(GroupEventClass::RelayGeneratedSnapshot { kind, group_id });
    }
    if is_moderation_kind(kind) {
        let group_id = require_group_tag(event.unsigned().tags(), GroupTagName::H, limits)?
            .group_id()
            .clone();
        return Ok(GroupEventClass::Moderation { kind, group_id });
    }
    if is_user_request_kind(kind) {
        let group_id = require_group_tag(event.unsigned().tags(), GroupTagName::H, limits)?
            .group_id()
            .clone();
        return Ok(GroupEventClass::Normal { group_id });
    }
    if has_group_identity_tag(event.unsigned().tags())
        && let Some(group_tag) =
            extract_group_tag(event.unsigned().tags(), GroupTagName::H, limits)?
    {
        return Ok(GroupEventClass::Normal {
            group_id: group_tag.group_id().clone(),
        });
    }
    Ok(GroupEventClass::NonGroup)
}

#[cfg(test)]
mod tests {
    use super::{GroupEventClass, classify_group_event};
    use crate::{
        GroupErrorKind, GroupLimitsConfig, KIND_GROUP_CREATE_GROUP, KIND_GROUP_JOIN_REQUEST,
        KIND_GROUP_METADATA, KIND_GROUP_PUT_USER,
    };
    use tangle_protocol::{
        Event, EventId, Kind, PublicKeyHex, SignatureHex, Tag, UnixTimestamp, UnsignedEvent,
    };

    #[test]
    fn classifies_non_group_normal_moderation_and_relay_generated_events() {
        assert_eq!(
            classify_group_event(&event(1, Vec::new()), GroupLimitsConfig::default())
                .expect("non-group"),
            GroupEventClass::NonGroup
        );
        assert_eq!(
            classify_group_event(
                &event(1, vec![Tag::from_parts("h", &["Farm"]).expect("h")]),
                GroupLimitsConfig::default()
            )
            .expect("normal"),
            GroupEventClass::Normal {
                group_id: crate::GroupId::new("Farm").expect("group")
            }
        );
        assert!(matches!(
            classify_group_event(
                &event(
                    KIND_GROUP_PUT_USER,
                    vec![Tag::from_parts("h", &["Farm"]).expect("h")]
                ),
                GroupLimitsConfig::default()
            )
            .expect("moderation"),
            GroupEventClass::Moderation { kind, group_id }
                if kind.as_u32() == KIND_GROUP_PUT_USER && group_id.as_str() == "Farm"
        ));
        assert!(matches!(
            classify_group_event(
                &event(
                    KIND_GROUP_METADATA,
                    vec![Tag::from_parts("d", &["Farm"]).expect("d")]
                ),
                GroupLimitsConfig::default()
            )
            .expect("relay generated"),
            GroupEventClass::RelayGeneratedSnapshot { kind, group_id }
                if kind.as_u32() == KIND_GROUP_METADATA && group_id.as_str() == "Farm"
        ));
        assert!(matches!(
            classify_group_event(
                &event(
                    KIND_GROUP_CREATE_GROUP,
                    vec![Tag::from_parts("h", &["Farm"]).expect("h")]
                ),
                GroupLimitsConfig::default()
            )
            .expect("create"),
            GroupEventClass::Moderation { kind, .. } if kind.as_u32() == KIND_GROUP_CREATE_GROUP
        ));
        assert!(matches!(
            classify_group_event(
                &event(
                    KIND_GROUP_JOIN_REQUEST,
                    vec![Tag::from_parts("h", &["Farm"]).expect("h")]
                ),
                GroupLimitsConfig::default()
            )
            .expect("join"),
            GroupEventClass::Normal { group_id } if group_id.as_str() == "Farm"
        ));
    }

    #[test]
    fn d_tags_do_not_make_regular_addressable_events_group_events() {
        assert_eq!(
            classify_group_event(
                &event(30_001, vec![Tag::from_parts("d", &["note"]).expect("d")]),
                GroupLimitsConfig::default()
            )
            .expect("event"),
            GroupEventClass::NonGroup
        );
    }

    #[test]
    fn required_h_and_d_tag_rules_are_strict() {
        assert_eq!(
            classify_group_event(
                &event(KIND_GROUP_PUT_USER, Vec::new()),
                GroupLimitsConfig::default()
            )
            .expect_err("missing h")
            .kind(),
            GroupErrorKind::MissingGroupTag
        );
        assert_eq!(
            classify_group_event(
                &event(KIND_GROUP_JOIN_REQUEST, Vec::new()),
                GroupLimitsConfig::default()
            )
            .expect_err("missing h")
            .kind(),
            GroupErrorKind::MissingGroupTag
        );
        assert_eq!(
            classify_group_event(
                &event(
                    KIND_GROUP_METADATA,
                    vec![Tag::from_parts("h", &["Farm"]).expect("h")]
                ),
                GroupLimitsConfig::default()
            )
            .expect_err("missing d")
            .kind(),
            GroupErrorKind::MissingGroupTag
        );
    }

    fn event(kind: u32, tags: Vec<Tag>) -> Event {
        Event::new(
            EventId::new(&"0".repeat(64)).expect("id"),
            UnsignedEvent::new(
                PublicKeyHex::new(&"1".repeat(64)).expect("pubkey"),
                UnixTimestamp::new(1),
                Kind::new(kind.into()).expect("kind"),
                tags,
                "",
            ),
            SignatureHex::new(&"2".repeat(128)).expect("sig"),
        )
    }
}
