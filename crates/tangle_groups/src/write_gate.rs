use crate::{
    GroupEventClass, GroupLimitsConfig,
    classification::classify_group_event,
    errors::{GroupError, GroupErrorKind},
    kinds::{KIND_GROUP_DELETE_EVENT, KIND_GROUP_PUT_USER, KIND_GROUP_REMOVE_USER},
    tags::ensure_group_tag_limit,
};
use std::collections::BTreeSet;
use tangle_protocol::{Event, PublicKeyHex};

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GroupAuthContext {
    authenticated_pubkeys: BTreeSet<PublicKeyHex>,
}

impl GroupAuthContext {
    pub fn unauthenticated() -> Self {
        Self::default()
    }

    pub fn new(pubkeys: impl IntoIterator<Item = PublicKeyHex>) -> Self {
        Self {
            authenticated_pubkeys: pubkeys.into_iter().collect(),
        }
    }

    pub fn contains(&self, pubkey: &PublicKeyHex) -> bool {
        self.authenticated_pubkeys.contains(pubkey)
    }

    pub fn authenticated_pubkeys(&self) -> &BTreeSet<PublicKeyHex> {
        &self.authenticated_pubkeys
    }
}

pub fn validate_client_group_event_structure(
    event: &Event,
    limits: GroupLimitsConfig,
) -> Result<GroupEventClass, GroupError> {
    ensure_group_tag_limit(event.unsigned().tags(), limits)?;
    let class = classify_group_event(event, limits)?;
    match &class {
        GroupEventClass::RelayGeneratedSnapshot { .. } => Err(GroupError::blocked(
            GroupErrorKind::DirectRelayGeneratedSubmission,
            "relay-generated group state events cannot be submitted by clients",
        )),
        GroupEventClass::Moderation { kind, .. } => {
            validate_moderation_targets(event, kind.as_u32())?;
            Ok(class)
        }
        GroupEventClass::Normal { .. } | GroupEventClass::NonGroup => Ok(class),
    }
}

pub fn require_group_auth_as_author(
    event: &Event,
    class: &GroupEventClass,
    auth: &GroupAuthContext,
) -> Result<(), GroupError> {
    if matches!(class, GroupEventClass::NonGroup) {
        return Ok(());
    }
    if auth.contains(event.unsigned().pubkey()) {
        return Ok(());
    }
    Err(GroupError::auth_required(
        "group event author must authenticate with AUTH",
    ))
}

fn validate_moderation_targets(event: &Event, kind: u32) -> Result<(), GroupError> {
    match kind {
        KIND_GROUP_PUT_USER | KIND_GROUP_REMOVE_USER => require_valid_p_tag(event),
        KIND_GROUP_DELETE_EVENT => require_indexed_tag_value(event, "e").map(|_| ()),
        _ => Ok(()),
    }
}

fn require_valid_p_tag(event: &Event) -> Result<(), GroupError> {
    let value = require_indexed_tag_value(event, "p")?;
    PublicKeyHex::new(value).map_err(|reason| {
        GroupError::invalid(
            GroupErrorKind::MalformedTargetTag,
            format!("malformed p target tag: {reason}"),
        )
    })?;
    Ok(())
}

fn require_indexed_tag_value<'a>(event: &'a Event, name: &str) -> Result<&'a str, GroupError> {
    for tag in event.unsigned().tags() {
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

#[cfg(test)]
mod tests {
    use super::{
        GroupAuthContext, require_group_auth_as_author, validate_client_group_event_structure,
    };
    use crate::{
        GroupErrorKind, GroupEventClass, GroupLimitsConfig, KIND_GROUP_DELETE_EVENT,
        KIND_GROUP_JOIN_REQUEST, KIND_GROUP_METADATA, KIND_GROUP_PUT_USER,
    };
    use tangle_protocol::{
        Event, EventId, Kind, PublicKeyHex, SignatureHex, Tag, UnixTimestamp, UnsignedEvent,
    };

    #[test]
    fn client_submitted_relay_generated_events_are_rejected() {
        let error = validate_client_group_event_structure(
            &event(
                KIND_GROUP_METADATA,
                vec![Tag::from_parts("d", &["Farm"]).expect("d")],
            ),
            GroupLimitsConfig::default(),
        )
        .expect_err("relay generated");

        assert_eq!(error.kind(), GroupErrorKind::DirectRelayGeneratedSubmission);
        assert_eq!(
            error.prefixed_message(),
            "blocked: relay-generated group state events cannot be submitted by clients"
        );
    }

    #[test]
    fn validates_moderation_target_tags() {
        assert_eq!(
            validate_client_group_event_structure(
                &event(
                    KIND_GROUP_PUT_USER,
                    vec![Tag::from_parts("h", &["Farm"]).expect("h")]
                ),
                GroupLimitsConfig::default()
            )
            .expect_err("missing p")
            .kind(),
            GroupErrorKind::MissingTargetTag
        );
        assert_eq!(
            validate_client_group_event_structure(
                &event(
                    KIND_GROUP_PUT_USER,
                    vec![
                        Tag::from_parts("h", &["Farm"]).expect("h"),
                        Tag::from_parts("p", &["bad"]).expect("p")
                    ]
                ),
                GroupLimitsConfig::default()
            )
            .expect_err("bad p")
            .kind(),
            GroupErrorKind::MalformedTargetTag
        );
        assert_eq!(
            validate_client_group_event_structure(
                &event(
                    KIND_GROUP_DELETE_EVENT,
                    vec![Tag::from_parts("h", &["Farm"]).expect("h")]
                ),
                GroupLimitsConfig::default()
            )
            .expect_err("missing e")
            .kind(),
            GroupErrorKind::MissingTargetTag
        );
    }

    #[test]
    fn validates_non_group_and_normal_group_structure() {
        assert_eq!(
            validate_client_group_event_structure(
                &event(1, Vec::new()),
                GroupLimitsConfig::default()
            )
            .expect("non-group"),
            GroupEventClass::NonGroup
        );
        assert!(matches!(
            validate_client_group_event_structure(
                &event(1, vec![Tag::from_parts("h", &["Farm"]).expect("h")]),
                GroupLimitsConfig::default()
            )
            .expect("normal"),
            GroupEventClass::Normal { group_id } if group_id.as_str() == "Farm"
        ));
        assert!(matches!(
            validate_client_group_event_structure(
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
    fn group_write_auth_requires_event_author() {
        let group_event = event(1, vec![Tag::from_parts("h", &["Farm"]).expect("h")]);
        let class =
            validate_client_group_event_structure(&group_event, GroupLimitsConfig::default())
                .expect("class");

        assert_eq!(
            require_group_auth_as_author(
                &group_event,
                &class,
                &GroupAuthContext::unauthenticated()
            )
            .expect_err("auth")
            .kind(),
            GroupErrorKind::AuthenticationRequired
        );
        assert!(
            require_group_auth_as_author(
                &group_event,
                &class,
                &GroupAuthContext::new([PublicKeyHex::new(&"1".repeat(64)).expect("pubkey")])
            )
            .is_ok()
        );
        assert_eq!(
            require_group_auth_as_author(
                &group_event,
                &class,
                &GroupAuthContext::new([PublicKeyHex::new(&"3".repeat(64)).expect("pubkey")])
            )
            .expect_err("wrong author")
            .kind(),
            GroupErrorKind::AuthenticationRequired
        );
        assert!(
            require_group_auth_as_author(
                &event(1, Vec::new()),
                &GroupEventClass::NonGroup,
                &GroupAuthContext::unauthenticated()
            )
            .is_ok()
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
