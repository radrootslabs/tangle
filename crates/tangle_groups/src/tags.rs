use crate::{
    GroupLimitsConfig,
    errors::{GroupError, GroupErrorKind},
    event_view::GroupEventView,
    ids::GroupId,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupTagName {
    H,
    D,
}

impl GroupTagName {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::H => "h",
            Self::D => "d",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupTag {
    name: GroupTagName,
    group_id: GroupId,
}

impl GroupTag {
    pub fn new(name: GroupTagName, group_id: GroupId) -> Self {
        Self { name, group_id }
    }

    pub fn name(&self) -> GroupTagName {
        self.name
    }

    pub fn group_id(&self) -> &GroupId {
        &self.group_id
    }
}

pub fn has_group_identity_tag(event: &(impl GroupEventView + ?Sized)) -> Result<bool, GroupError> {
    let mut found = false;
    event.visit_tags(|tag| {
        if tag.first_value().is_some_and(is_group_identity_tag_name) {
            found = true;
        }
        Ok(())
    })?;
    Ok(found)
}

pub fn group_identity_tag_count(
    event: &(impl GroupEventView + ?Sized),
) -> Result<usize, GroupError> {
    let mut count = 0;
    event.visit_tags(|tag| {
        if tag.first_value().is_some_and(is_group_identity_tag_name) {
            count += 1;
        }
        Ok(())
    })?;
    Ok(count)
}

pub fn ensure_group_tag_limit(
    event: &(impl GroupEventView + ?Sized),
    limits: GroupLimitsConfig,
) -> Result<(), GroupError> {
    let count = group_identity_tag_count(event)?;
    let max = usize::from(limits.max_group_tags_per_event());
    if count > max {
        return Err(GroupError::invalid(
            GroupErrorKind::TooManyGroupTags,
            format!("group event has {count} group tags, maximum is {max}"),
        ));
    }
    Ok(())
}

pub fn extract_group_tag(
    event: &(impl GroupEventView + ?Sized),
    name: GroupTagName,
    limits: GroupLimitsConfig,
) -> Result<Option<GroupTag>, GroupError> {
    let mut found: Option<GroupId> = None;
    event.visit_tags(|tag| {
        if tag
            .first_value()
            .is_none_or(|tag_name| tag_name != name.as_str())
        {
            return Ok(());
        }
        let Some((_, value)) = tag.indexed_pair() else {
            return Err(GroupError::invalid(
                GroupErrorKind::MalformedGroupTag,
                format!("malformed {} group tag", name.as_str()),
            ));
        };
        let group_id =
            GroupId::new_with_max_bytes(value, usize::from(limits.max_group_id_bytes()))?;
        if let Some(first) = &found {
            if first != &group_id {
                return Err(GroupError::invalid(
                    GroupErrorKind::ConflictingGroupTag,
                    format!("conflicting {} group tags", name.as_str()),
                ));
            }
        } else {
            found = Some(group_id);
        }
        Ok(())
    })?;
    Ok(found.map(|group_id| GroupTag::new(name, group_id)))
}

pub fn require_group_tag(
    event: &(impl GroupEventView + ?Sized),
    name: GroupTagName,
    limits: GroupLimitsConfig,
) -> Result<GroupTag, GroupError> {
    extract_group_tag(event, name, limits)?.ok_or_else(|| {
        GroupError::invalid(
            GroupErrorKind::MissingGroupTag,
            format!("missing {} group tag", name.as_str()),
        )
    })
}

fn is_group_identity_tag_name(name: &str) -> bool {
    name == GroupTagName::H.as_str() || name == GroupTagName::D.as_str()
}

#[cfg(test)]
mod tests {
    use super::{
        GroupTagName, extract_group_tag, group_identity_tag_count, has_group_identity_tag,
    };
    use crate::{GroupErrorKind, GroupLimitsConfig};
    use tangle_protocol::{
        Event, EventId, Kind, PublicKeyHex, SignatureHex, Tag, UnixTimestamp, UnsignedEvent,
    };

    #[test]
    fn extracts_first_indexed_group_tag_and_allows_exact_duplicates() {
        let event = event(vec![
            Tag::from_parts("h", &["Farm"]).expect("h"),
            Tag::from_parts("p", &["a"]).expect("p"),
            Tag::from_parts("h", &["Farm"]).expect("h"),
        ]);

        let group_tag = extract_group_tag(&event, GroupTagName::H, GroupLimitsConfig::default())
            .expect("tag")
            .expect("present");

        assert_eq!(group_tag.name(), GroupTagName::H);
        assert_eq!(group_tag.group_id().as_str(), "Farm");
        assert!(has_group_identity_tag(&event).expect("identity"));
        assert_eq!(group_identity_tag_count(&event).expect("count"), 2);
    }

    #[test]
    fn conflicting_duplicate_group_tags_are_rejected() {
        let event = event(vec![
            Tag::from_parts("h", &["Farm"]).expect("h"),
            Tag::from_parts("h", &["farm"]).expect("h"),
        ]);
        let error = extract_group_tag(&event, GroupTagName::H, GroupLimitsConfig::default())
            .expect_err("error");

        assert_eq!(error.kind(), GroupErrorKind::ConflictingGroupTag);
        assert_eq!(error.message(), "conflicting h group tags");
    }

    #[test]
    fn malformed_group_tags_are_rejected() {
        let event = event(vec![Tag::new(vec!["h".to_owned()]).expect("tag")]);
        let error = extract_group_tag(&event, GroupTagName::H, GroupLimitsConfig::default())
            .expect_err("error");

        assert_eq!(error.kind(), GroupErrorKind::MalformedGroupTag);
        assert_eq!(error.message(), "malformed h group tag");
    }

    #[test]
    fn group_tag_limit_counts_h_and_d_tags() {
        let event = event(vec![
            Tag::from_parts("h", &["a"]).expect("h"),
            Tag::from_parts("d", &["a"]).expect("d"),
        ]);
        let limits = GroupLimitsConfig::new(128, 1, 512, 1, 1).expect("limits");

        assert_eq!(
            super::ensure_group_tag_limit(&event, limits)
                .expect_err("limit")
                .message(),
            "group event has 2 group tags, maximum is 1"
        );
    }

    fn event(tags: Vec<Tag>) -> Event {
        Event::new(
            EventId::new(&"0".repeat(64)).expect("id"),
            UnsignedEvent::new(
                PublicKeyHex::new(&"1".repeat(64)).expect("pubkey"),
                UnixTimestamp::new(1),
                Kind::new(1).expect("kind"),
                tags,
                "",
            ),
            SignatureHex::new(&"2".repeat(128)).expect("sig"),
        )
    }
}
