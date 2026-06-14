use crate::{
    GroupLimitsConfig,
    errors::{GroupError, GroupErrorKind},
    ids::GroupId,
};
use tangle_protocol::Tag;

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

pub fn has_group_identity_tag(tags: &[Tag]) -> bool {
    tags.iter().any(|tag| {
        tag.values().first().is_some_and(|name| {
            name == GroupTagName::H.as_str() || name == GroupTagName::D.as_str()
        })
    })
}

pub fn group_identity_tag_count(tags: &[Tag]) -> usize {
    tags.iter()
        .filter(|tag| {
            tag.values().first().is_some_and(|name| {
                name == GroupTagName::H.as_str() || name == GroupTagName::D.as_str()
            })
        })
        .count()
}

pub fn ensure_group_tag_limit(tags: &[Tag], limits: GroupLimitsConfig) -> Result<(), GroupError> {
    let count = group_identity_tag_count(tags);
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
    tags: &[Tag],
    name: GroupTagName,
    limits: GroupLimitsConfig,
) -> Result<Option<GroupTag>, GroupError> {
    let mut found: Option<GroupId> = None;
    for tag in tags {
        if !tag
            .values()
            .first()
            .is_some_and(|tag_name| tag_name == name.as_str())
        {
            continue;
        }
        let Some((indexed_name, value)) = tag.indexed_pair() else {
            return Err(GroupError::invalid(
                GroupErrorKind::MalformedGroupTag,
                format!("malformed {} group tag", name.as_str()),
            ));
        };
        if indexed_name != name.as_str() {
            continue;
        }
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
    }
    Ok(found.map(|group_id| GroupTag::new(name, group_id)))
}

pub fn require_group_tag(
    tags: &[Tag],
    name: GroupTagName,
    limits: GroupLimitsConfig,
) -> Result<GroupTag, GroupError> {
    extract_group_tag(tags, name, limits)?.ok_or_else(|| {
        GroupError::invalid(
            GroupErrorKind::MissingGroupTag,
            format!("missing {} group tag", name.as_str()),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::{
        GroupTagName, extract_group_tag, group_identity_tag_count, has_group_identity_tag,
    };
    use crate::{GroupErrorKind, GroupLimitsConfig};
    use tangle_protocol::Tag;

    #[test]
    fn extracts_first_indexed_group_tag_and_allows_exact_duplicates() {
        let tags = vec![
            Tag::from_parts("h", &["Farm"]).expect("h"),
            Tag::from_parts("p", &["a"]).expect("p"),
            Tag::from_parts("h", &["Farm"]).expect("h"),
        ];

        let group_tag = extract_group_tag(&tags, GroupTagName::H, GroupLimitsConfig::default())
            .expect("tag")
            .expect("present");

        assert_eq!(group_tag.name(), GroupTagName::H);
        assert_eq!(group_tag.group_id().as_str(), "Farm");
        assert!(has_group_identity_tag(&tags));
        assert_eq!(group_identity_tag_count(&tags), 2);
    }

    #[test]
    fn conflicting_duplicate_group_tags_are_rejected() {
        let tags = vec![
            Tag::from_parts("h", &["Farm"]).expect("h"),
            Tag::from_parts("h", &["farm"]).expect("h"),
        ];
        let error = extract_group_tag(&tags, GroupTagName::H, GroupLimitsConfig::default())
            .expect_err("error");

        assert_eq!(error.kind(), GroupErrorKind::ConflictingGroupTag);
        assert_eq!(error.message(), "conflicting h group tags");
    }

    #[test]
    fn malformed_group_tags_are_rejected() {
        let tags = vec![Tag::new(vec!["h".to_owned()]).expect("tag")];
        let error = extract_group_tag(&tags, GroupTagName::H, GroupLimitsConfig::default())
            .expect_err("error");

        assert_eq!(error.kind(), GroupErrorKind::MalformedGroupTag);
        assert_eq!(error.message(), "malformed h group tag");
    }

    #[test]
    fn group_tag_limit_counts_h_and_d_tags() {
        let tags = vec![
            Tag::from_parts("h", &["a"]).expect("h"),
            Tag::from_parts("d", &["a"]).expect("d"),
        ];
        let limits = GroupLimitsConfig::new(128, 1, 512, 1, 1).expect("limits");

        assert_eq!(
            super::ensure_group_tag_limit(&tags, limits)
                .expect_err("limit")
                .message(),
            "group event has 2 group tags, maximum is 1"
        );
    }
}
