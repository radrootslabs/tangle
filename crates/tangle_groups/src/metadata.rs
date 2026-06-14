use std::collections::BTreeSet;

use crate::{
    GroupLimitsConfig,
    errors::{GroupError, GroupErrorKind},
};
use tangle_protocol::{Kind, Tag};

pub const MAX_METADATA_NAME_BYTES: usize = 128;
pub const MAX_METADATA_PICTURE_BYTES: usize = 2_048;
pub const MAX_METADATA_ABOUT_BYTES: usize = 4_096;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupMetadata {
    name: Option<String>,
    picture: Option<String>,
    about: Option<String>,
    private: bool,
    restricted: bool,
    hidden: bool,
    closed: bool,
    supported_kinds: SupportedKinds,
}

impl GroupMetadata {
    pub fn new(
        name: Option<String>,
        picture: Option<String>,
        about: Option<String>,
        private: bool,
        restricted: bool,
        hidden: bool,
        closed: bool,
        supported_kinds: SupportedKinds,
    ) -> Self {
        Self {
            name,
            picture,
            about,
            private,
            restricted,
            hidden,
            closed,
            supported_kinds,
        }
    }

    pub fn empty() -> Self {
        Self {
            name: None,
            picture: None,
            about: None,
            private: false,
            restricted: false,
            hidden: false,
            closed: false,
            supported_kinds: SupportedKinds::UnspecifiedAll,
        }
    }

    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    pub fn picture(&self) -> Option<&str> {
        self.picture.as_deref()
    }

    pub fn about(&self) -> Option<&str> {
        self.about.as_deref()
    }

    pub fn private(&self) -> bool {
        self.private
    }

    pub fn restricted(&self) -> bool {
        self.restricted
    }

    pub fn hidden(&self) -> bool {
        self.hidden
    }

    pub fn closed(&self) -> bool {
        self.closed
    }

    pub fn supported_kinds(&self) -> &SupportedKinds {
        &self.supported_kinds
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SupportedKinds {
    UnspecifiedAll,
    None,
    Only(BTreeSet<Kind>),
}

pub fn parse_group_metadata(
    tags: &[Tag],
    limits: GroupLimitsConfig,
) -> Result<GroupMetadata, GroupError> {
    let mut builder = MetadataBuilder::default();
    for tag in tags {
        let Some(name) = tag.values().first().map(String::as_str) else {
            continue;
        };
        match name {
            "name" => builder.name = parse_text_tag(tag, "name", MAX_METADATA_NAME_BYTES)?,
            "picture" => {
                builder.picture = parse_text_tag(tag, "picture", MAX_METADATA_PICTURE_BYTES)?
            }
            "about" => builder.about = parse_text_tag(tag, "about", MAX_METADATA_ABOUT_BYTES)?,
            "private" => builder.private = true,
            "restricted" => builder.restricted = true,
            "hidden" => builder.hidden = true,
            "closed" => builder.closed = true,
            "supported_kinds" => {
                if builder.supported_kinds.is_some() {
                    return Err(GroupError::invalid(
                        GroupErrorKind::TooManySupportedKinds,
                        "metadata must contain at most one supported_kinds tag",
                    ));
                }
                builder.supported_kinds = Some(parse_supported_kinds_tag(tag, limits)?);
            }
            _ => {}
        }
    }
    Ok(GroupMetadata {
        name: builder.name,
        picture: builder.picture,
        about: builder.about,
        private: builder.private,
        restricted: builder.restricted,
        hidden: builder.hidden,
        closed: builder.closed,
        supported_kinds: builder
            .supported_kinds
            .unwrap_or(SupportedKinds::UnspecifiedAll),
    })
}

#[derive(Default)]
struct MetadataBuilder {
    name: Option<String>,
    picture: Option<String>,
    about: Option<String>,
    private: bool,
    restricted: bool,
    hidden: bool,
    closed: bool,
    supported_kinds: Option<SupportedKinds>,
}

fn parse_text_tag(
    tag: &Tag,
    field: &'static str,
    max_bytes: usize,
) -> Result<Option<String>, GroupError> {
    let value = tag.values().get(1).cloned();
    if let Some(value) = &value
        && value.len() > max_bytes
    {
        return Err(GroupError::invalid(
            GroupErrorKind::MetadataTooLarge,
            format!("metadata {field} must be at most {max_bytes} bytes"),
        ));
    }
    Ok(value)
}

fn parse_supported_kinds_tag(
    tag: &Tag,
    limits: GroupLimitsConfig,
) -> Result<SupportedKinds, GroupError> {
    let values = tag.values().iter().skip(1).collect::<Vec<_>>();
    if values.is_empty() {
        return Ok(SupportedKinds::None);
    }
    let max = usize::from(limits.max_supported_kinds());
    if values.len() > max {
        return Err(GroupError::invalid(
            GroupErrorKind::TooManySupportedKinds,
            format!(
                "supported_kinds has {} values, maximum is {max}",
                values.len()
            ),
        ));
    }
    let mut kinds = BTreeSet::new();
    for value in values {
        let raw = value.parse::<u64>().map_err(|_| {
            GroupError::invalid(
                GroupErrorKind::UnsupportedGroupKind,
                "supported_kinds values must be unsigned integers",
            )
        })?;
        kinds.insert(Kind::new(raw).map_err(|reason| {
            GroupError::invalid(
                GroupErrorKind::UnsupportedGroupKind,
                format!("supported_kinds value is invalid: {reason}"),
            )
        })?);
    }
    Ok(SupportedKinds::Only(kinds))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::{SupportedKinds, parse_group_metadata};
    use crate::{GroupErrorKind, GroupLimitsConfig};
    use tangle_protocol::{Kind, Tag};

    #[test]
    fn parses_group_metadata_flags_and_fields() {
        let metadata = parse_group_metadata(
            &[
                Tag::from_parts("name", &["Farmers"]).expect("name"),
                Tag::from_parts("picture", &["https://radroots.test/group.png"]).expect("picture"),
                Tag::from_parts("about", &["Local harvest coordination"]).expect("about"),
                Tag::from_parts("private", &[]).expect("private"),
                Tag::from_parts("restricted", &[]).expect("restricted"),
                Tag::from_parts("hidden", &[]).expect("hidden"),
                Tag::from_parts("closed", &[]).expect("closed"),
                Tag::from_parts("supported_kinds", &["1", "7"]).expect("supported"),
            ],
            GroupLimitsConfig::default(),
        )
        .expect("metadata");

        assert_eq!(metadata.name(), Some("Farmers"));
        assert_eq!(metadata.picture(), Some("https://radroots.test/group.png"));
        assert_eq!(metadata.about(), Some("Local harvest coordination"));
        assert!(metadata.private());
        assert!(metadata.restricted());
        assert!(metadata.hidden());
        assert!(metadata.closed());
        assert_eq!(
            metadata.supported_kinds(),
            &SupportedKinds::Only(BTreeSet::from([
                Kind::new(1).expect("kind"),
                Kind::new(7).expect("kind")
            ]))
        );
    }

    #[test]
    fn supported_kinds_absent_empty_and_list_forms_are_distinct() {
        assert_eq!(
            parse_group_metadata(&[], GroupLimitsConfig::default())
                .expect("absent")
                .supported_kinds(),
            &SupportedKinds::UnspecifiedAll
        );
        assert_eq!(
            parse_group_metadata(
                &[Tag::from_parts("supported_kinds", &[]).expect("supported")],
                GroupLimitsConfig::default()
            )
            .expect("empty")
            .supported_kinds(),
            &SupportedKinds::None
        );
        assert!(matches!(
            parse_group_metadata(
                &[Tag::from_parts("supported_kinds", &["1"]).expect("supported")],
                GroupLimitsConfig::default()
            )
            .expect("list")
            .supported_kinds(),
            SupportedKinds::Only(kinds) if kinds.contains(&Kind::new(1).expect("kind"))
        ));
    }

    #[test]
    fn metadata_parser_rejects_oversize_fields_and_kind_limits() {
        let error = parse_group_metadata(
            &[Tag::from_parts("name", &[&"a".repeat(129)]).expect("name")],
            GroupLimitsConfig::default(),
        )
        .expect_err("name");
        assert_eq!(error.kind(), GroupErrorKind::MetadataTooLarge);

        let limits = GroupLimitsConfig::new(128, 8, 1, 1, 1).expect("limits");
        let error = parse_group_metadata(
            &[Tag::from_parts("supported_kinds", &["1", "2"]).expect("supported")],
            limits,
        )
        .expect_err("supported kinds");
        assert_eq!(error.kind(), GroupErrorKind::TooManySupportedKinds);
    }
}
