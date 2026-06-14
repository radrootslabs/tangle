use crate::errors::{GroupError, GroupErrorKind};
use pocket_types::{
    Event as PocketEvent, OwnedEvent as PocketOwnedEvent, TagsStringIter as PocketTagsStringIter,
};
use std::str;
use tangle_protocol::{Event, Tag, TagName};

pub trait GroupEventView {
    fn id_hex(&self) -> String;

    fn pubkey_hex(&self) -> String;

    fn kind_u32(&self) -> u32;

    fn visit_tags<'a, F>(&'a self, visitor: F) -> Result<(), GroupError>
    where
        F: FnMut(GroupEventTag<'a>) -> Result<(), GroupError>;
}

#[derive(Debug)]
pub enum GroupEventTag<'a> {
    Tangle(&'a Tag),
    Pocket(PocketTagsStringIter<'a>),
}

impl<'a> GroupEventTag<'a> {
    pub fn first_value(self) -> Result<Option<&'a str>, GroupError> {
        match self {
            Self::Tangle(tag) => Ok(tag.values().first().map(String::as_str)),
            Self::Pocket(mut values) => values.next().map(tag_value_utf8).transpose(),
        }
    }

    pub fn indexed_pair(self) -> Result<Option<(&'a str, &'a str)>, GroupError> {
        match self {
            Self::Tangle(tag) => Ok(tag.indexed_pair()),
            Self::Pocket(mut values) => {
                let Some(name) = values.next() else {
                    return Ok(None);
                };
                let name = tag_value_utf8(name)?;
                if !TagName::is_indexable_name(name) {
                    return Ok(None);
                }
                let Some(value) = values.next() else {
                    return Ok(None);
                };
                Ok(Some((name, tag_value_utf8(value)?)))
            }
        }
    }

    pub fn values(self) -> Result<Vec<&'a str>, GroupError> {
        match self {
            Self::Tangle(tag) => Ok(tag.values().iter().map(String::as_str).collect()),
            Self::Pocket(values) => values.map(tag_value_utf8).collect(),
        }
    }
}

impl GroupEventView for Event {
    fn id_hex(&self) -> String {
        self.id().as_str().to_owned()
    }

    fn pubkey_hex(&self) -> String {
        self.unsigned().pubkey().as_str().to_owned()
    }

    fn kind_u32(&self) -> u32 {
        self.unsigned().kind().as_u32()
    }

    fn visit_tags<'a, F>(&'a self, mut visitor: F) -> Result<(), GroupError>
    where
        F: FnMut(GroupEventTag<'a>) -> Result<(), GroupError>,
    {
        for tag in self.unsigned().tags() {
            visitor(GroupEventTag::Tangle(tag))?;
        }
        Ok(())
    }
}

impl GroupEventView for PocketEvent {
    fn id_hex(&self) -> String {
        self.id().as_hex_string()
    }

    fn pubkey_hex(&self) -> String {
        self.pubkey().as_hex_string()
    }

    fn kind_u32(&self) -> u32 {
        u32::from(self.kind().as_u16())
    }

    fn visit_tags<'a, F>(&'a self, mut visitor: F) -> Result<(), GroupError>
    where
        F: FnMut(GroupEventTag<'a>) -> Result<(), GroupError>,
    {
        let tags = self.tags().map_err(pocket_tags_error)?;
        for tag in tags.iter() {
            visitor(GroupEventTag::Pocket(tag))?;
        }
        Ok(())
    }
}

impl GroupEventView for PocketOwnedEvent {
    fn id_hex(&self) -> String {
        let event: &PocketEvent = self;
        event.id_hex()
    }

    fn pubkey_hex(&self) -> String {
        let event: &PocketEvent = self;
        event.pubkey_hex()
    }

    fn kind_u32(&self) -> u32 {
        let event: &PocketEvent = self;
        event.kind_u32()
    }

    fn visit_tags<'a, F>(&'a self, visitor: F) -> Result<(), GroupError>
    where
        F: FnMut(GroupEventTag<'a>) -> Result<(), GroupError>,
    {
        let event: &PocketEvent = self;
        event.visit_tags(visitor)
    }
}

fn tag_value_utf8(value: &[u8]) -> Result<&str, GroupError> {
    str::from_utf8(value).map_err(|_| {
        GroupError::invalid(
            GroupErrorKind::MalformedGroupTag,
            "group event tag is not valid UTF-8",
        )
    })
}

fn pocket_tags_error(error: pocket_types::Error) -> GroupError {
    GroupError::invalid(
        GroupErrorKind::MalformedGroupTag,
        format!("malformed Pocket event tags: {error}"),
    )
}

#[cfg(test)]
mod tests {
    use super::GroupEventView;
    use pocket_types::Event as PocketEvent;
    use tangle_protocol::{
        Event, EventId, Kind, PublicKeyHex, SignatureHex, Tag, UnixTimestamp, UnsignedEvent,
        event_to_value,
    };

    #[test]
    fn tangle_event_view_exposes_group_fields() {
        let event = event();

        assert_eq!(event.kind_u32(), 1);
        assert_eq!(event.id_hex(), "0".repeat(64));
        assert_eq!(event.pubkey_hex(), "1".repeat(64));
        assert_eq!(
            indexed_pairs(&event),
            vec![("h".to_owned(), "Farm".to_owned())]
        );
        assert_eq!(
            tag_values(&event),
            vec![
                vec!["h".to_owned(), "Farm".to_owned()],
                vec!["summary".to_owned(), "Harvest".to_owned()],
            ]
        );
    }

    #[test]
    fn pocket_event_view_exposes_group_fields_without_tangle_reparse() {
        let event = event();
        let raw = event_to_value(&event).to_string();
        let mut buffer = vec![0; 4096];
        let (_, pocket) = PocketEvent::from_json(raw.as_bytes(), &mut buffer).expect("pocket");

        assert_eq!(pocket.kind_u32(), 1);
        assert_eq!(pocket.id_hex(), "0".repeat(64));
        assert_eq!(pocket.pubkey_hex(), "1".repeat(64));
        assert_eq!(
            indexed_pairs(pocket),
            vec![("h".to_owned(), "Farm".to_owned())]
        );
        assert_eq!(
            tag_values(pocket),
            vec![
                vec!["h".to_owned(), "Farm".to_owned()],
                vec!["summary".to_owned(), "Harvest".to_owned()],
            ]
        );
    }

    fn indexed_pairs<E: GroupEventView + ?Sized>(event: &E) -> Vec<(String, String)> {
        let mut pairs = Vec::new();
        event
            .visit_tags(|tag| {
                if let Some((name, value)) = tag.indexed_pair()? {
                    pairs.push((name.to_owned(), value.to_owned()));
                }
                Ok(())
            })
            .expect("visit tags");
        pairs
    }

    fn tag_values<E: GroupEventView + ?Sized>(event: &E) -> Vec<Vec<String>> {
        let mut tags = Vec::new();
        event
            .visit_tags(|tag| {
                tags.push(tag.values()?.into_iter().map(str::to_owned).collect());
                Ok(())
            })
            .expect("visit tags");
        tags
    }

    fn event() -> Event {
        Event::new(
            EventId::new(&"0".repeat(64)).expect("id"),
            UnsignedEvent::new(
                PublicKeyHex::new(&"1".repeat(64)).expect("pubkey"),
                UnixTimestamp::new(1),
                Kind::new(1).expect("kind"),
                vec![
                    Tag::from_parts("h", &["Farm"]).expect("h"),
                    Tag::from_parts("summary", &["Harvest"]).expect("summary"),
                ],
                "",
            ),
            SignatureHex::new(&"2".repeat(128)).expect("sig"),
        )
    }
}
