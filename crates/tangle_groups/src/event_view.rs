use crate::errors::{GroupError, GroupErrorKind};
use pocket_types::{Event as PocketEvent, OwnedEvent as PocketOwnedEvent, TagsStringIter};
use std::str;
use tangle_protocol::{Event, EventId, Kind, PublicKeyHex, Tag, TagName};

pub trait GroupEventView {
    fn id_hex(&self) -> String;

    fn pubkey_hex(&self) -> String;

    fn kind_u32(&self) -> u32;

    fn visit_tags<'a, F>(&'a self, visitor: F) -> Result<(), GroupError>
    where
        F: FnMut(GroupEventTag<'a>) -> Result<(), GroupError>;

    fn id(&self) -> Result<EventId, GroupError> {
        EventId::new(&self.id_hex()).map_err(event_view_scalar_error)
    }

    fn pubkey(&self) -> Result<PublicKeyHex, GroupError> {
        PublicKeyHex::new(&self.pubkey_hex()).map_err(event_view_scalar_error)
    }

    fn kind(&self) -> Result<Kind, GroupError> {
        Kind::new(u64::from(self.kind_u32())).map_err(event_view_scalar_error)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GroupEventTag<'a> {
    name: Option<&'a str>,
    value: Option<&'a str>,
}

impl<'a> GroupEventTag<'a> {
    pub fn first_value(&self) -> Option<&'a str> {
        self.name
    }

    pub fn indexed_pair(&self) -> Option<(&'a str, &'a str)> {
        let name = self.name?;
        if !TagName::is_indexable_name(name) {
            return None;
        }
        self.value.map(|value| (name, value))
    }

    fn from_tangle(tag: &'a Tag) -> Self {
        Self {
            name: tag.values().first().map(String::as_str),
            value: tag.values().get(1).map(String::as_str),
        }
    }

    fn from_pocket(mut values: TagsStringIter<'a>) -> Result<Self, GroupError> {
        Ok(Self {
            name: values.next().map(tag_value_utf8).transpose()?,
            value: values.next().map(tag_value_utf8).transpose()?,
        })
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
            visitor(GroupEventTag::from_tangle(tag))?;
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
            visitor(GroupEventTag::from_pocket(tag)?)?;
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

fn event_view_scalar_error(error: String) -> GroupError {
    GroupError::internal(error)
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
    }

    fn indexed_pairs<E: GroupEventView + ?Sized>(event: &E) -> Vec<(String, String)> {
        let mut pairs = Vec::new();
        event
            .visit_tags(|tag| {
                if let Some((name, value)) = tag.indexed_pair() {
                    pairs.push((name.to_owned(), value.to_owned()));
                }
                Ok(())
            })
            .expect("visit tags");
        pairs
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
