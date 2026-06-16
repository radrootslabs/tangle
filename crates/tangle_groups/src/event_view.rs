use crate::errors::{GroupError, GroupErrorKind};
use pocket_types::{Event as PocketEvent, OwnedEvent as PocketOwnedEvent, TagsStringIter};
use std::str;
#[cfg(test)]
use tangle_protocol::{Event, Tag};
use tangle_protocol::{EventId, Kind, PublicKeyHex, UnixTimestamp};

pub trait GroupEventView {
    fn id_hex(&self) -> String;

    fn pubkey_hex(&self) -> String;

    fn kind_u32(&self) -> u32;

    fn created_at_unix(&self) -> u64;

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

    fn created_at(&self) -> UnixTimestamp {
        UnixTimestamp::new(self.created_at_unix())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupEventTag<'a> {
    values: Vec<&'a str>,
}

impl<'a> GroupEventTag<'a> {
    pub fn first_value(&self) -> Option<&'a str> {
        self.value(0)
    }

    pub fn value(&self, index: usize) -> Option<&'a str> {
        self.values.get(index).copied()
    }

    pub fn values(&self) -> &[&'a str] {
        &self.values
    }

    pub fn indexed_pair(&self) -> Option<(&'a str, &'a str)> {
        let name = self.first_value()?;
        if !is_indexable_tag_name(name) {
            return None;
        }
        self.value(1).map(|value| (name, value))
    }

    #[cfg(test)]
    fn from_tangle(tag: &'a Tag) -> Self {
        Self {
            values: tag.values().iter().map(String::as_str).collect(),
        }
    }

    fn from_pocket(mut values: TagsStringIter<'a>) -> Result<Self, GroupError> {
        let mut tag_values = Vec::new();
        for value in values.by_ref() {
            tag_values.push(tag_value_utf8(value)?);
        }
        Ok(Self { values: tag_values })
    }
}

#[cfg(test)]
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

    fn created_at_unix(&self) -> u64 {
        self.unsigned().created_at().as_u64()
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

    fn created_at_unix(&self) -> u64 {
        self.created_at().as_u64()
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

    fn created_at_unix(&self) -> u64 {
        let event: &PocketEvent = self;
        event.created_at_unix()
    }

    fn visit_tags<'a, F>(&'a self, visitor: F) -> Result<(), GroupError>
    where
        F: FnMut(GroupEventTag<'a>) -> Result<(), GroupError>,
    {
        let event: &PocketEvent = self;
        event.visit_tags(visitor)
    }
}

fn is_indexable_tag_name(value: &str) -> bool {
    let mut bytes = value.bytes();
    let Some(byte) = bytes.next() else {
        return false;
    };
    bytes.next().is_none() && byte.is_ascii_alphabetic()
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
    use pocket_types::{Event as PocketEvent, OwnedEvent as PocketOwnedEvent};
    use tangle_protocol::{
        Event, EventId, Kind, PublicKeyHex, SignatureHex, Tag, UnixTimestamp, UnsignedEvent,
        event_to_value,
    };

    #[test]
    fn tangle_event_view_exposes_group_fields() {
        let event = event();

        assert_eq!(event.kind_u32(), 1);
        assert_eq!(event.created_at_unix(), 42);
        assert_eq!(event.created_at(), UnixTimestamp::new(42));
        assert_eq!(event.id_hex(), "0".repeat(64));
        assert_eq!(event.pubkey_hex(), "1".repeat(64));
        assert_eq!(
            indexed_pairs(&event),
            vec![("h".to_owned(), "Farm".to_owned())]
        );
        assert_eq!(
            tag_values(&event, "role"),
            vec![vec!["role".to_owned(), "moderator".to_owned()]]
        );
        assert_eq!(
            tag_values(&event, "supported_kinds"),
            vec![vec![
                "supported_kinds".to_owned(),
                "1".to_owned(),
                "9".to_owned()
            ]]
        );
    }

    #[test]
    fn pocket_event_view_exposes_group_fields_without_tangle_reparse() {
        let event = event();
        let raw = event_to_value(&event).to_string();
        let mut buffer = vec![0; 4096];
        let (_, pocket) = PocketEvent::from_json(raw.as_bytes(), &mut buffer).expect("pocket");

        assert_eq!(pocket.kind_u32(), 1);
        assert_eq!(pocket.created_at_unix(), 42);
        assert_eq!(
            <PocketEvent as GroupEventView>::created_at(pocket),
            UnixTimestamp::new(42)
        );
        assert_eq!(pocket.id_hex(), "0".repeat(64));
        assert_eq!(pocket.pubkey_hex(), "1".repeat(64));
        assert_eq!(
            indexed_pairs(pocket),
            vec![("h".to_owned(), "Farm".to_owned())]
        );
        assert_eq!(
            tag_values(pocket, "role"),
            vec![vec!["role".to_owned(), "moderator".to_owned()]]
        );
        assert_eq!(
            tag_values(pocket, "supported_kinds"),
            vec![vec![
                "supported_kinds".to_owned(),
                "1".to_owned(),
                "9".to_owned()
            ]]
        );
    }

    #[test]
    fn owned_pocket_event_view_exposes_group_fields() {
        let event = event();
        let raw = event_to_value(&event).to_string();
        let mut buffer = vec![0; 4096];
        let (_, pocket) = PocketEvent::from_json(raw.as_bytes(), &mut buffer).expect("pocket");
        let owned: PocketOwnedEvent = pocket.to_owned();

        assert_eq!(owned.kind_u32(), 1);
        assert_eq!(owned.created_at_unix(), 42);
        assert_eq!(
            <PocketOwnedEvent as GroupEventView>::created_at(&owned),
            UnixTimestamp::new(42)
        );
        assert_eq!(owned.id_hex(), "0".repeat(64));
        assert_eq!(owned.pubkey_hex(), "1".repeat(64));
        assert_eq!(
            tag_values(&owned, "supported_kinds"),
            vec![vec![
                "supported_kinds".to_owned(),
                "1".to_owned(),
                "9".to_owned()
            ]]
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

    fn tag_values<E: GroupEventView + ?Sized>(event: &E, name: &str) -> Vec<Vec<String>> {
        let mut values = Vec::new();
        event
            .visit_tags(|tag| {
                if tag.first_value().is_some_and(|value| value == name) {
                    values.push(
                        tag.values()
                            .iter()
                            .map(|value| (*value).to_owned())
                            .collect(),
                    );
                }
                Ok(())
            })
            .expect("visit tags");
        values
    }

    fn event() -> Event {
        Event::new(
            EventId::new(&"0".repeat(64)).expect("id"),
            UnsignedEvent::new(
                PublicKeyHex::new(&"1".repeat(64)).expect("pubkey"),
                UnixTimestamp::new(42),
                Kind::new(1).expect("kind"),
                vec![
                    Tag::from_parts("h", &["Farm"]).expect("h"),
                    Tag::from_parts("role", &["moderator"]).expect("role"),
                    Tag::from_parts("supported_kinds", &["1", "9"]).expect("supported kinds"),
                    Tag::from_parts("summary", &["Harvest"]).expect("summary"),
                ],
                "",
            ),
            SignatureHex::new(&"2".repeat(128)).expect("sig"),
        )
    }
}
