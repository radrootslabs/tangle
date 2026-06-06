#![forbid(unsafe_code)]

use core::fmt;
use tangle_nips::{DeletionTarget, ListingProjection};
use tangle_protocol::{AddressCoordinate, Event, EventId, PublicKeyHex, UnixTimestamp};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredEvent {
    event: Event,
    received_at: UnixTimestamp,
    content_len: usize,
    tag_count: usize,
}

impl StoredEvent {
    pub fn new(event: Event, received_at: UnixTimestamp) -> Self {
        let content_len = event.unsigned().content().len();
        let tag_count = event.unsigned().tags().len();
        Self {
            event,
            received_at,
            content_len,
            tag_count,
        }
    }

    pub fn event(&self) -> &Event {
        &self.event
    }

    pub fn received_at(&self) -> UnixTimestamp {
        self.received_at
    }

    pub fn content_len(&self) -> usize {
        self.content_len
    }

    pub fn tag_count(&self) -> usize {
        self.tag_count
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreEventOutcome {
    Inserted,
    Duplicate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreProjectionOutcome {
    Inserted,
    Replaced,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeletionMarker {
    deletion_event_id: EventId,
    author_pubkey: PublicKeyHex,
    target: DeletionTarget,
    deleted_at: UnixTimestamp,
}

impl DeletionMarker {
    pub fn new(
        deletion_event_id: EventId,
        author_pubkey: PublicKeyHex,
        target: DeletionTarget,
        deleted_at: UnixTimestamp,
    ) -> Self {
        Self {
            deletion_event_id,
            author_pubkey,
            target,
            deleted_at,
        }
    }

    pub fn deletion_event_id(&self) -> &EventId {
        &self.deletion_event_id
    }

    pub fn author_pubkey(&self) -> &PublicKeyHex {
        &self.author_pubkey
    }

    pub fn target(&self) -> &DeletionTarget {
        &self.target
    }

    pub fn deleted_at(&self) -> UnixTimestamp {
        self.deleted_at
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct RepositoryError {
    message: String,
}

impl RepositoryError {
    pub fn new(message: &str) -> Self {
        Self {
            message: message.to_owned(),
        }
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for RepositoryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl fmt::Debug for RepositoryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RepositoryError")
            .field("message", &self.message)
            .finish()
    }
}

impl std::error::Error for RepositoryError {}

pub trait RawEventRepository {
    fn put_event(&mut self, record: StoredEvent) -> Result<StoreEventOutcome, RepositoryError>;

    fn event_by_id(&self, event_id: &EventId) -> Result<Option<StoredEvent>, RepositoryError>;

    fn events(&self) -> Result<Vec<StoredEvent>, RepositoryError>;
}

pub trait ListingProjectionRepository {
    fn put_listing_projection(
        &mut self,
        projection: ListingProjection,
    ) -> Result<StoreProjectionOutcome, RepositoryError>;

    fn listing_projection(
        &self,
        address: &AddressCoordinate,
    ) -> Result<Option<ListingProjection>, RepositoryError>;
}

pub trait DeletionMarkerRepository {
    fn put_deletion_marker(&mut self, marker: DeletionMarker) -> Result<(), RepositoryError>;

    fn deletion_markers(&self) -> Result<Vec<DeletionMarker>, RepositoryError>;
}

#[cfg(test)]
mod tests {
    use super::{
        DeletionMarker, RepositoryError, StoreEventOutcome, StoreProjectionOutcome, StoredEvent,
    };
    use tangle_nips::DeletionTarget;
    use tangle_protocol::{
        Event, EventId, Kind, PublicKeyHex, SignatureHex, Tag, UnixTimestamp, UnsignedEvent,
    };

    #[test]
    fn stored_event_preserves_event_and_derived_metadata() {
        let event = event_with_tags_and_content(
            vec![
                Tag::from_parts("d", &["listing-a"]).expect("d"),
                Tag::from_parts("t", &["carrots"]).expect("topic"),
            ],
            "fresh",
        );
        let stored = StoredEvent::new(event.clone(), UnixTimestamp::new(100));

        assert_eq!(stored.event(), &event);
        assert_eq!(stored.received_at().as_u64(), 100);
        assert_eq!(stored.content_len(), 5);
        assert_eq!(stored.tag_count(), 2);
        assert_eq!(StoreEventOutcome::Inserted, StoreEventOutcome::Inserted);
        assert_eq!(StoreEventOutcome::Duplicate, StoreEventOutcome::Duplicate);
        assert_eq!(
            StoreProjectionOutcome::Inserted,
            StoreProjectionOutcome::Inserted
        );
        assert_eq!(
            StoreProjectionOutcome::Replaced,
            StoreProjectionOutcome::Replaced
        );
    }

    #[test]
    fn deletion_marker_preserves_typed_deletion_target() {
        let deletion_event_id = EventId::new(&"2".repeat(EventId::HEX_LENGTH)).expect("id");
        let author_pubkey = PublicKeyHex::new(&"3".repeat(PublicKeyHex::HEX_LENGTH)).expect("pk");
        let target_id = EventId::new(&"4".repeat(EventId::HEX_LENGTH)).expect("target");
        let target = DeletionTarget::Event(target_id.clone());
        let marker = DeletionMarker::new(
            deletion_event_id.clone(),
            author_pubkey.clone(),
            target,
            UnixTimestamp::new(200),
        );

        assert_eq!(marker.deletion_event_id(), &deletion_event_id);
        assert_eq!(marker.author_pubkey(), &author_pubkey);
        assert_eq!(marker.target(), &DeletionTarget::Event(target_id));
        assert_eq!(marker.deleted_at().as_u64(), 200);
    }

    #[test]
    fn repository_error_has_stable_message_display_and_debug() {
        let error = RepositoryError::new("store unavailable");

        assert_eq!(error.message(), "store unavailable");
        assert_eq!(error.to_string(), "store unavailable");
        assert_eq!(
            format!("{error:?}"),
            "RepositoryError { message: \"store unavailable\" }"
        );
    }

    fn event_with_tags_and_content(tags: Vec<Tag>, content: &str) -> Event {
        Event::new(
            EventId::new(&"a".repeat(EventId::HEX_LENGTH)).expect("id"),
            UnsignedEvent::new(
                PublicKeyHex::new(&"1".repeat(PublicKeyHex::HEX_LENGTH)).expect("pubkey"),
                UnixTimestamp::new(1_714_124_433),
                Kind::new(30_402).expect("kind"),
                tags,
                content,
            ),
            SignatureHex::new(&"b".repeat(SignatureHex::HEX_LENGTH)).expect("sig"),
        )
    }
}
