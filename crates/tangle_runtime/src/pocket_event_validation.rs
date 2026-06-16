#![forbid(unsafe_code)]

use crate::errors::BaseRelayError;
use tangle_protocol::{EventId, Kind, PublicKeyHex, UnixTimestamp};
use tangle_store_pocket::PocketEvent;

pub(crate) fn pocket_event_id(event: &PocketEvent) -> Result<EventId, BaseRelayError> {
    EventId::new(&event.id().as_hex_string()).map_err(BaseRelayError::error)
}

pub(crate) fn pocket_event_pubkey(event: &PocketEvent) -> Result<PublicKeyHex, BaseRelayError> {
    PublicKeyHex::new(&event.pubkey().as_hex_string()).map_err(BaseRelayError::error)
}

pub(crate) fn pocket_event_kind(event: &PocketEvent) -> Result<Kind, BaseRelayError> {
    Kind::new(u64::from(event.kind().as_u16())).map_err(BaseRelayError::error)
}

pub(crate) fn pocket_event_created_at(event: &PocketEvent) -> UnixTimestamp {
    UnixTimestamp::new(event.created_at().as_u64())
}

pub(crate) fn validate_pocket_event_shape(
    event: &PocketEvent,
    max_event_tags: usize,
    max_content_length: usize,
) -> Result<(), BaseRelayError> {
    let tags = event.tags().map_err(|error| {
        BaseRelayError::invalid(format!("malformed Pocket event tags: {error}"))
    })?;
    if tags.count() > max_event_tags {
        return Err(BaseRelayError::invalid(format!(
            "event tag count exceeds runtime max_event_tags {max_event_tags}"
        )));
    }
    if event.content().len() > max_content_length {
        return Err(BaseRelayError::invalid(format!(
            "event content length exceeds runtime max_content_length {max_content_length}"
        )));
    }
    Ok(())
}

pub(crate) fn is_pocket_nip70_protected_event(event: &PocketEvent) -> Result<bool, BaseRelayError> {
    let tags = event.tags().map_err(|error| {
        BaseRelayError::invalid(format!("malformed Pocket event tags: {error}"))
    })?;
    for tag in tags.iter() {
        if tag
            .into_iter()
            .next()
            .map(|value| value == b"-")
            .unwrap_or(false)
        {
            return Ok(true);
        }
    }
    Ok(false)
}

pub(crate) fn verify_pocket_event_signature(event: &PocketEvent) -> Result<(), BaseRelayError> {
    event
        .verify()
        .map_err(|error| BaseRelayError::invalid(error.to_string()))
}

#[cfg(test)]
pub(crate) fn pocket_canonical_event_json(event: &PocketEvent) -> Result<String, BaseRelayError> {
    use std::str;

    let tags = event
        .tags()
        .map_err(|error| BaseRelayError::invalid(format!("malformed Pocket event tags: {error}")))?
        .iter()
        .map(|tag| {
            tag.map(|value| {
                str::from_utf8(value)
                    .map(|value| serde_json::Value::String(value.to_owned()))
                    .map_err(|error| BaseRelayError::invalid(error.to_string()))
            })
            .collect::<Result<Vec<_>, _>>()
            .map(serde_json::Value::Array)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let content = str::from_utf8(event.content())
        .map_err(|error| BaseRelayError::invalid(error.to_string()))?;
    Ok(serde_json::json!([
        0,
        event.pubkey().as_hex_string(),
        event.created_at().as_u64(),
        u32::from(event.kind().as_u16()),
        tags,
        content
    ])
    .to_string())
}

#[cfg(test)]
mod tests {
    use super::{
        is_pocket_nip70_protected_event, pocket_canonical_event_json, pocket_event_id,
        pocket_event_pubkey, validate_pocket_event_shape, verify_pocket_event_signature,
    };
    use crate::pocket_conversion::tangle_event_to_pocket;
    use tangle_crypto::RelaySigner;
    use tangle_protocol::{Tag, event_to_value};
    use tangle_store_pocket::{
        PocketKind, PocketOwnedEvent, PocketOwnedTags, PocketTime, parse_pocket_event_json,
    };
    use tangle_test_support::{FixtureKey, tangle_v2_event};

    #[test]
    fn pocket_event_validation_verifies_valid_and_invalid_signatures() {
        let tags = PocketOwnedTags::empty();
        let pocket = pocket_event(12, 1_714_124_433, 1, &tags, b"hello");

        assert_eq!(verify_pocket_event_signature(&pocket), Ok(()));

        let signature_source = pocket_event(11, 1_714_124_433, 1, &tags, b"hello");
        let wrong_signature = PocketOwnedEvent::new(
            pocket.id(),
            pocket.kind(),
            pocket.pubkey(),
            signature_source.sig(),
            pocket.tags().expect("tags"),
            pocket.created_at(),
            pocket.content(),
        )
        .expect("wrong signature");
        assert!(
            verify_pocket_event_signature(&wrong_signature)
                .expect_err("signature")
                .prefixed_message()
                .starts_with("invalid:")
        );

        let id_source = pocket_event(12, 1_714_124_433, 1, &tags, b"other");
        let wrong_id = PocketOwnedEvent::new(
            id_source.id(),
            pocket.kind(),
            pocket.pubkey(),
            pocket.sig(),
            pocket.tags().expect("tags"),
            pocket.created_at(),
            pocket.content(),
        )
        .expect("wrong id");
        assert!(
            verify_pocket_event_signature(&wrong_id)
                .expect_err("id")
                .prefixed_message()
                .starts_with("invalid:")
        );
    }

    #[test]
    fn pocket_event_validation_detects_protected_tags_and_shape_limits() {
        let event = tangle_v2_event(
            FixtureKey::Member,
            1_714_124_433,
            1,
            vec![Tag::from_parts("-", &[]).expect("protected")],
            "hello",
        )
        .expect("event");
        let pocket = tangle_event_to_pocket(&event).expect("pocket");

        assert!(is_pocket_nip70_protected_event(&pocket).expect("protected"));
        assert_eq!(validate_pocket_event_shape(&pocket, 1, 5), Ok(()));
        assert_eq!(
            validate_pocket_event_shape(&pocket, 0, 5)
                .expect_err("tags")
                .prefixed_message(),
            "invalid: event tag count exceeds runtime max_event_tags 0"
        );
        assert_eq!(
            validate_pocket_event_shape(&pocket, 1, 4)
                .expect_err("content")
                .prefixed_message(),
            "invalid: event content length exceeds runtime max_content_length 4"
        );
    }

    #[test]
    fn pocket_event_validation_preserves_protocol_canonical_json() {
        let event = tangle_v2_event(
            FixtureKey::Member,
            1_714_124_433,
            1,
            vec![Tag::from_parts("t", &["market"]).expect("t")],
            "hello",
        )
        .expect("event");
        let raw = event_to_value(&event).to_string();
        let pocket = parse_pocket_event_json(raw.as_bytes()).expect("pocket");

        assert_eq!(pocket_event_id(&pocket).expect("id"), event.id().clone());
        assert_eq!(
            pocket_event_pubkey(&pocket).expect("pubkey"),
            event.unsigned().pubkey().clone()
        );
        assert_eq!(
            pocket_canonical_event_json(&pocket).expect("canonical"),
            event.unsigned().canonical_json()
        );
    }

    fn pocket_event(
        secret_byte: u8,
        created_at: u64,
        kind: u16,
        tags: &PocketOwnedTags,
        content: &[u8],
    ) -> PocketOwnedEvent {
        let secret = format!("{secret_byte:02x}").repeat(32);
        RelaySigner::from_secret_hex(&secret)
            .expect("signer")
            .sign_pocket_event(
                PocketKind::from_u16(kind),
                tags,
                PocketTime::from_u64(created_at),
                content,
            )
            .expect("pocket event")
    }
}
