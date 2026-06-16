#![forbid(unsafe_code)]

use crate::errors::BaseRelayError;
use std::str;
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
    let canonical = pocket_canonical_event_json(event)?;
    tangle_crypto::verify_event_signature_bytes(
        &canonical,
        &event.id().into_inner(),
        event.pubkey().as_bytes(),
        &event.sig().into_inner(),
    )
    .map_err(BaseRelayError::invalid)
}

pub(crate) fn pocket_canonical_event_json(event: &PocketEvent) -> Result<String, BaseRelayError> {
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
    use tangle_protocol::{Event, EventId, Tag, event_to_value};
    use tangle_store_pocket::parse_pocket_event_json;
    use tangle_test_support::{FixtureKey, tangle_v2_event};

    #[test]
    fn pocket_event_validation_verifies_valid_and_invalid_signatures() {
        let event = tangle_v2_event(FixtureKey::Member, 1_714_124_433, 1, Vec::new(), "hello")
            .expect("event");
        let pocket = tangle_event_to_pocket(&event).expect("pocket");

        assert_eq!(verify_pocket_event_signature(&pocket), Ok(()));

        let signature_source =
            tangle_v2_event(FixtureKey::Admin, 1_714_124_433, 1, Vec::new(), "hello")
                .expect("signature source");
        let wrong_signature = Event::new(
            event.id().clone(),
            event.unsigned().clone(),
            signature_source.sig().clone(),
        );
        let wrong_pocket = tangle_event_to_pocket(&wrong_signature).expect("wrong pocket");
        assert!(
            verify_pocket_event_signature(&wrong_pocket)
                .expect_err("signature")
                .prefixed_message()
                .starts_with("invalid:")
        );

        let wrong_id = Event::new(
            EventId::new(&"0".repeat(64)).expect("id"),
            event.unsigned().clone(),
            event.sig().clone(),
        );
        let wrong_id_pocket = tangle_event_to_pocket(&wrong_id).expect("wrong id pocket");
        assert!(
            verify_pocket_event_signature(&wrong_id_pocket)
                .expect_err("id")
                .prefixed_message()
                .starts_with("invalid: event id mismatch:")
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
}
