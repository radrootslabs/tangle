#![forbid(unsafe_code)]

use crate::errors::BaseRelayError;
#[cfg(test)]
use std::str;
use tangle_protocol::EventId;
#[cfg(test)]
use tangle_protocol::Filter;
#[cfg(test)]
use tangle_protocol::{Event, Kind, PublicKeyHex, SignatureHex, Tag, UnixTimestamp, UnsignedEvent};
#[cfg(test)]
use tangle_store_pocket::PocketEvent;
use tangle_store_pocket::PocketEventId;
#[cfg(test)]
use tangle_store_pocket::{
    PocketKind, PocketOwnedEvent, PocketOwnedFilter, PocketOwnedTags, PocketPubkey, PocketSig,
    PocketTags, PocketTime,
};

#[cfg(test)]
pub(crate) fn tangle_event_to_pocket(event: &Event) -> Result<PocketOwnedEvent, BaseRelayError> {
    let tags = tangle_tags_to_pocket(event.unsigned().tags())?;
    ensure_event_size(tags.as_bytes().len(), event.unsigned().content().len())?;
    PocketOwnedEvent::new(
        pocket_event_id(event.id())?,
        tangle_kind_to_pocket(event.unsigned().kind())?,
        pocket_pubkey(event.unsigned().pubkey())?,
        pocket_sig(event.sig())?,
        &tags,
        PocketTime::from_u64(event.unsigned().created_at().as_u64()),
        event.unsigned().content().as_bytes(),
    )
    .map_err(|error| BaseRelayError::error(error.to_string()))
}

#[cfg(test)]
pub(crate) fn tangle_filter_to_pocket(
    filter: &Filter,
) -> Result<PocketOwnedFilter, BaseRelayError> {
    let ids = filter
        .ids()
        .iter()
        .map(pocket_event_id)
        .collect::<Result<Vec<_>, _>>()?;
    let authors = filter
        .authors()
        .iter()
        .map(pocket_pubkey)
        .collect::<Result<Vec<_>, _>>()?;
    let kinds = filter
        .kinds()
        .iter()
        .copied()
        .map(tangle_kind_to_pocket)
        .collect::<Result<Vec<_>, _>>()?;
    let tag_parts = filter
        .tag_filters()
        .iter()
        .map(|(name, values)| {
            core::iter::once(name.as_str().to_owned())
                .chain(values.iter().map(|value| value.as_str().to_owned()))
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    ensure_filter_array_len("ids", ids.len())?;
    ensure_filter_array_len("authors", authors.len())?;
    ensure_filter_array_len("kinds", kinds.len())?;
    ensure_tag_size(PocketTags::output_size_needed(&tag_parts))?;
    let tags = PocketOwnedTags::new(&tag_parts)
        .map_err(|error| BaseRelayError::error(error.to_string()))?;
    let limit = filter
        .limit()
        .map(|limit| {
            u32::try_from(limit)
                .map_err(|_| BaseRelayError::invalid(format!("filter limit {limit} exceeds u32")))
        })
        .transpose()?;
    ensure_filter_size(&ids, &authors, &kinds, &tags)?;
    PocketOwnedFilter::new(
        &ids,
        &authors,
        &kinds,
        &tags,
        filter
            .since()
            .map(|since| PocketTime::from_u64(since.as_u64())),
        filter
            .until()
            .map(|until| PocketTime::from_u64(until.as_u64())),
        limit,
    )
    .map_err(|error| BaseRelayError::error(error.to_string()))
}

#[cfg(test)]
pub(crate) fn pocket_event_to_tangle(event: &PocketEvent) -> Result<Event, BaseRelayError> {
    let tags = event
        .tags()
        .map_err(|error| BaseRelayError::error(error.to_string()))?
        .iter()
        .map(|tag| {
            tag.map(|value| {
                str::from_utf8(value)
                    .map(str::to_owned)
                    .map_err(|error| BaseRelayError::error(error.to_string()))
            })
            .collect::<Result<Vec<_>, _>>()
            .and_then(|values| Tag::new(values).map_err(BaseRelayError::error))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let content = str::from_utf8(event.content())
        .map_err(|error| BaseRelayError::error(error.to_string()))?;
    Ok(Event::new(
        EventId::new(&event.id().as_hex_string()).map_err(BaseRelayError::error)?,
        UnsignedEvent::new(
            PublicKeyHex::new(&event.pubkey().as_hex_string()).map_err(BaseRelayError::error)?,
            UnixTimestamp::new(event.created_at().as_u64()),
            Kind::new(u64::from(event.kind().as_u16())).map_err(BaseRelayError::error)?,
            tags,
            content,
        ),
        SignatureHex::new(&event.sig().to_string()).map_err(BaseRelayError::error)?,
    ))
}

pub(crate) fn pocket_event_id(event_id: &EventId) -> Result<PocketEventId, BaseRelayError> {
    PocketEventId::read_hex(event_id.as_str().as_bytes())
        .map_err(|error| BaseRelayError::error(error.to_string()))
}

#[cfg(test)]
pub(crate) fn pocket_pubkey(pubkey: &PublicKeyHex) -> Result<PocketPubkey, BaseRelayError> {
    PocketPubkey::read_hex(pubkey.as_str().as_bytes())
        .map_err(|error| BaseRelayError::error(error.to_string()))
}

#[cfg(test)]
fn pocket_sig(sig: &SignatureHex) -> Result<PocketSig, BaseRelayError> {
    PocketSig::read_hex(sig.as_str().as_bytes())
        .map_err(|error| BaseRelayError::error(error.to_string()))
}

#[cfg(test)]
fn tangle_kind_to_pocket(kind: Kind) -> Result<PocketKind, BaseRelayError> {
    u16::try_from(kind.as_u32())
        .map(PocketKind::from_u16)
        .map_err(|_| {
            BaseRelayError::invalid(format!(
                "event kind {} exceeds Pocket kind range",
                kind.as_u32()
            ))
        })
}

#[cfg(test)]
fn tangle_tags_to_pocket(tags: &[Tag]) -> Result<PocketOwnedTags, BaseRelayError> {
    let parts = tags
        .iter()
        .map(|tag| tag.values().iter().map(String::as_str).collect::<Vec<_>>())
        .collect::<Vec<_>>();
    ensure_tag_size(PocketTags::output_size_needed(&parts))?;
    PocketOwnedTags::new(&parts).map_err(|error| BaseRelayError::error(error.to_string()))
}

#[cfg(test)]
fn ensure_tag_size(size: usize) -> Result<(), BaseRelayError> {
    if size > usize::from(u16::MAX) {
        return Err(BaseRelayError::invalid(format!(
            "tag section size {size} exceeds Pocket range"
        )));
    }
    Ok(())
}

#[cfg(test)]
fn ensure_filter_array_len(name: &str, len: usize) -> Result<(), BaseRelayError> {
    if len > usize::from(u16::MAX) {
        return Err(BaseRelayError::invalid(format!(
            "filter {name} count {len} exceeds Pocket range"
        )));
    }
    Ok(())
}

#[cfg(test)]
fn ensure_filter_size(
    ids: &[PocketEventId],
    authors: &[PocketPubkey],
    kinds: &[PocketKind],
    tags: &PocketTags,
) -> Result<(), BaseRelayError> {
    let size = tangle_store_pocket::PocketFilter::output_size_needed(ids, authors, kinds, tags);
    if size > usize::try_from(u32::MAX).expect("u32 max fits usize") {
        return Err(BaseRelayError::invalid(format!(
            "filter size {size} exceeds Pocket range"
        )));
    }
    Ok(())
}

#[cfg(test)]
fn ensure_event_size(tags_len: usize, content_len: usize) -> Result<(), BaseRelayError> {
    if content_len > usize::try_from(u32::MAX).expect("u32 max fits usize") {
        return Err(BaseRelayError::invalid(format!(
            "event content size {content_len} exceeds Pocket range"
        )));
    }
    let size = PocketEvent::output_size_needed(tags_len, content_len);
    if size > usize::try_from(u32::MAX).expect("u32 max fits usize") {
        return Err(BaseRelayError::invalid(format!(
            "event size {size} exceeds Pocket range"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        pocket_event_id, pocket_event_to_tangle, tangle_event_to_pocket, tangle_filter_to_pocket,
    };
    use tangle_protocol::{
        Event, EventId, Kind, PublicKeyHex, SignatureHex, Tag, UnixTimestamp, UnsignedEvent,
        filter_from_value,
    };
    use tangle_test_support::{FixtureKey, tangle_v2_event};

    #[test]
    fn pocket_event_conversion_round_trips_signed_events() {
        let event = tangle_v2_event(FixtureKey::Member, 1_714_124_433, 1, Vec::new(), "hello")
            .expect("event");
        let pocket = tangle_event_to_pocket(&event).expect("pocket");
        let converted = pocket_event_to_tangle(&pocket).expect("converted");

        assert_eq!(converted, event);
        pocket_event_id(event.id()).expect("event id");
    }

    #[test]
    fn pocket_event_conversion_preserves_tags_and_utf8_content_without_json_bridge() {
        let event = Event::new(
            EventId::new(&"1".repeat(64)).expect("id"),
            UnsignedEvent::new(
                PublicKeyHex::new(&"2".repeat(64)).expect("pubkey"),
                UnixTimestamp::new(1_714_124_433),
                Kind::new(30_402).expect("kind"),
                vec![
                    Tag::from_parts("d", &["market"]).expect("d"),
                    Tag::from_parts("p", &[&"3".repeat(64), "relay"]).expect("p"),
                ],
                "harvest \u{2022} update",
            ),
            SignatureHex::new(&"4".repeat(128)).expect("sig"),
        );
        let pocket = tangle_event_to_pocket(&event).expect("pocket");
        let converted = pocket_event_to_tangle(&pocket).expect("converted");

        assert_eq!(converted, event);
    }

    #[test]
    fn pocket_filter_conversion_uses_native_filter_matching() {
        let event = tangle_v2_event(
            FixtureKey::Member,
            1_714_124_433,
            1,
            vec![Tag::from_parts("t", &["market"]).expect("tag")],
            "hello",
        )
        .expect("event");
        let filter = filter_from_value(&serde_json::json!({
            "authors": [event.unsigned().pubkey().as_str()],
            "kinds": [1],
            "#t": ["market"],
            "since": 1_714_124_400,
            "limit": 1,
            "search": "ignored by Pocket and Tangle matching"
        }))
        .expect("filter");
        let pocket_event = tangle_event_to_pocket(&event).expect("event");
        let pocket_filter = tangle_filter_to_pocket(&filter).expect("filter");

        assert!(pocket_filter.event_matches(&pocket_event).expect("match"));
    }

    #[test]
    fn pocket_filter_conversion_matches_tangle_filter_matching_for_supported_fields() {
        let event = tangle_v2_event(
            FixtureKey::Member,
            1_714_124_433,
            1,
            vec![
                Tag::from_parts("e", &[&"a".repeat(64)]).expect("e"),
                Tag::from_parts("p", &[FixtureKey::Owner.public_key().as_str()]).expect("p"),
                Tag::from_parts("t", &["market"]).expect("t"),
            ],
            "filter parity",
        )
        .expect("event");
        let pocket_event = tangle_event_to_pocket(&event).expect("event");
        for value in [
            serde_json::json!({"ids": [event.id().as_str()]}),
            serde_json::json!({"authors": [event.unsigned().pubkey().as_str()]}),
            serde_json::json!({"kinds": [1]}),
            serde_json::json!({"#e": ["a".repeat(64)]}),
            serde_json::json!({"#p": [FixtureKey::Owner.public_key().as_str()]}),
            serde_json::json!({"#t": ["market"]}),
            serde_json::json!({"since": 1_714_124_400, "until": 1_714_124_500}),
            serde_json::json!({"limit": 1}),
            serde_json::json!({"kinds": [2]}),
            serde_json::json!({"#t": ["other"]}),
        ] {
            let filter = filter_from_value(&value).expect("filter");
            let pocket_filter = tangle_filter_to_pocket(&filter).expect("pocket filter");

            assert_eq!(
                pocket_filter.event_matches(&pocket_event).expect("match"),
                filter.matches(&event)
            );
        }
    }
}
