#![forbid(unsafe_code)]

use crate::errors::BaseRelayError;
use std::str;
use tangle_protocol::{Event, EventId, Filter, event_to_value, filter_to_value, parse_event_json};
use tangle_store_pocket::{
    PocketEvent, PocketEventId, PocketOwnedEvent, PocketOwnedFilter, parse_pocket_event_json,
    parse_pocket_filter_json,
};

pub(crate) fn tangle_event_to_pocket(event: &Event) -> Result<PocketOwnedEvent, BaseRelayError> {
    let raw = event_to_value(event).to_string();
    parse_pocket_event_json(raw.as_bytes()).map_err(BaseRelayError::from)
}

pub(crate) fn tangle_filter_to_pocket(
    filter: &Filter,
) -> Result<PocketOwnedFilter, BaseRelayError> {
    let raw = filter_to_value(filter).to_string();
    parse_pocket_filter_json(raw.as_bytes()).map_err(BaseRelayError::from)
}

pub(crate) fn pocket_event_to_tangle(event: &PocketEvent) -> Result<Event, BaseRelayError> {
    let raw = event
        .as_json()
        .map_err(|error| BaseRelayError::error(error.to_string()))?;
    let raw = str::from_utf8(&raw).map_err(|error| BaseRelayError::error(error.to_string()))?;
    let raw = tangle_protocol::RawEventJson::new(raw)
        .map_err(|error| BaseRelayError::error(error.to_string()))?;
    parse_event_json(&raw).map_err(|error| BaseRelayError::error(error.to_string()))
}

pub(crate) fn pocket_event_id(event_id: &EventId) -> Result<PocketEventId, BaseRelayError> {
    PocketEventId::read_hex(event_id.as_str().as_bytes())
        .map_err(|error| BaseRelayError::error(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::{pocket_event_id, pocket_event_to_tangle, tangle_event_to_pocket};
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
}
