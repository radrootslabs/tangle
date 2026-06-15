#![forbid(unsafe_code)]

use crate::{errors::BaseRelayError, pocket_conversion::pocket_event_to_tangle};
use serde_json::value::RawValue;
use tangle_protocol::{ClientMessage, parse_client_message};
use tangle_store_pocket::parse_pocket_event_json;

pub(crate) fn parse_runtime_client_message(raw: &str) -> Result<ClientMessage, String> {
    let Ok(values) = serde_json::from_str::<Vec<Box<RawValue>>>(raw) else {
        return parse_client_message(raw);
    };
    let Some(command) = values
        .first()
        .and_then(|value| serde_json::from_str::<String>(value.get()).ok())
    else {
        return parse_client_message(raw);
    };
    match command.as_str() {
        "EVENT" => parse_event_or_auth(&values, ClientMessage::Event),
        "AUTH" => parse_event_or_auth(&values, ClientMessage::Auth),
        _ => parse_client_message(raw),
    }
}

fn parse_event_or_auth(
    values: &[Box<RawValue>],
    build: impl FnOnce(tangle_protocol::Event) -> ClientMessage,
) -> Result<ClientMessage, String> {
    if values.len() != 2 {
        return Err("EVENT and AUTH client messages must contain exactly one event".to_owned());
    }
    let event = parse_pocket_event_json(values[1].get().as_bytes())
        .map_err(|error| error.message().to_owned())
        .and_then(|event| pocket_event_to_tangle(&event).map_err(base_relay_error_message))?;
    Ok(build(event))
}

fn base_relay_error_message(error: BaseRelayError) -> String {
    error.message().to_owned()
}

#[cfg(test)]
mod tests {
    use super::parse_runtime_client_message;
    use serde_json::json;
    use tangle_protocol::{ClientMessage, event_to_value};
    use tangle_test_support::{FixtureKey, tangle_v2_auth_event, tangle_v2_event};

    #[test]
    fn runtime_parser_maps_event_and_auth_through_pocket_event_json() {
        let event = tangle_v2_event(FixtureKey::Member, 1_714_124_433, 1, Vec::new(), "hello")
            .expect("event");
        assert_eq!(
            parse_runtime_client_message(&json!(["EVENT", event_to_value(&event)]).to_string())
                .expect("event"),
            ClientMessage::Event(event.clone())
        );

        let auth =
            tangle_v2_auth_event(FixtureKey::Member, "challenge-a", 1_714_124_434).expect("auth");
        assert_eq!(
            parse_runtime_client_message(&json!(["AUTH", event_to_value(&auth)]).to_string())
                .expect("auth"),
            ClientMessage::Auth(auth)
        );
    }

    #[test]
    fn runtime_parser_rejects_malformed_event_and_auth_payloads() {
        assert_eq!(
            parse_runtime_client_message("[\"EVENT\"]").expect_err("missing event"),
            "EVENT and AUTH client messages must contain exactly one event"
        );
        assert_eq!(
            parse_runtime_client_message("[\"AUTH\",{},{}]").expect_err("too many auth values"),
            "EVENT and AUTH client messages must contain exactly one event"
        );
        assert!(
            !parse_runtime_client_message("[\"EVENT\",{\"id\":5}]")
                .expect_err("invalid event")
                .is_empty()
        );
    }

    #[test]
    fn runtime_parser_delegates_req_count_and_close_until_filter_slice() {
        assert!(matches!(
            parse_runtime_client_message("[\"REQ\",\"sub\",{\"kinds\":[1]}]").expect("req"),
            ClientMessage::Req { .. }
        ));
        assert!(matches!(
            parse_runtime_client_message("[\"COUNT\",\"sub\",{\"kinds\":[1]}]").expect("count"),
            ClientMessage::Count { .. }
        ));
        assert!(matches!(
            parse_runtime_client_message("[\"CLOSE\",\"sub\"]").expect("close"),
            ClientMessage::Close(_)
        ));
    }
}
