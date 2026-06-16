#![forbid(unsafe_code)]

use serde::de::{self, Deserialize, Deserializer, MapAccess, Visitor};
use serde_json::value::RawValue;
use std::collections::BTreeSet;
use std::fmt;
use tangle_protocol::{SubscriptionId, TagName};
use tangle_store_pocket::{
    PocketOwnedEvent, PocketOwnedFilter, parse_pocket_event_json, parse_pocket_filter_json,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RuntimeClientMessage {
    Event(PocketOwnedEvent),
    Auth(PocketOwnedEvent),
    Req {
        subscription_id: SubscriptionId,
        filters: Vec<PocketOwnedFilter>,
        search_present: bool,
    },
    Count {
        subscription_id: SubscriptionId,
        filters: Vec<PocketOwnedFilter>,
        search_present: bool,
    },
    Close(SubscriptionId),
    NegOpen {
        subscription_id: SubscriptionId,
        filter: PocketOwnedFilter,
        message: String,
    },
    NegMsg {
        subscription_id: SubscriptionId,
        message: String,
    },
    NegClose(SubscriptionId),
}

pub(crate) fn parse_runtime_client_message(raw: &str) -> Result<RuntimeClientMessage, String> {
    let values = serde_json::from_str::<Vec<Box<RawValue>>>(raw)
        .map_err(|source| format!("client message JSON is invalid: {source}"))?;
    let command = parse_string_value(
        values.first().map(Box::as_ref),
        "client message command is missing",
        "client message command must be a string",
    )?;
    match command.as_str() {
        "EVENT" => parse_event_or_auth(&values, RuntimeClientMessage::Event),
        "AUTH" => parse_event_or_auth(&values, RuntimeClientMessage::Auth),
        "REQ" => parse_req_or_count(&values, "REQ", |subscription_id, filters| {
            RuntimeClientMessage::Req {
                subscription_id,
                search_present: filters.iter().any(|filter| filter.search_present),
                filters: filters
                    .into_iter()
                    .map(|filter| filter.filter)
                    .collect::<Vec<_>>(),
            }
        }),
        "COUNT" => parse_req_or_count(&values, "COUNT", |subscription_id, filters| {
            RuntimeClientMessage::Count {
                subscription_id,
                search_present: filters.iter().any(|filter| filter.search_present),
                filters: filters
                    .into_iter()
                    .map(|filter| filter.filter)
                    .collect::<Vec<_>>(),
            }
        }),
        "CLOSE" => parse_close(&values),
        "NEG-OPEN" => parse_neg_open(&values),
        "NEG-MSG" => parse_neg_msg(&values),
        "NEG-CLOSE" => parse_neg_close(&values),
        unsupported => Err(format!(
            "client message command `{unsupported}` is unsupported"
        )),
    }
}

fn parse_event_or_auth(
    values: &[Box<RawValue>],
    build: impl FnOnce(PocketOwnedEvent) -> RuntimeClientMessage,
) -> Result<RuntimeClientMessage, String> {
    if values.len() != 2 {
        return Err("EVENT and AUTH client messages must contain exactly one event".to_owned());
    }
    let event = parse_pocket_event_json(values[1].get().as_bytes())
        .map_err(|error| error.message().to_owned())?;
    Ok(build(event))
}

fn parse_req_or_count(
    values: &[Box<RawValue>],
    command: &'static str,
    build: impl FnOnce(SubscriptionId, Vec<RuntimeParsedFilter>) -> RuntimeClientMessage,
) -> Result<RuntimeClientMessage, String> {
    if values.len() < 3 {
        return Err(format!(
            "{command} client message must contain a subscription id and filters"
        ));
    }
    let subscription_id = parse_subscription_id(&values[1], command)?;
    let filters = values[2..]
        .iter()
        .map(|value| parse_filter(value))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(build(subscription_id, filters))
}

fn parse_close(values: &[Box<RawValue>]) -> Result<RuntimeClientMessage, String> {
    if values.len() != 2 {
        return Err("CLOSE client message must contain exactly 2 elements".to_owned());
    }
    parse_subscription_id(&values[1], "CLOSE").map(RuntimeClientMessage::Close)
}

fn parse_neg_open(values: &[Box<RawValue>]) -> Result<RuntimeClientMessage, String> {
    if values.len() != 4 {
        return Err(
            "NEG-OPEN client message must contain a subscription id, filter, and message"
                .to_owned(),
        );
    }
    Ok(RuntimeClientMessage::NegOpen {
        subscription_id: parse_subscription_id(&values[1], "NEG-OPEN")?,
        filter: parse_filter(&values[2])?.filter,
        message: parse_negentropy_message(&values[3], "NEG-OPEN")?,
    })
}

fn parse_neg_msg(values: &[Box<RawValue>]) -> Result<RuntimeClientMessage, String> {
    if values.len() != 3 {
        return Err("NEG-MSG client message must contain a subscription id and message".to_owned());
    }
    Ok(RuntimeClientMessage::NegMsg {
        subscription_id: parse_subscription_id(&values[1], "NEG-MSG")?,
        message: parse_negentropy_message(&values[2], "NEG-MSG")?,
    })
}

fn parse_neg_close(values: &[Box<RawValue>]) -> Result<RuntimeClientMessage, String> {
    if values.len() != 2 {
        return Err("NEG-CLOSE client message must contain exactly 2 elements".to_owned());
    }
    parse_subscription_id(&values[1], "NEG-CLOSE").map(RuntimeClientMessage::NegClose)
}

fn parse_subscription_id(
    value: &RawValue,
    command: &'static str,
) -> Result<SubscriptionId, String> {
    serde_json::from_str::<String>(value.get())
        .map_err(|_| format!("{command} subscription id must be a string"))
        .and_then(|subscription_id| SubscriptionId::new(&subscription_id))
}

fn parse_negentropy_message(value: &RawValue, command: &'static str) -> Result<String, String> {
    let message = serde_json::from_str::<String>(value.get())
        .map_err(|_| format!("{command} message must be a string"))?;
    if message.len() % 2 == 0
        && message
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        Ok(message)
    } else {
        Err(format!(
            "{command} message must be a lowercase even-length hex string"
        ))
    }
}

fn parse_filter(value: &RawValue) -> Result<RuntimeParsedFilter, String> {
    let shape = inspect_filter_shape(value.get())?;
    let search_present = shape.search;
    let pocket_filter_json = serde_json::Value::Object(shape.pocket_fields).to_string();
    let filter = parse_pocket_filter_json(pocket_filter_json.as_bytes())
        .map_err(|error| error.message().to_owned())?;
    Ok(RuntimeParsedFilter {
        filter,
        search_present,
    })
}

fn parse_string_value(
    value: Option<&RawValue>,
    missing: &'static str,
    invalid_type: &'static str,
) -> Result<String, String> {
    let Some(value) = value else {
        return Err(missing.to_owned());
    };
    serde_json::from_str::<String>(value.get()).map_err(|_| invalid_type.to_owned())
}

fn inspect_filter_shape(raw: &str) -> Result<RuntimeFilterShape, String> {
    let mut deserializer = serde_json::Deserializer::from_str(raw);
    let shape =
        RuntimeFilterShape::deserialize(&mut deserializer).map_err(filter_deserialize_error)?;
    deserializer
        .end()
        .map_err(|source| format!("filter JSON is invalid: {source}"))?;
    Ok(shape)
}

fn filter_deserialize_error(source: serde_json::Error) -> String {
    if source.classify() == serde_json::error::Category::Data {
        strip_json_location(&source.to_string()).to_owned()
    } else {
        format!("filter JSON is invalid: {source}")
    }
}

fn strip_json_location(message: &str) -> &str {
    message
        .split_once(" at line ")
        .map_or(message, |(head, _)| head)
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct RuntimeFilterShape {
    search: bool,
    pocket_fields: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RuntimeParsedFilter {
    filter: PocketOwnedFilter,
    search_present: bool,
}

impl<'de> Deserialize<'de> for RuntimeFilterShape {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(RuntimeFilterShapeVisitor)
    }
}

struct RuntimeFilterShapeVisitor;

impl<'de> Visitor<'de> for RuntimeFilterShapeVisitor {
    type Value = RuntimeFilterShape;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a filter JSON object")
    }

    fn visit_map<A>(self, mut object: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut fields = BTreeSet::new();
        let mut shape = RuntimeFilterShape::default();
        while let Some(field) = object.next_key::<String>()? {
            if !fields.insert(field.clone()) {
                return Err(de::Error::custom(format!(
                    "duplicate object field `{field}`"
                )));
            }
            let value = object.next_value::<serde_json::Value>()?;
            match field.as_str() {
                "ids" | "authors" | "kinds" => {
                    validate_non_empty_array(&field, &value)?;
                    shape.pocket_fields.insert(field, value);
                }
                "since" | "until" => {
                    validate_u64_field(&field, &value)?;
                    shape.pocket_fields.insert(field, value);
                }
                "limit" => {
                    validate_limit_field(&field, &value)?;
                    shape.pocket_fields.insert(field, value);
                }
                "search" => {
                    value.as_str().ok_or_else(|| {
                        de::Error::custom(format!("filter field `{field}` must be a string"))
                    })?;
                    shape.search = true;
                }
                tag_field if tag_field.starts_with('#') => {
                    validate_tag_filter_field(tag_field, &value)?;
                    shape.pocket_fields.insert(field, value);
                }
                unsupported => {
                    return Err(de::Error::custom(format!(
                        "filter field `{unsupported}` is unsupported"
                    )));
                }
            }
        }
        Ok(shape)
    }
}

fn validate_non_empty_array<E>(field: &str, value: &serde_json::Value) -> Result<(), E>
where
    E: de::Error,
{
    match value.as_array() {
        Some(items) if !items.is_empty() => Ok(()),
        _ => Err(de::Error::custom(format!(
            "filter field `{field}` must be a non-empty array"
        ))),
    }
}

fn validate_u64_field<E>(field: &str, value: &serde_json::Value) -> Result<(), E>
where
    E: de::Error,
{
    value.as_u64().map(|_| ()).ok_or_else(|| {
        de::Error::custom(format!(
            "filter field `{field}` must be an unsigned integer"
        ))
    })
}

fn validate_limit_field<E>(field: &str, value: &serde_json::Value) -> Result<(), E>
where
    E: de::Error,
{
    let limit = value.as_u64().ok_or_else(|| {
        de::Error::custom(format!(
            "filter field `{field}` must be an unsigned integer"
        ))
    })?;
    u32::try_from(limit)
        .map(|_| ())
        .map_err(|_| de::Error::custom(format!("filter field `{field}` exceeds Pocket range")))
}

fn validate_tag_filter_field<E>(field: &str, value: &serde_json::Value) -> Result<(), E>
where
    E: de::Error,
{
    let name = &field[1..];
    let tag_name = TagName::new(name).map_err(|reason| {
        de::Error::custom(format!("filter field `{field}` is invalid: {reason}"))
    })?;
    if !tag_name.is_indexable() {
        return Err(de::Error::custom(format!(
            "filter field `{field}` is invalid: tag name must be a single ASCII letter"
        )));
    }
    validate_non_empty_array(field, value)
}

#[cfg(test)]
mod tests {
    use super::{RuntimeClientMessage, parse_runtime_client_message};
    use serde_json::json;
    use tangle_protocol::event_to_value;
    use tangle_test_support::{FixtureKey, tangle_v2_auth_event, tangle_v2_event};

    #[test]
    fn runtime_parser_maps_event_and_auth_through_pocket_event_json() {
        let event = tangle_v2_event(FixtureKey::Member, 1_714_124_433, 1, Vec::new(), "hello")
            .expect("event");
        let RuntimeClientMessage::Event(parsed_event) =
            parse_runtime_client_message(&json!(["EVENT", event_to_value(&event)]).to_string())
                .expect("event")
        else {
            panic!("event expected")
        };
        assert_eq!(parsed_event.id().as_hex_string(), event.id().as_str());

        let auth =
            tangle_v2_auth_event(FixtureKey::Member, "challenge-a", 1_714_124_434).expect("auth");
        let RuntimeClientMessage::Auth(parsed_auth) =
            parse_runtime_client_message(&json!(["AUTH", event_to_value(&auth)]).to_string())
                .expect("auth")
        else {
            panic!("auth expected")
        };
        assert_eq!(parsed_auth.id().as_hex_string(), auth.id().as_str());
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
    fn runtime_parser_maps_req_count_and_close_without_protocol_parser_delegation() {
        let filter = json!({"ids":["a".repeat(64)],"authors":["b".repeat(64)],"kinds":[1],"#t":["market"],"since":10,"until":20,"limit":30});
        let RuntimeClientMessage::Req {
            subscription_id,
            filters,
            search_present,
        } = parse_runtime_client_message(&json!(["REQ", "sub", filter.clone()]).to_string())
            .expect("req")
        else {
            panic!("req expected")
        };
        assert_eq!(subscription_id.as_str(), "sub");
        assert_eq!(filters.len(), 1);
        assert!(!search_present);

        let RuntimeClientMessage::Count {
            subscription_id,
            filters,
            search_present,
        } = parse_runtime_client_message(&json!(["COUNT", "sub", filter]).to_string())
            .expect("count")
        else {
            panic!("count expected")
        };
        assert_eq!(subscription_id.as_str(), "sub");
        assert_eq!(filters.len(), 1);
        assert!(!search_present);
        assert_eq!(
            parse_runtime_client_message("[\"CLOSE\",\"sub\"]").expect("close"),
            RuntimeClientMessage::Close("sub".parse().expect("subscription"))
        );
    }

    #[test]
    fn runtime_parser_maps_negentropy_commands_without_protocol_parser_delegation() {
        let RuntimeClientMessage::NegOpen {
            subscription_id,
            filter,
            message,
        } = parse_runtime_client_message(
            &json!(["NEG-OPEN", "neg-sub", json!({"kinds": [1]}), "00ff"]).to_string(),
        )
        .expect("neg open")
        else {
            panic!("neg open expected")
        };
        assert_eq!(subscription_id.as_str(), "neg-sub");
        assert_eq!(filter.kinds().count(), 1);
        assert_eq!(message, "00ff");
        assert_eq!(
            parse_runtime_client_message("[\"NEG-MSG\",\"neg-sub\",\"\"]").expect("neg msg"),
            RuntimeClientMessage::NegMsg {
                subscription_id: "neg-sub".parse().expect("subscription"),
                message: String::new()
            }
        );
        assert_eq!(
            parse_runtime_client_message("[\"NEG-CLOSE\",\"neg-sub\"]").expect("neg close"),
            RuntimeClientMessage::NegClose("neg-sub".parse().expect("subscription"))
        );
    }

    #[test]
    fn runtime_parser_preserves_search_rejection_marker_before_dispatch() {
        let RuntimeClientMessage::Req { search_present, .. } =
            parse_runtime_client_message("[\"REQ\",\"sub\",{\"search\":\"carrots\",\"limit\":1}]")
                .expect("search req")
        else {
            panic!("req expected")
        };
        assert!(search_present);
    }

    #[test]
    fn runtime_parser_rejects_malformed_req_and_count_filters() {
        for (raw, expected) in [
            (
                "[\"REQ\",\"sub\",{\"ids\":[]}]",
                "filter field `ids` must be a non-empty array",
            ),
            (
                "[\"REQ\",\"sub\",{\"unknown\":true}]",
                "filter field `unknown` is unsupported",
            ),
            (
                "[\"REQ\",\"sub\",{\"#aa\":[\"value\"]}]",
                "filter field `#aa` is invalid: tag name must be a single ASCII letter",
            ),
            (
                "[\"COUNT\",\"sub\",{\"limit\":4294967296}]",
                "filter field `limit` exceeds Pocket range",
            ),
            (
                "[\"COUNT\",\"sub\",{\"authors\":[\"BAD\"]}]",
                "Too short reading pubkey",
            ),
            (
                "[\"REQ\",\"sub\",{\"limit\":1,\"limit\":2}]",
                "duplicate object field `limit`",
            ),
        ] {
            let actual = parse_runtime_client_message(raw).expect_err(raw);
            assert!(actual.contains(expected), "{actual}");
        }
    }

    #[test]
    fn runtime_parser_rejects_malformed_negentropy_commands() {
        for (raw, expected) in [
            (
                "[\"NEG-OPEN\",\"sub\",{}]",
                "NEG-OPEN client message must contain a subscription id, filter, and message",
            ),
            (
                "[\"NEG-OPEN\",1,{},\"00\"]",
                "NEG-OPEN subscription id must be a string",
            ),
            (
                "[\"NEG-OPEN\",\"sub\",1,\"00\"]",
                "expected a filter JSON object",
            ),
            (
                "[\"NEG-OPEN\",\"sub\",{},1]",
                "NEG-OPEN message must be a string",
            ),
            (
                "[\"NEG-MSG\",\"sub\",\"0\"]",
                "NEG-MSG message must be a lowercase even-length hex string",
            ),
            (
                "[\"NEG-MSG\",\"sub\",\"0G\"]",
                "NEG-MSG message must be a lowercase even-length hex string",
            ),
            (
                "[\"NEG-CLOSE\",\"sub\",{}]",
                "NEG-CLOSE client message must contain exactly 2 elements",
            ),
        ] {
            let actual = parse_runtime_client_message(raw).expect_err(raw);
            assert!(actual.contains(expected), "{actual}");
        }
    }
}
