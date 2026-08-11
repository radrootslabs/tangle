#![forbid(unsafe_code)]

use crate::errors::BaseRelayError;
use std::str;
use tangle_protocol::{RelayMessage, SubscriptionId};
use tangle_store_pocket::PocketOwnedEvent;

#[derive(Debug, Clone, PartialEq)]
pub enum RuntimeRelayMessage {
    Event {
        subscription_id: SubscriptionId,
        event: PocketOwnedEvent,
    },
    Protocol(RelayMessage),
}

impl RuntimeRelayMessage {
    pub(crate) fn event(subscription_id: SubscriptionId, event: PocketOwnedEvent) -> Self {
        Self::Event {
            subscription_id,
            event,
        }
    }

    pub fn encode(&self) -> Result<String, BaseRelayError> {
        match self {
            Self::Event {
                subscription_id,
                event,
            } => encode_pocket_event_message(subscription_id, event),
            Self::Protocol(message) => Ok(message.encode()),
        }
    }

    pub(crate) fn map_protocol(self, mapper: impl FnOnce(RelayMessage) -> RelayMessage) -> Self {
        match self {
            Self::Event {
                subscription_id,
                event,
            } => Self::Event {
                subscription_id,
                event,
            },
            Self::Protocol(message) => Self::Protocol(mapper(message)),
        }
    }

    pub(crate) fn into_protocol_control_message(self) -> Result<RelayMessage, BaseRelayError> {
        match self {
            Self::Event { .. } => Err(BaseRelayError::error(
                "event-bearing runtime messages must be encoded from Pocket events",
            )),
            Self::Protocol(message) => Ok(message),
        }
    }
}

impl From<RelayMessage> for RuntimeRelayMessage {
    fn from(message: RelayMessage) -> Self {
        Self::Protocol(message)
    }
}

pub(crate) fn protocol_control_messages(
    messages: Vec<RuntimeRelayMessage>,
) -> Result<Vec<RelayMessage>, BaseRelayError> {
    messages
        .into_iter()
        .map(RuntimeRelayMessage::into_protocol_control_message)
        .collect()
}

#[cfg(test)]
pub(crate) fn protocol_messages_for_test(
    messages: Vec<RuntimeRelayMessage>,
) -> Result<Vec<RelayMessage>, BaseRelayError> {
    messages
        .into_iter()
        .map(|message| match message {
            RuntimeRelayMessage::Event {
                subscription_id,
                event,
            } => Ok(RelayMessage::Event {
                subscription_id,
                event: crate::pocket_conversion::pocket_event_to_tangle(&event)?,
            }),
            RuntimeRelayMessage::Protocol(message) => Ok(message),
        })
        .collect()
}

fn encode_pocket_event_message(
    subscription_id: &SubscriptionId,
    event: &PocketOwnedEvent,
) -> Result<String, BaseRelayError> {
    let subscription = serde_json::to_string(subscription_id.as_str()).map_err(|error| {
        BaseRelayError::error(format!("outbound subscription encode failed: {error}"))
    })?;
    let event_json = event.as_json().map_err(|error| {
        BaseRelayError::error(format!("outbound Pocket event encode failed: {error}"))
    })?;
    let event_json = str::from_utf8(&event_json).map_err(|error| {
        BaseRelayError::error(format!("outbound Pocket event JSON is not UTF-8: {error}"))
    })?;
    Ok(format!(r#"["EVENT",{subscription},{event_json}]"#))
}

#[cfg(test)]
mod tests {
    use super::RuntimeRelayMessage;
    use crate::pocket_conversion::tangle_event_to_pocket;
    use serde_json::json;
    use tangle_protocol::{RelayMessage, SubscriptionId, event_to_value, relay_message_to_value};
    use tangle_test_support::{FixtureKey, tangle_v2_event};

    #[test]
    fn outbound_pocket_event_encoding_preserves_event_fields() {
        let event = tangle_v2_event(
            FixtureKey::Member,
            1_714_124_433,
            1,
            vec![tangle_protocol::Tag::from_parts("t", &["market"]).expect("tag")],
            "fresh carrots",
        )
        .expect("event");
        let pocket = tangle_event_to_pocket(&event).expect("pocket");
        let subscription_id = SubscriptionId::new("outbound-event").expect("subscription");
        let encoded = RuntimeRelayMessage::event(subscription_id.clone(), pocket)
            .encode()
            .expect("encoded");

        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&encoded).expect("json"),
            json!(["EVENT", subscription_id.as_str(), event_to_value(&event)])
        );
    }

    #[test]
    fn outbound_protocol_messages_still_use_protocol_encoder() {
        let subscription_id = SubscriptionId::new("outbound-eose").expect("subscription");
        let message = RelayMessage::Eose(subscription_id);

        assert_eq!(
            serde_json::from_str::<serde_json::Value>(
                &RuntimeRelayMessage::from(message.clone())
                    .encode()
                    .expect("encoded")
            )
            .expect("json"),
            relay_message_to_value(&message)
        );
    }

    #[test]
    fn protocol_mapping_never_rewrites_event_payloads() {
        let subscription_id = SubscriptionId::new("outbound-map").expect("subscription");
        let event = tangle_v2_event(
            FixtureKey::Member,
            1_714_124_433,
            1,
            Vec::new(),
            "unchanged",
        )
        .expect("event");
        let pocket = tangle_event_to_pocket(&event).expect("pocket");
        let event_message = RuntimeRelayMessage::event(subscription_id.clone(), pocket);
        let mapped_event = event_message
            .clone()
            .map_protocol(|_| RelayMessage::Notice("must not replace event payload".to_owned()));
        assert_eq!(mapped_event, event_message);

        let mapped_protocol =
            RuntimeRelayMessage::from(RelayMessage::Notice("internal diagnostic".to_owned()))
                .map_protocol(|_| RelayMessage::Notice("public code".to_owned()));
        assert_eq!(
            mapped_protocol,
            RuntimeRelayMessage::from(RelayMessage::Notice("public code".to_owned()))
        );
    }
}
