#![forbid(unsafe_code)]

use core::fmt;
use tangle_groups::GroupError;
use tangle_protocol::{EventId, RelayMessage};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaseRelayError {
    prefix: &'static str,
    message: String,
}

impl BaseRelayError {
    pub fn invalid(message: impl Into<String>) -> Self {
        Self {
            prefix: "invalid",
            message: message.into(),
        }
    }

    pub fn auth_required(message: impl Into<String>) -> Self {
        Self {
            prefix: "auth-required",
            message: message.into(),
        }
    }

    pub fn rate_limited(message: impl Into<String>) -> Self {
        Self {
            prefix: "rate-limited",
            message: message.into(),
        }
    }

    pub fn restricted(message: impl Into<String>) -> Self {
        Self {
            prefix: "restricted",
            message: message.into(),
        }
    }

    pub fn error(message: impl Into<String>) -> Self {
        Self {
            prefix: "error",
            message: message.into(),
        }
    }

    pub fn prefixed_message(&self) -> String {
        format!("{}: {}", self.prefix, self.message)
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for BaseRelayError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.prefixed_message())
    }
}

impl std::error::Error for BaseRelayError {}

impl From<tangle_store_pocket::PocketStoreError> for BaseRelayError {
    fn from(error: tangle_store_pocket::PocketStoreError) -> Self {
        Self::error(error.to_string())
    }
}

impl From<GroupError> for BaseRelayError {
    fn from(error: GroupError) -> Self {
        Self::error(error.prefixed_message())
    }
}

pub(crate) fn ok_accepted(event_id: EventId, message: String) -> RelayMessage {
    RelayMessage::Ok {
        event_id,
        accepted: true,
        message,
    }
}

pub(crate) fn ok_rejected(event_id: EventId, message: String) -> RelayMessage {
    RelayMessage::Ok {
        event_id,
        accepted: false,
        message,
    }
}

#[cfg(test)]
mod tests {
    use super::BaseRelayError;

    #[test]
    fn relay_error_prefixes_are_stable() {
        assert_eq!(
            BaseRelayError::invalid("bad event").prefixed_message(),
            "invalid: bad event"
        );
        assert_eq!(
            BaseRelayError::auth_required("login").prefixed_message(),
            "auth-required: login"
        );
        assert_eq!(
            BaseRelayError::rate_limited("slow down").prefixed_message(),
            "rate-limited: slow down"
        );
        assert_eq!(
            BaseRelayError::restricted("nope").prefixed_message(),
            "restricted: nope"
        );
        assert_eq!(
            BaseRelayError::error("store").prefixed_message(),
            "error: store"
        );
    }
}
