#![forbid(unsafe_code)]

use core::fmt;
use core::str::FromStr;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EventId(String);

impl EventId {
    pub const HEX_LENGTH: usize = 64;

    pub fn new(value: &str) -> Result<Self, String> {
        require_lowercase_hex("event id", value, Self::HEX_LENGTH)?;
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for EventId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for EventId {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PublicKeyHex(String);

impl PublicKeyHex {
    pub const HEX_LENGTH: usize = 64;

    pub fn new(value: &str) -> Result<Self, String> {
        require_lowercase_hex("public key", value, Self::HEX_LENGTH)?;
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PublicKeyHex {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for PublicKeyHex {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SignatureHex(String);

impl SignatureHex {
    pub const HEX_LENGTH: usize = 128;

    pub fn new(value: &str) -> Result<Self, String> {
        require_lowercase_hex("signature", value, Self::HEX_LENGTH)?;
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SignatureHex {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for SignatureHex {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SubscriptionId(String);

impl SubscriptionId {
    pub const MAX_LENGTH: usize = 64;

    pub fn new(value: &str) -> Result<Self, String> {
        let actual = value.chars().count();
        if actual == 0 {
            return Err(empty_error("subscription id"));
        }
        if actual > Self::MAX_LENGTH {
            return Err(too_long_error("subscription id", Self::MAX_LENGTH, actual));
        }
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SubscriptionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for SubscriptionId {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UnixTimestamp(u64);

impl UnixTimestamp {
    pub fn new(value: u64) -> Self {
        Self(value)
    }

    pub fn as_u64(self) -> u64 {
        self.0
    }
}

impl fmt::Display for UnixTimestamp {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.0)
    }
}

impl From<u64> for UnixTimestamp {
    fn from(value: u64) -> Self {
        Self::new(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Kind(u32);

impl Kind {
    pub fn new(value: u64) -> Result<Self, String> {
        let value = u32::try_from(value).map_err(|_| kind_out_of_range_error(value))?;
        Ok(Self(value))
    }

    pub fn as_u32(self) -> u32 {
        self.0
    }
}

impl fmt::Display for Kind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.0)
    }
}

impl TryFrom<u64> for Kind {
    type Error = String;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

fn require_lowercase_hex(scalar: &'static str, value: &str, expected: usize) -> Result<(), String> {
    let actual = value.chars().count();
    if actual != expected {
        return Err(invalid_length_error(scalar, expected, actual));
    }
    if value
        .bytes()
        .any(|byte| !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase())
    {
        return Err(non_lowercase_hex_error(scalar));
    }
    Ok(())
}

fn empty_error(scalar: &'static str) -> String {
    format!("{scalar} must not be empty")
}

fn invalid_length_error(scalar: &'static str, expected: usize, actual: usize) -> String {
    format!("{scalar} must be {expected} characters, got {actual}")
}

fn too_long_error(scalar: &'static str, max: usize, actual: usize) -> String {
    format!("{scalar} must be at most {max} characters, got {actual}")
}

fn non_lowercase_hex_error(scalar: &'static str) -> String {
    format!("{scalar} must be lowercase hex")
}

fn kind_out_of_range_error(value: u64) -> String {
    format!("kind must fit in u32, got {value}")
}

#[cfg(test)]
mod tests {
    use super::{
        EventId, Kind, PublicKeyHex, SignatureHex, SubscriptionId, UnixTimestamp, empty_error,
        invalid_length_error, kind_out_of_range_error, non_lowercase_hex_error, too_long_error,
    };
    use core::str::FromStr;
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    #[test]
    fn event_id_accepts_lowercase_hex() {
        let value = "0".repeat(EventId::HEX_LENGTH);
        let event_id = EventId::new(&value).expect("event id");

        assert_eq!(event_id.as_str(), value);
        assert_eq!(event_id.to_string(), value);
        let cloned = event_id.clone();
        let mut hasher = DefaultHasher::new();
        cloned.hash(&mut hasher);
        assert_ne!(hasher.finish(), 0);
        assert_eq!(format!("{cloned:?}"), format!("EventId(\"{value}\")"));
        assert!(cloned <= event_id);
        assert_eq!(EventId::from_str(&value), Ok(event_id));
    }

    #[test]
    fn fixed_hex_scalars_reject_bad_lengths_and_characters() {
        assert_eq!(
            EventId::new(&"0".repeat(EventId::HEX_LENGTH - 1)),
            Err(format!(
                "event id must be {} characters, got {}",
                EventId::HEX_LENGTH,
                EventId::HEX_LENGTH - 1
            ))
        );
        assert_eq!(
            EventId::new("bad"),
            Err("event id must be 64 characters, got 3".to_owned())
        );
        let invalid_public_key = format!("{}G", "0".repeat(PublicKeyHex::HEX_LENGTH - 1));
        assert_eq!(
            PublicKeyHex::new(&invalid_public_key),
            Err("public key must be lowercase hex".to_owned())
        );
        let invalid_signature = format!("{}A", "0".repeat(SignatureHex::HEX_LENGTH - 1));
        assert_eq!(
            SignatureHex::new(&invalid_signature),
            Err("signature must be lowercase hex".to_owned())
        );
    }

    #[test]
    fn public_key_and_signature_display_values() {
        let public_key_value = "1".repeat(PublicKeyHex::HEX_LENGTH);
        let signature_value = "2".repeat(SignatureHex::HEX_LENGTH);
        let public_key = PublicKeyHex::new(&public_key_value).expect("pubkey");
        let signature = SignatureHex::new(&signature_value).expect("sig");

        assert_eq!(public_key.as_str(), "1".repeat(PublicKeyHex::HEX_LENGTH));
        assert_eq!(signature.as_str(), "2".repeat(SignatureHex::HEX_LENGTH));
        assert_eq!(public_key.to_string(), public_key.as_str());
        assert_eq!(signature.to_string(), signature.as_str());
        assert_eq!(PublicKeyHex::from_str(public_key.as_str()), Ok(public_key));
        assert_eq!(SignatureHex::from_str(signature.as_str()), Ok(signature));
    }

    #[test]
    fn subscription_id_rejects_empty_and_overlong_values() {
        assert_eq!(
            SubscriptionId::new(""),
            Err("subscription id must not be empty".to_owned())
        );
        assert_eq!(
            SubscriptionId::new(&"x".repeat(SubscriptionId::MAX_LENGTH + 1)),
            Err(format!(
                "subscription id must be at most {} characters, got {}",
                SubscriptionId::MAX_LENGTH,
                SubscriptionId::MAX_LENGTH + 1
            ))
        );
        let subscription = SubscriptionId::new("radroots").expect("subscription");
        assert_eq!(subscription.as_str(), "radroots");
        assert_eq!(subscription.to_string(), "radroots");
        assert_eq!(SubscriptionId::from_str("radroots"), Ok(subscription));
    }

    #[test]
    fn timestamp_and_kind_expose_numeric_values() {
        let timestamp = UnixTimestamp::new(1_714_124_433);
        let kind = Kind::new(30_402).expect("kind");

        assert_eq!(timestamp.as_u64(), 1_714_124_433);
        assert_eq!(timestamp.to_string(), "1714124433");
        assert_eq!(UnixTimestamp::from(7).as_u64(), 7);
        assert_eq!(kind.as_u32(), 30_402);
        assert_eq!(kind.to_string(), "30402");
        assert_eq!(Kind::try_from(30_402), Ok(kind));
    }

    #[test]
    fn kind_rejects_values_outside_u32() {
        let value = u64::from(u32::MAX) + 1;

        assert_eq!(
            Kind::new(value),
            Err(format!("kind must fit in u32, got {value}"))
        );
        assert_eq!(
            kind_out_of_range_error(value),
            format!("kind must fit in u32, got {value}")
        );
    }

    #[test]
    fn scalar_errors_have_stable_messages() {
        assert_eq!(empty_error("id"), "id must not be empty");
        assert_eq!(
            invalid_length_error("id", 64, 63),
            "id must be 64 characters, got 63"
        );
        assert_eq!(
            too_long_error("id", 64, 65),
            "id must be at most 64 characters, got 65"
        );
        assert_eq!(non_lowercase_hex_error("id"), "id must be lowercase hex");
    }
}
