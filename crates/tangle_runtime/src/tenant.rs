#![forbid(unsafe_code)]

use crate::errors::BaseRelayError;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TenantId(String);

impl TenantId {
    pub const MAX_LENGTH: usize = 64;

    pub fn new(value: impl Into<String>) -> Result<Self, BaseRelayError> {
        let value = value.into();
        validate_identifier(
            "tenant_id",
            &value,
            Self::MAX_LENGTH,
            IdentifierAlphabet::TenantId,
        )?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for TenantId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TenantSchema(String);

impl TenantSchema {
    pub const MAX_LENGTH: usize = 64;

    pub fn new(value: impl Into<String>) -> Result<Self, BaseRelayError> {
        let value = value.into();
        validate_identifier(
            "tenant_schema",
            &value,
            Self::MAX_LENGTH,
            IdentifierAlphabet::TenantSchema,
        )?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for TenantSchema {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CanonicalHost(String);

impl CanonicalHost {
    pub fn new(value: impl AsRef<str>) -> Result<Self, BaseRelayError> {
        let raw = value.as_ref();
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(BaseRelayError::invalid("host must not be empty"));
        }
        if trimmed != raw {
            return Err(BaseRelayError::invalid(
                "host must not contain leading or trailing whitespace",
            ));
        }
        if trimmed.contains("://") {
            return Err(BaseRelayError::invalid(
                "host must not include a URL scheme",
            ));
        }
        if trimmed.chars().any(|character| {
            character.is_whitespace() || matches!(character, '/' | '\\' | '?' | '#' | '@')
        }) {
            return Err(BaseRelayError::invalid(
                "host must not contain whitespace, path, query, fragment, or credentials",
            ));
        }
        if trimmed.contains('[') || trimmed.contains(']') {
            return Err(BaseRelayError::invalid(
                "host must use a DNS name or IPv4 address with optional port",
            ));
        }
        let lowercase = trimmed.to_ascii_lowercase();
        let (host, port) = split_host_port(&lowercase)?;
        validate_host_name(host)?;
        if let Some(port) = port {
            validate_port(port)?;
        }
        Ok(Self(lowercase))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CanonicalHost {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TenantRelayUrl(String);

impl TenantRelayUrl {
    pub fn new(value: impl AsRef<str>) -> Result<Self, BaseRelayError> {
        let raw = value.as_ref();
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(BaseRelayError::invalid("relay_url must not be empty"));
        }
        if trimmed != raw {
            return Err(BaseRelayError::invalid(
                "relay_url must not contain leading or trailing whitespace",
            ));
        }
        if trimmed.chars().any(char::is_whitespace) {
            return Err(BaseRelayError::invalid(
                "relay_url must not contain whitespace",
            ));
        }
        let (scheme, rest) = trimmed
            .split_once("://")
            .ok_or_else(|| BaseRelayError::invalid("relay_url must include ws:// or wss://"))?;
        let scheme = match scheme {
            "ws" => "ws",
            "wss" => "wss",
            _ => {
                return Err(BaseRelayError::invalid(
                    "relay_url must start with ws:// or wss://",
                ));
            }
        };
        let authority = rest.split('/').next().unwrap_or_default();
        if authority.is_empty() {
            return Err(BaseRelayError::invalid("relay_url host must not be empty"));
        }
        let host = CanonicalHost::new(authority)?;
        let suffix = rest
            .strip_prefix(authority)
            .expect("authority came from rest prefix");
        Ok(Self(format!("{scheme}://{}{}", host.as_str(), suffix)))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for TenantRelayUrl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Clone, Copy)]
enum IdentifierAlphabet {
    TenantId,
    TenantSchema,
}

fn validate_identifier(
    field: &str,
    value: &str,
    max_length: usize,
    alphabet: IdentifierAlphabet,
) -> Result<(), BaseRelayError> {
    if value.is_empty() {
        return Err(BaseRelayError::invalid(format!(
            "{field} must not be empty"
        )));
    }
    if value.len() > max_length {
        return Err(BaseRelayError::invalid(format!(
            "{field} must be {max_length} bytes or less"
        )));
    }
    if value.trim() != value {
        return Err(BaseRelayError::invalid(format!(
            "{field} must not contain leading or trailing whitespace"
        )));
    }
    let Some(first) = value.as_bytes().first().copied() else {
        return Err(BaseRelayError::invalid(format!(
            "{field} must not be empty"
        )));
    };
    if !first.is_ascii_lowercase() {
        return Err(BaseRelayError::invalid(format!(
            "{field} must start with a lowercase ASCII letter"
        )));
    }
    let valid = value.bytes().all(|byte| match alphabet {
        IdentifierAlphabet::TenantId => {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_' || byte == b'-'
        }
        IdentifierAlphabet::TenantSchema => {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_'
        }
    });
    if !valid {
        return Err(BaseRelayError::invalid(format!(
            "{field} must contain only lowercase ASCII letters, digits, and approved separators"
        )));
    }
    Ok(())
}

fn split_host_port(host: &str) -> Result<(&str, Option<&str>), BaseRelayError> {
    if host.matches(':').count() > 1 {
        return Err(BaseRelayError::invalid(
            "host must not contain multiple port separators",
        ));
    }
    if let Some((name, port)) = host.rsplit_once(':') {
        if name.is_empty() || port.is_empty() {
            return Err(BaseRelayError::invalid(
                "host and port must both be present",
            ));
        }
        Ok((name, Some(port)))
    } else {
        Ok((host, None))
    }
}

fn validate_host_name(host: &str) -> Result<(), BaseRelayError> {
    if host.is_empty() {
        return Err(BaseRelayError::invalid("host name must not be empty"));
    }
    for label in host.split('.') {
        if label.is_empty() {
            return Err(BaseRelayError::invalid("host labels must not be empty"));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(BaseRelayError::invalid(
                "host labels must not start or end with hyphen",
            ));
        }
        if !label
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return Err(BaseRelayError::invalid(
                "host labels must contain only lowercase ASCII letters, digits, and hyphen",
            ));
        }
    }
    Ok(())
}

fn validate_port(port: &str) -> Result<(), BaseRelayError> {
    if !port.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(BaseRelayError::invalid("host port must be numeric"));
    }
    let parsed = port
        .parse::<u16>()
        .map_err(|_| BaseRelayError::invalid("host port must be between 1 and 65535"))?;
    if parsed == 0 {
        return Err(BaseRelayError::invalid(
            "host port must be between 1 and 65535",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{CanonicalHost, TenantId, TenantRelayUrl, TenantSchema};

    #[test]
    fn tenant_identity_types_accept_canonical_values() {
        assert_eq!(
            TenantId::new("farmers-market").expect("id").as_str(),
            "farmers-market"
        );
        assert_eq!(
            TenantSchema::new("farmers_market")
                .expect("schema")
                .as_str(),
            "farmers_market"
        );
        assert_eq!(
            CanonicalHost::new("Relay.Example.TEST:8083")
                .expect("host")
                .as_str(),
            "relay.example.test:8083"
        );
        assert_eq!(
            TenantRelayUrl::new("wss://Relay.Example.TEST:443/groups")
                .expect("url")
                .as_str(),
            "wss://relay.example.test:443/groups"
        );
    }

    #[test]
    fn tenant_identity_types_reject_noncanonical_values() {
        for value in ["", "Farm", "farm space", "farm.market"] {
            assert!(TenantId::new(value).is_err());
        }
        for value in ["", "farm-market", "Farm", "_farm"] {
            assert!(TenantSchema::new(value).is_err());
        }
        for value in [
            "",
            " https://relay.example.test",
            "https://relay.example.test",
            "relay.example.test/path",
            "user@relay.example.test",
        ] {
            assert!(CanonicalHost::new(value).is_err());
        }
        for value in [
            "",
            "http://relay.example.test",
            "wss://",
            "wss://user@relay.example.test",
            "wss://relay example.test",
        ] {
            assert!(TenantRelayUrl::new(value).is_err());
        }
    }
}
