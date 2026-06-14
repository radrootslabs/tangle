#![forbid(unsafe_code)]

pub mod classification;
pub mod errors;
pub mod ids;
pub mod kinds;
pub mod metadata;
pub mod outbox;
pub mod policy;
pub mod projection;
pub mod read_gate;
pub mod roles;
pub mod signing;
pub mod tags;
pub mod write_gate;

use core::fmt;
use serde::Deserialize;
use tangle_protocol::PublicKeyHex;

pub use classification::{GroupEventClass, classify_group_event};
pub use errors::{GroupError, GroupErrorKind, GroupReplyPrefix};
pub use ids::GroupId;
pub use kinds::{
    KIND_GROUP_ADMINS, KIND_GROUP_CREATE_GROUP, KIND_GROUP_CREATE_INVITE, KIND_GROUP_DELETE_EVENT,
    KIND_GROUP_DELETE_GROUP, KIND_GROUP_EDIT_METADATA, KIND_GROUP_JOIN_REQUEST,
    KIND_GROUP_LEAVE_REQUEST, KIND_GROUP_MEMBERS, KIND_GROUP_METADATA, KIND_GROUP_PUT_USER,
    KIND_GROUP_REMOVE_USER, KIND_GROUP_ROLES, KIND_GROUP_STATE_39004, NIP29_GROUP_KIND_VALUES,
    NIP29_MODERATION_KIND_VALUES, NIP29_RELAY_GENERATED_KIND_VALUES,
    NIP29_USER_REQUEST_KIND_VALUES,
};
pub use metadata::{GroupMetadata, SupportedKinds, parse_group_metadata};
pub use outbox::{
    GroupCrashHooks, GroupCrashPoint, GroupOutbox, GroupOutboxEffect, GroupOutboxKey,
    GroupOutboxPayload, GroupOutboxRecord, GroupOutboxStatus, OutboxRecoveryReadiness,
    OutboxReplayPlan,
};
pub use policy::{
    GroupAuthority, GroupWriteDecision, GroupWritePolicy, non_enumerating_group_error,
};
pub use projection::{
    CanonicalGroupEvent, GROUP_POLICY_VERSION, GROUP_PROJECTION_SCHEMA_VERSION,
    GroupLifecycleState, GroupProjection, GroupRecoveryReadiness, GroupSnapshotIds, GroupState,
    GroupTombstone, MemberState, MemberStatus, ProjectedRoleDefinition, ProjectionApplyOutcome,
    ProjectionCheckpoint, ProjectionOrderTuple, ProjectionRebuildReport, StoreOffset,
    group_current_key, member_current_key, projection_checkpoint_key, rebuild_group_projection,
    role_current_key, tombstone_key,
};
pub use read_gate::{GroupReadDecision, GroupReadGate};
pub use roles::{
    Capability, CapabilitySet, PERMANENT_RELAY_OVERRIDE_ROLE, RoleDefinition, RoleName,
    resolve_capabilities,
};
pub use signing::GroupGeneratedEventBuilder;
pub use tags::{GroupTag, GroupTagName, extract_group_tag, has_group_identity_tag};
pub use write_gate::{
    GroupAuthContext, require_group_auth_as_author, validate_client_group_event_structure,
};

#[derive(Clone, PartialEq, Eq)]
pub struct RelaySecret(String);

impl RelaySecret {
    pub const HEX_LENGTH: usize = 64;

    pub fn from_hex(value: &str) -> Result<Self, GroupConfigError> {
        require_lowercase_hex("groups.relay_secret", value, Self::HEX_LENGTH)?;
        Ok(Self(value.to_owned()))
    }

    pub fn expose_for_signing(&self) -> &str {
        &self.0
    }

    pub fn redacted(&self) -> &'static str {
        "<redacted>"
    }
}

impl fmt::Debug for RelaySecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RelaySecret(<redacted>)")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalRelayUrl(String);

impl CanonicalRelayUrl {
    pub fn new(value: &str) -> Result<Self, GroupConfigError> {
        if value.is_empty() {
            return Err(GroupConfigError::invalid(
                "groups.canonical_relay_url is required",
            ));
        }
        if value.trim() != value {
            return Err(GroupConfigError::invalid(
                "groups.canonical_relay_url must not contain leading or trailing whitespace",
            ));
        }
        if !(value.starts_with("ws://") || value.starts_with("wss://")) {
            return Err(GroupConfigError::invalid(
                "groups.canonical_relay_url must start with ws:// or wss://",
            ));
        }
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CanonicalRelayUrl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub struct GroupRedactionConfig {
    #[serde(default = "default_true")]
    redact_private_tags: bool,
    #[serde(default = "default_true")]
    redact_invite_codes: bool,
}

impl GroupRedactionConfig {
    pub fn strict() -> Self {
        Self {
            redact_private_tags: true,
            redact_invite_codes: true,
        }
    }

    pub fn redact_private_tags(&self) -> bool {
        self.redact_private_tags
    }

    pub fn redact_invite_codes(&self) -> bool {
        self.redact_invite_codes
    }
}

impl Default for GroupRedactionConfig {
    fn default() -> Self {
        Self::strict()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub struct GroupLimitsConfig {
    #[serde(default = "default_max_group_id_bytes")]
    max_group_id_bytes: u16,
    #[serde(default = "default_max_group_tags_per_event")]
    max_group_tags_per_event: u16,
    #[serde(default = "default_max_supported_kinds")]
    max_supported_kinds: u16,
    #[serde(default = "default_max_member_list_pubkeys")]
    max_member_list_pubkeys: u32,
    #[serde(default = "default_max_outbox_replay_batch")]
    max_outbox_replay_batch: u32,
}

impl GroupLimitsConfig {
    pub fn new(
        max_group_id_bytes: u16,
        max_group_tags_per_event: u16,
        max_supported_kinds: u16,
        max_member_list_pubkeys: u32,
        max_outbox_replay_batch: u32,
    ) -> Result<Self, GroupConfigError> {
        let value = Self {
            max_group_id_bytes,
            max_group_tags_per_event,
            max_supported_kinds,
            max_member_list_pubkeys,
            max_outbox_replay_batch,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), GroupConfigError> {
        require_positive("groups.limits.max_group_id_bytes", self.max_group_id_bytes)?;
        require_positive(
            "groups.limits.max_group_tags_per_event",
            self.max_group_tags_per_event,
        )?;
        require_positive(
            "groups.limits.max_supported_kinds",
            self.max_supported_kinds,
        )?;
        require_positive(
            "groups.limits.max_member_list_pubkeys",
            self.max_member_list_pubkeys,
        )?;
        require_positive(
            "groups.limits.max_outbox_replay_batch",
            self.max_outbox_replay_batch,
        )?;
        Ok(())
    }

    pub fn max_group_id_bytes(&self) -> u16 {
        self.max_group_id_bytes
    }

    pub fn max_group_tags_per_event(&self) -> u16 {
        self.max_group_tags_per_event
    }

    pub fn max_supported_kinds(&self) -> u16 {
        self.max_supported_kinds
    }

    pub fn max_member_list_pubkeys(&self) -> u32 {
        self.max_member_list_pubkeys
    }

    pub fn max_outbox_replay_batch(&self) -> u32 {
        self.max_outbox_replay_batch
    }
}

impl Default for GroupLimitsConfig {
    fn default() -> Self {
        Self {
            max_group_id_bytes: default_max_group_id_bytes(),
            max_group_tags_per_event: default_max_group_tags_per_event(),
            max_supported_kinds: default_max_supported_kinds(),
            max_member_list_pubkeys: default_max_member_list_pubkeys(),
            max_outbox_replay_batch: default_max_outbox_replay_batch(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupRuntimeConfig {
    enabled: bool,
    canonical_relay_url: Option<CanonicalRelayUrl>,
    relay_secret: Option<RelaySecret>,
    owner_pubkeys: Vec<PublicKeyHex>,
    admin_pubkeys: Vec<PublicKeyHex>,
    redaction: GroupRedactionConfig,
    limits: GroupLimitsConfig,
}

impl GroupRuntimeConfig {
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            canonical_relay_url: None,
            relay_secret: None,
            owner_pubkeys: Vec::new(),
            admin_pubkeys: Vec::new(),
            redaction: GroupRedactionConfig::default(),
            limits: GroupLimitsConfig::default(),
        }
    }

    pub fn new(
        enabled: bool,
        canonical_relay_url: Option<CanonicalRelayUrl>,
        relay_secret: Option<RelaySecret>,
        owner_pubkeys: Vec<PublicKeyHex>,
        admin_pubkeys: Vec<PublicKeyHex>,
        redaction: GroupRedactionConfig,
        limits: GroupLimitsConfig,
    ) -> Result<Self, GroupConfigError> {
        limits.validate()?;
        if enabled && canonical_relay_url.is_none() {
            return Err(GroupConfigError::invalid(
                "groups.canonical_relay_url is required when groups are enabled",
            ));
        }
        if enabled && relay_secret.is_none() {
            return Err(GroupConfigError::invalid(
                "groups.relay_secret is required when groups are enabled",
            ));
        }
        Ok(Self {
            enabled,
            canonical_relay_url,
            relay_secret,
            owner_pubkeys,
            admin_pubkeys,
            redaction,
            limits,
        })
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    pub fn canonical_relay_url(&self) -> Option<&CanonicalRelayUrl> {
        self.canonical_relay_url.as_ref()
    }

    pub fn relay_secret(&self) -> Option<&RelaySecret> {
        self.relay_secret.as_ref()
    }

    pub fn owner_pubkeys(&self) -> &[PublicKeyHex] {
        &self.owner_pubkeys
    }

    pub fn admin_pubkeys(&self) -> &[PublicKeyHex] {
        &self.admin_pubkeys
    }

    pub fn redaction(&self) -> GroupRedactionConfig {
        self.redaction
    }

    pub fn limits(&self) -> GroupLimitsConfig {
        self.limits
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupConfigError {
    message: String,
}

impl GroupConfigError {
    pub fn invalid(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for GroupConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for GroupConfigError {}

#[derive(Debug, Deserialize)]
struct GroupRuntimeConfigDocument {
    enabled: bool,
    canonical_relay_url: Option<String>,
    relay_secret: Option<String>,
    #[serde(default)]
    owner_pubkeys: Vec<String>,
    #[serde(default)]
    admin_pubkeys: Vec<String>,
    #[serde(default)]
    redaction: GroupRedactionConfig,
    #[serde(default)]
    limits: GroupLimitsConfig,
}

pub fn parse_group_runtime_config_json(raw: &str) -> Result<GroupRuntimeConfig, GroupConfigError> {
    let document = serde_json::from_str::<GroupRuntimeConfigDocument>(raw).map_err(|error| {
        GroupConfigError::invalid(format!("groups config JSON is invalid: {error}"))
    })?;
    let canonical_relay_url = document
        .canonical_relay_url
        .as_deref()
        .map(CanonicalRelayUrl::new)
        .transpose()?;
    let relay_secret = document
        .relay_secret
        .as_deref()
        .map(RelaySecret::from_hex)
        .transpose()?;
    GroupRuntimeConfig::new(
        document.enabled,
        canonical_relay_url,
        relay_secret,
        parse_pubkeys("groups.owner_pubkeys", document.owner_pubkeys)?,
        parse_pubkeys("groups.admin_pubkeys", document.admin_pubkeys)?,
        document.redaction,
        document.limits,
    )
}

fn parse_pubkeys(field: &str, values: Vec<String>) -> Result<Vec<PublicKeyHex>, GroupConfigError> {
    values
        .into_iter()
        .map(|value| {
            PublicKeyHex::new(&value).map_err(|error| {
                GroupConfigError::invalid(format!("{field} contains invalid pubkey: {error}"))
            })
        })
        .collect()
}

fn require_lowercase_hex(field: &str, value: &str, length: usize) -> Result<(), GroupConfigError> {
    if value.len() != length {
        return Err(GroupConfigError::invalid(format!(
            "{field} must be {length} lowercase hex characters"
        )));
    }
    if !value
        .as_bytes()
        .iter()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return Err(GroupConfigError::invalid(format!(
            "{field} must be lowercase hex"
        )));
    }
    Ok(())
}

fn require_positive<T>(field: &str, value: T) -> Result<(), GroupConfigError>
where
    T: Copy + PartialEq + From<u8> + fmt::Display,
{
    if value == T::from(0) {
        return Err(GroupConfigError::invalid(format!(
            "{field} must be greater than zero"
        )));
    }
    Ok(())
}

fn default_true() -> bool {
    true
}

fn default_max_group_id_bytes() -> u16 {
    128
}

fn default_max_group_tags_per_event() -> u16 {
    8
}

fn default_max_supported_kinds() -> u16 {
    512
}

fn default_max_member_list_pubkeys() -> u32 {
    100_000
}

fn default_max_outbox_replay_batch() -> u32 {
    1_000
}

#[cfg(test)]
mod tests {
    use super::{
        CanonicalRelayUrl, GroupLimitsConfig, RelaySecret, parse_group_runtime_config_json,
    };

    #[test]
    fn enabled_group_config_requires_relay_identity_material() {
        let error = parse_group_runtime_config_json(r#"{"enabled": true}"#).expect_err("error");

        assert_eq!(
            error.message(),
            "groups.canonical_relay_url is required when groups are enabled"
        );
    }

    #[test]
    fn enabled_group_config_parses_relay_identity_limits_and_flags() {
        let owner = "1".repeat(64);
        let admin = "2".repeat(64);
        let secret = "3".repeat(64);
        let raw = format!(
            r#"{{
                "enabled": true,
                "canonical_relay_url": "wss://relay.radroots.test",
                "relay_secret": "{secret}",
                "owner_pubkeys": ["{owner}"],
                "admin_pubkeys": ["{admin}"],
                "redaction": {{"redact_private_tags": true, "redact_invite_codes": true}},
                "limits": {{
                    "max_group_id_bytes": 64,
                    "max_group_tags_per_event": 4,
                    "max_supported_kinds": 32,
                    "max_member_list_pubkeys": 500,
                    "max_outbox_replay_batch": 25
                }}
            }}"#
        );

        let config = parse_group_runtime_config_json(&raw).expect("config");

        assert!(config.enabled());
        assert_eq!(
            config.canonical_relay_url().expect("url").as_str(),
            "wss://relay.radroots.test"
        );
        assert_eq!(config.owner_pubkeys().len(), 1);
        assert_eq!(config.admin_pubkeys().len(), 1);
        assert!(config.redaction().redact_private_tags());
        assert!(config.redaction().redact_invite_codes());
        assert_eq!(config.limits().max_group_id_bytes(), 64);
        assert_eq!(config.limits().max_group_tags_per_event(), 4);
        assert_eq!(config.limits().max_supported_kinds(), 32);
        assert_eq!(config.limits().max_member_list_pubkeys(), 500);
        assert_eq!(config.limits().max_outbox_replay_batch(), 25);
    }

    #[test]
    fn disabled_group_config_does_not_require_relay_secret() {
        let config = parse_group_runtime_config_json(r#"{"enabled": false}"#).expect("config");

        assert!(!config.enabled());
        assert!(config.canonical_relay_url().is_none());
        assert!(config.relay_secret().is_none());
    }

    #[test]
    fn relay_secret_debug_output_is_redacted() {
        let secret = RelaySecret::from_hex(&"a".repeat(64)).expect("secret");

        assert_eq!(format!("{secret:?}"), "RelaySecret(<redacted>)");
        assert_eq!(secret.redacted(), "<redacted>");
        assert_eq!(secret.expose_for_signing(), "a".repeat(64));
    }

    #[test]
    fn relay_identity_validation_is_strict() {
        assert_eq!(
            RelaySecret::from_hex(&"A".repeat(64))
                .expect_err("error")
                .message(),
            "groups.relay_secret must be lowercase hex"
        );
        assert_eq!(
            CanonicalRelayUrl::new(" wss://relay.radroots.test")
                .expect_err("error")
                .message(),
            "groups.canonical_relay_url must not contain leading or trailing whitespace"
        );
        assert_eq!(
            CanonicalRelayUrl::new("https://relay.radroots.test")
                .expect_err("error")
                .message(),
            "groups.canonical_relay_url must start with ws:// or wss://"
        );
    }

    #[test]
    fn limits_reject_zero_values() {
        let error = GroupLimitsConfig::new(0, 1, 1, 1, 1).expect_err("error");

        assert_eq!(
            error.message(),
            "groups.limits.max_group_id_bytes must be greater than zero"
        );
    }
}
