#![forbid(unsafe_code)]

use core::fmt;
use pocket_types::OwnedEvent as PocketOwnedEvent;
use tangle_crypto::RelaySigner;
use tangle_groups::{
    CanonicalRelayUrl, GroupGeneratedEventBuilder, GroupLimitsConfig, GroupOutboxPayload,
    GroupPolicyConfig, GroupRuntimeConfig, GroupRuntimeSettingsConfig, KIND_GROUP_CREATE_GROUP,
    KIND_GROUP_DELETE_EVENT, KIND_GROUP_DELETE_GROUP, KIND_GROUP_EDIT_METADATA,
    KIND_GROUP_JOIN_REQUEST, KIND_GROUP_LEAVE_REQUEST, KIND_GROUP_PUT_USER, KIND_GROUP_REMOVE_USER,
    RelaySecret,
};
use tangle_protocol::{
    Event, EventId, Kind, PublicKeyHex, Tag, UnixTimestamp, UnsignedEvent, event_to_value,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FixtureKey {
    Relay,
    Owner,
    Admin,
    Member,
    Outsider,
}

impl FixtureKey {
    pub fn public_key(self) -> PublicKeyHex {
        self.signer().public_key().clone()
    }

    fn signer(self) -> RelaySigner {
        let secret_byte = match self {
            Self::Relay => 9_u8,
            Self::Owner => 10_u8,
            Self::Admin => 11_u8,
            Self::Member => 12_u8,
            Self::Outsider => 13_u8,
        };
        RelaySigner::from_secret_hex(&lower_hex(&[secret_byte; 32])).expect("fixture signing key")
    }
}

impl fmt::Display for FixtureKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Relay => "relay",
            Self::Owner => "owner",
            Self::Admin => "admin",
            Self::Member => "member",
            Self::Outsider => "outsider",
        })
    }
}

pub fn build_fixture_event_from_parts(
    fixture_key: FixtureKey,
    created_at: u64,
    kind: u64,
    tags: Vec<Vec<String>>,
    content: &str,
) -> Result<Event, String> {
    let unsigned = UnsignedEvent::new(
        fixture_key.public_key(),
        UnixTimestamp::new(created_at),
        Kind::new(kind)?,
        tags.into_iter()
            .map(Tag::new)
            .collect::<Result<Vec<_>, _>>()?,
        content,
    );
    sign_unsigned_event(fixture_key, unsigned)
}

pub const TANGLE_V2_RELAY_URL: &str = "wss://relay.radroots.test";
pub const TANGLE_V2_RELAY_SECRET_HEX: &str =
    "7777777777777777777777777777777777777777777777777777777777777777";

pub fn tangle_v2_group_config(
    owner: FixtureKey,
    admins: &[FixtureKey],
) -> Result<GroupRuntimeConfig, String> {
    GroupRuntimeConfig::new(
        true,
        Some(CanonicalRelayUrl::new(TANGLE_V2_RELAY_URL).map_err(|error| error.to_string())?),
        Some(RelaySecret::from_hex(TANGLE_V2_RELAY_SECRET_HEX).map_err(|error| error.to_string())?),
        vec![owner.public_key()],
        admins.iter().map(|admin| admin.public_key()).collect(),
        GroupRuntimeSettingsConfig::new(GroupPolicyConfig::strict(), GroupLimitsConfig::default())
            .map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())
}

pub fn tangle_v2_relay_signer() -> Result<RelaySigner, String> {
    RelaySigner::from_secret_hex(TANGLE_V2_RELAY_SECRET_HEX).map_err(|error| error.to_string())
}

pub fn tangle_v2_generated_pocket_event(
    payload: &GroupOutboxPayload,
) -> Result<PocketOwnedEvent, String> {
    GroupGeneratedEventBuilder::new(tangle_v2_relay_signer()?)
        .sign_payload_pocket(payload)
        .map_err(|error| error.to_string())
}

pub fn tangle_v2_event(
    fixture_key: FixtureKey,
    created_at: u64,
    kind: u64,
    tags: Vec<Tag>,
    content: &str,
) -> Result<Event, String> {
    let unsigned = UnsignedEvent::new(
        fixture_key.public_key(),
        UnixTimestamp::new(created_at),
        Kind::new(kind)?,
        tags,
        content,
    );
    sign_unsigned_event(fixture_key, unsigned)
}

pub fn tangle_v2_auth_event(
    fixture_key: FixtureKey,
    challenge: &str,
    created_at: u64,
) -> Result<Event, String> {
    tangle_v2_event(
        fixture_key,
        created_at,
        22_242,
        vec![
            tangle_v2_tag("relay", &[TANGLE_V2_RELAY_URL])?,
            tangle_v2_tag("challenge", &[challenge])?,
        ],
        "",
    )
}

pub fn tangle_v2_group_create_event(
    fixture_key: FixtureKey,
    group_id: &str,
    created_at: u64,
    flags: &[&str],
) -> Result<Event, String> {
    let mut tags = vec![
        tangle_v2_group_tag(group_id)?,
        tangle_v2_tag("name", &[group_id])?,
    ];
    for flag in flags {
        tags.push(tangle_v2_tag(flag, &[])?);
    }
    tangle_v2_event(
        fixture_key,
        created_at,
        KIND_GROUP_CREATE_GROUP.into(),
        tags,
        "",
    )
}

pub fn tangle_v2_group_metadata_event(
    fixture_key: FixtureKey,
    group_id: &str,
    name: &str,
    created_at: u64,
    flags: &[&str],
) -> Result<Event, String> {
    let mut tags = vec![
        tangle_v2_group_tag(group_id)?,
        tangle_v2_tag("name", &[name])?,
    ];
    for flag in flags {
        tags.push(tangle_v2_tag(flag, &[])?);
    }
    tangle_v2_event(
        fixture_key,
        created_at,
        KIND_GROUP_EDIT_METADATA.into(),
        tags,
        "",
    )
}

pub fn tangle_v2_put_user_event(
    fixture_key: FixtureKey,
    group_id: &str,
    target: FixtureKey,
    created_at: u64,
) -> Result<Event, String> {
    tangle_v2_event(
        fixture_key,
        created_at,
        KIND_GROUP_PUT_USER.into(),
        vec![
            tangle_v2_group_tag(group_id)?,
            tangle_v2_pubkey_tag(target)?,
        ],
        "",
    )
}

pub fn tangle_v2_remove_user_event(
    fixture_key: FixtureKey,
    group_id: &str,
    target: FixtureKey,
    created_at: u64,
) -> Result<Event, String> {
    tangle_v2_event(
        fixture_key,
        created_at,
        KIND_GROUP_REMOVE_USER.into(),
        vec![
            tangle_v2_group_tag(group_id)?,
            tangle_v2_pubkey_tag(target)?,
        ],
        "",
    )
}

pub fn tangle_v2_join_event(
    fixture_key: FixtureKey,
    group_id: &str,
    created_at: u64,
) -> Result<Event, String> {
    tangle_v2_group_event(
        fixture_key,
        group_id,
        created_at,
        KIND_GROUP_JOIN_REQUEST.into(),
        "",
    )
}

pub fn tangle_v2_leave_event(
    fixture_key: FixtureKey,
    group_id: &str,
    created_at: u64,
) -> Result<Event, String> {
    tangle_v2_group_event(
        fixture_key,
        group_id,
        created_at,
        KIND_GROUP_LEAVE_REQUEST.into(),
        "",
    )
}

pub fn tangle_v2_delete_event_event(
    fixture_key: FixtureKey,
    group_id: &str,
    target: &Event,
    created_at: u64,
) -> Result<Event, String> {
    tangle_v2_event(
        fixture_key,
        created_at,
        KIND_GROUP_DELETE_EVENT.into(),
        vec![
            tangle_v2_group_tag(group_id)?,
            tangle_v2_event_tag(target.id())?,
        ],
        "",
    )
}

pub fn tangle_v2_delete_group_event(
    fixture_key: FixtureKey,
    group_id: &str,
    created_at: u64,
) -> Result<Event, String> {
    tangle_v2_group_event(
        fixture_key,
        group_id,
        created_at,
        KIND_GROUP_DELETE_GROUP.into(),
        "",
    )
}

pub fn tangle_v2_group_event(
    fixture_key: FixtureKey,
    group_id: &str,
    created_at: u64,
    kind: u64,
    content: &str,
) -> Result<Event, String> {
    tangle_v2_event(
        fixture_key,
        created_at,
        kind,
        vec![tangle_v2_group_tag(group_id)?],
        content,
    )
}

pub fn tangle_v2_group_tag(group_id: &str) -> Result<Tag, String> {
    tangle_v2_tag("h", &[group_id])
}

pub fn tangle_v2_address_group_tag(group_id: &str) -> Result<Tag, String> {
    tangle_v2_tag("d", &[group_id])
}

pub fn tangle_v2_pubkey_tag(fixture_key: FixtureKey) -> Result<Tag, String> {
    let pubkey = fixture_key.public_key();
    tangle_v2_tag("p", &[pubkey.as_str()])
}

pub fn tangle_v2_event_tag(event_id: &EventId) -> Result<Tag, String> {
    tangle_v2_tag("e", &[event_id.as_str()])
}

pub fn tangle_v2_tag(name: &str, values: &[&str]) -> Result<Tag, String> {
    let mut parts = Vec::with_capacity(values.len() + 1);
    parts.push(name.to_owned());
    parts.extend(values.iter().map(|value| (*value).to_owned()));
    Tag::new(parts)
}

pub fn fixture_event_json(event: &Event) -> serde_json::Value {
    event_to_value(event)
}

fn sign_unsigned_event(fixture_key: FixtureKey, unsigned: UnsignedEvent) -> Result<Event, String> {
    Ok(fixture_key.signer().sign_unsigned_event(unsigned))
}

#[cfg(test)]
fn fixed_hex_bytes(value: &str, expected: usize, scalar: &str) -> Result<Vec<u8>, String> {
    if value.len() != expected * 2 {
        return Err(format!(
            "{scalar} must decode to {expected} bytes, got {} hex characters",
            value.len()
        ));
    }
    let mut output = Vec::with_capacity(expected);
    for chunk in value.as_bytes().chunks_exact(2) {
        output.push((hex_value(chunk[0], scalar)? << 4) | hex_value(chunk[1], scalar)?);
    }
    Ok(output)
}

#[cfg(test)]
fn hex_value(value: u8, scalar: &str) -> Result<u8, String> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(format!("{scalar} must be lowercase hex")),
    }
}

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::{
        FixtureKey, build_fixture_event_from_parts, fixed_hex_bytes, fixture_event_json,
        tangle_v2_auth_event, tangle_v2_generated_pocket_event, tangle_v2_group_config,
        tangle_v2_group_create_event, tangle_v2_group_event, tangle_v2_group_metadata_event,
        tangle_v2_join_event, tangle_v2_put_user_event,
    };
    use tangle_crypto::{event_id_matches, verify_event_signature};
    use tangle_groups::{GroupOutboxPayload, KIND_GROUP_CREATE_GROUP, KIND_GROUP_METADATA};
    use tangle_protocol::UnixTimestamp;

    #[test]
    fn fixture_keys_have_stable_synthetic_public_keys() {
        assert_eq!(FixtureKey::Relay.to_string(), "relay");
        assert_eq!(FixtureKey::Owner.to_string(), "owner");
        assert_eq!(FixtureKey::Admin.to_string(), "admin");
        assert_eq!(FixtureKey::Member.to_string(), "member");
        assert_eq!(FixtureKey::Outsider.to_string(), "outsider");
        assert_eq!(
            FixtureKey::Owner.public_key().as_str(),
            "f76a39d05686e34a4420897e359371836145dd3973e3982568b60f8433adde6e"
        );
        assert_ne!(
            FixtureKey::Owner.public_key(),
            FixtureKey::Admin.public_key()
        );
    }

    #[test]
    fn tangle_v2_builders_create_deterministic_signed_events() {
        let first =
            tangle_v2_group_create_event(FixtureKey::Owner, "Farm", 1_714_124_433, &["private"])
                .expect("first");
        let second =
            tangle_v2_group_create_event(FixtureKey::Owner, "Farm", 1_714_124_433, &["private"])
                .expect("second");
        let auth =
            tangle_v2_auth_event(FixtureKey::Owner, "challenge-001", 1_714_124_434).expect("auth");

        assert_eq!(first.id(), second.id());
        assert_eq!(verify_event_signature(&first), Ok(()));
        assert_eq!(verify_event_signature(&auth), Ok(()));
        assert!(event_id_matches(&first));
        assert_eq!(first.unsigned().kind().as_u32(), KIND_GROUP_CREATE_GROUP);
        assert_eq!(auth.unsigned().kind().as_u32(), 22_242);
    }

    #[test]
    fn tangle_v2_builders_cover_group_config_and_generated_events() {
        let config =
            tangle_v2_group_config(FixtureKey::Owner, &[FixtureKey::Admin]).expect("config");
        let metadata = tangle_v2_group_metadata_event(
            FixtureKey::Owner,
            "Farm",
            "Market",
            1_714_124_435,
            &["hidden"],
        )
        .expect("metadata");
        let put =
            tangle_v2_put_user_event(FixtureKey::Admin, "Farm", FixtureKey::Member, 1_714_124_436)
                .expect("put");
        let join = tangle_v2_join_event(FixtureKey::Member, "Farm", 1_714_124_437).expect("join");
        let normal = tangle_v2_group_event(FixtureKey::Member, "Farm", 1_714_124_438, 1, "harvest")
            .expect("normal");
        let payload = GroupOutboxPayload::new(
            KIND_GROUP_METADATA,
            UnixTimestamp::new(1_714_124_439),
            vec![vec!["d".to_owned(), "Farm".to_owned()]],
            "",
        );
        let generated = tangle_v2_generated_pocket_event(&payload).expect("generated");

        assert!(config.enabled());
        assert_eq!(config.owner_pubkeys(), &[FixtureKey::Owner.public_key()]);
        assert_eq!(config.admin_pubkeys(), &[FixtureKey::Admin.public_key()]);
        assert_eq!(verify_event_signature(&metadata), Ok(()));
        assert_eq!(verify_event_signature(&put), Ok(()));
        assert_eq!(verify_event_signature(&join), Ok(()));
        assert_eq!(verify_event_signature(&normal), Ok(()));
        generated.verify().expect("generated signature");
        assert_eq!(u32::from(generated.kind().as_u16()), KIND_GROUP_METADATA);
    }

    #[test]
    fn fixture_json_uses_signed_event_shape() {
        let event =
            build_fixture_event_from_parts(FixtureKey::Member, 1_714_124_440, 1, Vec::new(), "hi")
                .expect("event");
        let json = fixture_event_json(&event);

        assert_eq!(verify_event_signature(&event), Ok(()));
        assert_eq!(json["kind"], 1);
        assert_eq!(json["content"], "hi");
    }

    #[test]
    fn fixture_builder_rejects_invalid_parts() {
        let bad_tag = build_fixture_event_from_parts(FixtureKey::Owner, 1, 1, vec![Vec::new()], "")
            .expect_err("tag");
        let bad_kind =
            build_fixture_event_from_parts(FixtureKey::Owner, 1, 4_294_967_296, Vec::new(), "")
                .expect_err("kind");

        assert_eq!(bad_tag, "tag must not be empty");
        assert_eq!(bad_kind, "kind must fit in u32, got 4294967296");
    }

    #[test]
    fn fixed_hex_bytes_validates_expected_width_and_lowercase() {
        assert_eq!(fixed_hex_bytes("0a", 1, "value"), Ok(vec![10]));
        assert_eq!(
            fixed_hex_bytes("0a", 2, "value").expect_err("width"),
            "value must decode to 2 bytes, got 2 hex characters"
        );
        assert_eq!(
            fixed_hex_bytes("0G", 1, "value").expect_err("case"),
            "value must be lowercase hex"
        );
    }
}
