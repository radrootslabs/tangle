#![forbid(unsafe_code)]

use crate::{
    errors::BaseRelayError,
    pocket_event_validation::{
        pocket_event_created_at, pocket_event_kind, pocket_event_pubkey,
        verify_pocket_event_signature,
    },
};
use std::collections::BTreeSet;
use std::str;
#[cfg(test)]
use tangle_crypto::verify_event_signature;
#[cfg(test)]
use tangle_protocol::Event;
use tangle_protocol::{PublicKeyHex, RelayMessage, UnixTimestamp};
use tangle_store_pocket::PocketEvent;

pub fn generate_auth_challenge() -> Result<String, BaseRelayError> {
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes).map_err(|error| {
        BaseRelayError::error(format!("auth challenge generation failed: {error}"))
    })?;
    Ok(lower_hex(&bytes))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaseAuthState {
    relay_url: String,
    accepted_relay_urls: BTreeSet<String>,
    challenge_ttl_seconds: u64,
    created_at_skew_seconds: u64,
    challenge: Option<BaseAuthChallenge>,
    authenticated_pubkeys: BTreeSet<PublicKeyHex>,
}

impl BaseAuthState {
    pub fn new(
        relay_url: impl Into<String>,
        challenge_ttl_seconds: u64,
        created_at_skew_seconds: u64,
    ) -> Result<Self, BaseRelayError> {
        let relay_url = relay_url.into();
        if relay_url.trim().is_empty() {
            return Err(BaseRelayError::invalid("auth relay URL must not be empty"));
        }
        if challenge_ttl_seconds == 0 {
            return Err(BaseRelayError::invalid(
                "auth challenge ttl must be greater than zero",
            ));
        }
        if created_at_skew_seconds == 0 {
            return Err(BaseRelayError::invalid(
                "auth created_at skew must be greater than zero",
            ));
        }
        Ok(Self {
            relay_url,
            accepted_relay_urls: BTreeSet::new(),
            challenge_ttl_seconds,
            created_at_skew_seconds,
            challenge: None,
            authenticated_pubkeys: BTreeSet::new(),
        })
    }

    pub fn accept_relay_url(&mut self, relay_url: impl Into<String>) -> Result<(), BaseRelayError> {
        let relay_url = relay_url.into();
        if relay_url.trim().is_empty() {
            return Err(BaseRelayError::invalid("auth relay URL must not be empty"));
        }
        self.accepted_relay_urls.insert(relay_url);
        Ok(())
    }

    pub fn issue_challenge(
        &mut self,
        challenge: impl Into<String>,
        issued_at: UnixTimestamp,
    ) -> Result<RelayMessage, BaseRelayError> {
        let challenge = challenge.into();
        if challenge.is_empty() {
            return Err(BaseRelayError::invalid("auth challenge must not be empty"));
        }
        self.challenge = Some(BaseAuthChallenge {
            value: challenge.clone(),
            issued_at,
        });
        Ok(RelayMessage::Auth(challenge))
    }

    #[cfg(test)]
    pub fn authenticate(
        &mut self,
        event: &Event,
        now: UnixTimestamp,
    ) -> Result<PublicKeyHex, BaseRelayError> {
        verify_event_signature(event).map_err(BaseRelayError::invalid)?;
        let auth = parse_base_relay_auth_event(event)
            .map_err(BaseRelayError::invalid)?
            .ok_or_else(|| BaseRelayError::invalid("AUTH message must contain kind 22242"))?;
        let challenge = self
            .challenge
            .as_ref()
            .ok_or_else(|| BaseRelayError::auth_required("auth challenge is missing"))?;
        if !self.accepts_relay_url(auth.relay()) {
            return Err(BaseRelayError::auth_required(
                "auth relay does not match accepted relay URL",
            ));
        }
        if auth.challenge() != challenge.value {
            return Err(BaseRelayError::auth_required(
                "auth challenge does not match",
            ));
        }
        if now.as_u64()
            > challenge
                .issued_at
                .as_u64()
                .saturating_add(self.challenge_ttl_seconds)
        {
            return Err(BaseRelayError::auth_required("auth challenge expired"));
        }
        if auth
            .created_at()
            .as_u64()
            .saturating_add(self.created_at_skew_seconds)
            < now.as_u64()
            || auth.created_at().as_u64()
                > now.as_u64().saturating_add(self.created_at_skew_seconds)
        {
            return Err(BaseRelayError::auth_required(
                "auth event created_at is outside configured skew",
            ));
        }
        let pubkey = auth.pubkey().clone();
        self.authenticated_pubkeys.insert(pubkey.clone());
        Ok(pubkey)
    }

    pub fn authenticate_pocket(
        &mut self,
        event: &PocketEvent,
        now: UnixTimestamp,
    ) -> Result<PublicKeyHex, BaseRelayError> {
        verify_pocket_event_signature(event)?;
        let auth = parse_base_relay_pocket_auth_event(event)
            .map_err(BaseRelayError::invalid)?
            .ok_or_else(|| BaseRelayError::invalid("AUTH message must contain kind 22242"))?;
        let challenge = self
            .challenge
            .as_ref()
            .ok_or_else(|| BaseRelayError::auth_required("auth challenge is missing"))?;
        if !self.accepts_relay_url(auth.relay()) {
            return Err(BaseRelayError::auth_required(
                "auth relay does not match accepted relay URL",
            ));
        }
        if auth.challenge() != challenge.value {
            return Err(BaseRelayError::auth_required(
                "auth challenge does not match",
            ));
        }
        if now.as_u64()
            > challenge
                .issued_at
                .as_u64()
                .saturating_add(self.challenge_ttl_seconds)
        {
            return Err(BaseRelayError::auth_required("auth challenge expired"));
        }
        if auth
            .created_at()
            .as_u64()
            .saturating_add(self.created_at_skew_seconds)
            < now.as_u64()
            || auth.created_at().as_u64()
                > now.as_u64().saturating_add(self.created_at_skew_seconds)
        {
            return Err(BaseRelayError::auth_required(
                "auth event created_at is outside configured skew",
            ));
        }
        let pubkey = auth.pubkey().clone();
        self.authenticated_pubkeys.insert(pubkey.clone());
        Ok(pubkey)
    }

    pub fn authenticated_pubkeys(&self) -> &BTreeSet<PublicKeyHex> {
        &self.authenticated_pubkeys
    }

    fn accepts_relay_url(&self, relay_url: &str) -> bool {
        relay_url == self.relay_url || self.accepted_relay_urls.contains(relay_url)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BaseAuthChallenge {
    value: String,
    issued_at: UnixTimestamp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BaseRelayAuthEvent {
    pubkey: PublicKeyHex,
    created_at: UnixTimestamp,
    relay: String,
    challenge: String,
}

impl BaseRelayAuthEvent {
    fn pubkey(&self) -> &PublicKeyHex {
        &self.pubkey
    }

    fn created_at(&self) -> UnixTimestamp {
        self.created_at
    }

    fn relay(&self) -> &str {
        &self.relay
    }

    fn challenge(&self) -> &str {
        &self.challenge
    }
}

#[cfg(test)]
fn parse_base_relay_auth_event(event: &Event) -> Result<Option<BaseRelayAuthEvent>, String> {
    if event.unsigned().kind().as_u32() != 22_242 {
        return Ok(None);
    }
    let relay = required_single_tag_value(event, "relay")?;
    let challenge = required_single_tag_value(event, "challenge")?;
    if relay.is_empty() {
        return Err("relay auth relay tag must not be empty".to_owned());
    }
    if challenge.is_empty() {
        return Err("relay auth challenge tag must not be empty".to_owned());
    }
    Ok(Some(BaseRelayAuthEvent {
        pubkey: event.unsigned().pubkey().clone(),
        created_at: event.unsigned().created_at(),
        relay,
        challenge,
    }))
}

fn parse_base_relay_pocket_auth_event(
    event: &PocketEvent,
) -> Result<Option<BaseRelayAuthEvent>, String> {
    if pocket_event_kind(event)
        .map_err(|error| error.message().to_owned())?
        .as_u32()
        != 22_242
    {
        return Ok(None);
    }
    let relay = required_single_pocket_tag_value(event, "relay")?;
    let challenge = required_single_pocket_tag_value(event, "challenge")?;
    if relay.is_empty() {
        return Err("relay auth relay tag must not be empty".to_owned());
    }
    if challenge.is_empty() {
        return Err("relay auth challenge tag must not be empty".to_owned());
    }
    Ok(Some(BaseRelayAuthEvent {
        pubkey: pocket_event_pubkey(event).map_err(|error| error.message().to_owned())?,
        created_at: pocket_event_created_at(event),
        relay,
        challenge,
    }))
}

#[cfg(test)]
fn required_single_tag_value(event: &Event, name: &str) -> Result<String, String> {
    let mut matches = event
        .unsigned()
        .tags()
        .iter()
        .filter(|tag| tag.name().as_str() == name);
    let tag = matches
        .next()
        .ok_or_else(|| format!("tag `{name}` is required"))?;
    if matches.next().is_some() {
        return Err(format!("tag `{name}` must not be repeated"));
    }
    tag.values()
        .get(1)
        .cloned()
        .ok_or_else(|| format!("tag `{name}` must include a value"))
}

fn required_single_pocket_tag_value(event: &PocketEvent, name: &str) -> Result<String, String> {
    let tags = event
        .tags()
        .map_err(|error| format!("malformed Pocket event tags: {error}"))?;
    let mut matched = None;
    for mut tag in tags.iter() {
        let Some(tag_name) = tag.next() else {
            continue;
        };
        let tag_name = str::from_utf8(tag_name).map_err(|error| error.to_string())?;
        if tag_name != name {
            continue;
        }
        if matched.is_some() {
            return Err(format!("tag `{name}` must not be repeated"));
        }
        let value = tag
            .next()
            .ok_or_else(|| format!("tag `{name}` must include a value"))
            .and_then(|value| str::from_utf8(value).map_err(|error| error.to_string()))?;
        matched = Some(value.to_owned());
    }
    matched.ok_or_else(|| format!("tag `{name}` is required"))
}

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::{BaseAuthState, generate_auth_challenge};
    use tangle_crypto::RelaySigner;
    use tangle_protocol::{Event, EventId, Kind, RelayMessage, Tag, UnixTimestamp, UnsignedEvent};
    use tangle_store_pocket::{PocketKind, PocketOwnedEvent, PocketOwnedTags, PocketTime};

    #[test]
    fn auth_state_issues_challenges_and_accepts_multiple_pubkeys() {
        let mut auth =
            BaseAuthState::new("wss://relay.radroots.test", 60, 600).expect("auth state");
        let issued = UnixTimestamp::new(100);

        assert_eq!(
            auth.issue_challenge("challenge-a", issued)
                .expect("challenge"),
            RelayMessage::Auth("challenge-a".to_owned())
        );

        let first = signed_auth_event(7, "challenge-a", 120);
        let second = signed_auth_event(8, "challenge-a", 130);

        let first_pubkey = auth
            .authenticate(&first, UnixTimestamp::new(120))
            .expect("first");
        let second_pubkey = auth
            .authenticate(&second, UnixTimestamp::new(130))
            .expect("second");

        assert_ne!(first_pubkey, second_pubkey);
        assert!(auth.authenticated_pubkeys().contains(&first_pubkey));
        assert!(auth.authenticated_pubkeys().contains(&second_pubkey));
        assert_eq!(auth.authenticated_pubkeys().len(), 2);
        assert_eq!(
            auth.authenticate(&signed_auth_event(9, "wrong", 130), UnixTimestamp::new(130))
                .expect_err("wrong")
                .prefixed_message(),
            "auth-required: auth challenge does not match"
        );
    }

    #[test]
    fn auth_state_rejects_invalid_event_shape_and_signature() {
        let mut auth =
            BaseAuthState::new("wss://relay.radroots.test", 60, 600).expect("auth state");
        auth.issue_challenge("challenge-a", UnixTimestamp::new(100))
            .expect("challenge");
        let valid = signed_auth_event(7, "challenge-a", 120);
        let wrong_id = Event::new(
            EventId::new(&"0".repeat(EventId::HEX_LENGTH)).expect("id"),
            valid.unsigned().clone(),
            valid.sig().clone(),
        );
        assert!(
            auth.authenticate(&wrong_id, UnixTimestamp::new(120))
                .expect_err("id")
                .prefixed_message()
                .starts_with("invalid: event id mismatch:")
        );

        let other = signed_auth_event(8, "challenge-a", 120);
        let wrong_signature = Event::new(
            valid.id().clone(),
            valid.unsigned().clone(),
            other.sig().clone(),
        );
        assert_eq!(
            auth.authenticate(&wrong_signature, UnixTimestamp::new(120))
                .expect_err("signature")
                .prefixed_message(),
            "invalid: event signature verification failed"
        );

        assert_eq!(
            auth.authenticate(
                &signed_event(7, 1, auth_tags("challenge-a"), 120),
                UnixTimestamp::new(120)
            )
            .expect_err("kind")
            .prefixed_message(),
            "invalid: AUTH message must contain kind 22242"
        );

        assert_eq!(
            auth.authenticate(
                &signed_event(
                    7,
                    22_242,
                    vec![Tag::from_parts("challenge", &["challenge-a"]).expect("challenge")],
                    120
                ),
                UnixTimestamp::new(120)
            )
            .expect_err("relay")
            .prefixed_message(),
            "invalid: tag `relay` is required"
        );

        assert_eq!(
            auth.authenticate(
                &signed_event(
                    7,
                    22_242,
                    vec![Tag::from_parts("relay", &["wss://relay.radroots.test"]).expect("relay")],
                    120
                ),
                UnixTimestamp::new(120)
            )
            .expect_err("challenge")
            .prefixed_message(),
            "invalid: tag `challenge` is required"
        );
    }

    #[test]
    fn auth_state_rejects_created_at_outside_configured_skew() {
        let mut auth = BaseAuthState::new("wss://relay.radroots.test", 60, 10).expect("auth state");
        auth.issue_challenge("challenge-a", UnixTimestamp::new(100))
            .expect("challenge");

        auth.authenticate(
            &signed_auth_event(7, "challenge-a", 90),
            UnixTimestamp::new(100),
        )
        .expect("lower boundary");
        auth.authenticate(
            &signed_auth_event(8, "challenge-a", 110),
            UnixTimestamp::new(100),
        )
        .expect("upper boundary");

        assert_eq!(
            auth.authenticate(
                &signed_auth_event(9, "challenge-a", 89),
                UnixTimestamp::new(100)
            )
            .expect_err("stale")
            .prefixed_message(),
            "auth-required: auth event created_at is outside configured skew"
        );
        assert_eq!(
            auth.authenticate(
                &signed_auth_event(10, "challenge-a", 111),
                UnixTimestamp::new(100)
            )
            .expect_err("future")
            .prefixed_message(),
            "auth-required: auth event created_at is outside configured skew"
        );
    }

    #[test]
    fn auth_state_accepts_explicit_additional_relay_urls() {
        let mut auth =
            BaseAuthState::new("wss://relay.radroots.test", 60, 600).expect("auth state");
        assert_eq!(
            auth.accept_relay_url("")
                .expect_err("empty alias")
                .prefixed_message(),
            "invalid: auth relay URL must not be empty"
        );
        auth.accept_relay_url("wss://relay.radroots.test/es")
            .expect("alias");
        auth.issue_challenge("challenge-a", UnixTimestamp::new(100))
            .expect("challenge");

        let alias_event = signed_event(
            7,
            22_242,
            auth_tags_for("wss://relay.radroots.test/es", "challenge-a"),
            105,
        );
        let base_event = signed_auth_event(8, "challenge-a", 106);
        let alias_pocket_event = signed_pocket_event(
            9,
            22_242,
            pocket_auth_tags_for("wss://relay.radroots.test/es", "challenge-a"),
            107,
        );

        let alias_pubkey = auth
            .authenticate(&alias_event, UnixTimestamp::new(105))
            .expect("alias event");
        let base_pubkey = auth
            .authenticate(&base_event, UnixTimestamp::new(106))
            .expect("base event");
        let alias_pocket_pubkey = auth
            .authenticate_pocket(&alias_pocket_event, UnixTimestamp::new(107))
            .expect("alias pocket event");

        assert!(auth.authenticated_pubkeys().contains(&alias_pubkey));
        assert!(auth.authenticated_pubkeys().contains(&base_pubkey));
        assert!(auth.authenticated_pubkeys().contains(&alias_pocket_pubkey));
        assert_eq!(auth.authenticated_pubkeys().len(), 3);
    }

    #[test]
    fn auth_state_preserves_chorus_auth_parity() {
        let mut auth = BaseAuthState::new("wss://relay.radroots.test", 20, 10).expect("auth state");
        auth.issue_challenge("challenge-a", UnixTimestamp::new(100))
            .expect("challenge");
        let owner = signed_auth_event(7, "challenge-a", 105);
        let admin = signed_auth_event(8, "challenge-a", 106);

        let owner_pubkey = auth
            .authenticate(&owner, UnixTimestamp::new(105))
            .expect("owner");
        let admin_pubkey = auth
            .authenticate(&admin, UnixTimestamp::new(106))
            .expect("admin");
        assert_ne!(owner_pubkey, admin_pubkey);
        assert!(auth.authenticated_pubkeys().contains(&owner_pubkey));
        assert!(auth.authenticated_pubkeys().contains(&admin_pubkey));
        assert_eq!(auth.authenticated_pubkeys().len(), 2);

        let wrong_id = Event::new(
            EventId::new(&"0".repeat(EventId::HEX_LENGTH)).expect("id"),
            owner.unsigned().clone(),
            owner.sig().clone(),
        );
        assert!(
            auth.authenticate(&wrong_id, UnixTimestamp::new(105))
                .expect_err("id")
                .prefixed_message()
                .starts_with("invalid: event id mismatch:")
        );

        let wrong_signature = Event::new(
            owner.id().clone(),
            owner.unsigned().clone(),
            admin.sig().clone(),
        );
        assert_eq!(
            auth.authenticate(&wrong_signature, UnixTimestamp::new(105))
                .expect_err("signature")
                .prefixed_message(),
            "invalid: event signature verification failed"
        );
        assert_eq!(
            auth.authenticate(
                &signed_event(9, 1, auth_tags("challenge-a"), 105),
                UnixTimestamp::new(105)
            )
            .expect_err("kind")
            .prefixed_message(),
            "invalid: AUTH message must contain kind 22242"
        );
        assert_eq!(
            auth.authenticate(
                &signed_event(
                    9,
                    22_242,
                    auth_tags_for("wss://other.radroots.test", "challenge-a"),
                    105
                ),
                UnixTimestamp::new(105)
            )
            .expect_err("relay")
            .prefixed_message(),
            "auth-required: auth relay does not match accepted relay URL"
        );
        assert_eq!(
            auth.authenticate(
                &signed_event(
                    9,
                    22_242,
                    vec![Tag::from_parts("challenge", &["challenge-a"]).expect("challenge")],
                    105
                ),
                UnixTimestamp::new(105)
            )
            .expect_err("missing relay")
            .prefixed_message(),
            "invalid: tag `relay` is required"
        );
        assert_eq!(
            auth.authenticate(
                &signed_event(
                    9,
                    22_242,
                    vec![Tag::from_parts("relay", &["wss://relay.radroots.test"]).expect("relay")],
                    105
                ),
                UnixTimestamp::new(105)
            )
            .expect_err("missing challenge")
            .prefixed_message(),
            "invalid: tag `challenge` is required"
        );
        assert_eq!(
            auth.authenticate(&signed_auth_event(9, "wrong", 105), UnixTimestamp::new(105))
                .expect_err("challenge")
                .prefixed_message(),
            "auth-required: auth challenge does not match"
        );
        assert_eq!(
            auth.authenticate(
                &signed_auth_event(9, "challenge-a", 121),
                UnixTimestamp::new(121)
            )
            .expect_err("expired")
            .prefixed_message(),
            "auth-required: auth challenge expired"
        );
        assert_eq!(
            auth.authenticate(
                &signed_auth_event(9, "challenge-a", 94),
                UnixTimestamp::new(105)
            )
            .expect_err("stale")
            .prefixed_message(),
            "auth-required: auth event created_at is outside configured skew"
        );
        assert_eq!(
            auth.authenticate(
                &signed_auth_event(9, "challenge-a", 116),
                UnixTimestamp::new(105)
            )
            .expect_err("future")
            .prefixed_message(),
            "auth-required: auth event created_at is outside configured skew"
        );
    }

    #[test]
    fn auth_state_authenticates_pocket_events_without_protocol_conversion() {
        let mut auth = BaseAuthState::new("wss://relay.radroots.test", 20, 10).expect("auth state");
        auth.issue_challenge("challenge-a", UnixTimestamp::new(100))
            .expect("challenge");
        let owner = signed_pocket_auth_event(7, "challenge-a", 105);
        let admin = signed_pocket_auth_event(8, "challenge-a", 106);

        let owner_pubkey = auth
            .authenticate_pocket(&owner, UnixTimestamp::new(105))
            .expect("owner");
        let admin_pubkey = auth
            .authenticate_pocket(&admin, UnixTimestamp::new(106))
            .expect("admin");

        assert_ne!(owner_pubkey, admin_pubkey);
        assert!(auth.authenticated_pubkeys().contains(&owner_pubkey));
        assert!(auth.authenticated_pubkeys().contains(&admin_pubkey));
        assert_eq!(auth.authenticated_pubkeys().len(), 2);
    }

    #[test]
    fn auth_state_rejects_invalid_pocket_auth_events_with_existing_semantics() {
        let mut auth = BaseAuthState::new("wss://relay.radroots.test", 20, 10).expect("auth state");
        auth.issue_challenge("challenge-a", UnixTimestamp::new(100))
            .expect("challenge");
        let owner = signed_pocket_auth_event(7, "challenge-a", 105);
        let admin = signed_pocket_auth_event(8, "challenge-a", 105);

        let id_source = signed_pocket_auth_event(7, "challenge-a", 106);
        let wrong_id = PocketOwnedEvent::new(
            id_source.id(),
            owner.kind(),
            owner.pubkey(),
            owner.sig(),
            owner.tags().expect("tags"),
            owner.created_at(),
            owner.content(),
        )
        .expect("wrong id pocket");
        assert!(
            auth.authenticate_pocket(&wrong_id, UnixTimestamp::new(105))
                .expect_err("id")
                .prefixed_message()
                .starts_with("invalid:")
        );

        let wrong_signature = PocketOwnedEvent::new(
            owner.id(),
            owner.kind(),
            owner.pubkey(),
            admin.sig(),
            owner.tags().expect("tags"),
            owner.created_at(),
            owner.content(),
        )
        .expect("wrong signature pocket");
        assert!(
            auth.authenticate_pocket(&wrong_signature, UnixTimestamp::new(105))
                .expect_err("signature")
                .prefixed_message()
                .starts_with("invalid:")
        );

        for (event, now, expected) in [
            (
                signed_pocket_event(9, 1, pocket_auth_tags("challenge-a"), 105),
                105,
                "invalid: AUTH message must contain kind 22242",
            ),
            (
                signed_pocket_event(
                    9,
                    22_242,
                    pocket_auth_tags_for("wss://other.radroots.test", "challenge-a"),
                    105,
                ),
                105,
                "auth-required: auth relay does not match accepted relay URL",
            ),
            (
                signed_pocket_auth_event(9, "wrong", 105),
                105,
                "auth-required: auth challenge does not match",
            ),
            (
                signed_pocket_auth_event(9, "challenge-a", 121),
                121,
                "auth-required: auth challenge expired",
            ),
            (
                signed_pocket_auth_event(9, "challenge-a", 94),
                105,
                "auth-required: auth event created_at is outside configured skew",
            ),
            (
                signed_pocket_auth_event(9, "challenge-a", 116),
                105,
                "auth-required: auth event created_at is outside configured skew",
            ),
        ] {
            assert_eq!(
                auth.authenticate_pocket(&event, UnixTimestamp::new(now))
                    .expect_err("invalid")
                    .prefixed_message(),
                expected
            );
        }
    }

    #[test]
    fn generated_auth_challenge_is_lowercase_hex_nonce() {
        let first = generate_auth_challenge().expect("first");
        let second = generate_auth_challenge().expect("second");

        assert_eq!(first.len(), 64);
        assert_ne!(first, second);
        assert!(first.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_eq!(first, first.to_ascii_lowercase());
    }

    fn signed_auth_event(secret_byte: u8, challenge: &str, created_at: u64) -> Event {
        signed_event(secret_byte, 22_242, auth_tags(challenge), created_at)
    }

    fn signed_pocket_auth_event(
        secret_byte: u8,
        challenge: &str,
        created_at: u64,
    ) -> PocketOwnedEvent {
        signed_pocket_event(secret_byte, 22_242, pocket_auth_tags(challenge), created_at)
    }

    fn signed_event(secret_byte: u8, kind: u64, tags: Vec<Tag>, created_at: u64) -> Event {
        let secret = format!("{:02x}", secret_byte).repeat(32);
        let signer = RelaySigner::from_secret_hex(&secret).expect("signer");
        let unsigned = UnsignedEvent::new(
            signer.public_key().clone(),
            UnixTimestamp::new(created_at),
            Kind::new(kind).expect("kind"),
            tags,
            "",
        );
        signer.sign_unsigned_event(unsigned)
    }

    fn signed_pocket_event(
        secret_byte: u8,
        kind: u16,
        tags: PocketOwnedTags,
        created_at: u64,
    ) -> PocketOwnedEvent {
        let secret = format!("{secret_byte:02x}").repeat(32);
        RelaySigner::from_secret_hex(&secret)
            .expect("signer")
            .sign_pocket_event(
                PocketKind::from_u16(kind),
                &tags,
                PocketTime::from_u64(created_at),
                b"",
            )
            .expect("pocket event")
    }

    fn auth_tags(challenge: &str) -> Vec<Tag> {
        auth_tags_for("wss://relay.radroots.test", challenge)
    }

    fn auth_tags_for(relay: &str, challenge: &str) -> Vec<Tag> {
        vec![
            Tag::from_parts("relay", &[relay]).expect("relay"),
            Tag::from_parts("challenge", &[challenge]).expect("challenge"),
        ]
    }

    fn pocket_auth_tags(challenge: &str) -> PocketOwnedTags {
        pocket_auth_tags_for("wss://relay.radroots.test", challenge)
    }

    fn pocket_auth_tags_for(relay: &str, challenge: &str) -> PocketOwnedTags {
        PocketOwnedTags::new(&[["relay", relay], ["challenge", challenge]]).expect("tags")
    }
}
