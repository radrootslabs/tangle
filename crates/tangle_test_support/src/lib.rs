#![forbid(unsafe_code)]

use core::fmt;
use k256::schnorr::signature::Signer;
use k256::schnorr::{Signature, SigningKey};
use serde::Deserialize;
use tangle_crypto::compute_event_id;
use tangle_protocol::{
    Event, Kind, PublicKeyHex, SignatureHex, Tag, UnixTimestamp, UnsignedEvent, event_to_value,
};

const VALID_PUBLIC_LISTING_JSON: &str =
    include_str!("../../../testing/fixtures/canonical/nostr/valid_public_listing.json");
const PROJECTION_INELIGIBLE_LISTING_JSON: &str =
    include_str!("../../../testing/fixtures/canonical/nostr/projection_ineligible_listing.json");
const AUTH_EVENT_JSON: &str =
    include_str!("../../../testing/fixtures/canonical/nostr/auth_event.json");
const DELETION_EVENT_JSON: &str =
    include_str!("../../../testing/fixtures/canonical/nostr/deletion_event.json");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FixtureKey {
    Seller,
    Buyer,
    Relay,
}

impl FixtureKey {
    pub fn public_key(self) -> PublicKeyHex {
        let signing_key = self.signing_key();
        PublicKeyHex::new(&lower_hex(signing_key.verifying_key().to_bytes().as_ref()))
            .expect("fixture public key is valid x-only lowercase hex")
    }

    fn signing_key(self) -> SigningKey {
        match self {
            Self::Seller => SigningKey::from_bytes(&[7_u8; 32]).expect("seller fixture key"),
            Self::Buyer => SigningKey::from_bytes(&[8_u8; 32]).expect("buyer fixture key"),
            Self::Relay => SigningKey::from_bytes(&[9_u8; 32]).expect("relay fixture key"),
        }
    }
}

impl fmt::Display for FixtureKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Seller => "seller",
            Self::Buyer => "buyer",
            Self::Relay => "relay",
        })
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct FixtureEventSpec {
    name: String,
    key: String,
    created_at: u64,
    kind: u64,
    tags: Vec<Vec<String>>,
    content: String,
}

impl FixtureEventSpec {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn key(&self) -> &str {
        &self.key
    }

    pub fn created_at(&self) -> u64 {
        self.created_at
    }

    pub fn kind(&self) -> u64 {
        self.kind
    }

    pub fn tags(&self) -> &[Vec<String>] {
        &self.tags
    }

    pub fn content(&self) -> &str {
        &self.content
    }

    pub fn fixture_key(&self) -> Result<FixtureKey, String> {
        match self.key.as_str() {
            "seller" => Ok(FixtureKey::Seller),
            "buyer" => Ok(FixtureKey::Buyer),
            "relay" => Ok(FixtureKey::Relay),
            value => Err(format!("fixture key `{value}` is unsupported")),
        }
    }
}

pub fn valid_public_listing_spec() -> FixtureEventSpec {
    fixture_spec_from_json(VALID_PUBLIC_LISTING_JSON).expect("valid listing fixture parses")
}

pub fn projection_ineligible_listing_spec() -> FixtureEventSpec {
    fixture_spec_from_json(PROJECTION_INELIGIBLE_LISTING_JSON)
        .expect("projection-ineligible listing fixture parses")
}

pub fn auth_event_spec() -> FixtureEventSpec {
    fixture_spec_from_json(AUTH_EVENT_JSON).expect("auth event fixture parses")
}

pub fn deletion_event_spec() -> FixtureEventSpec {
    fixture_spec_from_json(DELETION_EVENT_JSON).expect("deletion event fixture parses")
}

pub fn fixture_spec_from_json(raw: &str) -> Result<FixtureEventSpec, String> {
    serde_json::from_str(raw).map_err(|source| format!("fixture JSON is invalid: {source}"))
}

pub fn build_fixture_event(spec: &FixtureEventSpec) -> Result<Event, String> {
    let fixture_key = spec.fixture_key()?;
    let unsigned = UnsignedEvent::new(
        fixture_key.public_key(),
        UnixTimestamp::new(spec.created_at),
        Kind::new(spec.kind)?,
        spec.tags
            .iter()
            .map(|values| Tag::new(values.clone()))
            .collect::<Result<Vec<_>, _>>()?,
        &spec.content,
    );
    sign_unsigned_event(fixture_key, unsigned)
}

pub fn fixture_event_json(event: &Event) -> serde_json::Value {
    event_to_value(event)
}

fn sign_unsigned_event(fixture_key: FixtureKey, unsigned: UnsignedEvent) -> Result<Event, String> {
    let signing_key = fixture_key.signing_key();
    let event_id = compute_event_id(&unsigned);
    let event_id_bytes =
        fixed_hex_bytes(event_id.as_str(), 32, "event id").expect("computed event id decodes");
    let signature: Signature = signing_key.sign(&event_id_bytes);
    let signature =
        SignatureHex::new(&lower_hex(signature.to_bytes().as_ref())).expect("signature hex");
    Ok(Event::new(event_id, unsigned, signature))
}

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
        FixtureKey, auth_event_spec, build_fixture_event, deletion_event_spec, fixed_hex_bytes,
        fixture_event_json, fixture_spec_from_json, projection_ineligible_listing_spec,
        valid_public_listing_spec,
    };
    use tangle_crypto::{event_id_matches, verify_event_signature};
    use tangle_nips::{
        DeletionTarget, ListingProjectionEvaluation, evaluate_listing_projection,
        parse_deletion_request, parse_relay_auth_event,
    };
    use tangle_protocol::{EventId, PublicKeyHex};

    #[test]
    fn fixture_specs_load_from_canonical_json() {
        let listing = valid_public_listing_spec();
        let ineligible = projection_ineligible_listing_spec();
        let auth = auth_event_spec();
        let deletion = deletion_event_spec();

        assert_eq!(listing.name(), "valid_public_listing");
        assert_eq!(listing.key(), "seller");
        assert_eq!(listing.created_at(), 1_714_124_433);
        assert_eq!(listing.kind(), 30_402);
        assert_eq!(listing.content(), "Sweet storage carrots.");
        assert_eq!(listing.tags().len(), 10);
        assert_eq!(ineligible.name(), "projection_ineligible_listing");
        assert_eq!(auth.name(), "auth_event");
        assert_eq!(deletion.name(), "deletion_event");
    }

    #[test]
    fn fixture_keys_have_stable_synthetic_public_keys() {
        assert_eq!(FixtureKey::Seller.to_string(), "seller");
        assert_eq!(FixtureKey::Buyer.to_string(), "buyer");
        assert_eq!(FixtureKey::Relay.to_string(), "relay");
        assert_eq!(
            FixtureKey::Seller.public_key().as_str(),
            "989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6f"
        );
        assert_ne!(
            FixtureKey::Seller.public_key(),
            FixtureKey::Buyer.public_key()
        );
    }

    #[test]
    fn fixture_builder_signs_verifiable_public_listing_events() {
        let event = build_fixture_event(&valid_public_listing_spec()).expect("event");
        let json = fixture_event_json(&event);

        assert!(event_id_matches(&event));
        assert_eq!(verify_event_signature(&event), Ok(()));
        assert_eq!(json["kind"], 30_402);
        assert_eq!(json["content"], "Sweet storage carrots.");
        assert_eq!(
            evaluate_listing_projection(&event),
            ListingProjectionEvaluation::Eligible(Box::new(
                evaluate_listing_projection(&event)
                    .projection()
                    .expect("projection")
                    .clone()
            ))
        );
    }

    #[test]
    fn projection_ineligible_fixture_is_signed_but_not_projectable() {
        let event = build_fixture_event(&projection_ineligible_listing_spec()).expect("event");
        let evaluation = evaluate_listing_projection(&event);

        assert_eq!(verify_event_signature(&event), Ok(()));
        assert_eq!(
            evaluation.rejection().expect("rejection").reasons(),
            &["tag `title` is required".to_owned()]
        );
    }

    #[test]
    fn auth_and_deletion_fixtures_build_protocol_specific_events() {
        let auth = build_fixture_event(&auth_event_spec()).expect("auth");
        let deletion = build_fixture_event(&deletion_event_spec()).expect("deletion");
        let auth = parse_relay_auth_event(&auth)
            .expect("auth parse")
            .expect("auth event");
        let deletion = parse_deletion_request(&deletion)
            .expect("deletion parse")
            .expect("deletion event");
        let target = EventId::new(&"a".repeat(EventId::HEX_LENGTH)).expect("target");

        assert_eq!(auth.relay(), "wss://relay.radroots.test");
        assert_eq!(auth.challenge(), "challenge-001");
        assert_eq!(deletion.targets(), &[DeletionTarget::Event(target)]);
    }

    #[test]
    fn fixture_spec_parser_rejects_invalid_json_and_keys() {
        let invalid = fixture_spec_from_json("{").expect_err("json");
        let unsupported = fixture_spec_from_json(
            r#"{"name":"bad","key":"unknown","created_at":1,"kind":1,"tags":[],"content":""}"#,
        )
        .expect("fixture");

        assert!(invalid.starts_with("fixture JSON is invalid"));
        assert_eq!(
            unsupported.fixture_key().expect_err("key"),
            "fixture key `unknown` is unsupported"
        );
        assert_eq!(
            FixtureKey::Buyer,
            fixture_spec_from_json(
                r#"{"name":"buyer","key":"buyer","created_at":1,"kind":1,"tags":[],"content":""}"#,
            )
            .expect("buyer")
            .fixture_key()
            .expect("buyer")
        );
        assert_eq!(
            FixtureKey::Relay,
            fixture_spec_from_json(
                r#"{"name":"relay","key":"relay","created_at":1,"kind":1,"tags":[],"content":""}"#,
            )
            .expect("relay")
            .fixture_key()
            .expect("relay")
        );
    }

    #[test]
    fn fixture_builder_rejects_malformed_fixture_shapes() {
        let bad_key = fixture_spec_from_json(
            r#"{"name":"bad","key":"unknown","created_at":1,"kind":1,"tags":[],"content":""}"#,
        )
        .expect("bad key");
        let bad_tag = fixture_spec_from_json(
            r#"{"name":"bad","key":"seller","created_at":1,"kind":1,"tags":[[]],"content":""}"#,
        )
        .expect("bad tag");
        let bad_kind = fixture_spec_from_json(
            r#"{"name":"bad","key":"seller","created_at":1,"kind":4294967296,"tags":[],"content":""}"#,
        )
        .expect("bad kind");

        assert_eq!(
            build_fixture_event(&bad_tag).expect_err("tag"),
            "tag must not be empty"
        );
        assert_eq!(
            build_fixture_event(&bad_kind).expect_err("kind"),
            "kind must fit in u32, got 4294967296"
        );
        assert_eq!(
            PublicKeyHex::HEX_LENGTH,
            FixtureKey::Relay.public_key().as_str().len()
        );
        assert_eq!(
            build_fixture_event(&bad_key).expect_err("key"),
            "fixture key `unknown` is unsupported"
        );
    }

    #[test]
    fn fixed_hex_decoder_rejects_bad_lengths_and_characters() {
        assert_eq!(
            fixed_hex_bytes("abc", 2, "fixture").expect_err("length"),
            "fixture must decode to 2 bytes, got 3 hex characters"
        );
        assert_eq!(
            fixed_hex_bytes("0G", 1, "fixture").expect_err("low"),
            "fixture must be lowercase hex"
        );
        assert_eq!(
            fixed_hex_bytes("G0", 1, "fixture").expect_err("high"),
            "fixture must be lowercase hex"
        );
    }
}
