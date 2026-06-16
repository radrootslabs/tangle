#![forbid(unsafe_code)]

use core::fmt;
use std::sync::Arc;

use k256::schnorr::signature::{Signer, Verifier};
use k256::schnorr::{Signature, SigningKey, VerifyingKey};
use pocket_types::{
    Kind as PocketKind, OwnedEvent as PocketOwnedEvent, Tags as PocketTags, Time as PocketTime,
};
use secp256k1::{Keypair, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};
use tangle_protocol::{
    Event, EventId, PublicKeyHex, SignatureHex, UnsignedEvent, canonical_event_json,
};
use tokio::sync::Semaphore;

pub fn compute_event_id(event: &UnsignedEvent) -> EventId {
    let event_id = compute_event_id_hex(event);
    EventId::new(&event_id).expect("sha256 emits 32-byte lowercase hex")
}

pub fn compute_event_id_hex(event: &UnsignedEvent) -> String {
    let canonical = canonical_event_json(event);
    let digest = Sha256::digest(canonical.as_bytes());
    lower_hex(&digest)
}

pub fn event_id_matches(event: &Event) -> bool {
    compute_event_id(event.unsigned()) == *event.id()
}

pub fn verify_event_id(event: &Event) -> Result<(), String> {
    let expected = compute_event_id(event.unsigned());
    if event.id() == &expected {
        Ok(())
    } else {
        Err(format!(
            "event id mismatch: expected {}, got {}",
            expected,
            event.id()
        ))
    }
}

pub fn verify_event_signature(event: &Event) -> Result<(), String> {
    verify_event_id(event)?;
    let event_id =
        validated_fixed_hex_bytes(event.id().as_str(), EventId::HEX_LENGTH / 2, "event id");
    let pubkey = fixed_hex_bytes(
        event.unsigned().pubkey().as_str(),
        EventId::HEX_LENGTH / 2,
        "public key",
    )
    .expect("validated public key scalar decodes");
    let signature = fixed_hex_bytes(event.sig().as_str(), 64, "signature")
        .expect("validated signature decodes");
    let verifying_key = VerifyingKey::from_bytes(&pubkey)
        .map_err(|_| "event public key is not a valid secp256k1 x-only key".to_owned())?;
    let signature = Signature::try_from(signature.as_slice())
        .map_err(|_| "event signature is not a valid schnorr signature".to_owned())?;
    verifying_key
        .verify(&event_id, &signature)
        .map_err(|_| "event signature verification failed".to_owned())
}

pub fn compute_event_id_hex_from_canonical_json(canonical: &str) -> String {
    let digest = Sha256::digest(canonical.as_bytes());
    lower_hex(&digest)
}

pub fn verify_event_signature_bytes(
    canonical: &str,
    event_id: &[u8; 32],
    pubkey: &[u8; 32],
    signature: &[u8; 64],
) -> Result<(), String> {
    let expected_id = Sha256::digest(canonical.as_bytes());
    let expected_id_bytes: &[u8] = expected_id.as_ref();
    if expected_id_bytes != event_id {
        return Err(format!(
            "event id mismatch: expected {}, got {}",
            lower_hex(&expected_id),
            lower_hex(event_id)
        ));
    }
    let verifying_key = VerifyingKey::from_bytes(pubkey)
        .map_err(|_| "event public key is not a valid secp256k1 x-only key".to_owned())?;
    let signature = Signature::try_from(signature.as_slice())
        .map_err(|_| "event signature is not a valid schnorr signature".to_owned())?;
    verifying_key
        .verify(event_id, &signature)
        .map_err(|_| "event signature verification failed".to_owned())
}

pub struct RelaySigner {
    signing_key: SigningKey,
    public_key: PublicKeyHex,
    secret_bytes: [u8; 32],
}

impl RelaySigner {
    pub fn from_secret_hex(secret: &str) -> Result<Self, String> {
        let bytes = fixed_hex_bytes(secret, 32, "relay secret")?;
        let bytes: [u8; 32] = bytes
            .try_into()
            .expect("validated relay secret length is 32 bytes");
        let signing_key = SigningKey::from_bytes(&bytes)
            .map_err(|_| "relay secret is not a valid secp256k1 signing key".to_owned())?;
        let public_key =
            PublicKeyHex::new(&lower_hex(signing_key.verifying_key().to_bytes().as_ref()))
                .expect("signing key emits a valid x-only public key");
        Ok(Self {
            signing_key,
            public_key,
            secret_bytes: bytes,
        })
    }

    pub fn public_key(&self) -> &PublicKeyHex {
        &self.public_key
    }

    pub fn sign_unsigned_event(&self, unsigned: UnsignedEvent) -> Event {
        let event_id = compute_event_id(&unsigned);
        let event_id_bytes =
            fixed_hex_bytes(event_id.as_str(), 32, "event id").expect("event id is valid hex");
        let signature: Signature = self.signing_key.sign(&event_id_bytes);
        let signature = SignatureHex::new(&lower_hex(signature.to_bytes().as_ref()))
            .expect("schnorr signature emits valid hex");
        Event::new(event_id, unsigned, signature)
    }

    pub fn sign_pocket_event(
        &self,
        kind: PocketKind,
        tags: &PocketTags,
        created_at: PocketTime,
        content: &[u8],
    ) -> Result<PocketOwnedEvent, String> {
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_byte_array(self.secret_bytes)
            .map_err(|_| "relay secret is not a valid secp256k1 signing key".to_owned())?;
        let keypair = Keypair::from_secret_key(&secp, &secret_key);
        PocketOwnedEvent::sign_new(&keypair, kind, tags, created_at, content)
            .map_err(|error| format!("Pocket event signing failed: {error}"))
    }
}

impl fmt::Debug for RelaySigner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RelaySigner")
            .field("public_key", &self.public_key)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug)]
pub struct VerificationService {
    semaphore: Arc<Semaphore>,
    max_concurrent: usize,
}

impl VerificationService {
    pub fn new(max_concurrent: usize) -> Result<Self, String> {
        if max_concurrent == 0 {
            return Err("verification concurrency limit must be greater than zero".to_owned());
        }
        Ok(Self {
            semaphore: Arc::new(Semaphore::new(max_concurrent)),
            max_concurrent,
        })
    }

    pub fn max_concurrent(&self) -> usize {
        self.max_concurrent
    }

    pub fn available_permits(&self) -> usize {
        self.semaphore.available_permits()
    }

    pub fn close(&self) {
        self.semaphore.close();
    }

    pub async fn verify_event(&self, event: &Event) -> Result<VerificationOutcome, String> {
        let permit = self
            .semaphore
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| "verification service is closed".to_owned())?;
        let result = verify_event_signature(event);
        drop(permit);
        result.map(|_| VerificationOutcome {
            event_id: event.id().clone(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationOutcome {
    event_id: EventId,
}

impl VerificationOutcome {
    pub fn event_id(&self) -> &EventId {
        &self.event_id
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

fn fixed_hex_bytes(value: &str, expected: usize, scalar: &str) -> Result<Vec<u8>, String> {
    if value.len() != expected * 2 {
        return Err(format!(
            "{scalar} must decode to {expected} bytes, got {} hex characters",
            value.len()
        ));
    }
    let mut output = Vec::with_capacity(expected);
    for chunk in value.as_bytes().chunks_exact(2) {
        let high = hex_value(chunk[0], scalar)?;
        let low = hex_value(chunk[1], scalar)?;
        output.push((high << 4) | low);
    }
    Ok(output)
}

fn validated_fixed_hex_bytes(value: &str, expected: usize, scalar: &str) -> Vec<u8> {
    fixed_hex_bytes(value, expected, scalar).expect("validated hex scalar decodes")
}

fn hex_value(value: u8, scalar: &str) -> Result<u8, String> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(format!("{scalar} must be lowercase hex")),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        RelaySigner, VerificationService, compute_event_id, compute_event_id_hex, event_id_matches,
        fixed_hex_bytes, lower_hex, verify_event_id, verify_event_signature,
    };
    use k256::schnorr::signature::Signer;
    use k256::schnorr::{Signature, SigningKey};
    use pocket_types::{Kind as PocketKind, OwnedTags as PocketOwnedTags, Time as PocketTime};
    use std::time::Duration;
    use tangle_protocol::{
        Event, EventId, Kind, PublicKeyHex, SignatureHex, Tag, UnixTimestamp, UnsignedEvent,
    };
    use tokio::time::timeout;

    #[test]
    fn event_id_hashes_canonical_event_bytes() {
        let event = unsigned_event(Vec::new(), "");

        assert_eq!(
            compute_event_id_hex(&event),
            "da90287b43a114ad00f2a87854947df1251b9a0f148b1707b9241c73f11569ae"
        );
        assert_eq!(
            compute_event_id(&event).as_str(),
            "da90287b43a114ad00f2a87854947df1251b9a0f148b1707b9241c73f11569ae"
        );
    }

    #[test]
    fn event_id_verification_reports_match_and_mismatch() {
        let unsigned = unsigned_event(
            vec![Tag::from_parts("t", &["radroots"]).expect("tag")],
            "radroots cafe",
        );
        let event_id = compute_event_id(&unsigned);
        let event = Event::new(
            event_id,
            unsigned.clone(),
            SignatureHex::new(&"b".repeat(SignatureHex::HEX_LENGTH)).expect("sig"),
        );
        let wrong_event = Event::new(
            EventId::new(&"f".repeat(EventId::HEX_LENGTH)).expect("id"),
            unsigned,
            SignatureHex::new(&"b".repeat(SignatureHex::HEX_LENGTH)).expect("sig"),
        );

        assert!(event_id_matches(&event));
        assert_eq!(verify_event_id(&event), Ok(()));
        assert!(!event_id_matches(&wrong_event));
        assert_eq!(
            verify_event_id(&wrong_event).expect_err("mismatch"),
            format!(
                "event id mismatch: expected {}, got {}",
                compute_event_id(wrong_event.unsigned()),
                wrong_event.id()
            )
        );
    }

    #[test]
    fn schnorr_verifier_accepts_deterministically_signed_event() {
        let event = signed_event();

        assert_eq!(verify_event_signature(&event), Ok(()));
    }

    #[test]
    fn relay_signer_derives_public_key_and_signs_canonical_events() {
        let secret = lower_hex(&[7_u8; 32]);
        let signer = RelaySigner::from_secret_hex(&secret).expect("signer");
        let unsigned = UnsignedEvent::new(
            signer.public_key().clone(),
            UnixTimestamp::new(1_714_124_433),
            Kind::new(1).expect("kind"),
            vec![Tag::from_parts("t", &["radroots"]).expect("tag")],
            "relay generated",
        );

        let event = signer.sign_unsigned_event(unsigned);

        assert_eq!(event.unsigned().pubkey(), signer.public_key());
        assert_eq!(verify_event_signature(&event), Ok(()));
        assert_eq!(
            format!("{signer:?}"),
            format!(
                "RelaySigner {{ public_key: {:?}, .. }}",
                signer.public_key()
            )
        );
        assert!(!format!("{signer:?}").contains(&secret));
    }

    #[test]
    fn relay_signer_signs_pocket_events() {
        let secret = "7".repeat(64);
        let signer = RelaySigner::from_secret_hex(&secret).expect("signer");
        let tags = PocketOwnedTags::new(&[["d", "Farm"]]).expect("tags");
        let event = signer
            .sign_pocket_event(
                PocketKind::from_u16(39_000),
                &tags,
                PocketTime::from_u64(20),
                b"",
            )
            .expect("event");

        event.verify().expect("verify");
        assert_eq!(event.pubkey().as_hex_string(), signer.public_key().as_str());
        assert_eq!(event.kind().as_u16(), 39_000);
        assert_eq!(
            event.id().as_hex_string(),
            "b107997a285780bc383ee5aadc0a0eefc46734914103d80f765a46543622782a"
        );
    }

    #[test]
    fn schnorr_verifier_rejects_bad_id_bad_pubkey_and_bad_signature() {
        let event = signed_event();
        let wrong_id = Event::new(
            EventId::new(&"f".repeat(EventId::HEX_LENGTH)).expect("id"),
            event.unsigned().clone(),
            event.sig().clone(),
        );
        let invalid_pubkey_unsigned = UnsignedEvent::new(
            PublicKeyHex::new(&"f".repeat(PublicKeyHex::HEX_LENGTH)).expect("pubkey"),
            event.unsigned().created_at(),
            event.unsigned().kind(),
            event.unsigned().tags().to_vec(),
            event.unsigned().content(),
        );
        let invalid_pubkey = Event::new(
            compute_event_id(&invalid_pubkey_unsigned),
            invalid_pubkey_unsigned,
            event.sig().clone(),
        );
        let invalid_signature = Event::new(
            compute_event_id(event.unsigned()),
            event.unsigned().clone(),
            SignatureHex::new(&"f".repeat(SignatureHex::HEX_LENGTH)).expect("sig"),
        );
        let wrong_message_unsigned = UnsignedEvent::new(
            event.unsigned().pubkey().clone(),
            event.unsigned().created_at(),
            event.unsigned().kind(),
            event.unsigned().tags().to_vec(),
            "different message",
        );
        let wrong_message_signature = Event::new(
            compute_event_id(&wrong_message_unsigned),
            wrong_message_unsigned,
            event.sig().clone(),
        );

        assert!(
            verify_event_signature(&wrong_id)
                .expect_err("bad id")
                .starts_with("event id mismatch")
        );
        assert_eq!(
            verify_event_signature(&invalid_pubkey).expect_err("bad pubkey"),
            "event public key is not a valid secp256k1 x-only key"
        );
        assert_eq!(
            verify_event_signature(&invalid_signature).expect_err("bad sig"),
            "event signature is not a valid schnorr signature"
        );
        assert_eq!(
            verify_event_signature(&wrong_message_signature).expect_err("wrong message"),
            "event signature verification failed"
        );
    }

    #[test]
    fn hex_decoder_rejects_bad_length_and_non_hex_input() {
        assert_eq!(
            fixed_hex_bytes("abc", 2, "sample").expect_err("length"),
            "sample must decode to 2 bytes, got 3 hex characters"
        );
        assert_eq!(
            fixed_hex_bytes("0G", 1, "sample").expect_err("hex"),
            "sample must be lowercase hex"
        );
        assert_eq!(
            fixed_hex_bytes("G0", 1, "sample").expect_err("hex"),
            "sample must be lowercase hex"
        );
    }

    #[tokio::test]
    async fn verification_service_accepts_valid_events_and_rejects_invalid_events() {
        let event = signed_event();
        let invalid = Event::new(
            EventId::new(&"f".repeat(EventId::HEX_LENGTH)).expect("id"),
            event.unsigned().clone(),
            event.sig().clone(),
        );
        let service = VerificationService::new(2).expect("service");

        let outcome = service.verify_event(&event).await.expect("verified");

        assert_eq!(service.max_concurrent(), 2);
        assert_eq!(service.available_permits(), 2);
        assert_eq!(outcome.event_id(), event.id());
        assert!(
            service
                .verify_event(&invalid)
                .await
                .expect_err("invalid")
                .starts_with("event id mismatch")
        );
    }

    #[tokio::test]
    async fn verification_service_enforces_limit_and_reports_closed_state() {
        let event = signed_event();
        let service = VerificationService::new(1).expect("service");
        let permit = service
            .semaphore
            .clone()
            .acquire_owned()
            .await
            .expect("permit");

        assert_eq!(service.available_permits(), 0);
        assert!(
            timeout(Duration::from_millis(20), service.verify_event(&event))
                .await
                .is_err()
        );
        drop(permit);
        assert!(
            timeout(Duration::from_secs(1), service.verify_event(&event))
                .await
                .expect("timeout")
                .is_ok()
        );
        service.close();
        assert_eq!(
            service.verify_event(&event).await.expect_err("closed"),
            "verification service is closed"
        );
    }

    #[test]
    fn verification_service_rejects_zero_limit() {
        assert_eq!(
            VerificationService::new(0).expect_err("zero"),
            "verification concurrency limit must be greater than zero"
        );
    }

    fn unsigned_event(tags: Vec<Tag>, content: &str) -> UnsignedEvent {
        UnsignedEvent::new(
            PublicKeyHex::new(&"1".repeat(PublicKeyHex::HEX_LENGTH)).expect("pubkey"),
            UnixTimestamp::new(1_714_124_433),
            Kind::new(1).expect("kind"),
            tags,
            content,
        )
    }

    fn signed_event() -> Event {
        let signing_key = SigningKey::from_bytes(&[7_u8; 32]).expect("signing key");
        let public_key =
            PublicKeyHex::new(&lower_hex(signing_key.verifying_key().to_bytes().as_ref()))
                .expect("pubkey");
        let unsigned = UnsignedEvent::new(
            public_key,
            UnixTimestamp::new(1_714_124_433),
            Kind::new(1).expect("kind"),
            vec![Tag::from_parts("t", &["radroots"]).expect("tag")],
            "radroots cafe",
        );
        let event_id = compute_event_id(&unsigned);
        let event_id_bytes = fixed_hex_bytes(event_id.as_str(), 32, "event id").expect("event id");
        let signature: Signature = signing_key.sign(&event_id_bytes);
        let signature = SignatureHex::new(&lower_hex(signature.to_bytes().as_ref())).expect("sig");
        Event::new(event_id, unsigned, signature)
    }
}
