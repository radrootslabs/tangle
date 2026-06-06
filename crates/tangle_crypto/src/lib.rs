#![forbid(unsafe_code)]

use sha2::{Digest, Sha256};
use tangle_protocol::{Event, EventId, UnsignedEvent, canonical_event_json};

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
    use super::{compute_event_id, compute_event_id_hex, event_id_matches, verify_event_id};
    use tangle_protocol::{
        Event, EventId, Kind, PublicKeyHex, SignatureHex, Tag, UnixTimestamp, UnsignedEvent,
    };

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

    fn unsigned_event(tags: Vec<Tag>, content: &str) -> UnsignedEvent {
        UnsignedEvent::new(
            PublicKeyHex::new(&"1".repeat(PublicKeyHex::HEX_LENGTH)).expect("pubkey"),
            UnixTimestamp::new(1_714_124_433),
            Kind::new(1).expect("kind"),
            tags,
            content,
        )
    }
}
