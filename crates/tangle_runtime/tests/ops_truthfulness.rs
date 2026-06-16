#![forbid(unsafe_code)]

use serde_json::json;
use std::path::{Path, PathBuf};
use tangle_crypto::RelaySigner;
use tangle_protocol::{
    Event, EventId, Kind, PublicKeyHex, RelayMessage, SignatureHex, Tag, UnixTimestamp,
    UnsignedEvent, event_to_value,
};
use tangle_runtime::{
    config::{BaseRelayRuntimeConfig, parse_base_relay_runtime_config_json},
    errors::BaseRelayError,
    logging::{TANGLE_LOG_REDACTED, TangleLogRedactor},
    nip11::BaseRelayInfoConfig,
    ops::BaseRelayReadinessCheckStatus,
    rate_limits::{TangleRateLimitKey, TangleRateLimitScope, TangleRateLimiter},
    relay::{auth::BaseAuthState, core::BaseRelay},
    runtime::TangleRuntime,
};
use tangle_store_pocket::parse_pocket_event_json;
use tangle_store_pocket::{PocketEvent, PocketKind, PocketOwnedEvent, PocketOwnedTags, PocketTime};
use tangle_test_support::{FixtureKey, TANGLE_V2_RELAY_SECRET_HEX, TANGLE_V2_RELAY_URL};

trait BaseRelayEventTestExt {
    fn handle_event(&self, event: Event) -> Result<RelayMessage, BaseRelayError>;

    fn handle_event_with_auth(
        &self,
        event: Event,
        auth: &BaseAuthState,
    ) -> Result<RelayMessage, BaseRelayError>;
}

impl BaseRelayEventTestExt for BaseRelay {
    fn handle_event(&self, event: Event) -> Result<RelayMessage, BaseRelayError> {
        let raw = serde_json::to_vec(&event_to_value(&event)).expect("event JSON");
        let pocket = parse_pocket_event_json(&raw).expect("pocket event");
        self.handle_pocket_event(&pocket)
    }

    fn handle_event_with_auth(
        &self,
        event: Event,
        auth: &BaseAuthState,
    ) -> Result<RelayMessage, BaseRelayError> {
        let raw = serde_json::to_vec(&event_to_value(&event)).expect("event JSON");
        let pocket = parse_pocket_event_json(&raw).expect("pocket event");
        self.handle_pocket_event_with_auth(&pocket, auth)
    }
}

fn authenticate_pocket_event_for_test(
    auth: &mut BaseAuthState,
    event: &Event,
    now: UnixTimestamp,
) -> Result<(), BaseRelayError> {
    let raw = serde_json::to_vec(&event_to_value(event)).expect("event JSON");
    let pocket = parse_pocket_event_json(&raw).expect("pocket event");
    auth.authenticate_pocket(&pocket, now).map(|_| ())
}

fn tangle_v2_event(
    key: FixtureKey,
    created_at: u64,
    kind: u64,
    tags: Vec<Tag>,
    content: &str,
) -> Result<Event, String> {
    let event = ops_pocket_event(key, created_at, kind, tags, content);
    ops_pocket_event_to_protocol(&event)
}

fn tangle_v2_auth_event(
    key: FixtureKey,
    challenge: &str,
    created_at: u64,
) -> Result<Event, String> {
    tangle_v2_event(
        key,
        created_at,
        22_242,
        vec![
            Tag::from_parts("relay", &[TANGLE_V2_RELAY_URL])?,
            Tag::from_parts("challenge", &[challenge])?,
        ],
        "",
    )
}

fn ops_pocket_event(
    key: FixtureKey,
    created_at: u64,
    kind: u64,
    tags: Vec<Tag>,
    content: &str,
) -> PocketOwnedEvent {
    let tags = ops_pocket_tags_from_protocol(&tags);
    let secret = format!("{:02x}", fixture_secret_byte(key)).repeat(32);
    RelaySigner::from_secret_hex(&secret)
        .expect("signer")
        .sign_pocket_event(
            PocketKind::from_u16(u16::try_from(kind).expect("pocket kind")),
            &tags,
            PocketTime::from_u64(created_at),
            content.as_bytes(),
        )
        .expect("pocket event")
}

fn ops_pocket_tags_from_protocol(tags: &[Tag]) -> PocketOwnedTags {
    let parts = tags
        .iter()
        .map(|tag| tag.values().iter().map(String::as_str).collect::<Vec<_>>())
        .collect::<Vec<_>>();
    PocketOwnedTags::new(&parts).expect("pocket tags")
}

fn ops_pocket_event_to_protocol(event: &PocketEvent) -> Result<Event, String> {
    let tags = event
        .tags()
        .map_err(|error| error.to_string())?
        .iter()
        .map(|tag| {
            Tag::new(
                tag.map(|value| {
                    std::str::from_utf8(value)
                        .map(str::to_owned)
                        .map_err(|error| error.to_string())
                })
                .collect::<Result<Vec<_>, _>>()?,
            )
            .map_err(|error| error.to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Event::new(
        EventId::new(&event.id().as_hex_string()).map_err(|error| error.to_string())?,
        UnsignedEvent::new(
            PublicKeyHex::new(&event.pubkey().as_hex_string())
                .map_err(|error| error.to_string())?,
            UnixTimestamp::new(event.created_at().as_u64()),
            Kind::new(u64::from(event.kind().as_u16())).map_err(|error| error.to_string())?,
            tags,
            std::str::from_utf8(event.content()).map_err(|error| error.to_string())?,
        ),
        SignatureHex::new(&event.sig().to_string()).map_err(|error| error.to_string())?,
    ))
}

fn fixture_secret_byte(key: FixtureKey) -> u8 {
    match key {
        FixtureKey::Relay => 9,
        FixtureKey::Owner => 10,
        FixtureKey::Admin => 11,
        FixtureKey::Member => 12,
        FixtureKey::Outsider => 13,
    }
}

#[test]
fn operations_surfaces_match_enforced_runtime_contracts() {
    let root = temp_root("ops-truthfulness");
    let _ = std::fs::remove_dir_all(&root);
    let config = runtime_config(&root);
    let document = BaseRelayInfoConfig::new("tangle", &config)
        .expect("info config")
        .build_document()
        .expect("document");

    assert_eq!(document.supported_nips, vec![1, 11, 29, 42, 45, 70]);
    assert!(!document.supported_nips.contains(&77));
    assert_eq!(document.limitation.max_message_length, 1_048_576);
    assert_eq!(document.limitation.max_subscriptions, 64);
    assert_eq!(document.limitation.max_filters, 10);
    assert_eq!(document.limitation.max_limit, 500);
    assert_eq!(document.limitation.max_query_complexity, 2_048);
    assert_eq!(document.limitation.default_limit, 100);
    assert!(document.limitation.restricted_writes);
    assert!(!document.retention.physical_erasure);
    assert!(!document.retention.compaction_guarantee);

    let redactor = TangleLogRedactor::from_runtime_config(&config);
    assert_eq!(
        redactor.redact(format!("relay secret {TANGLE_V2_RELAY_SECRET_HEX}")),
        format!("relay secret {TANGLE_LOG_REDACTED}")
    );
    assert!(!format!("{redactor:?}").contains(TANGLE_V2_RELAY_SECRET_HEX));

    let rate_limits = config.rate_limits();
    assert_eq!(rate_limits.auth().failures().max_hits(), 1);
    assert_eq!(rate_limits.req().broad().window_seconds(), 60);
    let limiter = TangleRateLimiter::new();
    let key =
        TangleRateLimitKey::pubkey(TangleRateLimitScope::Auth, FixtureKey::Member.public_key());
    assert!(
        limiter
            .record(
                key.clone(),
                rate_limits.auth().failures(),
                UnixTimestamp::new(100)
            )
            .is_allowed()
    );
    assert!(
        !limiter
            .record(
                key.clone(),
                rate_limits.auth().failures(),
                UnixTimestamp::new(101)
            )
            .is_allowed()
    );

    let runtime = TangleRuntime::open(config.clone()).expect("runtime");
    let pre_bind = runtime.readiness_state().response();
    assert_eq!(pre_bind.status, "not_ready");
    assert_eq!(pre_bind.checks.server_bind, "not_ready");
    assert_eq!(pre_bind.checks.group_projection, "ready");
    assert_eq!(pre_bind.checks.group_outbox_replay, "ready");
    assert_eq!(pre_bind.checks.event_bus, "ready");
    let bound = runtime
        .readiness_state()
        .clone()
        .with_server_bind(BaseRelayReadinessCheckStatus::Ready)
        .response();
    assert_eq!(bound.status, "ready");
    assert_eq!(bound.checks.server_bind, "ready");

    let relay = config.open_relay().expect("relay");
    let protected = tangle_v2_event(
        FixtureKey::Member,
        1_714_124_433,
        1,
        vec![Tag::from_parts("-", &[]).expect("protected")],
        "protected",
    )
    .expect("protected event");
    assert_eq!(
        relay.handle_event(protected.clone()).expect("unauth"),
        RelayMessage::Ok {
            event_id: protected.id().clone(),
            accepted: false,
            message: "auth-required: protected event requires authenticated event author"
                .to_owned()
        }
    );

    let mut auth = BaseAuthState::new(TANGLE_V2_RELAY_URL, 300, 600).expect("auth");
    auth.issue_challenge("challenge-a", UnixTimestamp::new(1_714_124_433))
        .expect("challenge");
    authenticate_pocket_event_for_test(
        &mut auth,
        &tangle_v2_auth_event(FixtureKey::Member, "challenge-a", 1_714_124_433).expect("auth"),
        UnixTimestamp::new(1_714_124_433),
    )
    .expect("author auth");
    assert_eq!(
        relay
            .handle_event_with_auth(protected.clone(), &auth)
            .expect("author write"),
        RelayMessage::Ok {
            event_id: protected.id().clone(),
            accepted: true,
            message: String::new()
        }
    );

    let _ = std::fs::remove_dir_all(root);
}

fn runtime_config(root: &Path) -> BaseRelayRuntimeConfig {
    parse_base_relay_runtime_config_json(
        &json!({
            "server": {
                "listen_addr": "127.0.0.1:0",
                "relay_url": TANGLE_V2_RELAY_URL
            },
            "pocket": {
                "data_directory": root.join("pocket"),
                "sync_policy": "flush_on_shutdown",
                "query": {
                  "allow_scraping": false,
                  "allow_scrape_if_limited_to": 100,
                  "allow_scrape_if_max_seconds": 3600
                }
            },
            "groups": {
                "enabled": true,
                "canonical_relay_url": TANGLE_V2_RELAY_URL,
                "relay_secret": TANGLE_V2_RELAY_SECRET_HEX,
                "owner_pubkeys": [FixtureKey::Owner.public_key().as_str()],
                "admin_pubkeys": [FixtureKey::Admin.public_key().as_str()]
            },
            "auth": {
                "challenge_ttl_seconds": 300,
                "created_at_skew_seconds": 600
            },
            "limits": {
                "max_message_length": 1048576,
                "max_subid_length": 64,
                "max_subscriptions_per_connection": 64,
                "max_filters_per_request": 10,
                "max_tag_values_per_filter": 100,
                "max_query_complexity": 2048,
                "max_limit": 500,
                "default_limit": 100,
                "max_event_tags": 200,
                "max_content_length": 65536,
                "broadcast_channel_capacity": 16,
                "per_connection_outbound_queue": 8
            },
            "rate_limits": {
                "auth": {
                    "per_ip": {"window_seconds": 60, "max_hits": 120},
                    "per_pubkey": {"window_seconds": 60, "max_hits": 30},
                    "failures": {"window_seconds": 60, "max_hits": 1},
                    "failures_per_ip": {"window_seconds": 300, "max_hits": 20}
                },
                "event": {
                    "per_ip": {"window_seconds": 60, "max_hits": 600},
                    "per_pubkey": {"window_seconds": 60, "max_hits": 120},
                    "per_kind": {"window_seconds": 60, "max_hits": 1000}
                },
                "group": {
                    "write_per_ip": {"window_seconds": 60, "max_hits": 300},
                    "write_per_pubkey": {"window_seconds": 60, "max_hits": 60},
                    "write_per_group": {"window_seconds": 60, "max_hits": 90},
                    "write_per_kind": {"window_seconds": 60, "max_hits": 300},
                    "join_flow": {"window_seconds": 300, "max_hits": 10},
                    "join_flow_per_ip": {"window_seconds": 300, "max_hits": 30}
                },
                "req": {
                    "per_ip": {"window_seconds": 60, "max_hits": 600},
                    "per_connection": {"window_seconds": 60, "max_hits": 120},
                    "per_pubkey": {"window_seconds": 60, "max_hits": 240},
                    "per_group": {"window_seconds": 60, "max_hits": 240},
                    "per_kind": {"window_seconds": 60, "max_hits": 500},
                    "broad": {"window_seconds": 60, "max_hits": 30}
                },
                "count": {
                    "per_ip": {"window_seconds": 60, "max_hits": 300},
                    "per_connection": {"window_seconds": 60, "max_hits": 60},
                    "per_pubkey": {"window_seconds": 60, "max_hits": 120},
                    "per_group": {"window_seconds": 60, "max_hits": 120},
                    "per_kind": {"window_seconds": 60, "max_hits": 240},
                    "broad": {"window_seconds": 60, "max_hits": 20}
                }
            }
        })
        .to_string(),
    )
    .expect("config")
}

fn temp_root(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("tangle-ops-{name}-{}", std::process::id()))
}
