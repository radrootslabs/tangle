#![forbid(unsafe_code)]

use serde_json::json;
use std::path::{Path, PathBuf};
use tangle_protocol::{RelayMessage, Tag, UnixTimestamp};
use tangle_runtime::{
    config::{BaseRelayRuntimeConfig, parse_base_relay_runtime_config_json},
    logging::{TANGLE_LOG_REDACTED, TangleLogRedactor},
    nip11::BaseRelayInfoConfig,
    ops::BaseRelayReadinessCheckStatus,
    rate_limits::{TangleRateLimitKey, TangleRateLimitScope, TangleRateLimiter},
    relay::auth::BaseAuthState,
    runtime::TangleRuntime,
};
use tangle_test_support::{
    FixtureKey, TANGLE_V2_RELAY_SECRET_HEX, TANGLE_V2_RELAY_URL, tangle_v2_auth_event,
    tangle_v2_event,
};

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
    let bound = runtime
        .readiness_state()
        .clone()
        .with_server_bind(BaseRelayReadinessCheckStatus::Ready)
        .response();
    assert_eq!(bound.status, "ready");
    assert_eq!(bound.checks.server_bind, "ready");

    let mut relay = config.open_relay().expect("relay");
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
    auth.authenticate(
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
                "map_size_bytes": 1073741824_u64,
                "reader_slots": 128,
                "sync_policy": "flush_on_shutdown"
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
                    "per_pubkey": {"window_seconds": 60, "max_hits": 30},
                    "failures": {"window_seconds": 60, "max_hits": 1}
                },
                "event": {
                    "per_pubkey": {"window_seconds": 60, "max_hits": 120},
                    "per_kind": {"window_seconds": 60, "max_hits": 1000}
                },
                "group": {
                    "write_per_pubkey": {"window_seconds": 60, "max_hits": 60},
                    "write_per_group": {"window_seconds": 60, "max_hits": 90},
                    "write_per_kind": {"window_seconds": 60, "max_hits": 300},
                    "join_flow": {"window_seconds": 300, "max_hits": 10}
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
