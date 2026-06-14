#![forbid(unsafe_code)]

use futures_util::{SinkExt, StreamExt};
use http::header;
use serde_json::{Value, json};
use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tangle_groups::{
    GroupAuthContext, GroupAuthority, GroupErrorKind, GroupEventClass, GroupId, GroupMetadata,
    GroupMetadataFlags, GroupMetadataText, GroupPolicyConfig, GroupProjection, GroupReadDecision,
    GroupReadGate, GroupState, GroupWriteDecision, GroupWritePolicy, KIND_GROUP_ADMINS,
    KIND_GROUP_JOIN_REQUEST, KIND_GROUP_LEAVE_REQUEST, KIND_GROUP_MEMBERS, KIND_GROUP_METADATA,
    MemberState, MemberStatus, ProjectionOrderTuple, StoreOffset, SupportedKinds,
    parse_group_runtime_config_json,
};
use tangle_protocol::{
    Event, EventId, Kind, PublicKeyHex, RelayMessage, SignatureHex, Tag, UnixTimestamp,
    UnsignedEvent, event_to_value,
};
use tangle_runtime::{
    config::{BaseRelayRuntimeConfig, parse_base_relay_runtime_config_json},
    relay::auth::BaseAuthState,
    runtime::TangleRuntime,
    server::serve_listener_until_shutdown,
};
use tangle_test_support::{
    FixtureKey, TANGLE_V2_RELAY_SECRET_HEX, TANGLE_V2_RELAY_URL, tangle_v2_auth_event,
    tangle_v2_event, tangle_v2_group_create_event,
};
use tokio::{net::TcpListener, time::timeout};
use tokio_tungstenite::tungstenite::{Message as TungsteniteMessage, client::IntoClientRequest};

#[tokio::test]
async fn tangle_run_serves_until_shutdown() {
    let root = temp_root("acceptance-server");
    let _ = std::fs::remove_dir_all(&root);
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
    let address = listener.local_addr().expect("address");
    let runtime = TangleRuntime::open(runtime_config(&root, address)).expect("runtime");
    let shutdown = runtime.shutdown_signal().clone();
    let task = tokio::spawn(serve_listener_until_shutdown(runtime, listener));

    let health = wait_for_http_ok(address, "/healthz", None).await;
    let ready = wait_for_http_ok(address, "/readyz", None).await;
    let nip11 = wait_for_http_ok(address, "/", Some("application/nostr+json")).await;

    assert!(health.contains(r#""status":"ok""#));
    assert!(ready.contains(r#""status":"ready""#));
    assert!(nip11.contains(r#""name":"tangle""#));
    assert!(
        nip11
            .to_ascii_lowercase()
            .contains("content-type: application/nostr+json")
    );
    assert!(!task.is_finished());

    shutdown.request_shutdown();

    let report = timeout(Duration::from_secs(2), task)
        .await
        .expect("shutdown timeout")
        .expect("task")
        .expect("serve");
    assert_eq!(report.listen_addr(), address);
    assert_eq!(report.closed_subscriptions(), 0);

    let _ = std::fs::remove_dir_all(root);
}

#[tokio::test]
async fn websocket_clients_use_nip01_nip42_and_nip45_flows() {
    let root = temp_root("acceptance-websocket");
    let _ = std::fs::remove_dir_all(&root);
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
    let address = listener.local_addr().expect("address");
    let runtime = TangleRuntime::open(runtime_config(&root, address)).expect("runtime");
    let shutdown = runtime.shutdown_signal().clone();
    let task = tokio::spawn(serve_listener_until_shutdown(runtime, listener));
    let mut first = connect_nostr_socket(address).await;
    let mut second = connect_nostr_socket(address).await;
    let first_challenge = read_auth_challenge(&mut first).await;
    let second_challenge = read_auth_challenge(&mut second).await;
    let first_event = tangle_v2_event(
        FixtureKey::Member,
        1_714_124_433,
        1,
        Vec::new(),
        "websocket-one",
    )
    .expect("first event");
    let second_event = tangle_v2_event(
        FixtureKey::Member,
        1_714_124_434,
        1,
        Vec::new(),
        "websocket-two",
    )
    .expect("second event");
    let auth_created_at = current_unix_timestamp();
    let owner_auth = tangle_v2_auth_event(FixtureKey::Owner, &first_challenge, auth_created_at)
        .expect("owner auth");
    let admin_auth = tangle_v2_auth_event(
        FixtureKey::Admin,
        &first_challenge,
        auth_created_at.saturating_add(1),
    )
    .expect("admin auth");
    let wrong_challenge_auth = tangle_v2_auth_event(
        FixtureKey::Member,
        &second_challenge,
        auth_created_at.saturating_add(2),
    )
    .expect("wrong challenge auth");

    send_client_text(&mut first, "{").await;
    assert_notice_prefix(
        read_relay_value(&mut first).await,
        "invalid: client message JSON is invalid:",
    );

    send_client_binary(&mut first, &[1, 2, 3]).await;
    assert_eq!(
        read_relay_value(&mut first).await,
        json!(["NOTICE", "invalid: client message must be a text frame"])
    );

    send_client_value(&mut first, json!(["AUTH", event_to_value(&owner_auth)])).await;
    assert_ok(read_relay_value(&mut first).await, &owner_auth, true, "");
    send_client_value(&mut first, json!(["AUTH", event_to_value(&admin_auth)])).await;
    assert_ok(read_relay_value(&mut first).await, &admin_auth, true, "");
    send_client_value(
        &mut first,
        json!(["AUTH", event_to_value(&wrong_challenge_auth)]),
    )
    .await;
    assert_ok(
        read_relay_value(&mut first).await,
        &wrong_challenge_auth,
        false,
        "auth-required: auth challenge does not match",
    );

    let group_create = tangle_v2_group_create_event(
        FixtureKey::Owner,
        "WebsocketFarm",
        auth_created_at.saturating_add(3),
        &[],
    )
    .expect("group create");
    send_client_value(&mut second, json!(["EVENT", event_to_value(&group_create)])).await;
    assert_ok(
        read_relay_value(&mut second).await,
        &group_create,
        false,
        "auth-required: group event author must authenticate with AUTH",
    );
    send_client_value(&mut first, json!(["EVENT", event_to_value(&group_create)])).await;
    assert_ok(read_relay_value(&mut first).await, &group_create, true, "");

    send_client_value(&mut first, json!(["EVENT", event_to_value(&first_event)])).await;
    assert_ok(read_relay_value(&mut first).await, &first_event, true, "");
    send_client_value(&mut first, json!(["EVENT", event_to_value(&first_event)])).await;
    assert_ok(
        read_relay_value(&mut first).await,
        &first_event,
        true,
        "duplicate: already have this event",
    );

    send_client_value(
        &mut first,
        json!(["COUNT", "count-websocket", {"kinds":[1]}]),
    )
    .await;
    assert_eq!(
        read_relay_value(&mut first).await,
        json!(["COUNT", "count-websocket", {"count": 1}])
    );

    send_client_value(&mut first, json!(["REQ", "shared-sub", {"kinds":[1]}])).await;
    assert_live_event(
        read_relay_value(&mut first).await,
        "shared-sub",
        &first_event,
    );
    assert_eq!(
        read_relay_value(&mut first).await,
        json!(["EOSE", "shared-sub"])
    );

    send_client_value(&mut second, json!(["REQ", "shared-sub", {"kinds":[1]}])).await;
    assert_live_event(
        read_relay_value(&mut second).await,
        "shared-sub",
        &first_event,
    );
    assert_eq!(
        read_relay_value(&mut second).await,
        json!(["EOSE", "shared-sub"])
    );

    send_client_value(&mut first, json!(["CLOSE", "shared-sub"])).await;
    expect_no_relay_message(&mut first).await;

    send_client_value(&mut first, json!(["EVENT", event_to_value(&second_event)])).await;
    assert_ok(read_relay_value(&mut first).await, &second_event, true, "");
    assert_live_event(
        read_relay_value(&mut second).await,
        "shared-sub",
        &second_event,
    );
    expect_no_relay_message(&mut first).await;

    send_client_value(&mut first, json!(["EVENT", event_to_value(&second_event)])).await;
    assert_ok(
        read_relay_value(&mut first).await,
        &second_event,
        true,
        "duplicate: already have this event",
    );
    expect_no_relay_message(&mut second).await;

    send_client_value(&mut second, json!(["CLOSE", "shared-sub"])).await;
    expect_no_relay_message(&mut second).await;

    shutdown.request_shutdown();
    read_websocket_close(&mut first).await;
    read_websocket_close(&mut second).await;
    let report = timeout(Duration::from_secs(2), task)
        .await
        .expect("shutdown timeout")
        .expect("task")
        .expect("serve");
    assert_eq!(report.listen_addr(), address);

    let _ = std::fs::remove_dir_all(root);
}

#[test]
#[ignore = "phase2 target: nip11 truthfulness"]
fn nip11_includes_cors_headers_and_truthful_supported_nips() {
    pending("NIP-11 must include CORS headers and advertise only enforced NIPs");
}

#[test]
fn auth_rejects_events_outside_created_at_skew() {
    let mut auth = BaseAuthState::new(TANGLE_V2_RELAY_URL, 300, 10).expect("auth");

    assert_eq!(
        auth.issue_challenge("challenge-a", UnixTimestamp::new(100))
            .expect("challenge"),
        RelayMessage::Auth("challenge-a".to_owned())
    );

    auth.authenticate(
        &tangle_v2_auth_event(FixtureKey::Owner, "challenge-a", 100).expect("fresh"),
        UnixTimestamp::new(100),
    )
    .expect("fresh");

    assert_eq!(
        auth.authenticate(
            &tangle_v2_auth_event(FixtureKey::Admin, "challenge-a", 89).expect("auth"),
            UnixTimestamp::new(100),
        )
        .expect_err("stale")
        .prefixed_message(),
        "auth-required: auth event created_at is outside configured skew"
    );
    assert_eq!(
        auth.authenticate(
            &tangle_v2_auth_event(FixtureKey::Member, "challenge-a", 111).expect("auth"),
            UnixTimestamp::new(100),
        )
        .expect_err("future")
        .prefixed_message(),
        "auth-required: auth event created_at is outside configured skew"
    );
}

#[test]
#[ignore = "phase2 target: nip70 enforcement"]
fn protected_events_require_author_auth_before_nip70_is_advertised() {
    pending("events with a dash tag require AUTH as event author before NIP-70 advertisement");
}

#[test]
fn private_but_not_hidden_group_metadata_remains_visible() {
    let owner = phase2_pubkey("1");
    let projection = phase2_projection_with_group(
        "Farm",
        phase2_metadata(true, false, false, false),
        owner.clone(),
    );
    let authority = GroupAuthority::new([owner.clone()], Vec::<PublicKeyHex>::new());
    let gate = GroupReadGate::new(&projection, &authority);

    assert_eq!(
        gate.screen_event(
            &phase2_snapshot_event(KIND_GROUP_METADATA, "Farm"),
            None,
            Default::default()
        )
        .expect("metadata"),
        GroupReadDecision::Visible
    );
    assert_eq!(
        gate.screen_event(
            &phase2_snapshot_event(KIND_GROUP_ADMINS, "Farm"),
            None,
            Default::default()
        )
        .expect("admins"),
        GroupReadDecision::Visible
    );
    assert_eq!(
        gate.screen_event(
            &phase2_snapshot_event(KIND_GROUP_MEMBERS, "Farm"),
            None,
            Default::default()
        )
        .expect("members"),
        GroupReadDecision::Hidden
    );

    let hidden_projection =
        phase2_projection_with_group("Hidden", phase2_metadata(false, false, true, false), owner);
    let hidden_gate = GroupReadGate::new(&hidden_projection, &authority);
    assert_eq!(
        hidden_gate
            .screen_event(
                &phase2_snapshot_event(KIND_GROUP_METADATA, "Hidden"),
                None,
                Default::default()
            )
            .expect("hidden metadata"),
        GroupReadDecision::Hidden
    );
}

#[test]
fn public_join_defaults_false() {
    let owner = phase2_pubkey("1");
    let joiner = phase2_pubkey("2");
    let projection = phase2_projection_with_group(
        "Farm",
        phase2_metadata(false, false, false, false),
        owner.clone(),
    );
    let authority = GroupAuthority::new([owner], Vec::<PublicKeyHex>::new());
    let policy = GroupWritePolicy::new(&projection, &authority, GroupPolicyConfig::strict());
    let join = phase2_group_event(KIND_GROUP_JOIN_REQUEST, "Farm", joiner.clone());
    let error = policy
        .check_event(
            &join,
            &GroupEventClass::Normal {
                group_id: GroupId::new("Farm").expect("group"),
            },
            &GroupAuthContext::new([joiner]),
        )
        .expect_err("join");

    assert_eq!(error.kind(), GroupErrorKind::GroupUnavailable);
    assert_eq!(error.prefixed_message(), "restricted: group is unavailable");
}

#[test]
fn duplicate_join_and_leave_use_duplicate_prefix() {
    let owner = phase2_pubkey("1");
    let member = phase2_pubkey("2");
    let outsider = phase2_pubkey("3");
    let mut projection = phase2_projection_with_group(
        "Farm",
        phase2_metadata(false, false, false, false),
        owner.clone(),
    );
    projection.put_member(
        GroupId::new("Farm").expect("group"),
        MemberState::new(
            member.clone(),
            MemberStatus::Member,
            Default::default(),
            phase2_event_id("20"),
            phase2_order_tuple(20, "20", 2),
        ),
    );
    let authority = GroupAuthority::new([owner], Vec::<PublicKeyHex>::new());
    let policy = GroupWritePolicy::new(
        &projection,
        &authority,
        GroupPolicyConfig::new(true, false).expect("policy"),
    );

    let duplicate_join = policy
        .check_event(
            &phase2_group_event(KIND_GROUP_JOIN_REQUEST, "Farm", member.clone()),
            &GroupEventClass::Normal {
                group_id: GroupId::new("Farm").expect("group"),
            },
            &GroupAuthContext::new([member]),
        )
        .expect_err("duplicate join");
    assert_eq!(
        duplicate_join.prefixed_message(),
        "duplicate: group member already exists"
    );

    let duplicate_leave = policy
        .check_event(
            &phase2_group_event(KIND_GROUP_LEAVE_REQUEST, "Farm", outsider.clone()),
            &GroupEventClass::Normal {
                group_id: GroupId::new("Farm").expect("group"),
            },
            &GroupAuthContext::new([outsider]),
        )
        .expect_err("duplicate leave");
    assert_eq!(
        duplicate_leave.prefixed_message(),
        "duplicate: group member does not exist"
    );
}

#[test]
fn closed_groups_use_strict_nip29_semantics_without_compatibility_flag() {
    let owner = phase2_pubkey("1");
    let outsider = phase2_pubkey("2");
    let projection = phase2_projection_with_group(
        "Closed",
        phase2_metadata(false, false, false, true),
        owner.clone(),
    );
    let authority = GroupAuthority::new([owner], Vec::<PublicKeyHex>::new());
    let policy = GroupWritePolicy::new(
        &projection,
        &authority,
        GroupPolicyConfig::new(true, false).expect("policy"),
    );

    let join_error = policy
        .check_event(
            &phase2_group_event(KIND_GROUP_JOIN_REQUEST, "Closed", outsider.clone()),
            &GroupEventClass::Normal {
                group_id: GroupId::new("Closed").expect("group"),
            },
            &GroupAuthContext::new([outsider.clone()]),
        )
        .expect_err("closed join");
    assert_eq!(join_error.kind(), GroupErrorKind::GroupUnavailable);
    assert_eq!(
        join_error.prefixed_message(),
        "restricted: group is unavailable"
    );

    assert_eq!(
        policy
            .check_event(
                &phase2_group_event(1, "Closed", outsider.clone()),
                &GroupEventClass::Normal {
                    group_id: GroupId::new("Closed").expect("group"),
                },
                &GroupAuthContext::new([outsider]),
            )
            .expect("normal write"),
        GroupWriteDecision::Accept
    );

    let error = parse_group_runtime_config_json(
        r#"{"enabled": false, "policy": {"compat_zooid_closed_means_restricted": true}}"#,
    )
    .expect_err("compat");
    assert!(
        error
            .message()
            .contains("unknown field `compat_zooid_closed_means_restricted`")
    );
}

#[test]
fn req_count_and_live_fanout_share_one_group_read_gate() {
    let relay_core = include_str!("../src/relay/core.rs");

    assert_eq!(
        relay_core
            .matches("fn group_read_gate_visible_to_auth")
            .count(),
        1
    );
    assert_eq!(
        relay_core
            .matches("Self::group_read_gate_visible_to_auth")
            .count(),
        4
    );
    assert!(!relay_core.contains("fn event_visible_to_auth("));
    assert!(!relay_core.contains("fn pocket_event_visible_to_auth("));
}

#[test]
fn runtime_hot_path_does_not_stringify_and_reparse_events() {
    let conversion_boundary = include_str!("../src/pocket_conversion.rs");
    for forbidden in [
        "event_to_value",
        "filter_to_value",
        "parse_event_json",
        "parse_pocket_event_json",
        "parse_pocket_filter_json",
        ".as_json()",
    ] {
        assert!(
            !conversion_boundary.contains(forbidden),
            "runtime Pocket conversion boundary contains forbidden JSON bridge `{forbidden}`"
        );
    }
}

#[test]
#[ignore = "phase2 target: canonical recovery"]
fn projection_and_outbox_recover_from_canonical_pocket_events() {
    pending("projection and outbox recovery must rebuild from canonical Pocket events");
}

#[test]
#[ignore = "phase2 target: generated broadcast"]
fn relay_generated_events_are_stored_projected_recovered_and_broadcast() {
    pending(
        "relay-generated group events must be stored projected recovered and broadcast by offset",
    );
}

fn pending(target: &str) {
    panic!("{target}");
}

fn runtime_config(root: &Path, listen_addr: SocketAddr) -> BaseRelayRuntimeConfig {
    let raw = serde_json::json!({
        "server": {
            "listen_addr": listen_addr.to_string(),
            "relay_url": "wss://relay.radroots.test"
        },
        "pocket": {
            "data_directory": root.join("pocket"),
            "map_size_bytes": 1073741824_u64,
            "reader_slots": 128,
            "sync_policy": "flush_on_shutdown"
        },
        "groups": {
            "enabled": true,
            "canonical_relay_url": "wss://relay.radroots.test",
            "relay_secret": TANGLE_V2_RELAY_SECRET_HEX,
            "owner_pubkeys": [FixtureKey::Owner.public_key().as_str()]
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
            "max_limit": 500,
            "default_limit": 100,
            "max_event_tags": 200,
            "max_content_length": 65536,
            "broadcast_channel_capacity": 8,
            "per_connection_outbound_queue": 8
        },
        "rate_limits": {
            "auth": {
                "per_pubkey": {"window_seconds": 60, "max_hits": 30},
                "failures": {"window_seconds": 300, "max_hits": 5}
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
            }
        }
    })
    .to_string();
    parse_base_relay_runtime_config_json(&raw).expect("config")
}

async fn wait_for_http_ok(
    address: SocketAddr,
    path: &'static str,
    accept: Option<&'static str>,
) -> String {
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut last_error = String::new();
    while Instant::now() < deadline {
        match tokio::task::spawn_blocking(move || http_get(address, path, accept))
            .await
            .expect("http task")
        {
            Ok(response) if response.starts_with("HTTP/1.1 200 OK") => return response,
            Ok(response) => {
                last_error = response.lines().next().unwrap_or("").to_owned();
            }
            Err(error) => {
                last_error = error.to_string();
            }
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("server did not answer {path}: {last_error}");
}

fn http_get(address: SocketAddr, path: &str, accept: Option<&str>) -> std::io::Result<String> {
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_millis(200))?;
    stream.set_read_timeout(Some(Duration::from_millis(500)))?;
    stream.set_write_timeout(Some(Duration::from_millis(500)))?;
    let mut request = format!("GET {path} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n");
    if let Some(accept) = accept {
        request.push_str(&format!("Accept: {accept}\r\n"));
    }
    request.push_str("\r\n");
    stream.write_all(request.as_bytes())?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    Ok(response)
}

fn temp_root(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("tangle-runtime-{name}-{}", std::process::id()))
}

type TestWebSocket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

async fn connect_nostr_socket(address: SocketAddr) -> TestWebSocket {
    let mut request = format!("ws://{address}/")
        .into_client_request()
        .expect("request");
    request.headers_mut().insert(
        header::SEC_WEBSOCKET_PROTOCOL,
        http::HeaderValue::from_static("nostr"),
    );
    let (socket, response) = tokio_tungstenite::connect_async(request)
        .await
        .expect("websocket");
    assert_eq!(response.status(), http::StatusCode::SWITCHING_PROTOCOLS);
    assert_eq!(
        response
            .headers()
            .get(header::SEC_WEBSOCKET_PROTOCOL)
            .expect("protocol"),
        "nostr"
    );
    socket
}

async fn send_client_value(socket: &mut TestWebSocket, value: Value) {
    send_client_text(socket, &value.to_string()).await;
}

async fn send_client_text(socket: &mut TestWebSocket, value: &str) {
    socket
        .send(TungsteniteMessage::Text(value.to_owned().into()))
        .await
        .expect("send client message");
}

async fn send_client_binary(socket: &mut TestWebSocket, value: &[u8]) {
    socket
        .send(TungsteniteMessage::Binary(value.to_vec().into()))
        .await
        .expect("send client binary");
}

async fn read_relay_value(socket: &mut TestWebSocket) -> Value {
    let message = timeout(Duration::from_secs(1), socket.next())
        .await
        .expect("relay message timeout")
        .expect("relay message")
        .expect("relay message result");
    let TungsteniteMessage::Text(text) = message else {
        panic!("expected relay text message, got {message:?}");
    };
    serde_json::from_str(text.as_str()).expect("relay json")
}

async fn read_auth_challenge(socket: &mut TestWebSocket) -> String {
    let auth = read_relay_value(socket).await;
    assert_eq!(auth[0], "AUTH");
    auth[1].as_str().expect("auth challenge").to_owned()
}

async fn read_websocket_close(socket: &mut TestWebSocket) {
    let next = timeout(Duration::from_secs(1), socket.next())
        .await
        .expect("websocket close");
    match next {
        Some(Ok(TungsteniteMessage::Close(_))) | None => {}
        other => panic!("expected websocket close, got {other:?}"),
    }
}

async fn expect_no_relay_message(socket: &mut TestWebSocket) {
    assert!(
        timeout(Duration::from_millis(75), socket.next())
            .await
            .is_err()
    );
}

fn assert_notice_prefix(value: Value, prefix: &str) {
    assert_eq!(value[0], "NOTICE");
    assert!(value[1].as_str().expect("notice").starts_with(prefix));
}

fn assert_ok(value: Value, event: &Event, accepted: bool, message: &str) {
    assert_eq!(value, json!(["OK", event.id().as_str(), accepted, message]));
}

fn assert_live_event(value: Value, subscription_id: &str, event: &Event) {
    assert_eq!(value[0], "EVENT");
    assert_eq!(value[1], subscription_id);
    assert_eq!(value[2]["id"], event.id().as_str());
}

fn phase2_projection_with_group(
    group_id: &str,
    metadata: GroupMetadata,
    author: PublicKeyHex,
) -> GroupProjection {
    let mut projection = GroupProjection::new();
    projection.put_group(GroupState::new(
        tangle_groups::GroupId::new(group_id).expect("group"),
        metadata,
        author,
        phase2_event_id("10"),
        phase2_order_tuple(10, "10", 1),
    ));
    projection
}

fn phase2_metadata(private: bool, restricted: bool, hidden: bool, closed: bool) -> GroupMetadata {
    GroupMetadata::from_parts(
        GroupMetadataText::empty(),
        GroupMetadataFlags::new(private, restricted, hidden, closed),
        SupportedKinds::UnspecifiedAll,
    )
}

fn phase2_snapshot_event(kind: u32, group_id: &str) -> Event {
    Event::new(
        phase2_event_id("01"),
        UnsignedEvent::new(
            phase2_pubkey("9"),
            UnixTimestamp::new(1),
            Kind::new(kind.into()).expect("kind"),
            vec![Tag::from_parts("d", &[group_id]).expect("d")],
            "",
        ),
        SignatureHex::new(&"2".repeat(128)).expect("sig"),
    )
}

fn phase2_group_event(kind: u32, group_id: &str, author: PublicKeyHex) -> Event {
    Event::new(
        phase2_event_id("02"),
        UnsignedEvent::new(
            author,
            UnixTimestamp::new(2),
            Kind::new(kind.into()).expect("kind"),
            vec![Tag::from_parts("h", &[group_id]).expect("h")],
            "",
        ),
        SignatureHex::new(&"3".repeat(128)).expect("sig"),
    )
}

fn phase2_pubkey(suffix: &str) -> PublicKeyHex {
    PublicKeyHex::new(&suffix.repeat(64)).expect("pubkey")
}

fn phase2_event_id(suffix: &str) -> EventId {
    let mut value = "0".repeat(64 - suffix.len());
    value.push_str(suffix);
    EventId::new(&value).expect("id")
}

fn phase2_order_tuple(created_at: u64, suffix: &str, offset: u64) -> ProjectionOrderTuple {
    ProjectionOrderTuple::new(
        UnixTimestamp::new(created_at),
        phase2_event_id(suffix),
        StoreOffset::new(offset),
    )
}

fn current_unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time")
        .as_secs()
}
