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
    Event, EventId, Filter, Kind, PublicKeyHex, RelayMessage, SignatureHex, SubscriptionId, Tag,
    UnixTimestamp, UnsignedEvent, event_to_value, filter_from_value,
};
use tangle_runtime::{
    config::{BaseRelayRuntimeConfig, parse_base_relay_runtime_config_json},
    nip11::BaseRelayInfoConfig,
    relay::auth::BaseAuthState,
    runtime::TangleRuntime,
    server::serve_listener_until_shutdown,
};
use tangle_store_pocket::{
    PocketStoreConfig, PocketStoreHandle, TANGLE_GROUP_CHECKPOINT_TABLE, TANGLE_GROUP_OUTBOX_TABLE,
    TANGLE_GROUP_PROJECTION_TABLE,
};
use tangle_test_support::{
    FixtureKey, TANGLE_V2_RELAY_SECRET_HEX, TANGLE_V2_RELAY_URL, tangle_v2_auth_event,
    tangle_v2_event, tangle_v2_group_create_event, tangle_v2_group_event,
    tangle_v2_group_metadata_event, tangle_v2_join_event, tangle_v2_put_user_event,
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
    let metrics = wait_for_http_ok(address, "/metricsz", None).await;
    let nip11 = wait_for_http_ok(address, "/", Some("application/nostr+json")).await;

    assert!(health.contains(r#""status":"ok""#));
    assert!(ready.contains(r#""status":"ready""#));
    assert!(ready.contains(r#""server_bind":"ready""#));
    assert!(metrics.contains(r#""tangle_readiness_ready":true"#));
    assert!(metrics.contains(r#""tangle_ws_connections_current":0"#));
    assert!(metrics.contains(r#""tangle_stored_event_offsets_total":0"#));
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

#[tokio::test]
async fn websocket_public_relay_covers_query_count_ephemeral_and_rejection_flows() {
    let root = temp_root("acceptance-public-websocket");
    let _ = std::fs::remove_dir_all(&root);
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
    let address = listener.local_addr().expect("address");
    let runtime = TangleRuntime::open(runtime_config(&root, address)).expect("runtime");
    let shutdown = runtime.shutdown_signal().clone();
    let task = tokio::spawn(serve_listener_until_shutdown(runtime, listener));
    let mut publisher = connect_nostr_socket(address).await;
    let mut subscriber = connect_nostr_socket(address).await;
    let _ = read_auth_challenge(&mut publisher).await;
    let _ = read_auth_challenge(&mut subscriber).await;
    let first = tangle_v2_event(
        FixtureKey::Member,
        1_714_124_433,
        1,
        Vec::new(),
        "public one",
    )
    .expect("first event");
    let second = tangle_v2_event(
        FixtureKey::Admin,
        1_714_124_435,
        1,
        Vec::new(),
        "public two",
    )
    .expect("second event");
    let other_kind = tangle_v2_event(
        FixtureKey::Owner,
        1_714_124_436,
        2,
        Vec::new(),
        "public other",
    )
    .expect("other event");
    let ephemeral = tangle_v2_event(
        FixtureKey::Member,
        1_714_124_437,
        20_001,
        Vec::new(),
        "public transient",
    )
    .expect("ephemeral event");
    let signature_source = tangle_v2_event(
        FixtureKey::Owner,
        1_714_124_438,
        1,
        Vec::new(),
        "signature source",
    )
    .expect("signature source");
    let invalid = Event::new(
        first.id().clone(),
        first.unsigned().clone(),
        signature_source.sig().clone(),
    );

    send_client_value(
        &mut subscriber,
        json!(["REQ", "live-public", {"kinds":[1, 20001]}]),
    )
    .await;
    assert_eq!(
        read_relay_value(&mut subscriber).await,
        json!(["EOSE", "live-public"])
    );

    send_client_value(&mut publisher, json!(["EVENT", event_to_value(&invalid)])).await;
    assert_ok(
        read_relay_value(&mut publisher).await,
        &invalid,
        false,
        "invalid: event signature verification failed",
    );
    expect_no_relay_message(&mut subscriber).await;

    send_client_value(&mut publisher, json!(["EVENT", event_to_value(&first)])).await;
    assert_ok(read_relay_value(&mut publisher).await, &first, true, "");
    assert_live_event(
        read_relay_value(&mut subscriber).await,
        "live-public",
        &first,
    );

    send_client_value(&mut publisher, json!(["EVENT", event_to_value(&second)])).await;
    assert_ok(read_relay_value(&mut publisher).await, &second, true, "");
    assert_live_event(
        read_relay_value(&mut subscriber).await,
        "live-public",
        &second,
    );

    send_client_value(
        &mut publisher,
        json!(["EVENT", event_to_value(&other_kind)]),
    )
    .await;
    assert_ok(
        read_relay_value(&mut publisher).await,
        &other_kind,
        true,
        "",
    );
    expect_no_relay_message(&mut subscriber).await;

    send_client_value(&mut publisher, json!(["EVENT", event_to_value(&ephemeral)])).await;
    assert_ok(read_relay_value(&mut publisher).await, &ephemeral, true, "");
    expect_no_relay_message(&mut subscriber).await;

    send_client_value(
        &mut publisher,
        json!(["COUNT", "count-kind-one", {"kinds":[1]}]),
    )
    .await;
    assert_eq!(
        read_relay_value(&mut publisher).await,
        json!(["COUNT", "count-kind-one", {"count": 2}])
    );

    send_client_value(
        &mut publisher,
        json!(["COUNT", "count-ephemeral", {"kinds":[20001]}]),
    )
    .await;
    assert_eq!(
        read_relay_value(&mut publisher).await,
        json!(["COUNT", "count-ephemeral", {"count": 0}])
    );

    send_client_value(
        &mut publisher,
        json!([
            "REQ",
            "query-public",
            {"kinds":[1], "limit":1},
            {"ids":[first.id().as_str(), other_kind.id().as_str()]}
        ]),
    )
    .await;
    assert_live_event(
        read_relay_value(&mut publisher).await,
        "query-public",
        &other_kind,
    );
    assert_live_event(
        read_relay_value(&mut publisher).await,
        "query-public",
        &second,
    );
    assert_live_event(
        read_relay_value(&mut publisher).await,
        "query-public",
        &first,
    );
    assert_eq!(
        read_relay_value(&mut publisher).await,
        json!(["EOSE", "query-public"])
    );

    send_client_value(&mut subscriber, json!(["CLOSE", "live-public"])).await;
    expect_no_relay_message(&mut subscriber).await;
    send_client_value(&mut publisher, json!(["CLOSE", "query-public"])).await;
    expect_no_relay_message(&mut publisher).await;

    let after_close = tangle_v2_event(
        FixtureKey::Admin,
        1_714_124_439,
        1,
        Vec::new(),
        "after close",
    )
    .expect("after close event");
    send_client_value(
        &mut publisher,
        json!(["EVENT", event_to_value(&after_close)]),
    )
    .await;
    assert_ok(
        read_relay_value(&mut publisher).await,
        &after_close,
        true,
        "",
    );
    expect_no_relay_message(&mut subscriber).await;

    shutdown.request_shutdown();
    read_websocket_close(&mut publisher).await;
    read_websocket_close(&mut subscriber).await;
    let report = timeout(Duration::from_secs(2), task)
        .await
        .expect("shutdown timeout")
        .expect("task")
        .expect("serve");
    assert_eq!(report.listen_addr(), address);

    let _ = std::fs::remove_dir_all(root);
}

#[tokio::test]
async fn websocket_nip29_group_lifecycle_state_and_live_paths_are_integrated() {
    let root = temp_root("acceptance-nip29-websocket");
    let _ = std::fs::remove_dir_all(&root);
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
    let address = listener.local_addr().expect("address");
    let runtime = TangleRuntime::open(runtime_config(&root, address)).expect("runtime");
    let shutdown = runtime.shutdown_signal().clone();
    let task = tokio::spawn(serve_listener_until_shutdown(runtime, listener));
    let mut owner = connect_nostr_socket(address).await;
    let mut member = connect_nostr_socket(address).await;
    let mut outsider = connect_nostr_socket(address).await;
    let mut observer = connect_nostr_socket(address).await;
    let owner_challenge = read_auth_challenge(&mut owner).await;
    let member_challenge = read_auth_challenge(&mut member).await;
    let outsider_challenge = read_auth_challenge(&mut outsider).await;
    let _ = read_auth_challenge(&mut observer).await;
    let auth_created_at = current_unix_timestamp();

    authenticate_client(
        &mut owner,
        FixtureKey::Owner,
        &owner_challenge,
        auth_created_at,
    )
    .await;
    authenticate_client(
        &mut member,
        FixtureKey::Member,
        &member_challenge,
        auth_created_at.saturating_add(1),
    )
    .await;
    authenticate_client(
        &mut outsider,
        FixtureKey::Outsider,
        &outsider_challenge,
        auth_created_at.saturating_add(2),
    )
    .await;

    let create = tangle_v2_group_create_event(FixtureKey::Owner, "SocketFarm", 1_714_124_440, &[])
        .expect("create");
    send_client_value(&mut owner, json!(["EVENT", event_to_value(&create)])).await;
    assert_ok(read_relay_value(&mut owner).await, &create, true, "");

    let denied_join =
        tangle_v2_join_event(FixtureKey::Outsider, "SocketFarm", 1_714_124_441).expect("join");
    send_client_value(
        &mut outsider,
        json!(["EVENT", event_to_value(&denied_join)]),
    )
    .await;
    assert_ok(
        read_relay_value(&mut outsider).await,
        &denied_join,
        false,
        "restricted: group is unavailable",
    );

    let metadata = tangle_v2_group_metadata_event(
        FixtureKey::Owner,
        "SocketFarm",
        "Socket Market",
        1_714_124_442,
        &[],
    )
    .expect("metadata");
    send_client_value(&mut owner, json!(["EVENT", event_to_value(&metadata)])).await;
    assert_ok(read_relay_value(&mut owner).await, &metadata, true, "");

    let put_member = tangle_v2_put_user_event(
        FixtureKey::Owner,
        "SocketFarm",
        FixtureKey::Member,
        1_714_124_443,
    )
    .expect("put member");
    send_client_value(&mut owner, json!(["EVENT", event_to_value(&put_member)])).await;
    assert_ok(read_relay_value(&mut owner).await, &put_member, true, "");

    for (subscription_id, kind) in [
        ("metadata-count", KIND_GROUP_METADATA),
        ("admins-count", KIND_GROUP_ADMINS),
        ("members-count", KIND_GROUP_MEMBERS),
    ] {
        send_client_value(
            &mut observer,
            json!(["COUNT", subscription_id, {"kinds":[kind], "#d":["SocketFarm"]}]),
        )
        .await;
        assert_eq!(
            read_relay_value(&mut observer).await,
            json!(["COUNT", subscription_id, {"count": 1}])
        );
    }

    for (subscription_id, kind) in [
        ("metadata-state", KIND_GROUP_METADATA),
        ("admins-state", KIND_GROUP_ADMINS),
        ("members-state", KIND_GROUP_MEMBERS),
    ] {
        send_client_value(
            &mut observer,
            json!(["REQ", subscription_id, {"kinds":[kind], "#d":["SocketFarm"]}]),
        )
        .await;
        assert_relay_event_kind_tag(
            read_relay_value(&mut observer).await,
            subscription_id,
            kind,
            "d",
            "SocketFarm",
        );
        assert_eq!(
            read_relay_value(&mut observer).await,
            json!(["EOSE", subscription_id])
        );
        send_client_value(&mut observer, json!(["CLOSE", subscription_id])).await;
        expect_no_relay_message(&mut observer).await;
    }

    send_client_value(
        &mut observer,
        json!(["REQ", "group-live", {"kinds":[1], "#h":["SocketFarm"]}]),
    )
    .await;
    assert_eq!(
        read_relay_value(&mut observer).await,
        json!(["EOSE", "group-live"])
    );

    let group_note = tangle_v2_group_event(
        FixtureKey::Member,
        "SocketFarm",
        1_714_124_444,
        1,
        "harvest",
    )
    .expect("group note");
    send_client_value(&mut member, json!(["EVENT", event_to_value(&group_note)])).await;
    assert_ok(read_relay_value(&mut member).await, &group_note, true, "");
    assert_live_event(
        read_relay_value(&mut observer).await,
        "group-live",
        &group_note,
    );

    send_client_value(
        &mut observer,
        json!(["COUNT", "group-note-count", {"kinds":[1], "#h":["SocketFarm"]}]),
    )
    .await;
    assert_eq!(
        read_relay_value(&mut observer).await,
        json!(["COUNT", "group-note-count", {"count": 1}])
    );

    send_client_value(
        &mut observer,
        json!(["REQ", "group-note-query", {"kinds":[1], "#h":["SocketFarm"]}]),
    )
    .await;
    assert_live_event(
        read_relay_value(&mut observer).await,
        "group-note-query",
        &group_note,
    );
    assert_eq!(
        read_relay_value(&mut observer).await,
        json!(["EOSE", "group-note-query"])
    );

    shutdown.request_shutdown();
    read_websocket_close(&mut owner).await;
    read_websocket_close(&mut member).await;
    read_websocket_close(&mut outsider).await;
    read_websocket_close(&mut observer).await;
    let report = timeout(Duration::from_secs(2), task)
        .await
        .expect("shutdown timeout")
        .expect("task")
        .expect("serve");
    assert_eq!(report.listen_addr(), address);

    let _ = std::fs::remove_dir_all(root);
}

#[tokio::test]
async fn websocket_private_and_hidden_groups_do_not_leak_through_query_count_or_live() {
    let root = temp_root("acceptance-privacy-websocket");
    let _ = std::fs::remove_dir_all(&root);
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
    let address = listener.local_addr().expect("address");
    let runtime = TangleRuntime::open(runtime_config(&root, address)).expect("runtime");
    let shutdown = runtime.shutdown_signal().clone();
    let task = tokio::spawn(serve_listener_until_shutdown(runtime, listener));
    let mut owner_writer = connect_nostr_socket(address).await;
    let mut owner_reader = connect_nostr_socket(address).await;
    let mut member_writer = connect_nostr_socket(address).await;
    let mut member_reader = connect_nostr_socket(address).await;
    let mut observer = connect_nostr_socket(address).await;
    let owner_writer_challenge = read_auth_challenge(&mut owner_writer).await;
    let owner_reader_challenge = read_auth_challenge(&mut owner_reader).await;
    let member_writer_challenge = read_auth_challenge(&mut member_writer).await;
    let member_reader_challenge = read_auth_challenge(&mut member_reader).await;
    let _ = read_auth_challenge(&mut observer).await;
    let auth_created_at = current_unix_timestamp();

    authenticate_client(
        &mut owner_writer,
        FixtureKey::Owner,
        &owner_writer_challenge,
        auth_created_at,
    )
    .await;
    authenticate_client(
        &mut owner_reader,
        FixtureKey::Owner,
        &owner_reader_challenge,
        auth_created_at.saturating_add(1),
    )
    .await;
    authenticate_client(
        &mut member_writer,
        FixtureKey::Member,
        &member_writer_challenge,
        auth_created_at.saturating_add(2),
    )
    .await;
    authenticate_client(
        &mut member_reader,
        FixtureKey::Member,
        &member_reader_challenge,
        auth_created_at.saturating_add(3),
    )
    .await;

    let private_create = tangle_v2_group_create_event(
        FixtureKey::Owner,
        "PrivateSocket",
        1_714_124_450,
        &["private"],
    )
    .expect("private create");
    send_client_value(
        &mut owner_writer,
        json!(["EVENT", event_to_value(&private_create)]),
    )
    .await;
    assert_ok(
        read_relay_value(&mut owner_writer).await,
        &private_create,
        true,
        "",
    );

    let private_put = tangle_v2_put_user_event(
        FixtureKey::Owner,
        "PrivateSocket",
        FixtureKey::Member,
        1_714_124_451,
    )
    .expect("private put");
    send_client_value(
        &mut owner_writer,
        json!(["EVENT", event_to_value(&private_put)]),
    )
    .await;
    assert_ok(
        read_relay_value(&mut owner_writer).await,
        &private_put,
        true,
        "",
    );

    assert_count_message(
        &mut observer,
        "private-metadata-public-count",
        json!({"kinds":[KIND_GROUP_METADATA], "#d":["PrivateSocket"]}),
        1,
    )
    .await;
    assert_count_message(
        &mut observer,
        "private-members-public-count",
        json!({"kinds":[KIND_GROUP_MEMBERS], "#d":["PrivateSocket"]}),
        0,
    )
    .await;

    send_client_value(
        &mut observer,
        json!(["REQ", "private-public-live", {"kinds":[1], "#h":["PrivateSocket"]}]),
    )
    .await;
    assert_eq!(
        read_relay_value(&mut observer).await,
        json!(["EOSE", "private-public-live"])
    );
    send_client_value(
        &mut member_reader,
        json!(["REQ", "private-member-live", {"kinds":[1], "#h":["PrivateSocket"]}]),
    )
    .await;
    assert_eq!(
        read_relay_value(&mut member_reader).await,
        json!(["EOSE", "private-member-live"])
    );

    let private_note = tangle_v2_group_event(
        FixtureKey::Member,
        "PrivateSocket",
        1_714_124_452,
        1,
        "private harvest",
    )
    .expect("private note");
    send_client_value(
        &mut member_writer,
        json!(["EVENT", event_to_value(&private_note)]),
    )
    .await;
    assert_ok(
        read_relay_value(&mut member_writer).await,
        &private_note,
        true,
        "",
    );
    assert_live_event(
        read_relay_value(&mut member_reader).await,
        "private-member-live",
        &private_note,
    );
    expect_no_relay_message(&mut observer).await;
    assert_count_message(
        &mut observer,
        "private-public-count",
        json!({"kinds":[1], "#h":["PrivateSocket"]}),
        0,
    )
    .await;
    assert_count_message(
        &mut member_reader,
        "private-member-count",
        json!({"kinds":[1], "#h":["PrivateSocket"]}),
        1,
    )
    .await;
    assert_empty_req(
        &mut observer,
        "private-public-query",
        json!({"kinds":[1], "#h":["PrivateSocket"]}),
    )
    .await;
    assert_req_event_then_eose(
        &mut member_reader,
        "private-member-query",
        json!({"kinds":[1], "#h":["PrivateSocket"]}),
        &private_note,
    )
    .await;

    let hidden_create = tangle_v2_group_create_event(
        FixtureKey::Owner,
        "HiddenSocket",
        1_714_124_453,
        &["hidden"],
    )
    .expect("hidden create");
    send_client_value(
        &mut owner_writer,
        json!(["EVENT", event_to_value(&hidden_create)]),
    )
    .await;
    assert_ok(
        read_relay_value(&mut owner_writer).await,
        &hidden_create,
        true,
        "",
    );

    assert_count_message(
        &mut observer,
        "hidden-metadata-public-count",
        json!({"kinds":[KIND_GROUP_METADATA], "#d":["HiddenSocket"]}),
        0,
    )
    .await;
    assert_count_message(
        &mut owner_reader,
        "hidden-metadata-owner-count",
        json!({"kinds":[KIND_GROUP_METADATA], "#d":["HiddenSocket"]}),
        1,
    )
    .await;
    assert_empty_req(
        &mut observer,
        "hidden-metadata-public-query",
        json!({"kinds":[KIND_GROUP_METADATA], "#d":["HiddenSocket"]}),
    )
    .await;

    send_client_value(
        &mut observer,
        json!(["REQ", "hidden-public-live", {"kinds":[1], "#h":["HiddenSocket"]}]),
    )
    .await;
    assert_eq!(
        read_relay_value(&mut observer).await,
        json!(["EOSE", "hidden-public-live"])
    );
    send_client_value(
        &mut owner_reader,
        json!(["REQ", "hidden-owner-live", {"kinds":[1], "#h":["HiddenSocket"]}]),
    )
    .await;
    assert_eq!(
        read_relay_value(&mut owner_reader).await,
        json!(["EOSE", "hidden-owner-live"])
    );

    let hidden_note = tangle_v2_group_event(
        FixtureKey::Owner,
        "HiddenSocket",
        1_714_124_454,
        1,
        "hidden harvest",
    )
    .expect("hidden note");
    send_client_value(
        &mut owner_writer,
        json!(["EVENT", event_to_value(&hidden_note)]),
    )
    .await;
    assert_ok(
        read_relay_value(&mut owner_writer).await,
        &hidden_note,
        true,
        "",
    );
    assert_live_event(
        read_relay_value(&mut owner_reader).await,
        "hidden-owner-live",
        &hidden_note,
    );
    expect_no_relay_message(&mut observer).await;
    assert_count_message(
        &mut observer,
        "hidden-public-count",
        json!({"kinds":[1], "#h":["HiddenSocket"]}),
        0,
    )
    .await;
    assert_count_message(
        &mut owner_reader,
        "hidden-owner-count",
        json!({"kinds":[1], "#h":["HiddenSocket"]}),
        1,
    )
    .await;
    assert_empty_req(
        &mut observer,
        "hidden-public-query",
        json!({"kinds":[1], "#h":["HiddenSocket"]}),
    )
    .await;
    assert_req_event_then_eose(
        &mut owner_reader,
        "hidden-owner-query",
        json!({"kinds":[1], "#h":["HiddenSocket"]}),
        &hidden_note,
    )
    .await;

    shutdown.request_shutdown();
    read_websocket_close(&mut owner_writer).await;
    read_websocket_close(&mut owner_reader).await;
    read_websocket_close(&mut member_writer).await;
    read_websocket_close(&mut member_reader).await;
    read_websocket_close(&mut observer).await;
    let report = timeout(Duration::from_secs(2), task)
        .await
        .expect("shutdown timeout")
        .expect("task")
        .expect("serve");
    assert_eq!(report.listen_addr(), address);

    let _ = std::fs::remove_dir_all(root);
}

#[tokio::test]
async fn nip11_includes_cors_headers_and_truthful_supported_nips() {
    let root = temp_root("acceptance-nip11");
    let _ = std::fs::remove_dir_all(&root);
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
    let address = listener.local_addr().expect("address");
    let runtime = TangleRuntime::open(runtime_config(&root, address)).expect("runtime");
    let shutdown = runtime.shutdown_signal().clone();
    let task = tokio::spawn(serve_listener_until_shutdown(runtime, listener));

    let response = wait_for_http_ok(address, "/", Some("application/nostr+json")).await;
    let lower = response.to_ascii_lowercase();
    assert!(lower.contains("content-type: application/nostr+json"));
    assert!(lower.contains("access-control-allow-origin: *"));
    assert!(lower.contains("access-control-allow-headers: *"));
    assert!(lower.contains("access-control-allow-methods: *"));

    let document = serde_json::from_str::<Value>(response_body(&response)).expect("nip11 json");
    assert_eq!(document["supported_nips"], json!([1, 11, 29, 42, 45, 70]));
    assert!(
        !document["supported_nips"]
            .as_array()
            .expect("supported nips")
            .contains(&json!(50))
    );
    assert!(
        !document["supported_nips"]
            .as_array()
            .expect("supported nips")
            .contains(&json!(77))
    );
    assert!(
        !document["supported_nips"]
            .as_array()
            .expect("supported nips")
            .contains(&json!(99))
    );

    shutdown.request_shutdown();
    let report = timeout(Duration::from_secs(2), task)
        .await
        .expect("shutdown timeout")
        .expect("task")
        .expect("serve");
    assert_eq!(report.listen_addr(), address);

    let _ = std::fs::remove_dir_all(root);
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
fn protected_events_require_author_auth_before_nip70_is_advertised() {
    let root = temp_root("acceptance-nip70");
    let _ = std::fs::remove_dir_all(&root);
    let config = runtime_config(&root, SocketAddr::from(([127, 0, 0, 1], 0)));
    let document = BaseRelayInfoConfig::new("tangle", &config)
        .expect("info config")
        .build_document()
        .expect("document");
    let relay = config.open_relay().expect("relay");
    let protected = tangle_v2_event(
        FixtureKey::Member,
        1_714_124_433,
        1,
        vec![Tag::from_parts("-", &[]).expect("protected")],
        "protected",
    )
    .expect("protected event");
    let mut auth = BaseAuthState::new(TANGLE_V2_RELAY_URL, 300, 10).expect("auth");
    auth.issue_challenge("challenge-a", UnixTimestamp::new(1_714_124_433))
        .expect("challenge");
    auth.authenticate(
        &tangle_v2_auth_event(FixtureKey::Member, "challenge-a", 1_714_124_433).expect("auth"),
        UnixTimestamp::new(1_714_124_433),
    )
    .expect("author auth");

    assert!(document.supported_nips.contains(&70));
    assert_eq!(
        relay.handle_event(protected.clone()).expect("unauth"),
        RelayMessage::Ok {
            event_id: protected.id().clone(),
            accepted: false,
            message: "auth-required: protected event requires authenticated event author"
                .to_owned()
        }
    );
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

#[test]
fn negentropy_remains_unconfigurable_and_unadvertised_until_read_gated() {
    let root = temp_root("acceptance-negentropy");
    let mut raw = runtime_config_value(&root, SocketAddr::from(([127, 0, 0, 1], 0)));
    raw.as_object_mut()
        .expect("config object")
        .insert("negentropy".to_owned(), json!({"enabled": true}));

    let error =
        parse_base_relay_runtime_config_json(&raw.to_string()).expect_err("negentropy rejected");
    assert!(error.message().contains("unknown field `negentropy`"));

    raw.as_object_mut()
        .expect("config object")
        .remove("negentropy")
        .expect("negentropy field");
    let config = parse_base_relay_runtime_config_json(&raw.to_string()).expect("config");
    let document = BaseRelayInfoConfig::new("tangle", &config)
        .expect("info config")
        .build_document()
        .expect("document");
    assert!(!document.supported_nips.contains(&77));

    let _ = std::fs::remove_dir_all(root);
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
    let runtime = include_str!("../src/runtime.rs");

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
        3
    );
    assert_eq!(
        runtime
            .matches("BaseRelay::group_read_gate_visible_to_auth")
            .count(),
        2
    );
    assert!(!relay_core.contains("fn event_visible_to_auth("));
    assert!(!relay_core.contains("fn pocket_event_visible_to_auth("));
}

#[test]
fn runtime_event_handling_does_not_lock_relay_state() {
    let runtime = include_str!("../src/runtime.rs");
    let event_branch = runtime
        .split("ClientMessage::Event(event) => {")
        .nth(1)
        .expect("event branch")
        .split("ClientMessage::Req")
        .next()
        .expect("req branch");

    assert!(!event_branch.contains("relay.lock().await"));
    assert!(event_branch.contains("self.inner.handle_event_with_auth_report(event, auth)?"));
}

#[test]
fn runtime_req_handling_does_not_lock_relay_state() {
    let runtime = include_str!("../src/runtime.rs");
    let req_branch = runtime
        .split("ClientMessage::Req {")
        .nth(1)
        .expect("req branch")
        .split("ClientMessage::Count")
        .next()
        .expect("count branch");
    let query_helper = runtime
        .split("pub(crate) async fn query_req_with_auth")
        .nth(1)
        .expect("query helper")
        .split("pub async fn event_by_offset_with_auth")
        .next()
        .expect("offset helper");

    assert!(!req_branch.contains("relay.lock().await"));
    assert!(!query_helper.contains("relay.lock().await"));
    assert!(req_branch.contains("query_req_with_auth_report(subscription_id, filters, auth)?"));
    assert!(query_helper.contains("query_req_with_auth_report(subscription_id, filters, auth)?"));
}

#[test]
fn runtime_count_handling_does_not_lock_relay_state() {
    let runtime = include_str!("../src/runtime.rs");
    let count_branch = runtime
        .split("ClientMessage::Count {")
        .nth(1)
        .expect("count branch")
        .split("ClientMessage::Auth")
        .next()
        .expect("auth branch");

    assert!(!count_branch.contains("relay.lock().await"));
    assert!(
        count_branch.contains("handle_count_with_auth_report(subscription_id, filters, auth)?")
    );
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
fn projection_and_outbox_recover_from_canonical_pocket_events() {
    let root = temp_root("acceptance-recovery");
    let _ = std::fs::remove_dir_all(&root);
    let config = runtime_config(&root, "127.0.0.1:0".parse().expect("listen addr"));
    let mut auth = config.auth_state().expect("auth");
    auth.issue_challenge("recovery-challenge", UnixTimestamp::new(1_714_124_470))
        .expect("challenge");
    let owner_auth = tangle_v2_auth_event(FixtureKey::Owner, "recovery-challenge", 1_714_124_470)
        .expect("owner auth");
    let member_auth = tangle_v2_auth_event(FixtureKey::Member, "recovery-challenge", 1_714_124_471)
        .expect("member auth");
    auth.authenticate(&owner_auth, UnixTimestamp::new(1_714_124_470))
        .expect("owner");
    auth.authenticate(&member_auth, UnixTimestamp::new(1_714_124_471))
        .expect("member");
    let create =
        tangle_v2_group_create_event(FixtureKey::Owner, "RecoverSocket", 1_714_124_472, &[])
            .expect("create");
    let put_member = tangle_v2_put_user_event(
        FixtureKey::Owner,
        "RecoverSocket",
        FixtureKey::Member,
        1_714_124_473,
    )
    .expect("put member");
    let note = tangle_v2_group_event(
        FixtureKey::Member,
        "RecoverSocket",
        1_714_124_474,
        1,
        "recover harvest",
    )
    .expect("note");

    {
        let mut runtime = TangleRuntime::open(config.clone()).expect("runtime");
        assert_relay_ok(
            runtime
                .relay_mut()
                .handle_event_with_auth(create.clone(), &auth)
                .expect("create"),
            &create,
            true,
            "",
        );
        assert_relay_ok(
            runtime
                .relay_mut()
                .handle_event_with_auth(put_member.clone(), &auth)
                .expect("put member"),
            &put_member,
            true,
            "",
        );
        assert_relay_ok(
            runtime
                .relay_mut()
                .handle_event_with_auth(note.clone(), &auth)
                .expect("note"),
            &note,
            true,
            "",
        );
        assert_relay_count(
            runtime
                .relay()
                .handle_count(
                    subscription_id("pre-recovery-members"),
                    vec![relay_filter(
                        json!({"kinds":[KIND_GROUP_MEMBERS], "#d":["RecoverSocket"]}),
                    )],
                )
                .expect("members count"),
            "pre-recovery-members",
            1,
        );
        runtime.shutdown().expect("shutdown");
    }

    delete_group_extra_records(config.pocket_config());

    let recovered = TangleRuntime::open(config.clone()).expect("recovered");
    let readiness = recovered.readiness_state().response();
    assert_eq!(readiness.checks.group_projection, "ready");
    assert_eq!(readiness.checks.group_outbox_replay, "ready");
    assert_eq!(readiness.checks.event_bus, "ready");
    assert!(
        recovered
            .relay()
            .group_projection()
            .expect("projection")
            .group(&GroupId::new("RecoverSocket").expect("group"))
            .is_some()
    );
    assert_relay_count(
        recovered
            .relay()
            .handle_count(
                subscription_id("recovered-metadata"),
                vec![relay_filter(
                    json!({"kinds":[KIND_GROUP_METADATA], "#d":["RecoverSocket"]}),
                )],
            )
            .expect("metadata count"),
        "recovered-metadata",
        1,
    );
    assert_relay_count(
        recovered
            .relay()
            .handle_count(
                subscription_id("recovered-admins"),
                vec![relay_filter(
                    json!({"kinds":[KIND_GROUP_ADMINS], "#d":["RecoverSocket"]}),
                )],
            )
            .expect("admins count"),
        "recovered-admins",
        1,
    );
    assert_relay_count(
        recovered
            .relay()
            .handle_count(
                subscription_id("recovered-members"),
                vec![relay_filter(
                    json!({"kinds":[KIND_GROUP_MEMBERS], "#d":["RecoverSocket"]}),
                )],
            )
            .expect("members count"),
        "recovered-members",
        1,
    );
    assert_relay_count(
        recovered
            .relay()
            .handle_count(
                subscription_id("recovered-note"),
                vec![relay_filter(json!({"kinds":[1], "#h":["RecoverSocket"]}))],
            )
            .expect("note count"),
        "recovered-note",
        1,
    );

    let _ = std::fs::remove_dir_all(root);
}

#[tokio::test]
async fn relay_generated_events_are_stored_projected_and_broadcast_to_websocket_clients() {
    let root = temp_root("acceptance-generated-websocket");
    let _ = std::fs::remove_dir_all(&root);
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
    let address = listener.local_addr().expect("address");
    let runtime = TangleRuntime::open(runtime_config(&root, address)).expect("runtime");
    let shutdown = runtime.shutdown_signal().clone();
    let task = tokio::spawn(serve_listener_until_shutdown(runtime, listener));
    let mut owner = connect_nostr_socket(address).await;
    let mut observer = connect_nostr_socket(address).await;
    let owner_challenge = read_auth_challenge(&mut owner).await;
    let _ = read_auth_challenge(&mut observer).await;
    authenticate_client(
        &mut owner,
        FixtureKey::Owner,
        &owner_challenge,
        current_unix_timestamp(),
    )
    .await;

    send_client_value(
        &mut observer,
        json!([
            "REQ",
            "generated-state-live",
            {"kinds":[KIND_GROUP_METADATA, KIND_GROUP_ADMINS, KIND_GROUP_MEMBERS], "#d":["GeneratedSocket"]}
        ]),
    )
    .await;
    assert_eq!(
        read_relay_value(&mut observer).await,
        json!(["EOSE", "generated-state-live"])
    );

    let create =
        tangle_v2_group_create_event(FixtureKey::Owner, "GeneratedSocket", 1_714_124_460, &[])
            .expect("create");
    send_client_value(&mut owner, json!(["EVENT", event_to_value(&create)])).await;
    assert_ok(read_relay_value(&mut owner).await, &create, true, "");
    let create_generated_kinds = [
        relay_event_kind_tag(
            read_relay_value(&mut observer).await,
            "generated-state-live",
            "d",
            "GeneratedSocket",
        ),
        relay_event_kind_tag(
            read_relay_value(&mut observer).await,
            "generated-state-live",
            "d",
            "GeneratedSocket",
        ),
    ];
    assert!(create_generated_kinds.contains(&KIND_GROUP_METADATA));
    assert!(create_generated_kinds.contains(&KIND_GROUP_ADMINS));
    assert_count_message(
        &mut observer,
        "generated-metadata-count",
        json!({"kinds":[KIND_GROUP_METADATA], "#d":["GeneratedSocket"]}),
        1,
    )
    .await;
    assert_count_message(
        &mut observer,
        "generated-admins-count",
        json!({"kinds":[KIND_GROUP_ADMINS], "#d":["GeneratedSocket"]}),
        1,
    )
    .await;

    let put_member = tangle_v2_put_user_event(
        FixtureKey::Owner,
        "GeneratedSocket",
        FixtureKey::Member,
        1_714_124_461,
    )
    .expect("put member");
    send_client_value(&mut owner, json!(["EVENT", event_to_value(&put_member)])).await;
    assert_ok(read_relay_value(&mut owner).await, &put_member, true, "");
    assert_eq!(
        relay_event_kind_tag(
            read_relay_value(&mut observer).await,
            "generated-state-live",
            "d",
            "GeneratedSocket",
        ),
        KIND_GROUP_MEMBERS
    );
    assert_count_message(
        &mut observer,
        "generated-members-count",
        json!({"kinds":[KIND_GROUP_MEMBERS], "#d":["GeneratedSocket"]}),
        1,
    )
    .await;

    shutdown.request_shutdown();
    read_websocket_close(&mut owner).await;
    read_websocket_close(&mut observer).await;
    let report = timeout(Duration::from_secs(2), task)
        .await
        .expect("shutdown timeout")
        .expect("task")
        .expect("serve");
    assert_eq!(report.listen_addr(), address);

    let _ = std::fs::remove_dir_all(root);
}

fn runtime_config(root: &Path, listen_addr: SocketAddr) -> BaseRelayRuntimeConfig {
    parse_base_relay_runtime_config_json(&runtime_config_value(root, listen_addr).to_string())
        .expect("config")
}

fn runtime_config_value(root: &Path, listen_addr: SocketAddr) -> Value {
    json!({
        "server": {
            "listen_addr": listen_addr.to_string(),
            "relay_url": "wss://relay.radroots.test"
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
            "max_query_complexity": 2048,
            "max_limit": 500,
            "default_limit": 100,
            "max_event_tags": 200,
            "max_content_length": 65536,
            "broadcast_channel_capacity": 8,
            "per_connection_outbound_queue": 8
        },
        "rate_limits": {
            "auth": {
                "per_ip": {"window_seconds": 60, "max_hits": 120},
                "per_pubkey": {"window_seconds": 60, "max_hits": 30},
                "failures": {"window_seconds": 300, "max_hits": 5},
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

fn response_body(response: &str) -> &str {
    response.split_once("\r\n\r\n").expect("response body").1
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

async fn authenticate_client(
    socket: &mut TestWebSocket,
    fixture_key: FixtureKey,
    challenge: &str,
    created_at: u64,
) {
    let auth = tangle_v2_auth_event(fixture_key, challenge, created_at).expect("auth");
    send_client_value(socket, json!(["AUTH", event_to_value(&auth)])).await;
    assert_ok(read_relay_value(socket).await, &auth, true, "");
}

async fn assert_count_message(
    socket: &mut TestWebSocket,
    subscription_id: &str,
    filter: Value,
    count: u64,
) {
    send_client_value(socket, json!(["COUNT", subscription_id, filter])).await;
    assert_eq!(
        read_relay_value(socket).await,
        json!(["COUNT", subscription_id, {"count": count}])
    );
}

async fn assert_empty_req(socket: &mut TestWebSocket, subscription_id: &str, filter: Value) {
    send_client_value(socket, json!(["REQ", subscription_id, filter])).await;
    assert_eq!(
        read_relay_value(socket).await,
        json!(["EOSE", subscription_id])
    );
}

async fn assert_req_event_then_eose(
    socket: &mut TestWebSocket,
    subscription_id: &str,
    filter: Value,
    event: &Event,
) {
    send_client_value(socket, json!(["REQ", subscription_id, filter])).await;
    assert_live_event(read_relay_value(socket).await, subscription_id, event);
    assert_eq!(
        read_relay_value(socket).await,
        json!(["EOSE", subscription_id])
    );
}

fn assert_relay_ok(message: RelayMessage, event: &Event, accepted: bool, reason: &str) {
    assert_eq!(
        message,
        RelayMessage::Ok {
            event_id: event.id().clone(),
            accepted,
            message: reason.to_owned()
        }
    );
}

fn assert_relay_count(message: RelayMessage, subscription_id: &str, count: u64) {
    assert_eq!(
        message,
        RelayMessage::Count {
            subscription_id: SubscriptionId::new(subscription_id).expect("subscription"),
            count
        }
    );
}

fn relay_filter(value: Value) -> Filter {
    filter_from_value(&value).expect("filter")
}

fn subscription_id(value: &str) -> SubscriptionId {
    SubscriptionId::new(value).expect("subscription")
}

fn delete_group_extra_records(config: &PocketStoreConfig) {
    let store = PocketStoreHandle::open(config).expect("store");
    for table in [
        TANGLE_GROUP_PROJECTION_TABLE,
        TANGLE_GROUP_OUTBOX_TABLE,
        TANGLE_GROUP_CHECKPOINT_TABLE,
    ] {
        for (key, _) in store.scan_extra_records(table).expect("scan") {
            store.delete_extra_record(table, &key).expect("delete");
        }
    }
    store.sync().expect("sync");
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

fn assert_relay_event_kind_tag(
    value: Value,
    subscription_id: &str,
    kind: u32,
    tag_name: &str,
    tag_value: &str,
) {
    assert_eq!(
        relay_event_kind_tag(value, subscription_id, tag_name, tag_value),
        kind
    );
}

fn relay_event_kind_tag(
    value: Value,
    subscription_id: &str,
    tag_name: &str,
    tag_value: &str,
) -> u32 {
    assert_eq!(value[0], "EVENT");
    assert_eq!(value[1], subscription_id);
    let tags = value[2]["tags"].as_array().expect("tags");
    assert!(tags.iter().any(|tag| {
        let Some(parts) = tag.as_array() else {
            return false;
        };
        parts.first().and_then(Value::as_str) == Some(tag_name)
            && parts.get(1).and_then(Value::as_str) == Some(tag_value)
    }));
    u32::try_from(value[2]["kind"].as_u64().expect("event kind")).expect("event kind fits u32")
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
