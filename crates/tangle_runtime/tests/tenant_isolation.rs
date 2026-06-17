#![forbid(unsafe_code)]

use futures_util::{SinkExt, StreamExt};
use http::header;
use serde_json::{Value, json};
use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tangle_crypto::RelaySigner;
use tangle_groups::{
    KIND_GROUP_ADMINS, KIND_GROUP_CREATE_GROUP, KIND_GROUP_DELETE_GROUP, KIND_GROUP_EDIT_METADATA,
    KIND_GROUP_MEMBERS, KIND_GROUP_METADATA, KIND_GROUP_PUT_USER,
};
use tangle_protocol::{
    Event, EventId, Kind, PublicKeyHex, SignatureHex, Tag, UnixTimestamp, UnsignedEvent,
    event_from_value, event_to_value,
};
use tangle_runtime::{
    config::{
        TangleHostRuntimeConfigSet, parse_tangle_host_runtime_config_json,
        parse_tenant_runtime_config_json,
    },
    errors::BaseRelayError,
    host::TangleHostRuntime,
    runtime::TangleShutdownSignal,
    server::{TangleServeReport, serve_listener_until_shutdown},
};
use tangle_store_pocket::{
    PocketEvent, PocketKind, PocketOwnedEvent, PocketOwnedTags, PocketTime, parse_pocket_event_json,
};
use tangle_test_support::FixtureKey;
use tokio::{net::TcpListener, task::JoinHandle, time::timeout};
use tokio_tungstenite::{
    MaybeTlsStream, WebSocketStream, connect_async,
    tungstenite::{Message as TungsteniteMessage, client::IntoClientRequest},
};

type TestWebSocket = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

#[tokio::test]
async fn tenant_isolation_public_events_counts_hll_and_live_fanout() {
    let host = RunningHost::start("public-events", 600).await;
    let mut alpha = connect_socket(host.address, "alpha.relay.test").await;
    let mut beta = connect_socket(host.address, "beta.relay.test").await;
    let mut beta_subscriber = connect_socket(host.address, "beta.relay.test").await;
    let target = "a".repeat(EventId::HEX_LENGTH);
    let target_tag = Tag::from_parts("e", &[&target]).expect("target");
    let shared = tangle_v2_event(
        FixtureKey::Member,
        1_714_200_001,
        1,
        Vec::new(),
        "shared tenant note",
    )
    .expect("shared");
    let beta_extra = tangle_v2_event(
        FixtureKey::Admin,
        1_714_200_002,
        1,
        Vec::new(),
        "beta only note",
    )
    .expect("beta extra");
    let hll_shared = tangle_v2_event(
        FixtureKey::Member,
        1_714_200_003,
        7,
        vec![target_tag.clone()],
        "+",
    )
    .expect("hll shared");
    let hll_beta_extra =
        tangle_v2_event(FixtureKey::Admin, 1_714_200_004, 7, vec![target_tag], "+")
            .expect("hll beta extra");

    send_client_value(
        &mut beta_subscriber,
        json!(["REQ", "beta-live", {"kinds":[1]}]),
    )
    .await;
    assert_eq!(
        read_relay_value(&mut beta_subscriber).await,
        json!(["EOSE", "beta-live"])
    );

    assert_ok_accepted(&mut alpha, &shared).await;
    assert_eq!(
        collect_req_events(&mut alpha, "alpha-after-alpha", json!({"kinds":[1]}))
            .await
            .iter()
            .map(|event| event.id().as_str().to_owned())
            .collect::<Vec<_>>(),
        vec![shared.id().as_str().to_owned()]
    );
    assert!(
        collect_req_events(&mut beta, "beta-before-beta", json!({"kinds":[1]}))
            .await
            .is_empty()
    );
    assert_no_relay_message(&mut beta_subscriber).await;

    assert_ok_accepted(&mut beta, &shared).await;
    let live_shared = read_relay_value(&mut beta_subscriber).await;
    assert_eq!(live_shared[0], "EVENT");
    assert_eq!(live_shared[1], "beta-live");
    assert_eq!(live_shared[2]["id"], shared.id().as_str());

    assert_ok_accepted(&mut beta, &beta_extra).await;
    let live_extra = read_relay_value(&mut beta_subscriber).await;
    assert_eq!(live_extra[0], "EVENT");
    assert_eq!(live_extra[1], "beta-live");
    assert_eq!(live_extra[2]["id"], beta_extra.id().as_str());
    assert_ok_accepted(&mut alpha, &hll_shared).await;
    assert_ok_accepted(&mut beta, &hll_shared).await;
    assert_ok_accepted(&mut beta, &hll_beta_extra).await;

    let alpha_events = collect_req_events(&mut alpha, "alpha-final", json!({"kinds":[1]})).await;
    let beta_events = collect_req_events(&mut beta, "beta-final", json!({"kinds":[1]})).await;
    assert_eq!(alpha_events.len(), 1);
    assert_eq!(beta_events.len(), 2);
    assert_eq!(alpha_events[0].id(), shared.id());
    assert!(beta_events.iter().any(|event| event.id() == shared.id()));
    assert!(
        beta_events
            .iter()
            .any(|event| event.id() == beta_extra.id())
    );

    let alpha_count = count_payload(
        &mut alpha,
        "alpha-count",
        json!({"kinds":[7], "#e":[target]}),
    )
    .await;
    let beta_count =
        count_payload(&mut beta, "beta-count", json!({"kinds":[7], "#e":[target]})).await;
    assert_eq!(alpha_count["count"], 1);
    assert_eq!(beta_count["count"], 2);
    let alpha_hll = alpha_count["hll"].as_str().expect("alpha hll");
    let beta_hll = beta_count["hll"].as_str().expect("beta hll");
    assert_eq!(alpha_hll.len(), 512);
    assert_eq!(beta_hll.len(), 512);
    assert_ne!(alpha_hll, beta_hll);

    host.shutdown().await;
}

#[tokio::test]
async fn tenant_isolation_group_state_generated_signatures_and_delete_are_local() {
    let host = RunningHost::start("group-state", 600).await;
    let mut alpha = connect_authenticated_socket(
        host.address,
        "alpha.relay.test",
        "wss://alpha.relay.test",
        FixtureKey::Owner,
    )
    .await;
    let mut beta = connect_authenticated_socket(
        host.address,
        "beta.relay.test",
        "wss://beta.relay.test",
        FixtureKey::Owner,
    )
    .await;
    let group_id = "shared-isolation";
    let create =
        tangle_v2_group_create_event(FixtureKey::Owner, group_id, 1_714_200_100, &["public"])
            .expect("create");
    let alpha_metadata = tangle_v2_group_metadata_event(
        FixtureKey::Owner,
        group_id,
        "Alpha Tenant Market",
        1_714_200_101,
        &[],
    )
    .expect("alpha metadata");
    let beta_metadata = tangle_v2_group_metadata_event(
        FixtureKey::Owner,
        group_id,
        "Beta Tenant Market",
        1_714_200_102,
        &[],
    )
    .expect("beta metadata");
    let beta_member = tangle_v2_put_user_event(
        FixtureKey::Owner,
        group_id,
        FixtureKey::Member,
        1_714_200_103,
    )
    .expect("beta member");
    let alpha_normal =
        tangle_v2_group_event(FixtureKey::Owner, group_id, 1_714_200_104, 1, "alpha crop")
            .expect("alpha normal");
    let beta_normal =
        tangle_v2_group_event(FixtureKey::Owner, group_id, 1_714_200_105, 1, "beta crop")
            .expect("beta normal");

    assert_ok_accepted(&mut alpha, &create).await;
    assert_ok_accepted(&mut beta, &create).await;
    assert_ok_accepted(&mut alpha, &alpha_metadata).await;
    assert_ok_accepted(&mut beta, &beta_metadata).await;
    assert_ok_accepted(&mut beta, &beta_member).await;
    assert_ok_accepted(&mut alpha, &alpha_normal).await;
    assert_ok_accepted(&mut beta, &beta_normal).await;

    let alpha_relay_pubkey = relay_pubkey_hex(0x77);
    let beta_relay_pubkey = relay_pubkey_hex(0x88);
    let alpha_generated = collect_req_events(
        &mut alpha,
        "alpha-generated-metadata",
        json!({"kinds":[KIND_GROUP_METADATA], "#d":[group_id]}),
    )
    .await;
    let beta_generated = collect_req_events(
        &mut beta,
        "beta-generated-metadata",
        json!({"kinds":[KIND_GROUP_METADATA], "#d":[group_id]}),
    )
    .await;
    assert_eq!(alpha_generated.len(), 1);
    assert_eq!(beta_generated.len(), 1);
    assert_eq!(
        tag_value(&alpha_generated[0], "name"),
        Some("Alpha Tenant Market")
    );
    assert_eq!(
        tag_value(&beta_generated[0], "name"),
        Some("Beta Tenant Market")
    );
    assert_eq!(
        alpha_generated[0].unsigned().pubkey().as_str(),
        alpha_relay_pubkey
    );
    assert_eq!(
        beta_generated[0].unsigned().pubkey().as_str(),
        beta_relay_pubkey
    );
    assert_pocket_signature(&alpha_generated[0]);
    assert_pocket_signature(&beta_generated[0]);

    let alpha_admins = collect_req_events(
        &mut alpha,
        "alpha-generated-admins",
        json!({"kinds":[KIND_GROUP_ADMINS], "#d":[group_id]}),
    )
    .await;
    let beta_admins = collect_req_events(
        &mut beta,
        "beta-generated-admins",
        json!({"kinds":[KIND_GROUP_ADMINS], "#d":[group_id]}),
    )
    .await;
    assert_eq!(alpha_admins.len(), 1);
    assert_eq!(beta_admins.len(), 1);
    assert_eq!(
        alpha_admins[0].unsigned().pubkey().as_str(),
        alpha_relay_pubkey
    );
    assert_eq!(
        beta_admins[0].unsigned().pubkey().as_str(),
        beta_relay_pubkey
    );

    assert!(
        collect_req_events(
            &mut alpha,
            "alpha-generated-members",
            json!({"kinds":[KIND_GROUP_MEMBERS], "#d":[group_id]}),
        )
        .await
        .is_empty()
    );
    let beta_members = collect_req_events(
        &mut beta,
        "beta-generated-members",
        json!({"kinds":[KIND_GROUP_MEMBERS], "#d":[group_id]}),
    )
    .await;
    assert_eq!(beta_members.len(), 1);
    assert_eq!(
        beta_members[0].unsigned().pubkey().as_str(),
        beta_relay_pubkey
    );

    let alpha_delete =
        tangle_v2_delete_group_event(FixtureKey::Owner, group_id, 1_714_200_106).expect("delete");
    let alpha_future = tangle_v2_group_event(
        FixtureKey::Owner,
        group_id,
        1_714_200_107,
        1,
        "alpha blocked",
    )
    .expect("alpha future");
    let beta_future = tangle_v2_group_event(
        FixtureKey::Owner,
        group_id,
        1_714_200_108,
        1,
        "beta still open",
    )
    .expect("beta future");
    assert_ok_accepted(&mut alpha, &alpha_delete).await;
    let rejected = publish_event(&mut alpha, &alpha_future).await;
    assert_eq!(rejected[0], "OK");
    assert_eq!(rejected[2], false);
    assert_eq!(rejected[3], "blocked: group is deleted");
    assert_ok_accepted(&mut beta, &beta_future).await;

    assert_eq!(
        req_closed_message(
            &mut alpha,
            "alpha-deleted-normal",
            json!({"kinds":[1], "#h":[group_id]}),
        )
        .await,
        "restricted: group is unavailable"
    );
    assert_eq!(
        collect_req_events(
            &mut beta,
            "beta-open-normal",
            json!({"kinds":[1], "#h":[group_id]}),
        )
        .await
        .len(),
        2
    );
    assert_eq!(
        count_payload(
            &mut alpha,
            "alpha-delete-marker",
            json!({"kinds":[KIND_GROUP_DELETE_GROUP], "#h":[group_id]}),
        )
        .await["count"],
        1
    );
    assert_eq!(
        count_payload(
            &mut beta,
            "beta-delete-marker",
            json!({"kinds":[KIND_GROUP_DELETE_GROUP], "#h":[group_id]}),
        )
        .await["count"],
        0
    );

    let metrics = http_get(host.address, "/.well-known/tangle/metrics").await;
    for private_value in [
        group_id,
        alpha_metadata.id().as_str(),
        beta_metadata.id().as_str(),
        alpha_normal.id().as_str(),
        beta_normal.id().as_str(),
        FixtureKey::Owner.public_key().as_str(),
        "alpha crop",
        "beta crop",
        &"77".repeat(32),
        &"88".repeat(32),
    ] {
        assert!(!metrics.contains(private_value));
    }

    host.shutdown().await;
}

#[tokio::test]
async fn tenant_isolation_rate_limits_are_tenant_local() {
    let host = RunningHost::start("rate-limits", 1).await;
    let mut alpha = connect_socket(host.address, "alpha.relay.test").await;
    let mut beta = connect_socket(host.address, "beta.relay.test").await;
    let first = tangle_v2_event(
        FixtureKey::Member,
        1_714_200_200,
        1,
        Vec::new(),
        "alpha first",
    )
    .expect("first");
    let second = tangle_v2_event(
        FixtureKey::Admin,
        1_714_200_201,
        1,
        Vec::new(),
        "alpha second",
    )
    .expect("second");
    let beta_first = tangle_v2_event(
        FixtureKey::Outsider,
        1_714_200_202,
        1,
        Vec::new(),
        "beta first",
    )
    .expect("beta first");

    assert_ok_accepted(&mut alpha, &first).await;
    let rejected = publish_event(&mut alpha, &second).await;
    assert_eq!(rejected[0], "OK");
    assert_eq!(rejected[2], false);
    let message = rejected[3].as_str().expect("message");
    assert!(message.starts_with("rate-limited: "));
    assert!(message.contains("rate limit exceeded until "));
    assert_ok_accepted(&mut beta, &beta_first).await;

    host.shutdown().await;
}

#[test]
fn tenant_isolation_rejects_shared_pocket_store_config() {
    let root = temp_root("shared-store");
    let _ = std::fs::remove_dir_all(&root);
    let host = parse_tangle_host_runtime_config_json(&host_config_value().to_string())
        .expect("host config");
    let alpha = parse_tenant_runtime_config_json(
        &tenant_config_value(
            &root,
            TenantFixture {
                tenant_id: "alpha",
                tenant_schema: "alpha_schema",
                host: "alpha.relay.test",
                relay_url: "wss://alpha.relay.test",
                name: "Alpha Relay",
                relay_secret_byte: 0x77,
                pocket_suffix: "shared",
            },
            600,
        )
        .to_string(),
    )
    .expect("alpha");
    let beta = parse_tenant_runtime_config_json(
        &tenant_config_value(
            &root,
            TenantFixture {
                tenant_id: "beta",
                tenant_schema: "beta_schema",
                host: "beta.relay.test",
                relay_url: "wss://beta.relay.test",
                name: "Beta Relay",
                relay_secret_byte: 0x88,
                pocket_suffix: "shared",
            },
            600,
        )
        .to_string(),
    )
    .expect("beta");
    let error = TangleHostRuntimeConfigSet::new(host, vec![alpha, beta]).expect_err("shared store");

    assert!(
        error
            .message()
            .contains("duplicate tenant pocket data directory")
    );
    let _ = std::fs::remove_dir_all(root);
}

struct RunningHost {
    root: PathBuf,
    address: SocketAddr,
    shutdown_signal: TangleShutdownSignal,
    task: JoinHandle<Result<TangleServeReport, BaseRelayError>>,
}

impl RunningHost {
    async fn start(name: &str, event_per_ip_max_hits: u64) -> Self {
        let root = temp_root(name);
        let _ = std::fs::remove_dir_all(&root);
        let runtime = host_runtime(&root, event_per_ip_max_hits);
        let shutdown_signal = runtime.shutdown_signal().clone();
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
        let address = listener.local_addr().expect("address");
        let task = tokio::spawn(serve_listener_until_shutdown(runtime, listener));
        Self {
            root,
            address,
            shutdown_signal,
            task,
        }
    }

    async fn shutdown(self) {
        self.shutdown_signal.request_shutdown();
        let report = timeout(Duration::from_secs(1), self.task)
            .await
            .expect("server shutdown")
            .expect("task")
            .expect("serve");
        assert_eq!(report.listen_addr(), self.address);
        let _ = std::fs::remove_dir_all(self.root);
    }
}

async fn connect_socket(address: SocketAddr, host: &str) -> TestWebSocket {
    let mut request = format!("ws://{address}/")
        .into_client_request()
        .expect("request");
    request.headers_mut().insert(
        header::SEC_WEBSOCKET_PROTOCOL,
        http::HeaderValue::from_static("nostr"),
    );
    request.headers_mut().insert(
        header::HOST,
        http::HeaderValue::from_str(host).expect("host"),
    );
    let (mut socket, response) = connect_async(request).await.expect("websocket");
    assert_eq!(response.status(), http::StatusCode::SWITCHING_PROTOCOLS);
    let challenge = read_relay_value(&mut socket).await;
    assert_eq!(challenge[0], "AUTH");
    socket
}

async fn connect_authenticated_socket(
    address: SocketAddr,
    host: &str,
    relay_url: &str,
    key: FixtureKey,
) -> TestWebSocket {
    let mut request = format!("ws://{address}/")
        .into_client_request()
        .expect("request");
    request.headers_mut().insert(
        header::SEC_WEBSOCKET_PROTOCOL,
        http::HeaderValue::from_static("nostr"),
    );
    request.headers_mut().insert(
        header::HOST,
        http::HeaderValue::from_str(host).expect("host"),
    );
    let (mut socket, response) = connect_async(request).await.expect("websocket");
    assert_eq!(response.status(), http::StatusCode::SWITCHING_PROTOCOLS);
    let challenge = read_relay_value(&mut socket).await;
    assert_eq!(challenge[0], "AUTH");
    let auth = auth_event_for_relay(
        key,
        challenge[1].as_str().expect("challenge"),
        current_unix_timestamp(),
        relay_url,
    )
    .expect("auth");
    send_client_value(&mut socket, json!(["AUTH", event_to_value(&auth)])).await;
    assert_eq!(
        read_relay_value(&mut socket).await,
        json!(["OK", auth.id().as_str(), true, ""])
    );
    socket
}

async fn assert_ok_accepted(socket: &mut TestWebSocket, event: &Event) {
    assert_eq!(
        publish_event(socket, event).await,
        json!(["OK", event.id().as_str(), true, ""])
    );
}

async fn publish_event(socket: &mut TestWebSocket, event: &Event) -> Value {
    send_client_value(socket, json!(["EVENT", event_to_value(event)])).await;
    read_relay_value(socket).await
}

async fn collect_req_events(
    socket: &mut TestWebSocket,
    subscription_id: &str,
    filter: Value,
) -> Vec<Event> {
    send_client_value(socket, json!(["REQ", subscription_id, filter])).await;
    let mut events = Vec::new();
    loop {
        let message = read_relay_value(socket).await;
        match message[0].as_str().expect("message kind") {
            "EVENT" => {
                assert_eq!(message[1], subscription_id);
                events.push(event_from_value(&message[2]).expect("event"));
            }
            "EOSE" => {
                assert_eq!(message[1], subscription_id);
                send_client_value(socket, json!(["CLOSE", subscription_id])).await;
                break;
            }
            "CLOSED" => panic!("{message}"),
            other => panic!("{other}: {message}"),
        }
    }
    events
}

async fn req_closed_message(
    socket: &mut TestWebSocket,
    subscription_id: &str,
    filter: Value,
) -> String {
    send_client_value(socket, json!(["REQ", subscription_id, filter])).await;
    let message = read_relay_value(socket).await;
    assert_eq!(message[0], "CLOSED");
    assert_eq!(message[1], subscription_id);
    message[2].as_str().expect("closed message").to_owned()
}

async fn count_payload(socket: &mut TestWebSocket, subscription_id: &str, filter: Value) -> Value {
    send_client_value(socket, json!(["COUNT", subscription_id, filter])).await;
    let message = read_relay_value(socket).await;
    assert_eq!(message[0], "COUNT", "{message}");
    assert_eq!(message[1], subscription_id);
    message[2].clone()
}

async fn send_client_value(socket: &mut TestWebSocket, value: Value) {
    socket
        .send(TungsteniteMessage::Text(value.to_string().into()))
        .await
        .expect("send client message");
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

async fn assert_no_relay_message(socket: &mut TestWebSocket) {
    assert!(
        timeout(Duration::from_millis(100), socket.next())
            .await
            .is_err()
    );
}

async fn http_get(address: SocketAddr, path: &str) -> String {
    let path = path.to_owned();
    tokio::task::spawn_blocking(move || -> std::io::Result<String> {
        use std::io::{Read, Write};
        use std::net::TcpStream;

        let mut stream = TcpStream::connect_timeout(&address, Duration::from_millis(500))?;
        stream.set_read_timeout(Some(Duration::from_millis(500)))?;
        stream.set_write_timeout(Some(Duration::from_millis(500)))?;
        let request =
            format!("GET {path} HTTP/1.1\r\nHost: alpha.relay.test\r\nConnection: close\r\n\r\n");
        stream.write_all(request.as_bytes())?;
        let mut response = String::new();
        stream.read_to_string(&mut response)?;
        Ok(response
            .split("\r\n\r\n")
            .nth(1)
            .unwrap_or_default()
            .to_owned())
    })
    .await
    .expect("http task")
    .expect("http get")
}

fn auth_event_for_relay(
    key: FixtureKey,
    challenge: &str,
    created_at: u64,
    relay_url: &str,
) -> Result<Event, String> {
    tangle_v2_event(
        key,
        created_at,
        22_242,
        vec![
            Tag::from_parts("relay", &[relay_url])?,
            Tag::from_parts("challenge", &[challenge])?,
        ],
        "",
    )
}

fn tangle_v2_event(
    key: FixtureKey,
    created_at: u64,
    kind: u64,
    tags: Vec<Tag>,
    content: &str,
) -> Result<Event, String> {
    let event = isolation_pocket_event(key, created_at, kind, tags, content);
    isolation_pocket_event_to_protocol(&event)
}

fn tangle_v2_group_create_event(
    key: FixtureKey,
    group_id: &str,
    created_at: u64,
    flags: &[&str],
) -> Result<Event, String> {
    let mut tags = vec![
        Tag::from_parts("h", &[group_id])?,
        Tag::from_parts("name", &[group_id])?,
    ];
    for flag in flags {
        tags.push(Tag::from_parts(flag, &[])?);
    }
    tangle_v2_event(key, created_at, KIND_GROUP_CREATE_GROUP.into(), tags, "")
}

fn tangle_v2_group_metadata_event(
    key: FixtureKey,
    group_id: &str,
    name: &str,
    created_at: u64,
    flags: &[&str],
) -> Result<Event, String> {
    let mut tags = vec![
        Tag::from_parts("h", &[group_id])?,
        Tag::from_parts("name", &[name])?,
    ];
    for flag in flags {
        tags.push(Tag::from_parts(flag, &[])?);
    }
    tangle_v2_event(key, created_at, KIND_GROUP_EDIT_METADATA.into(), tags, "")
}

fn tangle_v2_put_user_event(
    key: FixtureKey,
    group_id: &str,
    target: FixtureKey,
    created_at: u64,
) -> Result<Event, String> {
    let target = target.public_key();
    tangle_v2_event(
        key,
        created_at,
        KIND_GROUP_PUT_USER.into(),
        vec![
            Tag::from_parts("h", &[group_id])?,
            Tag::from_parts("p", &[target.as_str()])?,
        ],
        "",
    )
}

fn tangle_v2_delete_group_event(
    key: FixtureKey,
    group_id: &str,
    created_at: u64,
) -> Result<Event, String> {
    tangle_v2_group_event(
        key,
        group_id,
        created_at,
        KIND_GROUP_DELETE_GROUP.into(),
        "",
    )
}

fn tangle_v2_group_event(
    key: FixtureKey,
    group_id: &str,
    created_at: u64,
    kind: u64,
    content: &str,
) -> Result<Event, String> {
    tangle_v2_event(
        key,
        created_at,
        kind,
        vec![Tag::from_parts("h", &[group_id])?],
        content,
    )
}

fn isolation_pocket_event(
    key: FixtureKey,
    created_at: u64,
    kind: u64,
    tags: Vec<Tag>,
    content: &str,
) -> PocketOwnedEvent {
    let tags = isolation_pocket_tags_from_protocol(&tags);
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

fn isolation_pocket_tags_from_protocol(tags: &[Tag]) -> PocketOwnedTags {
    let parts = tags
        .iter()
        .map(|tag| tag.values().iter().map(String::as_str).collect::<Vec<_>>())
        .collect::<Vec<_>>();
    PocketOwnedTags::new(&parts).expect("pocket tags")
}

fn isolation_pocket_event_to_protocol(event: &PocketEvent) -> Result<Event, String> {
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

fn host_runtime(root: &Path, event_per_ip_max_hits: u64) -> TangleHostRuntime {
    let host = parse_tangle_host_runtime_config_json(&host_config_value().to_string())
        .expect("host config");
    let tenants = [
        TenantFixture {
            tenant_id: "alpha",
            tenant_schema: "alpha_schema",
            host: "alpha.relay.test",
            relay_url: "wss://alpha.relay.test",
            name: "Alpha Relay",
            relay_secret_byte: 0x77,
            pocket_suffix: "alpha",
        },
        TenantFixture {
            tenant_id: "beta",
            tenant_schema: "beta_schema",
            host: "beta.relay.test",
            relay_url: "wss://beta.relay.test",
            name: "Beta Relay",
            relay_secret_byte: 0x88,
            pocket_suffix: "beta",
        },
    ]
    .into_iter()
    .map(|fixture| {
        parse_tenant_runtime_config_json(
            &tenant_config_value(root, fixture, event_per_ip_max_hits).to_string(),
        )
        .expect("tenant config")
    })
    .collect::<Vec<_>>();
    let config = TangleHostRuntimeConfigSet::new(host, tenants).expect("config set");
    TangleHostRuntime::open(config).expect("host runtime")
}

fn host_config_value() -> Value {
    json!({
        "listen_addr": "127.0.0.1:0",
        "tenant_config_dir": "tenants",
        "limits": {
            "max_total_connections": 64,
            "max_total_subscriptions": 512,
            "tenant_startup_concurrency": 4
        }
    })
}

struct TenantFixture<'a> {
    tenant_id: &'a str,
    tenant_schema: &'a str,
    host: &'a str,
    relay_url: &'a str,
    name: &'a str,
    relay_secret_byte: u8,
    pocket_suffix: &'a str,
}

fn tenant_config_value(
    root: &Path,
    fixture: TenantFixture<'_>,
    event_per_ip_max_hits: u64,
) -> Value {
    let relay_secret = format!("{:02x}", fixture.relay_secret_byte).repeat(32);
    json!({
        "tenant_id": fixture.tenant_id,
        "tenant_schema": fixture.tenant_schema,
        "host": fixture.host,
        "relay_url": fixture.relay_url,
        "info": {
            "name": fixture.name
        },
        "pocket": {
            "data_directory": root.join(fixture.pocket_suffix),
            "sync_policy": "flush_on_shutdown",
        },
        "pocket_query": {
            "allow_scraping": false,
            "allow_scrape_if_limited_to": 100,
            "allow_scrape_if_max_seconds": 3600
        },
        "groups": {
            "enabled": true,
            "canonical_relay_url": fixture.relay_url,
            "relay_secret": relay_secret,
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
            "per_connection_outbound_queue": 16
        },
        "rate_limits": {
            "auth": {
                "per_ip": {"window_seconds": 60, "max_hits": 120},
                "per_pubkey": {"window_seconds": 60, "max_hits": 30},
                "failures": {"window_seconds": 300, "max_hits": 5},
                "failures_per_ip": {"window_seconds": 300, "max_hits": 20}
            },
            "event": {
                "per_ip": {"window_seconds": 60, "max_hits": event_per_ip_max_hits},
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

fn relay_pubkey_hex(secret_byte: u8) -> String {
    RelaySigner::from_secret_hex(&format!("{secret_byte:02x}").repeat(32))
        .expect("relay signer")
        .public_key()
        .as_str()
        .to_owned()
}

fn tag_value<'a>(event: &'a Event, tag_name: &str) -> Option<&'a str> {
    event
        .unsigned()
        .tags()
        .iter()
        .find(|tag| tag.name().as_str() == tag_name)
        .and_then(|tag| tag.values().get(1))
        .map(String::as_str)
}

fn assert_pocket_signature(event: &Event) {
    let raw = serde_json::to_vec(&event_to_value(event)).expect("event json");
    parse_pocket_event_json(&raw)
        .expect("pocket event")
        .verify()
        .expect("pocket signature");
}

fn current_unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time")
        .as_secs()
}

fn temp_root(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "tangle-tenant-isolation-{name}-{}",
        std::process::id()
    ))
}
