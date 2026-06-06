#![forbid(unsafe_code)]

use futures_util::{SinkExt, StreamExt};
use serde_json::Value;
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use tangle_protocol::event_to_value;
use tangle_store_surreal::{SurrealConnectionConfig, SurrealStore};
use tangle_test_support::{
    FixtureKey, auth_event_spec, build_fixture_event, valid_public_listing_spec,
};
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;

#[tokio::test]
async fn tangle_run_serves_relay_clients_and_persists_surreal_state() {
    let port = free_port();
    let root = std::env::temp_dir().join(format!(
        "tangle-run-integration-{}-{port}",
        std::process::id()
    ));
    let db_path = root.join("surrealdb");
    let config_path = root.join("runtime.json");
    fs::create_dir_all(&root).expect("runtime root");
    write_runtime_config(&config_path, &db_path, port);

    let mut relay = Command::new(env!("CARGO_BIN_EXE_tangle"))
        .args(["run", "--config"])
        .arg(&config_path)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn tangle run");

    wait_for_http(port, &mut relay);
    let nip11 = http_get(port, "/");
    assert!(nip11.contains("200 OK"));
    assert!(nip11.contains("application/nostr+json"));
    assert!(nip11.contains("\"supported_nips\""));

    let listing = build_fixture_event(&valid_public_listing_spec()).expect("listing");
    let auth = build_fixture_event(&auth_event_spec()).expect("auth");
    let seller = FixtureKey::Seller.public_key();

    let (mut subscriber, _) = connect_async(format!("ws://127.0.0.1:{port}/ws"))
        .await
        .expect("subscriber connect");
    assert_eq!(next_label(&mut subscriber).await, "AUTH");
    subscriber
        .send(Message::Text(
            serde_json::json!([
                "REQ",
                "sub-live",
                {
                    "kinds": [30402],
                    "authors": [seller.as_str()]
                }
            ])
            .to_string()
            .into(),
        ))
        .await
        .expect("subscribe");
    assert_eq!(next_label(&mut subscriber).await, "EOSE");

    let (mut unauthenticated, _) = connect_async(format!("ws://127.0.0.1:{port}/ws"))
        .await
        .expect("unauthenticated connect");
    assert_eq!(next_label(&mut unauthenticated).await, "AUTH");
    unauthenticated
        .send(Message::Text(
            serde_json::json!(["EVENT", event_to_value(&listing)])
                .to_string()
                .into(),
        ))
        .await
        .expect("unauthenticated event send");
    let unauthenticated_rejection = next_json(&mut unauthenticated).await;
    assert_ok(&unauthenticated_rejection, false);
    assert!(
        unauthenticated_rejection[3]
            .as_str()
            .expect("rejection message")
            .contains("write authentication required")
    );

    let (mut publisher, _) = connect_async(format!("ws://127.0.0.1:{port}/ws"))
        .await
        .expect("publisher connect");
    assert_eq!(next_label(&mut publisher).await, "AUTH");
    publisher
        .send(Message::Text(
            serde_json::json!(["AUTH", event_to_value(&auth)])
                .to_string()
                .into(),
        ))
        .await
        .expect("auth send");
    assert_ok(&next_json(&mut publisher).await, true);

    publisher
        .send(Message::Text(
            serde_json::json!(["EVENT", event_to_value(&listing)])
                .to_string()
                .into(),
        ))
        .await
        .expect("event send");
    assert_ok(&next_json(&mut publisher).await, true);
    let live = next_json(&mut subscriber).await;
    assert_eq!(live[0], "EVENT");
    assert_eq!(live[1], "sub-live");
    assert_eq!(live[2]["id"], listing.id().as_str());

    publisher
        .send(Message::Text(
            serde_json::json!(["REQ", "sub-fetch", { "ids": [listing.id().as_str()] }])
                .to_string()
                .into(),
        ))
        .await
        .expect("fetch send");
    let fetched = next_json(&mut publisher).await;
    assert_eq!(fetched[0], "EVENT");
    assert_eq!(fetched[1], "sub-fetch");
    assert_eq!(fetched[2]["id"], listing.id().as_str());
    assert_eq!(next_label(&mut publisher).await, "EOSE");

    subscriber
        .send(Message::Text(
            serde_json::json!(["CLOSE", "sub-live"]).to_string().into(),
        ))
        .await
        .expect("close send");

    let listings = http_get(port, "/api/listings?limit=5");
    assert!(listings.contains("200 OK"));
    assert!(listings.contains("Carrot bunches"));
    assert!(listings.contains(listing.id().as_str()));
    let detail = http_get(
        port,
        &format!("/api/listings/{}/listing-a", seller.as_str()),
    );
    assert!(detail.contains("200 OK"));
    assert!(detail.contains("listing-a"));
    assert!(detail.contains("Carrot bunches"));
    let search = http_get(port, "/api/search?q=carrots&limit=5");
    assert!(search.contains("200 OK"));
    assert!(search.contains(listing.id().as_str()));
    let seller_detail = http_get(port, &format!("/api/sellers/{}", seller.as_str()));
    assert!(seller_detail.contains("200 OK"));
    assert!(seller_detail.contains(seller.as_str()));

    stop_relay(relay);

    let store_config =
        SurrealConnectionConfig::rocksdb(db_path.to_str().expect("db path"), "tangle_it", "relay")
            .expect("store config");
    let store = reopen_store(&store_config).await;
    let listing_key = format!("30402:{}:listing-a", seller.as_str());
    assert!(
        store
            .raw_event_row(listing.id())
            .await
            .expect("raw row")
            .is_some()
    );
    assert!(
        store
            .raw_event_row(auth.id())
            .await
            .expect("auth raw row")
            .is_none()
    );
    assert!(
        store
            .listing_current_row(&listing_key)
            .await
            .expect("listing row")
            .is_some()
    );
    assert!(
        store
            .search_document_row(&listing_key)
            .await
            .expect("search row")
            .is_some()
    );

    drop(store);
    fs::remove_dir_all(&root).expect("remove runtime root");
}

fn write_runtime_config(path: &Path, db_path: &Path, port: u16) {
    let config = serde_json::json!({
        "server": {
            "listen_addr": format!("127.0.0.1:{port}"),
            "relay_url": "wss://relay.radroots.test"
        },
        "database": {
            "mode": "rocks_db",
            "path": db_path.to_str().expect("db path"),
            "namespace": "tangle_it",
            "database": "relay"
        },
        "auth": {
            "challenge_ttl_seconds": 300
        },
        "limits": {
            "message_rate_limit": {
                "limit": 120,
                "window_seconds": 60
            }
        },
        "policy": {
            "approved_sellers": [FixtureKey::Seller.public_key().as_str()]
        }
    });
    fs::write(
        path,
        serde_json::to_string_pretty(&config).expect("config JSON"),
    )
    .expect("write config");
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind port")
        .local_addr()
        .expect("local addr")
        .port()
}

fn wait_for_http(port: u16, child: &mut Child) {
    let started = Instant::now();
    loop {
        if let Ok(response) = try_http_get(port, "/healthz")
            && response.contains("200 OK")
        {
            return;
        }
        if let Some(status) = child.try_wait().expect("child status") {
            panic!("relay exited before readiness: {status}");
        }
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "relay did not open port {port}"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn http_get(port: u16, path: &str) -> String {
    try_http_get(port, path).expect("http get")
}

fn try_http_get(port: u16, path: &str) -> Result<String, std::io::Error> {
    let mut stream = TcpStream::connect(("127.0.0.1", port))?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nAccept: application/nostr+json\r\nConnection: close\r\n\r\n"
    )?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    Ok(response)
}

async fn reopen_store(config: &SurrealConnectionConfig) -> SurrealStore {
    let started = Instant::now();
    loop {
        match SurrealStore::connect_local(config).await {
            Ok(store) => return store,
            Err(error) if started.elapsed() < Duration::from_secs(5) => {
                let _ = error;
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Err(error) => panic!("store reopen failed: {error}"),
        }
    }
}

async fn next_json(
    socket: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
) -> Value {
    let message = socket
        .next()
        .await
        .expect("websocket message")
        .expect("websocket frame");
    let text = message.into_text().expect("text frame");
    serde_json::from_str(&text).expect("relay JSON")
}

async fn next_label(
    socket: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
) -> String {
    next_json(socket).await[0]
        .as_str()
        .expect("label")
        .to_owned()
}

fn assert_ok(message: &Value, accepted: bool) {
    assert_eq!(message[0], "OK");
    assert_eq!(message[2], accepted);
}

fn stop_relay(mut relay: Child) {
    stop_child(&mut relay);
    let status = relay.wait().expect("relay exit");
    assert!(status.success());
}

#[cfg(unix)]
fn stop_child(relay: &mut Child) {
    let status = Command::new("kill")
        .args(["-INT", &relay.id().to_string()])
        .status()
        .expect("send interrupt");
    assert!(status.success());
}

#[cfg(not(unix))]
fn stop_child(relay: &mut Child) {
    relay.kill().expect("kill relay");
}
