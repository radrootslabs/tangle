use futures_util::{SinkExt, StreamExt};
use serde_json::Value;
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use tangle_protocol::{Event, event_to_value};
use tangle_store_surreal::{SurrealConnectionConfig, SurrealStore};
use tokio_tungstenite::tungstenite::Message;

pub type RelayClient =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

pub struct RelayHarness {
    pub port: u16,
    pub root: PathBuf,
    pub db_path: PathBuf,
    pub namespace: String,
    child: Child,
}

impl RelayHarness {
    pub fn start(namespace: &str, policy: Value) -> Self {
        let port = free_port();
        let root = std::env::temp_dir().join(format!(
            "tangle-conformance-{namespace}-{}-{port}",
            std::process::id()
        ));
        let db_path = root.join("surrealdb");
        let config_path = root.join("runtime.json");
        fs::create_dir_all(&root).expect("runtime root");
        write_runtime_config(&config_path, &db_path, port, namespace, policy);
        let mut child = Command::new(env!("CARGO_BIN_EXE_tangle"))
            .args(["run", "--config"])
            .arg(&config_path)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn tangle run");
        wait_for_http(port, &mut child);
        Self {
            port,
            root,
            db_path,
            namespace: namespace.to_owned(),
            child,
        }
    }

    pub fn store_config(&self) -> SurrealConnectionConfig {
        SurrealConnectionConfig::rocksdb(
            self.db_path.to_str().expect("db path"),
            &self.namespace,
            "relay",
        )
        .expect("store config")
    }

    pub fn stop(self) {
        stop_relay(self.child);
    }
}

pub async fn connect_client(port: u16) -> RelayClient {
    let (mut client, _) = tokio_tungstenite::connect_async(format!("ws://127.0.0.1:{port}/ws"))
        .await
        .expect("client connect");
    assert_eq!(next_label(&mut client).await, "AUTH");
    client
}

pub async fn send_event(client: &mut RelayClient, event: &Event) -> Value {
    client
        .send(Message::Text(
            serde_json::json!(["EVENT", event_to_value(event)])
                .to_string()
                .into(),
        ))
        .await
        .expect("event send");
    next_json(client).await
}

pub async fn send_auth(client: &mut RelayClient, event: &Event) -> Value {
    client
        .send(Message::Text(
            serde_json::json!(["AUTH", event_to_value(event)])
                .to_string()
                .into(),
        ))
        .await
        .expect("auth send");
    next_json(client).await
}

pub async fn request_event_by_id(
    client: &mut RelayClient,
    subscription: &str,
    event: &Event,
) -> Value {
    client
        .send(Message::Text(
            serde_json::json!(["REQ", subscription, { "ids": [event.id().as_str()] }])
                .to_string()
                .into(),
        ))
        .await
        .expect("req send");
    next_json(client).await
}

pub async fn close_subscription(client: &mut RelayClient, subscription: &str) {
    client
        .send(Message::Text(
            serde_json::json!(["CLOSE", subscription])
                .to_string()
                .into(),
        ))
        .await
        .expect("close send");
}

pub async fn send_text(client: &mut RelayClient, text: &str) -> Value {
    client
        .send(Message::Text(text.to_owned().into()))
        .await
        .expect("text send");
    next_json(client).await
}

pub async fn next_json(client: &mut RelayClient) -> Value {
    let message = client
        .next()
        .await
        .expect("websocket message")
        .expect("websocket frame");
    let text = message.into_text().expect("text frame");
    serde_json::from_str(&text).expect("relay JSON")
}

pub async fn next_label(client: &mut RelayClient) -> String {
    next_json(client).await[0]
        .as_str()
        .expect("label")
        .to_owned()
}

pub fn assert_ok(message: &Value, accepted: bool) {
    assert_eq!(message[0], "OK");
    assert_eq!(message[2], accepted, "relay OK frame: {message}");
}

pub fn http_get(port: u16, path: &str) -> String {
    try_http_get(port, path).expect("http get")
}

pub async fn reopen_store(config: &SurrealConnectionConfig) -> SurrealStore {
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

fn write_runtime_config(path: &Path, db_path: &Path, port: u16, namespace: &str, policy: Value) {
    let config = serde_json::json!({
        "server": {
            "listen_addr": format!("127.0.0.1:{port}"),
            "relay_url": "wss://relay.radroots.test"
        },
        "database": {
            "mode": "rocks_db",
            "path": db_path.to_str().expect("db path"),
            "namespace": namespace,
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
        "policy": policy
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

fn stop_relay(relay: Child) {
    let _ = stop_relay_with_stderr(relay);
}

fn stop_relay_with_stderr(mut relay: Child) -> String {
    stop_child(&mut relay);
    let output = relay.wait_with_output().expect("relay exit");
    assert!(output.status.success());
    String::from_utf8_lossy(&output.stderr).to_string()
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
