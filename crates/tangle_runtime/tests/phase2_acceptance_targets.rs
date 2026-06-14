#![forbid(unsafe_code)]

use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use tangle_runtime::{
    config::{BaseRelayRuntimeConfig, parse_base_relay_runtime_config_json},
    runtime::TangleRuntime,
    server::serve_listener_until_shutdown,
};
use tangle_test_support::{FixtureKey, TANGLE_V2_RELAY_SECRET_HEX};
use tokio::{net::TcpListener, time::timeout};

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

#[test]
#[ignore = "phase2 target: websocket protocol runtime"]
fn websocket_clients_use_nip01_nip42_and_nip45_flows() {
    pending("real websocket sessions must handle EVENT REQ COUNT CLOSE and AUTH");
}

#[test]
#[ignore = "phase2 target: nip11 truthfulness"]
fn nip11_includes_cors_headers_and_truthful_supported_nips() {
    pending("NIP-11 must include CORS headers and advertise only enforced NIPs");
}

#[test]
#[ignore = "phase2 target: auth skew"]
fn auth_rejects_events_outside_created_at_skew() {
    pending("AUTH must validate created_at against configured skew");
}

#[test]
#[ignore = "phase2 target: nip70 enforcement"]
fn protected_events_require_author_auth_before_nip70_is_advertised() {
    pending("events with a dash tag require AUTH as event author before NIP-70 advertisement");
}

#[test]
#[ignore = "phase2 target: private hidden semantics"]
fn private_but_not_hidden_group_metadata_remains_visible() {
    pending("private-but-not-hidden group metadata and admins must remain visible to non-members");
}

#[test]
#[ignore = "phase2 target: public join policy"]
fn public_join_defaults_false() {
    pending(
        "group join requests must be denied by default unless public join or invite flow allows them",
    );
}

#[test]
#[ignore = "phase2 target: duplicate membership prefixes"]
fn duplicate_join_and_leave_use_duplicate_prefix() {
    pending("duplicate join and leave responses must use the duplicate prefix");
}

#[test]
#[ignore = "phase2 target: central read gate"]
fn req_count_and_live_fanout_share_one_group_read_gate() {
    pending("REQ COUNT and live fanout must use one central group read gate");
}

#[test]
#[ignore = "phase2 target: hot path representation"]
fn runtime_hot_path_does_not_stringify_and_reparse_events() {
    pending("runtime hot paths must use Pocket event and filter types or EventView");
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
            "challenge_ttl_seconds": 300
        },
        "limits": {
            "max_pending_events": 8
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
