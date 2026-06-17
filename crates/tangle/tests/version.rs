#![forbid(unsafe_code)]

use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    process::{Child, Command, Output, Stdio},
    time::{Duration, Instant},
};
use tangle_test_support::{FixtureKey, TANGLE_V2_RELAY_SECRET_HEX};

#[test]
fn tangle_version_command_reports_package_version() {
    let output = Command::new(env!("CARGO_BIN_EXE_tangle"))
        .arg("--version")
        .output()
        .expect("run tangle --version");

    assert!(output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout), "tangle 0.1.0\n");
    assert!(output.stderr.is_empty());
}

#[test]
fn tangle_without_args_reports_usage() {
    let output = Command::new(env!("CARGO_BIN_EXE_tangle"))
        .output()
        .expect("run tangle without args");

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "usage:\n  tangle [--version]\n  tangle run --config PATH\n  tangle config validate --config PATH\n  tangle config inspect --config PATH --redacted\n  tangle tenant list --config PATH\n"
    );
    assert!(output.stderr.is_empty());
}

#[test]
fn tangle_unknown_arg_reports_usage_error() {
    let output = Command::new(env!("CARGO_BIN_EXE_tangle"))
        .arg("--unknown")
        .output()
        .expect("run tangle unknown arg");

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert_eq!(
        String::from_utf8_lossy(&output.stderr),
        "unknown command: --unknown\nusage:\n  tangle [--version]\n  tangle run --config PATH\n  tangle config validate --config PATH\n  tangle config inspect --config PATH --redacted\n  tangle tenant list --config PATH\n"
    );
}

#[test]
fn tangle_removed_commands_are_not_accepted() {
    for args in [
        vec!["migrate"],
        vec!["event", "import"],
        vec!["event", "export"],
        vec!["projection", "rebuild"],
        vec!["ops", "backup"],
        vec!["ops", "restore"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_tangle"))
            .args(args)
            .output()
            .expect("run tangle removed command");

        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        assert!(String::from_utf8_lossy(&output.stderr).contains("unknown command"));
    }
}

#[test]
fn tangle_run_reports_missing_config() {
    let output = Command::new(env!("CARGO_BIN_EXE_tangle"))
        .args(["run"])
        .output()
        .expect("run tangle without config");

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert_eq!(
        String::from_utf8_lossy(&output.stderr),
        "--config requires a value\n"
    );
}

#[test]
fn tangle_run_starts_server_and_stays_alive_until_shutdown() {
    let root = std::env::temp_dir().join(format!("tangle-cli-run-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).expect("runtime root");
    let data_dir = root.join("pocket");
    let tenant_dir = root.join("tenants");
    std::fs::create_dir_all(&tenant_dir).expect("tenant dir");
    let config_path = root.join("host.json");
    let tenant_config_path = tenant_dir.join("farmers_market.json");
    let listen_addr = reserve_loopback_addr();
    std::fs::write(
        &config_path,
        serde_json::json!({
            "listen_addr": listen_addr.to_string(),
            "tenant_config_dir": "tenants",
            "limits": {
                "max_total_connections": 10000,
                "max_total_subscriptions": 25000,
                "tenant_startup_concurrency": 4
            }
        })
        .to_string(),
    )
    .expect("write host config");
    std::fs::write(
        &tenant_config_path,
        serde_json::json!({
            "tenant_id": "farmers-market",
            "tenant_schema": "farmers_market",
            "host": "relay.radroots.test",
            "relay_url": "wss://relay.radroots.test",
            "inactive": false,
            "info": {
                "name": "Radroots Farmers Market"
            },
            "pocket": {
                "data_directory": data_dir,
                "sync_policy": "flush_on_shutdown"
            },
            "pocket_query": {
              "allow_scraping": false,
              "allow_scrape_if_limited_to": 100,
              "allow_scrape_if_max_seconds": 3600
            },
            "groups": {
                "enabled": true,
                "canonical_relay_url": "wss://relay.radroots.test",
                "relay_secret": TANGLE_V2_RELAY_SECRET_HEX,
                "owner_pubkeys": [FixtureKey::Owner.public_key().as_str()],
                "admin_pubkeys": [FixtureKey::Admin.public_key().as_str()],
                "limits": {
                    "max_group_id_bytes": 128,
                    "max_group_tags_per_event": 8,
                    "max_supported_kinds": 512,
                    "max_member_list_pubkeys": 100000,
                    "max_outbox_replay_batch": 1000
                }
            },
            "backup_export": {
                "backup_enabled": true,
                "export_enabled": true
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
                "broadcast_channel_capacity": 4096,
                "per_connection_outbound_queue": 256
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
        .to_string(),
    )
    .expect("write config");

    let mut child = TangleChild::spawn(&config_path);
    let ready = wait_for_http_ok(listen_addr, "/.well-known/tangle/ready", None);
    let metrics = wait_for_http_ok(listen_addr, "/.well-known/tangle/metrics", None);
    let tenants = wait_for_http_ok(listen_addr, "/.well-known/tangle/tenants", None);
    let nip11 = wait_for_http_ok(listen_addr, "/", Some("application/nostr+json"));
    let ready_value =
        serde_json::from_str::<serde_json::Value>(response_body(&ready)).expect("ready json");
    let metrics_value =
        serde_json::from_str::<serde_json::Value>(response_body(&metrics)).expect("metrics json");
    let tenants_value =
        serde_json::from_str::<serde_json::Value>(response_body(&tenants)).expect("tenants json");
    let nip11_value =
        serde_json::from_str::<serde_json::Value>(response_body(&nip11)).expect("nip11 json");

    assert_eq!(ready_value["status"], "ready");
    assert_eq!(ready_value["checks"]["active_tenants"], "ready");
    assert_eq!(metrics_value["tangle_host_configured_tenants"], 1);
    assert_eq!(metrics_value["tangle_host_active_tenants"], 1);
    assert_eq!(tenants_value["tenants"][0]["tenant_id"], "farmers-market");
    assert_eq!(tenants_value["tenants"][0]["ready"], true);
    assert_eq!(nip11_value["name"], "Radroots Farmers Market");
    assert_eq!(nip11_value["limitation"]["max_message_length"], 1_048_576);
    assert_eq!(nip11_value["limitation"]["max_subscriptions"], 64);
    assert_eq!(nip11_value["limitation"]["max_filters"], 10);
    assert_eq!(nip11_value["limitation"]["max_limit"], 500);
    assert_eq!(nip11_value["limitation"]["max_query_complexity"], 2_048);
    assert_eq!(nip11_value["limitation"]["max_subid_length"], 64);
    assert_eq!(nip11_value["limitation"]["max_event_tags"], 200);
    assert_eq!(nip11_value["limitation"]["max_content_length"], 65_536);
    assert_eq!(nip11_value["limitation"]["auth_required"], false);
    assert_eq!(nip11_value["limitation"]["payment_required"], false);
    assert_eq!(nip11_value["limitation"]["restricted_writes"], true);
    assert_eq!(nip11_value["limitation"]["default_limit"], 100);
    assert_eq!(nip11_value["retention"]["physical_erasure"], false);
    assert_eq!(nip11_value["retention"]["compaction_guarantee"], false);
    assert!(
        nip11_value["supported_nips"]
            .as_array()
            .expect("supported nips")
            .contains(&serde_json::json!(29))
    );
    assert!(child.try_wait().expect("child status").is_none());
    assert!(data_dir.exists());

    let output = child.stop().expect("stop child");

    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    assert!(stderr.contains(r#""event":"runtime_config_loaded""#));
    assert!(stderr.contains(r#""relay_secret":"<redacted>""#));
    assert!(!stderr.contains(TANGLE_V2_RELAY_SECRET_HEX));

    std::fs::remove_dir_all(&root).expect("remove runtime root");
}

struct TangleChild {
    child: Option<Child>,
}

impl TangleChild {
    fn spawn(config_path: &std::path::Path) -> Self {
        let child = Command::new(env!("CARGO_BIN_EXE_tangle"))
            .args(["run", "--config"])
            .arg(config_path)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn tangle");
        Self { child: Some(child) }
    }

    fn try_wait(&mut self) -> std::io::Result<Option<std::process::ExitStatus>> {
        self.child.as_mut().expect("child").try_wait()
    }

    fn stop(mut self) -> std::io::Result<Output> {
        let mut child = self.child.take().expect("child");
        let kill_error = child.kill().err();
        let output = child.wait_with_output();
        if let Some(error) = kill_error
            && error.kind() != std::io::ErrorKind::InvalidInput
        {
            return Err(error);
        }
        output
    }
}

impl Drop for TangleChild {
    fn drop(&mut self) {
        if let Some(child) = &mut self.child {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn reserve_loopback_addr() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("reserve loopback address");
    listener.local_addr().expect("loopback address")
}

fn wait_for_http_ok(address: SocketAddr, path: &str, accept: Option<&str>) -> String {
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut last_error = String::new();
    while Instant::now() < deadline {
        match http_get(address, path, accept) {
            Ok(response) if response.starts_with("HTTP/1.1 200 OK") => return response,
            Ok(response) => {
                last_error = response.lines().next().unwrap_or("").to_owned();
            }
            Err(error) => {
                last_error = error.to_string();
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("server did not answer {path}: {last_error}");
}

fn http_get(address: SocketAddr, path: &str, accept: Option<&str>) -> std::io::Result<String> {
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_millis(200))?;
    stream.set_read_timeout(Some(Duration::from_millis(500)))?;
    stream.set_write_timeout(Some(Duration::from_millis(500)))?;
    let mut request = format!("GET {path} HTTP/1.1\r\nHost: relay.radroots.test\r\n");
    if let Some(accept) = accept {
        request.push_str("Accept: ");
        request.push_str(accept);
        request.push_str("\r\n");
    }
    request.push_str("Connection: close\r\n\r\n");
    stream.write_all(request.as_bytes())?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    Ok(response)
}

fn response_body(response: &str) -> &str {
    response.split_once("\r\n\r\n").expect("response body").1
}
