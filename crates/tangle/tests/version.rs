#![forbid(unsafe_code)]

use std::{
    fmt::Write as _,
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
        "usage:\n  tangle [--version]\n  tangle run --config PATH\n"
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
        "unknown command: --unknown\nusage:\n  tangle [--version]\n  tangle run --config PATH\n"
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
    let config_path = root.join("runtime.json");
    let listen_addr = reserve_loopback_addr();
    std::fs::write(
        &config_path,
        serde_json::json!({
            "server": {
                "listen_addr": listen_addr.to_string(),
                "relay_url": "wss://relay.radroots.test"
            },
            "pocket": {
                "data_directory": data_dir,
                "map_size_bytes": 10485760,
                "reader_slots": 32,
                "sync_policy": "flush_on_shutdown"
            },
            "groups": {
                "enabled": true,
                "canonical_relay_url": "wss://relay.radroots.test",
                "relay_secret": TANGLE_V2_RELAY_SECRET_HEX,
                "owner_pubkeys": [FixtureKey::Owner.public_key().as_str()],
                "admin_pubkeys": [FixtureKey::Admin.public_key().as_str()],
                "redaction": {
                    "redact_private_tags": true,
                    "redact_invite_codes": true
                },
                "limits": {
                    "max_group_id_bytes": 128,
                    "max_group_tags_per_event": 8,
                    "max_supported_kinds": 512,
                    "max_member_list_pubkeys": 100000,
                    "max_outbox_replay_batch": 1000
                }
            },
            "auth": {
                "challenge_ttl_seconds": 300
            },
            "limits": {
                "max_pending_events": 1024
            }
        })
        .to_string(),
    )
    .expect("write config");

    let mut child = TangleChild::spawn(&config_path);
    let response = wait_for_http_ok(listen_addr, "/healthz");

    assert!(response.contains(r#""status":"ok""#));
    assert!(child.try_wait().expect("child status").is_none());
    assert!(data_dir.exists());

    let output = child.stop().expect("stop child");

    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());

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

fn wait_for_http_ok(address: SocketAddr, path: &str) -> String {
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut last_error = String::new();
    while Instant::now() < deadline {
        match http_get(address, path) {
            Ok(response) if response.starts_with("HTTP/1.1 200 OK") => return response,
            Ok(response) => {
                last_error = response.lines().next().unwrap_or("").to_owned();
            }
            Err(error) => {
                last_error.clear();
                write!(&mut last_error, "{error}").expect("format error");
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("server did not answer {path}: {last_error}");
}

fn http_get(address: SocketAddr, path: &str) -> std::io::Result<String> {
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_millis(200))?;
    stream.set_read_timeout(Some(Duration::from_millis(500)))?;
    stream.set_write_timeout(Some(Duration::from_millis(500)))?;
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n"
    )?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    Ok(response)
}
