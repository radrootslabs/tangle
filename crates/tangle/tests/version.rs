#![forbid(unsafe_code)]

use std::process::Command;
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
fn tangle_run_smoke_opens_v2_config() {
    let root = std::env::temp_dir().join(format!("tangle-cli-run-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).expect("runtime root");
    let data_dir = root.join("pocket");
    let config_path = root.join("runtime.json");
    std::fs::write(
        &config_path,
        serde_json::json!({
            "server": {
                "listen_addr": "127.0.0.1:0",
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

    let output = Command::new(env!("CARGO_BIN_EXE_tangle"))
        .args(["run", "--config"])
        .arg(&config_path)
        .output()
        .expect("run tangle");

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        format!(
            "relay url: wss://relay.radroots.test\npocket data directory: {}\ngroups enabled: true\nreadiness: ready\n",
            data_dir.display()
        )
    );
    assert!(output.stderr.is_empty());

    std::fs::remove_dir_all(&root).expect("remove runtime root");
}
