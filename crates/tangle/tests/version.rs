#![forbid(unsafe_code)]

use std::process::Command;

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
        "usage: tangle [--version] <command> [--config PATH]\n\ncommands:\n  migrate\n  run\n  event import\n  event export\n  projection rebuild\n"
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
        "unknown command: --unknown\nusage: tangle [--version] <command> [--config PATH]\n\ncommands:\n  migrate\n  run\n  event import\n  event export\n  projection rebuild\n"
    );
}

#[test]
fn tangle_migrate_command_applies_configured_migrations() {
    let path = std::env::temp_dir().join(format!("tangle-cli-migrate-{}.json", std::process::id()));
    std::fs::write(
        &path,
        r#"{
            "server": {
                "listen_addr": "127.0.0.1:7400",
                "relay_url": "ws://127.0.0.1:7400"
            },
            "database": {
                "mode": "memory",
                "namespace": "tangle_cli_migrate",
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
            }
        }"#,
    )
    .expect("write config");

    let output = Command::new(env!("CARGO_BIN_EXE_tangle"))
        .args(["migrate", "--config"])
        .arg(&path)
        .output()
        .expect("run tangle migrate");
    std::fs::remove_file(&path).expect("remove config");

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "migrations applied: 10\nmigrations already applied: 0\nmigrations total: 10\n"
    );
    assert!(output.stderr.is_empty());
}

#[test]
fn tangle_migrate_requires_config_path() {
    let output = Command::new(env!("CARGO_BIN_EXE_tangle"))
        .arg("migrate")
        .output()
        .expect("run tangle migrate without config");

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert_eq!(
        String::from_utf8_lossy(&output.stderr),
        "--config requires a value\n"
    );
}

#[test]
fn tangle_known_future_commands_report_not_implemented() {
    let output = Command::new(env!("CARGO_BIN_EXE_tangle"))
        .args(["event", "import"])
        .output()
        .expect("run tangle event import");

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert_eq!(
        String::from_utf8_lossy(&output.stderr),
        "command not implemented: event import\n"
    );
}
