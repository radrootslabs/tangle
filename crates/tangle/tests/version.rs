#![forbid(unsafe_code)]

use std::process::Command;
use std::time::{Duration, Instant};
use tangle_protocol::event_to_value;
use tangle_store_surreal::{SurrealConnectionConfig, SurrealStore};
use tangle_test_support::{FixtureKey, build_fixture_event, valid_public_listing_spec};

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
        "usage:\n  tangle [--version]\n  tangle migrate --config PATH\n  tangle run --config PATH\n  tangle event import --config PATH --input PATH\n  tangle event export --config PATH\n  tangle projection rebuild --config PATH\n"
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
        "unknown command: --unknown\nusage:\n  tangle [--version]\n  tangle migrate --config PATH\n  tangle run --config PATH\n  tangle event import --config PATH --input PATH\n  tangle event export --config PATH\n  tangle projection rebuild --config PATH\n"
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

#[tokio::test]
async fn tangle_event_import_command_imports_canonical_jsonl() {
    let listing = build_fixture_event(&valid_public_listing_spec()).expect("listing");
    let root = std::env::temp_dir().join(format!(
        "tangle-cli-import-{}-{}",
        std::process::id(),
        &listing.id().as_str()[..8]
    ));
    let _ = std::fs::remove_dir_all(&root);
    let db_path = root.join("db");
    let config_path = root.join("runtime.json");
    let input_path = root.join("events.jsonl");
    std::fs::create_dir_all(&root).expect("runtime root");
    write_rocksdb_config(&config_path, &db_path, "tangle_cli_import");
    std::fs::write(&input_path, format!("{}\n", event_to_value(&listing)))
        .expect("write import file");

    let first = Command::new(env!("CARGO_BIN_EXE_tangle"))
        .args(["event", "import", "--config"])
        .arg(&config_path)
        .args(["--input"])
        .arg(&input_path)
        .output()
        .expect("run tangle event import");

    assert!(first.status.success());
    assert_eq!(
        String::from_utf8_lossy(&first.stdout),
        "events total: 1\nevents inserted: 1\nevents duplicate: 0\nevents projected: 1\nevents skipped: 0\n"
    );
    assert!(first.stderr.is_empty());

    let second = Command::new(env!("CARGO_BIN_EXE_tangle"))
        .args(["event", "import", "--config"])
        .arg(&config_path)
        .args(["--input"])
        .arg(&input_path)
        .output()
        .expect("rerun tangle event import");

    assert!(second.status.success());
    assert_eq!(
        String::from_utf8_lossy(&second.stdout),
        "events total: 1\nevents inserted: 0\nevents duplicate: 1\nevents projected: 0\nevents skipped: 0\n"
    );
    assert!(second.stderr.is_empty());

    let seller = FixtureKey::Seller.public_key();
    let listing_key = format!("30402:{}:listing-a", seller.as_str());
    let store_config = SurrealConnectionConfig::rocksdb(
        db_path.to_str().expect("db path"),
        "tangle_cli_import",
        "relay",
    )
    .expect("store config");
    let store = reopen_store(&store_config).await;
    assert!(
        store
            .raw_event_row(listing.id())
            .await
            .expect("raw row")
            .is_some()
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
    std::fs::remove_dir_all(&root).expect("remove runtime root");
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
        .args(["event", "export"])
        .output()
        .expect("run tangle event export");

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert_eq!(
        String::from_utf8_lossy(&output.stderr),
        "command not implemented: event export\n"
    );
}

fn write_rocksdb_config(path: &std::path::Path, db_path: &std::path::Path, namespace: &str) {
    let config = serde_json::json!({
        "server": {
            "listen_addr": "127.0.0.1:0",
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
        "policy": {
            "approved_sellers": [FixtureKey::Seller.public_key().as_str()]
        }
    });
    std::fs::write(
        path,
        serde_json::to_string_pretty(&config).expect("config JSON"),
    )
    .expect("write config");
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
