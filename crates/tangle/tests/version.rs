#![forbid(unsafe_code)]

use std::process::Command;
use std::time::{Duration, Instant};
use tangle_protocol::event_to_value;
use tangle_store_surreal::{SurrealConnectionConfig, SurrealStore, base_migration_plan};
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
        "usage:\n  tangle [--version]\n  tangle migrate --config PATH\n  tangle run --config PATH\n  tangle event import --config PATH --input PATH\n  tangle event export --config PATH --output PATH\n  tangle projection rebuild --config PATH\n  tangle ops backup --config PATH --output DIR\n  tangle ops restore --config PATH --input DIR\n"
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
        "unknown command: --unknown\nusage:\n  tangle [--version]\n  tangle migrate --config PATH\n  tangle run --config PATH\n  tangle event import --config PATH --input PATH\n  tangle event export --config PATH --output PATH\n  tangle projection rebuild --config PATH\n  tangle ops backup --config PATH --output DIR\n  tangle ops restore --config PATH --input DIR\n"
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
    let migration_count = base_migration_plan().migrations().len();
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        format!(
            "migrations applied: {migration_count}\nmigrations already applied: 0\nmigrations total: {migration_count}\n"
        )
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
    let output_path = root.join("exported.jsonl");
    let backup_path = root.join("backup");
    let restore_db_path = root.join("restore-db");
    let restore_config_path = root.join("restore-runtime.json");
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

    let export = Command::new(env!("CARGO_BIN_EXE_tangle"))
        .args(["event", "export", "--config"])
        .arg(&config_path)
        .args(["--output"])
        .arg(&output_path)
        .output()
        .expect("run tangle event export");

    assert!(export.status.success());
    assert_eq!(
        String::from_utf8_lossy(&export.stdout),
        "events exported: 1\n"
    );
    assert!(export.stderr.is_empty());
    assert_eq!(
        std::fs::read_to_string(&output_path).expect("export file"),
        format!("{}\n", event_to_value(&listing))
    );

    let backup = Command::new(env!("CARGO_BIN_EXE_tangle"))
        .args(["ops", "backup", "--config"])
        .arg(&config_path)
        .args(["--output"])
        .arg(&backup_path)
        .output()
        .expect("run tangle ops backup");

    assert!(backup.status.success());
    assert!(backup.stderr.is_empty());
    let backup_stdout = String::from_utf8_lossy(&backup.stdout);
    assert!(backup_stdout.starts_with(&format!(
        "backup directory: {}\nraw events: 1\nraw events sha256: ",
        backup_path.display()
    )));
    assert!(backup_stdout.contains(&format!(
        "\nsurrealdb export available: false\nmanifest: {}\nmanifest sha256: ",
        backup_path.join("manifest.json").display()
    )));
    assert_eq!(
        std::fs::read_to_string(backup_path.join("raw-events.jsonl")).expect("backup raw events"),
        format!("{}\n", event_to_value(&listing))
    );
    let manifest: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(backup_path.join("manifest.json")).expect("backup manifest"),
    )
    .expect("manifest JSON");
    assert_eq!(manifest["format"], "tangle-backup-v1");
    assert_eq!(manifest["database"]["namespace"], "tangle_cli_import");
    assert_eq!(manifest["database"]["database"], "relay");
    assert_eq!(manifest["raw_events"]["path"], "raw-events.jsonl");
    assert_eq!(manifest["raw_events"]["count"], 1);
    assert_eq!(
        manifest["raw_events"]["sha256"]
            .as_str()
            .expect("raw sha")
            .len(),
        64
    );
    assert_eq!(manifest["surrealdb_export"]["available"], false);
    assert!(manifest["surrealdb_export"]["path"].is_null());
    assert!(manifest["surrealdb_export"]["sha256"].is_null());

    write_rocksdb_config(&restore_config_path, &restore_db_path, "tangle_cli_restore");
    let restore = Command::new(env!("CARGO_BIN_EXE_tangle"))
        .args(["ops", "restore", "--config"])
        .arg(&restore_config_path)
        .args(["--input"])
        .arg(&backup_path)
        .output()
        .expect("run tangle ops restore");

    assert!(restore.status.success());
    assert!(restore.stderr.is_empty());
    let restore_stdout = String::from_utf8_lossy(&restore.stdout);
    assert!(restore_stdout.starts_with(&format!(
        "restore directory: {}\nraw events: 1\nraw events sha256: ",
        backup_path.display()
    )));
    assert!(restore_stdout.contains(
        "\nevents inserted: 1\nevents duplicate: 0\nevents rebuilt: 1\nlistings projected: 1\nevents skipped: 0\n"
    ));

    let rebuild = Command::new(env!("CARGO_BIN_EXE_tangle"))
        .args(["projection", "rebuild", "--config"])
        .arg(&config_path)
        .output()
        .expect("run tangle projection rebuild");

    assert!(rebuild.status.success());
    assert_eq!(
        String::from_utf8_lossy(&rebuild.stdout),
        "events scanned: 1\nevents rebuilt: 1\nlistings projected: 1\nevents skipped: 0\n"
    );
    assert!(rebuild.stderr.is_empty());

    let second_rebuild = Command::new(env!("CARGO_BIN_EXE_tangle"))
        .args(["projection", "rebuild", "--config"])
        .arg(&config_path)
        .output()
        .expect("rerun tangle projection rebuild");

    assert!(second_rebuild.status.success());
    assert_eq!(
        String::from_utf8_lossy(&second_rebuild.stdout),
        "events scanned: 1\nevents rebuilt: 1\nlistings projected: 1\nevents skipped: 0\n"
    );
    assert!(second_rebuild.stderr.is_empty());

    let seller = FixtureKey::Seller.public_key();
    let listing_key = format!("30402:{}:listing-a", seller.as_str());
    let restore_store_config = SurrealConnectionConfig::rocksdb(
        restore_db_path.to_str().expect("restore db path"),
        "tangle_cli_restore",
        "relay",
    )
    .expect("restore store config");
    let restore_store = reopen_store(&restore_store_config).await;
    assert!(
        restore_store
            .raw_event_row(listing.id())
            .await
            .expect("restore raw row")
            .is_some()
    );
    assert!(
        restore_store
            .listing_current_row(&listing_key)
            .await
            .expect("restore listing row")
            .is_some()
    );
    assert!(
        restore_store
            .search_document_row(&listing_key)
            .await
            .expect("restore search row")
            .is_some()
    );
    drop(restore_store);

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
fn tangle_projection_rebuild_requires_config_path() {
    let output = Command::new(env!("CARGO_BIN_EXE_tangle"))
        .args(["projection", "rebuild"])
        .output()
        .expect("run tangle projection rebuild without config");

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert_eq!(
        String::from_utf8_lossy(&output.stderr),
        "--config requires a value\n"
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
