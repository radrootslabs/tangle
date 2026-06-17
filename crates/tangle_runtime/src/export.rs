#![forbid(unsafe_code)]

use crate::{
    TANGLE_RELAY_VERSION,
    backup::{
        TANGLE_SPEC_VERSION, file_sha256_hex, load_selected_tenant_config, now_unix_seconds,
        tenant_manifest_source, write_json_file,
    },
};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
    str,
};
use tangle_store_pocket::{PocketEvent, PocketStoreHandle};

const EXPORT_SCHEMA: &str = "tangle.tenant.export.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TenantExportRequest<'a> {
    pub config_path: &'a str,
    pub tenant_id: &'a str,
    pub output: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TenantExportReport {
    pub tenant_id: String,
    pub output_path: String,
    pub manifest_path: String,
    pub event_count: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct TenantExportManifest {
    schema: String,
    tangle_version: String,
    tangle_spec_version: String,
    created_at: u64,
    source: crate::backup::TenantManifestSource,
    events: TenantExportEventsManifest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct TenantExportEventsManifest {
    path: String,
    count: u64,
    sha256: String,
    size_bytes: u64,
}

pub fn export_tenant(request: TenantExportRequest<'_>) -> Result<TenantExportReport, String> {
    let tenant = load_selected_tenant_config(request.config_path, request.tenant_id)?;
    if !tenant.backup_export().export_enabled() {
        return Err(format!(
            "tenant export is disabled for {}",
            tenant.tenant_id().as_str()
        ));
    }
    let output = PathBuf::from(request.output);
    if output.exists() {
        return Err(format!(
            "export output already exists: {}",
            output.display()
        ));
    }
    let manifest_path = export_manifest_path(&output)?;
    if manifest_path.exists() {
        return Err(format!(
            "export manifest already exists: {}",
            manifest_path.display()
        ));
    }
    if let Some(parent) = output.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)
            .map_err(|error| format!("failed to create {}: {error}", parent.display()))?;
    }
    let handle =
        PocketStoreHandle::open(tenant.pocket_config()).map_err(|error| error.to_string())?;
    let events = handle.scan_events().map_err(|error| error.to_string())?;
    let mut file = File::create(&output)
        .map_err(|error| format!("failed to create {}: {error}", output.display()))?;
    for stored in &events {
        let raw = serde_json::to_string(&pocket_event_json(stored.event())?)
            .map_err(|error| error.to_string())?;
        file.write_all(raw.as_bytes())
            .map_err(|error| format!("failed to write {}: {error}", output.display()))?;
        file.write_all(b"\n")
            .map_err(|error| format!("failed to write {}: {error}", output.display()))?;
    }
    file.sync_all()
        .map_err(|error| format!("failed to sync {}: {error}", output.display()))?;
    drop(file);
    let (sha256, size_bytes) = file_sha256_hex(&output)?;
    let event_count = u64::try_from(events.len()).expect("event count fits u64");
    let manifest = TenantExportManifest {
        schema: EXPORT_SCHEMA.to_owned(),
        tangle_version: TANGLE_RELAY_VERSION.to_owned(),
        tangle_spec_version: TANGLE_SPEC_VERSION.to_owned(),
        created_at: now_unix_seconds()?,
        source: tenant_manifest_source(&tenant)?,
        events: TenantExportEventsManifest {
            path: output
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(|| {
                    format!("export output has no UTF-8 file name: {}", output.display())
                })?
                .to_owned(),
            count: event_count,
            sha256: sha256.clone(),
            size_bytes,
        },
    };
    write_json_file(&manifest_path, &manifest)?;
    Ok(TenantExportReport {
        tenant_id: tenant.tenant_id().as_str().to_owned(),
        output_path: output.display().to_string(),
        manifest_path: manifest_path.display().to_string(),
        event_count,
        sha256,
    })
}

pub fn export_manifest_path(output: &Path) -> Result<PathBuf, String> {
    let file_name = output
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| format!("export output has no UTF-8 file name: {}", output.display()))?;
    Ok(output.with_file_name(format!("{file_name}.manifest.json")))
}

fn pocket_event_json(event: &PocketEvent) -> Result<serde_json::Value, String> {
    let tags = event
        .tags()
        .map_err(|error| error.to_string())?
        .iter()
        .map(|tag| {
            tag.map(|value| {
                str::from_utf8(value)
                    .map(str::to_owned)
                    .map_err(|error| error.to_string())
            })
            .collect::<Result<Vec<_>, _>>()
        })
        .collect::<Result<Vec<_>, _>>()?;
    let content = str::from_utf8(event.content()).map_err(|error| error.to_string())?;
    Ok(serde_json::json!({
        "id": event.id().as_hex_string(),
        "pubkey": event.pubkey().as_hex_string(),
        "created_at": event.created_at().as_u64(),
        "kind": event.kind().as_u16(),
        "tags": tags,
        "content": content,
        "sig": event.sig().to_string()
    }))
}

#[cfg(test)]
mod tests {
    use super::{TenantExportRequest, export_manifest_path, export_tenant};
    use crate::pocket_conversion::tangle_event_to_pocket;
    use serde_json::{Value, json};
    use std::path::{Path, PathBuf};
    use tangle_protocol::Tag;
    use tangle_store_pocket::{PocketStoreConfig, PocketStoreHandle, PocketSyncPolicy};
    use tangle_test_support::{FixtureKey, tangle_v2_event};

    #[test]
    fn export_writes_selected_tenant_jsonl_and_manifest() {
        let fixture = ExportFixture::new("export-selected");
        fixture.write_config();
        fixture.store_event(&fixture.alpha_store, "alpha note", 1_714_400_001);
        fixture.store_event(&fixture.beta_store, "beta note", 1_714_400_002);
        let report = export_tenant(TenantExportRequest {
            config_path: fixture.host_config.to_str().expect("config"),
            tenant_id: "alpha",
            output: fixture.output.to_str().expect("output"),
        })
        .expect("export");
        let jsonl = std::fs::read_to_string(&fixture.output).expect("jsonl");
        let manifest = read_json(&export_manifest_path(&fixture.output).expect("manifest path"));

        assert_eq!(report.tenant_id, "alpha");
        assert_eq!(report.event_count, 1);
        assert!(jsonl.contains("alpha note"));
        assert!(!jsonl.contains("beta note"));
        assert_eq!(manifest["schema"], "tangle.tenant.export.v1");
        assert_eq!(manifest["source"]["tenant_id"], "alpha");
        assert_eq!(manifest["events"]["count"], 1);
        assert_eq!(manifest["events"]["sha256"], report.sha256);

        fixture.cleanup();
    }

    #[test]
    fn export_refuses_existing_outputs() {
        let fixture = ExportFixture::new("export-existing");
        fixture.write_config();
        std::fs::create_dir_all(fixture.output.parent().expect("parent")).expect("parent");
        std::fs::write(&fixture.output, b"exists").expect("output");
        let error = export_tenant(TenantExportRequest {
            config_path: fixture.host_config.to_str().expect("config"),
            tenant_id: "alpha",
            output: fixture.output.to_str().expect("output"),
        })
        .expect_err("existing");

        assert!(error.contains("export output already exists"));

        fixture.cleanup();
    }

    struct ExportFixture {
        root: PathBuf,
        host_config: PathBuf,
        alpha_store: PathBuf,
        beta_store: PathBuf,
        output: PathBuf,
    }

    impl ExportFixture {
        fn new(name: &str) -> Self {
            let root = temp_root(name);
            let _ = std::fs::remove_dir_all(&root);
            Self {
                host_config: root.join("host.json"),
                alpha_store: root.join("alpha-pocket"),
                beta_store: root.join("beta-pocket"),
                output: root.join("exports").join("alpha.jsonl"),
                root,
            }
        }

        fn write_config(&self) {
            std::fs::create_dir_all(self.root.join("tenants")).expect("tenants");
            std::fs::write(
                &self.host_config,
                json!({
                    "listen_addr": "127.0.0.1:0",
                    "tenant_config_dir": "tenants"
                })
                .to_string(),
            )
            .expect("host");
            std::fs::write(
                self.root.join("tenants").join("alpha.json"),
                tenant_config_json("alpha", "alpha.test", &self.alpha_store).to_string(),
            )
            .expect("alpha tenant");
            std::fs::write(
                self.root.join("tenants").join("beta.json"),
                tenant_config_json("beta", "beta.test", &self.beta_store).to_string(),
            )
            .expect("beta tenant");
        }

        fn store_event(&self, store: &Path, content: &str, created_at: u64) {
            let config =
                PocketStoreConfig::new(store, PocketSyncPolicy::FlushOnShutdown).expect("config");
            let handle = PocketStoreHandle::open(&config).expect("open");
            let event = tangle_v2_event(
                FixtureKey::Member,
                created_at,
                1,
                vec![Tag::from_parts("t", &[content]).expect("tag")],
                content,
            )
            .expect("event");
            let pocket = tangle_event_to_pocket(&event).expect("pocket");
            handle.store_event(&pocket).expect("store");
            handle.sync().expect("sync");
        }

        fn cleanup(self) {
            let _ = std::fs::remove_dir_all(self.root);
        }
    }

    fn tenant_config_json(tenant_id: &str, host: &str, store: &Path) -> Value {
        let relay_secret = if tenant_id == "alpha" {
            "7777777777777777777777777777777777777777777777777777777777777777"
        } else {
            "8888888888888888888888888888888888888888888888888888888888888888"
        };
        json!({
            "tenant_id": tenant_id,
            "tenant_schema": tenant_id,
            "host": host,
            "relay_url": format!("wss://{host}"),
            "info": {"name": format!("{tenant_id} relay")},
            "pocket": {
                "data_directory": store,
                "sync_policy": "flush_on_shutdown"
            },
            "pocket_query": {
                "allow_scraping": false,
                "allow_scrape_if_limited_to": 100,
                "allow_scrape_if_max_seconds": 3600
            },
            "groups": {
                "enabled": true,
                "canonical_relay_url": format!("wss://{host}"),
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
            },
            "backup_export": {
                "backup_enabled": true,
                "export_enabled": true
            }
        })
    }

    fn read_json(path: &Path) -> Value {
        serde_json::from_str(&std::fs::read_to_string(path).expect("read")).expect("json")
    }

    fn temp_root(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("tangle-runtime-{name}-{}", std::process::id()))
    }
}
