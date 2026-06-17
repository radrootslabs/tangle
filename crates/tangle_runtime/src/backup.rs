#![forbid(unsafe_code)]

use crate::{TANGLE_RELAY_VERSION, config::TenantRuntimeConfig, load_tangle_host_runtime_config};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Read,
    path::{Component, Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use tangle_store_pocket::{PocketStoreConfig, PocketStoreHandle};

pub const TANGLE_SPEC_VERSION: &str = "tangle_v1_mvp";
const BACKUP_SCHEMA: &str = "tangle.tenant.backup.v1";
const CHECKSUM_SCHEMA: &str = "tangle.tenant.checksums.v1";
const POCKET_STORE_DIR: &str = "pocket_store";
const REDACTED_TENANT_CONFIG: &str = "tenant_config.redacted.json";
const BACKUP_MANIFEST: &str = "backup_manifest.json";
const CHECKSUM_MANIFEST: &str = "checksums.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TenantBackupRequest<'a> {
    pub config_path: &'a str,
    pub tenant_id: &'a str,
    pub output: &'a str,
    pub include_secrets: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TenantRestoreRequest<'a> {
    pub config_path: &'a str,
    pub tenant_id: &'a str,
    pub input: &'a str,
    pub target_data_dir: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TenantBackupReport {
    pub tenant_id: String,
    pub output_path: String,
    pub manifest_path: String,
    pub checksum_manifest_path: String,
    pub checksum_file_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TenantRestoreReport {
    pub tenant_id: String,
    pub input_path: String,
    pub target_data_dir: String,
    pub restored_file_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ChecksumManifest {
    schema: String,
    algorithm: String,
    files: Vec<ChecksumFile>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ChecksumFile {
    path: String,
    sha256: String,
    size_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct TenantBackupManifest {
    schema: String,
    tangle_version: String,
    tangle_spec_version: String,
    created_at: u64,
    source: TenantManifestSource,
    store: TenantStoreManifest,
    redacted_tenant_config_path: String,
    checksum_manifest_path: String,
    checksum_manifest_sha256: String,
    checksum_file_count: usize,
    includes_secrets: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct TenantManifestSource {
    tenant_id: String,
    tenant_schema: String,
    host: String,
    relay_url: String,
    relay_self_pubkey: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct TenantStoreManifest {
    source_data_directory: String,
    snapshot_path: String,
}

pub fn backup_tenant(request: TenantBackupRequest<'_>) -> Result<TenantBackupReport, String> {
    if request.include_secrets {
        return Err("including tenant secrets in backups is unsupported".to_owned());
    }
    let tenant = load_selected_tenant_config(request.config_path, request.tenant_id)?;
    if !tenant.backup_export().backup_enabled() {
        return Err(format!(
            "tenant backup is disabled for {}",
            tenant.tenant_id().as_str()
        ));
    }
    let output = PathBuf::from(request.output);
    prepare_empty_directory(&output, "backup output")?;
    let snapshot_path = output.join(POCKET_STORE_DIR);
    copy_directory(tenant.pocket_config().data_directory(), &snapshot_path)?;
    let redacted_path = output.join(REDACTED_TENANT_CONFIG);
    write_json_file(&redacted_path, &redacted_tenant_config_value(&tenant)?)?;
    let checksums = ChecksumManifest {
        schema: CHECKSUM_SCHEMA.to_owned(),
        algorithm: "sha256".to_owned(),
        files: collect_checksums(&output)?,
    };
    let checksum_path = output.join(CHECKSUM_MANIFEST);
    write_json_file(&checksum_path, &checksums)?;
    let (checksum_manifest_sha256, _) = file_sha256_hex(&checksum_path)?;
    let source = tenant_manifest_source(&tenant)?;
    let manifest = TenantBackupManifest {
        schema: BACKUP_SCHEMA.to_owned(),
        tangle_version: TANGLE_RELAY_VERSION.to_owned(),
        tangle_spec_version: TANGLE_SPEC_VERSION.to_owned(),
        created_at: now_unix_seconds()?,
        source,
        store: TenantStoreManifest {
            source_data_directory: tenant
                .pocket_config()
                .data_directory()
                .display()
                .to_string(),
            snapshot_path: POCKET_STORE_DIR.to_owned(),
        },
        redacted_tenant_config_path: REDACTED_TENANT_CONFIG.to_owned(),
        checksum_manifest_path: CHECKSUM_MANIFEST.to_owned(),
        checksum_manifest_sha256,
        checksum_file_count: checksums.files.len(),
        includes_secrets: false,
    };
    let manifest_path = output.join(BACKUP_MANIFEST);
    write_json_file(&manifest_path, &manifest)?;
    Ok(TenantBackupReport {
        tenant_id: tenant.tenant_id().as_str().to_owned(),
        output_path: output.display().to_string(),
        manifest_path: manifest_path.display().to_string(),
        checksum_manifest_path: checksum_path.display().to_string(),
        checksum_file_count: checksums.files.len(),
    })
}

pub fn restore_tenant(request: TenantRestoreRequest<'_>) -> Result<TenantRestoreReport, String> {
    let tenant = load_selected_tenant_config(request.config_path, request.tenant_id)?;
    if !tenant.backup_export().backup_enabled() {
        return Err(format!(
            "tenant backup is disabled for {}",
            tenant.tenant_id().as_str()
        ));
    }
    let input = PathBuf::from(request.input);
    let manifest = read_backup_manifest(&input.join(BACKUP_MANIFEST))?;
    if manifest.schema != BACKUP_SCHEMA {
        return Err(format!("unsupported backup schema: {}", manifest.schema));
    }
    if manifest.source.tenant_id != tenant.tenant_id().as_str() {
        return Err(format!(
            "backup tenant {} does not match requested tenant {}",
            manifest.source.tenant_id,
            tenant.tenant_id().as_str()
        ));
    }
    let checksum_path = input.join(&manifest.checksum_manifest_path);
    let (actual_checksum_manifest_sha256, _) = file_sha256_hex(&checksum_path)?;
    if actual_checksum_manifest_sha256 != manifest.checksum_manifest_sha256 {
        return Err("backup checksum manifest digest mismatch".to_owned());
    }
    let checksum_manifest = read_checksum_manifest(&checksum_path)?;
    verify_checksums(&input, &checksum_manifest.files)?;
    let target = PathBuf::from(request.target_data_dir);
    prepare_empty_directory(&target, "restore target data directory")?;
    copy_directory(&input.join(&manifest.store.snapshot_path), &target)?;
    let restored_config = PocketStoreConfig::new(&target, tenant.pocket_config().sync_policy())
        .map_err(|error| error.to_string())?;
    let restored = PocketStoreHandle::open(&restored_config).map_err(|error| error.to_string())?;
    let restored_file_count = collect_files(&target)?.len();
    restored.scan_events().map_err(|error| error.to_string())?;
    Ok(TenantRestoreReport {
        tenant_id: tenant.tenant_id().as_str().to_owned(),
        input_path: input.display().to_string(),
        target_data_dir: target.display().to_string(),
        restored_file_count,
    })
}

pub(crate) fn load_selected_tenant_config(
    config_path: &str,
    tenant_id: &str,
) -> Result<TenantRuntimeConfig, String> {
    let config = load_tangle_host_runtime_config(config_path).map_err(|error| error.to_string())?;
    config
        .tenants()
        .iter()
        .find(|tenant| tenant.tenant_id().as_str() == tenant_id)
        .cloned()
        .ok_or_else(|| format!("tenant not found: {tenant_id}"))
}

pub(crate) fn tenant_manifest_source(
    tenant: &TenantRuntimeConfig,
) -> Result<TenantManifestSource, String> {
    Ok(TenantManifestSource {
        tenant_id: tenant.tenant_id().as_str().to_owned(),
        tenant_schema: tenant.tenant_schema().as_str().to_owned(),
        host: tenant.host().as_str().to_owned(),
        relay_url: tenant.relay_url().as_str().to_owned(),
        relay_self_pubkey: tenant
            .relay_self_pubkey()
            .map_err(|error| error.to_string())?
            .map(|pubkey| pubkey.as_str().to_owned()),
    })
}

pub(crate) fn redacted_tenant_config_value(
    tenant: &TenantRuntimeConfig,
) -> Result<serde_json::Value, String> {
    Ok(serde_json::json!({
        "tenant_id": tenant.tenant_id().as_str(),
        "tenant_schema": tenant.tenant_schema().as_str(),
        "host": tenant.host().as_str(),
        "relay_url": tenant.relay_url().as_str(),
        "inactive": tenant.inactive(),
        "info": {
            "name": tenant.info().name(),
            "description": tenant.info().description(),
            "contact": tenant.info().contact(),
            "icon": tenant.info().icon()
        },
        "pocket": {
            "data_directory": tenant.pocket_config().data_directory().display().to_string(),
            "sync_policy": format!("{:?}", tenant.pocket_config().sync_policy())
        },
        "groups": {
            "enabled": tenant.groups().enabled(),
            "relay_secret": "<redacted>",
            "relay_self": tenant.relay_self_pubkey().map_err(|error| error.to_string())?.map(|pubkey| pubkey.as_str().to_owned())
        },
        "backup_export": {
            "backup_enabled": tenant.backup_export().backup_enabled(),
            "export_enabled": tenant.backup_export().export_enabled()
        }
    }))
}

pub(crate) fn write_json_file<T>(path: &Path, value: &T) -> Result<(), String>
where
    T: Serialize,
{
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)
            .map_err(|error| format!("failed to create {}: {error}", parent.display()))?;
    }
    let raw = serde_json::to_vec_pretty(value).map_err(|error| error.to_string())?;
    fs::write(path, raw).map_err(|error| format!("failed to write {}: {error}", path.display()))
}

pub(crate) fn file_sha256_hex(path: &Path) -> Result<(String, u64), String> {
    let mut file = fs::File::open(path)
        .map_err(|error| format!("failed to open {}: {error}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut size = 0_u64;
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        size = size
            .checked_add(u64::try_from(read).expect("read size fits u64"))
            .ok_or_else(|| format!("file {} exceeds u64 size", path.display()))?;
    }
    Ok((lower_hex(&hasher.finalize()), size))
}

pub(crate) fn now_unix_seconds() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|error| error.to_string())
}

pub(crate) fn collect_files(root: &Path) -> Result<Vec<PathBuf>, String> {
    let mut files = Vec::new();
    collect_files_into(root, root, &mut files)?;
    files.sort();
    Ok(files)
}

pub(crate) fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn prepare_empty_directory(path: &Path, label: &str) -> Result<(), String> {
    if path.exists() {
        if !path.is_dir() {
            return Err(format!("{label} is not a directory: {}", path.display()));
        }
        if fs::read_dir(path)
            .map_err(|error| format!("failed to read {}: {error}", path.display()))?
            .next()
            .transpose()
            .map_err(|error| format!("failed to read {}: {error}", path.display()))?
            .is_some()
        {
            return Err(format!("{label} must be empty: {}", path.display()));
        }
    }
    fs::create_dir_all(path)
        .map_err(|error| format!("failed to create {}: {error}", path.display()))
}

fn copy_directory(source: &Path, target: &Path) -> Result<(), String> {
    if !source.is_dir() {
        return Err(format!(
            "source directory does not exist: {}",
            source.display()
        ));
    }
    fs::create_dir_all(target)
        .map_err(|error| format!("failed to create {}: {error}", target.display()))?;
    let mut entries = fs::read_dir(source)
        .map_err(|error| format!("failed to read {}: {error}", source.display()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("failed to read {}: {error}", source.display()))?;
    entries.sort_by_key(|entry| entry.path());
    for entry in entries {
        let source_path = entry.path();
        let target_path = target.join(entry.file_name());
        let metadata = fs::symlink_metadata(&source_path)
            .map_err(|error| format!("failed to stat {}: {error}", source_path.display()))?;
        let file_type = metadata.file_type();
        if file_type.is_symlink() {
            return Err(format!(
                "symlink is not supported in backup bundles: {}",
                source_path.display()
            ));
        }
        if file_type.is_dir() {
            copy_directory(&source_path, &target_path)?;
        } else if file_type.is_file() {
            fs::copy(&source_path, &target_path).map_err(|error| {
                format!(
                    "failed to copy {} to {}: {error}",
                    source_path.display(),
                    target_path.display()
                )
            })?;
        } else {
            return Err(format!(
                "special file is not supported in backup bundles: {}",
                source_path.display()
            ));
        }
    }
    Ok(())
}

fn collect_checksums(root: &Path) -> Result<Vec<ChecksumFile>, String> {
    collect_files(root)?
        .into_iter()
        .map(|path| {
            let relative = path
                .strip_prefix(root)
                .map_err(|error| error.to_string())
                .and_then(relative_path_string)?;
            let (sha256, size_bytes) = file_sha256_hex(&path)?;
            Ok(ChecksumFile {
                path: relative,
                sha256,
                size_bytes,
            })
        })
        .collect()
}

fn collect_files_into(root: &Path, path: &Path, files: &mut Vec<PathBuf>) -> Result<(), String> {
    if !path.exists() {
        return Ok(());
    }
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("failed to stat {}: {error}", path.display()))?;
    let file_type = metadata.file_type();
    if file_type.is_symlink() {
        return Err(format!(
            "symlink is not supported in backup bundles: {}",
            path.display()
        ));
    }
    if file_type.is_file() {
        files.push(path.to_path_buf());
        return Ok(());
    }
    if !file_type.is_dir() {
        return Err(format!(
            "special file is not supported in backup bundles: {}",
            path.display()
        ));
    }
    let mut entries = fs::read_dir(path)
        .map_err(|error| format!("failed to read {}: {error}", path.display()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    entries.sort_by_key(|entry| entry.path());
    for entry in entries {
        let child = entry.path();
        if child == root.join(BACKUP_MANIFEST) || child == root.join(CHECKSUM_MANIFEST) {
            continue;
        }
        collect_files_into(root, &child, files)?;
    }
    Ok(())
}

fn relative_path_string(path: &Path) -> Result<String, String> {
    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => {
                parts.push(
                    part.to_str()
                        .ok_or_else(|| format!("path is not UTF-8: {}", path.display()))?
                        .to_owned(),
                );
            }
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(format!("path is not relative: {}", path.display()));
            }
        }
    }
    Ok(parts.join("/"))
}

fn read_backup_manifest(path: &Path) -> Result<TenantBackupManifest, String> {
    let raw = fs::read_to_string(path)
        .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    serde_json::from_str(&raw).map_err(|error| format!("backup manifest JSON is invalid: {error}"))
}

fn read_checksum_manifest(path: &Path) -> Result<ChecksumManifest, String> {
    let raw = fs::read_to_string(path)
        .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    let manifest: ChecksumManifest = serde_json::from_str(&raw)
        .map_err(|error| format!("checksum manifest JSON is invalid: {error}"))?;
    if manifest.schema != CHECKSUM_SCHEMA {
        return Err(format!("unsupported checksum schema: {}", manifest.schema));
    }
    if manifest.algorithm != "sha256" {
        return Err(format!(
            "unsupported checksum algorithm: {}",
            manifest.algorithm
        ));
    }
    Ok(manifest)
}

fn verify_checksums(root: &Path, files: &[ChecksumFile]) -> Result<(), String> {
    for expected in files {
        let path = root.join(&expected.path);
        let (sha256, size_bytes) = file_sha256_hex(&path)?;
        if sha256 != expected.sha256 || size_bytes != expected.size_bytes {
            return Err(format!("backup checksum mismatch for {}", expected.path));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{TenantBackupRequest, TenantRestoreRequest, backup_tenant, restore_tenant};
    use crate::{
        backup::{BACKUP_MANIFEST, CHECKSUM_MANIFEST, REDACTED_TENANT_CONFIG},
        pocket_conversion::tangle_event_to_pocket,
    };
    use serde_json::{Value, json};
    use std::path::{Path, PathBuf};
    use tangle_protocol::Tag;
    use tangle_store_pocket::{PocketStoreConfig, PocketStoreHandle, PocketSyncPolicy};
    use tangle_test_support::{FixtureKey, tangle_v2_event};

    #[test]
    fn backup_creates_manifest_redacted_config_checksum_and_store_snapshot() {
        let fixture = BackupFixture::new("backup-create");
        fixture.write_config();
        fixture.store_event("alpha event", 1_714_300_001);
        let report = backup_tenant(TenantBackupRequest {
            config_path: fixture.host_config.to_str().expect("config"),
            tenant_id: "alpha",
            output: fixture.backup_dir.to_str().expect("backup"),
            include_secrets: false,
        })
        .expect("backup");

        assert_eq!(report.tenant_id, "alpha");
        let manifest = read_json(&fixture.backup_dir.join(BACKUP_MANIFEST));
        assert_eq!(manifest["schema"], "tangle.tenant.backup.v1");
        assert_eq!(manifest["source"]["tenant_id"], "alpha");
        assert_eq!(manifest["includes_secrets"], false);
        assert!(manifest["checksum_file_count"].as_u64().expect("count") >= 3);
        assert!(
            fixture
                .backup_dir
                .join("pocket_store")
                .join("event.map")
                .exists()
        );
        assert!(
            fixture
                .backup_dir
                .join("pocket_store")
                .join("lmdb")
                .join("data.mdb")
                .exists()
        );
        assert!(fixture.backup_dir.join(CHECKSUM_MANIFEST).exists());
        let redacted = fs_read(&fixture.backup_dir.join(REDACTED_TENANT_CONFIG));
        assert!(redacted.contains("\"relay_secret\": \"<redacted>\""));
        assert!(
            !redacted.contains("7777777777777777777777777777777777777777777777777777777777777777")
        );

        fixture.cleanup();
    }

    #[test]
    fn backup_rejects_secret_inclusion_requests() {
        let fixture = BackupFixture::new("backup-secrets");
        fixture.write_config();
        fixture.store_event("alpha event", 1_714_300_011);
        let error = backup_tenant(TenantBackupRequest {
            config_path: fixture.host_config.to_str().expect("config"),
            tenant_id: "alpha",
            output: fixture.backup_dir.to_str().expect("backup"),
            include_secrets: true,
        })
        .expect_err("secrets unsupported");

        assert_eq!(error, "including tenant secrets in backups is unsupported");

        fixture.cleanup();
    }

    #[test]
    fn restore_verifies_checksums_and_recreates_usable_store() {
        let fixture = BackupFixture::new("backup-restore");
        fixture.write_config();
        fixture.store_event("alpha event", 1_714_300_021);
        backup_tenant(TenantBackupRequest {
            config_path: fixture.host_config.to_str().expect("config"),
            tenant_id: "alpha",
            output: fixture.backup_dir.to_str().expect("backup"),
            include_secrets: false,
        })
        .expect("backup");
        let report = restore_tenant(TenantRestoreRequest {
            config_path: fixture.host_config.to_str().expect("config"),
            tenant_id: "alpha",
            input: fixture.backup_dir.to_str().expect("backup"),
            target_data_dir: fixture.restore_dir.to_str().expect("restore"),
        })
        .expect("restore");
        let restored_config =
            PocketStoreConfig::new(&fixture.restore_dir, PocketSyncPolicy::FlushOnShutdown)
                .expect("config");
        let restored = PocketStoreHandle::open(&restored_config).expect("open");
        let events = restored.scan_events().expect("scan");

        assert_eq!(report.tenant_id, "alpha");
        assert_eq!(events.len(), 1);
        assert_eq!(event_content(events[0].event()), "alpha event");

        fixture.cleanup();
    }

    #[test]
    fn restore_refuses_non_empty_targets_and_corrupt_backup_files() {
        let fixture = BackupFixture::new("backup-corrupt");
        fixture.write_config();
        fixture.store_event("alpha event", 1_714_300_031);
        backup_tenant(TenantBackupRequest {
            config_path: fixture.host_config.to_str().expect("config"),
            tenant_id: "alpha",
            output: fixture.backup_dir.to_str().expect("backup"),
            include_secrets: false,
        })
        .expect("backup");
        std::fs::create_dir_all(&fixture.restore_dir).expect("restore dir");
        std::fs::write(fixture.restore_dir.join("existing"), b"present").expect("existing");
        let dirty_error = restore_tenant(TenantRestoreRequest {
            config_path: fixture.host_config.to_str().expect("config"),
            tenant_id: "alpha",
            input: fixture.backup_dir.to_str().expect("backup"),
            target_data_dir: fixture.restore_dir.to_str().expect("restore"),
        })
        .expect_err("dirty target");

        assert!(dirty_error.contains("restore target data directory must be empty"));
        std::fs::remove_dir_all(&fixture.restore_dir).expect("clean target");
        std::fs::write(
            fixture.backup_dir.join("pocket_store").join("event.map"),
            b"corrupt",
        )
        .expect("corrupt");
        let corrupt_error = restore_tenant(TenantRestoreRequest {
            config_path: fixture.host_config.to_str().expect("config"),
            tenant_id: "alpha",
            input: fixture.backup_dir.to_str().expect("backup"),
            target_data_dir: fixture.restore_dir.to_str().expect("restore"),
        })
        .expect_err("corrupt");

        assert!(corrupt_error.contains("backup checksum mismatch"));

        fixture.cleanup();
    }

    struct BackupFixture {
        root: PathBuf,
        host_config: PathBuf,
        alpha_store: PathBuf,
        backup_dir: PathBuf,
        restore_dir: PathBuf,
    }

    impl BackupFixture {
        fn new(name: &str) -> Self {
            let root = temp_root(name);
            let _ = std::fs::remove_dir_all(&root);
            Self {
                host_config: root.join("host.json"),
                alpha_store: root.join("alpha-pocket"),
                backup_dir: root.join("backup"),
                restore_dir: root.join("restore-pocket"),
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
                tenant_config_json("beta", "beta.test", &self.root.join("beta-pocket")).to_string(),
            )
            .expect("beta tenant");
        }

        fn store_event(&self, content: &str, created_at: u64) {
            let config =
                PocketStoreConfig::new(&self.alpha_store, PocketSyncPolicy::FlushOnShutdown)
                    .expect("config");
            let handle = PocketStoreHandle::open(&config).expect("open");
            let event = tangle_v2_event(
                FixtureKey::Member,
                created_at,
                1,
                vec![Tag::from_parts("t", &["alpha"]).expect("tag")],
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
        serde_json::from_str(&fs_read(path)).expect("json")
    }

    fn fs_read(path: &Path) -> String {
        std::fs::read_to_string(path).expect("read")
    }

    fn event_content(event: &tangle_store_pocket::PocketEvent) -> String {
        std::str::from_utf8(event.content())
            .expect("utf8")
            .to_owned()
    }

    fn temp_root(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("tangle-runtime-{name}-{}", std::process::id()))
    }
}
