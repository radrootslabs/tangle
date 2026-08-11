#![forbid(unsafe_code)]

use crate::TANGLE_RELAY_VERSION;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs::{self, File},
    io::{BufRead, BufReader, BufWriter, Read, Write},
    path::{Component, Path, PathBuf},
    str,
    time::{SystemTime, UNIX_EPOCH},
};
use tangle_store_pocket::{
    POCKET_SOURCE_REVISION, PocketEvent, PocketStoreConfig, PocketStoreHandle, PocketSyncPolicy,
    parse_pocket_event_json,
};

const BACKUP_SCHEMA: &str = "tangle.portable-relay-backup.v1";
const MANIFEST_FILE: &str = "manifest.json";
const EVENTS_FILE: &str = "events.jsonl";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortableRelayBackupPolicy {
    maximum_event_count: u64,
    maximum_event_json_bytes: u64,
    maximum_backup_bytes: u64,
}

impl PortableRelayBackupPolicy {
    pub fn new(
        maximum_event_count: u64,
        maximum_event_json_bytes: u64,
        maximum_backup_bytes: u64,
    ) -> Result<Self, String> {
        if maximum_event_count == 0
            || maximum_event_json_bytes == 0
            || maximum_backup_bytes == 0
            || maximum_event_json_bytes > maximum_backup_bytes
        {
            return Err("portable relay backup limits must be nonzero and ordered".to_owned());
        }
        Ok(Self {
            maximum_event_count,
            maximum_event_json_bytes,
            maximum_backup_bytes,
        })
    }

    pub fn maximum_event_count(self) -> u64 {
        self.maximum_event_count
    }

    pub fn maximum_event_json_bytes(self) -> u64 {
        self.maximum_event_json_bytes
    }

    pub fn maximum_backup_bytes(self) -> u64 {
        self.maximum_backup_bytes
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortableRelayBackupIdentity {
    relay_url: String,
}

impl PortableRelayBackupIdentity {
    pub fn new(relay_url: impl Into<String>) -> Result<Self, String> {
        let relay_url = relay_url.into();
        if !(relay_url.starts_with("ws://") || relay_url.starts_with("wss://"))
            || relay_url.chars().any(char::is_whitespace)
        {
            return Err("portable relay backup identity requires a relay URL".to_owned());
        }
        Ok(Self { relay_url })
    }

    pub fn relay_url(&self) -> &str {
        &self.relay_url
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortableRelayBackupReport {
    pub backup_path: String,
    pub relay_url: String,
    pub created_at_unix_seconds: u64,
    pub event_count: u64,
    pub events_sha256: String,
    pub events_size_bytes: u64,
    pub first_store_offset: Option<u64>,
    pub last_store_offset: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortableRelayRestoreReport {
    pub backup_path: String,
    pub target_data_directory: String,
    pub event_count: u64,
    pub events_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PortableRelayBackupManifest {
    schema: String,
    tangle_version: String,
    pocket_source_revision: String,
    relay_url: String,
    created_at_unix_seconds: u64,
    events: PortableRelayBackupEvents,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PortableRelayBackupEvents {
    path: String,
    count: u64,
    sha256: String,
    size_bytes: u64,
    first_store_offset: Option<u64>,
    last_store_offset: Option<u64>,
}

pub fn create_portable_relay_backup(
    store_config: &PocketStoreConfig,
    identity: &PortableRelayBackupIdentity,
    output: &Path,
    policy: PortableRelayBackupPolicy,
) -> Result<PortableRelayBackupReport, String> {
    validate_final_backup_path(output)?;
    if output.exists() {
        return Err(format!(
            "portable relay backup already exists: {}",
            output.display()
        ));
    }
    let parent = output
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| "portable relay backup requires a parent directory".to_owned())?;
    fs::create_dir_all(parent)
        .map_err(|error| format!("failed to create {}: {error}", parent.display()))?;
    let stage = staging_path(output)?;
    if stage.exists() {
        return Err(format!(
            "portable relay backup stage exists: {}",
            stage.display()
        ));
    }
    fs::create_dir(&stage)
        .map_err(|error| format!("failed to create {}: {error}", stage.display()))?;
    let result =
        create_backup_in_stage(store_config, identity, &stage, policy).and_then(|report| {
            fs::rename(&stage, output).map_err(|error| {
                format!(
                    "failed to publish portable relay backup {}: {error}",
                    output.display()
                )
            })?;
            Ok(PortableRelayBackupReport {
                backup_path: output.display().to_string(),
                ..report
            })
        });
    if result.is_err() {
        let _ = fs::remove_dir_all(&stage);
    }
    result
}

pub fn verify_portable_relay_backup(
    input: &Path,
    expected_identity: &PortableRelayBackupIdentity,
    policy: PortableRelayBackupPolicy,
) -> Result<PortableRelayBackupReport, String> {
    let manifest = read_manifest(input)?;
    if manifest.schema != BACKUP_SCHEMA {
        return Err(format!(
            "unsupported portable relay backup schema: {}",
            manifest.schema
        ));
    }
    if manifest.relay_url != expected_identity.relay_url() {
        return Err("portable relay backup relay identity does not match".to_owned());
    }
    if !is_lower_hex(&manifest.pocket_source_revision, 40) {
        return Err("portable relay backup Pocket source revision is invalid".to_owned());
    }
    if manifest.events.path != EVENTS_FILE {
        return Err("portable relay backup event path is invalid".to_owned());
    }
    if manifest.events.count > policy.maximum_event_count()
        || manifest.events.size_bytes > policy.maximum_backup_bytes()
    {
        return Err("portable relay backup exceeds configured limits".to_owned());
    }
    let events_path = input.join(EVENTS_FILE);
    let metadata = regular_file_metadata(&events_path)?;
    if metadata.len() != manifest.events.size_bytes {
        return Err("portable relay backup event size does not match manifest".to_owned());
    }
    let (sha256, size_bytes) = file_sha256(&events_path)?;
    if sha256 != manifest.events.sha256 {
        return Err("portable relay backup event checksum does not match manifest".to_owned());
    }
    let observed = verify_event_lines(&events_path, policy)?;
    if observed.count != manifest.events.count
        || observed.first_store_offset != manifest.events.first_store_offset
        || observed.last_store_offset != manifest.events.last_store_offset
    {
        return Err("portable relay backup event inventory does not match manifest".to_owned());
    }
    Ok(PortableRelayBackupReport {
        backup_path: input.display().to_string(),
        relay_url: manifest.relay_url,
        created_at_unix_seconds: manifest.created_at_unix_seconds,
        event_count: observed.count,
        events_sha256: sha256,
        events_size_bytes: size_bytes,
        first_store_offset: observed.first_store_offset,
        last_store_offset: observed.last_store_offset,
    })
}

pub fn restore_portable_relay_backup(
    input: &Path,
    expected_identity: &PortableRelayBackupIdentity,
    target_data_directory: &Path,
    policy: PortableRelayBackupPolicy,
) -> Result<PortableRelayRestoreReport, String> {
    let verified = verify_portable_relay_backup(input, expected_identity, policy)?;
    validate_final_backup_path(target_data_directory)?;
    if target_data_directory.exists() {
        return Err(format!(
            "portable relay restore target already exists: {}",
            target_data_directory.display()
        ));
    }
    let parent = target_data_directory
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| "portable relay restore target requires a parent directory".to_owned())?;
    fs::create_dir_all(parent)
        .map_err(|error| format!("failed to create {}: {error}", parent.display()))?;
    let stage = staging_path(target_data_directory)?;
    fs::create_dir(&stage)
        .map_err(|error| format!("failed to create {}: {error}", stage.display()))?;
    let result = restore_into_stage(input, &stage, policy).and_then(|event_count| {
        if event_count != verified.event_count {
            return Err("portable relay restore event count differs".to_owned());
        }
        fs::rename(&stage, target_data_directory).map_err(|error| {
            format!(
                "failed to publish portable relay restore {}: {error}",
                target_data_directory.display()
            )
        })?;
        Ok(PortableRelayRestoreReport {
            backup_path: input.display().to_string(),
            target_data_directory: target_data_directory.display().to_string(),
            event_count,
            events_sha256: verified.events_sha256,
        })
    });
    if result.is_err() {
        let _ = fs::remove_dir_all(&stage);
    }
    result
}

fn create_backup_in_stage(
    store_config: &PocketStoreConfig,
    identity: &PortableRelayBackupIdentity,
    stage: &Path,
    policy: PortableRelayBackupPolicy,
) -> Result<PortableRelayBackupReport, String> {
    let store = PocketStoreHandle::open(store_config).map_err(|error| error.to_string())?;
    store.sync().map_err(|error| error.to_string())?;
    let events = store.scan_events().map_err(|error| error.to_string())?;
    let event_count = u64::try_from(events.len()).expect("event count fits u64");
    if event_count > policy.maximum_event_count() {
        return Err("portable relay backup event count exceeds policy".to_owned());
    }
    let events_path = stage.join(EVENTS_FILE);
    let mut writer = BufWriter::new(
        File::create(&events_path)
            .map_err(|error| format!("failed to create {}: {error}", events_path.display()))?,
    );
    for stored in &events {
        let line = serde_json::to_vec(&serde_json::json!({
            "store_offset": stored.store_offset(),
            "event": pocket_event_json(stored.event())?,
        }))
        .map_err(|error| error.to_string())?;
        if u64::try_from(line.len()).expect("line length fits u64")
            > policy.maximum_event_json_bytes()
        {
            return Err("portable relay backup event JSON exceeds policy".to_owned());
        }
        writer
            .write_all(&line)
            .and_then(|_| writer.write_all(b"\n"))
            .map_err(|error| format!("failed to write {}: {error}", events_path.display()))?;
    }
    writer
        .flush()
        .map_err(|error| format!("failed to flush {}: {error}", events_path.display()))?;
    writer
        .get_ref()
        .sync_all()
        .map_err(|error| format!("failed to sync {}: {error}", events_path.display()))?;
    drop(writer);
    let (events_sha256, events_size_bytes) = file_sha256(&events_path)?;
    if events_size_bytes > policy.maximum_backup_bytes() {
        return Err("portable relay backup byte size exceeds policy".to_owned());
    }
    let created_at_unix_seconds = now_unix_seconds()?;
    let first_store_offset = events.first().map(|event| event.store_offset());
    let last_store_offset = events.last().map(|event| event.store_offset());
    let manifest = PortableRelayBackupManifest {
        schema: BACKUP_SCHEMA.to_owned(),
        tangle_version: TANGLE_RELAY_VERSION.to_owned(),
        pocket_source_revision: POCKET_SOURCE_REVISION.to_owned(),
        relay_url: identity.relay_url().to_owned(),
        created_at_unix_seconds,
        events: PortableRelayBackupEvents {
            path: EVENTS_FILE.to_owned(),
            count: event_count,
            sha256: events_sha256.clone(),
            size_bytes: events_size_bytes,
            first_store_offset,
            last_store_offset,
        },
    };
    let manifest_path = stage.join(MANIFEST_FILE);
    let manifest_bytes = serde_json::to_vec_pretty(&manifest).map_err(|error| error.to_string())?;
    let mut manifest_file = File::create(&manifest_path)
        .map_err(|error| format!("failed to create {}: {error}", manifest_path.display()))?;
    manifest_file
        .write_all(&manifest_bytes)
        .and_then(|_| manifest_file.sync_all())
        .map_err(|error| format!("failed to write {}: {error}", manifest_path.display()))?;
    verify_portable_relay_backup(stage, identity, policy)?;
    Ok(PortableRelayBackupReport {
        backup_path: stage.display().to_string(),
        relay_url: identity.relay_url().to_owned(),
        created_at_unix_seconds,
        event_count,
        events_sha256,
        events_size_bytes,
        first_store_offset,
        last_store_offset,
    })
}

fn restore_into_stage(
    input: &Path,
    stage: &Path,
    policy: PortableRelayBackupPolicy,
) -> Result<u64, String> {
    let config = PocketStoreConfig::new(stage, PocketSyncPolicy::FlushOnWrite)
        .map_err(|error| error.to_string())?;
    let store = PocketStoreHandle::open(&config).map_err(|error| error.to_string())?;
    let events_path = input.join(EVENTS_FILE);
    let mut reader = BufReader::new(
        File::open(&events_path)
            .map_err(|error| format!("failed to open {}: {error}", events_path.display()))?,
    );
    let mut line = Vec::new();
    let mut count = 0_u64;
    loop {
        line.clear();
        if reader
            .read_until(b'\n', &mut line)
            .map_err(|error| format!("failed to read {}: {error}", events_path.display()))?
            == 0
        {
            break;
        }
        let parsed = parse_backup_line(&line, policy)?;
        store
            .store_event(&parsed.event)
            .map_err(|error| error.to_string())?;
        count = count
            .checked_add(1)
            .ok_or_else(|| "portable relay restore event count overflowed".to_owned())?;
    }
    store.sync().map_err(|error| error.to_string())?;
    let restored = store.scan_events().map_err(|error| error.to_string())?;
    if u64::try_from(restored.len()).expect("event count fits u64") != count {
        return Err("portable relay restore verification count differs".to_owned());
    }
    Ok(count)
}

struct VerifiedEventInventory {
    count: u64,
    first_store_offset: Option<u64>,
    last_store_offset: Option<u64>,
}

fn verify_event_lines(
    path: &Path,
    policy: PortableRelayBackupPolicy,
) -> Result<VerifiedEventInventory, String> {
    let mut reader = BufReader::new(
        File::open(path).map_err(|error| format!("failed to open {}: {error}", path.display()))?,
    );
    let mut line = Vec::new();
    let mut count = 0_u64;
    let mut first_store_offset = None;
    let mut last_store_offset = None;
    let mut event_ids = BTreeSet::new();
    loop {
        line.clear();
        if reader
            .read_until(b'\n', &mut line)
            .map_err(|error| format!("failed to read {}: {error}", path.display()))?
            == 0
        {
            break;
        }
        let parsed = parse_backup_line(&line, policy)?;
        parsed
            .event
            .verify()
            .map_err(|_| "portable relay backup contains an invalid event signature".to_owned())?;
        if last_store_offset.is_some_and(|offset| parsed.store_offset <= offset) {
            return Err(
                "portable relay backup store offsets are not strictly increasing".to_owned(),
            );
        }
        if !event_ids.insert(parsed.event.id().as_hex_string()) {
            return Err("portable relay backup contains duplicate event IDs".to_owned());
        }
        first_store_offset.get_or_insert(parsed.store_offset);
        last_store_offset = Some(parsed.store_offset);
        count = count
            .checked_add(1)
            .ok_or_else(|| "portable relay backup event count overflowed".to_owned())?;
        if count > policy.maximum_event_count() {
            return Err("portable relay backup event count exceeds policy".to_owned());
        }
    }
    Ok(VerifiedEventInventory {
        count,
        first_store_offset,
        last_store_offset,
    })
}

struct ParsedBackupLine {
    store_offset: u64,
    event: tangle_store_pocket::PocketOwnedEvent,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BackupLineDocument {
    store_offset: u64,
    event: serde_json::Value,
}

fn parse_backup_line(
    line: &[u8],
    policy: PortableRelayBackupPolicy,
) -> Result<ParsedBackupLine, String> {
    let line = line.strip_suffix(b"\n").unwrap_or(line);
    if line.is_empty()
        || u64::try_from(line.len()).expect("line length fits u64")
            > policy.maximum_event_json_bytes()
    {
        return Err("portable relay backup event line is empty or oversized".to_owned());
    }
    let value: BackupLineDocument = serde_json::from_slice(line)
        .map_err(|_| "portable relay backup line is invalid".to_owned())?;
    let raw = serde_json::to_vec(&value.event).map_err(|error| error.to_string())?;
    let event = parse_pocket_event_json(&raw).map_err(|error| error.to_string())?;
    Ok(ParsedBackupLine {
        store_offset: value.store_offset,
        event,
    })
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
        "sig": event.sig().to_string(),
    }))
}

fn read_manifest(input: &Path) -> Result<PortableRelayBackupManifest, String> {
    let metadata = fs::symlink_metadata(input)
        .map_err(|error| format!("failed to stat {}: {error}", input.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("portable relay backup input must be a real directory".to_owned());
    }
    let path = input.join(MANIFEST_FILE);
    let metadata = regular_file_metadata(&path)?;
    if metadata.len() > 64 * 1024 {
        return Err("portable relay backup manifest exceeds size policy".to_owned());
    }
    let raw =
        fs::read(&path).map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    serde_json::from_slice(&raw).map_err(|_| "portable relay backup manifest is invalid".to_owned())
}

fn regular_file_metadata(path: &Path) -> Result<fs::Metadata, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("failed to stat {}: {error}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(format!(
            "portable relay backup file is unsafe: {}",
            path.display()
        ));
    }
    Ok(metadata)
}

fn file_sha256(path: &Path) -> Result<(String, u64), String> {
    let mut file =
        File::open(path).map_err(|error| format!("failed to open {}: {error}", path.display()))?;
    let mut digest = Sha256::new();
    let mut size = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
        size = size
            .checked_add(u64::try_from(read).expect("read length fits u64"))
            .ok_or_else(|| "portable relay backup size overflowed".to_owned())?;
    }
    Ok((lower_hex(&digest.finalize()), size))
}

fn validate_final_backup_path(path: &Path) -> Result<(), String> {
    if path.as_os_str().is_empty() {
        return Err("portable relay backup path must not be empty".to_owned());
    }
    for component in path.components() {
        if matches!(component, Component::ParentDir) {
            return Err("portable relay backup path must not contain parent traversal".to_owned());
        }
    }
    Ok(())
}

fn staging_path(path: &Path) -> Result<PathBuf, String> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| "portable relay backup path requires a UTF-8 file name".to_owned())?;
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| error.to_string())?
        .as_nanos();
    Ok(path.with_file_name(format!(".{name}.stage-{}-{nonce}", std::process::id())))
}

fn now_unix_seconds() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|error| error.to_string())
}

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn is_lower_hex(value: &str, expected: usize) -> bool {
    value.len() == expected
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::{
        PortableRelayBackupIdentity, PortableRelayBackupPolicy, create_portable_relay_backup,
        restore_portable_relay_backup, verify_portable_relay_backup,
    };
    use crate::pocket_conversion::tangle_event_to_pocket;
    use std::path::PathBuf;
    use tangle_store_pocket::{
        PocketStoreConfig, PocketStoreHandle, PocketSyncPolicy, parse_pocket_filter_json,
    };
    use tangle_test_support::{FixtureKey, build_fixture_event_from_parts};

    #[test]
    fn portable_backup_round_trip_preserves_profile_head_and_delete_event() {
        let root = temp_root("round-trip");
        let _ = std::fs::remove_dir_all(&root);
        let source = root.join("source");
        let backup = root.join("backups").join("backup-1");
        let restored = root.join("restored");
        let source_config =
            PocketStoreConfig::new(&source, PocketSyncPolicy::FlushOnWrite).expect("source config");
        let source_store = PocketStoreHandle::open(&source_config).expect("source store");
        for event in [
            event(1_714_124_433, 0, Vec::new(), r#"{"name":"Farm"}"#),
            event(1_714_124_434, 0, Vec::new(), r#"{"name":"Farm Market"}"#),
            event(
                1_714_124_435,
                5,
                vec![vec!["e".to_owned(), "0".repeat(64)]],
                "deleted",
            ),
        ] {
            source_store
                .store_event(&tangle_event_to_pocket(&event).expect("pocket event"))
                .expect("store event");
        }
        let identity =
            PortableRelayBackupIdentity::new("wss://relay.radroots.test").expect("identity");
        let policy = policy();

        let created = create_portable_relay_backup(&source_config, &identity, &backup, policy)
            .expect("backup");
        let verified =
            verify_portable_relay_backup(&backup, &identity, policy).expect("verify backup");
        let restore =
            restore_portable_relay_backup(&backup, &identity, &restored, policy).expect("restore");

        assert_eq!(created.event_count, 3);
        assert_eq!(verified.event_count, 3);
        assert_eq!(restore.event_count, 3);
        assert_eq!(created.events_sha256, restore.events_sha256);
        let restored_config = PocketStoreConfig::new(&restored, PocketSyncPolicy::FlushOnWrite)
            .expect("restored config");
        let restored_store = PocketStoreHandle::open(&restored_config).expect("restored store");
        let profile_filter = parse_pocket_filter_json(
            format!(
                r#"{{"authors":["{}"],"kinds":[0]}}"#,
                FixtureKey::Member.public_key()
            )
            .as_bytes(),
        )
        .expect("profile filter");
        let profile = restored_store
            .find_events(
                &profile_filter,
                tangle_store_pocket::PocketQueryConfig::default(),
            )
            .expect("profile query");
        assert_eq!(profile.len(), 1);
        assert_eq!(profile[0].content(), br#"{"name":"Farm Market"}"#);
        let delete_filter = parse_pocket_filter_json(
            format!(
                r#"{{"authors":["{}"],"kinds":[5]}}"#,
                FixtureKey::Member.public_key()
            )
            .as_bytes(),
        )
        .expect("delete filter");
        assert_eq!(
            restored_store
                .find_events(
                    &delete_filter,
                    tangle_store_pocket::PocketQueryConfig::default()
                )
                .expect("delete query")
                .len(),
            1
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn portable_backup_detects_corruption_identity_drift_and_existing_restore_target() {
        let root = temp_root("adverse");
        let _ = std::fs::remove_dir_all(&root);
        let source_config =
            PocketStoreConfig::new(root.join("source"), PocketSyncPolicy::FlushOnWrite)
                .expect("source config");
        let source = PocketStoreHandle::open(&source_config).expect("source");
        source
            .store_event(
                &tangle_event_to_pocket(&event(1_714_124_433, 1, Vec::new(), "note"))
                    .expect("pocket"),
            )
            .expect("store");
        let identity =
            PortableRelayBackupIdentity::new("wss://relay.radroots.test").expect("identity");
        let backup = root.join("backup");
        create_portable_relay_backup(&source_config, &identity, &backup, policy()).expect("backup");
        assert!(
            verify_portable_relay_backup(
                &backup,
                &PortableRelayBackupIdentity::new("wss://other.test").expect("other"),
                policy(),
            )
            .is_err()
        );
        let target = root.join("existing");
        std::fs::create_dir_all(&target).expect("target");
        assert!(restore_portable_relay_backup(&backup, &identity, &target, policy()).is_err());
        std::fs::write(backup.join("events.jsonl"), b"corrupt\n").expect("corrupt");
        assert!(verify_portable_relay_backup(&backup, &identity, policy()).is_err());
        let _ = std::fs::remove_dir_all(root);
    }

    fn event(
        created_at: u64,
        kind: u64,
        tags: Vec<Vec<String>>,
        content: &str,
    ) -> tangle_protocol::Event {
        build_fixture_event_from_parts(FixtureKey::Member, created_at, kind, tags, content)
            .expect("event")
    }

    fn policy() -> PortableRelayBackupPolicy {
        PortableRelayBackupPolicy::new(100, 128 * 1024, 1024 * 1024).expect("policy")
    }

    fn temp_root(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "tangle-portable-backup-{name}-{}",
            std::process::id()
        ))
    }
}
