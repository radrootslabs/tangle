#![forbid(unsafe_code)]

use core::fmt;
use pocket_db::{
    ScreenResult, Store,
    heed::{Database, types::Bytes},
};
use pocket_types::{
    Event, Filter, Hll8, Id, Kind, OwnedEvent, OwnedFilter, OwnedTags, Pubkey, Sig, Tags, Time,
};
use std::{
    io,
    path::{Path, PathBuf},
    sync::Arc,
};

pub const POCKET_SOURCE_REPOSITORY: &str = "https://github.com/triesap/pocket";
pub const POCKET_SOURCE_REVISION: &str = "329334f20948c796c6016b673b92551ac4855ad7";

pub type PocketEvent = Event;
pub type PocketEventId = Id;
pub type PocketFilter = Filter;
pub type PocketHll8 = Hll8;
pub type PocketKind = Kind;
pub type PocketOwnedEvent = OwnedEvent;
pub type PocketOwnedFilter = OwnedFilter;
pub type PocketOwnedTags = OwnedTags;
pub type PocketPubkey = Pubkey;
pub type PocketSig = Sig;
pub type PocketTags = Tags;
pub type PocketTime = Time;
pub type PocketScreenResult = ScreenResult;
pub type PocketStore = Store;
pub type PocketExtraRecord = (Vec<u8>, Vec<u8>);
pub type PocketExtraRecords = Vec<PocketExtraRecord>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PocketStoredEvent {
    store_offset: u64,
    event: PocketOwnedEvent,
}

impl PocketStoredEvent {
    pub fn new(store_offset: u64, event: PocketOwnedEvent) -> Self {
        Self {
            store_offset,
            event,
        }
    }

    pub fn store_offset(&self) -> u64 {
        self.store_offset
    }

    pub fn event(&self) -> &PocketEvent {
        &self.event
    }

    pub fn into_event(self) -> PocketOwnedEvent {
        self.event
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PocketScreenedEvents {
    events: Vec<PocketOwnedEvent>,
    redacted: bool,
}

impl PocketScreenedEvents {
    pub fn new(events: Vec<PocketOwnedEvent>, redacted: bool) -> Self {
        Self { events, redacted }
    }

    pub fn events(&self) -> &[PocketOwnedEvent] {
        &self.events
    }

    pub fn redacted(&self) -> bool {
        self.redacted
    }

    pub fn into_events(self) -> Vec<PocketOwnedEvent> {
        self.events
    }
}

pub const TANGLE_GROUP_PROJECTION_TABLE: &str = "group_projection";
pub const TANGLE_GROUP_OUTBOX_TABLE: &str = "group_outbox";
pub const TANGLE_GROUP_CHECKPOINT_TABLE: &str = "group_checkpoint";
pub const TANGLE_POCKET_EXTRA_TABLES: [&str; 3] = [
    TANGLE_GROUP_PROJECTION_TABLE,
    TANGLE_GROUP_OUTBOX_TABLE,
    TANGLE_GROUP_CHECKPOINT_TABLE,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PocketQueryConfig {
    allow_scraping: bool,
    allow_scrape_if_limited_to: u32,
    allow_scrape_if_max_seconds: u64,
}

impl PocketQueryConfig {
    pub const fn new(
        allow_scraping: bool,
        allow_scrape_if_limited_to: u32,
        allow_scrape_if_max_seconds: u64,
    ) -> Self {
        Self {
            allow_scraping,
            allow_scrape_if_limited_to,
            allow_scrape_if_max_seconds,
        }
    }

    pub fn allow_scraping(self) -> bool {
        self.allow_scraping
    }

    pub fn allow_scrape_if_limited_to(self) -> u32 {
        self.allow_scrape_if_limited_to
    }

    pub fn allow_scrape_if_max_seconds(self) -> u64 {
        self.allow_scrape_if_max_seconds
    }

    pub fn exact_count(self) -> Self {
        Self::new(
            true,
            self.allow_scrape_if_limited_to,
            self.allow_scrape_if_max_seconds,
        )
    }
}

impl Default for PocketQueryConfig {
    fn default() -> Self {
        Self::new(false, 100, 3_600)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PocketDependencyBoundary {
    source_repository: &'static str,
    source_revision: &'static str,
}

impl PocketDependencyBoundary {
    pub fn current() -> Self {
        Self {
            source_repository: POCKET_SOURCE_REPOSITORY,
            source_revision: POCKET_SOURCE_REVISION,
        }
    }

    pub fn source_repository(&self) -> &'static str {
        self.source_repository
    }

    pub fn source_revision(&self) -> &'static str {
        self.source_revision
    }
}

#[derive(Clone)]
pub struct PocketStoreHandle {
    store: Arc<PocketStore>,
    sync_policy: PocketSyncPolicy,
}

impl PocketStoreHandle {
    pub fn open(config: &PocketStoreConfig) -> Result<Self, PocketStoreError> {
        std::fs::create_dir_all(config.data_directory())
            .map_err(|error| PocketStoreError::from_create_dir(config.data_directory(), error))?;
        let store = PocketStore::new(config.data_directory(), TANGLE_POCKET_EXTRA_TABLES.to_vec())
            .map_err(PocketStoreError::from_pocket)?;
        Ok(Self {
            store: Arc::new(store),
            sync_policy: config.sync_policy(),
        })
    }

    pub fn dir(&self) -> &Path {
        self.store.dir()
    }

    pub fn sync(&self) -> Result<(), PocketStoreError> {
        self.store.sync().map_err(PocketStoreError::from_pocket)
    }

    pub fn sync_policy(&self) -> PocketSyncPolicy {
        self.sync_policy
    }

    pub fn store_event(&self, event: &PocketEvent) -> Result<u64, PocketStoreError> {
        let offset = self
            .store
            .store_event(event)
            .map_err(PocketStoreError::from_pocket)?;
        self.sync_after_write()?;
        Ok(offset)
    }

    pub fn event_by_id(
        &self,
        event_id: PocketEventId,
    ) -> Result<Option<PocketOwnedEvent>, PocketStoreError> {
        self.store
            .get_event_by_id(event_id)
            .map(|event| event.map(PocketEvent::to_owned))
            .map_err(PocketStoreError::from_pocket)
    }

    pub fn event_by_offset(&self, offset: u64) -> Result<PocketOwnedEvent, PocketStoreError> {
        self.store
            .get_event_by_offset(offset)
            .map(PocketEvent::to_owned)
            .map_err(PocketStoreError::from_pocket)
    }

    pub fn find_events(
        &self,
        filter: &PocketFilter,
        query: PocketQueryConfig,
    ) -> Result<Vec<PocketOwnedEvent>, PocketStoreError> {
        self.find_events_with_screen(filter, query, |_| PocketScreenResult::Match)
            .map(PocketScreenedEvents::into_events)
    }

    pub fn find_events_with_screen<F>(
        &self,
        filter: &PocketFilter,
        query: PocketQueryConfig,
        screen: F,
    ) -> Result<PocketScreenedEvents, PocketStoreError>
    where
        F: Fn(&PocketEvent) -> PocketScreenResult,
    {
        let (events, redacted) = self
            .store
            .find_events(
                filter,
                query.allow_scraping(),
                query.allow_scrape_if_limited_to(),
                query.allow_scrape_if_max_seconds(),
                screen,
            )
            .map_err(PocketStoreError::from_pocket)?;
        Ok(PocketScreenedEvents::new(
            events.into_iter().map(PocketEvent::to_owned).collect(),
            redacted,
        ))
    }

    pub fn count_events(
        &self,
        filter: &PocketFilter,
        query: PocketQueryConfig,
    ) -> Result<u64, PocketStoreError> {
        self.find_events(filter, query)
            .map(|events| u64::try_from(events.len()).expect("usize count fits in u64"))
    }

    pub fn scan_events(&self) -> Result<Vec<PocketStoredEvent>, PocketStoreError> {
        self.scan_events_after(None)
    }

    pub fn scan_events_after(
        &self,
        last_offset: Option<u64>,
    ) -> Result<Vec<PocketStoredEvent>, PocketStoreError> {
        let stats = self.store.stats().map_err(PocketStoreError::from_pocket)?;
        let end = u64::try_from(stats.event_bytes)
            .map_err(|_| PocketStoreError::invalid("Pocket event map size exceeds u64"))?;
        let mut offset = match last_offset {
            Some(offset) => {
                let event = self
                    .store
                    .get_event_by_offset(offset)
                    .map_err(PocketStoreError::from_pocket)?;
                next_event_offset(offset, event)?
            }
            None => event_map_start_offset(),
        };
        let mut events = Vec::new();
        while offset < end {
            let event = self
                .store
                .get_event_by_offset(offset)
                .map_err(PocketStoreError::from_pocket)?;
            events.push(PocketStoredEvent::new(offset, event.to_owned()));
            offset = next_event_offset(offset, event)?;
        }
        Ok(events)
    }

    pub fn put_extra_record(
        &self,
        table: &'static str,
        key: &[u8],
        value: &[u8],
    ) -> Result<(), PocketStoreError> {
        let table_handle = self.extra_table(table)?;
        let mut txn = self.store.write_txn().map_err(|error| {
            PocketStoreError::from_extra_table(table, "write transaction", error)
        })?;
        table_handle
            .put(&mut txn, key, value)
            .map_err(|error| PocketStoreError::from_extra_table(table, "put", error))?;
        txn.commit()
            .map_err(|error| PocketStoreError::from_extra_table(table, "commit", error))?;
        self.sync_after_write()
    }

    pub fn get_extra_record(
        &self,
        table: &'static str,
        key: &[u8],
    ) -> Result<Option<Vec<u8>>, PocketStoreError> {
        let table_handle = self.extra_table(table)?;
        let txn = self.store.read_txn().map_err(|error| {
            PocketStoreError::from_extra_table(table, "read transaction", error)
        })?;
        table_handle
            .get(&txn, key)
            .map(|value| value.map(<[u8]>::to_vec))
            .map_err(|error| PocketStoreError::from_extra_table(table, "get", error))
    }

    pub fn delete_extra_record(
        &self,
        table: &'static str,
        key: &[u8],
    ) -> Result<(), PocketStoreError> {
        let table_handle = self.extra_table(table)?;
        let mut txn = self.store.write_txn().map_err(|error| {
            PocketStoreError::from_extra_table(table, "write transaction", error)
        })?;
        table_handle
            .delete(&mut txn, key)
            .map_err(|error| PocketStoreError::from_extra_table(table, "delete", error))?;
        txn.commit()
            .map_err(|error| PocketStoreError::from_extra_table(table, "commit", error))?;
        self.sync_after_write()
    }

    pub fn scan_extra_records(
        &self,
        table: &'static str,
    ) -> Result<PocketExtraRecords, PocketStoreError> {
        let table_handle = self.extra_table(table)?;
        let txn = self.store.read_txn().map_err(|error| {
            PocketStoreError::from_extra_table(table, "read transaction", error)
        })?;
        let mut records = Vec::new();
        let iter = table_handle
            .iter(&txn)
            .map_err(|error| PocketStoreError::from_extra_table(table, "scan", error))?;
        for item in iter {
            let (key, value) =
                item.map_err(|error| PocketStoreError::from_extra_table(table, "scan", error))?;
            records.push((key.to_vec(), value.to_vec()));
        }
        Ok(records)
    }

    fn extra_table(&self, table: &'static str) -> Result<Database<Bytes, Bytes>, PocketStoreError> {
        self.store
            .extra_table(table)
            .ok_or_else(|| PocketStoreError::missing_table(table))
    }

    fn sync_after_write(&self) -> Result<(), PocketStoreError> {
        match self.sync_policy {
            PocketSyncPolicy::FlushOnWrite => self.sync(),
            PocketSyncPolicy::FlushOnShutdown => Ok(()),
        }
    }
}

pub fn parse_pocket_event_json(raw: &[u8]) -> Result<PocketOwnedEvent, PocketStoreError> {
    if raw.is_empty() {
        return Err(PocketStoreError::invalid(
            "pocket event JSON must not be empty",
        ));
    }
    let mut buffer = vec![0; pocket_json_buffer_len(raw.len())];
    let (_, event) =
        PocketEvent::from_json(raw, &mut buffer).map_err(PocketStoreError::from_pocket_types)?;
    Ok(event.to_owned())
}

pub fn parse_pocket_filter_json(raw: &[u8]) -> Result<PocketOwnedFilter, PocketStoreError> {
    if raw.is_empty() {
        return Err(PocketStoreError::invalid(
            "pocket filter JSON must not be empty",
        ));
    }
    let mut buffer = vec![0; pocket_json_buffer_len(raw.len())];
    let (_, _, filter) =
        PocketFilter::from_json(raw, &mut buffer).map_err(PocketStoreError::from_pocket_types)?;
    Ok(filter.to_owned())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PocketSyncPolicy {
    FlushOnWrite,
    FlushOnShutdown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PocketStoreConfig {
    data_directory: PathBuf,
    sync_policy: PocketSyncPolicy,
}

impl PocketStoreConfig {
    pub fn new(
        data_directory: impl Into<PathBuf>,
        sync_policy: PocketSyncPolicy,
    ) -> Result<Self, PocketConfigError> {
        let config = Self {
            data_directory: data_directory.into(),
            sync_policy,
        };
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), PocketConfigError> {
        if self.data_directory.as_os_str().is_empty() {
            return Err(PocketConfigError::invalid(
                "pocket.data_directory must not be empty",
            ));
        }
        Ok(())
    }

    pub fn data_directory(&self) -> &Path {
        &self.data_directory
    }

    pub fn sync_policy(&self) -> PocketSyncPolicy {
        self.sync_policy
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PocketConfigError {
    message: String,
}

impl PocketConfigError {
    pub fn invalid(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for PocketConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for PocketConfigError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PocketStoreError {
    message: String,
}

impl PocketStoreError {
    pub fn invalid(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    pub fn from_create_dir(path: &Path, error: io::Error) -> Self {
        Self {
            message: format!(
                "failed to create Pocket store directory {}: {error}",
                path.display()
            ),
        }
    }

    pub fn from_pocket(error: pocket_db::Error) -> Self {
        Self {
            message: error.to_string(),
        }
    }

    pub fn from_pocket_types(error: pocket_types::Error) -> Self {
        Self {
            message: error.to_string(),
        }
    }

    pub fn missing_table(table: &'static str) -> Self {
        Self {
            message: format!("missing Pocket extra table {table}"),
        }
    }

    pub fn from_extra_table(
        table: &'static str,
        operation: &'static str,
        error: impl fmt::Display,
    ) -> Self {
        Self {
            message: format!("Pocket extra table {table} {operation} failed: {error}"),
        }
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for PocketStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for PocketStoreError {}

fn pocket_json_buffer_len(raw_len: usize) -> usize {
    raw_len.saturating_mul(2).max(4096)
}

fn event_map_start_offset() -> u64 {
    u64::try_from(std::mem::size_of::<usize>()).expect("usize header size fits u64")
}

fn align_event_offset(offset: u64) -> u64 {
    if offset.is_multiple_of(8) {
        offset
    } else {
        offset + (8 - offset % 8)
    }
}

fn next_event_offset(offset: u64, event: &PocketEvent) -> Result<u64, PocketStoreError> {
    let next = offset
        .checked_add(event_len_u64(event)?)
        .ok_or_else(|| PocketStoreError::invalid("Pocket event offset exceeds u64"))?;
    Ok(align_event_offset(next))
}

fn event_len_u64(event: &PocketEvent) -> Result<u64, PocketStoreError> {
    u64::try_from(event.len())
        .map_err(|_| PocketStoreError::invalid("Pocket event size exceeds u64"))
}

#[cfg(test)]
mod tests {
    use super::{
        POCKET_SOURCE_REPOSITORY, POCKET_SOURCE_REVISION, PocketDependencyBoundary,
        PocketQueryConfig, PocketStoreConfig, PocketStoreHandle, PocketSyncPolicy,
        TANGLE_GROUP_CHECKPOINT_TABLE, TANGLE_GROUP_OUTBOX_TABLE, TANGLE_GROUP_PROJECTION_TABLE,
        TANGLE_POCKET_EXTRA_TABLES, parse_pocket_event_json, parse_pocket_filter_json,
    };
    use pocket_db::ScreenResult;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn pocket_dependency_boundary_pins_triesap_revision() {
        let boundary = PocketDependencyBoundary::current();

        assert_eq!(
            boundary.source_repository(),
            "https://github.com/triesap/pocket"
        );
        assert_eq!(boundary.source_repository(), POCKET_SOURCE_REPOSITORY);
        assert_eq!(
            boundary.source_revision(),
            "329334f20948c796c6016b673b92551ac4855ad7"
        );
        assert_eq!(boundary.source_revision(), POCKET_SOURCE_REVISION);
    }

    #[test]
    fn pocket_dependency_boundary_matches_manifest_and_lock_state() {
        let store_manifest = include_str!("../Cargo.toml");
        let groups_manifest = include_str!("../../tangle_groups/Cargo.toml");
        let lockfile = include_str!("../../../Cargo.lock");
        let approved_source = format!("git = \"{}\"", POCKET_SOURCE_REPOSITORY);
        let approved_revision = format!("rev = \"{}\"", POCKET_SOURCE_REVISION);
        let approved_lock_source = format!(
            "git+{}?rev={}#{}",
            POCKET_SOURCE_REPOSITORY, POCKET_SOURCE_REVISION, POCKET_SOURCE_REVISION
        );

        for manifest in [store_manifest, groups_manifest] {
            assert!(!manifest.contains("mikedilger/pocket"));
            assert!(manifest.contains(&approved_source));
            assert!(manifest.contains(&approved_revision));
        }
        assert!(!lockfile.contains("mikedilger/pocket"));
        assert!(lockfile.contains(&approved_lock_source));
    }

    #[test]
    fn pocket_query_config_exact_count_enables_scrape_scan() {
        let config = PocketQueryConfig::new(false, 7, 11).exact_count();

        assert!(config.allow_scraping());
        assert_eq!(config.allow_scrape_if_limited_to(), 7);
        assert_eq!(config.allow_scrape_if_max_seconds(), 11);
    }

    #[test]
    fn pocket_store_handle_opens_syncs_and_exposes_tangle_tables() {
        let root = std::env::temp_dir().join(format!("tangle-pocket-store-{}", std::process::id()));
        let config = PocketStoreConfig::new(root.join("pocket"), PocketSyncPolicy::FlushOnShutdown)
            .expect("config");

        let handle = PocketStoreHandle::open(&config).expect("open");

        assert_eq!(handle.dir(), config.data_directory());
        assert_eq!(handle.sync_policy(), PocketSyncPolicy::FlushOnShutdown);
        assert_eq!(
            TANGLE_POCKET_EXTRA_TABLES,
            ["group_projection", "group_outbox", "group_checkpoint"]
        );
        handle.sync().expect("sync");

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn pocket_store_handle_clones_share_one_store_boundary() {
        let root = temp_root("tangle-pocket-shared");
        let config = PocketStoreConfig::new(root.join("pocket"), PocketSyncPolicy::FlushOnShutdown)
            .expect("config");
        let writer = PocketStoreHandle::open(&config).expect("open");
        let reader = writer.clone();
        let event = parse_pocket_event_json(event_json().as_bytes()).expect("event");
        let filter = parse_pocket_filter_json(filter_json().as_bytes()).expect("filter");

        let offset = writer.store_event(&event).expect("store");
        let stored = reader.event_by_offset(offset).expect("offset");
        let found = reader
            .find_events(&filter, PocketQueryConfig::default())
            .expect("find");

        assert_eq!(stored.id(), event.id());
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].id(), event.id());

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn pocket_store_handle_stores_queries_and_counts_events() {
        let root = std::env::temp_dir().join(format!("tangle-pocket-query-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let config = PocketStoreConfig::new(root.join("pocket"), PocketSyncPolicy::FlushOnShutdown)
            .expect("config");
        let handle = PocketStoreHandle::open(&config).expect("open");
        let event = parse_pocket_event_json(event_json().as_bytes()).expect("event");
        let filter = parse_pocket_filter_json(filter_json().as_bytes()).expect("filter");

        let offset = handle.store_event(&event).expect("store");
        let stored = handle
            .event_by_id(event.id())
            .expect("lookup")
            .expect("event");
        let offset_event = handle.event_by_offset(offset).expect("offset lookup");
        let found = handle
            .find_events(&filter, PocketQueryConfig::default())
            .expect("find");

        assert_eq!(stored.id(), event.id());
        assert_eq!(offset_event.id(), event.id());
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].id(), event.id());
        assert_eq!(
            handle
                .count_events(&filter, PocketQueryConfig::default())
                .expect("count"),
            1
        );

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn pocket_store_handle_scans_canonical_events_with_offsets() {
        let root = temp_root("tangle-pocket-scan");
        let config = PocketStoreConfig::new(root.join("pocket"), PocketSyncPolicy::FlushOnShutdown)
            .expect("config");
        let handle = PocketStoreHandle::open(&config).expect("open");
        let first =
            parse_pocket_event_json(event_json_with("a", "1", "first").as_bytes()).expect("first");
        let second = parse_pocket_event_json(event_json_with("c", "2", "second").as_bytes())
            .expect("second");

        let first_offset = handle.store_event(&first).expect("store first");
        let second_offset = handle.store_event(&second).expect("store second");
        let all = handle.scan_events().expect("scan");
        let after_first = handle
            .scan_events_after(Some(first_offset))
            .expect("scan after first");

        assert_eq!(all.len(), 2);
        assert_eq!(all[0].store_offset(), first_offset);
        assert_eq!(all[0].event().id(), first.id());
        assert_eq!(all[1].store_offset(), second_offset);
        assert_eq!(all[1].event().id(), second.id());
        assert_eq!(after_first.len(), 1);
        assert_eq!(after_first[0].store_offset(), second_offset);
        assert_eq!(after_first[0].event().id(), second.id());

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn pocket_store_handle_screens_events_before_materialization() {
        let root = temp_root("tangle-pocket-screen");
        let config = PocketStoreConfig::new(root.join("pocket"), PocketSyncPolicy::FlushOnShutdown)
            .expect("config");
        let handle = PocketStoreHandle::open(&config).expect("open");
        let visible = parse_pocket_event_json(event_json_with("a", "1", "visible").as_bytes())
            .expect("visible");
        let redacted = parse_pocket_event_json(event_json_with("c", "2", "redacted").as_bytes())
            .expect("redacted");
        let filter = parse_pocket_filter_json(kind_filter_json().as_bytes()).expect("filter");

        handle.store_event(&visible).expect("store visible");
        handle.store_event(&redacted).expect("store redacted");

        let screened = handle
            .find_events_with_screen(&filter, PocketQueryConfig::default(), |event| {
                if event.id() == visible.id() {
                    ScreenResult::Match
                } else {
                    ScreenResult::Redacted
                }
            })
            .expect("screened");

        assert!(screened.redacted());
        assert_eq!(screened.events().len(), 1);
        assert_eq!(screened.events()[0].id(), visible.id());

        let mismatched = handle
            .find_events_with_screen(&filter, PocketQueryConfig::default(), |event| {
                if event.id() == visible.id() {
                    ScreenResult::Match
                } else {
                    ScreenResult::Mismatch
                }
            })
            .expect("mismatched");

        assert!(!mismatched.redacted());
        assert_eq!(mismatched.events().len(), 1);
        assert_eq!(mismatched.events()[0].id(), visible.id());

        let hidden = handle
            .find_events_with_screen(&filter, PocketQueryConfig::default(), |_| {
                ScreenResult::Mismatch
            })
            .expect("hidden");

        assert!(!hidden.redacted());
        assert!(hidden.events().is_empty());

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn pocket_store_handle_rejects_duplicate_event_writes_without_duplicate_materialization() {
        let root = temp_root("tangle-pocket-duplicate");
        let config = PocketStoreConfig::new(root.join("pocket"), PocketSyncPolicy::FlushOnShutdown)
            .expect("config");
        let handle = PocketStoreHandle::open(&config).expect("open");
        let event = parse_pocket_event_json(event_json().as_bytes()).expect("event");
        let filter = parse_pocket_filter_json(filter_json().as_bytes()).expect("filter");

        let first_offset = handle.store_event(&event).expect("store first");
        let duplicate_error = handle.store_event(&event).expect_err("duplicate");
        let by_id = handle
            .event_by_id(event.id())
            .expect("lookup")
            .expect("event");
        let by_offset = handle.event_by_offset(first_offset).expect("offset");
        let found = handle
            .find_events(&filter, PocketQueryConfig::default())
            .expect("find");
        let scanned = handle.scan_events().expect("scan");

        assert!(
            duplicate_error
                .message()
                .to_lowercase()
                .contains("duplicate")
        );
        assert_eq!(by_id.id(), event.id());
        assert_eq!(by_offset.id(), event.id());
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].id(), event.id());
        assert_eq!(scanned.len(), 1);
        assert_eq!(scanned[0].store_offset(), first_offset);
        assert_eq!(scanned[0].event().id(), event.id());

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn pocket_store_query_config_controls_scraping() {
        let root = temp_root("tangle-pocket-query-config");
        let config = PocketStoreConfig::new(root.join("pocket"), PocketSyncPolicy::FlushOnShutdown)
            .expect("config");
        let handle = PocketStoreHandle::open(&config).expect("open");
        let event =
            parse_pocket_event_json(event_json_with("f", "6", "scrape").as_bytes()).expect("event");
        let broad = parse_pocket_filter_json(r#"{"limit":1}"#.as_bytes()).expect("filter");

        handle.store_event(&event).expect("store");

        assert!(
            handle
                .find_events(&broad, PocketQueryConfig::new(false, 0, 0))
                .expect_err("scrape rejected")
                .message()
                .contains("scraper")
        );
        let found = handle
            .find_events(&broad, PocketQueryConfig::new(false, 1, 0))
            .expect("limited scrape");

        assert_eq!(found.len(), 1);
        assert_eq!(found[0].id(), event.id());

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn pocket_store_handle_persists_extra_table_records() {
        let root = temp_root("tangle-pocket-extra");
        let config = PocketStoreConfig::new(root.join("pocket"), PocketSyncPolicy::FlushOnShutdown)
            .expect("config");
        let handle = PocketStoreHandle::open(&config).expect("open");

        handle
            .put_extra_record(TANGLE_GROUP_PROJECTION_TABLE, b"group\0Farm", b"state-v1")
            .expect("put projection");
        handle
            .put_extra_record(TANGLE_GROUP_PROJECTION_TABLE, b"group\0Farm", b"state-v2")
            .expect("update projection");
        handle
            .put_extra_record(TANGLE_GROUP_OUTBOX_TABLE, b"outbox\0b", b"record-1")
            .expect("put outbox one");
        handle
            .put_extra_record(TANGLE_GROUP_OUTBOX_TABLE, b"outbox\0a", b"record-0")
            .expect("put outbox zero");
        handle
            .put_extra_record(
                TANGLE_GROUP_CHECKPOINT_TABLE,
                b"checkpoint\0groups",
                b"checkpoint",
            )
            .expect("put checkpoint");

        assert_eq!(
            handle
                .get_extra_record(TANGLE_GROUP_PROJECTION_TABLE, b"group\0Farm")
                .expect("get projection"),
            Some(b"state-v2".to_vec())
        );
        assert_eq!(
            handle
                .scan_extra_records(TANGLE_GROUP_OUTBOX_TABLE)
                .expect("scan outbox"),
            vec![
                (b"outbox\0a".to_vec(), b"record-0".to_vec()),
                (b"outbox\0b".to_vec(), b"record-1".to_vec()),
            ]
        );
        handle
            .delete_extra_record(TANGLE_GROUP_PROJECTION_TABLE, b"group\0Farm")
            .expect("delete projection");
        assert_eq!(
            handle
                .get_extra_record(TANGLE_GROUP_PROJECTION_TABLE, b"group\0Farm")
                .expect("deleted projection"),
            None
        );
        drop(handle);

        let reopened = PocketStoreHandle::open(&config).expect("reopen");
        assert_eq!(
            reopened
                .get_extra_record(TANGLE_GROUP_CHECKPOINT_TABLE, b"checkpoint\0groups")
                .expect("checkpoint"),
            Some(b"checkpoint".to_vec())
        );

        drop(reopened);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn pocket_store_handle_flush_on_write_syncs_written_events_and_extra_records() {
        let root = temp_root("tangle-pocket-flush-write");
        let config = PocketStoreConfig::new(root.join("pocket"), PocketSyncPolicy::FlushOnWrite)
            .expect("config");
        let handle = PocketStoreHandle::open(&config).expect("open");
        let event =
            parse_pocket_event_json(event_json_with("e", "5", "flush").as_bytes()).expect("event");

        let offset = handle.store_event(&event).expect("store");
        handle
            .put_extra_record(
                TANGLE_GROUP_CHECKPOINT_TABLE,
                b"checkpoint\0flush",
                b"flushed",
            )
            .expect("checkpoint");
        drop(handle);

        let reopened = PocketStoreHandle::open(&config).expect("reopen");
        let by_id = reopened
            .event_by_id(event.id())
            .expect("lookup")
            .expect("event");
        let by_offset = reopened.event_by_offset(offset).expect("offset");

        assert_eq!(by_id.id(), event.id());
        assert_eq!(by_offset.id(), event.id());
        assert_eq!(
            reopened
                .get_extra_record(TANGLE_GROUP_CHECKPOINT_TABLE, b"checkpoint\0flush")
                .expect("checkpoint"),
            Some(b"flushed".to_vec())
        );

        drop(reopened);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn pocket_store_handle_syncs_written_events_and_extra_records() {
        let root = temp_root("tangle-pocket-sync");
        let config = PocketStoreConfig::new(root.join("pocket"), PocketSyncPolicy::FlushOnShutdown)
            .expect("config");
        let handle = PocketStoreHandle::open(&config).expect("open");
        let event =
            parse_pocket_event_json(event_json_with("d", "4", "synced").as_bytes()).expect("event");

        let offset = handle.store_event(&event).expect("store");
        handle
            .put_extra_record(
                TANGLE_GROUP_CHECKPOINT_TABLE,
                b"checkpoint\0sync",
                b"synced",
            )
            .expect("checkpoint");
        handle.sync().expect("sync");
        drop(handle);

        let reopened = PocketStoreHandle::open(&config).expect("reopen");
        let by_id = reopened
            .event_by_id(event.id())
            .expect("lookup")
            .expect("event");
        let by_offset = reopened.event_by_offset(offset).expect("offset");

        assert_eq!(by_id.id(), event.id());
        assert_eq!(by_offset.id(), event.id());
        assert_eq!(
            reopened
                .get_extra_record(TANGLE_GROUP_CHECKPOINT_TABLE, b"checkpoint\0sync")
                .expect("checkpoint"),
            Some(b"synced".to_vec())
        );

        drop(reopened);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn pocket_store_config_preserves_explicit_storage_boundary() {
        let config = PocketStoreConfig::new(
            "runtime/radroots/tangle/pocket",
            PocketSyncPolicy::FlushOnShutdown,
        )
        .expect("config");

        assert_eq!(
            config.data_directory().to_string_lossy(),
            "runtime/radroots/tangle/pocket"
        );
        assert_eq!(config.sync_policy(), PocketSyncPolicy::FlushOnShutdown);
    }

    #[test]
    fn pocket_store_config_rejects_implicit_storage_values() {
        assert_eq!(
            PocketStoreConfig::new("", PocketSyncPolicy::FlushOnWrite)
                .expect_err("error")
                .message(),
            "pocket.data_directory must not be empty"
        );
    }

    fn event_json() -> String {
        event_json_with("a", "1", "hello")
    }

    fn event_json_with(id_hex: &str, pubkey_hex: &str, content: &str) -> String {
        format!(
            r#"{{
                "id":"{}",
                "pubkey":"{}",
                "created_at":1714124433,
                "kind":1,
                "tags":[["t","radroots"]],
                "content":"{}",
                "sig":"{}"
            }}"#,
            id_hex.repeat(64),
            pubkey_hex.repeat(64),
            content,
            "b".repeat(128)
        )
    }

    fn filter_json() -> String {
        r#"{"ids":["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],"limit":10}"#
            .to_owned()
    }

    fn kind_filter_json() -> String {
        r#"{"kinds":[1],"limit":10}"#.to_owned()
    }

    fn temp_root(prefix: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "{}-{}-{}",
            prefix,
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system time")
                .as_nanos()
        ))
    }
}
