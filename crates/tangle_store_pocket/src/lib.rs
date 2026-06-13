#![forbid(unsafe_code)]

use core::fmt;
use pocket_db::Store;
use pocket_types::{Event, Filter, Id, Pubkey};
use std::{
    io,
    path::{Path, PathBuf},
};

pub const POCKET_SOURCE_REPOSITORY: &str = "https://github.com/triesap/pocket";
pub const POCKET_SOURCE_REVISION: &str = "329334f20948c796c6016b673b92551ac4855ad7";

pub type PocketEvent = Event;
pub type PocketEventId = Id;
pub type PocketFilter = Filter;
pub type PocketPubkey = Pubkey;
pub type PocketStore = Store;

pub const TANGLE_POCKET_EXTRA_TABLES: [&str; 3] =
    ["group_projection", "group_outbox", "group_checkpoint"];

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

pub struct PocketStoreHandle {
    store: PocketStore,
}

impl PocketStoreHandle {
    pub fn open(config: &PocketStoreConfig) -> Result<Self, PocketStoreError> {
        std::fs::create_dir_all(config.data_directory())
            .map_err(|error| PocketStoreError::from_create_dir(config.data_directory(), error))?;
        let store = PocketStore::new(config.data_directory(), TANGLE_POCKET_EXTRA_TABLES.to_vec())
            .map_err(PocketStoreError::from_pocket)?;
        Ok(Self { store })
    }

    pub fn dir(&self) -> &Path {
        self.store.dir()
    }

    pub fn sync(&self) -> Result<(), PocketStoreError> {
        self.store.sync().map_err(PocketStoreError::from_pocket)
    }

    pub fn into_inner(self) -> PocketStore {
        self.store
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PocketSyncPolicy {
    FlushOnWrite,
    FlushOnShutdown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PocketStoreConfig {
    data_directory: PathBuf,
    map_size_bytes: u64,
    reader_slots: u32,
    sync_policy: PocketSyncPolicy,
}

impl PocketStoreConfig {
    pub fn new(
        data_directory: impl Into<PathBuf>,
        map_size_bytes: u64,
        reader_slots: u32,
        sync_policy: PocketSyncPolicy,
    ) -> Result<Self, PocketConfigError> {
        let config = Self {
            data_directory: data_directory.into(),
            map_size_bytes,
            reader_slots,
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
        if self.map_size_bytes == 0 {
            return Err(PocketConfigError::invalid(
                "pocket.map_size_bytes must be greater than zero",
            ));
        }
        if self.reader_slots == 0 {
            return Err(PocketConfigError::invalid(
                "pocket.reader_slots must be greater than zero",
            ));
        }
        Ok(())
    }

    pub fn data_directory(&self) -> &Path {
        &self.data_directory
    }

    pub fn map_size_bytes(&self) -> u64 {
        self.map_size_bytes
    }

    pub fn reader_slots(&self) -> u32 {
        self.reader_slots
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

#[cfg(test)]
mod tests {
    use super::{
        POCKET_SOURCE_REPOSITORY, POCKET_SOURCE_REVISION, PocketDependencyBoundary,
        PocketStoreConfig, PocketStoreHandle, PocketSyncPolicy, TANGLE_POCKET_EXTRA_TABLES,
    };

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
    fn pocket_store_handle_opens_syncs_and_exposes_tangle_tables() {
        let root = std::env::temp_dir().join(format!("tangle-pocket-store-{}", std::process::id()));
        let config = PocketStoreConfig::new(
            root.join("pocket"),
            1024 * 1024 * 1024,
            128,
            PocketSyncPolicy::FlushOnShutdown,
        )
        .expect("config");

        let handle = PocketStoreHandle::open(&config).expect("open");

        assert_eq!(handle.dir(), config.data_directory());
        assert_eq!(
            TANGLE_POCKET_EXTRA_TABLES,
            ["group_projection", "group_outbox", "group_checkpoint"]
        );
        handle.sync().expect("sync");

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn pocket_store_config_preserves_explicit_storage_boundary() {
        let config = PocketStoreConfig::new(
            "runtime/radroots/tangle/pocket",
            1024 * 1024 * 1024,
            128,
            PocketSyncPolicy::FlushOnShutdown,
        )
        .expect("config");

        assert_eq!(
            config.data_directory().to_string_lossy(),
            "runtime/radroots/tangle/pocket"
        );
        assert_eq!(config.map_size_bytes(), 1024 * 1024 * 1024);
        assert_eq!(config.reader_slots(), 128);
        assert_eq!(config.sync_policy(), PocketSyncPolicy::FlushOnShutdown);
    }

    #[test]
    fn pocket_store_config_rejects_implicit_storage_values() {
        assert_eq!(
            PocketStoreConfig::new("", 1, 1, PocketSyncPolicy::FlushOnWrite)
                .expect_err("error")
                .message(),
            "pocket.data_directory must not be empty"
        );
        assert_eq!(
            PocketStoreConfig::new(
                "runtime/radroots/tangle/pocket",
                0,
                1,
                PocketSyncPolicy::FlushOnWrite
            )
            .expect_err("error")
            .message(),
            "pocket.map_size_bytes must be greater than zero"
        );
        assert_eq!(
            PocketStoreConfig::new(
                "runtime/radroots/tangle/pocket",
                1,
                0,
                PocketSyncPolicy::FlushOnWrite
            )
            .expect_err("error")
            .message(),
            "pocket.reader_slots must be greater than zero"
        );
    }
}
