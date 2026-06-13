#![forbid(unsafe_code)]

use core::fmt;
use std::path::{Path, PathBuf};

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

#[cfg(test)]
mod tests {
    use super::{PocketStoreConfig, PocketSyncPolicy};

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
