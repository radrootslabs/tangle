use core::fmt;
use std::path::{Path, PathBuf};
use tangle_groups::GroupRuntimeConfig;
use tangle_store_pocket::{PocketStoreConfig, PocketStoreError, PocketStoreHandle};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChorusPocketRuntimeConfig {
    pocket: PocketStoreConfig,
    groups: GroupRuntimeConfig,
}

impl ChorusPocketRuntimeConfig {
    pub fn new(pocket: PocketStoreConfig, groups: GroupRuntimeConfig) -> Self {
        Self { pocket, groups }
    }

    pub fn pocket(&self) -> &PocketStoreConfig {
        &self.pocket
    }

    pub fn groups(&self) -> &GroupRuntimeConfig {
        &self.groups
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChorusPocketStartupReport {
    store_directory: PathBuf,
    groups_enabled: bool,
}

impl ChorusPocketStartupReport {
    pub fn store_directory(&self) -> &Path {
        &self.store_directory
    }

    pub fn groups_enabled(&self) -> bool {
        self.groups_enabled
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChorusPocketRuntimeError {
    message: String,
}

impl ChorusPocketRuntimeError {
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for ChorusPocketRuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for ChorusPocketRuntimeError {}

impl From<PocketStoreError> for ChorusPocketRuntimeError {
    fn from(error: PocketStoreError) -> Self {
        Self {
            message: error.to_string(),
        }
    }
}

pub fn probe_chorus_pocket_startup(
    config: &ChorusPocketRuntimeConfig,
) -> Result<ChorusPocketStartupReport, ChorusPocketRuntimeError> {
    let store = PocketStoreHandle::open(config.pocket())?;
    store.sync()?;
    Ok(ChorusPocketStartupReport {
        store_directory: store.dir().to_path_buf(),
        groups_enabled: config.groups().enabled(),
    })
}

#[cfg(test)]
mod tests {
    use super::{ChorusPocketRuntimeConfig, probe_chorus_pocket_startup};
    use tangle_groups::parse_group_runtime_config_json;
    use tangle_store_pocket::{PocketStoreConfig, PocketSyncPolicy};

    #[test]
    fn chorus_pocket_startup_probe_opens_store_and_reports_group_state() {
        let root = std::env::temp_dir().join(format!(
            "tangle-chorus-pocket-runtime-{}",
            std::process::id()
        ));
        let pocket = PocketStoreConfig::new(
            root.join("pocket"),
            1024 * 1024 * 1024,
            128,
            PocketSyncPolicy::FlushOnShutdown,
        )
        .expect("pocket");
        let groups = parse_group_runtime_config_json(r#"{"enabled": false}"#).expect("groups");
        let config = ChorusPocketRuntimeConfig::new(pocket.clone(), groups);

        let report = probe_chorus_pocket_startup(&config).expect("startup");

        assert_eq!(report.store_directory(), pocket.data_directory());
        assert!(!report.groups_enabled());

        let _ = std::fs::remove_dir_all(root);
    }
}
