#![forbid(unsafe_code)]

pub mod base_relay;
pub mod chorus_pocket;

use std::{fmt, fs, path::Path, path::PathBuf};

use base_relay::{
    BaseRelayError, BaseRelayReadinessState, BaseRelayRuntimeConfig,
    parse_base_relay_runtime_config_json,
};

pub const TANGLE_SUPPORTED_NIPS: [u16; 6] = [1, 11, 29, 42, 45, 70];
pub const TANGLE_RELAY_SOFTWARE: &str = "https://github.com/radrootslabs/tangle";
pub const TANGLE_RELAY_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TangleRuntimeStartupReport {
    relay_url: String,
    data_directory: PathBuf,
    groups_enabled: bool,
    readiness: BaseRelayReadinessState,
}

impl TangleRuntimeStartupReport {
    pub fn relay_url(&self) -> &str {
        &self.relay_url
    }

    pub fn data_directory(&self) -> &Path {
        &self.data_directory
    }

    pub fn groups_enabled(&self) -> bool {
        self.groups_enabled
    }

    pub fn readiness(&self) -> &BaseRelayReadinessState {
        &self.readiness
    }
}

#[derive(Debug)]
pub enum TangleRuntimeLoadError {
    ReadConfig {
        path: PathBuf,
        source: std::io::Error,
    },
    ParseConfig(BaseRelayError),
    OpenRelay(BaseRelayError),
    ShutdownRelay(BaseRelayError),
}

impl fmt::Display for TangleRuntimeLoadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReadConfig { path, source } => {
                write!(
                    formatter,
                    "failed to read tangle runtime config `{}`: {source}",
                    path.display()
                )
            }
            Self::ParseConfig(error) => write!(formatter, "{error}"),
            Self::OpenRelay(error) => write!(formatter, "{error}"),
            Self::ShutdownRelay(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for TangleRuntimeLoadError {}

pub fn load_base_relay_runtime_config(
    path: impl AsRef<Path>,
) -> Result<BaseRelayRuntimeConfig, TangleRuntimeLoadError> {
    let path = path.as_ref();
    let raw = fs::read_to_string(path).map_err(|source| TangleRuntimeLoadError::ReadConfig {
        path: path.to_path_buf(),
        source,
    })?;
    parse_base_relay_runtime_config_json(&raw).map_err(TangleRuntimeLoadError::ParseConfig)
}

pub fn open_base_relay_from_config_path(
    path: impl AsRef<Path>,
) -> Result<TangleRuntimeStartupReport, TangleRuntimeLoadError> {
    let config = load_base_relay_runtime_config(path)?;
    let mut relay = config
        .open_relay()
        .map_err(TangleRuntimeLoadError::OpenRelay)?;
    let readiness = relay.readiness_state();
    relay
        .shutdown()
        .map_err(TangleRuntimeLoadError::ShutdownRelay)?;
    Ok(TangleRuntimeStartupReport {
        relay_url: config.relay_url().to_owned(),
        data_directory: config.pocket_config().data_directory().to_path_buf(),
        groups_enabled: config.groups().enabled(),
        readiness,
    })
}
