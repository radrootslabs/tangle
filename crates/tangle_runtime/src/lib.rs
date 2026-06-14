#![forbid(unsafe_code)]

pub mod chorus_pocket;
pub mod config;
pub mod errors;
pub mod event_bus;
pub mod groups;
pub mod nip11;
pub mod ops;
pub(crate) mod pocket_conversion;
pub mod relay;
pub mod runtime;

use std::{fmt, fs, path::Path, path::PathBuf};

use config::{BaseRelayRuntimeConfig, parse_base_relay_runtime_config_json};
use errors::BaseRelayError;
use ops::BaseRelayReadinessState;
use runtime::TangleRuntime;

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
    pub(crate) fn new(
        relay_url: impl Into<String>,
        data_directory: PathBuf,
        groups_enabled: bool,
        readiness: BaseRelayReadinessState,
    ) -> Self {
        Self {
            relay_url: relay_url.into(),
            data_directory,
            groups_enabled,
            readiness,
        }
    }

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
    let mut runtime = open_tangle_runtime_from_config_path(path)?;
    let report = runtime.startup_report();
    runtime
        .shutdown()
        .map_err(TangleRuntimeLoadError::ShutdownRelay)?;
    Ok(report)
}

pub fn open_tangle_runtime_from_config_path(
    path: impl AsRef<Path>,
) -> Result<TangleRuntime, TangleRuntimeLoadError> {
    let config = load_base_relay_runtime_config(path)?;
    TangleRuntime::open(config).map_err(TangleRuntimeLoadError::OpenRelay)
}
