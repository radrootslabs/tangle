#![forbid(unsafe_code)]

pub mod chorus_pocket;
pub mod config;
pub mod errors;
pub mod event_bus;
pub mod groups;
pub mod logging;
pub mod nip11;
pub mod ops;
pub(crate) mod pocket_conversion;
pub mod rate_limits;
pub mod relay;
pub mod runtime;
pub mod server;
pub mod session;

use std::{fmt, fs, path::Path, path::PathBuf};

use config::{BaseRelayRuntimeConfig, parse_base_relay_runtime_config_json};
use errors::BaseRelayError;
use runtime::TangleRuntime;

pub const TANGLE_RELAY_SOFTWARE: &str = "https://github.com/radrootslabs/tangle";
pub const TANGLE_RELAY_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug)]
pub enum TangleRuntimeLoadError {
    ReadConfig {
        path: PathBuf,
        source: std::io::Error,
    },
    ParseConfig(BaseRelayError),
    OpenRelay(BaseRelayError),
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

pub fn open_tangle_runtime_from_config_path(
    path: impl AsRef<Path>,
) -> Result<TangleRuntime, TangleRuntimeLoadError> {
    let config = load_base_relay_runtime_config(path)?;
    TangleRuntime::open(config).map_err(TangleRuntimeLoadError::OpenRelay)
}
