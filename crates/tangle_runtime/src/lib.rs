#![forbid(unsafe_code)]

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

#[cfg(test)]
mod tests {
    use crate::pocket_conversion::{pocket_event_to_tangle, tangle_event_to_pocket};
    use tangle_protocol::{Tag, event_from_value, event_to_value};
    use tangle_test_support::{FixtureKey, tangle_v2_event};

    #[test]
    fn pocket_event_conversion_accepts_protocol_event_json_shapes() {
        let event = tangle_v2_event(
            FixtureKey::Owner,
            1_714_124_433,
            30_402,
            vec![
                Tag::from_parts("d", &["market"]).expect("d"),
                Tag::from_parts("t", &["radroots", "farm"]).expect("t"),
            ],
            "json parity",
        )
        .expect("event");
        let parsed = event_from_value(&event_to_value(&event)).expect("parsed");
        let pocket = tangle_event_to_pocket(&parsed).expect("pocket");
        let converted = pocket_event_to_tangle(&pocket).expect("converted");

        assert_eq!(parsed, event);
        assert_eq!(converted, event);
    }
}
