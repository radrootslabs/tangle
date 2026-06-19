#![forbid(unsafe_code)]

pub mod backup;
pub(crate) mod client_message;
pub mod config;
pub mod errors;
pub mod event_bus;
pub mod export;
pub mod groups;
pub mod host;
pub mod logging;
pub mod nip11;
pub mod ops;
pub(crate) mod pocket_conversion;
pub(crate) mod pocket_event_validation;
pub mod rate_limits;
pub mod relay;
pub mod resource_limits;
pub mod runtime;
pub mod server;
pub mod session;
pub mod tenant;

use std::{fmt, fs, path::Path, path::PathBuf};

use config::{
    TangleHostRuntimeConfigSet, parse_tangle_host_runtime_config_json,
    parse_tenant_runtime_config_json,
};
use errors::BaseRelayError;

pub const TANGLE_RELAY_SOFTWARE: &str = "https://github.com/radrootslabs/tangle";
pub const TANGLE_RELAY_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug)]
pub enum TangleRuntimeLoadError {
    ReadConfig {
        path: PathBuf,
        source: std::io::Error,
    },
    ReadTenantConfigDir {
        path: PathBuf,
        source: std::io::Error,
    },
    ReadTenantConfig {
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
            Self::ReadTenantConfigDir { path, source } => {
                write!(
                    formatter,
                    "failed to read tangle tenant config directory `{}`: {source}",
                    path.display()
                )
            }
            Self::ReadTenantConfig { path, source } => {
                write!(
                    formatter,
                    "failed to read tangle tenant config `{}`: {source}",
                    path.display()
                )
            }
            Self::ParseConfig(error) => write!(formatter, "{error}"),
            Self::OpenRelay(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for TangleRuntimeLoadError {}

pub fn load_tangle_host_runtime_config(
    path: impl AsRef<Path>,
) -> Result<TangleHostRuntimeConfigSet, TangleRuntimeLoadError> {
    let path = path.as_ref();
    let raw = fs::read_to_string(path).map_err(|source| TangleRuntimeLoadError::ReadConfig {
        path: path.to_path_buf(),
        source,
    })?;
    let host =
        parse_tangle_host_runtime_config_json(&raw).map_err(TangleRuntimeLoadError::ParseConfig)?;
    let config_dir = resolve_config_path(path.parent(), host.tenant_config_dir());
    let mut tenant_paths = fs::read_dir(&config_dir)
        .map_err(|source| TangleRuntimeLoadError::ReadTenantConfigDir {
            path: config_dir.clone(),
            source,
        })?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source| TangleRuntimeLoadError::ReadTenantConfigDir {
            path: config_dir.clone(),
            source,
        })?;
    tenant_paths.retain(|path| {
        path.is_file()
            && path
                .extension()
                .is_some_and(|extension| extension == "json")
    });
    tenant_paths.sort();
    let mut tenants = Vec::with_capacity(tenant_paths.len());
    for tenant_path in tenant_paths {
        let raw = fs::read_to_string(&tenant_path).map_err(|source| {
            TangleRuntimeLoadError::ReadTenantConfig {
                path: tenant_path.clone(),
                source,
            }
        })?;
        let tenant =
            parse_tenant_runtime_config_json(&raw).map_err(TangleRuntimeLoadError::ParseConfig)?;
        tenants.push(tenant);
    }
    TangleHostRuntimeConfigSet::new(host, tenants).map_err(TangleRuntimeLoadError::ParseConfig)
}

fn resolve_config_path(base: Option<&Path>, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else if let Some(base) = base {
        base.join(path)
    } else {
        path.to_path_buf()
    }
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
