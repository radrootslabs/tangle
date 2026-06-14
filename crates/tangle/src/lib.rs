#![forbid(unsafe_code)]

use std::fmt;

pub const PACKAGE_NAME: &str = env!("CARGO_PKG_NAME");
pub const PACKAGE_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const USAGE: &str = "\
usage:
  tangle [--version]
  tangle run --config PATH";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TangleCommand {
    Version,
    Help,
    Run,
}

impl TangleCommand {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Version => "version",
            Self::Help => "help",
            Self::Run => "run",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TangleInvocation {
    command: TangleCommand,
    config_path: Option<String>,
}

impl TangleInvocation {
    pub fn new(command: TangleCommand, config_path: Option<String>) -> Self {
        Self {
            command,
            config_path,
        }
    }

    pub fn command(&self) -> TangleCommand {
        self.command
    }

    pub fn config_path(&self) -> Option<&str> {
        self.config_path.as_deref()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TangleCliError {
    UnknownCommand(String),
    MissingOptionValue(&'static str),
    RepeatedOption(&'static str),
    UnexpectedArgument { command: String, argument: String },
}

impl fmt::Display for TangleCliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownCommand(command) => write!(formatter, "unknown command: {command}"),
            Self::MissingOptionValue(option) => {
                write!(formatter, "{option} requires a value")
            }
            Self::RepeatedOption(option) => {
                write!(formatter, "{option} must not be repeated")
            }
            Self::UnexpectedArgument { command, argument } => {
                write!(
                    formatter,
                    "{command} command does not accept argument: {argument}"
                )
            }
        }
    }
}

impl std::error::Error for TangleCliError {}

pub fn version_output() -> String {
    format!("{PACKAGE_NAME} {PACKAGE_VERSION}")
}

pub fn usage_output() -> &'static str {
    USAGE
}

pub fn parse_tangle_command<I, S>(args: I) -> Result<TangleCommand, TangleCliError>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    parse_tangle_invocation(args).map(|invocation| invocation.command)
}

pub fn parse_tangle_invocation<I, S>(args: I) -> Result<TangleInvocation, TangleCliError>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let mut args = args.into_iter().map(Into::into);
    let Some(first) = args.next() else {
        return Ok(TangleInvocation::new(TangleCommand::Help, None));
    };
    let command = match first.as_str() {
        "--version" | "-V" => TangleCommand::Version,
        "--help" | "-h" | "help" => TangleCommand::Help,
        "run" => TangleCommand::Run,
        _ => return Err(TangleCliError::UnknownCommand(first)),
    };
    let mut config_path = None;
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--config" => {
                if config_path.is_some() {
                    return Err(TangleCliError::RepeatedOption("--config"));
                }
                let Some(path) = args.next() else {
                    return Err(TangleCliError::MissingOptionValue("--config"));
                };
                config_path = Some(path);
            }
            _ => {
                return Err(TangleCliError::UnexpectedArgument {
                    command: command.as_str().to_owned(),
                    argument,
                });
            }
        }
    }
    if config_path.is_some() && command != TangleCommand::Run {
        return Err(TangleCliError::UnexpectedArgument {
            command: command.as_str().to_owned(),
            argument: "--config".to_owned(),
        });
    }
    Ok(TangleInvocation::new(command, config_path))
}

pub fn require_config_path(invocation: &TangleInvocation) -> Result<&str, TangleCliError> {
    invocation
        .config_path()
        .ok_or(TangleCliError::MissingOptionValue("--config"))
}

pub async fn run_with_config(
    config_path: &str,
) -> Result<tangle_runtime::server::TangleServeReport, String> {
    let config = tangle_runtime::load_base_relay_runtime_config(config_path)
        .map_err(|error| error.to_string())?;
    tangle_runtime::logging::init_tangle_tracing(config.tracing())
        .map_err(|error| error.to_string())?;
    tangle_runtime::logging::log_runtime_config_loaded(&config);
    let runtime =
        tangle_runtime::runtime::TangleRuntime::open(config).map_err(|error| error.to_string())?;
    tangle_runtime::server::serve_until_shutdown(runtime)
        .await
        .map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::{
        PACKAGE_NAME, PACKAGE_VERSION, TangleCliError, TangleCommand, TangleInvocation,
        parse_tangle_invocation, require_config_path, usage_output, version_output,
    };

    #[test]
    fn package_constants_track_cargo_metadata() {
        assert_eq!(PACKAGE_NAME, "tangle");
        assert_eq!(PACKAGE_VERSION, "0.1.0");
        assert_eq!(version_output(), "tangle 0.1.0");
    }

    #[test]
    fn usage_lists_only_v2_command_surface() {
        assert_eq!(
            usage_output(),
            "usage:\n  tangle [--version]\n  tangle run --config PATH"
        );
    }

    #[test]
    fn parse_tangle_invocation_accepts_help_version_and_run() {
        assert_eq!(
            parse_tangle_invocation(Vec::<&str>::new()).expect("empty"),
            TangleInvocation::new(TangleCommand::Help, None)
        );
        assert_eq!(
            parse_tangle_invocation(["--version"]).expect("version"),
            TangleInvocation::new(TangleCommand::Version, None)
        );
        assert_eq!(
            parse_tangle_invocation(["run", "--config", "ops/production/tangle-v2.example.json"])
                .expect("run"),
            TangleInvocation::new(
                TangleCommand::Run,
                Some("ops/production/tangle-v2.example.json".to_owned())
            )
        );
    }

    #[test]
    fn parse_tangle_invocation_rejects_removed_command_surface() {
        for args in [
            vec!["migrate"],
            vec!["event", "import"],
            vec!["event", "export"],
            vec!["projection", "rebuild"],
            vec!["ops", "backup"],
            vec!["ops", "restore"],
        ] {
            assert!(matches!(
                parse_tangle_invocation(args).expect_err("removed"),
                TangleCliError::UnknownCommand(_)
            ));
        }
    }

    #[test]
    fn parse_tangle_invocation_validates_config_option() {
        assert_eq!(
            parse_tangle_invocation(["run", "--config"]).expect_err("missing"),
            TangleCliError::MissingOptionValue("--config")
        );
        assert_eq!(
            parse_tangle_invocation(["run", "--config", "a", "--config", "b"]).expect_err("repeat"),
            TangleCliError::RepeatedOption("--config")
        );
        assert_eq!(
            parse_tangle_invocation(["--version", "--config", "runtime.json"]).expect_err("config"),
            TangleCliError::UnexpectedArgument {
                command: "version".to_owned(),
                argument: "--config".to_owned(),
            }
        );
    }

    #[test]
    fn require_config_path_reports_missing_value() {
        assert_eq!(
            require_config_path(&TangleInvocation::new(TangleCommand::Run, None))
                .expect_err("config"),
            TangleCliError::MissingOptionValue("--config")
        );
    }
}
