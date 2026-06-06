#![forbid(unsafe_code)]

use std::fmt;

pub const PACKAGE_NAME: &str = env!("CARGO_PKG_NAME");
pub const PACKAGE_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const USAGE: &str = "\
usage: tangle [--version] <command> [--config PATH]

commands:
  migrate
  run
  event import
  event export
  projection rebuild";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TangleCommand {
    Version,
    Help,
    Migrate,
    Run,
    EventImport,
    EventExport,
    ProjectionRebuild,
}

impl TangleCommand {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Version => "version",
            Self::Help => "help",
            Self::Migrate => "migrate",
            Self::Run => "run",
            Self::EventImport => "event import",
            Self::EventExport => "event export",
            Self::ProjectionRebuild => "projection rebuild",
        }
    }

    pub fn implemented(self) -> bool {
        matches!(self, Self::Version | Self::Help | Self::Migrate | Self::Run)
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
    MissingNestedCommand(&'static str),
    MissingOptionValue(&'static str),
    RepeatedOption(&'static str),
    UnexpectedArgument { command: String, argument: String },
}

impl fmt::Display for TangleCliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownCommand(command) => write!(formatter, "unknown command: {command}"),
            Self::MissingNestedCommand(command) => {
                write!(formatter, "{command} command requires a nested command")
            }
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
        "migrate" => TangleCommand::Migrate,
        "run" => TangleCommand::Run,
        "event" => {
            let Some(nested) = args.next() else {
                return Err(TangleCliError::MissingNestedCommand("event"));
            };
            match nested.as_str() {
                "import" => TangleCommand::EventImport,
                "export" => TangleCommand::EventExport,
                _ => return Err(TangleCliError::UnknownCommand(format!("event {nested}"))),
            }
        }
        "projection" => {
            let Some(nested) = args.next() else {
                return Err(TangleCliError::MissingNestedCommand("projection"));
            };
            match nested.as_str() {
                "rebuild" => TangleCommand::ProjectionRebuild,
                _ => {
                    return Err(TangleCliError::UnknownCommand(format!(
                        "projection {nested}"
                    )));
                }
            }
        }
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
    Ok(TangleInvocation::new(command, config_path))
}

pub fn require_config_path(invocation: &TangleInvocation) -> Result<&str, TangleCliError> {
    invocation
        .config_path()
        .ok_or(TangleCliError::MissingOptionValue("--config"))
}

pub fn migrate_output(report: tangle_runtime::RuntimeMigrationReport) -> String {
    format!(
        "migrations applied: {}\nmigrations already applied: {}\nmigrations total: {}",
        report.applied(),
        report.already_applied(),
        report.total()
    )
}

pub async fn migrate_with_config(path: &str) -> Result<String, String> {
    let config = tangle_runtime::load_runtime_config(path).map_err(|error| error.to_string())?;
    let report = tangle_runtime::migrate_runtime_database(&config)
        .await
        .map_err(|error| error.to_string())?;
    Ok(migrate_output(report))
}

pub async fn run_with_config(path: &str) -> Result<(), String> {
    let config = tangle_runtime::load_runtime_config(path).map_err(|error| error.to_string())?;
    let (shutdown, _) = tangle_runtime::GracefulShutdownSignal::new();
    let signal = shutdown.clone();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            signal.request_shutdown();
        }
    });
    tangle_runtime::run_runtime_server(config, shutdown)
        .await
        .map(|_| ())
        .map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::{
        PACKAGE_NAME, PACKAGE_VERSION, TangleCliError, TangleCommand, TangleInvocation,
        migrate_output, parse_tangle_command, parse_tangle_invocation, require_config_path,
        usage_output, version_output,
    };
    use tangle_runtime::RuntimeMigrationReport;

    #[test]
    fn package_name_is_tangle() {
        assert_eq!(PACKAGE_NAME, "tangle");
    }

    #[test]
    fn package_version_matches_manifest() {
        assert_eq!(PACKAGE_VERSION, "0.1.0");
    }

    #[test]
    fn version_output_contains_package_and_version() {
        assert_eq!(version_output(), "tangle 0.1.0");
    }

    #[test]
    fn usage_output_lists_supported_command_model() {
        assert_eq!(
            usage_output(),
            "usage: tangle [--version] <command> [--config PATH]\n\ncommands:\n  migrate\n  run\n  event import\n  event export\n  projection rebuild"
        );
    }

    #[test]
    fn command_model_parses_known_commands() {
        let cases = [
            (Vec::<&str>::new(), TangleCommand::Help),
            (vec!["--version"], TangleCommand::Version),
            (vec!["-V"], TangleCommand::Version),
            (vec!["--help"], TangleCommand::Help),
            (vec!["help"], TangleCommand::Help),
            (vec!["migrate"], TangleCommand::Migrate),
            (vec!["run"], TangleCommand::Run),
            (vec!["event", "import"], TangleCommand::EventImport),
            (vec!["event", "export"], TangleCommand::EventExport),
            (
                vec!["projection", "rebuild"],
                TangleCommand::ProjectionRebuild,
            ),
        ];

        for (args, expected) in cases {
            assert_eq!(parse_tangle_command(args).expect("command"), expected);
            assert_eq!(
                expected.implemented(),
                matches!(
                    expected,
                    TangleCommand::Version
                        | TangleCommand::Help
                        | TangleCommand::Migrate
                        | TangleCommand::Run
                )
            );
        }
    }

    #[test]
    fn command_model_parses_common_config_option() {
        assert_eq!(
            parse_tangle_invocation(["migrate", "--config", "runtime.json"]).expect("invocation"),
            TangleInvocation::new(TangleCommand::Migrate, Some("runtime.json".to_owned()))
        );
        assert_eq!(
            require_config_path(&TangleInvocation::new(
                TangleCommand::Migrate,
                Some("runtime.json".to_owned())
            ))
            .expect("config"),
            "runtime.json"
        );
        assert_eq!(
            require_config_path(&TangleInvocation::new(TangleCommand::Migrate, None))
                .expect_err("config"),
            TangleCliError::MissingOptionValue("--config")
        );
    }

    #[test]
    fn command_model_rejects_unknown_or_extra_arguments() {
        assert_eq!(
            parse_tangle_command(["unknown"]).expect_err("unknown"),
            TangleCliError::UnknownCommand("unknown".to_owned())
        );
        assert_eq!(
            parse_tangle_command(["event"]).expect_err("nested"),
            TangleCliError::MissingNestedCommand("event")
        );
        assert_eq!(
            parse_tangle_command(["projection", "bad"]).expect_err("projection"),
            TangleCliError::UnknownCommand("projection bad".to_owned())
        );
        assert_eq!(
            parse_tangle_command(["run", "--extra"]).expect_err("extra"),
            TangleCliError::UnexpectedArgument {
                command: "run".to_owned(),
                argument: "--extra".to_owned()
            }
        );
        assert_eq!(
            parse_tangle_invocation(["migrate", "--config"]).expect_err("missing config"),
            TangleCliError::MissingOptionValue("--config")
        );
        assert_eq!(
            parse_tangle_invocation(["migrate", "--config", "a", "--config", "b"])
                .expect_err("repeated config"),
            TangleCliError::RepeatedOption("--config")
        );
    }

    #[test]
    fn migrate_output_reports_outcome_counts() {
        assert_eq!(
            migrate_output(RuntimeMigrationReport::new(8, 2, 10)),
            "migrations applied: 8\nmigrations already applied: 2\nmigrations total: 10"
        );
    }
}
