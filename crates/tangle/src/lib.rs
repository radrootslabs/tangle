#![forbid(unsafe_code)]

use std::fmt;

pub const PACKAGE_NAME: &str = env!("CARGO_PKG_NAME");
pub const PACKAGE_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const USAGE: &str = "\
usage:
  tangle [--version]
  tangle migrate --config PATH
  tangle run --config PATH
  tangle event import --config PATH --input PATH
  tangle event export --config PATH --output PATH
  tangle projection rebuild --config PATH";

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
        matches!(
            self,
            Self::Version
                | Self::Help
                | Self::Migrate
                | Self::Run
                | Self::EventImport
                | Self::EventExport
                | Self::ProjectionRebuild
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TangleInvocation {
    command: TangleCommand,
    config_path: Option<String>,
    input_path: Option<String>,
    output_path: Option<String>,
}

impl TangleInvocation {
    pub fn new(command: TangleCommand, config_path: Option<String>) -> Self {
        Self {
            command,
            config_path,
            input_path: None,
            output_path: None,
        }
    }

    pub fn with_input_path(mut self, input_path: Option<String>) -> Self {
        self.input_path = input_path;
        self
    }

    pub fn with_output_path(mut self, output_path: Option<String>) -> Self {
        self.output_path = output_path;
        self
    }

    pub fn command(&self) -> TangleCommand {
        self.command
    }

    pub fn config_path(&self) -> Option<&str> {
        self.config_path.as_deref()
    }

    pub fn input_path(&self) -> Option<&str> {
        self.input_path.as_deref()
    }

    pub fn output_path(&self) -> Option<&str> {
        self.output_path.as_deref()
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
    let mut input_path = None;
    let mut output_path = None;
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
            "--input" => {
                if input_path.is_some() {
                    return Err(TangleCliError::RepeatedOption("--input"));
                }
                let Some(path) = args.next() else {
                    return Err(TangleCliError::MissingOptionValue("--input"));
                };
                input_path = Some(path);
            }
            "--output" => {
                if output_path.is_some() {
                    return Err(TangleCliError::RepeatedOption("--output"));
                }
                let Some(path) = args.next() else {
                    return Err(TangleCliError::MissingOptionValue("--output"));
                };
                output_path = Some(path);
            }
            _ => {
                return Err(TangleCliError::UnexpectedArgument {
                    command: command.as_str().to_owned(),
                    argument,
                });
            }
        }
    }
    if input_path.is_some() && command != TangleCommand::EventImport {
        return Err(TangleCliError::UnexpectedArgument {
            command: command.as_str().to_owned(),
            argument: "--input".to_owned(),
        });
    }
    if output_path.is_some() && command != TangleCommand::EventExport {
        return Err(TangleCliError::UnexpectedArgument {
            command: command.as_str().to_owned(),
            argument: "--output".to_owned(),
        });
    }
    Ok(TangleInvocation::new(command, config_path)
        .with_input_path(input_path)
        .with_output_path(output_path))
}

pub fn require_config_path(invocation: &TangleInvocation) -> Result<&str, TangleCliError> {
    invocation
        .config_path()
        .ok_or(TangleCliError::MissingOptionValue("--config"))
}

pub fn require_input_path(invocation: &TangleInvocation) -> Result<&str, TangleCliError> {
    invocation
        .input_path()
        .ok_or(TangleCliError::MissingOptionValue("--input"))
}

pub fn require_output_path(invocation: &TangleInvocation) -> Result<&str, TangleCliError> {
    invocation
        .output_path()
        .ok_or(TangleCliError::MissingOptionValue("--output"))
}

pub fn migrate_output(report: tangle_runtime::RuntimeMigrationReport) -> String {
    format!(
        "migrations applied: {}\nmigrations already applied: {}\nmigrations total: {}",
        report.applied(),
        report.already_applied(),
        report.total()
    )
}

pub fn event_import_output(report: tangle_runtime::RuntimeEventImportReport) -> String {
    format!(
        "events total: {}\nevents inserted: {}\nevents duplicate: {}\nevents projected: {}\nevents skipped: {}",
        report.total(),
        report.inserted(),
        report.duplicate(),
        report.projected(),
        report.skipped()
    )
}

pub fn event_export_output(report: tangle_runtime::RuntimeEventExportReport) -> String {
    format!("events exported: {}", report.exported())
}

pub fn projection_rebuild_output(report: tangle_runtime::RuntimeProjectionRebuildReport) -> String {
    format!(
        "events scanned: {}\nevents rebuilt: {}\nlistings projected: {}\nevents skipped: {}",
        report.scanned(),
        report.rebuilt(),
        report.projected(),
        report.skipped()
    )
}

pub async fn migrate_with_config(path: &str) -> Result<String, String> {
    let config = tangle_runtime::load_runtime_config(path).map_err(|error| error.to_string())?;
    initialize_tracing(config.tracing_config())?;
    let report = tangle_runtime::migrate_runtime_database(&config)
        .await
        .map_err(|error| error.to_string())?;
    Ok(migrate_output(report))
}

pub async fn event_import_with_config(
    config_path: &str,
    input_path: &str,
) -> Result<String, String> {
    let config =
        tangle_runtime::load_runtime_config(config_path).map_err(|error| error.to_string())?;
    initialize_tracing(config.tracing_config())?;
    let report = tangle_runtime::import_events_from_path(&config, input_path)
        .await
        .map_err(|error| error.to_string())?;
    Ok(event_import_output(report))
}

pub async fn event_export_with_config(
    config_path: &str,
    output_path: &str,
) -> Result<String, String> {
    let config =
        tangle_runtime::load_runtime_config(config_path).map_err(|error| error.to_string())?;
    initialize_tracing(config.tracing_config())?;
    let report = tangle_runtime::export_events_to_path(&config, output_path)
        .await
        .map_err(|error| error.to_string())?;
    Ok(event_export_output(report))
}

pub async fn projection_rebuild_with_config(config_path: &str) -> Result<String, String> {
    let config =
        tangle_runtime::load_runtime_config(config_path).map_err(|error| error.to_string())?;
    initialize_tracing(config.tracing_config())?;
    let report = tangle_runtime::rebuild_projections(&config)
        .await
        .map_err(|error| error.to_string())?;
    Ok(projection_rebuild_output(report))
}

pub async fn run_with_config(path: &str) -> Result<(), String> {
    let config = tangle_runtime::load_runtime_config(path).map_err(|error| error.to_string())?;
    initialize_tracing(config.tracing_config())?;
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

fn initialize_tracing(config: &tangle_runtime::RuntimeTracingConfig) -> Result<(), String> {
    if !config.enabled() {
        return Ok(());
    }
    let filter = tracing_subscriber::EnvFilter::try_new(config.filter())
        .map_err(|error| format!("tracing filter is invalid: {error}"))?;
    match config.format() {
        tangle_runtime::RuntimeTracingFormat::Compact => {
            let _ = tracing_subscriber::fmt()
                .with_env_filter(filter)
                .with_writer(std::io::stderr)
                .try_init();
        }
        tangle_runtime::RuntimeTracingFormat::Json => {
            let _ = tracing_subscriber::fmt()
                .with_env_filter(filter)
                .with_writer(std::io::stderr)
                .json()
                .try_init();
        }
    }
    tracing::info!(
        filter = config.filter(),
        format = config.format().as_str(),
        "tracing initialized"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        PACKAGE_NAME, PACKAGE_VERSION, TangleCliError, TangleCommand, TangleInvocation,
        event_export_output, event_import_output, initialize_tracing, migrate_output,
        parse_tangle_command, parse_tangle_invocation, projection_rebuild_output,
        require_config_path, require_input_path, require_output_path, usage_output, version_output,
    };
    use tangle_runtime::{
        RuntimeEventExportReport, RuntimeEventImportReport, RuntimeMigrationReport,
        RuntimeProjectionRebuildReport, RuntimeTracingConfig, RuntimeTracingFormat,
    };

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
    fn tracing_setup_ignores_disabled_config_and_rejects_bad_filters() {
        assert_eq!(
            initialize_tracing(&RuntimeTracingConfig::disabled()),
            Ok(())
        );
        let invalid =
            RuntimeTracingConfig::new(true, "bad[", RuntimeTracingFormat::Compact).expect("config");
        assert!(
            initialize_tracing(&invalid)
                .expect_err("invalid filter")
                .starts_with("tracing filter is invalid:")
        );
    }

    #[test]
    fn usage_output_lists_supported_command_model() {
        assert_eq!(
            usage_output(),
            "usage:\n  tangle [--version]\n  tangle migrate --config PATH\n  tangle run --config PATH\n  tangle event import --config PATH --input PATH\n  tangle event export --config PATH --output PATH\n  tangle projection rebuild --config PATH"
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
                        | TangleCommand::EventImport
                        | TangleCommand::EventExport
                        | TangleCommand::ProjectionRebuild
                )
            );
        }
    }

    #[test]
    fn command_model_parses_export_output_option() {
        let invocation = parse_tangle_invocation([
            "event",
            "export",
            "--config",
            "runtime.json",
            "--output",
            "events.jsonl",
        ])
        .expect("invocation");
        assert_eq!(invocation.command(), TangleCommand::EventExport);
        assert_eq!(
            require_config_path(&invocation).expect("config"),
            "runtime.json"
        );
        assert_eq!(
            require_output_path(&invocation).expect("output"),
            "events.jsonl"
        );
        assert_eq!(
            require_output_path(&TangleInvocation::new(TangleCommand::EventExport, None))
                .expect_err("output"),
            TangleCliError::MissingOptionValue("--output")
        );
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
    fn command_model_parses_import_input_option() {
        let invocation = parse_tangle_invocation([
            "event",
            "import",
            "--config",
            "runtime.json",
            "--input",
            "events.jsonl",
        ])
        .expect("invocation");
        assert_eq!(invocation.command(), TangleCommand::EventImport);
        assert_eq!(
            require_config_path(&invocation).expect("config"),
            "runtime.json"
        );
        assert_eq!(
            require_input_path(&invocation).expect("input"),
            "events.jsonl"
        );
        assert_eq!(
            require_input_path(&TangleInvocation::new(TangleCommand::EventImport, None))
                .expect_err("input"),
            TangleCliError::MissingOptionValue("--input")
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
        assert_eq!(
            parse_tangle_invocation(["migrate", "--input", "events.jsonl"]).expect_err("input"),
            TangleCliError::UnexpectedArgument {
                command: "migrate".to_owned(),
                argument: "--input".to_owned()
            }
        );
        assert_eq!(
            parse_tangle_invocation(["event", "import", "--input"]).expect_err("missing input"),
            TangleCliError::MissingOptionValue("--input")
        );
        assert_eq!(
            parse_tangle_invocation(["event", "import", "--input", "a", "--input", "b"])
                .expect_err("repeated input"),
            TangleCliError::RepeatedOption("--input")
        );
        assert_eq!(
            parse_tangle_invocation(["run", "--output", "events.jsonl"]).expect_err("output"),
            TangleCliError::UnexpectedArgument {
                command: "run".to_owned(),
                argument: "--output".to_owned()
            }
        );
        assert_eq!(
            parse_tangle_invocation(["event", "export", "--output"]).expect_err("missing output"),
            TangleCliError::MissingOptionValue("--output")
        );
        assert_eq!(
            parse_tangle_invocation(["event", "export", "--output", "a", "--output", "b"])
                .expect_err("repeated output"),
            TangleCliError::RepeatedOption("--output")
        );
    }

    #[test]
    fn migrate_output_reports_outcome_counts() {
        assert_eq!(
            migrate_output(RuntimeMigrationReport::new(8, 2, 10)),
            "migrations applied: 8\nmigrations already applied: 2\nmigrations total: 10"
        );
    }

    #[test]
    fn event_import_output_reports_outcome_counts() {
        assert_eq!(
            event_import_output(RuntimeEventImportReport::new(5, 2, 1, 2, 2)),
            "events total: 5\nevents inserted: 2\nevents duplicate: 1\nevents projected: 2\nevents skipped: 2"
        );
    }

    #[test]
    fn event_export_output_reports_outcome_counts() {
        assert_eq!(
            event_export_output(RuntimeEventExportReport::new(3)),
            "events exported: 3"
        );
    }

    #[test]
    fn projection_rebuild_output_reports_outcome_counts() {
        assert_eq!(
            projection_rebuild_output(RuntimeProjectionRebuildReport::new(4, 3, 2, 1)),
            "events scanned: 4\nevents rebuilt: 3\nlistings projected: 2\nevents skipped: 1"
        );
    }
}
