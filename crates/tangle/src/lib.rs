#![forbid(unsafe_code)]

use std::fmt;

pub const PACKAGE_NAME: &str = env!("CARGO_PKG_NAME");
pub const PACKAGE_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const USAGE: &str = "\
usage: tangle [--version] <command>

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
        matches!(self, Self::Version | Self::Help)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TangleCliError {
    UnknownCommand(String),
    MissingNestedCommand(&'static str),
    UnexpectedArgument { command: String, argument: String },
}

impl fmt::Display for TangleCliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownCommand(command) => write!(formatter, "unknown command: {command}"),
            Self::MissingNestedCommand(command) => {
                write!(formatter, "{command} command requires a nested command")
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
    let mut args = args.into_iter().map(Into::into);
    let Some(first) = args.next() else {
        return Ok(TangleCommand::Help);
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
    if let Some(argument) = args.next() {
        return Err(TangleCliError::UnexpectedArgument {
            command: command.as_str().to_owned(),
            argument,
        });
    }
    Ok(command)
}

#[cfg(test)]
mod tests {
    use super::{
        PACKAGE_NAME, PACKAGE_VERSION, TangleCliError, TangleCommand, parse_tangle_command,
        usage_output, version_output,
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
    fn usage_output_lists_supported_command_model() {
        assert_eq!(
            usage_output(),
            "usage: tangle [--version] <command>\n\ncommands:\n  migrate\n  run\n  event import\n  event export\n  projection rebuild"
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
                matches!(expected, TangleCommand::Version | TangleCommand::Help)
            );
        }
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
    }
}
