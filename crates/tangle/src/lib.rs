#![forbid(unsafe_code)]

use std::fmt;

pub const PACKAGE_NAME: &str = env!("CARGO_PKG_NAME");
pub const PACKAGE_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const USAGE: &str = "\
usage:
  tangle [--version]
  tangle run --config PATH
  tangle config validate --config PATH
  tangle config inspect --config PATH --redacted
  tangle tenant list --config PATH
  tangle tenant backup --config PATH --tenant TENANT_ID --output PATH
  tangle tenant restore --config PATH --tenant TENANT_ID --input PATH --target-data-dir PATH
  tangle tenant export --config PATH --tenant TENANT_ID --output PATH";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TangleCommand {
    Version,
    Help,
    Run,
    ConfigValidate,
    ConfigInspect,
    TenantList,
    TenantBackup,
    TenantRestore,
    TenantExport,
}

impl TangleCommand {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Version => "version",
            Self::Help => "help",
            Self::Run => "run",
            Self::ConfigValidate => "config validate",
            Self::ConfigInspect => "config inspect",
            Self::TenantList => "tenant list",
            Self::TenantBackup => "tenant backup",
            Self::TenantRestore => "tenant restore",
            Self::TenantExport => "tenant export",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TangleInvocation {
    command: TangleCommand,
    config_path: Option<String>,
    tenant_id: Option<String>,
    input_path: Option<String>,
    output_path: Option<String>,
    target_data_dir: Option<String>,
    redacted: bool,
    include_secrets: bool,
}

impl TangleInvocation {
    pub fn new(command: TangleCommand, config_path: Option<String>) -> Self {
        Self::new_with_options(command, config_path, false)
    }

    pub fn new_with_options(
        command: TangleCommand,
        config_path: Option<String>,
        redacted: bool,
    ) -> Self {
        Self {
            command,
            config_path,
            tenant_id: None,
            input_path: None,
            output_path: None,
            target_data_dir: None,
            redacted,
            include_secrets: false,
        }
    }

    pub fn new_with_admin_options(
        command: TangleCommand,
        config_path: Option<String>,
        tenant_id: Option<String>,
        input_path: Option<String>,
        output_path: Option<String>,
        target_data_dir: Option<String>,
        include_secrets: bool,
    ) -> Self {
        Self {
            command,
            config_path,
            tenant_id,
            input_path,
            output_path,
            target_data_dir,
            redacted: false,
            include_secrets,
        }
    }

    pub fn command(&self) -> TangleCommand {
        self.command
    }

    pub fn config_path(&self) -> Option<&str> {
        self.config_path.as_deref()
    }

    pub fn tenant_id(&self) -> Option<&str> {
        self.tenant_id.as_deref()
    }

    pub fn input_path(&self) -> Option<&str> {
        self.input_path.as_deref()
    }

    pub fn output_path(&self) -> Option<&str> {
        self.output_path.as_deref()
    }

    pub fn target_data_dir(&self) -> Option<&str> {
        self.target_data_dir.as_deref()
    }

    pub fn redacted(&self) -> bool {
        self.redacted
    }

    pub fn include_secrets(&self) -> bool {
        self.include_secrets
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
        "config" => match args.next().as_deref() {
            Some("validate") => TangleCommand::ConfigValidate,
            Some("inspect") => TangleCommand::ConfigInspect,
            Some(command) => {
                return Err(TangleCliError::UnknownCommand(format!("config {command}")));
            }
            None => return Err(TangleCliError::UnknownCommand("config".to_owned())),
        },
        "tenant" => match args.next().as_deref() {
            Some("list") => TangleCommand::TenantList,
            Some("backup") => TangleCommand::TenantBackup,
            Some("restore") => TangleCommand::TenantRestore,
            Some("export") => TangleCommand::TenantExport,
            Some(command) => {
                return Err(TangleCliError::UnknownCommand(format!("tenant {command}")));
            }
            None => return Err(TangleCliError::UnknownCommand("tenant".to_owned())),
        },
        _ => return Err(TangleCliError::UnknownCommand(first)),
    };
    let mut config_path = None;
    let mut tenant_id = None;
    let mut input_path = None;
    let mut output_path = None;
    let mut target_data_dir = None;
    let mut redacted = false;
    let mut include_secrets = false;
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
            "--tenant" if command_accepts_tenant(command) => {
                if tenant_id.is_some() {
                    return Err(TangleCliError::RepeatedOption("--tenant"));
                }
                let Some(value) = args.next() else {
                    return Err(TangleCliError::MissingOptionValue("--tenant"));
                };
                tenant_id = Some(value);
            }
            "--input" if command == TangleCommand::TenantRestore => {
                if input_path.is_some() {
                    return Err(TangleCliError::RepeatedOption("--input"));
                }
                let Some(path) = args.next() else {
                    return Err(TangleCliError::MissingOptionValue("--input"));
                };
                input_path = Some(path);
            }
            "--output" if command_accepts_output(command) => {
                if output_path.is_some() {
                    return Err(TangleCliError::RepeatedOption("--output"));
                }
                let Some(path) = args.next() else {
                    return Err(TangleCliError::MissingOptionValue("--output"));
                };
                output_path = Some(path);
            }
            "--target-data-dir" if command == TangleCommand::TenantRestore => {
                if target_data_dir.is_some() {
                    return Err(TangleCliError::RepeatedOption("--target-data-dir"));
                }
                let Some(path) = args.next() else {
                    return Err(TangleCliError::MissingOptionValue("--target-data-dir"));
                };
                target_data_dir = Some(path);
            }
            "--redacted" if command == TangleCommand::ConfigInspect => {
                redacted = true;
            }
            "--include-secrets" if command == TangleCommand::TenantBackup => {
                include_secrets = true;
            }
            _ => {
                return Err(TangleCliError::UnexpectedArgument {
                    command: command.as_str().to_owned(),
                    argument,
                });
            }
        }
    }
    if config_path.is_some() && !command_accepts_config(command) {
        return Err(TangleCliError::UnexpectedArgument {
            command: command.as_str().to_owned(),
            argument: "--config".to_owned(),
        });
    }
    Ok(TangleInvocation {
        command,
        config_path,
        tenant_id,
        input_path,
        output_path,
        target_data_dir,
        redacted,
        include_secrets,
    })
}

pub fn require_config_path(invocation: &TangleInvocation) -> Result<&str, TangleCliError> {
    invocation
        .config_path()
        .ok_or(TangleCliError::MissingOptionValue("--config"))
}

pub fn require_tenant_id(invocation: &TangleInvocation) -> Result<&str, TangleCliError> {
    invocation
        .tenant_id()
        .ok_or(TangleCliError::MissingOptionValue("--tenant"))
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

pub fn require_target_data_dir(invocation: &TangleInvocation) -> Result<&str, TangleCliError> {
    invocation
        .target_data_dir()
        .ok_or(TangleCliError::MissingOptionValue("--target-data-dir"))
}

pub async fn run_with_config(
    config_path: &str,
) -> Result<tangle_runtime::server::TangleServeReport, String> {
    let config_set = tangle_runtime::load_tangle_host_runtime_config(config_path)
        .map_err(|error| error.to_string())?;
    tangle_runtime::logging::init_tangle_tracing(config_set.host().tracing())
        .map_err(|error| error.to_string())?;
    for tenant in config_set.active_tenants() {
        let config = tenant.to_base_relay_runtime_config(
            config_set.host().listen_addr(),
            config_set.host().tracing().clone(),
        );
        tangle_runtime::logging::log_runtime_config_loaded(&config);
    }
    let runtime = tangle_runtime::host::TangleHostRuntime::open(config_set)
        .map_err(|error| error.to_string())?;
    tangle_runtime::server::serve_until_shutdown(runtime)
        .await
        .map_err(|error| error.to_string())
}

pub fn validate_config(config_path: &str) -> Result<(), String> {
    tangle_runtime::load_tangle_host_runtime_config(config_path)
        .map(|_| ())
        .map_err(|error| error.to_string())
}

pub fn inspect_config(config_path: &str, redacted: bool) -> Result<String, String> {
    if !redacted {
        return Err("--redacted is required".to_owned());
    }
    let config = tangle_runtime::load_tangle_host_runtime_config(config_path)
        .map_err(|error| error.to_string())?;
    let tenants = config
        .tenants()
        .iter()
        .map(|tenant| {
            serde_json::json!({
                "tenant_id": tenant.tenant_id().as_str(),
                "tenant_schema": tenant.tenant_schema().as_str(),
                "host": tenant.host().as_str(),
                "relay_url": tenant.relay_url().as_str(),
                "inactive": tenant.inactive(),
                "info": {
                    "name": tenant.info().name(),
                    "description": tenant.info().description(),
                    "contact": tenant.info().contact(),
                    "icon": tenant.info().icon()
                },
                "pocket": {
                    "data_directory": tenant.pocket_config().data_directory().display().to_string(),
                    "sync_policy": format!("{:?}", tenant.pocket_config().sync_policy())
                },
                "groups": {
                    "enabled": tenant.groups().enabled(),
                    "relay_secret": "<redacted>",
                    "relay_self": tenant.relay_self_pubkey().ok().flatten().map(|pubkey| pubkey.as_str().to_owned())
                },
                "backup_export": {
                    "backup_enabled": tenant.backup_export().backup_enabled(),
                    "export_enabled": tenant.backup_export().export_enabled()
                }
            })
        })
        .collect::<Vec<_>>();
    serde_json::to_string_pretty(&serde_json::json!({
        "listen_addr": config.host().listen_addr().to_string(),
        "tenant_config_dir": config.host().tenant_config_dir().display().to_string(),
        "limits": {
            "max_total_connections": config.host().limits().max_total_connections(),
            "max_total_subscriptions": config.host().limits().max_total_subscriptions(),
            "tenant_startup_concurrency": config.host().limits().tenant_startup_concurrency()
        },
        "ops": {
            "enabled": config.host().ops().enabled(),
            "expose_tenant_inventory": config.host().ops().expose_tenant_inventory()
        },
        "trusted_proxy": {
            "enabled": config.host().trusted_proxy().enabled(),
            "trusted_peers": config.host().trusted_proxy().trusted_peers()
        },
        "tenants": tenants
    }))
    .map_err(|error| error.to_string())
}

pub fn list_tenants(config_path: &str) -> Result<String, String> {
    let config = tangle_runtime::load_tangle_host_runtime_config(config_path)
        .map_err(|error| error.to_string())?;
    let mut lines = vec!["tenant_id\thost\tstatus\ttenant_schema".to_owned()];
    for tenant in config.tenants() {
        lines.push(format!(
            "{}\t{}\t{}\t{}",
            tenant.tenant_id().as_str(),
            tenant.host().as_str(),
            if tenant.inactive() {
                "inactive"
            } else {
                "active"
            },
            tenant.tenant_schema().as_str()
        ));
    }
    Ok(lines.join("\n"))
}

pub fn backup_tenant(
    config_path: &str,
    tenant_id: &str,
    output: &str,
    include_secrets: bool,
) -> Result<String, String> {
    let report =
        tangle_runtime::backup::backup_tenant(tangle_runtime::backup::TenantBackupRequest {
            config_path,
            tenant_id,
            output,
            include_secrets,
        })?;
    serde_json::to_string_pretty(&report).map_err(|error| error.to_string())
}

pub fn restore_tenant(
    config_path: &str,
    tenant_id: &str,
    input: &str,
    target_data_dir: &str,
) -> Result<String, String> {
    let report =
        tangle_runtime::backup::restore_tenant(tangle_runtime::backup::TenantRestoreRequest {
            config_path,
            tenant_id,
            input,
            target_data_dir,
        })?;
    serde_json::to_string_pretty(&report).map_err(|error| error.to_string())
}

pub fn export_tenant(config_path: &str, tenant_id: &str, output: &str) -> Result<String, String> {
    let report =
        tangle_runtime::export::export_tenant(tangle_runtime::export::TenantExportRequest {
            config_path,
            tenant_id,
            output,
        })?;
    serde_json::to_string_pretty(&report).map_err(|error| error.to_string())
}

fn command_accepts_config(command: TangleCommand) -> bool {
    matches!(
        command,
        TangleCommand::Run
            | TangleCommand::ConfigValidate
            | TangleCommand::ConfigInspect
            | TangleCommand::TenantList
            | TangleCommand::TenantBackup
            | TangleCommand::TenantRestore
            | TangleCommand::TenantExport
    )
}

fn command_accepts_tenant(command: TangleCommand) -> bool {
    matches!(
        command,
        TangleCommand::TenantBackup | TangleCommand::TenantRestore | TangleCommand::TenantExport
    )
}

fn command_accepts_output(command: TangleCommand) -> bool {
    matches!(
        command,
        TangleCommand::TenantBackup | TangleCommand::TenantExport
    )
}

#[cfg(test)]
mod tests {
    use super::{
        PACKAGE_NAME, PACKAGE_VERSION, TangleCliError, TangleCommand, TangleInvocation,
        inspect_config, list_tenants, parse_tangle_invocation, require_config_path,
        require_input_path, require_output_path, require_target_data_dir, require_tenant_id,
        usage_output, validate_config, version_output,
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
            "usage:\n  tangle [--version]\n  tangle run --config PATH\n  tangle config validate --config PATH\n  tangle config inspect --config PATH --redacted\n  tangle tenant list --config PATH\n  tangle tenant backup --config PATH --tenant TENANT_ID --output PATH\n  tangle tenant restore --config PATH --tenant TENANT_ID --input PATH --target-data-dir PATH\n  tangle tenant export --config PATH --tenant TENANT_ID --output PATH"
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
            parse_tangle_invocation(["run", "--config", "config/tangle.host.example.json"])
                .expect("run"),
            TangleInvocation::new(
                TangleCommand::Run,
                Some("config/tangle.host.example.json".to_owned())
            )
        );
        assert_eq!(
            parse_tangle_invocation([
                "config",
                "validate",
                "--config",
                "config/tangle.host.example.json"
            ])
            .expect("validate"),
            TangleInvocation::new(
                TangleCommand::ConfigValidate,
                Some("config/tangle.host.example.json".to_owned())
            )
        );
        assert_eq!(
            parse_tangle_invocation([
                "config",
                "inspect",
                "--config",
                "config/tangle.host.example.json",
                "--redacted"
            ])
            .expect("inspect"),
            TangleInvocation::new_with_options(
                TangleCommand::ConfigInspect,
                Some("config/tangle.host.example.json".to_owned()),
                true
            )
        );
        assert_eq!(
            parse_tangle_invocation([
                "tenant",
                "list",
                "--config",
                "config/tangle.host.example.json"
            ])
            .expect("tenant list"),
            TangleInvocation::new(
                TangleCommand::TenantList,
                Some("config/tangle.host.example.json".to_owned())
            )
        );
        assert_eq!(
            parse_tangle_invocation([
                "tenant",
                "backup",
                "--config",
                "config/tangle.host.example.json",
                "--tenant",
                "farmers-market",
                "--output",
                "backup"
            ])
            .expect("tenant backup"),
            TangleInvocation::new_with_admin_options(
                TangleCommand::TenantBackup,
                Some("config/tangle.host.example.json".to_owned()),
                Some("farmers-market".to_owned()),
                None,
                Some("backup".to_owned()),
                None,
                false
            )
        );
        assert_eq!(
            parse_tangle_invocation([
                "tenant",
                "restore",
                "--config",
                "config/tangle.host.example.json",
                "--tenant",
                "farmers-market",
                "--input",
                "backup",
                "--target-data-dir",
                "runtime/restored"
            ])
            .expect("tenant restore"),
            TangleInvocation::new_with_admin_options(
                TangleCommand::TenantRestore,
                Some("config/tangle.host.example.json".to_owned()),
                Some("farmers-market".to_owned()),
                Some("backup".to_owned()),
                None,
                Some("runtime/restored".to_owned()),
                false
            )
        );
        assert_eq!(
            parse_tangle_invocation([
                "tenant",
                "export",
                "--config",
                "config/tangle.host.example.json",
                "--tenant",
                "farmers-market",
                "--output",
                "events.jsonl"
            ])
            .expect("tenant export"),
            TangleInvocation::new_with_admin_options(
                TangleCommand::TenantExport,
                Some("config/tangle.host.example.json".to_owned()),
                Some("farmers-market".to_owned()),
                None,
                Some("events.jsonl".to_owned()),
                None,
                false
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
            vec!["config", "migrate"],
            vec!["tenant", "create"],
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
        assert_eq!(
            parse_tangle_invocation(["run", "--redacted"]).expect_err("redacted"),
            TangleCliError::UnexpectedArgument {
                command: "run".to_owned(),
                argument: "--redacted".to_owned(),
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

    #[test]
    fn tenant_admin_required_options_report_missing_values() {
        let backup = TangleInvocation::new(TangleCommand::TenantBackup, None);
        let restore = TangleInvocation::new(TangleCommand::TenantRestore, None);

        assert_eq!(
            require_tenant_id(&backup).expect_err("tenant"),
            TangleCliError::MissingOptionValue("--tenant")
        );
        assert_eq!(
            require_output_path(&backup).expect_err("output"),
            TangleCliError::MissingOptionValue("--output")
        );
        assert_eq!(
            require_input_path(&restore).expect_err("input"),
            TangleCliError::MissingOptionValue("--input")
        );
        assert_eq!(
            require_target_data_dir(&restore).expect_err("target"),
            TangleCliError::MissingOptionValue("--target-data-dir")
        );
    }

    #[test]
    fn tenant_admin_parser_accepts_backup_restore_export_commands() {
        assert_eq!(
            parse_tangle_invocation([
                "tenant",
                "backup",
                "--config",
                "host.json",
                "--tenant",
                "market",
                "--output",
                "backup",
                "--include-secrets"
            ])
            .expect("backup"),
            TangleInvocation::new_with_admin_options(
                TangleCommand::TenantBackup,
                Some("host.json".to_owned()),
                Some("market".to_owned()),
                None,
                Some("backup".to_owned()),
                None,
                true
            )
        );
        assert_eq!(
            parse_tangle_invocation([
                "tenant",
                "restore",
                "--config",
                "host.json",
                "--tenant",
                "market",
                "--input",
                "backup",
                "--target-data-dir",
                "runtime/market"
            ])
            .expect("restore"),
            TangleInvocation::new_with_admin_options(
                TangleCommand::TenantRestore,
                Some("host.json".to_owned()),
                Some("market".to_owned()),
                Some("backup".to_owned()),
                None,
                Some("runtime/market".to_owned()),
                false
            )
        );
        assert_eq!(
            parse_tangle_invocation([
                "tenant",
                "export",
                "--config",
                "host.json",
                "--tenant",
                "market",
                "--output",
                "events.jsonl"
            ])
            .expect("export"),
            TangleInvocation::new_with_admin_options(
                TangleCommand::TenantExport,
                Some("host.json".to_owned()),
                Some("market".to_owned()),
                None,
                Some("events.jsonl".to_owned()),
                None,
                false
            )
        );
    }

    #[test]
    fn config_commands_use_new_host_config_surface() {
        let config_path = workspace_file("config/tangle.host.example.json");
        validate_config(&config_path).expect("validate");
        let inspect = inspect_config(&config_path, true).expect("inspect redacted");
        assert!(inspect.contains("\"tenant_id\": \"farmers-market\""));
        assert!(inspect.contains("\"relay_secret\": \"<redacted>\""));
        assert!(
            !inspect.contains("7777777777777777777777777777777777777777777777777777777777777777")
        );
        let tenants = list_tenants(&config_path).expect("tenant list");
        assert!(tenants.contains("tenant_id\thost\tstatus\ttenant_schema"));
        assert!(tenants.contains("farmers-market\trelay.radroots.test\tactive\tfarmers_market"));
    }

    fn workspace_file(path: &str) -> String {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(std::path::Path::parent)
            .expect("workspace root")
            .join(path)
            .to_string_lossy()
            .into_owned()
    }
}
