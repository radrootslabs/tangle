#![forbid(unsafe_code)]

use std::env;
use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    let invocation = match tangle::parse_tangle_invocation(env::args().skip(1)) {
        Ok(invocation) => invocation,
        Err(error) => {
            eprintln!("{error}");
            eprintln!("{}", tangle::usage_output());
            return ExitCode::from(2);
        }
    };
    match invocation.command() {
        tangle::TangleCommand::Version => {
            println!("{}", tangle::version_output());
            ExitCode::SUCCESS
        }
        tangle::TangleCommand::Help => {
            println!("{}", tangle::usage_output());
            ExitCode::SUCCESS
        }
        tangle::TangleCommand::Run => match run_server(&invocation).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("{error}");
                ExitCode::from(2)
            }
        },
        tangle::TangleCommand::ConfigValidate => {
            match config_path_or_error(&invocation).and_then(|path| tangle::validate_config(&path))
            {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!("{error}");
                    ExitCode::from(2)
                }
            }
        }
        tangle::TangleCommand::ConfigInspect => {
            match config_path_or_error(&invocation)
                .and_then(|path| tangle::inspect_config(&path, invocation.redacted()))
            {
                Ok(output) => {
                    println!("{output}");
                    ExitCode::SUCCESS
                }
                Err(error) => {
                    eprintln!("{error}");
                    ExitCode::from(2)
                }
            }
        }
        tangle::TangleCommand::TenantList => {
            match config_path_or_error(&invocation).and_then(|path| tangle::list_tenants(&path)) {
                Ok(output) => {
                    println!("{output}");
                    ExitCode::SUCCESS
                }
                Err(error) => {
                    eprintln!("{error}");
                    ExitCode::from(2)
                }
            }
        }
        tangle::TangleCommand::TenantBackup => match run_tenant_backup(&invocation) {
            Ok(output) => {
                println!("{output}");
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("{error}");
                ExitCode::from(2)
            }
        },
        tangle::TangleCommand::TenantRestore => match run_tenant_restore(&invocation) {
            Ok(output) => {
                println!("{output}");
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("{error}");
                ExitCode::from(2)
            }
        },
        tangle::TangleCommand::TenantExport => match run_tenant_export(&invocation) {
            Ok(output) => {
                println!("{output}");
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("{error}");
                ExitCode::from(2)
            }
        },
    }
}

async fn run_server(invocation: &tangle::TangleInvocation) -> Result<(), String> {
    let config_path = config_path_or_error(invocation)?;
    tangle::run_with_config(&config_path).await.map(|_| ())
}

fn config_path_or_error(invocation: &tangle::TangleInvocation) -> Result<String, String> {
    tangle::require_config_path(invocation)
        .map(str::to_owned)
        .map_err(|error| error.to_string())
}

fn tenant_id_or_error(invocation: &tangle::TangleInvocation) -> Result<String, String> {
    tangle::require_tenant_id(invocation)
        .map(str::to_owned)
        .map_err(|error| error.to_string())
}

fn output_path_or_error(invocation: &tangle::TangleInvocation) -> Result<String, String> {
    tangle::require_output_path(invocation)
        .map(str::to_owned)
        .map_err(|error| error.to_string())
}

fn input_path_or_error(invocation: &tangle::TangleInvocation) -> Result<String, String> {
    tangle::require_input_path(invocation)
        .map(str::to_owned)
        .map_err(|error| error.to_string())
}

fn target_data_dir_or_error(invocation: &tangle::TangleInvocation) -> Result<String, String> {
    tangle::require_target_data_dir(invocation)
        .map(str::to_owned)
        .map_err(|error| error.to_string())
}

fn run_tenant_backup(invocation: &tangle::TangleInvocation) -> Result<String, String> {
    let config = config_path_or_error(invocation)?;
    let tenant = tenant_id_or_error(invocation)?;
    let output = output_path_or_error(invocation)?;
    tangle::backup_tenant(&config, &tenant, &output, invocation.include_secrets())
}

fn run_tenant_restore(invocation: &tangle::TangleInvocation) -> Result<String, String> {
    let config = config_path_or_error(invocation)?;
    let tenant = tenant_id_or_error(invocation)?;
    let input = input_path_or_error(invocation)?;
    let target_data_dir = target_data_dir_or_error(invocation)?;
    tangle::restore_tenant(&config, &tenant, &input, &target_data_dir)
}

fn run_tenant_export(invocation: &tangle::TangleInvocation) -> Result<String, String> {
    let config = config_path_or_error(invocation)?;
    let tenant = tenant_id_or_error(invocation)?;
    let output = output_path_or_error(invocation)?;
    tangle::export_tenant(&config, &tenant, &output)
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn command_runner_reports_missing_config_in_process() {
        let run = tangle::TangleInvocation::new(tangle::TangleCommand::Run, None);
        assert_eq!(
            super::run_server(&run).await.expect_err("run config"),
            "--config requires a value"
        );
        let backup = tangle::TangleInvocation::new(tangle::TangleCommand::TenantBackup, None);
        assert_eq!(
            super::run_tenant_backup(&backup).expect_err("backup config"),
            "--config requires a value"
        );
    }
}
