#![forbid(unsafe_code)]

use std::env;
use std::process::ExitCode;

fn main() -> ExitCode {
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
        tangle::TangleCommand::Migrate => match run_migrate(&invocation) {
            Ok(output) => {
                println!("{output}");
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("{error}");
                ExitCode::from(2)
            }
        },
        tangle::TangleCommand::Run => match run_server(&invocation) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("{error}");
                ExitCode::from(2)
            }
        },
        tangle::TangleCommand::EventImport => match run_event_import(&invocation) {
            Ok(output) => {
                println!("{output}");
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("{error}");
                ExitCode::from(2)
            }
        },
        tangle::TangleCommand::EventExport => match run_event_export(&invocation) {
            Ok(output) => {
                println!("{output}");
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("{error}");
                ExitCode::from(2)
            }
        },
        tangle::TangleCommand::ProjectionRebuild => match run_projection_rebuild(&invocation) {
            Ok(output) => {
                println!("{output}");
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("{error}");
                ExitCode::from(2)
            }
        },
        tangle::TangleCommand::OpsBackup => match run_ops_backup(&invocation) {
            Ok(output) => {
                println!("{output}");
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("{error}");
                ExitCode::from(2)
            }
        },
        tangle::TangleCommand::OpsRestore => match run_ops_restore(&invocation) {
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

fn run_migrate(invocation: &tangle::TangleInvocation) -> Result<String, String> {
    let config_path = tangle::require_config_path(invocation).map_err(|error| error.to_string())?;
    let runtime = tangle_runtime();
    runtime.block_on(tangle::migrate_with_config(config_path))
}

fn run_server(invocation: &tangle::TangleInvocation) -> Result<(), String> {
    let config_path = tangle::require_config_path(invocation).map_err(|error| error.to_string())?;
    let runtime = tangle_runtime();
    runtime.block_on(tangle::run_with_config(config_path))
}

fn run_event_import(invocation: &tangle::TangleInvocation) -> Result<String, String> {
    let config_path = tangle::require_config_path(invocation).map_err(|error| error.to_string())?;
    let input_path = tangle::require_input_path(invocation).map_err(|error| error.to_string())?;
    let runtime = tangle_runtime();
    runtime.block_on(tangle::event_import_with_config(config_path, input_path))
}

fn run_event_export(invocation: &tangle::TangleInvocation) -> Result<String, String> {
    let config_path = tangle::require_config_path(invocation).map_err(|error| error.to_string())?;
    let output_path = tangle::require_output_path(invocation).map_err(|error| error.to_string())?;
    let runtime = tangle_runtime();
    runtime.block_on(tangle::event_export_with_config(config_path, output_path))
}

fn run_projection_rebuild(invocation: &tangle::TangleInvocation) -> Result<String, String> {
    let config_path = tangle::require_config_path(invocation).map_err(|error| error.to_string())?;
    let runtime = tangle_runtime();
    runtime.block_on(tangle::projection_rebuild_with_config(config_path))
}

fn run_ops_backup(invocation: &tangle::TangleInvocation) -> Result<String, String> {
    let config_path = tangle::require_config_path(invocation).map_err(|error| error.to_string())?;
    let output_path = tangle::require_output_path(invocation).map_err(|error| error.to_string())?;
    let runtime = tangle_runtime();
    runtime.block_on(tangle::ops_backup_with_config(config_path, output_path))
}

fn run_ops_restore(invocation: &tangle::TangleInvocation) -> Result<String, String> {
    let config_path = tangle::require_config_path(invocation).map_err(|error| error.to_string())?;
    let input_path = tangle::require_input_path(invocation).map_err(|error| error.to_string())?;
    let runtime = tangle_runtime();
    runtime.block_on(tangle::ops_restore_with_config(config_path, input_path))
}

fn tangle_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("failed to start tangle Tokio runtime")
}

#[cfg(test)]
mod tests {
    use super::{
        run_event_export, run_event_import, run_ops_backup, run_ops_restore, run_server,
        tangle_runtime,
    };

    #[test]
    fn command_runners_report_missing_options_in_process() {
        let run = tangle::TangleInvocation::new(tangle::TangleCommand::Run, None);
        assert_eq!(
            run_server(&run).expect_err("run config"),
            "--config requires a value"
        );

        let import_missing_config =
            tangle::TangleInvocation::new(tangle::TangleCommand::EventImport, None);
        assert_eq!(
            run_event_import(&import_missing_config).expect_err("import config"),
            "--config requires a value"
        );
        let import_missing_input = tangle::TangleInvocation::new(
            tangle::TangleCommand::EventImport,
            Some("runtime.json".to_owned()),
        );
        assert_eq!(
            run_event_import(&import_missing_input).expect_err("import input"),
            "--input requires a value"
        );

        let export_missing_config =
            tangle::TangleInvocation::new(tangle::TangleCommand::EventExport, None);
        assert_eq!(
            run_event_export(&export_missing_config).expect_err("export config"),
            "--config requires a value"
        );
        let export_missing_output = tangle::TangleInvocation::new(
            tangle::TangleCommand::EventExport,
            Some("runtime.json".to_owned()),
        );
        assert_eq!(
            run_event_export(&export_missing_output).expect_err("export output"),
            "--output requires a value"
        );

        let backup_missing_config =
            tangle::TangleInvocation::new(tangle::TangleCommand::OpsBackup, None);
        assert_eq!(
            run_ops_backup(&backup_missing_config).expect_err("backup config"),
            "--config requires a value"
        );
        let backup_missing_output = tangle::TangleInvocation::new(
            tangle::TangleCommand::OpsBackup,
            Some("runtime.json".to_owned()),
        );
        assert_eq!(
            run_ops_backup(&backup_missing_output).expect_err("backup output"),
            "--output requires a value"
        );

        let restore_missing_config =
            tangle::TangleInvocation::new(tangle::TangleCommand::OpsRestore, None);
        assert_eq!(
            run_ops_restore(&restore_missing_config).expect_err("restore config"),
            "--config requires a value"
        );
        let restore_missing_input = tangle::TangleInvocation::new(
            tangle::TangleCommand::OpsRestore,
            Some("runtime.json".to_owned()),
        );
        assert_eq!(
            run_ops_restore(&restore_missing_input).expect_err("restore input"),
            "--input requires a value"
        );
    }

    #[test]
    fn command_runner_runtime_builds_current_thread_executor() {
        let runtime = tangle_runtime();

        assert_eq!(runtime.block_on(async { 42 }), 42);
    }
}
