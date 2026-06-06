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
    }
}

fn run_migrate(invocation: &tangle::TangleInvocation) -> Result<String, String> {
    let config_path = tangle::require_config_path(invocation).map_err(|error| error.to_string())?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("failed to start runtime: {error}"))?;
    runtime.block_on(tangle::migrate_with_config(config_path))
}

fn run_server(invocation: &tangle::TangleInvocation) -> Result<(), String> {
    let config_path = tangle::require_config_path(invocation).map_err(|error| error.to_string())?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("failed to start runtime: {error}"))?;
    runtime.block_on(tangle::run_with_config(config_path))
}

fn run_event_import(invocation: &tangle::TangleInvocation) -> Result<String, String> {
    let config_path = tangle::require_config_path(invocation).map_err(|error| error.to_string())?;
    let input_path = tangle::require_input_path(invocation).map_err(|error| error.to_string())?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("failed to start runtime: {error}"))?;
    runtime.block_on(tangle::event_import_with_config(config_path, input_path))
}

fn run_event_export(invocation: &tangle::TangleInvocation) -> Result<String, String> {
    let config_path = tangle::require_config_path(invocation).map_err(|error| error.to_string())?;
    let output_path = tangle::require_output_path(invocation).map_err(|error| error.to_string())?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("failed to start runtime: {error}"))?;
    runtime.block_on(tangle::event_export_with_config(config_path, output_path))
}

fn run_projection_rebuild(invocation: &tangle::TangleInvocation) -> Result<String, String> {
    let config_path = tangle::require_config_path(invocation).map_err(|error| error.to_string())?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("failed to start runtime: {error}"))?;
    runtime.block_on(tangle::projection_rebuild_with_config(config_path))
}
