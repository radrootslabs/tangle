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
        command => {
            eprintln!("command not implemented: {}", command.as_str());
            ExitCode::from(2)
        }
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
