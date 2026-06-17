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

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn command_runner_reports_missing_config_in_process() {
        let run = tangle::TangleInvocation::new(tangle::TangleCommand::Run, None);
        assert_eq!(
            super::run_server(&run).await.expect_err("run config"),
            "--config requires a value"
        );
    }
}
