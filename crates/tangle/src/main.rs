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
        tangle::TangleCommand::Run => match run_server(&invocation) {
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

fn run_server(invocation: &tangle::TangleInvocation) -> Result<String, String> {
    let config_path = tangle::require_config_path(invocation).map_err(|error| error.to_string())?;
    tangle::run_with_config(config_path)
}

#[cfg(test)]
mod tests {
    use super::run_server;

    #[test]
    fn command_runner_reports_missing_config_in_process() {
        let run = tangle::TangleInvocation::new(tangle::TangleCommand::Run, None);
        assert_eq!(
            run_server(&run).expect_err("run config"),
            "--config requires a value"
        );
    }
}
