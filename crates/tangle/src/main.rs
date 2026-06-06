#![forbid(unsafe_code)]

use std::env;
use std::process::ExitCode;

fn main() -> ExitCode {
    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        Some("--version") | Some("-V") => {
            println!("{}", tangle::version_output());
            ExitCode::SUCCESS
        }
        Some(_) => {
            eprintln!("usage: tangle [--version]");
            ExitCode::from(2)
        }
        None => ExitCode::SUCCESS,
    }
}
