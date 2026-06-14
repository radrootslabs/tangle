#![forbid(unsafe_code)]

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};
use tangle_bench::{BenchDatasetConfig, BenchmarkRunReport};
use tangle_runtime::TANGLE_SUPPORTED_NIPS;

struct BenchmarkReportArgs {
    output_root: PathBuf,
    run_id: String,
    config: BenchDatasetConfig,
}

fn main() {
    match run() {
        Ok(Some(artifact_dir)) => println!("{}", path_string(&artifact_dir)),
        Ok(None) => {}
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
}

fn run() -> Result<Option<PathBuf>, String> {
    let Some(args) = BenchmarkReportArgs::parse(env::args().skip(1))? else {
        println!("{}", help_text());
        return Ok(None);
    };
    let artifact_dir = args.output_root.join(&args.run_id);
    fs::create_dir_all(&artifact_dir).map_err(|error| error.to_string())?;

    let report = BenchmarkRunReport::run(args.config)?;
    let dataset_path = artifact_dir.join("dataset-events.jsonl");
    fs::write(
        &dataset_path,
        report
            .dataset()
            .source_events_jsonl()
            .map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;

    let mut summary = report.summary_json(&args.run_id, &artifact_dir);
    summary["supported_nips_audit"] = serde_json::json!({
        "supported_nips": TANGLE_SUPPORTED_NIPS,
        "count": TANGLE_SUPPORTED_NIPS.len()
    });
    summary["run_identity"] = serde_json::json!({
        "git_commit": git_short_commit(),
        "rust_toolchain": rust_toolchain(),
        "host_profile": host_profile()
    });

    let summary_path = artifact_dir.join("summary.json");
    let raw = serde_json::to_string_pretty(&summary).map_err(|error| error.to_string())?;
    fs::write(&summary_path, format!("{raw}\n")).map_err(|error| error.to_string())?;
    Ok(Some(artifact_dir))
}

impl BenchmarkReportArgs {
    fn parse(args: impl IntoIterator<Item = String>) -> Result<Option<Self>, String> {
        let mut output_root = PathBuf::from(".local/tangle/benchmarks");
        let mut run_id = None;
        let mut config = BenchDatasetConfig::smoke();
        let mut args = args.into_iter();
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--output-root" => {
                    output_root = PathBuf::from(require_value("--output-root", args.next())?);
                }
                "--run-id" => {
                    run_id = Some(require_value("--run-id", args.next())?);
                }
                "--group-count" => {
                    config.group_count = parse_count("--group-count", args.next())?;
                }
                "--public-events-per-group" => {
                    config.public_events_per_group =
                        parse_count("--public-events-per-group", args.next())?;
                }
                "--private-events-per-group" => {
                    config.private_events_per_group =
                        parse_count("--private-events-per-group", args.next())?;
                }
                "--public-note-count" => {
                    config.public_note_count = parse_count("--public-note-count", args.next())?;
                }
                "--member-count" => {
                    config.member_count = parse_count("--member-count", args.next())?;
                }
                "--help" => return Ok(None),
                other => return Err(format!("unsupported argument `{other}`")),
            }
        }
        let run_id = run_id.unwrap_or_else(default_run_id);
        validate_run_id(&run_id)?;
        let config = config.validate()?;
        Ok(Some(Self {
            output_root,
            run_id,
            config,
        }))
    }
}

fn require_value(name: &'static str, value: Option<String>) -> Result<String, String> {
    value.ok_or_else(|| format!("{name} requires a value"))
}

fn parse_count(name: &'static str, value: Option<String>) -> Result<usize, String> {
    let raw = require_value(name, value)?;
    raw.parse::<usize>()
        .map_err(|error| format!("{name} must be a non-negative integer: {error}"))
}

fn validate_run_id(run_id: &str) -> Result<(), String> {
    if run_id.is_empty() || run_id.contains('/') || run_id.contains('\\') || run_id.contains("..") {
        return Err("run id must be a single relative path segment".to_owned());
    }
    Ok(())
}

fn default_run_id() -> String {
    format!("local-{}-{}", unix_seconds(), git_short_commit())
}

fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn git_short_commit() -> String {
    command_text("git", &["rev-parse", "--short", "HEAD"]).unwrap_or_else(|| "unknown".to_owned())
}

fn rust_toolchain() -> String {
    command_text("rustc", &["--version"]).unwrap_or_else(|| "unknown".to_owned())
}

fn host_profile() -> String {
    let os = env::consts::OS;
    let arch = env::consts::ARCH;
    format!("{os}-{arch}")
}

fn command_text(command: &str, args: &[&str]) -> Option<String> {
    Command::new(command)
        .args(args)
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn path_string(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

fn help_text() -> String {
    [
        "usage: tangle-benchmark-report [--output-root PATH] [--run-id ID]",
        "       [--group-count COUNT] [--public-events-per-group COUNT]",
        "       [--private-events-per-group COUNT] [--public-note-count COUNT]",
        "       [--member-count COUNT]",
    ]
    .join("\n")
}
