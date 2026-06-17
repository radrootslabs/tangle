#![forbid(unsafe_code)]

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};
use tangle_bench::{
    BenchDatasetConfig, BenchmarkProfile, BenchmarkProfileName, BenchmarkRunReport,
    BenchmarkThresholds,
};
use tangle_runtime::nip11::supported_nips_for_group_capability;

#[derive(Debug)]
struct BenchmarkReportArgs {
    output_root: PathBuf,
    run_id: String,
    profile: BenchmarkProfile,
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

    let report = BenchmarkRunReport::run(args.profile)?;
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
    let supported_nips = supported_nips_for_group_capability(true);
    let supported_nips_count = supported_nips.len();
    summary["supported_nips_audit"] = serde_json::json!({
        "groups_enabled": true,
        "supported_nips": supported_nips,
        "count": supported_nips_count
    });
    summary["run_identity"] = serde_json::json!({
        "git_commit": git_full_commit(),
        "git_commit_short": git_short_commit(),
        "rust_toolchain": rust_toolchain(),
        "host_profile": host_profile(),
        "os": env::consts::OS,
        "arch": env::consts::ARCH
    });
    summary["host_hardware"] = serde_json::json!({
        "cpu_model": cpu_model(),
        "cpu_parallelism": cpu_parallelism(),
        "memory_bytes": memory_bytes()
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
        let mut profile_name = BenchmarkProfileName::VirtualRelayTenancy;
        let mut config = BenchDatasetConfig::smoke();
        let mut dataset_overridden = false;
        let mut thresholds_json = None;
        let mut target_hardware_evidence = None;
        let mut args = args.into_iter();
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--output-root" => {
                    output_root = PathBuf::from(require_value("--output-root", args.next())?);
                }
                "--run-id" => {
                    run_id = Some(require_value("--run-id", args.next())?);
                }
                "--profile" => {
                    profile_name =
                        BenchmarkProfileName::parse(&require_value("--profile", args.next())?)?;
                }
                "--thresholds-json" => {
                    thresholds_json = Some(PathBuf::from(require_value(
                        "--thresholds-json",
                        args.next(),
                    )?));
                }
                "--target-hardware-evidence" => {
                    target_hardware_evidence =
                        Some(require_value("--target-hardware-evidence", args.next())?);
                }
                "--group-count" => {
                    config.group_count = parse_count("--group-count", args.next())?;
                    dataset_overridden = true;
                }
                "--public-events-per-group" => {
                    config.public_events_per_group =
                        parse_count("--public-events-per-group", args.next())?;
                    dataset_overridden = true;
                }
                "--private-events-per-group" => {
                    config.private_events_per_group =
                        parse_count("--private-events-per-group", args.next())?;
                    dataset_overridden = true;
                }
                "--public-note-count" => {
                    config.public_note_count = parse_count("--public-note-count", args.next())?;
                    dataset_overridden = true;
                }
                "--member-count" => {
                    config.member_count = parse_count("--member-count", args.next())?;
                    dataset_overridden = true;
                }
                "--help" => return Ok(None),
                other => return Err(format!("unsupported argument `{other}`")),
            }
        }
        let run_id = run_id.unwrap_or_else(default_run_id);
        validate_run_id(&run_id)?;
        if dataset_overridden && profile_name != BenchmarkProfileName::Smoke {
            return Err(
                "dataset size overrides are only supported with the smoke profile".to_owned(),
            );
        }
        let mut profile = BenchmarkProfile::from_name(profile_name);
        if dataset_overridden {
            profile = profile.with_dataset_config(config)?;
        }
        if let Some(path) = thresholds_json {
            let raw = fs::read_to_string(&path)
                .map_err(|error| format!("failed to read thresholds JSON: {error}"))?;
            let thresholds = BenchmarkThresholds::from_json_str(&raw)?;
            profile =
                profile.with_thresholds(thresholds, format!("file:{}", path_string(&path)))?;
        }
        if let Some(evidence) = target_hardware_evidence {
            profile = profile.with_target_hardware_evidence(evidence)?;
        }
        profile.validate_for_run()?;
        Ok(Some(Self {
            output_root,
            run_id,
            profile,
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

fn git_full_commit() -> String {
    command_text("git", &["rev-parse", "HEAD"]).unwrap_or_else(|| "unknown".to_owned())
}

fn rust_toolchain() -> String {
    command_text("rustc", &["--version"]).unwrap_or_else(|| "unknown".to_owned())
}

fn host_profile() -> String {
    let os = env::consts::OS;
    let arch = env::consts::ARCH;
    format!("{os}-{arch}")
}

fn cpu_model() -> String {
    command_text("sysctl", &["-n", "machdep.cpu.brand_string"])
        .or_else(cpu_model_from_proc)
        .unwrap_or_else(|| "unknown".to_owned())
}

fn cpu_parallelism() -> u64 {
    std::thread::available_parallelism()
        .map(|value| value.get().try_into().expect("parallelism fits in u64"))
        .unwrap_or(0)
}

fn memory_bytes() -> Option<u64> {
    command_text("sysctl", &["-n", "hw.memsize"])
        .and_then(|value| value.parse::<u64>().ok())
        .or_else(memory_bytes_from_proc)
}

fn cpu_model_from_proc() -> Option<String> {
    let raw = fs::read_to_string("/proc/cpuinfo").ok()?;
    raw.lines()
        .find_map(|line| line.strip_prefix("model name"))
        .and_then(|value| {
            value
                .split_once(':')
                .map(|(_, model)| model.trim().to_owned())
        })
        .filter(|value| !value.is_empty())
}

fn memory_bytes_from_proc() -> Option<u64> {
    let raw = fs::read_to_string("/proc/meminfo").ok()?;
    raw.lines()
        .find_map(|line| line.strip_prefix("MemTotal:"))
        .and_then(|value| value.split_whitespace().next())
        .and_then(|value| value.parse::<u64>().ok())
        .and_then(|kib| kib.checked_mul(1024))
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
        "usage: tangle-benchmark-report [--output-root PATH] [--run-id ID] [--profile smoke|virtual-relay-tenancy|medium|large-smoke|proof-10m|proof-large-group|proof-join-storm|proof-slow-client]",
        "       [--thresholds-json PATH] [--target-hardware-evidence TEXT]",
        "       [--group-count COUNT] [--public-events-per-group COUNT]",
        "       [--private-events-per-group COUNT] [--public-note-count COUNT]",
        "       [--member-count COUNT]",
    ]
    .join("\n")
}

#[cfg(test)]
mod tests {
    use super::BenchmarkReportArgs;
    use tangle_bench::{BenchDatasetConfig, BenchmarkProfileName};

    #[test]
    fn benchmark_report_args_default_to_virtual_relay_tenancy_profile() {
        let args = BenchmarkReportArgs::parse(["--run-id".to_owned(), "unit".to_owned()])
            .expect("parse")
            .expect("args");

        assert_eq!(
            args.profile.name(),
            BenchmarkProfileName::VirtualRelayTenancy
        );
        assert_eq!(args.profile.dataset_config(), BenchDatasetConfig::smoke());
        assert_eq!(
            args.profile.threshold_source(),
            "builtin:virtual-relay-tenancy"
        );
    }

    #[test]
    fn benchmark_report_args_reject_unknown_profile() {
        let error = BenchmarkReportArgs::parse([
            "--profile".to_owned(),
            "tiny".to_owned(),
            "--run-id".to_owned(),
            "unit".to_owned(),
        ])
        .expect_err("unknown profile");

        assert!(error.contains("unknown benchmark profile"));
    }

    #[test]
    fn benchmark_report_args_reject_dataset_overrides_for_non_smoke_profiles() {
        let error = BenchmarkReportArgs::parse([
            "--profile".to_owned(),
            "medium".to_owned(),
            "--group-count".to_owned(),
            "3".to_owned(),
            "--run-id".to_owned(),
            "unit".to_owned(),
        ])
        .expect_err("non-smoke override");

        assert!(error.contains("dataset size overrides"));
    }

    #[test]
    fn benchmark_report_args_accept_large_smoke_target_hardware_evidence_without_proof_claim() {
        let args = BenchmarkReportArgs::parse([
            "--profile".to_owned(),
            "large-smoke".to_owned(),
            "--target-hardware-evidence".to_owned(),
            "target-hardware:bench-node-001".to_owned(),
            "--run-id".to_owned(),
            "unit".to_owned(),
        ])
        .expect("parse")
        .expect("args");

        assert_eq!(args.profile.name(), BenchmarkProfileName::LargeSmoke);
        assert!(!args.profile.proof_claim_eligible());
    }

    #[test]
    fn benchmark_report_args_require_hardware_evidence_for_proof_profiles() {
        for profile in [
            "proof-10m",
            "proof-large-group",
            "proof-join-storm",
            "proof-slow-client",
        ] {
            let error = BenchmarkReportArgs::parse([
                "--profile".to_owned(),
                profile.to_owned(),
                "--run-id".to_owned(),
                "unit".to_owned(),
            ])
            .expect_err("proof profile requires evidence");

            assert!(error.contains("target hardware evidence is required"));
        }
    }

    #[test]
    fn benchmark_report_args_accept_proof_profile_with_hardware_evidence() {
        let args = BenchmarkReportArgs::parse([
            "--profile".to_owned(),
            "proof-10m".to_owned(),
            "--target-hardware-evidence".to_owned(),
            "target-hardware:proof-node-001".to_owned(),
            "--run-id".to_owned(),
            "unit".to_owned(),
        ])
        .expect("parse")
        .expect("args");

        assert_eq!(args.profile.name(), BenchmarkProfileName::Proof10m);
        assert!(args.profile.proof_claim_eligible());
    }

    #[test]
    fn benchmark_report_args_reject_production_profile_alias() {
        let error = BenchmarkReportArgs::parse([
            "--profile".to_owned(),
            "production".to_owned(),
            "--run-id".to_owned(),
            "unit".to_owned(),
        ])
        .expect_err("production profile removed");

        assert!(error.contains("unknown benchmark profile"));
    }
}
