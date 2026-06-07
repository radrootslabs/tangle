#![forbid(unsafe_code)]

use serde_json::json;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};
use tangle_bench::{
    BenchDatasetConfig, capture_query_plans, run_ingest_benchmark, run_listing_query_benchmark,
    run_rebuild_benchmark, run_restore_drill_smoke, run_search_benchmark,
};
use tangle_runtime::TANGLE_SUPPORTED_NIPS;

struct BenchmarkReportArgs {
    output_root: PathBuf,
    run_id: String,
    listing_count: usize,
    note_count: usize,
}

fn main() {
    let result = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| error.to_string())
        .and_then(|runtime| runtime.block_on(run()));
    if let Err(error) = result {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), String> {
    let args = BenchmarkReportArgs::parse(env::args().skip(1))?;
    let artifact_dir = args.output_root.join(&args.run_id);
    fs::create_dir_all(&artifact_dir).map_err(|error| error.to_string())?;
    let config = BenchDatasetConfig::new(args.listing_count, args.note_count);

    let ingest = run_ingest_benchmark(config).await?;
    let listing = run_listing_query_benchmark(config).await?;
    let search = run_search_benchmark(config).await?;
    let query_plans = capture_query_plans(config).await?;
    let rebuild = run_rebuild_benchmark(config).await?;
    let restore = run_restore_drill_smoke(config).await?;

    let listing_plan_path = artifact_dir.join("listing-query-plan.txt");
    let search_plan_path = artifact_dir.join("search-query-plan.txt");
    fs::write(&listing_plan_path, &query_plans.listing_plan_text)
        .map_err(|error| error.to_string())?;
    fs::write(&search_plan_path, &query_plans.search_plan_text)
        .map_err(|error| error.to_string())?;

    let expected_events = (args.listing_count + args.note_count) as u64;
    let benchmark_smoke = ingest.attempted == expected_events
        && ingest.inserted == expected_events
        && listing.listing_rows == args.listing_count as u64
        && listing.limited_rows <= listing.listing_rows
        && search.indexed == args.listing_count as u64
        && search.text_results > 0
        && search.browse_results > 0
        && rebuild.scanned == args.listing_count as u64
        && rebuild.rebuilt == rebuild.scanned
        && rebuild.projected == rebuild.scanned
        && rebuild.listing_rows == args.listing_count as u64
        && rebuild.checksum.len() == 64;
    let query_plan_capture =
        query_plans.listing_plan_steps > 0 && query_plans.search_plan_steps > 0;
    let restore_drill_smoke = restore.exported == args.listing_count as u64
        && restore.restored == restore.exported
        && restore.checksum_matches;

    let summary = json!({
        "schema": 1,
        "run_id": args.run_id,
        "artifact_directory": path_string(&artifact_dir),
        "surrealdb_mode": "memory",
        "dataset": {
            "listing_count": args.listing_count,
            "note_count": args.note_count,
            "fixture_builder_family": "tangle_test_support canonical event builders"
        },
        "artifacts": {
            "summary_json": "summary.json",
            "listing_query_plan": "listing-query-plan.txt",
            "search_query_plan": "search-query-plan.txt"
        },
        "ingest": {
            "attempted": ingest.attempted,
            "inserted": ingest.inserted,
            "elapsed_micros": elapsed(ingest.elapsed_micros)
        },
        "listing_query": {
            "listing_rows": listing.listing_rows,
            "limited_rows": listing.limited_rows,
            "elapsed_micros": elapsed(listing.elapsed_micros)
        },
        "search": {
            "indexed": search.indexed,
            "text_results": search.text_results,
            "browse_results": search.browse_results,
            "elapsed_micros": elapsed(search.elapsed_micros)
        },
        "query_plan_capture": {
            "listing_plan_steps": query_plans.listing_plan_steps,
            "search_plan_steps": query_plans.search_plan_steps,
            "listing_plan_text": "listing-query-plan.txt",
            "search_plan_text": "search-query-plan.txt"
        },
        "rebuild": {
            "scanned": rebuild.scanned,
            "rebuilt": rebuild.rebuilt,
            "projected": rebuild.projected,
            "listing_rows": rebuild.listing_rows,
            "checksum": rebuild.checksum,
            "elapsed_micros": elapsed(rebuild.elapsed_micros)
        },
        "restore_drill": {
            "exported": restore.exported,
            "restored": restore.restored,
            "source_checksum": restore.source_checksum,
            "restored_checksum": restore.restored_checksum,
            "checksum_matches": restore.checksum_matches
        },
        "supported_nips_audit": {
            "supported_nips": TANGLE_SUPPORTED_NIPS,
            "count": TANGLE_SUPPORTED_NIPS.len()
        },
        "validation_summary": {
            "benchmark_smoke": status(benchmark_smoke),
            "restore_drill_smoke": status(restore_drill_smoke),
            "query_plan_capture": status(query_plan_capture),
            "coverage_diagnostic": "not_run_by_release_acceptance"
        }
    });
    let summary_path = artifact_dir.join("summary.json");
    let raw = serde_json::to_string_pretty(&summary).map_err(|error| error.to_string())?;
    fs::write(&summary_path, format!("{raw}\n")).map_err(|error| error.to_string())?;
    println!("{}", path_string(&artifact_dir));
    Ok(())
}

impl BenchmarkReportArgs {
    fn parse(args: impl IntoIterator<Item = String>) -> Result<Self, String> {
        let mut output_root = PathBuf::from(".local/tangle/benchmarks");
        let mut run_id = None;
        let mut listing_count = 12;
        let mut note_count = 4;
        let mut args = args.into_iter();
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--output-root" => {
                    output_root = PathBuf::from(require_value("--output-root", args.next())?);
                }
                "--run-id" => {
                    run_id = Some(require_value("--run-id", args.next())?);
                }
                "--listing-count" => {
                    listing_count = parse_count("--listing-count", args.next())?;
                }
                "--note-count" => {
                    note_count = parse_count("--note-count", args.next())?;
                }
                "--help" => return Err(help_text()),
                other => return Err(format!("unsupported argument `{other}`")),
            }
        }
        let run_id = run_id.unwrap_or_else(default_run_id);
        validate_run_id(&run_id)?;
        Ok(Self {
            output_root,
            run_id,
            listing_count,
            note_count,
        })
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
    Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "unknown".to_owned())
}

fn status(value: bool) -> &'static str {
    if value { "pass" } else { "fail" }
}

fn elapsed(value: u128) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

fn path_string(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

fn help_text() -> String {
    [
        "usage: tangle-benchmark-report [--output-root PATH] [--run-id ID]",
        "       [--listing-count COUNT] [--note-count COUNT]",
    ]
    .join("\n")
}
