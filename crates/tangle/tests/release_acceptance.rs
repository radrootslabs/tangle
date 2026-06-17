#![forbid(unsafe_code)]

use std::fs;
use std::path::{Path, PathBuf};

#[test]
fn release_acceptance_app_covers_release_candidate_validation_ladder() {
    let flake = read("flake.nix");
    let release_start = flake
        .find("releaseAcceptance = mkScript")
        .expect("release app");
    let apps_start = release_start
        + flake[release_start..]
            .find("in\n        {")
            .expect("apps body");
    let release = &flake[release_start..apps_start];

    for required in [
        "cargo fmt --all -- --check",
        "cargo test -p tangle --test source_comments",
        "cargo test -p tangle --test unsafe_code",
        "cargo check --workspace --all-targets",
        "cargo clippy --workspace --all-targets -- -D warnings",
        "cargo test --workspace",
        "cargo test -p tangle_runtime --test base_relay_v2",
        "cargo test -p tangle_runtime isolation",
        "cargo test -p tangle_runtime server",
        "cargo test -p tangle_runtime auth",
        "cargo test -p tangle_runtime backup",
        "cargo test -p tangle_runtime export",
        "cargo test -p tangle_groups",
        "cargo test -p tangle_store_pocket",
        "cargo test -p tangle_bench",
        "cargo run -p tangle_bench --bin tangle-benchmark-report -- --profile virtual-relay-tenancy",
    ] {
        assert!(
            release.contains(required),
            "release acceptance app is missing `{required}`"
        );
    }

    assert!(
        !release.contains("cargo llvm-cov"),
        "release acceptance must not depend on strict line coverage"
    );
    assert!(
        !release.contains("cargo nextest run --workspace"),
        "release acceptance must not require a host-local nextest install"
    );
    for removed in [
        "nip50_conformance",
        "nip99_conformance",
        &["discuss", "ion_conformance"].concat(),
        "moderation_conformance",
        &["comm", "erce_privacy_conformance"].concat(),
        "abuse_conformance",
        "run_integration",
        "runtime_restore_command_imports_backup_and_rebuilds_projection_state",
    ] {
        assert!(
            !release.contains(removed),
            "release acceptance still references `{removed}`"
        );
    }
}

#[test]
fn nix_exposes_release_acceptance_entrypoint() {
    let flake = read("flake.nix");

    for required in [
        "releaseAcceptance = mkScript pkgs \"tangle-release-acceptance\"",
        "\"release-acceptance\"",
        "program = \"${releaseAcceptance}/bin/tangle-release-acceptance\"",
    ] {
        assert!(flake.contains(required), "flake is missing `{required}`");
    }
}

fn read(path: &str) -> String {
    fs::read_to_string(workspace_root().join(path)).expect(path)
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf()
}
