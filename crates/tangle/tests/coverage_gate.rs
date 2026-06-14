#![forbid(unsafe_code)]

use std::fs;
use std::path::{Path, PathBuf};

#[test]
fn flake_coverage_app_requires_workspace_full_line_coverage() {
    let flake = read("flake.nix");

    assert!(flake.contains("pkgs.cargo-llvm-cov"));
    assert!(flake.contains("pkgs.llvmPackages.llvm"));
    assert!(flake.contains("cargo llvm-cov --version"));
    assert!(flake.contains("LLVM_COV=\"$(command -v llvm-cov)\""));
    assert!(flake.contains("LLVM_PROFDATA=\"$(command -v llvm-profdata)\""));
    assert!(flake.contains("coverage = mkScript"));
    assert!(flake.contains("cargo llvm-cov clean --workspace"));
    assert!(flake.contains("cargo llvm-cov --workspace --all-targets"));
    assert!(flake.contains("--show-missing-lines"));
    assert!(flake.contains("--fail-under-lines 100"));
    assert!(flake.contains("--fail-uncovered-lines 0"));
}

#[test]
fn flake_validation_surface_does_not_depend_on_removed_dirs() {
    let root = workspace_root();
    let flake = read("flake.nix");

    assert!(!root.join("scripts").exists());
    assert!(!root.join("ci").exists());
    assert!(!flake.contains("scripts/"));
    assert!(!flake.contains("ci/"));
    assert!(!flake.contains("ops/"));
}

#[test]
fn release_and_ci_keep_coverage_diagnostic_outside_required_gates() {
    let flake = read("flake.nix");

    let ci_start = flake.find("ci = mkScript").expect("ci app");
    let release_start = flake
        .find("releaseAcceptance = mkScript")
        .expect("release app");
    let apps_start = release_start
        + flake[release_start..]
            .find("in\n        {")
            .expect("apps body");
    let ci = &flake[ci_start..release_start];
    let release = &flake[release_start..apps_start];

    assert!(!ci.contains("cargo llvm-cov"));
    assert!(!release.contains("cargo llvm-cov"));
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
