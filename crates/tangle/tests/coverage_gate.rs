#![forbid(unsafe_code)]

use std::fs;
use std::path::{Path, PathBuf};

#[test]
fn coverage_script_requires_workspace_full_line_coverage() {
    let script = read("scripts/coverage.sh");

    assert!(script.contains("cargo llvm-cov --version"));
    assert!(script.contains("LLVM_COV=\"$(command -v llvm-cov)\""));
    assert!(script.contains("LLVM_PROFDATA=\"$(command -v llvm-profdata)\""));
    assert!(script.contains("cargo llvm-cov clean --workspace"));
    assert!(script.contains("cargo llvm-cov --workspace --all-targets"));
    assert!(script.contains("--show-missing-lines"));
    assert!(script.contains("--fail-under-lines 100"));
    assert!(script.contains("--fail-uncovered-lines 0"));
}

#[test]
fn ci_and_validation_contract_require_coverage_gate() {
    let ci = read("scripts/ci.sh");
    let validation = read("ci/workspace-validation.toml");

    assert!(ci.contains("scripts/coverage.sh"));
    assert!(validation.contains("id = \"coverage\""));
    assert!(validation.contains("command = \"scripts/coverage.sh\""));
    assert!(validation.contains("\"cargo-llvm-cov\""));
    assert!(validation.contains("\"llvm-cov\""));
    assert!(validation.contains("\"llvm-profdata\""));
}

#[test]
fn nix_coverage_app_provisions_coverage_tools_and_environment() {
    let flake = read("flake.nix");

    assert!(flake.contains("pkgs.cargo-llvm-cov"));
    assert!(flake.contains("pkgs.llvmPackages.llvm"));
    assert!(flake.contains("LLVM_COV=\"$(command -v llvm-cov)\""));
    assert!(flake.contains("LLVM_PROFDATA=\"$(command -v llvm-profdata)\""));
    assert!(flake.contains("coverage = mkScript"));
    assert!(flake.contains("scripts/coverage.sh"));
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
