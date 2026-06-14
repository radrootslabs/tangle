#![forbid(unsafe_code)]

use std::fs;
use std::path::{Path, PathBuf};

#[test]
fn release_acceptance_script_covers_release_candidate_validation_ladder() {
    let script_path = workspace_root().join("scripts/release_acceptance.sh");
    let script = fs::read_to_string(&script_path).expect("release acceptance script");

    for required in [
        "#!/usr/bin/env bash",
        "set -euo pipefail",
        "scripts/check.sh",
        "scripts/test.sh",
        "cargo test -p tangle_runtime --test base_relay_v2",
        "cargo test -p tangle_groups",
        "cargo test -p tangle_store_pocket",
        "cargo test -p tangle_bench",
        "scripts/benchmark_report.sh",
        "cargo test -p tangle --test source_comments",
        "cargo test -p tangle --test unsafe_code",
    ] {
        assert!(
            script.contains(required),
            "release acceptance script is missing `{required}`"
        );
    }

    assert!(
        !script.contains("scripts/coverage.sh"),
        "release acceptance must not depend on strict line coverage"
    );
    assert!(
        !script.contains("cargo nextest run --workspace"),
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
            !script.contains(removed),
            "release acceptance still references `{removed}`"
        );
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mode = fs::metadata(&script_path)
            .expect("script metadata")
            .permissions()
            .mode();
        assert_ne!(
            mode & 0o111,
            0,
            "release acceptance script must be executable"
        );
    }
}

#[test]
fn nix_exposes_release_acceptance_entrypoint() {
    let flake = read("flake.nix");

    for required in [
        "releaseAcceptance = mkScript pkgs \"tangle-release-acceptance\"",
        "scripts/release_acceptance.sh",
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
