#!/usr/bin/env bash
set -euo pipefail

scripts/check.sh
scripts/test.sh
cargo nextest run --workspace
cargo test -p tangle --test nip01_conformance
cargo test -p tangle --test nip09_conformance
cargo test -p tangle --test nip42_conformance
cargo test -p tangle --test nip50_conformance
cargo test -p tangle --test nip99_conformance
cargo test -p tangle --test discussion_conformance
cargo test -p tangle --test moderation_conformance
cargo test -p tangle --test commerce_privacy_conformance
cargo test -p tangle --test abuse_conformance
cargo test -p tangle --test run_integration
cargo test -p tangle_runtime runtime_restore_command_imports_backup_and_rebuilds_projection_state
cargo test -p tangle_bench
cargo test -p tangle --test source_comments
cargo test -p tangle --test unsafe_code
scripts/coverage.sh
