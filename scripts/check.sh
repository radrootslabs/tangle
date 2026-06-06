#!/usr/bin/env bash
set -euo pipefail

cargo fmt --all -- --check
cargo test -p tangle --test coverage_gate
cargo test -p tangle --test source_comments
cargo test -p tangle --test unsafe_code
cargo check --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
