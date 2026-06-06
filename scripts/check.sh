#!/usr/bin/env bash
set -euo pipefail

cargo fmt --all -- --check
cargo test -p tangle --test source_comments
cargo check --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
