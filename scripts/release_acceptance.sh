#!/usr/bin/env bash
set -euo pipefail

scripts/check.sh
scripts/test.sh
cargo test -p tangle_runtime --test base_relay_v2
cargo test -p tangle_groups
cargo test -p tangle_store_pocket
cargo test -p tangle_bench
scripts/benchmark_report.sh
cargo test -p tangle --test source_comments
cargo test -p tangle --test unsafe_code
