#!/usr/bin/env bash
set -euo pipefail

cargo run -p tangle_bench --bin tangle-benchmark-report -- "$@"
