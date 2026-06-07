#!/usr/bin/env bash
set -euo pipefail

scripts/check.sh
scripts/test.sh
cargo nextest run --workspace
