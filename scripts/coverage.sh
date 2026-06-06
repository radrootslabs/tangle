#!/usr/bin/env bash
set -euo pipefail

if ! cargo llvm-cov --version >/dev/null 2>&1; then
  printf '%s\n' 'cargo llvm-cov is required'
  exit 1
fi

cargo llvm-cov clean --workspace
cargo llvm-cov --workspace --all-targets
