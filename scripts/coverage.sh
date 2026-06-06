#!/usr/bin/env bash
set -euo pipefail

if ! cargo llvm-cov --version >/dev/null 2>&1; then
  printf '%s\n' 'cargo llvm-cov is required'
  exit 1
fi

if command -v llvm-cov >/dev/null 2>&1 && command -v llvm-profdata >/dev/null 2>&1; then
  LLVM_COV="$(command -v llvm-cov)"
  LLVM_PROFDATA="$(command -v llvm-profdata)"
  export LLVM_COV
  export LLVM_PROFDATA
fi

cargo llvm-cov clean --workspace
cargo llvm-cov --workspace --all-targets --show-missing-lines --fail-under-lines 100 --fail-uncovered-lines 0
