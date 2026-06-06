#!/usr/bin/env bash
set -euo pipefail

docker compose -f ops/local/surrealdb/compose.yml up -d --wait
