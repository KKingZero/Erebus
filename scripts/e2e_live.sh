#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export TMPDIR="${ROOT}/.gotmp"
export GOCACHE="${ROOT}/.gocache"
mkdir -p "$TMPDIR" "$GOCACHE"

echo "==> Live e2e (teamserver + simulated implant)"
go test ./server/e2e/... -v -count=1 -timeout 3m

echo "==> E2E passed"