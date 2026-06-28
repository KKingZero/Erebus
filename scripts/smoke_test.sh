#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export TMPDIR="${ROOT}/.gotmp"
export GOCACHE="${ROOT}/.gocache"
mkdir -p "$TMPDIR" "$GOCACHE"

echo "==> Go tests"
go test ./pkg/suggestions/... ./pkg/agent/... ./pkg/dnstransport/... ./server/approval/... ./server/listeners/... -count=1

echo "==> Build erebus + teamserver + agent"
make erebus teamserver agent

echo "==> Build Go implant (linux amd64)"
GOOS=linux GOARCH=amd64 go build -o build/implant_linux ./cmd/implant

MINGW_BIN="${ROOT}/.toolchain/mingw-root/usr/bin"
if command -v x86_64-w64-mingw32-gcc >/dev/null 2>&1 || [[ -x "${MINGW_BIN}/x86_64-w64-mingw32-gcc" ]]; then
  echo "==> Build C implant"
  PATH="${MINGW_BIN}:$PATH" make implant-c \
    IMPLANT_ID=smoketest \
    IMPLANT_SECRET=0123456789abcdef0123456789abcdef \
    CALLBACK_URL=https://127.0.0.1:8443
  file build/implant_c.exe
else
  echo "==> SKIP C implant (mingw not available; install mingw64-gcc)"
fi

echo "==> DNS chunk roundtrip"
go test ./pkg/dnstransport/... -run Test -v -count=1

echo "==> All smoke checks passed"