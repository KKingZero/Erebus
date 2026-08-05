#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export TMPDIR="${ROOT}/.gotmp"
export GOCACHE="${ROOT}/.gocache"
mkdir -p "$TMPDIR" "$GOCACHE"

echo "==> Go tests"
go test ./pkg/suggestions/... ./pkg/agent/... ./pkg/dnstransport/... ./server/approval/... ./server/listeners/... ./server/builder/... ./pkg/crypto/... -count=1

echo "==> Build erebus + teamserver + agent"
make erebus teamserver agent

echo "==> Build Go implant (linux amd64)"
GOOS=linux GOARCH=amd64 go build -o build/implant_linux ./cmd/implant

echo "==> C implant host tests + Linux peer smoke"
SKIP_LIVE=1 bash scripts/c_linux_e2e_smoke.sh

MINGW_BIN="${ROOT}/.toolchain/mingw-root/usr/bin"
LLVM_MINGW="${ROOT}/.toolchain/llvm-mingw/bin"
if command -v x86_64-w64-mingw32-gcc >/dev/null 2>&1 || [[ -x "${MINGW_BIN}/x86_64-w64-mingw32-gcc" ]] || [[ -x "${LLVM_MINGW}/x86_64-w64-mingw32-gcc" ]]; then
  echo "==> Build C implant Windows PE"
  CA_ARG=()
  if [[ -f "${HOME}/.erebus/ca-cert.pem" ]]; then
    CA_ARG=(CA_CERT_PATH="${HOME}/.erebus/ca-cert.pem")
  elif [[ -f "${HOME}/.erebus/certs/ca.pem" ]]; then
    CA_ARG=(CA_CERT_PATH="${HOME}/.erebus/certs/ca.pem")
  else
    # Ephemeral CA so fail-closed HTTPS still builds
    openssl req -x509 -newkey rsa:2048 -keyout build/smoke-ca.key -out build/smoke-ca.pem \
      -days 1 -nodes -subj /CN=smoke >/dev/null 2>&1 || true
    [[ -f build/smoke-ca.pem ]] && CA_ARG=(CA_CERT_PATH="${ROOT}/build/smoke-ca.pem")
  fi
  PATH="${LLVM_MINGW}:${MINGW_BIN}:$PATH" make implant-c \
    IMPLANT_ID=smoketest0123456789abcdef \
    IMPLANT_SECRET=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
    CALLBACK_URL=https://127.0.0.1:8443 \
    "${CA_ARG[@]}"
  file build/implant_c.exe
else
  echo "==> SKIP C Windows PE (mingw not available)"
fi

echo "==> DNS chunk roundtrip"
go test ./pkg/dnstransport/... -run Test -v -count=1

echo "==> All smoke checks passed"