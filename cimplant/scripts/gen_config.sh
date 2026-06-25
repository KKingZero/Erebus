#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${1:-$ROOT/include/erebus/config.h}"
TEMPLATE="${2:-$ROOT/include/erebus/config.h.in}"

IMPLANT_ID="${IMPLANT_ID:-}"
IMPLANT_SECRET="${IMPLANT_SECRET:-}"
CALLBACK_URL="${CALLBACK_URL:-https://127.0.0.1:443}"
SLEEP_MS="${SLEEP_MS:-5000}"
JITTER_PCT="${JITTER_PCT:-20}"
CA_CERT_PEM="${CA_CERT_PEM:-}"
TRANSPORT_TYPE="${TRANSPORT_TYPE:-https}"
DNS_DOMAIN="${DNS_DOMAIN:-}"
DNS_SERVER="${DNS_SERVER:-}"
CDN_DOMAIN="${CDN_DOMAIN:-}"

sed \
  -e "s|@IMPLANT_ID@|${IMPLANT_ID}|g" \
  -e "s|@IMPLANT_SECRET@|${IMPLANT_SECRET}|g" \
  -e "s|@CALLBACK_URL@|${CALLBACK_URL}|g" \
  -e "s|@SLEEP_MS@|${SLEEP_MS}|g" \
  -e "s|@JITTER_PCT@|${JITTER_PCT}|g" \
  -e "s|@CA_CERT_PEM@|${CA_CERT_PEM}|g" \
  -e "s|@TRANSPORT_TYPE@|${TRANSPORT_TYPE}|g" \
  -e "s|@DNS_DOMAIN@|${DNS_DOMAIN}|g" \
  -e "s|@DNS_SERVER@|${DNS_SERVER}|g" \
  -e "s|@CDN_DOMAIN@|${CDN_DOMAIN}|g" \
  "$TEMPLATE" > "$OUT"