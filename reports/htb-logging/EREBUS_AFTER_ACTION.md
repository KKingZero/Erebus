# Erebus After-Action — HTB Logging (2026-07-30)

| Field | Value |
| --- | --- |
| **Machine** | Logging (Medium, Windows / AD) |
| **Target** | `10.129.245.130` / `logging.htb` |
| **Objective** | Full compromise (user + root) **and** exercise Erebus C2 |
| **Outcome** | **Box solved** · Erebus **partially** used (C2 path exercised; most AD steps external) |
| **Attacker** | `tun0` `10.10.14.15` · teamserver HTTPS `:8443` · gRPC `127.0.0.1:50051` |

---

## 1. Executive scorecard

| Dimension | Score (1–5) | Notes |
| --- | --- | --- |
| **Teamserver reliability** | **4** | Started cleanly; HTTPS listener on non-priv port; dual-seat certs worked |
| **Operator / approvals UX** | **3** | Dual-control works; no first-class non-interactive operator API beyond ad-hoc oneshots |
| **Implant lifecycle (build → check-in)** | **2** | Manual ldflags painful; empty `implantID` when `xxd` missing; Windows implant never useful mid-chain |
| **Soft-compromise modules (SMB / LDAP / WinRM)** | **2** | Shipped on paper; **not the primary path** this eng — external tools did the work |
| **Lateral WinRM PTH** | **1** | Timeout / 401 from implant; **pypsrp succeeded** with same hash |
| **Kerberos / Protected Users / tickets** | **1** | No in-framework AES TGT, clock-skew helper, or ticket lateral |
| **Shadow Creds / ADCS / DNS abuse** | **1** | Completely external (certipy, bloodyAD) |
| **WSUS / operator infra** | **0** | Correctly out-of-scope for implant; host firewall + cert were the real pain |
| **End-to-end “use Erebus for HTB” goal** | **2.5** | C2 demo OK; **engagement velocity still external-tool driven** |

**Bottom line:** Erebus was a **working C2 plane** (register, shell, approve) but **not yet an engagement plane** for a Medium AD chain like Logging. The box was solved with pypsrp / impacket / certipy / bloodyAD / wsuks; Erebus rode along for local implant shell and policy plumbing.

---

## 2. What ran inside Erebus vs outside

### Inside Erebus (worked)

| Capability | Evidence |
| --- | --- |
| `erebus teamserver` | gRPC + HTTPS `:8443` |
| Dual-control approvals | Operator + approver mTLS; shell/lateral gated |
| Local Linux implant | `callbackURL=https://127.0.0.1:8443`, shell `EREBUS_OK` |
| Generate / fleet secret | Config `implant_secret` + ldflags build |
| Oneshot helpers | `scripts/htb_oneshot.go`, `htb_lateral.go` (ad-hoc) |

### Outside Erebus (required to finish)

| Step | Tool |
| --- | --- |
| SMB share + log loot | `smbclient` |
| Clock skew + AES TGT (Protected Users) | Docker `libfaketime` + `getTGT.py` |
| Shadow Creds on `msa_health$` | `certipy shadow auto` |
| WinRM PTH shell | **pypsrp** (not Erebus lateral) |
| File upload (implant, zip, Rubeus) | pypsrp `copy` |
| DLL hijack wait / ACL fix | PowerShell via pypsrp |
| Ticket harvest | Rubeus on target → kirbi → ccache |
| AD DNS write | `bloodyAD add dnsRecord` |
| ADCS `UpdateSrv` cert | `certipy req` |
| WSUS MITM | `wsuks --serve-only` + ADCS PEM |
| Root shell / flag | pypsrp as `dark` |

### Attempted in Erebus but failed / weak

| Attempt | Failure mode |
| --- | --- |
| Windows implant on DC | Target → attacker `:8443` blocked until firewall; even then late in chain |
| `make implant-win` without tools | `xxd` missing → **empty implantID** → implant refuses to start |
| Beacon sleep 500 ms | Replay-cache collisions → HTTP 404 on `/beacon` |
| `lateral winrm … --hash` | Task timeout; later 401 vs pypsrp success |
| Soft path SMB/LDAP from implant | Not exercised as primary path (no early session on target) |

---

## 3. Phase-by-phase Erebus fitness

```text
Recon / SMB logs     ████░░░░░░  external (smbclient)
Kerberos AES+skew    ░░░░░░░░░░  external (faketime/docker)
Shadow Creds         ░░░░░░░░░░  external (certipy)
WinRM foothold       ██░░░░░░░░  pypsrp; Erebus PTH broken
DLL / code exec      █░░░░░░░░░  external upload + scheduled task
User flag            █░░░░░░░░░  DLL payload
Ticket / DNS         ░░░░░░░░░░  Rubeus + bloodyAD
ADCS cert            ░░░░░░░░░░  certipy
WSUS root            ░░░░░░░░░░  wsuks + host firewall
C2 / shell demo      ████████░░  local implant only
```

Logging is a **P1/P2 stress box** for Erebus (gMSA shadow, AES Kerberos, tickets, DNS, ADCS), not a P0 soft-path validation box. Shipping “WinRM PTH + SMB + LDAP interesting” is necessary but **insufficient** for this class of machine.

---

## 4. Product gaps (ordered by eng pain)

### P0 — Fix before next Windows eng

| # | Gap | Why it hurt | Wanted |
| --- | --- | --- | --- |
| P0.1 | **WinRM PTH unreliable** | Primary foothold after gMSA hash; pypsrp worked, Erebus did not | Parity with pypsrp NTLM hash transport; e2e test against live WinRM |
| P0.2 | **Implant build ergonomics** | `xxd` missing → empty ID; secret/callback easy to mis-set | `make implant-win` fails closed if ID/secret empty; no hard dep on `xxd` (use `od`/`python`) |
| P0.3 | **Beacon sleep vs replay window** | 500 ms sleep → 404 beacons | ms-resolution timestamps or allow sub-second beacons without drop |
| P0.4 | **Non-interactive operator** | REPL-only friction for agents | Stable `erebus op -c …` or gRPC oneshot for shell/lateral/smb/approve |
| P0.5 | **Deploy via WinRM** | 20 MB upload + Start-Process still external | First-class `deploy` / documented pypsrp-or-in-framework drop |

### P1 — Needed for Logging-class chains

| # | Gap | Wanted |
| --- | --- | --- |
| P1.1 | **Kerberos AES TGT + clock skew** | `krb tgt` helper: LDAP `currentTime` → skew → AES256 TGT (Protected Users) |
| P1.2 | **Shadow credentials** | Minimal: add/clear keycred + PKINIT/NT hash (wrap certipy or native) |
| P1.3 | **Ticket import / lateral** | Load kirbi/ccache; `lateral … --ticket` / SMB-Kerb |
| P1.4 | **AD DNS write** | `dns add A wsus <ip>` with Kerberos (bloodyAD-class) |
| P1.5 | **ADCS request** | Template list + `req` with DNS SAN (UpdateSrv / ESC17 path) |

### P2 — Quality / velocity

| # | Gap | Wanted |
| --- | --- | --- |
| P2.1 | Default listener **443** needs root | Sensible default high port or auto-fallback document |
| P2.2 | Approver cert provisioning | `erebus certs seats` on first serve without manual Go snippet |
| P2.3 | Lab host runbook | VPN + firewalld `tun0` trusted zone checklist in skill/runbook |
| P2.4 | Secrets hygiene | Operator refuse/`--pass-file` for `$`-heavy passwords |
| P2.5 | Agent catalog | Plan mode should prefer soft path; mark shadow/ADCS/DNS as external until modules exist |

### Explicit non-goals (do **not** force into implant)

| Capability | Rationale |
| --- | --- |
| Full **wsuks** / WSUS MITM server | Operator infrastructure; keep external + document |
| Generic “run arbitrary PE on attacker” | Use Docker images (`wsuks-tool`, `logging-krb`) |
| Replace certipy entirely day-one | Thin wrappers or shell-out OK for v1 |

---

## 5. What *not* to change

1. **Approval gate** — Dual-control is correct; keep for high-risk lateral/creds. Improve *automation* of the second seat in lab, don’t remove the gate.
2. **Compiled-in modules** — Right architecture; expand registry carefully.
3. **Protobuf wire protocol** — Fine; gaps are feature surface, not transport.
4. **Keeping WSUS as external** — Correct product boundary.

---

## 6. Recommended change plan (concrete)

### Sprint A — “Foothold reliability” (1–2 weeks)

1. Fix **WinRM NTLM hash** path until e2e matches pypsrp (`implant/modules/lateral/winrm*.go` + live test).
2. Harden **implant build**: generate ID/secret in pure Go/Make without `xxd`; refuse empty ID.
3. Fix **beacon replay** for sleep &lt; 1s (or clamp min sleep with warning).
4. Add **`erebus op`** oneshot commands: `sessions`, `shell`, `lateral`, `approve-pending`, `smb`, `ldap-enum`.
5. Document **lab preflight**: VPN, `firewall-cmd --zone=trusted --add-interface=tun0`, callback IP, skew.

**Exit criteria:** From a local Linux implant, `lateral winrm DC --hash … whoami` returns in &lt; 15s on a lab Windows host.

### Sprint B — “AD soft+medium” (2–4 weeks)

1. Kerberos helper: skew + AES TGT + ccache export.
2. Shadow Creds MVP (or tightly scoped certipy integration with sealed secrets).
3. Ticket lateral for at least WinRM or SMB.
4. Optional: DNS add A record with Kerberos.

**Exit criteria:** Logging soft path to **user** without leaving Erebus except Rubeus/tgtdeleg if still needed once.

### Sprint C — “Operator infra polish”

1. Runbook + skill updates for ESC17/WSUS (cert template `UpdateSrv`, HTTPS 8531, firewall).
2. Optional operator-side recipe docs — not implant modules.

---

## 7. Suggested Erebus gaps table (for runbook)

| Gap | Workaround used | Priority |
| --- | --- | --- |
| WinRM PTH broken/slow | pypsrp | **P0** |
| No AES Kerberos / skew | Docker faketime + getTGT | **P1** |
| No shadow creds | certipy | **P1** |
| No ticket lateral | Rubeus + convert + bloodyAD | **P1** |
| No ADCS enroll | certipy req UpdateSrv | **P1** |
| No AD DNS write | bloodyAD | **P1** |
| Implant build fragile | Manual ldflags + python secrets | **P0** |
| Beacon replay @ low sleep | sleep ≥ 2s | **P0** |
| No deploy-via-WinRM | pypsrp copy + Start-Process | **P0** |
| WSUS MITM | wsuks + host firewall | **P2** (docs only) |

---

## 8. Verdict

| Question | Answer |
| --- | --- |
| Did Erebus help solve Logging? | **Marginally** — C2/approval stack proven; not on the critical path for flags |
| Is the product direction right? | **Yes** — soft path P0 then AD medium modules |
| Should we change architecture? | **No** — fix reliability + fill P1 modules |
| Highest leverage next code? | **WinRM PTH parity + implant build/beacon hygiene + operator oneshot CLI** |

**Honest product grade this eng: C+ as a C2, D as an AD engagement framework.**  
Fix P0 and the grade on the next Easy/Medium soft AD box should jump to B without changing vision.

---

*Generated after HTB Logging full solve · 2026-07-30 · flags in `~/htb-logging/FLAGS.txt` · path notes in `PROGRESS_AND_FIXES.md`*
