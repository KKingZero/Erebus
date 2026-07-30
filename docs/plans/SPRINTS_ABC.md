# Erebus Sprints A / B / C — Implementation Plan

| Field | Value |
| --- | --- |
| **Source** | Logging after-action + operator Q&A (2026-07-30) |
| **Scope style** | Tight / shippable |
| **Capability home** | **Implant modules** (native Go preferred) |
| **Success metrics** | (1) Easy AD soft path fully in-Erebus (2) Logging-class path to **user** in-Erebus |
| **Test lab** | GOAD + existing `server/e2e` / lab-perf |
| **Approvals** | Keep dual-control; oneshot auto-approve via operator+approver seats |
| **Execution** | Implement in this repo with operator |
| **Sprint C** | Docs / skill / ESC17–WSUS recipe only (no new modules) |

Related: `reports/htb-logging/EREBUS_AFTER_ACTION.md`, `docs/HTB_NEXT_RUNBOOK.md`, `docs/AD_ENGAGEMENT.md`.

---

## Guiding rules

1. **Small PRs** — one theme per PR; green tests before merge.
2. **Fail closed** — empty implant ID/secret, bad hash, skew unknown → clear errors.
3. **External tools only as temporary** — no permanent “just shell out” for P0 foothold.
4. **Sprint B native Go where feasible** — if a piece would balloon (full ADCS wire), ship a **thin, tested subset** rather than a half-broken mega-module.
5. **Out of scope for A–C:** full wsuks, RBCD UI, LSASS, SOCKS rewrite, C implant feature parity.

---

## Sprint A — Foothold reliability + operator glue

**Goal:** From a **local or remote implant**, run **WinRM PTH** reliably and operate without fighting the REPL.  
**Duration target:** ~1–2 weeks of focused work (tight).  
**Exit (must all pass):**

| # | Criterion |
| --- | --- |
| A1 | `lateral winrm <host> "whoami" --user X --hash <NT> --domain D` succeeds via implant (matches pypsrp) on GOAD or lab Windows |
| A2 | `make implant-win` / `make implant` never produces empty `implantID` or empty secret (no `xxd` dependency) |
| A3 | Sleep ≤ 1s does not cause sustained `/beacon` 404 (replay fix or documented min sleep + clamp) |
| A4 | `erebus op` (or equivalent) oneshot: sessions, shell, lateral, pending approve-all — dual-seat auto-approve |
| A5 | Documented **deploy via WinRM** sequence (script or command) that uploads + starts Windows implant |

### A work packages

| ID | Work | Primary paths | Tests |
| --- | --- | --- | --- |
| **A.1** | **WinRM PTH fix** — debug hash transport vs pypsrp; domain\user formatting; encryption; timeouts | `implant/modules/lateral/winrm.go`, `winrm_ntlm_hash.go`, auth helpers | Unit tests + e2e if GOAD reachable; otherwise regression test with mock + manual GOAD checklist |
| **A.2** | **Implant build hygiene** — generate ID/secret in Makefile/Go without `xxd`; refuse empty ID at `LoadConfig` (already errors) + build-time check | `Makefile`, `implant/config.go`, builder if used | `go test` + smoke build windows/linux |
| **A.3** | **Beacon replay / sleep** — use ms (or unique nonce) in HMAC/replay identity, **or** clamp min sleep with loud warning | `pkg/crypto` replay, `server/listeners/beacon.go`, implant sleep | unit tests for sub-second beacons |
| **A.4** | **Operator oneshot CLI** — promote/fix `scripts/htb_oneshot.go` / `htb_lateral.go` into `cmd/erebus` or `erebus op` subcommand; dual-seat auto-approve | `cmd/erebus`, `pkg/erebuscli`, `pkg/operatorcli` | unit + short e2e against local teamserver + local implant |
| **A.5** | **Deploy recipe** — `scripts/deploy_winrm.py` or `erebus op deploy-winrm` wrapping upload+exec (may call pypsrp **only** if implant lateral cannot upload yet; prefer file_upload task once session exists) | `scripts/`, docs | manual GOAD checklist |
| **A.6** | **Seat cert helper** — `erebus certs seats` (EnsureSeatCerts) so lab dual-control is one command | `pkg/erebuscli/certs.go` | smoke |

### A explicitly deferred

- Kerberos, shadow, ADCS, DNS modules  
- Agent catalog overhaul (light prompt touch OK)  
- Changing approval policy levels  

### A acceptance demo script

```text
1. erebus teamserver (HTTPS high port)
2. erebus certs seats
3. build + run local Linux implant → sessions
4. erebus op shell -- 'id'
5. erebus op lateral winrm <GOAD-IP> 'whoami' --user … --hash … --domain …
6. (optional) deploy Windows implant via WinRM recipe → second session
```

---

## Sprint B — Logging-class path to **user** (native implant)

**Goal:** Reproduce Logging **through user flag** with Erebus-owned steps where possible:  
AES/Kerberos bind → (shadow or hash) → WinRM PTH → enough post-ex to read user flag (DLL path may remain hybrid).

**Duration target:** ~2–4 weeks.  
**Exit (must all pass):**

| # | Criterion |
| --- | --- |
| B1 | Obtain **AES TGT** for Protected Users–style account with **clock skew** handled (lab helper + implant or operator-side kerb module used by implant tasks) |
| B2 | **Shadow Creds MVP**: add key credential + recover NT hash for a target account (msa/user) |
| B3 | **Ticket import**: load kirbi/ccache into session/task; at least one of SMB or LDAP using ticket |
| B4 | Soft path regression: SMB list/download + ldap-enum interesting still work (no regressions) |
| B5 | **Dry-run writeup**: on GOAD (or HTB Logging re-run), document “in-Erebus vs external” — user path ≥70% in-Erebus by step count |

### B work packages

| ID | Work | Notes |
| --- | --- | --- |
| **B.1** | **Clock skew + AES TGT** | Prefer implant or shared `pkg/krb` used by tasks; `scripts/htb_krb_env.sh` as thin wrapper OK for operator host time, but product path must not *require* Docker for the happy path if GOAD clocks are synced |
| **B.2** | **Shadow Creds module** | Minimal: write `msDS-KeyCredentialLink`, PKINIT/cert auth path to NT hash — port proven certipy flow carefully; security: approval = critical |
| **B.3** | **Ticket store + lateral/smb with ticket** | Proto fields already have `ticket` on lateral; wire end-to-end |
| **B.4** | **LDAP/SMB with hash already shipped** — verify + fix any gaps found while testing B.1–B.3 | |
| **B.5** | **Optional thin DNS add A** | Only if time remains after B1–B3; else document as external for C recipe |

### B ADCS note (native “where feasible”)

- **Full certipy find/req surface is out of Sprint B** if it slips schedule.  
- **In scope if cheap:** request a **known template** (e.g. User or Machine) once shadow/PKINIT needs it.  
- **UpdateSrv / ESC17 WSUS cert** → documented in **Sprint C**, not required for “user flag” metric.

### B explicitly deferred

- WSUS MITM automation  
- RBCD helpers  
- Domain Admin / root automation  
- Agent Auto full Logging plan  

### B acceptance demo script

```text
1. Soft recon: smb + ldap-enum (existing)
2. Kerberos AES to service account (skew OK)
3. Shadow → msa/user NT hash
4. lateral winrm --hash whoami
5. Read user-equivalent flag/file on lab host
```

---

## Sprint C — Docs, skill, ESC17/WSUS recipe only

**Goal:** Next eng does not re-learn Logging root; no new implant features.  
**Duration target:** ~2–4 days.  
**Exit:**

| # | Criterion |
| --- | --- |
| C1 | `docs/HTB_NEXT_RUNBOOK.md` updated: Logging **solved**, Sprint A/B status, preflight firewall/VPN |
| C2 | `docs/AD_ENGAGEMENT.md` (or new `docs/ESC17_WSUS.md`): UpdateSrv + DNS + wsuks HTTPS + firewalld `tun0` |
| C3 | `/erebus-htb` skill references A oneshots + C recipe; secrets/`$$` rules |
| C4 | After-action gaps table marked done/partial for A/B items |

### C work packages

| ID | Work |
| --- | --- |
| **C.1** | Runbook + AD engagement updates |
| **C.2** | ESC17 / WSUS operator recipe (commands, certipy one-liners, wsuks, quoting for Domain Admins) |
| **C.3** | Skill `erebus-htb` + `references/commands.md` |
| **C.4** | Close the loop in `EREBUS_AFTER_ACTION.md` status section |

### C out of scope

- New modules, CLI features, wsuks packaging into erebus binary  

---

## Dependency graph

```text
A.2 build hygiene ──┐
A.3 beacon sleep  ──┼──► A.4 oneshot CLI ──► A.5 deploy recipe
A.1 WinRM PTH ──────┘         │
                              ▼
                    B.4 soft path QA
                              │
         B.1 Kerberos ◄───────┤
         B.2 Shadow  ─────────┼──► B.5 (optional DNS)
         B.3 Tickets ─────────┘
                              │
                              ▼
                         C.* docs (can start mid-B for WSUS recipe)
```

**Parallelism:** A.2 + A.3 can parallel A.1; C.2 recipe draft can start once Logging notes exist (already do).

---

## Testing strategy

| Layer | What |
| --- | --- |
| Unit | Hash normalize, replay cache, kerb skew math, shadow parse |
| Package | `go test ./implant/modules/lateral/... ./server/approval/... ./pkg/...` |
| Smoke | `bash scripts/smoke_test.sh` |
| E2E | Existing lab-perf + **GOAD checklist** for WinRM PTH and soft path |
| HTB | Optional re-run Support (Easy) after A; Logging user-path after B |

**Dual-control in tests:** oneshot dials operator + approver certs (as Logging eng did); no policy weaken.

---

## Risk register

| Risk | Mitigation |
| --- | --- |
| WinRM library limits vs pypsrp | Pin behavior with integration test; consider alternate HTTP stack if needed |
| Shadow Creds complexity | MVP only: one account, one DC, critical approval |
| GOAD clock already synced | Still implement skew helper; test with forced FAKETIME |
| Scope creep into WSUS | Hard stop: C is docs only |
| Stretch metric “both Easy + Logging user” | A owns Easy soft; B owns Logging-class user — do not block A exit on B features |

---

## Definition of done (program)

- [ ] Sprint A exit A1–A5 green  
- [ ] Sprint B exit B1–B5 green (B5 optional DNS)  
- [ ] Sprint C exit C1–C4 green  
- [ ] After-action gap table updated  
- [ ] No secrets committed; GOAD/HTB cleanup notes if used  

---

## Implementation status (2026-07-30)

| ID | Status | Notes |
| --- | --- | --- |
| **A.2** | **Done** | Makefile: openssl/python ID+secret; fail closed if empty/not 64 hex; default callback `:8443` |
| **A.3** | **Done** | Implant uses Unix **ms** timestamps; VerifyHMAC accepts s or ms; replay allows sub-second |
| **A.1** | **Partial** | Domain-aware NTLMv2 TYPE3 for PTH; conn pin MaxConnsPerHost=1; password path uses ClientNTLM. **Message encryption still open** (pypsrp `encryption=auto` parity) — validate on GOAD |
| **A.4** | **Done** | `erebus op sessions\|shell\|lateral\|pending\|approve-all` dual-seat |
| **A.6** | **Done** | `erebus certs seats` |
| **A.5** | **Done** | `scripts/deploy_winrm.py` (pypsrp temporary bridge) |

Next: GOAD live validation of A.1; then B.1 Kerberos.

---

## Open items (non-blocking)

- Exact GOAD hostnames/IPs for the WinRM PTH e2e target.  
- WinRM **message encryption** with NT hash (A.1 follow-up if GOAD requires AllowUnencrypted=false).
