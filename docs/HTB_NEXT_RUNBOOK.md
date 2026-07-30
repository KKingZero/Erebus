# HTB Next Machines — Runbook, Dev Steps & Security Checks

| Field | Value |
| --- | --- |
| **Audience** | Operator + Erebus developer |
| **Labs covered so far** | Support (solved), Logging (solved 2026-07-30) |
| **Erebus P0 shipped** | WinRM PTH, LDAP hash/`interesting`, remote SMB client |
| **Related** | `docs/AD_ENGAGEMENT.md`, `reports/htb-support/`, `reports/htb-logging/` (see `EREBUS_AFTER_ACTION.md`) |
| **Last updated** | 2026-07-30 |

Authorized HTB / lab use only. Do not use against systems without permission.

**Agent skills:** `/erebus-htb` (C2 + HTB) · `/htb-pentest` (general HTB). Installed for Grok and Claude under project `.grok/skills/`, `.claude/skills/`, and user `~/.grok/skills/`, `~/.claude/skills/`.

---

## 1. Goals for the next few boxes

1. **Finish unfinished work** (Logging root) with a clean procedure.
2. **Exercise new Erebus P0 features** on a real Windows/AD target (SMB → LDAP interesting → WinRM PTH).
3. **Drive P1 product gaps** with machines that need ACL abuse, Kerberos tickets, or shadow-style paths.
4. **Keep OPSEC and lab hygiene** consistent so reports and framework QA stay trustworthy.

---

## 2. Status snapshot

| Machine | Difficulty | Status | Flags | Erebus use so far |
| --- | --- | --- | --- | --- |
| **Support** | Easy (Win/AD) | Solved | user + root | Mostly external tools; good first implant-drop target |
| **Logging** | Medium (Win/AD) | **Solved** | user + root | C2 local implant OK; AD chain mostly external — see `reports/htb-logging/EREBUS_AFTER_ACTION.md` |
| Lab-perf (Juice/Meta) | N/A | Passed | N/A | Implant recon only |

---

## 3. Recommended next HTB queue

Order is intentional: finish open work → validate P0 on Easy AD → push Medium techniques that map to P1 Erebus modules.

### Priority 0 — Finish what is open

| # | Machine | Why | Success criteria |
| --- | --- | --- | --- |
| 0 | **Logging** (resume) | Root stalled on WSUS MITM; best medium AD chain for framework notes | DA + `root.txt`; short addendum to `reports/htb-logging/` |

**Resume checklist (Logging root)** — full detail in `reports/htb-logging/PROGRESS_AND_FIXES.md`:

1. VPN up; re-spawn if IP changed; re-establish `msa_health$` / jaylee path if box reset.
2. Dump WU registry (`WUServer` / `WUStatusServer` / `UseWUServer`).
3. Match `wsuks` to HTTP:8530 vs HTTPS:8531 + cert SAN `wsus.logging.htb`.
4. Re-point DNS A → current `tun0`; confirm client hits in log.
5. DA confirmation → read `C:\Users\toby.brynleigh\Desktop\root.txt`.
6. Write root section into `reports/htb-logging/PROGRESS_AND_FIXES.md`.

### Priority 1 — Validate Erebus soft-compromise path (Easy AD)

| # | Machine | Techniques to exercise | Erebus tools to prefer |
| --- | --- | --- | --- |
| 1 | **Support** (re-run as QA, if available / retired clone / similar Easy AD) | Anon SMB, LDAP free-text secret, WinRM, optional RBCD | `smb`, `ldap-enum interesting`, `lateral winrm` (+ `--hash` if available) |
| 2 | Next **Easy Windows/AD** from your HTB path (e.g. classic “soft AD” boxes: share → cred → WinRM/RDP → ACL) | Same soft chain without needing C2 mid-path | Drop implant after first shell; run soft path from `docs/AD_ENGAGEMENT.md` |

**QA acceptance (P0 features):**

- [ ] `smb list_shares` / `list_dir` / `download` without leaving Erebus  
- [ ] `ldap-enum interesting` recovers free-text secret class attrs  
- [ ] `lateral winrm … --pass` **and** at least one `--hash` shell if hash exists  
- [ ] Agent Plan mode lists `smb` + soft path; Auto does not DA-abuse without objective  

### Priority 2 — Medium AD that force P1 Erebus work

Pick **one** primary Medium at a time. Prefer machines that stress gaps still missing in Erebus.

| Theme | What the box should force | Product work it unlocks |
| --- | --- | --- |
| **ACL / RBCD** | GenericAll / Write on computer objects, machine account abuse | ACL enum module, RBCD + machine-account helpers |
| **gMSA / Shadow Creds** | GenericWrite on MSA/user + cert path | Minimal shadow-creds module |
| **Protected Users / AES Kerberos** | Password works only with AES TGT (no NTLM) | Kerberos AES TGT + ticket-aware lateral |
| **Delegation / tickets** | Constrained / unconstrained / tgtdeleg-style | Ticket export, lateral with `ticket` field |
| **Multi-host** | Jump via SOCKS / second implant | SOCKS polish, deploy-via-WinRM |

Examples of HTB themes (names rotate; pick current retired/active equivalents with writeups matching the theme):

- Easy→Medium “Support-like”: share + LDAP attribute + WinRM + ACL  
- Medium “Logging-like”: log secret → gMSA/shadow → DLL/hijack → DNS/WSUS  
- Medium Kerberos-heavy: AS-REP/Kerberoast → ticket abuse (good for roast modules already in tree)

### Priority 3 — After AD core is solid

| Track | Purpose |
| --- | --- |
| Linux Easy/Medium (web → shell) | Implant HTTPS callback, shell, portscan, SOCKS on non-Windows |
| Cloud / hybrid (if on path) | `cloud_harvest` validation |
| Hard AD / forest | Only after P1 RBCD/shadow/tickets land |

---

## 4. Per-machine engagement procedure

Use this every time so reports stay comparable and Erebus gaps get logged.

### 4.1 Pre-flight

```text
[ ] HTB VPN connected (machines_us-5 or current)
[ ] Target IP reachable (nmap -Pn -n -p 445,389,88,5985,5986 --open <IP>)
[ ] Workdir: ~/htb-<machine>/  (secrets as files only — never bash $$)
[ ] Clock: note skew vs DC if Kerberos will be used
[ ] Erebus: make erebus && erebus serve  (if testing C2 this session)
[ ] Windows implant built if callback path planned
```

### 4.2 Attack phases (record in report)

1. Recon (ports, SMB shares, web, LDAP anon if any)  
2. Initial access  
3. User flag  
4. Privilege escalation / domain path  
5. Root flag  
6. **Erebus section** — what ran in-framework vs external tools  
7. **Gap list** — missing module / bug / UX pain (feeds §5)  

### 4.3 Report locations

```text
reports/htb-<machine>/
  PENTEST_REPORT.md          # findings-oriented (target issues)
  PROGRESS_AND_FIXES.md      # if incomplete / tooling notes
```

Support template: `reports/htb-support/PENTEST_REPORT.md`.  
Logging template: `reports/htb-logging/PROGRESS_AND_FIXES.md`.

### 4.4 Erebus soft path (after foothold)

```text
sessions → use <id>
shell whoami / ifconfig
smb list_shares --host <DC_or_target> [--anon | --user --pass|--hash]
smb list_dir / download …
ldap-enum interesting --domain … --dc … --user … --pass|--hash …
ldap-enum kerberoastable …
lateral winrm <host> "whoami" --user … --pass … --domain …
# or:  --hash <NT>
loot
```

AI: `ai` → Plan with soft-compromise objective → Auto with approvals.

---

## 5. Development steps (Erebus) — ordered for next boxes

### Done (do not re-do unless bugs found)

| Item | Notes |
| --- | --- |
| WinRM PTH | `lateral winrm … --hash` |
| LDAP hash bind | `ldap-enum … --hash` |
| LDAP `interesting` / `secrets` / `rbcd` query types | Free-text + RBCD presence |
| Remote SMB module | `smb` list/download |
| Agent soft path + AD_ENGAGEMENT updates | Catalog tools `smb`, expanded prompt |

### Sprint B — before/during next Medium ACL/Kerberos box

| Step | Work | Validates on |
| --- | --- | --- |
| B1 | ACL / dangerous-rights LDAP surface (GenericAll, WriteDacl, WriteProperty on computers/users/gMSA) | Support-style, Logging GenericWrite |
| B2 | Kerberos AES TGT request + export loot; wire `LateralMoveConfig.ticket` if feasible | Protected Users accounts |
| B3 | Machine account create + RBCD write + S4U ticket path (approval: critical) | Support root path in-framework |
| B4 | Operator CLI + agent catalog + suggestions for B1–B3 | Auto Plan lists tools |
| B5 | Unit tests + one GOAD or HTB replay smoke | CI / smoke_test |

### Sprint C — Logging-class / modern AD

| Step | Work | Validates on |
| --- | --- | --- |
| C1 | Minimal shadow credentials (KeyCredentialLink write/clear + usable auth) | Logging mid-chain |
| C2 | Creds/loot → next-hop suggestions (loot id refs, no secret echo) | All AD boxes |
| C3 | Deploy implant via WinRM (upload + exec helper or documented sequence) | Post-user on any Win box |
| C4 | PsExec/SCMR completeness from non-Windows implant if needed | Lateral payload staging |

### Lab-host tooling (not implant, still unblocks HTB)

| Pri | Item | Status intent |
| --- | --- | --- |
| P0 | `scripts/htb_krb_env.sh` (LDAP time skew + faketime Docker) | Build before next Kerberos-heavy box |
| P0 | Secrets only via files (document in every report SOP) | Habit |
| P1 | Docker images: `logging-krb`, `mingw-i686`, `wsuks-tool` | Logging root + DLL work |
| P2 | pypsrp PTH helper only if Erebus WinRM unavailable | Fallback |

### Definition of done (product)

- Soft path on Easy AD fully inside Erebus (no smbclient/ldap3/pypsrp required for user).  
- At least one Medium root uses a **new** Erebus module (ACL/RBCD/shadow/ticket).  
- Every eng produces a short **Erebus gaps** bullet list in the report.

---

## 6. Security checks (every engagement)

### 6.1 Authorization & scope

| Check | Rule |
| --- | --- |
| Scope | Only assigned HTB machine IP(s) via HTB VPN |
| Out of scope | Other players, VPN infra, production, non-lab hosts |
| Cleanup | Remove lab machine accounts, RBCD blobs, DNS records, local users created for privesc when box is shared/reused |
| Implants | Kill implant; no persistence left after eng unless explicitly testing persist (then remove) |

### 6.2 Credential & secret hygiene (operator host)

| Check | Rule |
| --- | --- |
| Shell expansion | Never put passwords with `$` in double-quoted bash (`$$` → PID). Write to file via Python/`printf` |
| Files | Store secrets under `~/htb-<machine>/` with mode `600`; do not commit to git |
| Reports | Prefer redaction in public commits; lab-only flags/creds OK in private `reports/` if repo is private |
| Loot | Erebus loot DB under `~/.erebus/` — treat as sensitive |
| Logs | Do not paste full NT hashes/passwords into public issues/PRs |

### 6.3 Kerberos / time

| Check | Rule |
| --- | --- |
| Skew | Before TGT: compare local UTC vs DC LDAP `currentTime` |
| Fix | Prefer faketime/Docker wrapper over `date -s` without need |
| Caches | Treat `.ccache` / `.kirbi` as expiring secrets; delete after eng |

### 6.4 Erebus / C2 safety

| Check | Rule |
| --- | --- |
| Approvals | Keep high/critical gate on; dual-control for DA-class tasks |
| Sleep | Lab interactive: low sleep OK; never leave loud implant on shared box overnight |
| Callbacks | Listener only on intended interface; confirm implant points at your C2, not a shared lab IP |
| Generate | Prefer C implant for Windows when toolchain available (`docs/AD_ENGAGEMENT.md`) |
| SOCKS | Stop SOCKS when done; do not tunnel non-scope traffic |
| Builds | Rebuild implant per eng if secret/callback changes; do not reuse old ldflag secrets across long-lived ops |

### 6.5 Target OPSEC (lab-aware)

| Check | Rule |
| --- | --- |
| Noise | Prefer targeted LDAP queries over full domain dumps |
| Service accounts | Prefer PTH/WinRM over LSASS until objective needs creds_dump |
| DA actions | RBCD / DCSync / shadow only when root objective requires; log in report |
| Evidence | Capture command + output snippets for findings; avoid unnecessary second DA paths |

### 6.6 Pre-submit / end-of-session checklist

```text
[ ] user.txt / root.txt submitted if obtained
[ ] Report updated (flags, path, Erebus gaps)
[ ] Lab artifacts cleaned (EREBUS01$, RBCD, DNS, local users) if reusing box
[ ] Implant dead; listeners stopped if not needed
[ ] No secrets staged in git status (git status clean of ~/htb-* copies)
[ ] Open product issues filed or gaps listed in report § Erebus
```

---

## 7. Quick command cheat sheet

### Host / VPN

```bash
sudo openvpn --config /path/to/machines_us-*.ovpn
ip -br a show tun0
nmap -Pn -n -p 445,389,88,5985,5986,8530,8531 --open <TARGET_IP>
```

### Secrets without `$$`

```bash
python3 -c 'open("svc_pass.txt","w").write("Em3rg3ncyPa$$2026")'
# tools read from file — never: --pass "Em3rg3ncyPa$$2026" in bash double quotes
```

### Erebus operator (post-implant)

```text
erebus serve          # teamserver
erebus operator       # or unified CLI
sessions
use <session-id>
smb list_shares --host <IP> --anon
ldap-enum interesting --domain DOM --dc DC --user u --pass p
lateral winrm <IP> "whoami /all" --user u --hash <NT> --domain DOM
pending
approve <id>
loot
```

### Builds

```bash
make proto erebus
make implant-win CALLBACK_URL=https://<C2>:443 SLEEP_MS=500 JITTER_PCT=10
# optional: generate --language c  (Windows PE)
bash scripts/smoke_test.sh
```

---

## 8. Suggested calendar (example)

| Session | Focus |
| --- | --- |
| 1 | Logging root finish + report closeout |
| 2 | Support-style re-run / Easy AD with full Erebus soft path QA |
| 3 | Sprint B1–B2 coding (ACL enum + Kerberos AES/ticket) |
| 4 | Medium ACL/RBCD box — exercise B modules; file gaps |
| 5 | Sprint C shadow + deploy-via-WinRM; Logging-class techniques in-framework |

Adjust to your HTB rank path; keep the **finish open → QA P0 → code P1 → Medium that needs P1** loop.

---

## 9. Gap log template (paste into each report)

```markdown
## Erebus gaps this eng

| Gap | Severity | Workaround used | Wanted module/fix |
| --- | --- | --- | --- |
| e.g. no DNS write | medium | bloodyAD | ad_dns module |
| e.g. no shadow creds | high | certipy | shadow_creds |

## What worked in-framework

- smb / ldap / winrm / …
```

---

## 10. References

- `docs/AD_ENGAGEMENT.md` — operator AD cookbook  
- `docs/GOLDEN_DEMO.md` — Sprint 1 Auto path  
- `docs/GOAD_LAB.md` — offline AD lab alternative  
- `reports/htb-support/PENTEST_REPORT.md` — Support findings  
- `reports/htb-logging/PROGRESS_AND_FIXES.md` — Logging progress + root checklist  
- Plan (product): soft compromise → ACL/RBCD → shadow/tickets  

---

*Lab only. Keep this file updated when a machine is finished or a Sprint ships.*
