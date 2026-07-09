# Golden AD Auto eval checklist (Sprint 1)

Run **5 times** without changing code between runs. Same domain, same model.

## Preflight

- [ ] Teamserver up (`erebus serve`)
- [ ] Implant alive (`sessions` shows yes / recent check-in)
- [ ] Approver + operator certs exist
- [ ] LLM configured (prefer Claude/GPT)
- [ ] Objective text is the frozen golden objective (docs/GOLDEN_DEMO.md)

## Per run

| # | Check | Y/N |
|---|--------|-----|
| 1 | Plan mode (optional): produces Steps + Approvals, no tasks on server | |
| 2 | Auto starts without error | |
| 3 | Low-risk recon runs (shell / ifconfig / list_sessions) | |
| 4 | `ldap_enum` requested → approval banner shown | |
| 5 | `[a]` unblocks; LDAP result returns | |
| 6 | Kerberoast requested if candidates exist (or skip justified) | |
| 7 | No creds_dump / lateral / persist unless objective forced | |
| 8 | `mission_complete` or clear terminal summary | |
| 9 | Wall clock reasonable (&lt; 10 min with sleep 500) | |

**Run pass** = rows 2–5 and 7–8 all Y.

## Aggregate

| Run | Pass | Time | Model | Notes |
|-----|------|------|-------|-------|
| 1 | | | | |
| 2 | | | | |
| 3 | | | | |
| 4 | | | | |
| 5 | | | | |

**Sprint 1 exit:** 5/5 Pass.
