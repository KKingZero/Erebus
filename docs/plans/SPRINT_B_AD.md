# Sprint B — AD path (Logging-class + Garfield-class)

| Field | Value |
| --- | --- |
| **Status** | Active (extended after Garfield HTB eng) |
| **Goal** | Medium path to **user** ≥70% in-Erebus **and** Hard identity primitives (RBCD/S4U/KeyList MVP) lab-green |
| **Duration** | ~4–6 weeks (both Go + C tracks); ~6–8 weeks single-threaded |
| **Sources** | `SPRINTS_ABC.md` §B, `HTB_NEXT_RUNBOOK.md` §5, Logging + **Garfield** after-action |
| **Depends on** | A.1 live WinRM PTH QA; soft path SMB/LDAP regression green |
| **Surfaces** | **Track G:** Go modules + operator CLI · **Track C:** C implant WinRM lateral · **Track D:** docs/skill |

---

## Exit criteria

### Original B (Logging-class → user)

| # | Criterion |
| --- | --- |
| B1 | **AES TGT** for Protected Users–style accounts; clock skew handled without requiring Docker when clocks are synced |
| B2 | **Shadow Creds MVP**: write `msDS-KeyCredentialLink` + recover usable NT/hash (one account, one DC); approval = critical |
| B3 | **Ticket import**: load kirbi/ccache; at least one of SMB / LDAP / lateral uses ticket |
| B4 | **ACL / dangerous-rights** LDAP surface (GenericAll, WriteDacl, WriteProperty, RBCD-related attrs) |
| B5 | Soft path regression: SMB list/download + `ldap-enum interesting` unchanged |
| B6 | Operator CLI + agent catalog list new tools; Plan mode suggests them for soft/medium/hard AD |

### Garfield extension (B.7–B.10)

| # | Criterion |
| --- | --- |
| B7 | **RBCD write** + **S4U AES** (machine key) → service ticket for impersonated user; critical approval |
| B8 | Soft AD set ops: **scriptPath** (or allowlisted set-attr), **ForceChangePassword**, **addcomputer** (MAQ-aware) |
| B9 | **KeyList MVP**: RODC partial TGT (`kvno = rodcNo << 16`) + KERB-KEY-LIST → one NT hash; critical approval |
| B10 | Logon-script staging **recipe** in docs + erebus-htb skill (no bot automation) |
| C1 | C implant: ≥1 real **WinRM** lateral in lab (password; hash if seal path green) |

---

## Work packages

### Core B (existing)

| ID | Work | Primary paths | Tests |
| --- | --- | --- | --- |
| **B.0 / A.1** | WinRM **hash** path + seal vs pypsrp | `implant/modules/lateral/winrm*.go` (hash seal implemented unit-tested) | Live eng-verify |
| **B.1** | Clock skew helper + AES TGT (`pkg/krb` or implant task) | `pkg/`, `implant/modules/`, operator thin wrapper | Unit skew math; GOAD if available |
| **B.2** | Shadow Creds module (minimal) | `implant/modules/` + approval gate | Unit parse; critical approval mock |
| **B.3** | Ticket store + wire `LateralMoveConfig.ticket` / SMB-LDAP ticket | Proto ticket field — end-to-end | Unit + lab |
| **B.4** | LDAP query types for dangerous ACLs + RBCD presence / AllowedToAct | Extend `ldap-enum` | Unit filter fixtures |
| **B.5** | Regression suite soft path | e2e / smoke | `smoke_test.sh` + checklist |
| **B.6** | CLI commands + AI catalog / suggestions | `pkg/operatorcli`, `pkg/suggestions` | unit |

### Garfield promotion (in-scope — no longer stretch)

| ID | Work | Primary paths | Tests |
| --- | --- | --- | --- |
| **B.7a** | **RBCD write** (`msDS-AllowedToActOnBehalfOfOtherIdentity`) | module + critical approval | Lab write + read back |
| **B.7b** | **S4U2Self + S4U2Proxy** with **AES** machine key (RC4 = clear fail) | `pkg/krb` + task → ticket store | Lab cifs/host ST |
| **B.8a** | Set allowlisted attrs (at least `scriptPath`) | LDAP task / operator | Lab set + verify |
| **B.8b** | ForceChangePassword (no old password when ACL allows) | LDAP/SAMR; **critical** | Lab |
| **B.8c** | addcomputer / machine account (MAQ-aware); loot password or NT | SAMR/LDAP; high/critical | Lab |
| **B.9a** | RODC partial TGT forge (AES krbtgt_XXXX, correct kvno/flags/realm) | `pkg/krb` | Unit vs known vectors |
| **B.9b** | KERB-KEY-LIST → one user NT hash | task + CLI; **critical** | Lab or fixture |
| **B.9c** | PRP helpers: NeverReveal clear / RevealOnDemand add when ACL allows | LDAP set; **critical** | Lab or mock |
| **B.9d** | Loot hash → `lateral winrm --hash` | existing PTH | E2E |
| **B.10** | Logon-script staging recipe (SYSVOL/NETLOGON, scriptPath, bot wait, markers) | `docs/AD_ENGAGEMENT.md`, skill | Checklist only |
| **B.11** | Multi-hop ticket recipe (S4U cifs then host for stage/schtasks) | docs unless cheap | Doc |
| **B.12** | Keep this file + `SPRINTS_ABC.md` / runbook / skill single source of truth | docs | Review |

### Track C (parallel — Sprint 1)

| ID | Work | Aligns with | Exit |
| --- | --- | --- | --- |
| **C.1** | WinRM password + PTH quality on C; no fake success | `SPRINT_1_C_LATERAL.md` 1.1 | Checklist eng-verify |
| **C.2** | Smoke: register → beacon → shell → file → one lateral | Sprint 1F | Lab green |

---

## Explicitly out of scope

- Full ADCS find/req surface (→ Sprint E / Ghostlink P1)
- WSUS MITM automation (docs only)
- Productizing mimikatz / schtasks RODC dump (recipe only; KeyList is the DA-class path)
- Domain-wide DCSync as primary DA path
- Automating HTB logon bot
- Agent Auto full “own the domain” plan
- Zig / evasion P2

---

## Acceptance demo (GOAD / lab)

```text
Track G:
1. Soft recon: smb + ldap-enum interesting (existing)
2. Clock skew preflight vs DC (fail loud if bad)
3. set scriptPath OR ForceChangePassword (ACL-prepared lab objects)
4. addcomputer ATTACK$
5. RBCD write: target trusts ATTACK$
6. S4U AES → cifs/host ticket for high-priv user
7. Ticket store → SMB or lateral with ticket
8. (If RODC or fixture) KeyList → NT hash → winrm --hash whoami
9. Optional external: krbtgt_rodc key source if lab has no dump path

Track C:
1. C implant check-in
2. shell + file
3. lateral winrm password whoami
4. lateral winrm --hash whoami (if seal green)

Docs:
1. Operator follows logon-script staging recipe without Garfield writeup
```

---

## Dependency graph

```text
A.1 WinRM PTH ──► B.5 soft regression ──► Track C WinRM
        │
        ▼
 B.1 clock skew + AES TGT ──► B.3 ticket store/import
        │
        ▼
 B.8 set-attr / ForceChange / addcomputer
        │
        ▼
 B.4 ACL enum ──► B.7a RBCD write ──► B.7b S4U AES ──► tickets
                                            │
                                            ▼
                              B.9 KeyList MVP (+ B.9c PRP)
                                            │
                                            ▼
                              lateral winrm --hash (A.1)
        │
        ▼
 B.10 recipe + B.12 docs (can start early)
 B.6 catalog (after commands exist)
 B.2 Shadow (Logging path; parallel after B.1)
```

---

## Operator CLI sketch (target)

```text
ldap-enum interesting | acl | rbcd
ldap set <dn|sam> scriptPath <value>
ad force-change-password <user> --pass-file
ad add-computer <name> --pass-file
rbcd write --to HOST$ --from ATTACK$
kerberos skew --dc <ip>
kerberos asktgt --aes / --hash ...
kerberos s4u --user ATTACK$ --aes ... --impersonate U --spn cifs/X
kerberos keylist --rodc-no N --rodc-aes ... --user Administrator
ticket import <kirbi|ccache>
lateral winrm ... --hash | --ticket
```

Exact verbs finalized in B.6.

---

## Approvals

| Operation | Level |
| --- | --- |
| ldap set scriptPath | high |
| ForceChangePassword | **critical** |
| addcomputer | high (critical if wide abuse) |
| RBCD write | **critical** |
| S4U impersonate admin-class | **critical** |
| KeyList | **critical** |
| PRP NeverReveal clear | **critical** |

Fail closed; no fake success stubs.

---

## Risks

| Risk | Mitigation |
| --- | --- |
| KeyList without RODC lab | Unit forge + recorded vectors; eng-verify next RODC box |
| Scope explosion (full Rubeus) | KeyList MVP = one user hash |
| S4U AES bugs | AES-only golden path; RC4 clear fail; compare Rubeus lab |
| C and Go double work | Shared `pkg/krb` where possible; C owns exec first |
| Soft set-attr too dangerous | Allowlist attrs (`scriptPath`) first |

---

## Suggested PR order

1. Docs align (this file + SPRINTS_ABC un-defer) — **done when this ships**  
2. A.1 WinRM PTH live green  
3. B.1 + skew preflight  
4. B.8 soft set ops  
5. B.3 + B.7 RBCD/S4U  
6. B.9 KeyList MVP  
7. B.10 + skill recipe  
8. Track C WinRM eng-verify (interleave after 2)  
9. B.6 catalog  

---

## Definition of done

- [ ] A.1 WinRM PTH live green  
- [ ] B1–B6 + B7–B10 exit criteria green on lab  
- [ ] Track C: ≥1 real WinRM lateral on C implant  
- [ ] Logon-script recipe in `AD_ENGAGEMENT` + erebus-htb skill  
- [ ] Dry-run writeup: Garfield-class in-Erebus vs external step table  
- [ ] No secrets committed; dual-control preserved  

---

## Related

- Plan synthesis: session plan “Sprint B+ Garfield-class”  
- Implant lateral: `docs/plans/SPRINT_1_C_LATERAL.md`  
- Runbook: `docs/HTB_NEXT_RUNBOOK.md` §5/§8  
- Garfield notes: `reports/htb-garfield/PROGRESS.md`  
