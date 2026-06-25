# Erebus Architecture Decisions & Strategic Direction

> Living document. Records architectural decisions, rationale, and the strategic roadmap.
> Last updated: 2026-06-25

---

## Mission Statement

Erebus is an AI-driven C2 framework purpose-built for **Active Directory and Cloud security testing**. It is designed for semi-autonomous operation — an AI agent plans and chains attacks, with operator oversight and manual override capability. All module output is machine-parseable (structured JSON) for AI consumption first, human-readable second.

---

## Strategic Focus (Priority Split)

| Domain | Weight | Scope |
|---|---|---|
| **Active Directory (on-prem)** | 60% | Kerberos abuse, LDAP recon, lateral movement, privilege escalation, credential harvesting |
| **Cloud (Azure/AWS/GCP)** | 40% | Identity abuse, token theft, cloud pivot, IAM enumeration, metadata exploitation |

### Attack Chain Priority

```
Phase 1: AD Core
  └─ Kerberoasting, AS-REP roasting, LDAP enumeration, credential harvesting
  └─ Lateral movement (PsExec, WMI, WinRM, DCOM)
  └─ Privilege escalation (token manipulation, local exploits)

Phase 2: Hybrid Identity
  └─ Azure AD Connect credential extraction
  └─ Hybrid join trust abuse
  └─ Entra ID token theft (PRT, refresh tokens)
  └─ Conditional Access bypass techniques

Phase 3: Cloud Expansion
  └─ AWS: IMDS metadata, IAM enumeration, STS assume-role, credential files
  └─ Azure: Managed Identity, CLI token theft, ARM API abuse
  └─ GCP: Service account key theft, metadata server, IAM policy enum
  └─ Cross-cloud pivot (compromised on-prem → cloud control plane)
```

---

## Architecture Decisions

### AD-1: Built-in Kerberos & AD Attack Primitives

**Decision:** Implement Kerberoasting, AS-REP roasting, golden/silver ticket, and S4U abuse as compiled-in Go modules — not shelling out to external tools.

**Rationale:**
- External tools (Rubeus, Impacket) require dropping binaries to disk or loading .NET assemblies — increases detection surface
- Built-in Go implementations are cross-compiled, statically linked, and leave no child process artifacts
- Structured output is native — no stdout parsing needed for AI consumption
- Removes dependency on target having .NET runtime

**Trade-off:** More development effort upfront, but significantly better OPSEC and AI integration.

---

### AD-2: Built-in LDAP/AD Enumeration

**Decision:** Implement LDAP query engine directly in the implant (BloodHound-style recon) rather than running SharpHound or BOFs.

**Rationale:**
- SharpHound is heavily signatured by all major EDRs
- Built-in LDAP queries allow fine-grained, targeted enumeration (e.g., "find all Kerberoastable SPNs with admin group membership") instead of full domain dumps
- Results returned as typed JSON objects (`domain_admins: [...]`, `kerberoastable_spns: [...]`) for direct AI consumption
- Supports incremental/targeted queries — lower noise than full enumeration

**Output format example:**
```json
{
  "module": "ad_enum",
  "query_type": "kerberoastable_spns",
  "results": [
    {
      "samAccountName": "svc_sql",
      "spn": "MSSQLSvc/db01.corp.local:1433",
      "memberOf": ["Domain Admins", "SQL Admins"],
      "pwdLastSet": "2024-01-15T08:30:00Z",
      "enabled": true
    }
  ],
  "domain": "corp.local",
  "dc": "DC01.corp.local",
  "timestamp": "2026-03-08T12:00:00Z"
}
```

---

### AD-3: Lateral Movement — All Core Primitives

**Decision:** Implement PsExec, WMI, WinRM, and DCOM lateral movement with pass-the-hash and pass-the-ticket support baked in.

**Rationale:**
- Different environments block different protocols — having all four provides operational flexibility
- Pass-the-hash/ticket avoids plaintext credential exposure
- AI agent can select the optimal technique based on target configuration and detected defenses

**Priority order:** WMI (quietest) → WinRM (most versatile) → DCOM (least monitored) → PsExec (most reliable, most detected)

---

### CLOUD-1: Azure-First Cloud Strategy

**Decision:** Azure/Entra ID gets deep coverage (CLI tokens, IMDS, Managed Identity, AAD Connect, PRT theft). AWS and GCP get lightweight credential harvesting (credential files, env vars, IMDS).

**Rationale:**
- Azure/Entra ID is the primary hybrid identity pivot from on-prem AD
- Deep Azure coverage aligns with AD-focused attack chains
- AWS/GCP credential harvesting is opportunistic — file reads and env vars are low-risk recon
- All cloud modules are compiled-in and auto-harvested on new sessions

**Credential targets:**
| Provider | Targets |
|---|---|
| **Azure** | Managed Identity tokens, Azure CLI tokens (`~/.azure/`), PRT cookies, Entra ID refresh tokens |
| **AWS** | IMDS metadata (169.254.169.254), `~/.aws/credentials`, environment variables, STS session tokens |
| **GCP** | Metadata server tokens, service account keys (`*.json`), gcloud CLI tokens (`~/.config/gcloud/`) |

---

### CLOUD-2: Cloud Pivot from On-Prem

**Decision:** Build explicit hybrid pivot capabilities — compromised AD host → cloud control plane.

**Key attack paths:**
- Azure AD Connect credential extraction (DCSync-like for cloud)
- Hybrid Azure AD join trust abuse
- AWS SSO credential theft from domain-joined workstations
- GCP Workload Identity Federation abuse

---

### EVASION-1: EDR-Agnostic Evasion Strategy

**Decision:** Test against all major EDRs: Defender for Endpoint, CrowdStrike, SentinelOne, Carbon Black.

**Approach:**
- Indirect syscalls for all sensitive operations (NtCreateThreadEx, NtAllocateVirtualMemory, etc.)
- Sleep masking (encrypt implant memory during sleep)
- ETW patching to blind userland telemetry
- AMSI bypass for PowerShell/CLR operations
- No common signatures — avoid known tool strings, hashes, and behavioral patterns
- Malleable C2 profiles for traffic blending (disguise as Teams, OneDrive, Slack API calls)

---

### IMPLANT-1: Dual-Language Implant — Go Default, C Optional

**Decision:** Teamserver, operator CLI, gRPC API, and listeners remain **Go**. Implants ship in two forms: the default **Go** implant (`implant/`, `cmd/implant/`) and an optional **C** Windows implant (`cimplant/`) for smaller binaries and indirect-syscall evasion.

**Rationale:**
- Go implant is the reference implementation — fastest to extend, cross-platform (Linux/Windows), full module coverage
- C implant targets Windows-only engagements where PE size, syscall indirection, and non-Go runtime matter
- Single wire protocol (`c2.proto`) and shared DNS chunking (`pkg/dnstransport/`) keep both implants interoperable with one teamserver
- `GenerateImplant` gRPC accepts `language: "go"` (default) or `language: "c"`; builder routes to `make implant-c`

**C implant scope (2026-06):** Beacon loop, HTTPS/DNS transport, HMAC + AES-GCM, 9 compiled-in modules, task handlers for shell/file/process/network/screenshot/keylog/socks/inject/peload. Kerberoast ticket extraction and several lateral primitives remain stubs.

**Toolchain:** llvm-mingw via `scripts/setup_c_toolchain.sh`, or Fedora `mingw64-gcc` + `mingw64-cpp` (provides `cc1`).

---

### EVASION-2: Implant Execution Model — EXE, Shellcode, and DLL

**Decision:** Three output formats supported for the **Go** implant: standalone EXE (default), shellcode (via go-donut), and reflective DLL (c-shared buildmode). The C implant currently builds PE EXE only (`build/implant_c.exe`).

**Rationale:**
- EXE is simplest for testing and direct execution
- Shellcode enables process injection, reflective loading, and custom loaders
- DLL enables sideloading and rundll32 execution
- go-donut (Binject/go-donut) converts PE→shellcode with AMSI/ETW bypass
- GenerateImplant RPC supports all three formats

---

### EVASION-3: Process Injection — Pluggable Framework

**Decision:** Implement a pluggable injection framework starting with classic injection (CreateRemoteThread), then adding syscall-based, APC queue, and callback-based methods.

**Rationale:**
- Different EDRs hook different APIs — pluggable framework lets the AI agent choose the least-monitored technique per target
- Classic injection first for simplicity; advanced methods added iteratively

---

### EVASION-4: Malleable C2 Profiles

**Decision:** Implement Cobalt Strike-style malleable C2 profiles to disguise traffic as legitimate services.

**Planned profiles:**
- Microsoft Teams API calls
- OneDrive file sync
- Slack webhook traffic
- Generic REST API patterns

**Rationale:**
- Raw protobuf over HTTPS is distinctive to network monitoring
- Traffic blending is essential against network-level detection (NDR tools)
- Profiles are YAML-defined, loaded at teamserver startup

---

### CRYPTO-1: gRPC Authentication — mTLS with Operator Certificates

**Decision:** Secure the gRPC API with mutual TLS. The Erebus CA auto-generates operator certificates. Token-based auth (API keys) as secondary mechanism for AI agent integration.

**Rationale:**
- mTLS is the strongest option for remote operator access — no passwords to brute-force
- Operator certs are generated by the teamserver and distributed out-of-band
- API keys provide a simpler auth path for programmatic AI agent access
- Sliver uses this model successfully

**Implementation:**
- `erebus operator create <name>` generates a signed client cert + config file
- gRPC server requires valid client certificate from Erebus CA
- Optional: API key header for AI agents (validated against stored hashes)
- gRPC reflection disabled by default, enabled only with `--debug` flag

---

### CRYPTO-2: Implant Wire Encryption — Negotiated Session Keys + AES-GCM

**Decision:** Implement key negotiation during registration (ephemeral per-session keys), then AES-256-GCM encrypt all subsequent protobuf payloads.

**Rationale:**
- TLS alone is insufficient because the implant currently skips certificate validation
- Even after adding TLS pinning, defense-in-depth requires payload encryption
- Per-session keys mean compromising one session doesn't decrypt others
- AES-GCM provides both confidentiality and integrity

**Flow:**
1. Implant generates ephemeral X25519 keypair at registration
2. Server generates ephemeral X25519 keypair, derives shared secret via ECDH
3. Shared secret → HKDF → AES-256 session key
4. All subsequent beacon payloads encrypted with session key + AES-256-GCM
5. HMAC auth continues as additional authentication layer

---

### CRYPTO-3: TLS Certificate Pinning

**Decision:** Pin the Erebus CA certificate in the implant at build time (injected via ldflags or embedded).

**Rationale:**
- Eliminates MITM attacks — implant only trusts the specific CA that signed the server cert
- Self-signed CA is fine when pinned; `InsecureSkipVerify` is removed
- CA cert hash embedded at compile time, no runtime trust store dependency

---

### CRYPTO-4: Secret Management — Encrypted Config with Passphrase

**Decision:** Encrypt the server config file. Teamserver requires a passphrase on startup to decrypt.

**Rationale:**
- Plaintext secrets in YAML are unacceptable for a security tool
- OS keyring adds platform-specific complexity
- Env vars are visible in `/proc` and process listings
- Passphrase-on-startup is the simplest secure option
- Unattended mode: passphrase via `EREBUS_PASSPHRASE` env var (documented risk)

---

### AI-1: Semi-Autonomous Operation Model

**Decision:** AI agent operates semi-autonomously — it plans attack chains, selects techniques, and executes modules, but high-impact actions require operator approval.

**Approval gates (operator must confirm):**
- Lateral movement to new hosts
- Credential dumping / extraction
- Persistence installation
- Cloud control plane actions
- Any destructive operation

**Implementation (2026-06):** `ExecuteTask` in `server/grpc.go` calls `checkTaskApproval()` before dispatch. `server/approval/policy.go` defines high-risk task types (`TASK_CREDS_DUMP`, `TASK_LATERAL_MOVE`, `TASK_PERSIST`, `TASK_INJECT`, `TASK_PE_LOAD`, `TASK_PRIVESC`) and high-risk `TASK_MODULE` names (`creds_dump`, `lateral_move`, `persist`, `privesc`, `inject`). Pending requests block until operator `Approve`/`Deny` via CLI or gRPC. Live flow verified in `server/e2e/`.

**Autonomous (no approval needed):**
- Enumeration and reconnaissance
- Passive information gathering
- Task result analysis and reporting
- Attack path planning and recommendation

---

### AI-2: Structured JSON Output for All Modules

**Decision:** Every module returns machine-parseable JSON with typed fields. Raw output is a secondary field.

**Standard output envelope:**
```json
{
  "module": "string",
  "action": "string",
  "success": true,
  "timestamp": "ISO8601",
  "target": "string",
  "results": { },
  "raw_output": "string (optional)",
  "errors": [],
  "next_suggested_actions": ["string"]
}
```

**Rationale:**
- AI agent can directly parse results without NLP/regex extraction
- `next_suggested_actions` enables autonomous chaining (e.g., "kerberoast → crack → lateral_move")
- `raw_output` preserved for operator manual review
- Consistent envelope means the AI agent uses one parser for all modules

---

## Bug Fixes Roadmap (from Code Review)

### Phase 1 Critical (fixed)

| # | Issue | Status |
|---|---|---|
| 1 | gRPC has zero authentication | Fixed — mTLS implemented (CRYPTO-1) |
| 2 | gRPC reflection enabled | Fixed — disabled by default |
| 3 | TLS validation disabled on implant | Fixed — CA pinning via embedded cert (CRYPTO-3) |
| 4 | AES encryption unused | Fixed — session key negotiation + AES-GCM (CRYPTO-2) |
| 5 | Plaintext secret in config | Fixed — encrypted config with passphrase (CRYPTO-4) |
| 6 | Double beacon per loop cycle | Fixed — single send per cycle |
| 7 | ImplantId/SessionId field mismatch | Fixed — field mapping corrected |
| 8 | No session recovery on restart | Fixed — DB hydration on startup |
| 9 | Windows integrity level hardcoded | Fixed — token integrity check via syscall |

### Phase 2 Code Review (fixed)

| # | Issue | Status |
|---|---|---|
| 1 | TOCTOU in file download | Fixed — uses same fd for stat + read |
| 2 | SOCKS race condition | Fixed — net.Listen inside mutex |
| 3 | DNS chunk silent drop | Fixed — `pkg/dnstransport/chunk.go` + implant DNS chunking |
| 3b | DNS listener register/beacon incomplete | Fixed — shared `BeaconHandler` in `server/listeners/beacon.go` used by HTTPS and DNS |
| 4 | PE loader missing IAT patching | Fixed — full IAT walk + patching |
| 5 | Keylogger blocking GetMessageW | Fixed — MsgWaitForMultipleObjects + PeekMessageW |
| 6 | Keylog buffer trim off-by-one | Fixed — correct slice logic |
| 7 | PsExec always-true success | Fixed — based on payload presence |
| 8 | No task data size limit | Fixed — 10MB cap |
| 9 | No task default timeout | Fixed — 10 min default |
| 10 | Operator CLI context leak | Fixed — proper cancel() defer |

### Remaining (medium/low priority)

| # | Issue | Priority |
|---|---|---|
| 1 | Browser cred DPAPI decryption placeholder | Medium |
| 2 | C implant: Kerberoast/AS-REP ticket extraction stubs | Medium |
| 3 | C implant: lateral PsExec/WinRM/DCOM stubs | Medium |
| 4 | C implant: TLS pinning incomplete in HTTPS transport | Medium |
| 5 | Operator CLI lacks `generate --language c` | Low |
| 6 | Inject error handling for VirtualAllocEx failures | Low |
| 7 | Screenshot handle cleanup order | Low |
| 8 | WMI shells out to wmic.exe (detected by EDR) | Low |

---

## Open Questions (to revisit)

- [ ] Should implant support interactive (non-beacon) mode for time-sensitive operations?
- [ ] Built-in credential cracking (hashcat integration) or external only?
- [ ] Implant self-update mechanism (push new modules without full rebuild)?
- [ ] Multi-teamserver federation for large engagements?
- [ ] Malleable C2 profiles for traffic blending?
- [ ] Sleep masking (encrypt implant memory during sleep)?
- [ ] ETW/AMSI patching for CLR operations?

---

## Document History

| Date | Change |
|---|---|
| 2026-03-08 | Initial architecture decisions documented. AD/Cloud focus defined. Bug fix roadmap established. |
| 2026-03-09 | Phase 2 complete: AD attacks, evasion, infrastructure, operator CLI. 10 code review fixes applied. |
| 2026-03-10 | Phase 3: Redirector support (#2), Azure-first cloud modules (#7), auto-harvest (#8), shellcode/DLL output (#11). |
| 2026-06-25 | C implant (`cimplant/`), DNS listener completion, approval gate wiring on `ExecuteTask`, llvm-mingw toolchain, live e2e tests (`server/e2e/`). |
