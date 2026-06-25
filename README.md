# Erebus Exploitation Framework

A custom command-and-control (C2) framework for AI-driven offensive security operations. The **teamserver**, operator CLI, and listeners are Go; implants are available as **Go** (default) or an optional **C** Windows build (`cimplant/`). Erebus uses beacon-mode architecture with protobuf wire protocols, gRPC operator API, and mTLS-secured communications.

> **For authorized security testing, red team engagements, and research purposes only.**

## Architecture

```
┌──────────────┐         gRPC (mTLS)         ┌──────────────────┐
│   Operator   │◄───────────────────────────►│    Teamserver    │
│   CLI / AI   │                             │                  │
└──────────────┘                             │  ┌────────────┐  │
                                             │  │  Sessions   │  │
                                             │  │  Manager    │  │
┌──────────────┐   HTTPS/DNS (Protobuf)      │  ├────────────┤  │
│   Implant    │◄───────────────────────────►│  │  Listener   │  │
│   (Beacon)   │                             │  │  Manager    │  │
└──────────────┘                             │  ├────────────┤  │
                                             │  │  Task       │  │
                                             │  │  Dispatcher │  │
                                             │  ├────────────┤  │
                                             │  │  Approval   │  │
                                             │  │  Gate       │  │
                                             │  ├────────────┤  │
                                             │  │  SQLite DB  │  │
                                             │  └────────────┘  │
                                             └──────────────────┘
```

## Features

### Core Infrastructure
- **Teamserver** — Central C2 server with gRPC API for operator/AI interaction
- **HTTPS Listener** — TLS-encrypted callback handler for implant beacons
- **DNS Listener** — Covert C2 channel via TXT record queries with base32-encoded data
- **Beacon Implant** — Lightweight agent with configurable sleep/jitter intervals
- **Operator CLI** — Interactive REPL with tab completion for direct operator control
- **Task Queue** — Async task dispatch with optional blocking wait and 10-minute default timeout
- **Event Streaming** — Real-time gRPC event stream (new sessions, task results, approvals)
- **Approval Gates** — Server-side gates on `ExecuteTask` for creds dump, lateral movement, persistence, injection, and high-risk `TASK_MODULE` targets (operator `approve`/`deny` via CLI or gRPC)

### Implant Capabilities

| Category | Tasks |
|---|---|
| **Execution** | Shell command execution with structured output |
| **File Operations** | Upload/download with 50MB cap, TOCTOU-safe reads |
| **Process Management** | Process listing (cross-platform), process kill |
| **Network Recon** | Interface enumeration, TCP port scanning with service detection |
| **Screenshot** | GDI-based screen capture (Windows) |
| **Keylogger** | Low-level keyboard hook with window title capture (Windows) |
| **SOCKS Proxy** | SOCKS5 tunnel for network pivoting |

### Active Directory Attacks
- **LDAP Enumeration** — 12 pre-defined query types (kerberoastable SPNs, AS-REP roastable, domain admins, DCs, GPOs, trusts, delegation, custom filters)
- **Kerberoasting** — TGS extraction with hashcat-compatible output (modes 13100/19600/19700)
- **AS-REP Roasting** — Pre-auth bypass with hashcat mode 18200 output
- **Credential Dumping** — LSASS minidump, SAM/SYSTEM hive extraction, browser credential harvesting (Chrome/Edge/Firefox)

### Lateral Movement
- **WinRM** — HTTP-based remote execution (cross-platform)
- **PsExec** — SMB-based payload staging via ADMIN$ share
- **WMI** — Windows Management Instrumentation execution (Windows)
- **DCOM** — COM/DCOM automation for remote execution (Windows)

### Evasion & Post-Exploitation
- **Process Injection** — CreateRemoteThread, APC Queue methods with pluggable framework
- **PE/Shellcode Loader** — Reflective PE loading with full IAT patching and relocation processing
- **Persistence** — Scheduled tasks, registry Run keys, Windows services
- **Privilege Escalation** — Token theft (DuplicateTokenEx), UAC bypass (fodhelper/eventvwr)

### Security
- **mTLS** — Mutual TLS for operator ↔ teamserver communication
- **HMAC-SHA256** — Implant identity verification via pre-shared secret
- **AES-256-GCM** — Session encryption for implant payloads
- **Cross-platform** — Linux and Windows implant builds
- **SQLite Persistence** — Sessions, tasks, and loot stored locally

## Quick Start

### Prerequisites

- Go 1.22+
- `protoc` with `protoc-gen-go` and `protoc-gen-go-grpc` plugins
- `make`
- **C implant (optional):** Windows cross-compiler — Fedora: `mingw64-gcc` + `mingw64-cpp`; or run `scripts/setup_c_toolchain.sh` for llvm-mingw

### Build

```bash
# Generate protobuf code
make proto

# Build all components
make all

# Or build individually:
make teamserver     # Build teamserver
make implant        # Build implant (Linux)
make implant-win    # Build implant (Windows)
make operator       # Build operator CLI
make implant-c      # Build C implant (Windows PE, requires mingw)
```

### Verify Build

```bash
# Unit tests + teamserver/implant builds (+ C implant if mingw available)
bash scripts/smoke_test.sh

# Live teamserver flow: register → beacon → shell task → approval gate
go test ./server/e2e/... -v -count=1
```

### Run Teamserver

```bash
./build/teamserver
```

The teamserver starts with defaults:
- gRPC API on `127.0.0.1:50051`
- HTTPS listener on `0.0.0.0:443`
- Data stored in `~/.erebus/`

Override via CLI flags:

```bash
./build/teamserver \
  -grpc 127.0.0.1:50051 \
  -host 0.0.0.0 \
  -port 8443 \
  -secret <hex-encoded-secret>
```

### Run Operator CLI

```bash
./build/operator \
  -server 127.0.0.1:50051 \
  -cert operator.crt \
  -key operator.key \
  -ca ca.crt
```

### Build Implant with Custom Config

```bash
# HTTPS transport (default)
make implant \
  CALLBACK_URL=https://your-c2-server:8443 \
  SLEEP_MS=10000 \
  JITTER_PCT=30

# DNS transport
make implant \
  TRANSPORT_TYPE=dns \
  DNS_DOMAIN=c2.example.com \
  DNS_SERVER=ns1.example.com:53 \
  SLEEP_MS=30000
```

### C Implant (Windows)

The C implant mirrors the Go wire protocol (HTTPS/DNS, HMAC auth, AES-256-GCM session encryption) with indirect syscalls and compiled-in modules.

```bash
# One-time toolchain (llvm-mingw, ~150MB download)
bash scripts/setup_c_toolchain.sh

# Or on Fedora:
# sudo dnf install mingw64-gcc mingw64-cpp

make implant-c \
  IMPLANT_ID=my-implant \
  IMPLANT_SECRET=$(openssl rand -hex 32) \
  CALLBACK_URL=https://your-c2:8443
# Output: build/implant_c.exe
```

Generate via gRPC (`GenerateImplant` with `language: "c"`). The operator CLI does not yet expose a `generate --language c` flag — use gRPC or `make implant-c` directly.

**C implant gaps (honest):** Kerberoast/AS-REP ticket extraction and several lateral primitives (PsExec, WinRM, DCOM) are stubs; WMI works. TLS pinning in `cimplant/src/transport/https.c` is not fully implemented. Full validation requires a Windows host or VM.

## Configuration

Config file is auto-created at `~/.erebus/server.yaml`:

```yaml
grpc_addr: "127.0.0.1:50051"
db_path: "/home/user/.erebus/erebus.db"
data_dir: "/home/user/.erebus"
implant_secret: "<auto-generated hex>"
listeners:
  - name: default-https
    protocol: https
    host: 0.0.0.0
    port: 443
```

## Operator CLI Commands

```
sessions              - List active sessions
use <session-id>      - Select active session
shell <command>       - Execute shell command
upload <local> <remote> - Upload file
download <remote>     - Download file
ps                    - List processes
kill <pid>            - Kill process
ifconfig              - List network interfaces
portscan <host> <ports> - TCP port scan
sleep <ms> [jitter]   - Set beacon interval
screenshot            - Take screenshot
keylog <start|stop|dump> - Keylogger control
tasks                 - List session tasks
result <task-id>      - Get task result
loot                  - List loot
events                - Stream events
listeners             - List listeners
pending               - List pending approvals
approve <id>          - Approve operation
deny <id> [reason]    - Deny operation
exit                  - Exit operator CLI
help                  - Show help
```

High-risk tasks (`TASK_CREDS_DUMP`, `TASK_LATERAL_MOVE`, `TASK_PERSIST`, `TASK_INJECT`, `TASK_PE_LOAD`, `TASK_PRIVESC`, and `TASK_MODULE` for `creds_dump`, `lateral_move`, `persist`, `privesc`, `inject`) block in `ExecuteTask` until an operator approves via `pending`/`approve` or the gRPC `Approve` RPC.

## Testing

| Script / test | What it covers |
|---|---|
| `scripts/smoke_test.sh` | Go unit tests (DNS chunks, approval, beacon handler), teamserver + implant builds, optional C PE build |
| `go test ./server/e2e/...` | Live teamserver on ephemeral ports: implant register/beacon (HTTP client), shell task round-trip, creds-dump approval gate |

## Project Structure

```
.
├── cimplant/                # C Windows implant (beacon, transport, modules)
├── cmd/
│   ├── teamserver/          # Teamserver entry point
│   ├── implant/             # Go implant entry point
│   └── operator/            # Operator CLI (REPL + commands)
├── scripts/
│   ├── smoke_test.sh        # Build + unit test smoke checks
│   ├── setup_c_toolchain.sh # llvm-mingw downloader
│   └── e2e_live.sh          # Wrapper for live e2e tests
├── server/
│   ├── server.go            # Teamserver core
│   ├── grpc.go              # gRPC service implementation
│   ├── events.go            # Event bus for real-time streaming
│   ├── config.go            # Server configuration
│   ├── approval/            # Approval gate for high-risk ops
│   ├── db/                  # SQLite store, models, migrations
│   ├── builder/             # Go + C implant build pipeline
│   ├── listeners/           # HTTPS + DNS listeners (shared beacon handler)
│   ├── e2e/                 # Live teamserver integration tests
│   ├── sessions/            # Session tracking + reaper
│   ├── socks/               # Server-side SOCKS5 proxy
│   └── tasks/               # Task queue + dispatcher
├── implant/
│   ├── implant.go           # Implant core (beacon loop)
│   ├── config.go            # Build-time config (ldflags)
│   ├── transport/           # HTTPS + DNS transport layers
│   ├── tasks/               # Task executor + handlers
│   │   ├── executor.go      # Task routing (switch on TaskType)
│   │   ├── file.go          # File upload/download
│   │   ├── process*.go      # Process list/kill (cross-platform)
│   │   ├── network.go       # Ifconfig + port scan
│   │   ├── screenshot*.go   # Screen capture (Windows/stub)
│   │   ├── keylog*.go       # Keylogger (Windows/stub)
│   │   ├── inject*.go       # Process injection (Windows/stub)
│   │   ├── peload*.go       # PE loader (Windows/stub)
│   │   └── socks.go         # SOCKS5 proxy endpoint
│   └── modules/
│       ├── shell/           # Shell execution module
│       ├── ad/              # LDAP enum, Kerberoast, AS-REP roast
│       ├── creds/           # LSASS, SAM, browser credential dumping
│       ├── lateral/         # WinRM, PsExec, WMI, DCOM
│       ├── persist/         # Scheduled tasks, registry, services
│       └── privesc/         # Token theft, UAC bypass
├── pkg/
│   ├── crypto/              # AES, mTLS, key generation
│   ├── dnstransport/        # DNS chunk encode/decode (shared server + implant)
│   ├── pb/                  # Generated protobuf code
│   └── plugin/              # Module plugin interface + registry
├── proto/                   # Protobuf definitions
│   ├── c2.proto             # Implant <-> Teamserver messages
│   ├── api.proto            # Operator gRPC API + service
│   └── listener.proto       # Listener configuration messages
└── Makefile
```

## Wire Protocol

All communications use Protocol Buffers:

| Channel | Protocol | Auth | Definition |
|---|---|---|---|
| Implant ↔ Teamserver | HTTPS + Protobuf | HMAC-SHA256 + AES-256-GCM | `c2.proto` |
| Implant ↔ Teamserver | DNS TXT + Protobuf | HMAC-SHA256 + AES-256-GCM | `c2.proto` |
| Operator ↔ Teamserver | gRPC | mTLS | `api.proto` |

## gRPC API

The `ErebusC2` service exposes:

| RPC | Description |
|---|---|
| `StartListener` | Start a new listener (HTTPS or DNS) |
| `StopListener` | Stop a running listener |
| `ListListeners` | List all listeners |
| `ListSessions` | List active sessions |
| `GetSession` | Get session details |
| `KillSession` | Terminate a session |
| `ExecuteTask` | Dispatch a task to an implant |
| `GetTaskResult` | Poll for task result |
| `ListTasks` | List tasks for a session |
| `Subscribe` | Stream real-time events |
| `GenerateImplant` | Generate implant binary |
| `ListLoot` | List collected loot |
| `GetLoot` | Retrieve loot item |
| `ListPendingApprovals` | List pending approval requests |
| `Approve` | Approve a high-risk operation |
| `Deny` | Deny a high-risk operation |

## Task Types

| Task Type | Description | Platform |
|---|---|---|
| `TASK_SHELL` | Shell command execution | Cross-platform |
| `TASK_FILE_DOWNLOAD` | Download file from target | Cross-platform |
| `TASK_FILE_UPLOAD` | Upload file to target | Cross-platform |
| `TASK_PROCESS_LIST` | List running processes | Cross-platform |
| `TASK_PROCESS_KILL` | Kill a process by PID | Cross-platform |
| `TASK_NET_IFCONFIG` | List network interfaces | Cross-platform |
| `TASK_NET_PORTSCAN` | TCP port scan | Cross-platform |
| `TASK_SCREENSHOT` | Capture screenshot | Windows |
| `TASK_KEYLOG_START` | Start keylogger | Windows |
| `TASK_KEYLOG_STOP` | Stop keylogger | Windows |
| `TASK_KEYLOG_DUMP` | Dump captured keystrokes | Windows |
| `TASK_INJECT` | Process injection | Windows |
| `TASK_PE_LOAD` | Reflective PE loading | Windows |
| `TASK_SOCKS_START` | Start SOCKS5 proxy | Cross-platform |
| `TASK_SOCKS_STOP` | Stop SOCKS5 proxy | Cross-platform |
| `TASK_SLEEP` | Change beacon interval | Cross-platform |
| `TASK_EXIT` | Terminate implant | Cross-platform |
| `TASK_MODULE` | Execute a registered module | Cross-platform |
| `TASK_LDAP_ENUM` | LDAP/AD enumeration | Cross-platform |
| `TASK_KERBEROAST` | Kerberoasting attack | Cross-platform |
| `TASK_ASREP_ROAST` | AS-REP roasting attack | Cross-platform |
| `TASK_CREDS_DUMP` | Credential dumping | Windows |
| `TASK_LATERAL_MOVE` | Lateral movement | Varies |
| `TASK_PERSIST` | Install persistence | Windows |
| `TASK_PRIVESC` | Privilege escalation | Windows |

## License

[MIT](LICENSE)
