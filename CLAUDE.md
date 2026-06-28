# Erebus Exploitation Framework

Custom C2 framework for AI-driven offensive security operations.

## Build

```bash
make proto        # Generate protobuf code
make erebus       # Build unified erebus CLI (start + operator)
make install      # Install erebus + Erebus to ~/.local/bin
make teamserver   # Build teamserver
make implant      # Build implant (Linux)
make implant-win  # Build implant (Windows)
make implant-c    # Build C implant (Windows PE, requires mingw)
make operator     # Build operator CLI
make all          # Build everything

bash scripts/smoke_test.sh              # Build + unit smoke checks
go test ./server/e2e/... -v -count=1    # Live teamserver e2e
```

## Architecture

- **Teamserver** (Go): gRPC API server + HTTPS/DNS listeners for implant callbacks
- **Implant** (Go default, C optional): Beacon-mode agent with configurable sleep/jitter, HTTPS or DNS transport
- **C implant** (`cimplant/`): Windows-only; `make implant-c` or `GenerateImplant` with `language: "c"`
- **Operator CLI**: Interactive REPL with mTLS auth for direct operator control
- **Wire protocol**: Protobuf everywhere (c2.proto for implant, api.proto for operator)
- **DB**: SQLite at ~/.erebus/erebus.db
- **Config**: YAML at ~/.erebus/server.yaml

## Key Conventions

- All implant-facing comms use protobuf (c2.proto)
- AI/operator API uses gRPC (api.proto)
- Implant authenticates via HMAC-SHA256 pre-shared secret (injected via ldflags)
- Session encryption: AES-256-GCM with negotiated keys
- Module registry is compiled-in (no dynamic loading) via `init()` functions
- Task results carry structured data for AI consumption
- Platform-specific code uses build tags (`//go:build windows` / `//go:build !windows`)
- Task handler pattern: unmarshal proto → execute → marshal result → switch case in executor.go
- High-risk operations require server-side approval gate on `ExecuteTask` (`server/grpc.go` → `server/approval/`)
- New modules go in `implant/modules/<category>/` with `_stub.go` fallbacks for non-Windows
- New task handlers go in `implant/tasks/` with a case added to `executor.go`
- Transport selection via ldflags: `TRANSPORT_TYPE=https|dns`
- DNS transport uses base32-encoded subdomain labels in TXT queries; chunking in `pkg/dnstransport/`
- C modules register in `cimplant/src/modules/registry.c`; new handlers in `cimplant/src/tasks/`
