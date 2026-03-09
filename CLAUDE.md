# Erebus Exploitation Framework

Custom C2 framework for AI-driven offensive security operations.

## Build

```bash
make proto        # Generate protobuf code
make teamserver   # Build teamserver
make implant      # Build implant (Linux)
make implant-win  # Build implant (Windows)
make operator     # Build operator CLI
make all          # Build everything
```

## Architecture

- **Teamserver**: gRPC API server + HTTPS/DNS listeners for implant callbacks
- **Implant**: Beacon-mode agent with configurable sleep/jitter, HTTPS or DNS transport
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
- High-risk operations (creds dump, lateral movement, persistence, injection) require approval gate
- New modules go in `implant/modules/<category>/` with `_stub.go` fallbacks for non-Windows
- New task handlers go in `implant/tasks/` with a case added to `executor.go`
- Transport selection via ldflags: `TRANSPORT_TYPE=https|dns`
- DNS transport uses base32-encoded subdomain labels in TXT queries
