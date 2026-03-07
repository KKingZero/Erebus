# Erebus Exploitation Framework

Custom C2 framework for AI-driven offensive security operations.

## Build

```bash
make proto        # Generate protobuf code
make teamserver   # Build teamserver
make implant      # Build implant (Linux)
make implant-win  # Build implant (Windows)
```

## Architecture

- **Teamserver**: gRPC API server + HTTPS listener for implant callbacks
- **Implant**: Beacon-mode agent with configurable sleep/jitter
- **Wire protocol**: Protobuf everywhere
- **DB**: SQLite at ~/.erebus/erebus.db
- **Config**: YAML at ~/.erebus/server.yaml

## Key Conventions

- All implant-facing comms use protobuf (c2.proto)
- AI/operator API uses gRPC (api.proto)
- Implant authenticates via HMAC-SHA256 pre-shared secret (injected via ldflags)
- Module registry is compiled-in (no dynamic loading)
- Task results carry structured data for AI consumption
