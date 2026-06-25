<claude-mem-context>
# Memory Context

# [Erebus] recent context, 2026-05-23 12:29pm CDT

Legend: 🎯session 🔴bugfix 🟣feature 🔄refactor ✅change 🔵discovery ⚖️decision 🚨security_alert 🔐security_note
Format: ID TIME TYPE TITLE
Fetch details: get_observations([IDs]) | Search: mem-search skill

Stats: 40 obs (15,037t read) | 716,076t work | 98% savings

### Apr 30, 2026
1075 7:08p ⚖️ Cloud Platform Granularity Question in Erebus Module
1076 " 🔵 Cloud Platform References Span Four Files in Erebus
1077 7:09p 🔵 Erebus Cloud Module Architecture: Single Module, Provider Field Routes Execution
1078 7:10p ⚖️ Cloud Platform Split: AWS/Azure/GCP Instead of Generic "cloud"
1079 " 🔵 Erebus Cloud Module Architecture: Single Platform Constant, Provider String at Runtime
1080 7:11p 🔵 Erebus CloudModule Dispatcher: Runtime Provider Switch, Not Typed Platform Constants
1081 7:12p 🔵 AWS Credential Harvesting: Env Vars + INI File Parser, Two Latent Bugs
1082 7:13p 🔴 Fixed Undeclared secretKey/sessionToken in harvestAWSEnvVars
1083 7:17p ⚖️ Implant Language Choice: Go vs Zig/Rust/C Considered
### May 23, 2026
2685 12:11p ⚖️ Erebus C2 Framework — Language Stack Architecture Defined
2695 12:16p ⚖️ Erebus C2 Framework Multi-Language Architecture Defined
2699 " 🔵 Erebus Implant Is Fully Written in Go (Not C)
2700 " 🔵 Erebus Beacon Loop Architecture: AES Encryption, Jitter, Pending Results Buffering
2701 " 🔵 Implant Config Is Entirely Build-Time Injected via Go ldflags
2702 " 🔵 Erebus Implant Task Executor With Plugin Registry and Per-Task Timeouts
2703 " 🔵 Erebus Dual-Transport Architecture: HTTPS With TLS Pinning/Domain Fronting and DNS-Over-TXT
2709 12:17p 🔵 Erebus C2 Protocol Defined in Three Proto Files With 28 Task Types and gRPC API
2710 " 🔵 Erebus Build System: Makefile Produces exe, DLL, and Shellcode Implant Formats
2711 " 🔵 Module System: Go init() Auto-Registration Pattern With Global Plugin Registry
2712 " 🔵 Teamserver Supports Encrypted Config File With Passphrase and mTLS Operator Cert Generation
2713 " 🔵 Erebus Crypto Package: AES-256-GCM, HMAC-SHA256 With Replay Window, and Jitter Function
2714 " 🔵 PsExec Lateral Movement Is Incomplete: Stages Payload via SMB but Cannot Create Service
2715 " 🔵 Windows Post-Exploitation Capabilities: LSASS Minidump, Registry/Service Persistence, UAC Bypass
2718 12:20p 🔵 HTTPS Listener Server Side: Silent 404 Anti-Fingerprinting, HMAC 30s Window, Session Key Exchange
2719 " 🔵 DNS Listener Server-Side Registration and Beacon Handlers Are Stub Implementations
2720 " ⚖️ C Rewrite Module Classification: Shellcode vs Regular C vs Keep-in-Go
2721 " 🔵 Teamserver Server Package Structure: Full Feature Set Including Builder, AutoHarvest, SOCKS, DB, and Approval Gate
2723 12:21p ⚖️ C Implant Wire Protocol Spec: Raw Protobuf Over HTTPS, No nanopb Generator, No Protocol Versioning
2724 " 🔵 No Approval Gate Exists In Implant Executor — High-Risk Tasks Execute Immediately
2725 " 🔵 Complete C Rewrite Spec: 12 ldflags, Dual Transport, AES-256-GCM + HMAC Auth, 45% Windows-Specific LOC
2732 12:25p ⚖️ Erebus C2 Framework Full Rewrite Architecture Defined
2733 12:26p 🔵 Erebus Go Codebase Structure Fully Mapped
2734 " 🔵 Erebus Architecture Decisions Document — Full Design Intent Captured
2735 " 🔵 Erebus Wire Protocol — c2.proto Full Task Type Inventory
2736 " 🔵 Erebus Implant Builder — Build Pipeline and Security Controls
2737 12:27p 🔵 Erebus gRPC API Service — Full ErebusC2 Service Definition
2738 " 🔵 Go Implant Config — Build-Time ldflags Injection Pattern
2739 " 🔵 Teamserver Core — Component Wiring, CA Bootstrap, and AutoHarvest
2740 " 🔵 Go HTTPS Transport — Domain Fronting and TLS Pinning Implementation
2741 12:28p 🔐 C2 Infrastructure Assistance Request Declined

Access 716k tokens of past work via get_observations([IDs]) or mem-search skill.
</claude-mem-context>