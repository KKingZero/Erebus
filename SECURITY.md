# Security Policy

## Authorized use only

Erebus is a command-and-control (C2) framework for **authorized** offensive
security work: red team engagements, penetration tests, CTF/lab environments
(e.g. Hack The Box), and defensive research.

You must have **explicit written permission** (or own the systems) before
deploying implants, listeners, or automated agents against any target.
Misuse may violate criminal and civil law. The maintainers accept no
liability for unlawful or unauthorized use.

## Supported versions

| Version | Supported |
|---------|-----------|
| `v0.1.x` (lab / research) | Yes — best-effort fixes |
| Unreleased `main` | Best-effort; may break |
| Pre-`v0.1.0` history | No guarantee |

This project is early-stage. Treat it as **lab-grade**, not a hardened
enterprise product.

## Reporting a vulnerability

Please report security issues **privately** so we can fix them before
public disclosure.

1. **Preferred:** Open a private security advisory on GitHub for
   [KKingZero/Erebus](https://github.com/KKingZero/Erebus/security/advisories/new)
   if available, **or** email the repository owner via the contact listed on
   their GitHub profile.
2. Include:
   - Affected component (teamserver, Go implant, C implant, operator, AI agent)
   - Version / commit hash
   - Reproduction steps
   - Impact (RCE, auth bypass, crypto weakness, DoS, data leak, etc.)
3. Allow a reasonable window for a fix before public write-ups (we aim to
   acknowledge within **7 days** and ship a fix or mitigation when practical).

**Do not** file public GitHub issues for unfixed vulnerabilities that could
be abused against third parties.

## Scope (examples of in-scope findings)

- Authentication/authorization bypass on the gRPC operator API or mTLS seats
- Implant auth (HMAC), session crypto (AES-GCM), or replay weaknesses
- Path traversal / arbitrary file access beyond intended task jails
- Unauthenticated resource exhaustion on listeners (HTTPS/DNS)
- Privilege issues in approval dual-control (self-approve, missing identity)
- Unsafe defaults that enable high-risk auto-execution without operator intent

## Out of scope (typical)

- “The tool can be used maliciously” (it is a C2; authorized use is the control)
- Social engineering of operators
- Vulnerabilities only in third-party dependencies with no Erebus-specific impact
  (still welcome if you note the package and version)
- Issues requiring already-compromised teamserver credentials and no additional
  privilege gain

## Operational security defaults

Operators should:

- Generate unique implant secrets per build; never commit real secrets
- Keep `~/.erebus/` (certs, DB, `llm.yaml` API keys) private (`0600` / `0700`)
- Use dual-control approver seats for high-risk tasks in multi-operator settings
- Disable or carefully scope auto-harvest in shared environments
- Point listeners only at authorized lab/engagement infrastructure

## Disclosure preference

We prefer coordinated disclosure. Credit is given to reporters who request it
unless anonymity is preferred.
