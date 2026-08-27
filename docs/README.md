# Documentation Index

Trinity Panel — a Cloudflare-hosted proxy panel with an XHTTP-first transport layer
and a config translation layer that emits Xray, sing-box and mihomo configurations
from one source of truth.

## Start here

| Document | Contents |
|---|---|
| **[README](../README.md)** | What Trinity Panel is, the honest feature list, architecture overview, and the quick start |
| **[INSTALL](../INSTALL.md)** | Beginner-friendly installation: prerequisites, the wasm-bindgen version trap, Cloudflare token creation, every binding explained — and the manual CLI path the wizard wraps |
| **[Known issues](../KNOWN_ISSUES.md)** | What is not working or not verified, and which limitations are deliberate |

## Research and design

| Document | Contents |
|---|---|
| [Phase 0 report](research/phase-0-report.md) | Survey of ten existing panels, Cloudflare runtime constraints, the WebSocket/XHTTP coexistence answer, the outbound-UDP/WARP answer, and the design decisions taken |
| [Parameter inventory](research/parameter-inventory.md) | Cross-core parameter tables, equivalence map, core-exclusive features, the incompatibility matrix that the UI and emitter enforce, and emission rules |

## User documentation

| Document | Contents |
|---|---|
| [Installation and first deployment](../INSTALL.md) | Done — the setup wizard plus the manual CLI path, prerequisites through first client connection |
| [Known issues](../KNOWN_ISSUES.md) | Done |

- Every parameter, explained plainly — pending
- Getting a subscription onto a phone — pending
- Troubleshooting and FAQ — partly covered by [INSTALL §11](../INSTALL.md#11-troubleshooting)

## Developer documentation

- **[Architecture and module map](architecture.md)** — Done: module map, request path, DO lifecycle, runtime constants
- Protocol implementation notes — pending
- Transport internals — pending
- Build pipeline — pending
- Extending with a new protocol or core — pending

## Reading order for a newcomer

Start with the [Phase 0 report](research/phase-0-report.md). Sections 2 and 3 explain why this
project makes transport choices that differ from every other panel in this space. The
[parameter inventory](research/parameter-inventory.md) is the specification the translation
layer is built from and is the reference to reach for when a generated config is rejected by a
core.
