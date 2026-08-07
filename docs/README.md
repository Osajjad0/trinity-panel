# Documentation Index

A Cloudflare-hosted proxy panel with an XHTTP-first transport layer and a config translation
layer that emits Xray, sing-box and mihomo configurations from one source of truth.

## Start here

| Document | Contents |
|---|---|
| **[Project state](PROGRESS.md)** | What is built, what is *proven* versus what merely compiles, every key decision and why, stage-by-stage status, and the toolchain quirks this machine needs. Kept current as work lands. |

## Research and design

| Document | Contents |
|---|---|
| [Phase 0 report](research/phase-0-report.md) | Survey of ten existing panels, Cloudflare runtime constraints, the WebSocket/XHTTP coexistence answer, the outbound-UDP/WARP answer, and the design decisions taken |
| [Parameter inventory](research/parameter-inventory.md) | Cross-core parameter tables, equivalence map, core-exclusive features, the incompatibility matrix that the UI and emitter enforce, and emission rules |

## User documentation

*Written as each stage completes.*

- Installation and first deployment — pending
- Every parameter, explained plainly — pending
- Getting a subscription onto a phone — pending
- Troubleshooting and FAQ — pending

## Developer documentation

*Written as each stage completes.*

- Architecture and module map — pending
- Protocol implementation notes — pending
- Transport internals — pending
- Build pipeline — pending
- Extending with a new protocol or core — pending

## Reading order for a newcomer

Start with the [Phase 0 report](research/phase-0-report.md). Sections 2 and 3 explain why this
project makes transport choices that differ from every other panel in this space, and section 5
explains why the deployment story has two paths rather than one. The
[parameter inventory](research/parameter-inventory.md) is the specification the translation
layer is built from and is the reference to reach for when a generated config is rejected by a
core.
