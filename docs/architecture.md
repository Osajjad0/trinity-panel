# Architecture and Module Map

How Trinity Panel is organised, and why. Every claim here is attributable to a
source file — module doc-comments are quoted where they carry the rationale.

---

## The one-paragraph version

Trinity Panel is a single Cloudflare Worker (Rust → WASM) that is simultaneously
four things: a **proxy relay** (VLESS / Trojan / VMess / Shadowsocks-2022 in,
direct or Proxy-IP dial out), an **XHTTP transport server** (sessions owned by
Durable Objects), a **config translation layer** (one node model → Xray /
sing-box / mihomo output per client), and an **admin panel + subscription
server** (KV-backed settings, HTML UI, per-client subscription endpoints).
Everything that can be a pure function over bytes is one, which is what makes
the whole thing testable on a laptop without a runtime.

## Repository layout

```
├─ src/                  the worker crate (Rust, wasm32 + host)
├─ public/               static assets: decoy page + panel UI (served by the Worker)
├─ wizard/               the browser installer (installer/ Worker serves it)
├─ installer/            web-based installer Worker (JS, deploys panels via REST)
├─ relay-poc/            external-relay experiment (Python; not mainline)
├─ scripts/              build.py, deploy.py
├─ docs/                 this file + research reports
└─ .research_salvage/    primary-source research transcripts
```

## Module map (`src/`)

The module table from `lib.rs`:

| Module | Responsibility |
|---|---|
| `protocol` | Inbound protocol parsers. Pure, no I/O, no panics. |
| `transport` | XHTTP, WebSocket, and the decoy page. |
| `core_schema` | Typed models of each core's configuration schema. |
| `translate` | One config in, three cores out, with honest degradation. |
| `panel` | Authenticated admin UI and its API. |
| `subscription` | Per-client subscription rendering. |
| `config` | Runtime settings, bindings, and the unified model. |
| `relay` | Outbound dials (direct / Proxy IP / NAT64), socket pump. |
| `router` | Pure `(method, path) → Route` decision — host-tested. |
| `entry` | Thin fetch handler; performs the I/O the route implies. |

### protocol/ — parsers, pure

One file per protocol (`vless.rs`, `trojan.rs`, `vmess.rs`, `shadowsocks_body.rs`)
plus shared pieces (`addr.rs`, `codec.rs`, `detect.rs`, `uuid.rs`). Every parser
is a pure function over bytes with a fuzz-style "never panics on arbitrary input"
test. `detect.rs` classifies the first bytes of an inbound connection into a
protocol without consuming them.

### transport/xhttp/ — the transport layer

| File | Role |
|---|---|
| `wire.rs` | Request classification (packet-up / stream-up / stream-one), padding validation, header shaping. Host-tested. |
| `session.rs` | `UploadQueue` — reorders packet-up chunks by seq, drops duplicates, caps lookahead (`scMaxBufferedPosts`×4). Pure. |
| `durable.rs` | The Durable Object: owns the outbound TCP socket, runs the downlink pump (64 KiB buffer, 3 ms coalesce window), answers 404 when dead. wasm32-only. |
| `supervise.rs` | Teardown state machine: receiver-gone and poisoned sessions end immediately; 60 s true-idle for healthy ones. |
| `deadlines.rs` | Header-phase budget: 10 s first chunk / 4 s later chunks / 15 s total. Pure. |
| `diag.rs` | Per-session byte counters + exit-reason capture. Collected always; *published* only when `SESSION_DIAG` is set. |
| `decoy.rs` | The single page every negative outcome renders. |

### transport/websocket.rs — present, deliberately off

> "Disabled by default, and that is a deliberate security position rather than
> caution. Nearly every public panel in this space uses WebSocket and nothing
> else, so it is the most heavily trained-on transport a classifier sees."

`WS_ENABLED` is `"false"` in both deploy paths. The store records "the WS relay
path gives EOF" — uninvestigated (KNOWN_ISSUES §2).

### relay/ — the outbound side

| File | Role |
|---|---|
| `mod.rs` | The socket pump. `MAX_WRITE` = 32 KiB sliced writes (a test fails if this regresses to plain `write_all`); `MAX_BUFFER` = 512 KiB memory cap. |
| `connect.rs` | Preflight refusal: Cloudflare ranges, private, loopback, port 25 rejected before any dial. 5 s handshake bound for single-candidate dials. |
| `outbound.rs` | Dial plans: Off / ProxyIp (ordered candidates, ≤8 attempts) / NAT64 (RFC 6052 prefix synthesis). Pure. |
| `outbound_state.rs` | Last-known-good preference: records which Proxy IP won, port-scoped, debounced, demotes failed preferences. |

### translate/ — honest emission

`xray.rs`, `singbox.rs`, `mihomo.rs` each render the unified node model into
their core's config. The shared `gate` records **which field was dropped and
why** when a setting cannot survive to a client — the panel surfaces these
instead of emitting a config that silently omits what was asked for.
AdGuard DoH is injected into sing-box-family exports (incl. Hiddify/Karing) as a
leak-prevention default.

### panel/ — admin surface

`auth.rs` (constant-time password compare; empty password = panel disabled,
never open), `api.rs` (typed request/response, optimistic concurrency via
`expected_rev`), `advisor.rs` (the UI *pre-blocks* values the conflict engine
knows will break, per client), `store.rs` (KV read/write), `serve.rs` (routes).
`public/panel.html` is the UI: node editor, outbound settings, export preview,
QR, save with revision check.

### subscription/ — per-client rendering

`uri.rs` builds share links per protocol; `bundle.rs` dispatches per client
(7 targets: v2rayN, v2rayNG, Hiddify, Karing, upstream sing-box, mihomo,
NekoBox) and shape (share links vs full config). Nodes that cannot be expressed
for a client are listed as `skipped` with a reason, never silently dropped.

### config/ — the unified model

`model.rs` (Node, Protocol, Transport, Security, OutboundConfig…),
`conflicts.rs` (the incompatibility matrix, per-client severity), `env.rs`
(binding parsing — "a mistake here locks every user out").

## The request path

```
client TLS → Worker fetch → router::route(method, path, upgrade)
   ├─ Decoy        → public/decoy.html            (everything unidentified)
   ├─ Xhttp        → protocol detect → UploadQueue → Durable Object socket
   ├─ WebSocket    → only if WS_ENABLED            (default: off)
   ├─ Panel        → auth → panel UI/API
   ├─ Subscription → render per client from KV settings
   ├─ DuplexProbe / ConnectProbe → diagnostics (gated by DIAGNOSTICS)
   └─ error anywhere → decoy (entry.rs: never surface an internal error)
```

The invariant entry.rs exists to preserve: **anything not positively identified
resolves to the decoy, identically**. No distinguishable 404, no error body, no
timing signal.

## The Durable Object lifecycle

A Durable Object is the only thing in Workers that can own a TCP socket across
request boundaries — Xray itself requires this (session records are held
between the upload POST(s) and the draining GET). The lifecycle, as fixed in
the Aug 2026 outage campaign:

1. **Connect** — `/connect` request arrives → header phase under the 10/4/15 s
   deadline budget → outbound dial (direct or Proxy IP candidates).
2. **Pump** — uplink POST chunks feed `UploadQueue`; the owner task drains it
   into the socket in ≤32 KiB slices; the downlink pump reads 64 KiB buffers,
   coalesces within 3 ms, and streams to the GET.
3. **End, promptly** — receiver-gone or poisoned → immediate teardown
   (supervise.rs); healthy idle → 60 s teardown; the object marks itself ended.
4. **After death** — later requests on the same session id answer **404**,
   which clients treat as "rebuild now" instead of retrying a corpse. A single
   teardown finalizer guarantees one session can't double-publish.

This is what keeps free-tier DO duration accounting livable: every session
bounds its own lifetime, and dead ones cost nothing.

## Key runtime constants

| Constant | Value | Where | Why |
|---|---|---|---|
| `MAX_WRITE` | 32 KiB | relay/mod.rs | workerd write cap; regression-tested |
| `MAX_BUFFER` | 512 KiB | relay/mod.rs | isolate memory guard (128 MB total) |
| `DOWNLINK_BUFFER` | 64 KiB | xhttp/durable.rs | ~640→160 reads per 10 MB vs old 16.5 KiB |
| `COALESCE_WINDOW_MS` | 3 ms | xhttp/durable.rs | burst reads flush once |
| header deadlines | 10/4/15 s | xhttp/deadlines.rs | kills header-dribble abuse |
| `HANDSHAKE_TIMEOUT_SECS` | 5 s | relay/connect.rs | single-candidate dial bound |
| `MAX_PROXY_ATTEMPTS` | 8 (default 3) | relay/outbound.rs | retry-storm cap |
| idle teardown | 60 s | supervise.rs | DO lifetime bound |

## Compile-time posture

- `#![forbid(unsafe_code)]`
- `unwrap`/`expect` denied by lint on request paths (tests exempt)
- `worker` crate (0.8.5) is wasm32-only → protocol/wire/conflict/relay-plan
  layers compile and test on the host (483 tests, ~25 s)
- compatibility_date pinned at 2026-07-01; it moves only deliberately

## Deployments and bindings

One Worker + one KV namespace (`<name>-settings`) + one DO class
(`XhttpSession`). Secrets (write-only): `VLESS_USERS`, `TROJAN_USERS`,
`VMESS_USERS`, `SS_USERS`, `PANEL_PASSWORD`. Plain vars: `XHTTP_PATH`,
`PANEL_PATH`, `SUB_PATH`, `WS_ENABLED`, optional `DIAGNOSTICS` / `SESSION_DIAG`.
All paths and passwords are random at deploy time (`token_hex(8)` /
`token_urlsafe(18)`); the wizard and `scripts/deploy.py` both generate them.

Two deploy paths produce identical results: the web **wizard** (installer
Worker drives the Cloudflare REST API) and `scripts/deploy.py` (CLI).

## What lives outside the Worker

- **relay-poc/** — a Python external relay that owns the upstream sockets while
  a thin Worker forwards XHTTP requests to it. Validated (~214 Mbps local for
  5 MB) but an experiment: the DO approach remains mainline.
- **installer/** — the installer Worker. Deliberately tiny and stateless; the
  user's API token lives only in one request's memory and is never logged,
  persisted, or echoed.

## Related documents

- [Phase 0 report](research/phase-0-report.md) — the survey that chose XHTTP over WebSocket
- [Parameter inventory](research/parameter-inventory.md) — the matrix the emitters enforce
- [KNOWN_ISSUES](../KNOWN_ISSUES.md) — what is deliberately absent
- [PROJECT_STATE_2026-08-27](../PROJECT_STATE_2026-08-27.md) — evidence-attributed snapshot
