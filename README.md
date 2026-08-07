# Trinity Panel

A multi-protocol proxy panel that runs entirely on Cloudflare Workers — no VPS, no
Docker, no server to patch. It speaks **VLESS, VMess, Trojan and Shadowsocks-2022**
over **XHTTP** rather than WebSocket, and it generates working configuration files
for Xray, sing-box and mihomo from a single source of truth.

Free tier is enough. One `wasm` module, one KV namespace, one Durable Object.

---

## Quick Start

The fastest path from nothing to a working deployment. Every step is expanded in
**[INSTALL.md](INSTALL.md)** — read that instead if any line below is unfamiliar.

```bash
# 1. Prerequisites: Rust, the wasm32 target, and a version-matched wasm-bindgen
rustup target add wasm32-unknown-unknown
cargo install wasm-bindgen-cli --version 0.2.126   # MUST match Cargo.lock exactly
```

```bash
# 2. Clone and build
git clone https://github.com/Osajjad0/trinity-panel.git
cd trinity-panel
python scripts/build.py
```

```bash
# 3. Point the deploy script at your Cloudflare account
export CLOUDFLARE_API_TOKEN=...    # Workers Scripts: Edit + Workers KV Storage: Edit + Account Settings: Read
export CLOUDFLARE_ACCOUNT_ID=...
```

```bash
# 4. Deploy. Credentials and secret paths are generated and printed ONCE.
python scripts/deploy.py --name my-worker --build-dir build/worker
```

The script prints your panel URL, panel password, subscription URL and every
protocol credential. **Copy them immediately — they are not written to disk and
cannot be recovered.** Open the panel URL, sign in, and copy a subscription link
into your client.

Full walkthrough, token creation with screenshots-worth of detail, and every
binding explained: **[INSTALL.md](INSTALL.md)**.

---

## Why this exists

Almost every Cloudflare proxy panel in circulation does the same thing: VLESS over
WebSocket on a guessable path, with a config generator bolted on. That works right
up until it doesn't, and it fails for a structural reason — WebSocket is the most
heavily classified transport in this space. A `101 Switching Protocols` upgrade on
a CDN edge is a distinctive shape, and it is the shape every filtering system has
had years to learn.

Trinity Panel defaults to **XHTTP `packet-up`** instead. Traffic leaves as ordinary
HTTP `POST` and `GET` requests carrying padded bodies to a random path — the same
traffic pattern as any web application talking to its own API. There is no upgrade
handshake to fingerprint and no long-lived socket to notice. WebSocket support is
present in the code but **off by default**, deliberately: running both on one
hostname couples their fate, so a classifier that flags the hostname takes down
both at once.

Three more things make this different from the usual panel:

**It tells you what it dropped.** A node is modelled once, and each core's emitter
renders it. When a setting cannot survive the trip to a particular client, the
emitter records *which field and why*, and the panel shows you. Silently emitting
a config that omits what you asked for is the failure mode this design exists to
prevent — it is how you end up with a connection that establishes and then behaves
nothing like it was configured, with nothing anywhere to explain it.

**The conflict matrix is per-client, not per-core.** The same combination can be
fatal in one core, silently broken in another, and load-bearing in a third. `mux`
with Vision is rejected by sing-box, tolerated by Xray, and partly required there.
Treating "sing-box" as one target loses real capability: upstream sing-box has
never supported XHTTP, but Hiddify and Karing ship patched forks that do, and
v2rayN runs XHTTP through bundled Xray while its own sing-box builder rejects it.
Exports target *clients*, because that is what your users actually install.

**Every negative outcome returns the same page.** Wrong path, wrong credential,
bad padding, expired session — all render an identical plausible status page with
an identical status code. There is no distinguishable 404 and no error body. A
scanner that can tell those apart has learned that something is here.

Written in Rust, compiled to WebAssembly, `#![forbid(unsafe_code)]`, with
`unwrap`/`expect` denied by lint on every request-handling path. 369 tests run on
the host in seconds without a WASM harness or a live deployment.

---

## Features

Status is reported honestly, using the project's own verification levels. See
[KNOWN_ISSUES.md](KNOWN_ISSUES.md) for the full picture and
[docs/PROGRESS.md](docs/PROGRESS.md) for per-module detail.

| | Status |
|---|---|
| **VLESS** inbound | Proven on a live deployment with a real Xray client |
| **Trojan** inbound | Proven on a live deployment with a real Xray client |
| **VMess** inbound (`auto`, `aes-128-gcm`, `chacha20-poly1305`) | Proven, all three ciphers |
| **Shadowsocks-2022** (all three 2022-blake3 methods) | Proven, all three methods on one deployment at once |
| **XHTTP `packet-up`** transport | Proven — the default and the only mode needing no full-duplex support |
| **XHTTP `stream-up` / `stream-one`** | Not implemented. Gated behind a duplex probe that has not been run |
| **WebSocket** transport | Compiles only. Never enabled on a live deployment. Off by default |
| **Subscription serving** (`/sub/<client>` and `/sub/<client>.json`) | Proven — served live, validated by `xray -test` |
| **Config translation** → Xray / sing-box / mihomo | Host-tested **and** accepted by the real core binaries |
| **Per-client conflict engine** with plain-language reasons | Host-tested |
| **Admin panel UI** | Reachable and password-gated. Not verified end-to-end against a live deployment |
| **QR codes** for share links and subscriptions | Host-tested against independent vectors |
| **Decoy page** on every negative outcome | Proven live — `/`, `/robots.txt` and any unknown path return identical bytes |
| **Durable Object session store** | Proven, including 12 simultaneous tunnelled requests |
| **gRPC / `httpupgrade`** transports | Not implemented, and cannot be — see below |
| Installer wizard, standalone single-file `worker.js` | Not started |

Measured on a live deployment: 20/20 sequential requests succeeded, p50 891 ms,
p95 1661 ms. Sustained throughput, cold-start time and the obfuscation on/off delta
have **not** been measured — those numbers are absent rather than estimated.

**gRPC and `httpupgrade` are not missing by oversight.** Both gRPC modes are
bidirectional HTTP/2 streams, and `multiMode` batches buffers without removing the
duplex requirement. `httpupgrade` needs the raw socket after a `101`, which the
Workers runtime never exposes. **WARP is likewise client-side only**: the runtime
has no outbound UDP, so a Worker cannot speak WireGuard — it can only emit configs
your own core executes, with that traffic bypassing the Worker entirely.

---

## Architecture

```
        Client (Xray / sing-box / mihomo)
                    │  XHTTP packet-up over TLS 443
                    ▼
        ┌───────────────────────────────┐
        │  Worker  (src/entry.rs)       │  every unknown request → decoy page
        │  router.rs — pure, testable   │
        └───────┬───────────┬───────────┘
                │           │
     XHTTP prefix│           │panel + subscription prefix
                ▼           ▼
    ┌─────────────────┐  ┌──────────────────────────┐
    │ Durable Object  │  │ panel::serve             │
    │ XhttpSession    │  │  auth → store(KV) → api  │
    │  owns the socket│  │  subscription::bundle    │
    └────────┬────────┘  │  translate::{xray,       │
             │           │    singbox, mihomo}      │
   detect → protocol::*  └──────────────────────────┘
   → codec → relay
             │
             ▼
        Destination (TCP)
```

A Durable Object is required rather than chosen: XHTTP `packet-up` splits one
logical connection across separate HTTP requests, so the outbound socket must
outlive the request that opened it, and a Durable Object is the only thing on this
runtime that can hold it. That single constraint is also why the deployment target
is Workers with Static Assets rather than Pages Functions — a Pages project cannot
define a Durable Object.

Everything that can be a pure function over bytes is one, and lives behind no
runtime dependency at all. The `worker` crate is a `wasm32`-only dependency, which
is what lets the protocol parsers, the XHTTP wire layer and the conflict engine
compile and test on the host in milliseconds.

Depth:

- **[docs/PROGRESS.md](docs/PROGRESS.md)** — per-module verification status, every
  key design decision with its reasoning, and the defects that only a real
  deployment could surface.
- **[docs/research/phase-0-report.md](docs/research/phase-0-report.md)** — survey of
  ten existing panels, the Cloudflare runtime constraints, and why the transport
  choices here differ from everyone else's.
- **[docs/research/parameter-inventory.md](docs/research/parameter-inventory.md)** —
  cross-core parameter tables and the incompatibility matrix the emitters enforce.
- **[docs/deploy-and-test-procedure.md](docs/deploy-and-test-procedure.md)** — the
  terse build/deploy/verify checklist.

---

## Known issues

Summarised here; the full list with detail is in
**[KNOWN_ISSUES.md](KNOWN_ISSUES.md)**.

- **The panel UI has not been verified against a live deployment.** It is served
  and password-gated, but the project's own status notes record the UI as the
  outstanding half of its stage. Treat it as unproven.
- **`.dev.vars.example` documents secrets the code does not read.** It describes
  `PANEL_PASSWORD_HASH` and `SESSION_SIGNING_KEY`; the code reads a plaintext
  `PANEL_PASSWORD` binding and derives the session key from it. Follow
  [INSTALL.md](INSTALL.md), not that file.
- **It references `npm run hash-password` and `npm run gen-key`, which do not
  exist.** There is no `package.json` in this repository.
- **WebSocket is unproven and its relay path is suspect.** A source comment
  records that the WS relay path gives EOF, which is why the derived Trojan node
  uses XHTTP rather than WebSocket. It is off by default.
- **The duplex question is unresolved**, so `stream-up` and `stream-one` are
  unavailable. A probe endpoint exists to measure it and has not been run.
- **Adding or removing a proxy user is a redeploy, not a panel edit.** Credentials
  live in secret bindings read on the request path, by design. The panel owns
  everything client-side, not the credential set.
- Two `wrangler.jsonc` defaults (`XHTTP_PATH` / `PANEL_PATH` set to `/`) are
  placeholders that the deploy script replaces. Deploying via `wrangler` without
  changing them serves the transport on the root path.

---

## Security notes

- **The panel can read every credential the deployment serves.** Protect its
  password accordingly; a leaked panel password is equivalent to leaking all of them.
- **A deployment with no `PANEL_PASSWORD` has no panel, not an open one.** This is
  checked before anything else, so an unconfigured deployment is indistinguishable
  from one with no panel prefix at all.
- **Path prefixes are the first line of defence and must be random.** The deploy
  script generates 8-byte hex prefixes. A prefix like `/vless` is found by the
  first dictionary scan.
- **The diagnostic connect-probe is opt-in** via a `DIAGNOSTICS` variable, because
  it dials an attacker-chosen host and port and reports the result — which makes
  the Worker a port scanner. Leave it unset in production.
- Rotating `PANEL_PASSWORD` invalidates every outstanding session, which is the
  intended way to sign everyone out at once.
- Observability is sampled and logs no request bodies. Never add a log line
  carrying a UUID, a path prefix, or a destination host.

---

## Legal

You are responsible for how you use this. Running a proxy may be restricted or
illegal where you are, and the terms of service of your hosting provider apply to
you regardless of what this software does. Nothing here is an invitation to break
either.

---

## License

MIT — see [LICENSE](LICENSE). The `license = "MIT"` field in `Cargo.toml` predates
this file and is the original declaration.

### Attribution

The JavaScript shim emitted by `scripts/build.py` is modelled on the one in
Cloudflare's [`worker-build`](https://github.com/cloudflare/workers-rs)
(MIT/Apache-2.0). Two of its behaviours are deliberately preserved: marking a
WebAssembly instance for reinitialisation after a `RuntimeError`, and re-exporting
Durable Object classes through the same wrapper.

Protocol behaviour was established by capturing real client handshakes rather than
by reading specifications. The capture fixtures in `tests/fixtures/` are synthetic
handshakes made against a local listener with throwaway keys; they carry no live
credential. BLAKE3 is implemented in-tree and tested against the official vectors;
Base64 against the RFC 4648 vectors.
