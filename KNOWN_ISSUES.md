# Known issues

Current as of 2026-08-25. Everything here is drawn from reading
the code and from a live deployment. It documents the state as found.

The project's own verification vocabulary is used throughout:

| Level | Meaning |
|---|---|
| **Proven** | Exercised on a live deployment carrying real traffic |
| **Host-tested** | Has real unit tests that run in `cargo test --lib` and pass |
| **Compiles only** | Builds for `wasm32-unknown-unknown`; has never executed |
| **Unverified** | Written but not exercised against a real client, core or deployment |

---

## Not working / not verified

### 0. Live outage (measured 2026-08-25): free-tier Durable Object duration quota exhausts under idle zombie sessions

On the production deployment (`trinity-cleanacct`), every new session began
failing instantly from **~10:24 UTC** onward while earlier sessions that
morning tore down cleanly (`setup_ms` 12–239 ms, healthy byte counts in
`SESSION_DIAG`). Evidence, all read-only:

- Hourly GraphQL shows DO invocations stop entirely after the 10:00 UTC hour,
  while Worker-level requests keep succeeding (they serve decoys).
- `SESSION_DIAG` teardown blobs — written once per session end — stop
  mid-morning at exactly 10:24:08 UTC and never resume.
- The namespace holds **1,933 live `XhttpSession` objects**; each lingering
  object burns wall-clock duration against the free tier's daily allowance
  whether or not any traffic flows through it.

The mechanism matches the code: before supervised teardown existed, a session
whose client vanished without closing cleanly had no path that ended it
promptly, so abandoned half-sessions accumulated as objects that hold quota
all day. Once the day's duration budget is gone, *every* DO fetch fails before
an object wakes — the whole transport is down until 00:00 UTC resets the
allowance.

What exists for it: the supervisor (`src/transport/xhttp/supervise.rs`) ends
receiver-gone and poisoned sessions immediately and keeps the 60 s true-idle
teardown; it is merged to this tree but **not yet deployed**, so the live
deployment remains exposed until the next deploy. Deploying does not clear
existing zombies; they age out on their own schedule.

### 1. The panel UI is unverified end-to-end

The code wires `Route::Panel` to `panel::serve::panel`, a `PANEL_PASSWORD`
binding exists on the live deployment, and the panel path returns the 26 KB panel
HTML rather than the 68-byte decoy. So it is served and gated. What has **not**
happened is verification: no record exists of signing in, saving settings, and
confirming persistence against a live deployment. The panel's own backend calls
(`/api/state`, `/api/nodes`, `/api/check`, `/api/export`, `/api/qr`) are host-tested
as pure functions only.

Treat the panel as unproven. Subscription serving is independent of it and *is*
proven.

### 2. WebSocket transport: compiles only, and its relay path is suspect

`src/transport/websocket.rs` compiles for `wasm32` and has never been enabled on a
deployment. It is off by default, which is a deliberate security decision, not
caution about the code — WebSocket is the most heavily classified transport in this
space, and running it on the same hostname as XHTTP couples their fate.

Separately, a comment in `src/panel/store.rs` records that **"the WS relay path
gives EOF"**, which is why the derived Trojan node uses XHTTP rather than
WebSocket. That reads as a known defect rather than a design note. It has not been
investigated.

Note that `WS_ENABLED` is `"false"` everywhere it is set — in
`wrangler.jsonc` and in `scripts/deploy.py` alike (deploy.py:411) — so the
WebSocket route is unreachable on deployments made by either path. That is a
deliberate default: WebSocket is an unproven code path with a suspected relay
bug, and enabling it couples the transport's fate with XHTTP's hostname.

### 3. XHTTP `stream-up` and `stream-one` are not implemented

Only `packet-up` works. `src/entry.rs` returns the decoy for `StreamOne` and
`StreamUp` requests, with the comment "Not yet implemented; it stays behind the
duplex probe."

The blocker is upstream: whether Cloudflare supports full-duplex streaming is
genuinely unresolved, and the available evidence is contradictory (see
`docs/research/phase-0-report.md` §4). A probe endpoint (`Route::DuplexProbe`)
exists to measure it on a real deployment rather than guess. **It has not been
run.** Until it is, the two streaming modes stay unavailable.

### 4. Durable Object concurrency is enforced by reading, not by a test

The `RefCell`-not-held-across-`await` discipline in `XhttpSession` is maintained by
code review, not by any test. Overlapping requests for one session are the normal
case for `packet-up`.

Partial mitigation exists — 12 simultaneous tunnelled requests were measured
succeeding on a live deployment, with a request after the burst still working. That
is real evidence, but it is one measurement rather than a regression test, so a
future change can break it silently.

### 5. Measurements are incomplete

Measured on a live deployment: 20/20 sequential requests, p50 891 ms, p95 1661 ms,
and the 12-request concurrency burst above.

**Not measured:** sustained throughput, cold-start time, and the obfuscation on/off
delta. These are absent from the README rather than guessed; the project reports
only numbers that come from measurement.

### 6. NAT64 outbound mode does not work on `workers.dev`

**Unverified → measured negative.** The mode is implemented, host-tested, and
ships **disabled** (`mode: "off"` is the default and the only default). It was
tested end to end on a live deployment on 2026-08-16 and does not achieve
anything there. Two runtime limits stack:

- **Domains cannot be synthesised.** NAT64 rewrites an IPv4 address into an
  IPv6 one. A domain destination has no IPv4 address until it is resolved, and
  the runtime exposes no DNS API, so domain targets fall through to a direct
  dial. This is the common case for real client traffic.
- **IPv6 literals do not appear to be dialable at all.** With the mode Off, a
  native IPv6 literal that answers from an ordinary host was measured as
  unreachable through the relay, while the same operator's IPv4 literal
  answered: `[2620:fe::fe]` → no connection vs `9.9.9.9` → HTTP 505;
  `[2001:4860:4860::8888]` → no connection vs `8.8.8.8` → HTTP 302. Since NAT64
  can only ever produce an IPv6 target, it has nothing to succeed with.

It is kept rather than deleted because it costs nothing when unused (Off mode
takes a separate single-candidate path) and because IPv6 egress is a runtime
capability that may change. **Use Proxy IP mode instead** — that path is proven
on a live deployment across all four protocols.

### 7. Not built

- **Standalone single-file `worker.js`.** The honest limitation on this one is not
  the language but the **absence of `packet-up`**: a drag-and-drop Pages target
  cannot hold cross-request state, so a JS build gets WebSocket and `stream-one`
  only. Install via [the wizard](README.md#quick-start) instead.

---

## Design limitations that are not bugs

These are deliberate and documented here so they are not mistaken for defects.

### Adding a user is a redeploy, not a panel edit

Credentials live in secret bindings that the Durable Object reads on the request
path. Moving them into KV would put a storage round trip in front of every new
session, and would mean a panel bug could lock every user out of a working
deployment. So the panel *reads* credentials to build client configs but does not
own them.

This is a real limitation, stated rather than hidden. What the panel does own is
everything client-side: hostnames, SNI, transport parameters, per-core options,
chains.

### gRPC and `httpupgrade` cannot be implemented on this runtime

Both gRPC modes are bidirectional HTTP/2 streams — `multiMode` batches buffers but
does not remove the duplex requirement. `httpupgrade` needs the raw socket after a
`101`, which the Workers runtime never exposes. These are absent for a structural
reason, not an unfinished one.

### WARP is client-side only

The runtime has no outbound UDP, so a Worker cannot speak WireGuard. What it can do
is provision credentials over HTTPS and emit configs your own core executes, with
that traffic going directly to Cloudflare and bypassing the Worker entirely. Any UI
implying the Worker proxies WARP would be a lie.

### Upstream sing-box and NekoBox cannot import XHTTP nodes

Upstream sing-box has never supported the transport. Hiddify and Karing ship
patched forks that do, and v2rayN runs XHTTP through bundled Xray while its own
sing-box config builder rejects it. The panel refuses per client with a reason
rather than emitting a config that will not load.

### VMess `security: none` and `security: zero` are refused

Deliberate. The server declines body modes it cannot frame correctly, so the client
reports a clean failure rather than establishing a tunnel that silently garbles
everything through it. The refusal is covered by a passing test case, not a gap.

---

## Repository hygiene

- **`wrangler.jsonc` ships path placeholders (`/`) and `WS_ENABLED: "false"`.**
  Both are overwritten by [the wizard](README.md#quick-start) and by
  `scripts/deploy.py`; deploying with `wrangler` without editing them first serves
  the transport on the root path and leaves an unproven transport disabled.
  Prefer the wizard or the CLI script. `scripts/deploy.py` also ships
  `WS_ENABLED: "false"` (deploy.py:411), so every supported deploy path keeps
  the unproven transport off unless an operator opts in by hand.
- **The crate in `Cargo.toml` is still named `tricore_panel`.** The build artefact
  is therefore `tricore_panel.wasm`. Renaming the crate was out of scope; the
  rebrand is user-facing only.

---

## Where to look next

- [docs/research/phase-0-report.md](docs/research/phase-0-report.md) — the runtime
  constraints behind most of the limitations above.
- [docs/research/parameter-inventory.md](docs/research/parameter-inventory.md) — the
  incompatibility matrix, and the reference to reach for when a core rejects a
  generated config.
