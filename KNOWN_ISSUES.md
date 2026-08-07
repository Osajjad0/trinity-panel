# Known issues

Current as of the initial public release. Everything here is drawn from the
project's own record in [docs/PROGRESS.md](docs/PROGRESS.md) and from reading the
code — **nothing in this file has been investigated or fixed**, by instruction. It
documents the state as found.

The project's own verification vocabulary is used throughout:

| Level | Meaning |
|---|---|
| **Proven** | Exercised on a live deployment carrying real traffic |
| **Host-tested** | Has real unit tests that run in `cargo test --lib` and pass |
| **Compiles only** | Builds for `wasm32-unknown-unknown`; has never executed |
| **Unverified** | Written but not exercised against a real client, core or deployment |

---

## Not working / not verified

### 1. The panel UI is unverified end-to-end

`docs/PROGRESS.md` lists "panel UI" as the outstanding half of its stage 3 and
records `panel::auth` as "host-tested; **not yet reachable**", with `Route::Panel`
still wired to the decoy pending the UI.

The code has moved past that note — `Route::Panel` now dispatches to
`panel::serve::panel`, a `PANEL_PASSWORD` binding exists on the live deployment, and
the panel path returns the 26 KB panel HTML rather than the 68-byte decoy. So it is
served and gated. What has **not** happened is verification: no record exists of
signing in, saving settings, and confirming persistence against a live deployment.
The panel's own backend calls (`/api/state`, `/api/nodes`, `/api/check`,
`/api/export`, `/api/qr`) are host-tested as pure functions only.

Treat the panel as unproven. Subscription serving is independent of it and *is*
proven.

### 2. `.dev.vars.example` documents secrets the code does not read

The file describes two secrets:

- `PANEL_PASSWORD_HASH` — "Argon2id hash of the admin panel password"
- `SESSION_SIGNING_KEY` — "32 random bytes, base64, used to sign admin session cookies"

**Neither name appears anywhere in the source.** What `src/panel/serve.rs` actually
reads is a **plaintext** `PANEL_PASSWORD` binding, and `src/panel/auth.rs` derives
the session key from that password via BLAKE3 — which is what makes a password
change invalidate every session for free.

There is no Argon2 dependency in `Cargo.toml`. Anyone following
`.dev.vars.example` will deploy a Worker with no panel at all, because
`PANEL_PASSWORD` will be empty and an empty password means the panel does not
exist.

[INSTALL.md](INSTALL.md#9-every-binding-explained) has the accurate list. The
example file has not been corrected here, only documented.

### 3. Referenced npm scripts do not exist

`.dev.vars.example` tells you to run `npm run hash-password` and `npm run gen-key`.
`wrangler.jsonc` refers to `npm run build`. **There is no `package.json` in this
repository**, so all three fail.

### 4. WebSocket transport: compiles only, and its relay path is suspect

`src/transport/websocket.rs` compiles for `wasm32` and has never been enabled on a
deployment. It is off by default, which is a deliberate security decision, not
caution about the code — WebSocket is the most heavily classified transport in this
space, and running it on the same hostname as XHTTP couples their fate.

Separately, a comment in `src/panel/store.rs` records that **"the WS relay path
gives EOF"**, which is why the derived Trojan node uses XHTTP rather than
WebSocket. That reads as a known defect rather than a design note. It has not been
investigated.

Note that the live deployment has `WS_ENABLED=true` and `WS_PATH=/ws` set, so the
WebSocket route is reachable there — on an unproven code path with a suspected
relay bug.

### 5. XHTTP `stream-up` and `stream-one` are not implemented

Only `packet-up` works. `src/entry.rs` returns the decoy for `StreamOne` and
`StreamUp` requests, with the comment "Not yet implemented; it stays behind the
duplex probe."

The blocker is upstream: whether Cloudflare supports full-duplex streaming is
genuinely unresolved, and the available evidence is contradictory (see
`docs/research/phase-0-report.md` §4). A probe endpoint (`Route::DuplexProbe`)
exists to measure it on a real deployment rather than guess. **It has not been
run.** Until it is, the two streaming modes stay unavailable.

### 6. Durable Object concurrency is enforced by reading, not by a test

`docs/PROGRESS.md` flags this: the `RefCell`-not-held-across-`await` discipline is
maintained by code review, not by any test. Overlapping requests for one session
are the normal case for `packet-up`.

Partial mitigation exists — 12 simultaneous tunnelled requests were measured
succeeding on a live deployment, with a request after the burst still working. That
is real evidence, but it is one measurement rather than a regression test, so a
future change can break it silently.

### 7. Measurements are incomplete

Measured on a live deployment: 20/20 sequential requests, p50 891 ms, p95 1661 ms,
and the 12-request concurrency burst above.

**Not measured:** sustained throughput, cold-start time, and the obfuscation on/off
delta. `docs/PROGRESS.md` marks these outstanding and insists the numbers come from
measurement rather than estimation. They are therefore absent from the README
rather than guessed.

### 8. Not started

From the project's own stage list:

- **Installer wizard** (Linux + Windows CMD + Android). The stated bar is that it
  be genuinely double-clickable and tested by completing a real deployment with
  nothing typed into a terminal.
- **Standalone single-file `worker.js`.** The honest limitation on this one is not
  the language but the **absence of `packet-up`**: a drag-and-drop Pages target
  cannot hold cross-request state, so a JS build gets WebSocket and `stream-one`
  only.
- **User and developer documentation** beyond this file, README.md and INSTALL.md.

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
everything through it. `docs/PROGRESS.md` records the refusal as a passing test
case, not a gap.

---

## Repository hygiene

Noted during the pre-publication audit, not acted on:

- **Two stale `.bak` files exist on disk but are not published.**
  `public/panel.html.bak` and `src/panel/serve.rs.bak` are leftover copies that
  predate the current files — the live `panel.html` is 26,231 bytes against the
  backup's 25,074, and `serve.rs` is 13,714 against 14,260. Neither is referenced by
  the build. They are excluded from this repository via a `*.bak` rule in
  `.gitignore`, so a clone will not contain them.
- **`wrangler.jsonc` ships `XHTTP_PATH` and `PANEL_PATH` as `"/"`.** These are
  placeholders that `scripts/deploy.py` overwrites. Deploying with `wrangler`
  without editing them serves the transport on the root path, defeating the
  random-prefix design. The file also omits `SUB_PATH` entirely.
- **`wrangler.jsonc` sets `WS_ENABLED: "false"` while `scripts/deploy.py` sets it
  to `"true"`.** The two deploy paths disagree, and the comment in `wrangler.jsonc`
  explaining why WebSocket is off by default is the one the script contradicts.
- **`docs/deploy-and-test-procedure.md` still names `tricore_panel.wasm`.** That is
  correct — the crate name in `Cargo.toml` is unchanged, so the build artefact
  genuinely still has that filename. Renaming the crate was out of scope.

---

## Where to look next

- [docs/PROGRESS.md](docs/PROGRESS.md) — per-module verification table, every design
  decision with reasoning, and §1's "defects that only deployment could find",
  which is the most useful page in the repository for anyone extending this.
- [docs/research/phase-0-report.md](docs/research/phase-0-report.md) — the runtime
  constraints behind most of the limitations above.
- [docs/research/parameter-inventory.md](docs/research/parameter-inventory.md) — the
  incompatibility matrix, and the reference to reach for when a core rejects a
  generated config.
