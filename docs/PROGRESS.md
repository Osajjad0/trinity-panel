# Project State

**Living document.** Updated as work lands so that a context reset, a session restart, or a new
contributor loses nothing. If this disagrees with the code, the code wins — and this file is wrong
and should be fixed.

Last updated: after subscription serving went live; panel UI still outstanding.

---

## 1. Verification status — read this before trusting anything

The single most useful thing this file records is **what has actually been proven versus what merely
compiles.** These are not the same, and conflating them is how a project ships something confident
and broken.

| Level | Meaning |
|---|---|
| **Proven** | Exercised on a live deployment carrying real traffic |
| **Host-tested** | Has real unit tests that run in `cargo test --lib` and pass |
| **Compiles only** | Builds for `wasm32-unknown-unknown`; no runtime execution has ever happened |
| **Unverified** | Written but not yet exercised against a real client, core, or deployment |

| Component | File | Status |
|---|---|---|
| Bounds-checked reader, error taxonomy, constant-time compare | `src/protocol/mod.rs` | Host-tested |
| Address decoding (both wire tables) | `src/protocol/addr.rs` | Host-tested |
| UUID parse/format | `src/protocol/uuid.rs` | Host-tested |
| **VLESS inbound** | `src/protocol/vless.rs` | **Proven** |
| **Trojan inbound** | `src/protocol/trojan.rs` | **Proven** |
| **VMess AEAD handshake** | `src/protocol/vmess.rs` | **Proven** |
| **VMess body codec** | `src/protocol/vmess_body.rs` | **Proven** (both ciphers) |
| **Shadowsocks-2022 header** | `src/protocol/shadowsocks.rs` | **Proven** (all three ciphers) |
| **Shadowsocks-2022 body codec** | `src/protocol/shadowsocks_body.rs` | **Proven** (all three ciphers) |
| Body codec contract | `src/protocol/codec.rs` | Host-tested |
| BLAKE3 | `src/crypto/blake3.rs` | Host-tested against the official vectors |
| Base64 decode | `src/crypto/base64.rs` | Host-tested against the RFC 4648 vectors |
| Protocol detection | `src/protocol/detect.rs` | **Proven** (four protocols, one path) |
| XHTTP request classification + padding | `src/transport/xhttp/wire.rs` | Host-tested |
| XHTTP uplink reorder buffer | `src/transport/xhttp/session.rs` | Host-tested (incl. property test) |
| Relay hot path | `src/relay/mod.rs` | Host-tested (duplex streams) |
| Outbound destination guard | `src/relay/connect.rs` | Host-tested (guard only) |
| Request router | `src/router.rs` | Host-tested |
| Config model | `src/config/model.rs` | Host-tested |
| Conflict rules engine | `src/config/conflicts.rs` | Host-tested |
| Translation contract + gate | `src/translate/mod.rs` | Host-tested |
| Shared emitter defaults | `src/translate/util.rs` | Host-tested |
| Xray / sing-box / mihomo emitters | `src/translate/{xray,singbox,mihomo}.rs` | Host-tested **+ accepted by the real core binaries** |
| Share links | `src/subscription/uri.rs` | Host-tested |
| **Subscription bundles** | `src/subscription/bundle.rs` | **Proven** — served live, validated by `xray -test` |
| Multi-node emitters | `src/translate/{xray,singbox,mihomo}.rs` | Host-tested **+ accepted by the real cores** |
| Panel settings store | `src/panel/store.rs` | Host-tested |
| Panel session auth | `src/panel/auth.rs` | Host-tested; **not yet reachable** |
| **Durable Object session store** | `src/transport/xhttp/durable.rs` | **Proven** |
| **Worker entry point** | `src/entry.rs` | **Proven** |
| Build + deploy pipeline | `scripts/{build,deploy}.py` | **Proven** |

**The spine is deployed and carrying traffic.** A real Xray client completes requests through it and
the egress IP changes; 12 simultaneous tunnelled requests all succeed and a request after that burst
still works, which is the direct evidence that the Durable Object concurrency fix survives pipelined
traffic. Measured on the live deployment: 20/20 sequential requests, p50 891 ms, p95 1661 ms.

**All four protocols are proven on one path.** Against a live deployment, with a real Xray client and an
egress-IP change confirming the traffic actually went through the tunnel:

| Case | Client setting | Result |
|---|---|---|
| VLESS | — | egress IP changed |
| Trojan | — | egress IP changed |
| VMess | `security: auto` (the default) | egress IP changed |
| VMess | `security: aes-128-gcm` | egress IP changed |
| VMess | `security: chacha20-poly1305` | egress IP changed |
| VMess | `security: none` | **refused, as designed** — no connection, no corruption |
| Shadowsocks-2022 | `2022-blake3-aes-128-gcm` | egress IP changed |
| Shadowsocks-2022 | `2022-blake3-aes-256-gcm` | egress IP changed |
| Shadowsocks-2022 | `2022-blake3-chacha20-poly1305` | egress IP changed |

The `security: none` row matters as much as the passing ones. The server declines body modes it
cannot frame correctly, so the failure is a clean one the client reports rather than a tunnel that
connects and silently garbles everything through it.

The three Shadowsocks rows were run with all three methods configured on one deployment at once,
which is also what exercises the per-credential salt length: the 128-bit method uses a 16-byte salt
and the others 32, so the parser cannot assume one fixed prefix across credentials.

Still **compiles only**: the WebSocket transport (`src/transport/websocket.rs`) is written and
compiles but has never been enabled on a deployment.

**Subscriptions are live.** With no configuration at all beyond deploying, `/<sub-path>/v2rayn`
returns base64 share links for every enabled protocol and `/<sub-path>/v2rayn.json` returns a full
Xray config that `xray -test` accepts. Nodes are derived from the deployment's own bindings, so the
endpoint works the moment the Worker is up. Unknown client names render the decoy, so the path
cannot be used to enumerate what is served.

Current totals: **335 tests passing, 0 clippy warnings, `wasm32-unknown-unknown` compiles clean.**

### Defects that only deployment could find

Recorded because each is invisible to every local test, and each will recur in similar work.

1. **Spawned work is cancelled with the request that spawned it.** A bare `spawn_local` belongs to
   the request that created it. The socket-owner task therefore died as soon as the uplink `POST`
   responded — but it lived long enough to send the protocol reply header, so the client saw a
   successful handshake followed by permanent silence. Use `state.wait_until` in a Durable Object,
   and join concurrent directions into a single future rather than nesting spawns.
2. **Outbound connections to Cloudflare IP ranges are refused.** Port 443 is fine; the address range
   is what is blocked. This is easy to misdiagnose because the obvious way to test a proxy is a
   public IP-echo service, and most of those are Cloudflare-fronted — the first end-to-end test
   failed for a reason that had nothing to do with the code. Test against a non-Cloudflare host
   (for example an AWS-hosted echo).

3. **A failing client does not mean a failing server.** When every protocol suddenly failed at once,
   including two already proven, the cause was the build machine's network rather than the code —
   see §4 on fake-IP DNS. The diagnosis that settled it, and the one worth repeating: drive one
   session by hand (open the downlink, post a hand-built header, read the reply), and separately mirror
   the real client's requests to the deployment through a local forwarder. The first proves the server
   is correct; the second proves it is correct *for the exact bytes that client sends*. Between them
   there is nothing left for a guess to hide in.

5. **A conflict rule can remove a working feature as silently as a bug adds a broken one.**
   Shadowsocks over XHTTP was refused for every core. It is valid on Xray, where `streamSettings`
   belongs to the outbound rather than to the protocol — `xray -test` accepts it and all three 2022
   ciphers had already been carried end to end by a real client through this very deployment. The
   rule's stated reasoning was about sing-box and mihomo and was correct for them; it was simply
   applied too widely. Nothing failed: the protocol just quietly never appeared in any export. The
   lesson is that the conflict engine needs the same standard of evidence as the protocol code —
   each rule scoped to the cores it was actually verified against.

4. **A guard that is right for every protocol but one.** The relay called the body codec only when
   the header had trailing bytes. That holds for VLESS, Trojan and VMess, and is false for
   Shadowsocks-2022, which carries its first payload *inside* the encrypted header — so the client's
   opening request sat in the decoder, the destination waited for a request it had already been
   handed, and the session hung with nothing logged at either end. The unit test for the codec was
   passing the whole time; it asserted the payload is emitted on the first `decode` call, and the
   caller simply never made that call. **Codec unit tests cannot catch a caller that skips the
   codec** — only an integration path can.

### Encrypted-payload protocols need a body codec — confirmed, not assumed

The relay was built on an assumption that holds for only half the protocols:
that once the header is parsed, bytes forward untouched.

| Protocol | Payload after the header | Servable by plain relay? | Codec |
|---|---|---|---|
| VLESS | Plaintext | Yes | `Decoder::Plain` |
| Trojan | Plaintext | Yes | `Decoder::Plain` |
| **VMess** | **Chunked AEAD under the negotiated body key** | **No** | Written and proven |
| **Shadowsocks-2022** | **Fully AEAD from the salt onward** | **No** | Written and proven |

Both were established by capturing a real Xray client handshake rather than by
reading a specification. The Shadowsocks capture contains no plaintext anywhere —
not even the destination hostname — which settles it beyond argument.

This matters because the failure is silent. A relay that authenticates an encrypted
protocol and then forwards raw bytes hands the destination ciphertext and the client
plaintext: the handshake succeeds, the connection establishes, data flows, and both
ends receive garbage, with nothing at the transport layer reporting a fault. The
symptom a user sees — "it connects but nothing loads" — points nowhere near the cause.

`protocol::codec` exists so the question cannot go unasked: a protocol either supplies a body
transform or is not registered for serving, and the `match` arms are exhaustive so adding a protocol
without answering the question does not compile.

### What the client negotiates is part of the wire format

A second, subtler version of the same trap, found by capturing one real handshake per client
`security` setting rather than reading the specification:

| client `security` | option byte | flags | served |
|---|---|---|---|
| `auto` (the default) | `0x0d` | ChunkStream, ChunkMasking, GlobalPadding | yes |
| `aes-128-gcm` | `0x0d` | ChunkStream, ChunkMasking, GlobalPadding | yes |
| `chacha20-poly1305` | `0x0d` | ChunkStream, ChunkMasking, GlobalPadding | yes |
| `none` | `0x05` | ChunkStream, ChunkMasking | no |
| `zero` | `0x00` | *(none)* | no |

Two consequences. **`auto` resolves to AES-128-GCM on CPUs with AES instructions and to
ChaCha20-Poly1305 otherwise**, so supporting only one cipher would break the default configuration
on half the devices in use — and would have looked fine in testing on an x86 machine. And the option
byte selects chunk masking, global padding and authenticated length, each of which changes the
framing; it was previously parsed and thrown away. Everything outside the implemented set is now
refused rather than assumed.

### Known-unverifiable-until-tested

- **Durable Object concurrency.** The `RefCell`-not-held-across-`await` discipline is enforced by
  reading, not by a test. Overlapping requests for one session are the normal case, so this needs
  runtime proof.
- **Whether Cloudflare supports full-duplex streaming.** Upstream evidence is contradictory (see
  research report §4). A self-test endpoint was built to measure it on the real deployment rather
  than guess. Unmeasured so far.

---

## 2. Key decisions and why

These are the decisions a newcomer would otherwise re-litigate. Each has the reasoning that produced
it, so it can be revisited on evidence rather than on vibes.

1. **Deploy to Workers + Static Assets, not Pages Functions.** XHTTP `packet-up` splits one
   connection across separate HTTP requests, so the outbound socket must outlive the request that
   opened it. Only a Durable Object can do that on this runtime, and Cloudflare states plainly that
   a Pages project cannot define one. Separately, Pages has no REST API for asset upload, so no
   installer can automate it. Reverses the original brief, which assumed Pages handled streaming
   better; it does not — both run the identical runtime behind the identical edge.

2. **XHTTP `packet-up` is the default transport.** It is the only mode requiring no full-duplex
   support anywhere in the path. `stream-up` and `stream-one` are offered only where a live probe
   confirms the deployment can do duplex.

3. **WebSocket is implemented but off by default.** Nearly every public panel uses WebSocket and
   nothing else, making it the most classified transport in this space. Paths are invisible inside
   TLS, so running it on the same hostname as XHTTP couples their fate — a classifier that flags the
   hostname takes both down. Separate hostnames are the only real isolation.

4. **gRPC and `httpupgrade` are not implemented, because they cannot be.** Both gRPC modes are
   bidirectional HTTP/2 streams (`multiMode` batches buffers; it does not remove the duplex
   requirement). `httpupgrade` needs the raw socket after a `101`, which the runtime never exposes.

5. **WARP is client-side only.** The runtime has no outbound UDP, so a Worker cannot speak
   WireGuard. What it *can* do is provision credentials over HTTPS and emit configs the user's own
   core executes, with traffic going directly to Cloudflare and bypassing the Worker entirely. Any
   UI must say so; a toggle implying the Worker proxies WARP would be a lie.

6. **Export targets are clients, not cores.** Upstream sing-box has never supported XHTTP, but
   Hiddify and Karing ship patched forks that do, and v2rayN runs XHTTP through bundled Xray while
   its own sing-box builder rejects it. Treating "sing-box" as one target loses working capability
   for two clients and ships broken configs to another.

7. **The conflict matrix is per-core, not shared.** The same combination can be fatal in one core,
   silently broken in another, and load-bearing in a third — `mux` with Vision is rejected by
   sing-box, tolerated by Xray, and partly required there because Vision refuses bare UDP.

8. **Emit Xray's legacy key spellings.** v26.7.11 renamed `network`→`method` and
   `tcpSettings`→`rawSettings`, keeping the old names as aliases. The new names do not exist on any
   older build — i.e. essentially every installed client. `xhttpSettings` is the exception; it has
   been accepted since October 2024.

9. **Every negative outcome renders the identical decoy page.** No distinguishable 404, no error
   body, no differing status between a wrong path, a wrong credential and bad padding. A scanner
   that can tell those apart has learned something is here.

10. **The authenticated user index travels onto the data path.** Without it, per-user accounting is
    impossible — which is how the largest panel in this space has users losing terabytes to
    freeloaders.

11. **Validation runs the real core binaries, not just a schema model.** Several failure classes
    surface only at core startup (Shadowsocks-2022 key length is checked inside a vendored library,
    not at parse time), so a schema check is a fast path, not the authority.

---

## 3. Stage status against the original brief

| # | Stage | Status |
|---|---|---|
| 1 | Phase 0 research + parameter inventory + research answers | **Done** — `docs/research/` |
| 2 | Rust source tree | **Complete for the protocol set** — VLESS, Trojan, VMess and Shadowsocks-2022 all proven in production |
| 3 | Translation layer + panel UI | **Translation and subscription serving done and core-validated**; **panel UI not started** |
| 4 | Build config, deploy script | **Done and proven** — `scripts/build.py`, `scripts/deploy.py` |
| 5 | Test results with real numbers | **Partial** — latency and concurrency measured; obfuscation on/off delta and sustained throughput outstanding |
| 6 | `/docs` complete | Research + this file done; **user and developer docs not written** |
| 7 | Installer wizard (Linux + Windows CMD + Android) | **Not started** |
| 8 | `SETUP.md` | **Not started** |
| 9 | Pre-push security audit, GitHub publish | Audit runs ad hoc before each commit; **publish not done** |
| 10 | Standalone single-file `worker.js` | **Not started** |

### Definition of done for the deferred items

- **Stage 5** needs a real deployment, then p50/p95 latency, throughput, cold start, and the
  obfuscation on/off delta. Numbers must come from measurement, never from estimation.
- **Stage 7**'s wizard must be genuinely double-clickable and tested by running it on this machine
  and completing a real deployment with nothing typed into a terminal. "Should work" is not done.
- **Stage 10**'s honest limitation is not the language but the **absence of `packet-up`**: the
  drag-and-drop Pages target cannot hold cross-request state, so the JS build gets WebSocket and
  `stream-one` only. The README must say this plainly.

---

## 4. Environment and toolchain

Machine-specific and deliberately **not** in the repo. Recorded here because rediscovering it costs
an hour.

- **Rust toolchain**: `stable-x86_64-pc-windows-gnullvm`, plus the `wasm32-unknown-unknown` target.
  This host was chosen because the machine has no Visual Studio and no linker; `gnullvm` links with
  Rust's own bundled `rust-lld`.
- **Linker override** lives in the machine-global `~/.cargo/config.toml` (never the repo — it
  contains a user path). The `gnullvm` host defaults to invoking `x86_64-w64-mingw32-clang`, which
  is not installed; the toolchain does ship `rust-lld` plus a `self-contained` directory of mingw
  CRT objects, so the override sets `linker = rust-lld` with `-Clinker-flavor=ld.lld` and
  `-Clink-self-contained=y`. Note `gnu-lld` is **nightly-only**; `ld.lld` is the stable equivalent.
- **That `self-contained` set is incomplete.** It lacks `libadvapi32.a`, `libole32.a` and
  `liboleaut32.a`, so any crate whose *build script* pulls in the `cc` crate fails to link. This is
  why the `blake3` crate cannot be used and a dependency-free BLAKE3 is being written instead. Any
  future dependency with a C-building build script will hit the same wall.
- **Network**: if the build machine sits behind a TUN-mode proxy with fake-IP DNS — hostnames
  resolving into `198.18.0.0/15` or `fc00::/18` rather than to real addresses — then `rustup` and
  `cargo` may hang. Their HTTP client stalls on the synthetic IPv6 record with no fallback, while
  tools that use the OS resolver succeed, which makes it look like an intermittent network fault.
  Setting `HTTPS_PROXY` and `HTTP_PROXY` to the local proxy's own address bypasses DNS entirely and
  resolves it. Symptom to recognise: repeated timeouts fetching even a small file, from more than
  one host, while ordinary browsing works.
- **The same fake-IP DNS breaks proxy-core clients too, and looks like a server bug.** A core
  resolving the deployment hostname gets a synthetic address, dials it, and receives the local
  proxy's own error page. To the client that is a protocol violation — Xray reports
  `unexpected response version. Expecting 0 but actually 60`, and `60` is `0x3C`, the `<` of an HTML
  page. Every protocol fails at once, including ones already proven, which is the tell that it is
  environmental. Fix for testing: resolve the hostname out of band (DNS-over-HTTPS) and point the
  client's `address` at a real edge IP while leaving `serverName` and the transport `host` set to the
  hostname. That is the same clean-IP mechanism the panel exposes as a feature.
- **Core binaries for testing** are supplied by the operator and live outside the repo. Copy them to
  a temp directory before use. Their path must never appear in any committed file. Versions in use:
  Xray v26.6.1, sing-box v1.13.13, mihomo v1.19.25 (XHTTP requires ≥ v1.19.22).
- **Git identity** is configured repo-locally. Commits carry no AI attribution, by instruction.

---

## 5. Working agreements

- `.gitignore` covers `.claude/` because agent worktrees are created inside the repo. **`git add -A`
  is not safe** while background agents are running; stage explicitly or verify what was staged.
- Every commit is preceded by a scan for tokens, machine paths, usernames, emails and the local
  proxy address. History has been audited end to end and is clean.
- Modules stay small and single-responsibility, by request.
- Work that is genuinely independent gets parallelised across agents in isolated worktrees, with
  distinct roles (build / review for correctness and security / simplify). Anything depending on an
  unfinished piece stays sequential — the Durable Object and Worker entry were built together for
  exactly this reason, being two halves of one interface.
- Review findings are adversarially verified before being acted on, defaulting to refutation.

---

## 6. Immediate next actions

1. **Panel UI** — the remaining half of Stage 3. Simple default view, deep advanced surface,
   conflict-aware controls driven by `config::conflicts`, QR codes, one-click copy. The backend it
   needs is in place: [`panel::auth`] issues and verifies sessions, [`panel::store`] persists nodes,
   and `Route::Panel` is still wired to the decoy pending the UI itself. A `PANEL_PASSWORD` secret
   binding needs adding to the deploy script at the same time.
2. **Stage 5 measurements**: obfuscation on/off delta, sustained throughput, cold start.
3. Then the wizard (Stage 7), `SETUP.md` (Stage 8), the pre-push audit and publish (Stage 9), and
   the standalone `worker.js` (Stage 10).
