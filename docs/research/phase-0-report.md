# Phase 0 — State of the Art, Runtime Constraints, and Design Decisions

Research date: 2026-07-26. Every claim below is tagged **[V]** (verified against primary
source — upstream code, official docs, or a running binary) or **[I]** (inferred, with the
reasoning given). Where two credible sources conflict, both are stated and the conflict is
called out rather than resolved by preference.

Core versions this project targets, matching the binaries used for testing:

| Core | Latest upstream | Targeted schema |
|---|---|---|
| Xray-core | v26.7.11 | **v26.x** |
| sing-box | v1.13.0 stable | **v1.13** |
| mihomo (Clash.Meta) | v1.19.29 | **v1.19.22+** |

---

## 1. Field survey — what exists, what it does well, what it lacks

Ten projects were read at source level, not just from their READMEs.

### BPB-Worker-Panel — 12.7k★, TypeScript, actively maintained
The best-engineered project in the field and the only one that is honest about its own
limits. It is the **only existing multi-core translation layer**: `src/cores/{xray,sing-box,clash}/`
each carry `configs/dns/outbounds/routing/inbounds`, unified through `src/cores/common.ts`,
so one panel state emits four client dialects. **[V]**

*Weak:* WebSocket is the only transport it serves. No XHTTP, no gRPC. Panel password is
stored **in plaintext** in KV — the FAQ tells users to recover a lost password by reading
the KV pair directly. **[V]** UDP is disabled outright. 100k requests/day ≈ 2–3 users.

### cmliu/edgetunnel — 41.1k★, single 305KB `_worker.js`
The centre of gravity of the whole field, and the most battle-tested. Genuinely implements
WS **and** XHTTP **and** gRPC server-side (`xhttpBridge` wraps a fake-WebSocket shim in a
`ReadableStream` Response). SOCKS5/HTTP chain proxy, preferred-IP APIs. **[V]**

*Weak:* the data path has **no per-user authentication** — one user reports 6 TB of traffic
stolen in two weeks. **[V]** Newly created panels now draw Cloudflare error 1011 almost
immediately; CF is actively targeting this codebase. Subscriptions are outsourced to an
external sub-converter, so config generation leaves the operator's control.

### itsyebekhe/nahan — 3.0k★
Excellent Persian UX, D1-backed (deliberately avoiding KV write limits), NAT64 IPv6 egress.

*Weak:* **default master key is `admin`**. 104 open issues, the worst signal in the survey.
It emits `udp: true` into its Clash YAML while `_worker.js` contains no UDP path at all —
it advertises a capability it cannot serve. **[V]**

### byJoey/cfnew — 14.6k★
Broadest subscription coverage anywhere (ten client dialects, own converter, no third party).
Live KV config reload without redeploy.

*Weak:* **ships deliberately obfuscated** — a GitHub Action transforms a 424KB plaintext
source into a 1.6MB blob, so users cannot audit the code that carries their traffic. **[V]**
Its "xhttp" has no `x_padding` handling and is not Xray-standard; its own Clash emitter
silently downgrades `network: xhttp` to `network: ws`. **[V]**

### IRNova/Nova-Proxy — 3.0k★
Strongest auth in the field (password + TOTP 2FA), five protocols, and the only **Xray-standard**
XHTTP detection (`referer.includes('x_padding')`). **[V]**

*Weak:* vendor lock-in is coded in — an in-source comment confirms a channel line is injected
into every subscription and is deliberately not overridable from panel, env, or KV. **[V]**
730KB bundle, effectively unauditable.

### ZEUS-PANEL (564★) · NiREvil/zizifn (81★) · eooce/Cloudflare-proxy (2.5k★) · arkanpay/cfxhttp (45★) · PdYrust/cf-xray-proxy (119★)
ZEUS has the best per-user quota model (GB/days/devices) but VLESS+WS only and emits no
Clash or sing-box configs at all. NiREvil is the field's only Rust/WASM project — but the
Rust is 4.4KB covering the VLESS header parser only; all I/O stays in JS. eooce is the
cleanest small multi-protocol worker and the best one to actually read, but is single-tenant
with a default password of `123456`. cfxhttp is the original XHTTP-on-Workers proof of
concept, abandoned since 2024, whose author's own README warns *"this script is very slow."*
cf-xray-proxy is the architectural outlier: it bridges to a real backend Xray, so UDP
actually works — at the cost of needing a VPS, which forfeits the serverless premise. **[V]**

### What the entire field is missing

1. **Real UDP.** Every self-contained worker hard-codes the identical pattern:
   `if (port === 53) isDns = true; else throw 'UDP is not supported'`. QUIC, HTTP/3, WebRTC,
   Telegram voice and game traffic are dead across all of them.
2. **Per-user auth on the data path.** This is how cmliu users lose terabytes.
3. **Conflict prevention — literally zero projects.** Not one panel rejects
   `flow=xtls-rprx-vision` with `network=ws` (impossible), or TLS-off with an SNI set, or
   XHTTP selected for a sing-box target (untranslatable). They are free-text toggle forms
   that cheerfully emit non-working configs. **This is the largest untaken opportunity.**
4. **Schema currency.** Xray's v25→v26 transition was schema-breaking. Every surveyed panel
   still emits v25-era configs. `allowInsecure: true` became a **fatal** error after
   2026-06-01; `pinnedPeerCertificateChainSha256`, `domainMatcher`, VMess `alterId`, and
   reality's `dest`/`publicKey` names were all removed or renamed. **[V]** Configs from these
   panels will hard-fail on a current Xray build.
5. **Tests.** Not one project in the survey has any.

---

## 2. Research Question A — can XHTTP and WebSocket coexist on separate paths?

**Yes, technically and trivially — but "same origin" is where the real risk lives, and it is
not a path-level problem.**

### Why it works mechanically

A Worker dispatches on the request itself, and the two transports are unambiguously
distinguishable before any protocol state exists:

- WebSocket arrives as `GET` with `Upgrade: websocket` + `Sec-WebSocket-Key`. The Worker
  answers with `new Response(null, {status: 101, webSocket: client})`.
- XHTTP arrives as `GET`/`POST` with **no** Upgrade header, carrying its session in the URL
  path and its padding in `Referer: …?x_padding=XXXX…`. **[V]**

There is no shared state, no negotiation, and no port contention — HTTP multiplexes both over
the same TLS connection to the same hostname. Routing `/{ws-prefix}/…` to the WebSocket
handler and `/{xhttp-prefix}/…` to the XHTTP handler is a single branch on
`headers.get('Upgrade')`, evaluated before path matching. Enabling one cannot alter the
other's on-wire bytes.

### Why "does not weaken the fingerprint" is the wrong question

The honest answer is that **path separation buys you nothing against the adversary that
matters.** A DPI system observing this deployment sees TLS to a Cloudflare anycast IP with
SNI = your hostname. It cannot see paths — they are inside the encrypted stream. What it can
do is classify the *traffic shape* of the connection, and if it decides the **hostname** is a
proxy endpoint, it blackholes the hostname. XHTTP on `/a/` dies with WebSocket on `/b/`.

So the coexistence risk is **shared fate at the SNI level**, not fingerprint contamination at
the path level. WebSocket is the most heavily fingerprinted transport in this space precisely
because every panel in Section 1 uses it; adding it to a domain that is otherwise serving
XHTTP hands a classifier its easiest signal on your hostname.

**Decision:** implement WebSocket, ship it **disabled by default**, and gate it behind a UI
warning that states the shared-fate mechanism in plain language rather than a vague "may be
detected." Offer per-hostname separation (WS on a different hostname than XHTTP) as the
supported way to actually get isolation, since that is the only boundary the adversary can
see. Document that enabling WS on the same hostname as XHTTP couples their survival.

---

## 3. Research Question B — outbound UDP, and what it really rules out

**Confirmed: the Workers/Pages runtime has no outbound UDP and no datagram API of any kind.**
`connect()` from `cloudflare:sockets` is TCP-only; the docs mention UDP nowhere, and
Cloudflare's own blog lists UDP and QUIC as roadmap items, not features. **[V]** Additional
hard restrictions: outbound TCP to **Cloudflare's own IP ranges is blocked**, port 25 is
blocked, and self-connection returns `TCP Loop detected`. **[V]**

### What this rules out

| Feature | Status | Reason |
|---|---|---|
| WireGuard/WARP **as a Worker outbound** | **Impossible** | WireGuard is UDP. There is no datagram API to speak it with. |
| Chained WARP (WoW) **through the Worker** | **Impossible** | Same, twice over. |
| QUIC / HTTP/3 to origin | Impossible | UDP transport. |
| Hysteria2, TUIC | Impossible | UDP-native protocols. |
| Client UDP traffic (WebRTC, game traffic, Telegram voice) | **Not forwarded** | No egress datagram path. |
| UDP DNS (port 53) | **Workaround only** | Resolve over DoH/DoT to a TCP endpoint. |
| gRPC transport (`gun` **and** `multi`) | **Blocked, but for a different reason** — see §4 | Both are declared `rpc Tun (stream Hunk) returns (stream Hunk)`; both need full-duplex HTTP/2. `multiMode` batches buffers per frame; it does not reduce duplex requirements. **[V]** |
| Xray `httpupgrade` transport | **Impossible** | A Worker can only construct a `101` response carrying a `webSocket` property; a bare 101 throws. Even then the edge frames the connection, and there is no API to obtain the raw post-101 socket. **[V]** |

### But WARP *is* still deliverable — and here is precisely why

The critical discovery is what BPB's WARP feature actually does. **Its Worker never speaks the
WireGuard protocol at all.** **[V]** The split is:

1. **Server side is HTTPS provisioning only.** The Worker generates an x25519 keypair and makes
   one ordinary `fetch()` to `https://api.cloudflareclient.com/v0a4005/reg`, extracting the
   assigned addresses, `client_id` (→ `reserved`), and peer public key. That is TCP/HTTPS — it
   works fine on Workers.
2. **The tunnel runs entirely on the client.** The Worker emits configs whose WireGuard
   outbound is executed by the *user's local* Xray/sing-box/mihomo. Traffic goes client →
   WARP endpoint over UDP **directly, bypassing the Worker completely.** This is exactly why
   BPB calls them "limitless Warp configs" — they consume none of the 100k/day request quota.
3. **WoW / chained WARP is client-side chaining of two registered accounts** — Xray
   `sockopt.dialerProxy`, sing-box `detour`, mihomo `dialer-proxy`. All three hops run locally.

**Decision:** implement WARP account provisioning (HTTPS + x25519 keygen, server-side) and
WARP/WoW **client config generation** for all three cores. Label it unambiguously in the UI
and docs as *client-side tunnelling* — the Worker provisions credentials and never carries
WARP traffic. Do **not** ship any toggle implying the Worker proxies WireGuard. This is a real,
working feature; it is simply not a Worker outbound, and every panel that blurs that distinction
is misleading its users.

---

## 4. The XHTTP mode question — an unresolved conflict, and how the design handles it

This is the single most consequential open question, and the research came back **contradictory
from two credible directions.** Both are recorded here rather than silently resolved.

**Position 1 — stream-one cannot work.** Cloudflare's HTTP proxy stack does not do full-duplex.
Kenton Varda (Workers tech lead): *"workerd itself supports full duplex even on HTTP/1.1, but
the rest of the Cloudflare HTTP proxy stack does not."* Tracking issues cloudflare/workerd#5027
and #6455 are open and unassigned. Returning a Response with the request body unconsumed throws
`Can't read from request stream after response has been sent` (workerd#1730). Xray issue #4359
reports stream-up failing through the CF CDN while packet-up works. **[V]**

**Position 2 — stream-one does work.** Upstream Xray discussion #4118 states plainly
「目前 Cloudflare 完美支持 stream-one 模式」 ("Cloudflare perfectly supports stream-one mode"),
with the precondition that **gRPC is enabled in the Cloudflare network panel**. cfxhttp itself
emits `"mode": "stream-one"` and performs concurrent request-body-read / response-body-write
via `TransformStream`. **[V]**

**The reconciliation that fits both sets of evidence [I]:** the missing full-duplex is about a
Worker acting as an outbound HTTP *client* (`fetch()` is half-duplex — that is what #5027 and
#6455 track), not about a Worker acting as an *origin*. A Worker that **terminates** the proxy
protocol and dials out with raw TCP `connect()` never re-proxies a duplex stream through
`fetch()`, and so is not blocked by that limitation. Consistent with this: cf-xray-proxy, which
*forwards* to a backend, documents xhttp support as `auto`/`packet-up` only — no stream-one. **[V]**
So: **terminating Worker → stream-one may work; forwarding Worker → packet-up only.**

This is empirically decidable and will not be settled by argument. Two consequences for the design:

- **`packet-up` is the guaranteed path and the default.** It requires no duplex anywhere:
  downlink is `GET <path>/<session>`, uplink is a series of `POST <path>/<session>/<seq>` with
  a server-side reorder buffer. Upstream now describes its throughput as "very close to
  stream-up/one." **[V]**
- **The panel ships a live duplex self-test.** The Worker exposes a diagnostic endpoint that
  determines, on the actual deployment, whether the edge in front of *this* hostname delivers
  request-body bytes before client EOF. `stream-one` and `stream-up` are then offered as
  **probe-gated** options — enabled in the UI only where measurement says they work, with the
  measured result shown. No other panel measures this; they all guess.

### Additional hard runtime limits that shape the design **[V]**

- **Runtime updates are the real connection killer.** Cloudflare updates the Workers runtime
  a few times per week and gives in-flight requests a **30-second grace period**, then
  terminates them. Client reconnect logic is mandatory, not optional.
- **Client↔Cloudflare idle timeout is 400 s**, not configurable, and closes the TCP connection
  with no HTTP status. WebSocket idle timeout is real but **unpublished**; Cloudflare's own docs
  prescribe a client heartbeat. The widely-repeated "100 s" figure is community folklore and
  appears in no Cloudflare document.
- **Auto-compression breaks streaming** by coalescing chunks into buffered payloads. Compression
  must be off for the proxy hostname.
- Free plan: 10 ms CPU per request, 100k requests/day, 50 subrequests. CPU excludes I/O wait,
  so a mostly-idle relay is cheap — but the daily request cap is what limits user count, and
  `packet-up` spends one request per uplink chunk.

---

## 5. Deployment target — Workers with Static Assets, not Pages Functions

Two findings force the target away from Pages. Both are verified against Cloudflare's own
documentation, and together they are decisive.

### 5.1 XHTTP `packet-up` requires a Durable Object, and Pages cannot define one

`packet-up` splits one logical connection across separate HTTP requests: a long-lived `GET`
downlink and a series of `POST` uplinks. The outbound TCP socket must therefore outlive the
request that created it — and on this runtime, exactly one construct can do that.

- *"TCP sockets cannot be created in global scope and shared across requests. You should always
  create TCP sockets within a handler."* Cross-request use raises
  `Cannot perform I/O on behalf of a different request`. **[V]**
- Module-global state is explicitly ruled out: *"This causes cross-request data leaks, stale
  state … Never in module-level variables."* There is no isolate affinity guarantee and no
  intra-isolate messaging mechanism. **[V]**
- KV is eventually consistent with propagation *"up to 60 seconds or more"*; the Cache API
  stores only `Response` objects. Neither can hold a live socket — only serialised bytes. **[V]**
- A Durable Object can: one instance serves all requests for its ID and keeps in-memory state
  between them. Since 2026-06-19 an active `connect()` socket even keeps the DO alive for up to
  15 minutes. **[V]**

And Pages cannot host one: *"You must create a Durable Object Worker and bind it to your Pages
project … **You cannot create and deploy a Durable Object within a Pages project.**"* The
feature request (`workers-sdk#3050`) is **closed as not planned**. **[V]**

### 5.2 The premise behind "target Pages, not Workers" does not hold

The stated reason for preferring Pages was that it handles long-lived duplex streaming more
reliably. It does not: Pages Functions and Workers run the **identical runtime behind the
identical edge path**, and Cloudflare publishes no separate limits page for Pages Functions
because it inherits Workers' limits unchanged. **[V/I]** There is no streaming behaviour
available to one and not the other.

Meanwhile Cloudflare has been steering new projects the other way since 2025-04-08: *"Now that
Workers supports both serving static assets and server-side rendering, you should start with
Workers … all of our investment, optimizations, and feature work will be dedicated to improving
Workers."* The docs are blunter: *"If you are starting a new project, use Workers instead of
Pages."* **[V]**

### 5.3 Workers + Static Assets also gives a *better* no-CLI path

This is the point that matters most for the "I am not a terminal user" requirement.
**Pages has no public REST API for asset upload** — only a config `PATCH`. A wizard therefore
cannot automate a Pages deployment end to end. Workers has a documented three-step REST flow:

1. `POST /accounts/{acct}/workers/scripts/{script}/assets-upload-session` with a file manifest →
   returns a JWT and bucket list.
2. `POST /accounts/{acct}/workers/assets/upload` with the file parts → returns a completion token.
3. `PUT /accounts/{acct}/workers/scripts/{script}` — multipart metadata carrying `main_module`,
   the `.wasm` module part, **the Durable Object binding, and the migration** in one call. **[V]**

Durable Object migrations must use `new_sqlite_classes`; since 2026-07-09 the KV-backed
`new_classes` form fails outright on accounts without a pre-existing KV-backed namespace. **[V]**

### 5.4 Resulting deployment matrix

| Path | Carries | Terminal? |
|---|---|---|
| **Setup wizard → Workers + Assets (primary)** | Full Rust/WASM build, Durable Object, static panel assets | **No** — pure REST against the Cloudflare API |
| **Dashboard drag-and-drop → Pages** | Pure-JS single-file `_worker.js`, WebSocket and `stream-one` only | **No** — but no `packet-up`, since Pages cannot host the DO |
| **wrangler** | Full build | Yes — developer path |

Deliverable **C** (the standalone `worker.js`) is therefore not a consolation prize: it is what
makes the drag-and-drop path real, and its honest limitation is not the language but the
**absence of `packet-up`**, because the platform it lands on cannot hold cross-request state.

Free-plan Durable Objects (available since 2025-04-07, SQLite-backed) allow 100,000 requests and
13,000 GB-s per day. Since `packet-up` spends one DO request per uplink chunk, the daily request
quota — not bandwidth — remains the binding limit on user count. **[V]**

### 5.5 A Rust/WASM build still cannot be deployed by dashboard drag-and-drop

**[V]**

Cloudflare Pages direct upload accepts `_worker.js` as a **single file** only. The
`_worker.js/` *directory* form — the only form that can carry a sibling `.wasm` module — is
implemented in wrangler's client-side bundler (`lstatSync(...).isDirectory()` → bundle →
upload one `_worker.bundle` field), not in the dashboard. The dashboard does no bundling, so a
dragged `_worker.js/` folder is ingested as ordinary static assets and the Worker never
initialises. **[V]**

This is a second, independent reason the drag-and-drop path carries the JavaScript build rather
than the Rust one, and it holds regardless of §5.1–5.3. The wizard's REST flow (§5.3 step 3)
uploads the `.wasm` as a module part in the same multipart request as the script, which is the
mechanism wrangler itself uses — so the full build reaches Cloudflare without a terminal, just
not by dragging a folder into a browser.

---

## 6. Design decisions

Each of these is chosen against a specific, named gap in Section 1.

1. **XHTTP `packet-up` as the default transport, WebSocket off by default.** Beats: everyone —
   the field is ~90% WebSocket-only, which is why WS is the most classified transport in it.
2. **Probe-gated `stream-one`/`stream-up` with a live duplex self-test.** Beats: everyone —
   no project measures the runtime's actual duplex behaviour; cfnew ships a "xhttp" that is not
   Xray-standard at all.
3. **Compile-time-enforced conflict prevention.** The parameter model encodes incompatibilities
   as data (see `parameter-inventory.md`), the UI disables invalid combinations inline with the
   reason, and the emitter refuses to produce a config that violates one. Beats: **all ten** —
   zero projects do any of this.
4. **v26-current schema, with an explicit compatibility mode.** Emit `pinnedPeerCertSha256`,
   reality `target`/`password`, no `alterId`, no `domainMatcher`. Beats: **all ten** — every
   surveyed panel emits configs that now fail on current Xray.
5. **Honest per-*target* degradation, surfaced in the UI.** XHTTP → Xray ✅, mihomo ✅
   (v1.19.22+, VLESS only), **upstream sing-box ✗ — untranslatable, fail loudly.** sing-box has
   never supported XHTTP in any version; a source grep of the v1.13.0 tree returns zero hits,
   both contributed PRs were closed unmerged without comment, and the two request issues have
   been deleted, so no maintainer rationale exists in writing. **[V]** The panel says so rather
   than silently downgrading to WebSocket the way cfnew does.

   The refinement other panels miss: **"sing-box-based client" ≠ "no XHTTP".** Hiddify and
   Karing ship *patched* sing-box forks carrying `transport/v2rayxhttp`, and v2rayN executes
   XHTTP through bundled Xray while its own sing-box builder rejects it. **[V]** So the export
   layer targets **clients, not cores**, and Hiddify is a distinct target from generic sing-box
   — it can carry XHTTP where the upstream download cannot. See §2.1 of the parameter inventory.
6. **Per-user authentication on the data path.** Beats: cmliu (6 TB stolen), and the general
   absence of it everywhere else.
7. **Hashed panel credentials from a secret binding.** Beats: BPB (plaintext password in KV),
   nahan (`admin`), eooce (`123456`).
8. **WARP correctly labelled as client-side.** Beats: the general blurring of where the tunnel runs.
9. **Auditable source, no obfuscation, real tests.** Beats: cfnew (1.6MB obfuscated blob),
   Nova (730KB bundle with coded-in lock-in), and the entire field on testing.
10. **Rust/WASM for the data path — with the honest caveat** that the bottleneck on this
    platform is Cloudflare's `connect()` and the request quota, not header parsing. The win is
    exhaustive `Result` handling and no panics in a WASM isolate, not raw speed. NiREvil's
    project is the only prior Rust attempt and it left all I/O in JS.

---

## 7. Open items carried into implementation

- Duplex behaviour must be **measured** on a real deployment before `stream-one` is offered
  anywhere except behind the probe (§4).
- Whether Cloudflare's 2026-01 `request_body_buffering: none` Configuration Rule also un-buffers
  the *Worker* leg (as opposed to only the origin leg) is unverified, and it is zone-only —
  unavailable on `*.workers.dev` / `*.pages.dev`. **[I]**
- Whether the account's token carries the permissions the wizard needs cannot be read from
  `/user/tokens/verify`, which returns only `{id, status}`. Scope must be probed by attempting
  the actual API calls.
