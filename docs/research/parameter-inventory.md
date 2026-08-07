# Cross-Core Parameter Inventory

The specification the translation layer is built from. Targets **Xray v26.x**,
**sing-box v1.13**, **mihomo v1.19.22+**. Every row was verified against upstream source or
official documentation; entries that could not be confirmed are marked `?`.

Legend: ✅ supported · ❌ absent (untranslatable) · ⚠️ supported with a caveat in the notes.

---

## 1. Protocols

| Protocol | Xray | sing-box | mihomo | Notes |
|---|---|---|---|---|
| VLESS | ✅ | ✅ | ✅ | |
| VMess (AEAD) | ✅ | ✅ | ✅ | Xray **removed `alterId`** entirely — AEAD only. sing-box/mihomo still accept the field; emit `0`. |
| Trojan | ✅ | ✅ | ✅ | Xray **hard-errors** on any non-empty `flow` for Trojan: `Flow for Trojan` is a removed feature. |
| Shadowsocks (AEAD) | ✅ | ✅ | ✅ | |
| Shadowsocks 2022 | ✅ | ✅ | ✅ | See §5. |
| WireGuard | ✅ outbound | ✅ `endpoints[]` | ✅ proxy | sing-box moved this to `endpoints` in 1.11; the legacy outbound still works in 1.13 with a warning. |
| Hysteria2 / TUIC | ✅ (v26 `hysteria`) | ✅ | ✅ | UDP-native — **cannot be served by a Worker**, client-side only. |
| AnyTLS | ❌ | ✅ | ✅ | Needs raw TLS termination; not CDN-compatible. |

## 2. Transports — the decisive table

| Transport | Xray | sing-box | mihomo | Servable on a Worker? |
|---|---|---|---|---|
| **XHTTP / SplitHTTP** | ✅ `xhttp` | **❌ never, any version** | ✅ `network: xhttp` since **v1.19.22**, **VLESS only** | ✅ `packet-up`; `stream-up`/`stream-one` probe-gated |
| WebSocket | ⚠️ `ws` — **soft-deprecated in v26** | ✅ `ws` | ✅ `network: ws` | ✅ |
| gRPC | ⚠️ `grpc` — **soft-deprecated in v26** | ✅ `grpc` | ✅ `network: grpc` | ❌ — both `gun` and `multi` are bidirectional streams needing full-duplex HTTP/2 |
| httpupgrade | ⚠️ **soft-deprecated in v26** | ✅ | ✅ via `ws-opts.v2ray-http-upgrade: true` | ❌ — a Worker cannot emit a bare `101` or obtain the raw post-101 socket |
| HTTP/2 (`h2`) | **hard-removed 2024-12** | ✅ `http` | ✅ `h2` | ❌ |
| QUIC | **hard-removed 2024-09** | ✅ `quic` | ❌ | ❌ — UDP |
| mKCP | ⚠️ `header`/`seed` now **hard-error** | ❌ | ⚠️ VMess only (v1.19.28+) | ❌ — UDP |
| TCP + header obfs | ✅ `raw` (was `tcp`) | ❌ | ✅ `tcp` | n/a |

Xray v26 emits deprecation warnings for `ws`, `grpc` and `httpupgrade`, recommending XHTTP in
each case. Upstream is actively steering the ecosystem toward XHTTP — which independently
validates making it this project's default rather than a bolt-on.

**sing-box + XHTTP is the single most important gap in the matrix.** A source grep of the
v1.13.0 tree for `xhttp|splithttp` returns zero hits; `option/v2ray_transport.go` switches on
exactly five constants (`http`, `ws`, `quic`, `grpc`, `httpupgrade`) and returns
`unknown transport type` otherwise. `transport/` contains `v2ray{grpc,grpclite,http,httpupgrade,quic,websocket}`
and no `v2rayxhttp`. PRs #3879 and #4326 were both **closed unmerged with zero comment**, and
issues #2525 and #3550 have been **deleted** — there is no written maintainer rationale
anywhere, only a consistent pattern of silent closure. An XHTTP node **must fail loudly** when
an upstream sing-box config is requested. The claim circulating online that `type: "http"` +
`alpn: ["h3"]` is a near-equivalent is wrong; sing-box's `http` transport is H1/H2 only and has
no packet-up semantics.

**But "sing-box-based" does not imply "no XHTTP".** Several downstream clients ship patched
forks that add `transport/v2rayxhttp`: `hiddify/hiddify-sing-box`, `KaringX/sing-box`,
`shtorm-7/sing-box-extended`, `Leadaxe/sing-box-lx` (behind a `with_xhttp` build tag). This
distinction is invisible if you treat "sing-box" as one target, and it is why the client target
table in §2.1 is separate from the core table above.

### 2.1 Client targets — who can actually import an XHTTP node

The subscription layer targets *clients*, not cores, and the mapping is not one-to-one.

| Client | XHTTP | Executed by | Since |
|---|---|---|---|
| v2rayN | ✅ | **Xray-core only** — its sing-box config builder hard-rejects `xhttp` | 7.1.0 (2024-11) |
| v2rayNG | ✅ | Xray-core (no sing-box bundled) | 1.9.17 (2024-11) |
| **Hiddify** | ✅ | **patched `hiddify-sing-box` fork**, not upstream | v4.0.4 (2026-02) |
| Karing | ✅ | patched `KaringX/sing-box`; no Xray in the org | v1.2.9 (2025-12) |
| Throne (NekoRay successor) | ✅ | Xray-core as a side process; its sing-box fork has none | 2025-12 |
| mihomo / Clash Meta | ✅ | native, VLESS only | v1.19.22 (2026-04) |
| NekoBox for Android | ❌ | upstream sing-box only; maintainer declined | — |
| NekoRay | ❌ | archived 2024-12; 3.26 ships pre-XHTTP Xray | — |

**Emission consequence.** An XHTTP node is valid for the v2rayN/v2rayNG (Xray JSON), Hiddify
(sing-box JSON), Karing and mihomo targets, and invalid for a *generic upstream* sing-box JSON
download. The panel therefore treats "sing-box" and "Hiddify" as **distinct export targets**
rather than aliases — Hiddify carries XHTTP, generic sing-box refuses it with an explanation.
No other panel makes this distinction.

## 3. XHTTP parameters (Xray ⇄ mihomo)

Xray `xhttpSettings` ⇄ mihomo `xhttp-opts`, camelCase ⇄ kebab-case. Most numeric-looking
fields are **strings** carrying range syntax (`"100-1000"`).

| Xray | mihomo | Default | Side | Meaning |
|---|---|---|---|---|
| `path` | `path` | `/` | both | base path |
| `host` | `host` | — | both | Host header / server validation |
| `mode` | `mode` | `auto` | both | `packet-up` \| `stream-up` \| `stream-one` |
| `xPaddingBytes` | `x-padding-bytes` | `100-1000` | both | cannot be disabled |
| `xPaddingKey` | `x-padding-key` | `x_padding` | both | v26 obfuscation layer |
| `xPaddingPlacement` | `x-padding-placement` | `queryInHeader` | both | `queryInHeader`\|`cookie`\|`header`\|`query` |
| `scMaxEachPostBytes` | `sc-max-each-post-bytes` | `1000000` | both | server answers **413** if exceeded |
| `scMinPostsIntervalMs` | `sc-min-posts-interval-ms` | `30` | client | min gap between uplink POSTs |
| `scMaxBufferedPosts` | — | `30` | **server** | reorder-buffer depth |
| `scStreamUpServerSecs` | — | `20-80` | **server** | keepalive padding on the stream-up uplink |
| `xmux.*` | `reuse-settings.*` | see below | client | connection/request multiplexing |
| `downloadSettings` | `download-settings` | — | client | separate transport for the downlink |

`xmux` defaults, injected by Xray when the object is absent entirely: `maxConnections=6`,
`hMaxRequestTimes=600-900`, `hMaxReusableSecs=1800-3000`. `maxConcurrency` and `maxConnections`
are **mutually exclusive** — setting both is a build error.

**Removed field:** top-level `keepAlivePeriod` existed only in Xray v24.11.30 and was deleted.
Its replacement is `xmux.hKeepAlivePeriod`. Configs still emitting the old name — including
cfxhttp's — are stale.

### packet-up wire protocol (what the Worker must implement)

- Downlink: `GET <path>/<sessionId>` → `200` with `X-Accel-Buffering: no`,
  `Cache-Control: no-store`, `Content-Type: text/event-stream` (unless `noSSEHeader`), header
  flushed immediately, then the response body streams downstream data.
- Uplink: `POST <path>/<sessionId>/<seq>`, `seq` from `0`, body = raw payload. Each answers
  `200` with an empty body. The server reorders by `seq` into a buffer of `scMaxBufferedPosts`.
- Padding: client sends `Referer: <full-url>?x_padding=XXXX…`. The server validates the length
  against its configured range and returns **400** if out of range. Server responses carry
  their own `X-Padding`.
- `OPTIONS` → immediate `200`. Path prefix mismatch or Host mismatch → `404`.
- Server-side upload/download discrimination: `GET` with a `seq` component ⇒ uplink;
  `GET` without ⇒ downlink; any other method ⇒ uplink; empty session ⇒ stream-one downlink.

## 4. Equivalence map — the same idea in three dialects

| Concept | Xray | sing-box | mihomo |
|---|---|---|---|
| **Proxy chaining** | `sockopt.dialerProxy` (preferred) or `proxySettings.tag` | `detour` | `dialer-proxy` |
| Transport container | `streamSettings.network` | `transport.type` | `network` |
| TLS enable | `streamSettings.security: "tls"` | `tls.enabled: true` | `tls: true` |
| SNI | `tlsSettings.serverName` | `tls.server_name` | `servername` (`sni` on Trojan) |
| Skip cert verify | ⚠️ `allowInsecure` **fatal after 2026-06-01** → use `pinnedPeerCertSha256` / `verifyPeerCertByName` | `tls.insecure` | `skip-cert-verify` |
| uTLS fingerprint | `tlsSettings.fingerprint` | `tls.utls.fingerprint` (needs `-tags with_utls`) | `client-fingerprint` |
| ALPN | `tlsSettings.alpn` | `tls.alpn` | `alpn` |
| REALITY pubkey | `realitySettings.password` (**was `publicKey`**) | `reality.public_key` | `reality-opts.public-key` |
| REALITY target | `realitySettings.target` (**was `dest`**) | `reality.handshake.server` | n/a (client only) |
| Multiplexing | `mux.{enabled,concurrency}` | `multiplex.{enabled,protocol,…}` | `smux.{enabled,protocol,…}` |
| UDP-in-TCP | XUDP (implicit) | `packet_encoding` (VLESS/VMess) · `udp_over_tcp` (SS/SOCKS) | `packet-encoding` / `xudp` |
| WS path | `wsSettings.path` | `transport.path` | `ws-opts.path` |
| WS early data | `wsSettings` (0-RTT via path) | `max_early_data` + `early_data_header_name` | `ws-opts.max-early-data` + `early-data-header-name` |
| gRPC service name | `grpcSettings.serviceName` | `transport.service_name` | `grpc-opts.grpc-service-name` |
| Outbound selector | routing `balancers` | `selector` / `urltest` outbound | `proxy-groups` |

### Defaults that differ and must be translated explicitly

- **`packet_encoding` in sing-box is tri-state.** Omitted/`null` ⇒ **xUDP enabled**; `""` ⇒
  disabled; `"xudp"`/`"packetaddr"` explicit. Omitting is *not* the same as empty string, and
  the default is the opposite of Xray's. Always emit it explicitly.
- **mihomo's VLESS default is xUDP**; `packet-addr` and `xudp` are mutually exclusive and
  auto-corrected in favour of xudp.
- **sing-box multiplex default protocol is `h2mux`**; mihomo's is also `h2mux`; Xray's mux is a
  different mechanism entirely and does not map field-for-field.

## 5. Shadowsocks ciphers and key format

| Cipher | Xray | sing-box | mihomo | Password format |
|---|---|---|---|---|
| `aes-128-gcm`, `aes-256-gcm` | ✅ | ✅ | ✅ | arbitrary UTF-8 (KDF-derived) |
| `chacha20-ietf-poly1305` | ✅ | ✅ | ✅ | arbitrary UTF-8 |
| `xchacha20-ietf-poly1305` | ✅ | ✅ | ✅ | arbitrary UTF-8 |
| `2022-blake3-aes-128-gcm` | ✅ | ✅ | ✅ | **base64 of exactly 16 bytes** |
| `2022-blake3-aes-256-gcm` | ✅ | ✅ | ✅ | **base64 of exactly 32 bytes** |
| `2022-blake3-chacha20-poly1305` | ⚠️ | ✅ | ✅ | base64 of 32 bytes — **rejected by Xray in multi-user mode** (aes-* only) |
| legacy stream (`aes-256-cfb`, `rc4-md5`, …) | ❌ removed | ⚠️ present | ✅ | do not emit |

**SS over WebSocket differs structurally per core.** Xray uses ordinary `streamSettings`.
sing-box's shadowsocks outbound has **no `transport` field at all** — the only path is
`plugin: "v2ray-plugin"` with `plugin_opts` as a **SIP003 semicolon string**
(`"tls;host=example.com;path=/ws"`), not JSON. mihomo likewise uses
`plugin: v2ray-plugin` + `plugin-opts.mode: websocket`. These are not interchangeable with a
VLESS/VMess/Trojan `transport` object — the framing differs.

## 6. Core-exclusive features

**Xray only:** `fragment` (TLS-record fragmentation) and `noises`; `streamSettings.finalmask`
(v26.3.27 — ports fragment/noise to *any* outbound); VLESS post-quantum `encryption`
(`mlkem768x25519plus.<native|xorpub|random>.<0rtt|1rtt>…`); server-side REALITY; `dokodemo-door`;
`xtls-rprx-vision-udp443` as a distinct flow value; routing `balancers` with `leastLoad`.

**sing-box only:** `endpoints` (bidirectional adapters — WireGuard, Tailscale); rule-set `.srs`
binary format; `udp_over_tcp` v1/v2 with its `sp.udp-over-tcp.arpa` magic address; kernel TLS
(`kernel_tx`/`kernel_rx`, Linux 5.1+); `v2ray` QUIC transport.

**mihomo only:** `ech-opts` on nearly every outbound; `restls-opts`, `jls-opts`, `tlsmirror-opts`,
`mekya-opts`; Snell v1–v5; `.mrs` binary rule-set format; proxy-provider `override` blocks with
`override-expr`; regex `filter`/`exclude-filter` on groups; `fake-ip-filter-mode: rule`;
`unified-delay`; `sub-rules`; exotic SS ciphers (aegis-128l, lea-*, rabbit128-poly1305).

## 7. Incompatibility matrix — enforced by the UI and the emitter

### Cross-core (translation-blocking)

| Combination | Verdict | Reason |
|---|---|---|
| XHTTP + sing-box target | **Untranslatable** | sing-box has no xhttp transport in any version. Fail loudly; never downgrade to `ws`. |
| XHTTP + VMess (mihomo) | **Invalid** | mihomo's `VmessOption` has no `XHTTPOpts` field — VLESS only. |
| gRPC / httpupgrade / h2 served by a Worker | **Impossible** | Requires full-duplex HTTP/2 or a raw post-101 socket. |
| Any UDP-native protocol as a Worker outbound | **Impossible** | No outbound UDP. |

### Xray

| Combination | Verdict | Reason |
|---|---|---|
| `flow=xtls-rprx-vision` + `security=none` | Hard fail | *"XTLS only supports TLS and REALITY directly for now."* |
| `flow=xtls-rprx-vision` + ws/grpc/xhttp/httpupgrade/mkcp | Non-functional | Vision needs raw TLS record access to splice; framing layers destroy record boundaries. |
| `flow=xtls-rprx-vision` + outer TLS < 1.3 | Runtime fail | Splice requires TLS 1.3. |
| `flow=xtls-rprx-vision-udp443` on an **inbound** | Hard fail | Outbound-only value. |
| VLESS without `encryption`/`decryption` | Hard fail | *"please add/set \"encryption\":\"none\" for every user"*. |
| `security=reality` + ws / httpupgrade / mkcp | Hard fail | REALITY is permitted only with `raw`/`tcp`, `xhttp`, `grpc`. |
| REALITY behind a CDN | Broken **and abusive** | The CDN terminates TLS, breaking REALITY's borrowed handshake; failed auth is then proxied to `target`, making the deployment an open relay. |
| `allowInsecure: true` | **Functional ≤ v26.1.13; hard config error from v26.2.2 onward** | Bisected against tags. Migrate to `pinnedPeerCertSha256` / `verifyPeerCertByName`. Xray's own TLS docs still call it merely "deprecated", which understates a hard failure. |
| `pinnedPeerCertificateChainSha256` | Hard fail | Removed in v26.1.23. |
| VLESS or Trojan + `security: none` + a **public** server address | **Hard config error** | *"vless without TLS or other encryption is prohibited unless the server address is a private IP or domain."* Bypassed only when VLESS `encryption` is set to a non-`none` post-quantum value. |
| VLESS **inbound** account carrying `encryption` | Hard fail | *"`encryption` should not be in inbound settings"* — the server-side counterpart is the sibling top-level `decryption` field. |
| VLESS `decryption` ≠ `"none"` together with `fallbacks` | Hard fail | *"`fallbacks` can not be used together with `decryption`."* |
| VLESS outbound `vnext[]` or `users[]` with more than one member | **Hard fail** | *"should have one and only one member. Multiple members … should use multiple VLESS outbounds and routing balancer instead."* Same restriction on Shadowsocks `servers[]`. |
| REALITY server omitting `minClientVer` | **Silently rejects old clients from ~v26.4 onward** | The default became `{26,3,27}`; clients older than v26.3.27 are refused with only a log warning. A config that worked under v25.x starts failing purely from a binary upgrade. |
| `mux.enabled` + `flow=xtls-rprx-vision` | **Not rejected — and partly load-bearing** | No gate exists at parse or runtime. Vision *requires* the Mux command path because it rejects bare UDP, auto-rewriting UDP targets to `v1.mux.cool`. Raising `concurrency` does defeat Vision's splice fast-path, so it is a throughput cost, not a functional break. |
| `mux` on freedom / wireguard / dns outbounds | Builds cleanly, **silently inert** | Those outbounds have no code path recognising the `v1.mux.cool` marker. |
| `network: h2` / `http` / `quic` / `domainsocket` | Hard fail | Transports removed in v26. |
| `security: "xtls"` | Hard fail | *"Legacy XTLS"*. |
| `fingerprint: "unsafe"` / `"hellogolang"` | Hard fail | Rejected values. |
| Trojan with any non-empty `flow` | Hard fail | *"Flow for Trojan"* is an explicitly removed feature. |
| 2022-blake3 cipher + wrong-length key | Hard fail | PSK must decode to exactly 16 or 32 bytes. |
| `xmux.maxConcurrency` + `xmux.maxConnections` | Build error | Mutually exclusive. |
| `proxySettings.tag` + `sockopt.dialerProxy` | Conflict | Documented mutual exclusion. |
| `proxySettings.tag` without `transportLayer: true` | **Silently degraded** | This outbound's `streamSettings` (TLS/ws/xhttp) is discarded during forwarding. |
| `fragment`/`noises` on a non-freedom outbound | Ignored | freedom-only pre-v26.3.27; use `streamSettings.finalmask` after. |
| `routing.domainMatcher`, `processName` | Removed/renamed | Gone in v26 (`process` replaces `processName`). |

### sing-box

| Combination | Verdict | Reason |
|---|---|---|
| `flow` + any `transport` | Invalid | Vision needs the raw TLS record stream. |
| `flow` + `multiplex` | Invalid | Vision requires one TLS connection per stream. |
| `multiplex` on socks/http/direct/hysteria/tuic/shadowtls/ssh | **Parse error** | Field absent; sing-box uses `UnmarshalDisallowUnknownFields`. Only ss/trojan/vless/vmess. |
| `udp_over_tcp` on vless/vmess/trojan | **Parse error** | Field absent — use `packet_encoding`. |
| `udp_over_tcp` + `multiplex` on shadowsocks | Conflict | Mux already carries UDP; UoT double-wraps. |
| `multiplex.max_streams` + `max_connections`/`min_streams` | Invalid | Mutually exclusive sizing policies. |
| `reality` or `utls` without `-tags with_utls` | **Runtime** failure | Config validates, dialing fails. Official release binaries include the tag; self-built `go build` defaults do not. |
| `-tags with_ech` on ≥1.12 | **Compile** failure | Tag deliberately removed after the stdlib migration; required on ≤1.11. |
| `packet_encoding` on trojan/ss | Parse error | VLESS/VMess only. |
| `packet_encoding: "packetaddr"` + domain destination | Runtime error | packetaddr encodes IPs only. |
| `geoip` / `geosite` rule items | Removed in 1.12 | Rewrite as `rule_set`. |
| `detour` set | **Silently nullifies** other dial fields | *"If enabled, all other fields will be ignored"* — `bind_interface`, `connect_timeout`, `domain_resolver` are dropped on that outbound. |
| `type: "block"` / `"dns"` / `"wireguard"` outbound | Deprecated, still works in 1.13 | Emit `action: "reject"` / `"hijack-dns"` / `endpoints[]`. |

### mihomo

| Combination | Verdict | Reason |
|---|---|---|
| ≥2 of `reality-opts`/`shadow-tls-opts`/`restls-opts`/`jls-opts` | **Fatal** | `security modes are mutually exclusive`. |
| Any security mode + `tls: false` | **Fatal** | `%s requires TLS`. |
| `flow` ≠ `xtls-rprx-vision` (and ≥16 chars) | **Fatal** | `unsupported xtls flow type`. Values under 16 chars are **silently ignored** — a real trap. |
| `flow` + ws/grpc/h2/http/xhttp | **Silently broken** | No error raised; Vision is only wired into the raw TCP+TLS path. |
| `xhttp-opts.mode: stream-one` + `download-settings` | **Fatal** | Explicit error in `vless.go`. |
| `network: xhttp` + HTTP/3 (`alpn: [h3]`) + any security mode | **Fatal** | `xhttp HTTP/3 does not support %s`; also requires TLS. |
| `grpc-opts.max-connections` + `max-streams`/`min-streams` | Conflict | Documented mutual exclusion. |
| `smux` on hysteria2/tuic/anytls | Accepted, harmful | No capability check — wraps anything. QUIC already multiplexes; adds head-of-line blocking. |
| `reality-opts` without a fingerprint | Legal but broken | uTLS needs a ClientHello ID; with neither `client-fingerprint` nor `global-client-fingerprint`, REALITY cannot complete. |
| `reality-opts` + anytls | Unsupported | No `RealityOpts` field on `AnyTLSOption`. |
| `format: mrs` + `behavior: classical` | **Fatal** | mrs supports domain/ipcidr only. |
| `proxy-groups` type `relay` | **Deprecated** | Docs: *"The relay strategy has been deprecated. Please use dialer-proxy."* Never supported UDP relay correctly. |
| Chaining a UDP-based or TLS-camouflage inner node | Documented broken | hy2/tuic/wg/reality/shadowtls do not relay correctly through `dialer-proxy`. |

## 8. Tuned defaults this project ships (and why)

Not core defaults — researched values, each with a stated cost.

| Parameter | Core default | Shipped | Reason |
|---|---|---|---|
| `mode` | `auto` | `packet-up` | `auto` resolves to `packet-up` without REALITY, but pinning it makes behaviour explicit and prevents an `auto`→`stream-one` flip if REALITY is ever configured. |
| `xPaddingBytes` | `100-1000` | `100-1000` | Kept. Padding is mandatory in XHTTP and the cost is already priced into the protocol. |
| `scMaxEachPostBytes` | `1000000` | `1000000` | Larger chunks mean fewer requests, and the free-plan **request count** is the binding limit, not bandwidth. |
| `scMinPostsIntervalMs` | `30` | `30` | Lowering it multiplies request count against the 100k/day cap for negligible latency gain. |
| `scMaxBufferedPosts` | `30` | `30` | Reorder depth; raising it costs isolate memory against the 128 MB limit. |
| `xmux.hMaxRequestTimes` | `600-900` | `600-900` | Kept — connection reuse reduces request count. |
| ALPN | `["h2","http/1.1"]` | `["h2"]` | h2 multiplexes XHTTP's parallel POSTs over one connection; offering http/1.1 invites a downgrade that serialises them. |
| Client heartbeat | none | 30–60 s | The client↔Cloudflare idle timeout is **400 s** and the WebSocket idle timeout is unpublished; Cloudflare's own docs prescribe a heartbeat. |
| Zone compression | on | **off** (documented step) | Auto-compression coalesces chunks and buffers streaming responses, adding 10+ s to TTFB. |

---

## 9. Emission rules — traps the emitter must encode

### 9.1 Xray renamed three keys 19 days ago; emit the *legacy* names

PR #6426 (2026-07-07, shipped in **v26.7.11**) renamed:

| Old key | New canonical key | Both accepted? |
|---|---|---|
| `network` | `method` | ✅ — `method` wins if both present |
| `tcpSettings` | `rawSettings` | ✅ — `rawSettings` wins |
| `splithttpSettings` | `xhttpSettings` | ✅ — `xhttpSettings` wins |

**Decision: emit `network`, `tcpSettings` and `xhttpSettings`.** The new names do not exist on
builds older than v26.7.11 — including the v26.6.1 binary used for this project's own test
suite, and including essentially every client currently in users' hands. The old names remain
parsed on current builds as undocumented aliases. `xhttpSettings` is the exception because it
has been accepted since late October 2024 and is what mihomo and v2rayN already expect.

Re-evaluate this once v26.7.x has propagated to the mobile clients.

### 9.2 Partially specifying `xmux` silently discards Xray's sane defaults

If `xmux` is omitted **entirely**, Xray injects `maxConnections={6,6}`,
`hMaxRequestTimes={600,900}`, `hMaxReusableSecs={1800,3000}`. If **any single** `xmux` field is
present, that whole bundle is skipped and every unspecified sub-field falls back to `{0,0}` —
meaning unlimited/disabled, not the sane default.

**Rule: emit `xmux` either fully populated or not at all. Never partially.**

### 9.3 `host` inside `headers` — three different behaviours

| Transport | `headers: {"Host": …}` |
|---|---|
| `xhttpSettings` | **Hard error** |
| `httpupgradeSettings` | **Hard error** |
| `wsSettings` | Deprecation warning; auto-promoted to the dedicated `host` field if that is empty |

**Rule: always use the dedicated `host` field; never place Host in `headers`.**

### 9.4 `extra` merge semantics

`xhttpSettings.extra` accepts a complete nested `SplitHTTPConfig`. When present it becomes the
effective config **except** that `host`, `path` and `mode` are always taken from the outer
object. Do not split related settings across the boundary.

**mihomo has no `extra` key at all** — the equivalent settings are flattened directly into
`xhttp-opts`. When translating Xray → mihomo, the emitter must merge `extra` into the parent
following Xray's own precedence rules before emitting, not pass it through.

### 9.5 sockopt casing — the docs are wrong, follow the code

Xray's own documentation writes `tcpcongestion` and `V6Only`; the Go struct tags are
`tcpCongestion` and `v6only`. Both work only because Go's JSON decoder falls back to
case-insensitive matching. A strict schema validator would reject the documentation's own
examples. **Emit the code-canonical spelling.**

`tcpNoDelay` no longer exists — Go enables TCP_NODELAY by default; use `customSockopt` to
disable it.

### 9.6 mKCP `header` and `seed` are now hard errors

They were relocated to `streamSettings.finalmask` (`type: "mkcp-legacy"`). Since mKCP is UDP and
therefore unusable on this runtime, the emitter simply refuses mKCP for Worker-served nodes and
only passes it through for user-supplied external chain hops.

### 9.7 Schema validation is not sufficient — validate by execution

Several failure classes are invisible to a JSON-schema check because they surface during core
*startup*, not during parsing:

- **Shadowsocks 2022 key length.** Xray passes `password` through as an opaque string with no
  length or base64 validation of its own; the check lives in the vendored `sing-shadowsocks`
  library and fires at service construction. A syntactically perfect config with a
  base64-looking key of the wrong decoded length parses fine and then hard-fails at start.
- **`flow=xtls-rprx-vision` against a non-TLS connection.** The rejection
  (*"XTLS only supports TLS and REALITY directly for now"*) is a runtime type assertion on the
  connection object, not a parse-time gate.
- **sing-box `reality`/`utls` without `-tags with_utls`.** The config validates; dialing fails.

**Rule: the validation stage runs each core binary against the generated config** — `xray run
-test`, `sing-box check`, `mihomo -t` — rather than relying on a schema model alone. A schema
model still runs first because it produces better error messages and needs no binary, but it is
a fast path, not the authority.

### 9.8 Multi-server is expressed by multiple outbounds, never by array members

Xray hard-errors on more than one member in VLESS `vnext[]`, `users[]`, or Shadowsocks
`servers[]`. Multi-node output must therefore emit one outbound per node plus a routing
balancer — which happens to match how sing-box (`selector`/`urltest`) and mihomo
(`proxy-groups`) express the same idea, so the internal model should carry a node list and let
each emitter expand it, never assume array-of-servers is portable.

### 9.9 WebSocket keepalive has a native field

`wsSettings.heartbeatPeriod` (uint32 seconds, default `0` = no ping, present since PR #4065,
2024-11-29) makes the client send WebSocket Pings. This is the correct mechanism for staying
under Cloudflare's unpublished WebSocket idle timeout — preferable to application-level
keepalive traffic, which is visible to traffic analysis. Set it when WebSocket is enabled.
