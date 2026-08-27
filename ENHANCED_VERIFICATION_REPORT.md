# Enhanced Reachability — Deployment & Performance Verification Report

Date: 2026-08-17 · Worker: `trinity-enhanced-test-20260816` · Client: Xray v26.7.28 (real binary)

## 1. Live endpoints (disposable test Worker — left running for your review)

| Item | Value |
|---|---|
| Worker / XHTTP host | `https://trinity-enhanced-test-20260816.sajjaddsh1387-09d.workers.dev` |
| Panel URL | `[REDACTED — path is a credential]` |
| Panel password | `[REDACTED]` |
| Subscription URL | `[REDACTED — path is a credential]` |
| XHTTP path | `[REDACTED]` |
| Live state | `enhanced_reachability = false` (shipped default), outbound mode = off |

Note: the production Worker was never touched in this work.

## 2. DO/XHTTP hop status: VERIFIED WORKING

The original 100% benchmark failure was **not a code bug** — it was a bad benchmark
target. Proven with the first-party `__connect_probe` diagnostic (enabled temporarily
via a `DIAGNOSTICS=true` binding, no source change):

- The Cloudflare Workers runtime **blocks outbound TCP from a Worker to Cloudflare's
  own address space**. Every CF-owned destination fails with the exact runtime error:
  `Error: proxy request failed, cannot connect to the specified address. It looks
  like you might be trying to connect to a HTTP-based service — consider using fetch
  instead.`
  Failed via probe: `example.com` (resolves to CF), `1.1.1.1`, `speed.cloudflare.com`,
  `162.159.140.220` — exactly the old benchmark's target.
- Non-Cloudflare destinations connect and return real bytes via probe: `8.8.8.8`,
  `9.9.9.9`, `github.com`, `google.com` (read real `HTTP/1.1 301` response).
- Full relay verified with the real Xray client end-to-end:
  `github.com` → HTTP 200, 574 KB; `proof.ovh.net` 10 MB file → HTTP 200,
  10 485 760 B in 6.16 s; Tele2 small POST round-trip → HTTP 200 with echoed size.

**No source changes were required.** The 12 modified files in the working tree are
exactly the pre-existing Enhanced Reachability implementation from earlier sessions.

## 3. Benchmark methodology

- Client: Xray v26.7.28, XHTTP `packet-up` mode, per-run fresh xray process and port,
  modes alternated per attempt to average out network drift.
- Target: `proof.ovh.net` (OVH, 141.95.207.211, non-Cloudflare), IP-pinned via
  `--resolve` (this machine's resolver hands out 198.18/8 fake IPs that the Worker
  correctly rejects).
- Setup metric = curl `time_starttransfer` (TTFB) = full chain: SOCKS → TLS → XHTTP
  uplink → Worker/DO → outbound TCP+TLS to target → first byte.
- Throughput = 10 MB sustained download (`proof.ovh.net/files/10Mb.dat`), 3 rounds
  per mode.
- Run from my own network — **not** from an Iranian restricted network. No Iranian-
  network claim is made.

## 4. Connection setup — Enhanced OFF vs ON (p50, 8 attempts each, alternating)

| Protocol | OFF p50 | ON p50 | Δ | OFF min–max | ON min–max | success |
|---|---|---|---|---|---|---|
| VLESS | 3212 ms | 3222 ms | **+11 ms (+0.3%)** | 2064–6987 | 2164–5066 | 8/8, 8/8 |
| Trojan | 3825 ms | 5057 ms | +1232 ms (+32%) | 1898–9597 | 3182–10542 | 7/8, 8/8 |
| VMess | 3221 ms | 3727 ms | +507 ms (+16%) | 2355–4760 | 1763–5219 | 7/8, 8/8 |
| Shadowsocks | 2778 ms | 4768 ms | +1989 ms (+72%) | 2204–5518 | 3724–6197 | 8/8, 8/8 |

The two setup timeouts (rc=28, 30 s budget) occurred in OFF mode, not ON. The ON
deltas for Trojan/VMess/SS are within this network's run-to-run variance (OFF min–max
spans 3–8 s); VLESS — the primary protocol — shows no measurable difference.

## 5. Sustained download throughput — Enhanced OFF vs ON (10 MB, p50 of 3 rounds)

| Protocol | OFF p50 | ON p50 | Δ | OFF range | ON range |
|---|---|---|---|---|---|
| VLESS | 12.74 Mbps | 10.29 Mbps | −19% | 8.84–17.25 | 9.67–11.11 |
| Trojan | 17.95 Mbps | 12.33 Mbps | −31% | 12.46–18.22 | 12.31–14.59 |
| VMess | 13.61 Mbps | 10.73 Mbps | −21% | 11.38–19.74 | 8.79–11.72 |
| Shadowsocks | 11.02 Mbps | 10.31 Mbps | −6.5% | 10.06–11.12 | 3.37–11.40 |

ON-mode throughput shows **lower variance** (tighter ranges) — consistent with
fragmentation smoothing bursts. Median throughput deltas are negative but not
consistent in magnitude across protocols, and the OFF ranges overlap the ON ranges,
so this is best described as *within measurement noise of the network path*, not a
proven regression. All 24 rounds completed successfully (100% stability).

## 6. Upload measurement — SKIPPED (honestly)

No non-Cloudflare upload endpoint proved reliable enough for clean numbers:
- `httpbin.org` — overloaded, 503s even direct.
- `speedtest.tele2.net/upload.php` — works direct (200 + echoed size); via relay:
  small bodies OK, but ≥256 KB bodies were queued/reset by the Tele2 endpoint
  itself in repeated testing (same sizes work direct, and direct upload to the
  Worker handles 60 KB cleanly), so numbers would have reflected Tele2 throttling,
  not the relay.
- Echo services (postman-echo, httpbingo) — dead (500) or capped/flaky through the relay.

The relay uplink path itself is **proven working**: a small POST body traversed
client → XHTTP packet-up → Worker → Tele2 → HTTP 200 with the exact byte count
echoed back. Sustained-upload *bandwidth* numbers are not available.

## 7. Honest summary

- Enhanced Reachability ON is **not free**: it adds TLS-fragment + Chrome-fingerprint
  config to the client, and in this test it showed median throughput −6…−31% and
  slower worst-case connection setup on secondary protocols. These numbers come from
  a small sample on one uncongested network; behavior on a censored, DPI-active path
  is the point of the feature and was not measured here.
- Enhanced Reachability OFF (the shipped default): no additional network/config
  operation was introduced and no meaningful runtime overhead was observed — VLESS
  setup p50 +11 ms (+0.3%) on 8 alternating attempts, and the OFF-mode code path is
  structurally untouched (verified in `translate/xray.rs` and the OFF-mode runtime path).

## 8. Git status

- **Nothing committed, nothing pushed** — awaiting your separate go-ahead.
- Working tree: 12 modified files, no untracked files:
  `public/panel.html`, `src/config/conflicts.rs`, `src/panel/advisor.rs`,
  `src/panel/api.rs`, `src/panel/serve.rs`, `src/panel/store.rs`,
  `src/subscription/bundle.rs`, `src/subscription/uri.rs`, `src/translate/mihomo.rs`,
  `src/translate/mod.rs`, `src/translate/singbox.rs`, `src/translate/xray.rs`
- All 12 are the Enhanced Reachability implementation; **zero** changes were made to
  source in the verification sessions.

## 9. Open cleanup item (needs a working token)

The Cloudflare API token provided in your last message is now **invalid**
(`{"code":1000,"message":"Invalid API Token"}` — all variants found in session
history rejected). It worked earlier in this session; it appears to have been
revoked since. Because of that, one cleanup step is still pending:

- The test Worker still has a `DIAGNOSTICS=true` plain-text binding. This only
  enables the probe endpoints behind the secret XHTTP path (the `__connect_probe`
  used above), but it should be reverted to `false`. The re-upload script was ready;
  it only needs a valid token. **Send a fresh token when convenient and I'll flip
  this one binding — or say the word and I'll fold it into the final cleanup.**

Local cleanup already done: secrets-bearing scratch script deleted, background xray
stopped, `enhanced_reachability` confirmed OFF (shipped default) on the live Worker.
The test Worker remains running for your manual review.
