# Trinity Panel — Project State Report (2026-08-27)

Snapshot of everything verifiable in this tree as of today. Every number is
attributed to the file it came from; nothing here is reconstructed from memory.

---

## 1. Identity

**Trinity Panel** — an XHTTP-first proxy panel for Cloudflare Workers, written in
Rust and compiled to WebAssembly. One configuration model in, Xray / sing-box /
mihomo configs out, with per-client (not per-core) conflict reporting. Default
transport is XHTTP `packet-up`; WebSocket exists but is off by default as a
deliberate anti-classification position.

- Repo: `https://github.com/Osajjad0/trinity-panel.git`
- Local tree: `C:/Users/alma/Desktop/panel 2` (note the space in the folder name)
- License file: none committed (flag if publishing is intended)

## 2. Repository state

| Item | Value | Source |
|---|---|---|
| Branch | `main` | `git branch` |
| HEAD | `2b10d37` (2026-08-26) | `git log` |
| vs origin | **13 commits ahead**, not pushed | `git log origin/main..HEAD` |
| origin/main | `1eb0f3d` — "Add optional Proxy IP and NAT64 outbound fallback" (2026-08-16) | git |
| Latest tag | `v0.1.0` on `3962810` (2026-08-07, the rebrand commit) | git |
| Working tree | 90 untracked entries; clean otherwise | `git status --porcelain` |

The 13 unpushed commits are the entire Aug 25–26 crisis-and-fix campaign
(§5–§7). **If this machine dies, two days of measured work is lost.** Pushing is
the single highest-value next action, after deciding which of the untracked
files belong in the repo (§12).

### Commit timeline (all of it, 16 commits)

| SHA | Date | Subject |
|---|---|---|
| `8e2c57f` | 08-07 | Initial commit: XHTTP-first multi-protocol proxy panel |
| `3962810` | 08-07 | **v0.1.0** — rebrand to Trinity Panel; README, INSTALL, known issues |
| `1eb0f3d` | 08-16 | Optional Proxy IP and NAT64 outbound fallback ← *origin/main* |
| `e4ccadf` | 08-25 | Tooling: remove node-wiping bench paths, protect prod artifacts |
| `7dae714` | 08-25 | Checkpoint: audited optimization set (idle timeout, coalescing, chunking, enhanced reachability) — +1514/−294 across 21 files |
| `e98b906` | 08-25 | Bound the single-candidate dial handshake at 5 s |
| `0419999` | 08-25 | Last-known-good Proxy IP preference (order_plan + debounced teardown record) |
| `61d3794` | 08-25 | Supervised teardown state machine |
| `806f7e5` | 08-25 | Bounded header-phase deadlines (10 s / 4 s / 15 s) |
| `4576458` | 08-25 | Optimistic-concurrency save (`rev`, `expected_rev`, conflict refusal) |
| `42963a3` | 08-25 | Docs: sync KNOWN_ISSUES with measured reality (DO quota outage) |
| `625a5c8` | 08-25 | Fully de-KV `bench_beforeafter` (read-only observe) |
| `6ad7348` | 08-25 | Port-scope the LKG preference (measured 5 s cross-port penalty) |
| `0d4b86b` | 08-26 | EOL sessions answer 404; single teardown finalizer; LKG demotes failed preference |
| `63c1871` | 08-26 | Drop 30 ms uplink POST pacing (measured 4.7× upload gain) |
| `2b10d37` | 08-26 | Pin inbound routing to primary node (roundRobin removed) ← HEAD |

## 3. Architecture

~19,570 lines of Rust across 52 files; `cargo test` (2026-08-27): **483 passed,
0 failed** on the host in ~25 s. (README said 369 — fixed in the same pass.)

```
src/
├─ protocol/      inbound parsers (VLESS, Trojan, VMess, SS-2022) — pure, no I/O
├─ transport/
│   ├─ xhttp/     wire (classify), session (UploadQueue reorder),
│   │             durable (DO socket owner), supervise, deadlines, diag
│   ├─ websocket  compiles only; never enabled (security position)
│   └─ decoy      identical page for every negative outcome
├─ relay/         mod (pump, MAX_WRITE/MAX_BUFFER), connect (preflight refusal),
│                 outbound (Proxy IP / NAT64 dial plans), outbound_state (LKG)
├─ translate/     xray / singbox / mihomo emitters + shared gate
├─ core_schema/   typed models of each core's config schema
├─ panel/         auth, api, advisor (UI pre-blocks broken values), serve, store
├─ subscription/  uri (share links), bundle (per-client rendering), encode
├─ config/        env (binding parsing), model, conflicts (the matrix)
├─ router.rs      pure (method, path) → Route; host-tested
└─ entry.rs       thin fetch handler; errors fall back to decoy
```

Compile-time posture: `#![forbid(unsafe_code)]`; `unwrap`/`expect` denied by
lint on request paths (tests exempt). `worker` crate 0.8.5 is wasm32-only, so
the whole protocol/wire/conflict layer tests on the host.

Key runtime constants (verified in source):

| Constant | Value | Location | Purpose |
|---|---|---|---|
| `MAX_WRITE` | 32 KiB | relay/mod.rs:129 | sliced socket writes (regression-tested) |
| `MAX_BUFFER` | 512 KiB | relay/mod.rs | per-connection cap — isolate memory guard |
| `DOWNLINK_BUFFER` | 64 KiB | xhttp/durable.rs:94 | was 16.5 KiB; ~640→160 reads per 10 MB |
| `COALESCE_WINDOW_MS` | 3 ms | xhttp/durable.rs:105 | burst reads flush once; ~260 sends/MB → a few |
| header deadlines | 10 s first / 4 s later / 15 s total | xhttp/deadlines.rs | kills slowloris-style header dribble |
| `HANDSHAKE_TIMEOUT_SECS` | 5 s | relay/connect.rs:86 | single-candidate dial bound |
| `MAX_PROXY_ATTEMPTS` | 8 (default 3) | relay/outbound.rs | retry-storm cap |
| UploadQueue | mirrors Xray `scMaxBufferedPosts` (30), lookahead 4× | xhttp/session.rs | seq reordering, duplicate drop |
| idle teardown | 60 s true-idle | KNOWN_ISSUES §0 | DO lifetime bound |

Bindings (`wrangler.jsonc`, INSTALL §9): secrets `VLESS_USERS`, `TROJAN_USERS`,
`VMESS_USERS`, `SS_USERS`, `PANEL_PASSWORD`; plain vars `XHTTP_PATH`,
`PANEL_PATH`, `SUB_PATH`, `WS_ENABLED` ("false" everywhere), optional
`DIAGNOSTICS` / `SESSION_DIAG`; KV namespace `<name>-settings`; Durable Object
`XhttpSession` → class `XhttpSessionStore`. Empty `PANEL_PASSWORD` disables the
panel outright (deploy.py comment: "no password configured must mean no panel,
never no check").

## 4. Deployment inventory

All deployments live on Cloudflare account `koxis91079` (subdomain visible in
every benchmark file). Credentials themselves stay in `.clean_acct.env` /
`.env.fresh` (gitignored, values redacted here).

| Worker | Role | Evidence |
|---|---|---|
| `trinity-cleanacct` | Primary bench/verification deployment | `bench_*.py/json`, `set_diag.py`, `cleanacct_settings_backup.json` |
| `trinity-fresh` | Fresh deployment created ~08-25 during the quota crisis; received every fix | `fresh_*.py`, `.env.fresh`, XHTTP path `/41c75c3…` (redacted tail) |
| `trinity-bench-ab` | A/B worker for the chunking before/after benchmark | `bench_before_chunking.json` |
| `trinity-installer` | The web wizard (installer/ dir) that deploys the panel via REST | `installer/wrangler.jsonc` |

The last-known-good outbound preference recorded for the fresh deployment is
`di.nscl.ir:443` (`.env.fresh.state_backup.json`) — the winner of the Aug 21
Proxy IP sweep (§7).

## 5. The free-tier Durable Object duration-quota outage

Documented as KNOWN_ISSUES issue #0, measured **2026-08-25**:

- The `XhttpSession` namespace held **1,933 live DO objects**; every lingering
  (zombie) session burns free-tier DO duration quota while idle.
- Quota exhaustion took the transport down: new sessions couldn't start.
- Root cause classes, in order fixed:
  1. Unbounded header phase → `deadlines.rs` (10/4/15 s).
  2. Receiver-gone / poisoned sessions living out the full idle timer →
     `supervise.rs` state machine ends them immediately.
  3. Dead sessions answering like live ones → `0d4b86b`: end-of-life sessions
     answer **404** so Xray clients rebuild instantly instead of retrying a
     corpse; single teardown finalizer so one session can't double-publish.
- Forensics tooling (untracked): `gql_do_duration.py`, `gql_analytics.py`,
  `count_do_objects.py`, `fresh_quota_check.py` — GraphQL
  (`durableObjectsDurationAdaptiveGroups`) based, read-only. A full primary-source
  investigation of DO duration accounting survives in
  `.research_salvage/agent-aacb95415fe3774cc.txt` (with an explicit caveat that
  WebSearch had been returning fabricated URLs that day, so everything was
  re-verified against GitHub REST / Cloudflare docs / Terraform source).
- Architectural research verdict (`.research_salvage/agent-a07d6ea4515920ba9.txt`):
  **stateless packet-up is impossible** — the tunnel needs one live outbound TCP
  connection that survives request boundaries, and on Workers only a Durable
  Object can own it. An external-relay escape hatch was prototyped (`relay-poc/`,
  Python, `/connect|up|down|close` protocol): it works (verify_results.json,
  local numbers ~214 Mbps for 5 MB through the relay) but is an experiment, not
  mainline.

**Lifecycle proof on `trinity-fresh`** (`fresh_phase4_results.json`): six cases —
normal close, receiver-gone (curl killed mid-10 MB), client abort (--max-time),
upstream failure (code 000 after 30 s), reconnect, idle. Terminal SESSION_DIAG
verdicts observed: `relays_done`/`down_exit: eof`, `idle_timer`, with
`final_objects` returning to baseline after the backstop window. An earlier
lifecycle attempt failed (`fresh_lifecycle_v3_results.json`: 3 of 4 cases
`null`) — kept as evidence of the iteration, not deleted.

## 6. Security model (what the code actually enforces)

- **Uniform decoy**: wrong path, wrong credential, bad padding, expired session,
  internal error — all render one identical status page (entry.rs: errors fall
  back to `decoy()`). No distinguishable 404 anywhere.
- **WebSocket off by default** (`WS_ENABLED: "false"` in wrangler.jsonc *and*
  deploy.py:411) — classification-risk position, documented in websocket.rs;
  a store.rs comment records "the WS relay path gives EOF" (uninvestigated,
  KNOWN_ISSUES §2).
- **Preflight outbound refusal** (relay/connect.rs): Cloudflare ranges, private,
  loopback, port 25 refused before any dial.
- **Memory bounds**: MAX_BUFFER per connection; UploadQueue lookahead cap;
  installer subrequest limit 50 (of ~1000 allowed).
- **Panel auth**: constant-time compare (auth.rs); optimistic concurrency
  (`expected_rev` mismatch refuses the save — api.rs:113 `resolve_save_rev`,
  panel.html:821-825 sends it).
- **Diagnostics are opt-in**: SESSION_DIAG unset → zero KV writes, zero logs,
  bit-identical production path (diag.rs header).
- **Installer token hygiene**: the Cloudflare token lives only in request
  memory, never logged/persisted/echoed; Origin/Referer must match the
  installer's own host (installer/src/index.js header).
- **Deploy generates secrets**: panel password `token_urlsafe(18)`, paths
  `token_hex(8)` (deploy.py); redeploys can pin credentials
  (`fresh_redeploy_pinned.py`) or rotate only the panel password
  (`fresh_rotate_panel_pw.py`).

## 7. Measured performance history

All through VLESS + XHTTP packet-up via a real Xray client unless noted.
Download tests use `speed.cloudflare.com/__down`.

### Proxy IP candidate sweep (Aug 21, `bench_results.json`, via `trinity-cleanacct`)

| Candidate | 10 MB median Mbps | 1 MB Mbps | Fails/total |
|---|---|---|---|
| **di.nscl.ir** ← chosen, recorded as LKG | **26.17** | 3.49 | 0/9 |
| nima.nscl.ir | 20.93 | 4.26 | 0/9 |
| proxyip.cmliussss.net | 19.52 | 5.62 | 0/9 |
| bpb.yousef.isegaro.com | 18.29 | 4.47 | 0/9 |
| proxy.farel.is-a.dev | 14.89 | 2.30 | 0/9 |
| tr.diam4.ggff.net | 7.11 | 2.84 | 0/9 |
| pyip.ygkkk.dpdns.org | — | — | **6/9** |

Direct (untunneled) baseline: **88.6 Mbps** 10 MB (`bench_direct_baseline.json`)
— the tunnel runs at roughly a third of direct, path-limited.

### Chunking and buffer campaign (Aug 22–23)

| Label | 10 MB median Mbps | 60 s sustained Mbps | Upload 5 MB |
|---|---|---|---|
| smoke (Aug 22) | failed 5/5 | — | — |
| before_chunking (`trinity-bench-ab`) | 30.2 (1 short read) | 83.8 ⚠ anomalous (104 MB in 10 s) | 0/3 ok |
| after_chunking | 19.01 | 21.75 | 1.12 Mbps (1/2) |
| after_chunking_v2 | 19.73 | 27.76 | 1.38 Mbps (3/3) |
| fresh baseline (Aug 25, `fresh_perf_baseline.json`) | **31.12** (25 MB: 17.95) | — | 1.17 Mbps (1/3) |

### Coalescing A/B (`phase5_A_coalesced.json` / `_B_nocoalesce.json`)

10 MB × 5 runs: coalesced median ≈ 26.1 Mbps (first run cold at 16.3);
non-coalesced ≈ 27.5–32.8. Within noise of each other; the 3 ms coalesce window
was kept for send-count reduction (~260 sends/MB → a few), not throughput.

### Last-session fixes (Aug 26)

- **Upload pacing** (`63c1871`): Xray's default `scMinPostsIntervalMs: 30`
  serialized uplink POSTs behind RTT; commit records ~0.6 Mbps before vs
  ~14 Mbps after under RTT (**4.7×**). Emitter now ships `"0"`; ordering still
  guaranteed by server-side seq reordering.
- **Routing pin** (`2b10d37`): the roundRobin balancer dealt user traffic to
  unproven transports and configs hung/crawled; emitter now pins the inbound to
  the primary node, balancer code deleted.
- **Enhanced reachability A/B** (`ENHANCED_VERIFICATION_REPORT.md`): setup
  latency +0.3% for VLESS (noise), sustained throughput −6.5…−31% medians with
  tighter variance ON; reported as within path noise, not a proven regression;
  upload deliberately **skipped** (no non-CF upload endpoint proved reliable —
  httpbin 503ing, Tele2 throttling ≥256 KB via relay). Honesty preserved.
- Latency reference (README/KNOWN_ISSUES): 20/20 sequential requests,
  p50 891 ms, p95 1661 ms.

## 8. Tooling: the dangerous paths, and the guards now standing

This project has a documented near-miss with its own benchmarks:

- **Legacy `bench_proxy.py` used to PUT production `panel:settings`
  (including `nodes: []`) to swap outbound modes — wiping every user's
  subscription.** It now contains a hard block:

  ```python
  def kv_put(value):
      raise RuntimeError(
          "BLOCKED (roadmap Step 0): this legacy benchmark PUT production "
          "panel:settings ... KV writes from benches are forbidden.")
  ```

- Guard commits: `e4ccadf` (remove node-wiping bench paths, protect prod
  artifacts), `625a5c8` (`bench_beforeafter` fully de-KV'd, read-only).
- The one script allowed to mutate state, `fresh_state_clear.py`, is built as a
  ceremony: READ → VALIDATE → BACKUP → MUTATE EXACT FIELD → WRITE → READBACK →
  VERIFY, and its docstring pins it to the *outbound-state key only, never
  `panel:settings`*.
- Production artifacts are gitignored by name (`kv_prod_backup_*.json`,
  `cleanacct_settings_backup.json`) and backups exist on disk
  (`cleanacct_settings_backup.json` = version/nodes/outbound/enhancedReachability
  snapshot of the cleanacct deployment).

## 9. Documentation status

| Doc | State |
|---|---|
| README.md | Strong; one stale number (§11) |
| INSTALL.md | 12 sections, beginner path + manual CLI + troubleshooting; current |
| KNOWN_ISSUES.md | Current as of 08-25; two items now stale (§11) |
| docs/research/phase-0-report.md, parameter-inventory.md | Present, referenced from docs index |
| docs/README.md pending list | "Every parameter explained plainly", phone subscription guide, troubleshooting/FAQ, architecture/module map, protocol notes, transport internals, build pipeline — all still pending |

## 10. Client/DNS matrix (answers the standing question)

Seven `ClientTarget`s (`config/model.rs:46`): **V2rayN, V2rayNg** (Xray core),
**Hiddify, Karing, NekoBox, upstream sing-box** (sing-box core), **Mihomo**.

DNS emission, per emitter:

- **sing-box-core clients (incl. Hiddify)**: full-config export injects AdGuard
  DoH as the default resolver — `https://dns.adguard-dns.com/dns-query` with
  plain-IP fallbacks `94.140.14.14` / `94.140.15.15` so the DoH hostname itself
  resolves (`translate/singbox.rs`). **So yes — Hiddify's generated config
  carries AdGuard DNS by design, as a leak-prevention default.**
- Xray and mihomo emitters have their own DNS blocks (xray.rs, mihomo.rs).
- Share-link output (`subscription/uri.rs`) carries no DNS at all — it's a pure
  link; the client's own resolver settings apply there.
- Upstream sing-box and NekoBox cannot import XHTTP nodes at all; the panel
  refuses per-client with a reason (KNOWN_ISSUES §"Upstream sing-box…").

## 11. Doc drift found (evidence-based)

1. **README says 369 tests; the tree has 471** `#[test]` functions. Tests grew
   with the Aug 25–26 campaign; the README number was never bumped.
2. **KNOWN_ISSUES §0 says the supervisor is "merged to this tree but not yet
   deployed"** — but the `trinity-fresh` lifecycle results (`fresh_phase4_results.json`)
   show supervised terminal verdicts (`idle_timer`, `receiver_gone`-style fast
   ends, 404 rebuilds) running live. It *is* deployed on `trinity-fresh`;
   the statement is stale relative to the Aug 25–26 deploys.
3. KNOWN_ISSUES §5 says sustained throughput "not measured" — since then three
   sustained/60 s campaigns and the ENHANCED_VERIFICATION_REPORT exist. The
   section predates them.

## 12. Hygiene: what's sitting in the tree untracked

90 untracked entries. Categories:

- **Keep as-is (gitignored already)**: `.clean_acct.env`, `.env.fresh`,
  `cleanacct_settings_backup.json`, core binaries (`trx_core.exe` — 36 MB,
  untracked, presumably a renamed Xray core; `geoip.dat`/`geosite.dat`),
  `.wrangler/`, `__pycache__/`.
- **Candidates for the repo**: `relay-poc/` (self-contained experiment with its
  own verify results), the benchmark scripts + result JSONs (they are the
  evidence trail for every claim in §7 — consider a `benchmarks/` dir), the
  `gql_*.py` forensics scripts, `.research_salvage/` (the primary-source DO
  research is genuinely reusable).
- **Scratch to delete or quarantine**: `matin_j.md`/`patt_j.md` (contain only
  "Unavailable For Legal Reasons" — 451 capture bodies), `dl_probe.txt` /
  `resp_body.txt` (CF status pages), `test-*.json`, `gen_*.json` (generated
  config snapshots), `fetch_tg*.py` (Telegram scrapers), `capserver.py`.
- **Secrets check**: `.dev.vars` / `.clean_acct.env` / `.env.fresh` hold the
  live Cloudflare token + account ID + fresh panel password. All gitignored and
  none are tracked (`git ls-files | grep backup` → empty). The token's scope
  should still be reviewed: it has KV write + Worker upload rights, which is
  exactly the blast radius the guard in §8 exists to protect.

## 13. Open items, ranked

1. **Push the 13 commits.** Everything in §5–§7 exists only locally.
2. Refresh the three stale doc statements (§11) — each is a two-line edit.
3. Decide the untracked file disposition (§12); benchmarks + relay-poc +
   research salvage are worth committing, scratch captures are not.
4. KNOWN_ISSUES §1 (panel UI never driven by a browser end-to-end) and §2
   (WS relay EOF) remain the two genuinely unproven code paths.
5. The pending docs list (docs/README.md) — architecture/module map first,
   since the tree now has a story worth telling.

---
*Compiled 2026-08-27 from direct reads of the tree: git history, 21 benchmark
JSONs, all source headers, KNOWN_ISSUES/README/INSTALL/docs index, research
salvage, and untracked tooling. Credential values redacted.*
