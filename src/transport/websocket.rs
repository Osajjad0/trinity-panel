//! WebSocket transport.
//!
//! **Disabled by default, and that is a deliberate security position rather
//! than caution.** Nearly every public panel in this space uses WebSocket and
//! nothing else, so it is the most heavily trained-on transport a classifier
//! sees. Paths live inside TLS and are invisible from outside, which means
//! serving WebSocket on the same hostname as XHTTP couples their fate — a
//! classifier that flags the hostname takes both down together. Path
//! separation buys nothing here; only a separate hostname does.
//!
//! It exists because it is the one fallback that reliably works when XHTTP
//! does not, and refusing to implement it would push users to a worse panel
//! rather than to a safer configuration.
//!
//! # Fingerprint characteristics
//!
//! The handshake is unmistakable: `Sec-WebSocket-Key` and `Sec-WebSocket-Accept`
//! are unique to the protocol, and the connection negotiates `http/1.1` ALPN
//! rather than `h2`. After the upgrade, traffic is framed with a 2-to-14 byte
//! header per message, and client-to-server frames are XOR-masked with a
//! per-frame key — a pattern no ordinary web traffic produces at that volume.
//! None of that is hideable from here; the runtime frames the connection for
//! us and never exposes the raw socket.
//!
//! # What the runtime gives us
//!
//! Framed messages only. There is no way to obtain the post-101 byte stream,
//! which is why Xray's `httpupgrade` transport — which speaks unframed bytes
//! after an identical-looking handshake — cannot be implemented at all.
//!
//! # Multi-protocol support
//!
//! Originally VLESS-only, the handler now accepts VLESS and Trojan over
//! WebSocket. VLESS keeps its original path (the handler only routes, the
//! subscription config determines transport). Trojan gets a WebSocket path
//! so clients that cannot speak XHTTP can still reach the server.

use std::cell::Cell;
use std::rc::Rc;

use bytes::{Bytes, BytesMut};
use futures_util::{FutureExt, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use worker::{
    Context, Env, Request, Response, Result, WebSocket, WebSocketPair,
    WebsocketEvent,
};

use crate::config::{credentials_from_env, UserLists};
use crate::relay::outbound_state::{self, OutboundState};
use crate::protocol::{detect, ProtocolError};
use crate::relay::dirty_downlink;
use crate::relay::connect;

/// Downlink read buffer. Large enough that a coalesced train leaves room to
/// collect into, small enough to bound per-session memory. Sized above the
/// XHTTP relay's 64 KiB: a sustained stream fills this buffer in one window
/// (workerd hands back at most 4 KiB per `read_buf`), so the value sets how
/// many bytes ride one WS frame -- and therefore how much of the per-frame
/// cost (codec call, JS boundary, 4 KiB segment) each frame amortises.
const RELAY_BUFFER: usize = 64 * 1024;

/// How long to keep collecting a read train before sending. Same window the
/// XHTTP relay measured; a burst is flushed at most one window after its last
/// byte, so the added latency is bounded by this value.
const COALESCE_WINDOW_MS: u64 = 3;

/// Accept a WebSocket upgrade and relay it.
///
/// Returns the `101` immediately with the client half of the pair; all real
/// work happens in a spawned task, because the response must be returned
/// before any bytes can flow.
///
/// # Errors
/// Propagates only failures to construct the pair or the response. Protocol
/// and authentication failures are handled inside the task by closing the
/// socket without explanation — a peer that can tell a bad UUID from a bad
/// header has learned something.
pub fn handle(_req: &Request, env: &Env, ctx: &Context) -> Result<Response> {
    let pair = WebSocketPair::new()?;
    let server = pair.server;
    server.accept()?;

    // Binary messages must arrive as ArrayBuffer. The platform default is
    // "blob", and the crate's `MessageEvent::bytes()` does
    // `Uint8Array::new(&data)` — against a Blob that yields an **empty** view,
    // so it returns `Some(vec![])` rather than `None`. Every binary frame then
    // silently becomes zero bytes: the protocol header never accumulates,
    // `detect()` answers `Incomplete` forever, and the session hangs after a
    // successful handshake. Text is unaffected, which is why this hides.
    {
        let raw: &worker::web_sys::WebSocket = server.as_ref();
        raw.set_binary_type(worker::web_sys::BinaryType::Arraybuffer);
    }

    let read = |name: &str| env.var(name).map(|v| v.to_string()).unwrap_or_default();
    let creds = credentials_from_env(&UserLists {
        vless: read("VLESS_USERS"),
        trojan: read("TROJAN_USERS"),
        vmess: read("VMESS_USERS"),
        shadowsocks: read("SS_USERS"),
    });

    // Clone env for the async task: the outbound config lives in KV and can
    // only be read from an async context.
    let env_clone = env.clone();

    // Anchor the task to the request's context. `spawn_local` alone is not
    // enough: the Workers runtime cancels a spawned task the moment the fetch
    // handler's context finishes, which kills the relay mid-session — the
    // handshake succeeds, then every read on both sides hangs until reset. The
    // XHTTP path relies on the same anchor via `state.wait_until`; this handler
    // has no Durable Object, so the ExecutionContext is the only anchor
    // available. Without this the transport cannot carry a single byte.
    ctx.wait_until(async move {
        // Errors are deliberately swallowed: there is nobody to report them to
        // that is not also the untrusted peer.
        let _ = serve(&server, creds, &env_clone).await;
        let _ = server.close(Some(1000), Some("bye"));
    });

    Response::from_websocket(pair.client)
}

/// Drive one accepted WebSocket connection.
async fn serve(
    server: &WebSocket,
    creds: detect::Credentials,
    env: &worker::Env,
) -> core::result::Result<(), ()> {
    // Register the message listener BEFORE the first await. The event stream
    // is backed by an unbounded channel, so frames that arrive while the KV
    // read below is pending are buffered, not lost. Attaching after the await
    // (the previous order) dropped every frame that arrived during the read:
    // the session hung whenever KV was slower than the client's first write.
    let mut events = server.events().map_err(|_| ())?;
    // Outbound config and the last-known-good preference, same sources XHTTP
    // reads, fetched concurrently. Any failure degrades to "nothing known"
    // rather than blocking or failing the session.
    let state_env = env.clone();
    let settings_env = env.clone();
    let (outbound_cfg, snapshot, known_state) = futures_util::future::join3(
        crate::relay::outbound::load(env),
        async move {
            // The VERIFIED snapshot is the only catalog input; the operator's
            // location selects the pool. The pool itself is built after the
            // join — it is pure over the two documents this join reads, so
            // Trinity's worker-vantage health overlay can gate eligibility
            // with zero extra KV round trips (and the old second settings
            // read is gone).
            let Ok(kv) = settings_env.kv("SETTINGS") else { return None };
            let snapshot_raw = kv.get(crate::catalog::KV_KEY).text().await.ok().flatten()?;
            let document = serde_json::from_str::<serde_json::Value>(&snapshot_raw).ok()?;
            serde_json::from_value::<crate::catalog::Snapshot>(document.get("snapshot")?.clone())
                .ok()
        },
        async move {
            match state_env.kv("SETTINGS") {
                Ok(kv) => match kv.get(outbound_state::KV_KEY).text().await {
                    Ok(Some(raw)) => OutboundState::from_json(&raw),
                    _ => OutboundState::default(),
                },
                Err(_) => OutboundState::default(),
            }
        },
    )
    .await;

    // Pool construction is pure over the documents the join already read —
    // zero extra KV round trips. `known_state.geo` carries Trinity's own
    // worker-vantage verdicts: a quarantined candidate never enters the pool.
    let mut generated = outbound_cfg.verified_catalog_candidates.clone();
    if generated.is_empty()
        && (outbound_cfg.catalog_pool
            || outbound_cfg.mode == crate::relay::outbound::ProxyMode::Pool)
    {
        if let Some(snapshot) = snapshot.as_ref() {
            // Automatic resolves to ONE country through the persisted
            // OutboundState: stable across sessions, and the resolved country
            // is recorded instead of being re-spread on every request.
            let state = crate::catalog::auto_state_for_dial(
                env,
                &outbound_cfg,
                &known_state,
                Some(snapshot),
                worker::Date::now().as_millis(),
            )
            .await;
            if let Some(pool) = crate::catalog::pool_for_with_health(
                &outbound_cfg,
                Some(snapshot),
                &known_state.geo,
                worker::Date::now().as_millis(),
                Some(&state),
            ) {
                generated = pool
                    .into_iter()
                    .map(|e| format!("{}:{}", e.host, e.port))
                    .collect();
            }
        }
    }

    // The protocol header arrives in the first message, but not necessarily
    // *only* in the first message: transport framing does not align with
    // protocol framing, and a client that splits its write can straddle two
    // frames. Accumulate until the header parses or the peer gives up.
    let mut pending = BytesMut::new();

    let socket = loop {
        let Some(event) = events.next().await else {
            return Ok(());
        };
        let Ok(WebsocketEvent::Message(msg)) = event else {
            return Err(());
        };
        let Some(bytes) = msg.bytes() else {
            // Text frames are not part of this protocol. A client sending one
            // is not a client of ours.
            return Err(());
        };

        pending.extend_from_slice(&bytes);
        // Bound the wait: without this, a peer could feed one byte at a time
        // forever and hold an isolate open on an unauthenticated connection.
        if pending.len() > 8 * 1024 {
            return Err(());
        }

        match detect::detect(&pending, &creds, worker::Date::now().as_millis() / 1000) {
            // Not enough yet. Keep the buffer and wait for the next frame.
            Err(ProtocolError::Incomplete) => {}
            Err(_) => return Err(()),
            Ok(req) => {
                // WebSocket here only carries TCP. Refuse UDP and Mux without
                // a reply that would distinguish us from silence.
                if !req.is_tcp {
                    return Err(());
                }
                let target = req.target.ok_or(())?;
                // Plain-HTTP compatibility path — identical to the XHTTP DO's
                // (durable.rs): TLS-only fronts cannot carry non-TLS traffic,
                // and Speedtest's latency probes are exactly that class. TLS
                // (0x16 ClientHello) never matches, so every normal flow keeps
                // the country-enforced plan.
                let plain_http = matches!(target.port, 80 | 8080 | 8880 | 3128)
                    && (crate::transport::xhttp::wire::looks_like_http_request(req.payload)
                        // Same Speedtest exception as the XHTTP DO: TLS to a
                        // non-443 port cannot traverse TLS-only fronts; port
                        // 443 stays on the enforced pool.
                        || (target.port == 8080
                            && req.payload.first() == Some(&0x16)));
                // Route through the outbound layer using the loaded config.
                // In Off mode this is a single direct candidate; with Proxy IP
                // or NAT64 each candidate's handshake is verified before use.
                // The LKG preference (identical to XHTTP's) moves the last
                // candidate that carried a session to the front before
                // anything dials — a pure reorder of the same candidate list.
                let resolved = if plain_http {
                    crate::relay::outbound::DialPlan::direct(target.clone())
                } else {
                    outbound_cfg.resolve_with_catalog(&target, &generated)
                };
                let quality = snapshot
        .as_ref()
        .map(|s| s.quality_by_endpoint.clone())
        .unwrap_or_default();
                let capability = snapshot
        .as_ref()
        .map(|s| s.capability_by_endpoint.clone())
        .unwrap_or_default();
                let plan = outbound_state::order_plan_ranked(
                    resolved,
                    &known_state,
                    worker::Date::now().as_millis(),
                    &outbound_cfg.catalog_country,
                    &outbound_cfg.pinned_proxy,
                    &quality,
                    &capability,
                );
                let (sock, winner_idx, failed_first) = match
                    connect::open_with_plan_tracked(&plan).await
                {
                    Ok(triple) => triple,
                    Err(_) => {
                        // V24.4.4 geographic failover: Pool mode only, after
                        // the whole primary pool was attempted (that is the
                        // exhaustion definition). Same resolve/plan/dial
                        // engine — only the candidate source changes.
                        // Enforced location never falls back to another
                        // country: the session fails instead (the operator
                        // selected this egress; silently leaving it would
                        // present one location and deliver another).
                        let fb = if outbound_cfg.mode == crate::relay::outbound::ProxyMode::Pool
                            && !outbound_cfg.enforces_location()
                        {
                            crate::catalog::try_pool_fallback(
                                env,
                                &outbound_cfg,
                                &known_state,
                                worker::Date::now().as_millis(),
                            )
                            .await
                        } else {
                            None
                        };
                        if let Some((_fb_cc, fb_pool, fb_state)) = fb {
                            crate::catalog::write_fallback_state(env, &fb_state).await;
                            let fb_generated: Vec<String> = fb_pool
                                .into_iter()
                                .map(|e| format!("{}:{}", e.host, e.port))
                                .collect();
                            let resolved = outbound_cfg.resolve_with_catalog(&target, &fb_generated);
                            let quality = snapshot
        .as_ref()
        .map(|s| s.quality_by_endpoint.clone())
        .unwrap_or_default();
                            let capability = snapshot
        .as_ref()
        .map(|s| s.capability_by_endpoint.clone())
        .unwrap_or_default();
                            let plan = outbound_state::order_plan_ranked(
                                resolved,
                                &known_state,
                                worker::Date::now().as_millis(),
                                &outbound_cfg.catalog_country,
                                &outbound_cfg.pinned_proxy,
                                &quality,
                                &capability,
                            );
                            if let Ok(triple) = connect::open_with_plan_tracked(&plan).await {
                                triple
                            } else {
                                if known_state.preferred.is_some() {
                                    write_lkg(env, &known_state.clone().cleared_preference()).await;
                                }
                                return Err(());
                            }
                        } else {
                            // Total dial failure clears a stale preference, the
                            // same rule XHTTP's DialFailed arm applies: it was
                            // probably what steered every attempt wrong.
                            if known_state.preferred.is_some() {
                                write_lkg(env, &known_state.clone().cleared_preference()).await;
                            }
                            return Err(());
                        }
                    }
                };

                let (decoder, encoder) = match req.kind {
                    // VLESS needs its two-zero-byte reply, then any payload that
                    // rode in with the header. Dropping that payload is the
                    // classic bug whose symptom is a destination TLS handshake
                    // that hangs forever.
                    // VLESS's two-zero-byte reply is carried by the encoder's
                    // prologue and sent below, once, before any payload. Sending
                    // it here as well puts a second `00 00` at the head of the
                    // destination's byte stream, which the client hands to the
                    // origin as data -- the origin's TLS handshake then fails
                    // (measured: SSLEOFError) rather than hanging.
                    detect::Kind::Vless => {
                        if req.flow_requested {
                            return Err(());
                        }
                        req.body.split(&crate::random::bytes32()).map_err(|_| ())?
                    }
                    // Trojan has no reply header. Authentication succeeded, the
                    // header was consumed by `detect`.
                    detect::Kind::Trojan => {
                        req.body.split(&crate::random::bytes32()).map_err(|_| ())?
                    }
                    // Shadowsocks-2022: codec handles the AEAD framing end-to-end
                    // on both directions. The server emits no reply header; the
                    // SS session header (including its length prefix) is produced
                    // on-the-fly by `encoder.prologue()` for the first downlink
                    // chunk.
                    detect::Kind::Shadowsocks => {
                        // ponytail: split() handles all key derivation internally.
                        // entropy (32 random bytes) becomes the response salt.
                        req.body.split(&crate::random::bytes32()).map_err(|_| ())?
                    }
                    // VMess rides WS exactly as it rides XHTTP: `Body::split`
                    // builds the AEAD codec pair from the handshake params and
                    // the sealed response header is the encoder's prologue,
                    // sent once before the first body chunk. No transport is
                    // visible inside the codec.
                    detect::Kind::Vmess => {
                        req.body.split(&crate::random::bytes32()).map_err(|_| ())?
                    }
                };
                // `req` borrows `pending`, so the leftover must be copied out
                // before the buffer is cleared and dropped. For a real client
                // this is not an edge case: xray packs the header and the
                // destination's ClientHello into one write, so dropping it
                // leaves TLS waiting on a hello the origin never received --
                // a hang, not an error.
                let leftover = Bytes::copy_from_slice(req.payload);
                pending.clear();
                break (sock, decoder, encoder, leftover, plan, winner_idx, failed_first);
            }
        }
    };
    let (socket, mut decoder, mut encoder, leftover, plan, winner_idx, failed_first) = socket;

    // Opened the upstream socket. From here the two directions must run in the
    // *same* task, joined. A downlink spawned as a separate `spawn_local`
    // belongs to whichever request happened to be executing and is cancelled
    // the moment that request's context finishes — the exact trap the XHTTP
    // relay documents. Joining here means this single `serve` task owns both
    // directions and neither can be orphaned or cancelled beneath the other.
    let (mut read_half, mut write_half) = tokio::io::split(socket);
    let who = server.clone();
    let mut ready: Vec<Bytes> = Vec::new();
    // Downlink bytes actually handed to the client, shared with the pump.
    //
    // This was a plain `bool` set inside the `async move` downlink closure and
    // read here afterwards -- and `bool` is `Copy`, so `async move` captured a
    // copy and the outer binding stayed `false` forever, making the dirty
    // predicate below constantly true. Verified with a standalone reproduction
    // of the exact shape. A shared counter cannot be copied out of reach.
    let down_bytes: Rc<Cell<u64>> = Rc::new(Cell::new(0));
    // Longest drought between successful downlink sends, mirroring the XHTTP
    // relay's max_send_gap_ms: the stall signal for mid-tunnel collapse.
    let max_gap_ms: Rc<Cell<u64>> = Rc::new(Cell::new(0));

    // Send protocol-specific prologue (e.g., VLESS response header or SS session
    // header) before data relay begins.
    if let Ok(prologue) = encoder.prologue() {
        if !prologue.is_empty() {
            if who.send_with_bytes(&prologue).is_err() {
                return Err(());
            }
        }
    }

    // Forward whatever payload arrived alongside the header -- through the
    // codec, because for an encrypted protocol these bytes are ciphertext,
    // and to the *origin socket*, not to the client. Dropping it is the
    // classic bug whose symptom is a destination TLS handshake that hangs
    // forever: a real client packs its ClientHello into the same write as the
    // header, so the origin waits for a hello that was already delivered to us.
    //
    // Called unconditionally, matching the XHTTP relay. Cloning the ready list
    // is skipped: the codec writes into `ready` and the pieces are written
    // straight through to the destination below.
    if decoder.decode(leftover, &mut ready).is_err() {
        return Err(());
    }
    for piece in ready.drain(..) {
        if AsyncWriteExt::write_all(&mut write_half, &piece).await.is_err() {
            return Err(());
        }
    }

    // The pump gets its own handle: an `Arc<Cell<_>>` is deliberately not
    // `Copy`, so this cannot silently diverge from the counter read after the
    // join the way the old `bool` did.
    let down_bytes_pump = down_bytes.clone();
    let max_gap_pump = max_gap_ms.clone();
    let downlink = async move {
        let down_bytes = &down_bytes_pump;
        let max_gap_ms = &max_gap_pump;
        // Wall clock of the last successful downlink send; the gap tracker
        // stamps the longest drought. Lives INSIDE the pump: a `u64` outside
        // would be copied into the `async move` block and diverge silently.
        // Initialised at pump start, so a slow handshake never counts as a
        // stall -- only droughts *between* sends.
        let mut last_send_ms = worker::Date::now().as_millis();
        // workerd caps each `read_buf` at one 4 KiB segment, so forwarding per
        // read costs a WS frame, a codec call and a JS boundary crossing per
        // 4 KiB -- measured at ~389 frames/MB. Reads that arrive close together
        // describe one TCP segment train: block for the first, then keep
        // collecting while more arrive within COALESCE_WINDOW_MS, and send
        // once. An idle link pays only the single blocking read it always paid;
        // a burst is flushed at most one window after its last byte. This is
        // the strategy the XHTTP relay already proved, ported unchanged.
        let mut buf = BytesMut::with_capacity(RELAY_BUFFER);
        loop {
            if buf.capacity() < RELAY_BUFFER {
                buf.reserve(RELAY_BUFFER - buf.capacity());
            }

            let mut eof = false;
            match read_half.read_buf(&mut buf).await {
                Ok(0) | Err(_) => eof = true,
                Ok(_) => {
                    while buf.len() < RELAY_BUFFER {
                        let read = Box::pin(read_half.read_buf(&mut buf));
                        let window =
                            gloo_timers::future::sleep(std::time::Duration::from_millis(
                                COALESCE_WINDOW_MS,
                            ));
                        match futures_util::future::select(read, window).await {
                            futures_util::future::Either::Left((Ok(0), _))
                            | futures_util::future::Either::Left((Err(_), _)) => {
                                eof = true;
                                break;
                            }
                            futures_util::future::Either::Left((Ok(_), _)) => {}
                            // Window closed: the train so far goes as one frame.
                            futures_util::future::Either::Right(_) => break,
                        }
                    }
                }
            }

            // Flush before acting on EOF. Coalescing can leave a tail in the
            // buffer when the destination closes, and closing the socket
            // without sending it would truncate the last window of every
            // download -- the failure this ordering exists to prevent.
            if !buf.is_empty() {
                let chunk: Bytes = buf.split().freeze();
                match encoder.encode(chunk) {
                    Ok(encoded) => {
                        let n = encoded.len() as u64;
                        down_bytes.set(down_bytes.get().saturating_add(n));
                        // Stall tracking: longest drought between successful
                        // sends. `worker::Date::now()` is the same clock the
                        // XHTTP relay uses for its max_send_gap_ms, so the two
                        // transports agree on what counts as a stall.
                        let now = worker::Date::now().as_millis();
                        let gap = now.saturating_sub(last_send_ms);
                        if gap > max_gap_ms.get() {
                            max_gap_ms.set(gap);
                        }
                        last_send_ms = now;
                        if who.send_with_bytes(&encoded).is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }

            if eof {
                break;
            }
        }
        let _ = who.close(Some(1000), Some("eof"));
    };

    // Uplink coalescing, mirroring the downlink pump: xray hands us one small
    // write per message (4-16 KiB typical), and forwarding each decoded piece
    // as its own upstream write hands the box front a dribble instead of a
    // segment. Block for the first message of a burst, then drain whatever is
    // already queued without awaiting, and write once per batch. Ordering:
    // single consumer, FIFO. Backpressure: while the upstream write blocks,
    // nobody drains `events`, so the runtime's buffer fills — the same valve
    // the unbounded channel had, one layer earlier.
    let uplink = async {
        let mut upbuf: Vec<u8> = Vec::with_capacity(64 * 1024);
        while let Some(event) = events.next().await {
            let Ok(WebsocketEvent::Message(msg)) = event else {
                break;
            };
            let Some(bytes) = msg.bytes() else {
                break;
            };
            if decoder.decode(bytes.into(), &mut ready).is_err() {
                break;
            }
            for piece in ready.drain(..) {
                upbuf.extend_from_slice(&piece);
            }
            // Drain every message that has already arrived, up to the flush
            // threshold. `now_or_never() == None` means "nothing queued right
            // now" — a flush point, never a loop exit.
            while upbuf.len() < 64 * 1024 {
                match events.next().now_or_never().flatten() {
                    Some(Ok(WebsocketEvent::Message(msg))) => {
                        let Some(bytes) = msg.bytes() else { return };
                        if decoder.decode(bytes.into(), &mut ready).is_err() {
                            return;
                        }
                        for piece in ready.drain(..) {
                            upbuf.extend_from_slice(&piece);
                        }
                    }
                    // Nothing queued, stream ended, or a non-message event:
                    // flush what we have; a real stream end is handled by the
                    // outer loop's next iteration (or its exit below).
                    _ => break,
                }
            }
            if upbuf.is_empty() {
                continue;
            }
            // workerd destroys the connection when a single socket write
            // carries more than 64 KiB (cloudflare/workerd#7074): the promise
            // resolves and the failure only surfaces on the next read, which
            // aborts the isolate and takes every request it is serving with
            // it (observed live as intermittent Cloudflare 1101 on unrelated
            // panel GETs, 2026-09-30 19:51-20:01 UTC). A fast client's
            // message train can decode to pieces well past 64 KiB, so the
            // batched buffer MUST go out in slices, not as one write.
            if crate::relay::write_chunked(&mut write_half, &upbuf)
                .await
                .is_err()
            {
                return;
            }
            upbuf.clear();
        }
        if !upbuf.is_empty() {
            // Same 64 KiB workerd ceiling as above: slice the drain too.
            let _ = crate::relay::write_chunked(&mut write_half, &upbuf).await;
        }
    };

    futures_util::future::join(downlink, uplink).await;

    // LKG bookkeeping, the same rules XHTTP applies at teardown, via the same
    // shared helpers: a session that dialled through the full candidate list
    // may update the stored preference (proxy win, debounced); a direct win
    // keeps nothing unless the preferred candidate is the one that failed
    // first (demotion); a session that connected but relayed nothing is the
    // dirty-IP signature and clears the preference. The predicate is the same
    // one XHTTP applies to the same signal, against the same floor, so the two
    // transports cannot disagree about whether an egress carried traffic: a
    // destination that answers a ClientHello with a TLS alert and a reset
    // (7-16 bytes) is NOT a working egress, and must not be recorded as one.
    let dirty = dirty_downlink(down_bytes.get());
    // Stall demotion: a winner that moved real data and then dried up for
    // 15 s+ mid-session is the flapping-candidate signature (measured live:
    // 0 → 35 → 0 Mbps inside one tunnel). Same demotion as dirty -- one soft
    // fail, never a quarantine, self-heals on the next probe -- but the
    // byte gate keeps idle-but-healthy sessions out: those have almost no
    // bytes and stay on the dirty rule. XHTTP already tracks max_send_gap_ms
    // per session; its teardown applies this same predicate below.
    let stalled = crate::relay::stalled_downlink(down_bytes.get(), max_gap_ms.get());
    let winner_key = plan.candidates.get(winner_idx).map(outbound_state::candidate_key);
    // Session-sourced demotion, the same rule XHTTP's teardown applies: a
    // connected winner that carried nothing -- or that stalled mid-transfer --
    // records its first soft fail so the next plan ranks it behind untried
    // candidates.
    let (ws_doc, session_fail_recorded) =
        if (dirty || stalled) && plan.candidates.get(winner_idx) != Some(&plan.logical) {
            let key = winner_key.clone().unwrap_or_default();
            let (doc, changed) =
                known_state.clone().with_session_fail(&key, worker::Date::now().as_millis());
            (doc, changed)
        } else {
            (known_state.clone(), false)
        };
    match outbound_state::lkg_on_session_result(
        known_state.preferred.as_deref(),
        known_state.updated_at_ms,
        outbound_state::DialVerdict::Won {
            winner: winner_key.as_deref().unwrap_or_default(),
            is_direct: plan.candidates.get(winner_idx) == Some(&plan.logical),
            first_failed: failed_first
                .and_then(|i| plan.candidates.get(i))
                .map(outbound_state::candidate_key)
                .as_deref(),
        },
        worker::Date::now().as_millis(),
        dirty,
    ) {
        outbound_state::LkgAction::Record(key) => {
            write_lkg(
                env,
                &ws_doc.with_preference(
                    Some(key),
                    worker::Date::now().as_millis(),
                ),
            )
            .await;
        }
        outbound_state::LkgAction::Clear => {
            write_lkg(env, &ws_doc.cleared_preference()).await
        }
        outbound_state::LkgAction::Keep => {
            if session_fail_recorded {
                write_lkg(env, &ws_doc).await;
            }
        }
    }

    Ok(())
}

/// Persist one outbound-state document, or quietly do nothing. Failures are
/// not reportable: the preference is an optimisation, never a requirement.
async fn write_lkg(env: &worker::Env, state: &OutboundState) {
    // Re-read + freshness merge: the session's snapshot is minutes old; a
    // probe that landed mid-session must survive this write-back.
    let merged = match env.kv("SETTINGS") {
        Ok(kv) => match kv.get(outbound_state::KV_KEY).text().await {
            Ok(Some(raw)) => {
                outbound_state::merged_with_stored(state.clone(), OutboundState::from_json(&raw))
            }
            _ => state.clone(),
        },
        Err(_) => state.clone(),
    };
    let Ok(document) = serde_json::to_string(&merged) else {
        return;
    };
    if let Ok(kv) = env.kv("SETTINGS") {
        if let Ok(pending) = kv.put(outbound_state::KV_KEY, document) {
            let _ = pending.execute().await;
        }
    }
}
