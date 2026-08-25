//! The Durable Object that owns one XHTTP session.
//!
//! `packet-up` splits a single logical connection across many independent HTTP
//! requests — one long-lived `GET` carrying the downlink, and a stream of
//! `POST`s carrying the uplink. The outbound socket has to survive between
//! them, and on this runtime a Durable Object is the only construct that can
//! hold it: sockets may not be created in global scope or shared across
//! requests, and module-level state has no isolate affinity.
//!
//! # Concurrency: why a single owner task, not shared state
//!
//! `DurableObject::fetch` takes `&self`, and **nothing serialises concurrent
//! requests to one object here.** Cloudflare's input gate defers events only
//! while a *storage* operation is in flight, and this object never touches
//! storage. Meanwhile `packet-up` clients pipeline their uploads — that is the
//! entire reason the reorder buffer exists — so two `POST`s for one session
//! being in flight together is the normal case.
//!
//! An earlier design had each request take the writer out of a `RefCell`,
//! await on it, and put it back. That is broken in two distinct ways, both
//! reachable with ordinary traffic:
//!
//! - Before the connection exists, request A suspends inside `establish` while
//!   request B observes `established == false`, tries to establish again with
//!   a mid-stream chunk, fails to parse it, and poisons the session forever.
//! - After it exists, A takes the writer and suspends; B finds `None` and
//!   poisons the session. If A's request future is cancelled — a client
//!   disconnect is enough — the writer is never returned at all.
//!
//! So the writer is not shared. Exactly one spawned task owns it for the
//! lifetime of the session, and request handlers only hand it ordered bytes
//! through a bounded channel. Nothing awaits while holding session state, and
//! request cancellation cannot lose the socket because no request ever held
//! it. The channel's bound is also what propagates backpressure: when the
//! destination is slower than the client, `POST` responses slow down instead
//! of memory growing.
//!
//! The downlink channel is likewise created eagerly in `new` rather than when
//! the socket opens, which removes the ordering race between the client's
//! `GET` and its first `POST` — either may arrive first and neither has to
//! wait for the other.

use core::cell::RefCell;
use core::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use bytes::{Bytes, BytesMut};
use futures_channel::mpsc;
use futures_util::future::Either;
use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
// `wasm_bindgen` and `DurableObject` are not referenced anywhere below — the
// `#[durable_object]` macro expands to code that names them directly, so they
// must be in scope at the expansion site or the macro fails to compile.
use worker::{
    durable_object, wasm_bindgen, DurableObject, Env, Request, Response, Result, State,
};

use super::diag::{SessionDiag, SessionEnd, DownExit};
use super::wire::{self, Class};
use super::{UploadQueue, DEFAULT_MAX_BUFFERED_POSTS, DEFAULT_MAX_POST_BYTES};
#[allow(unused_imports)] // used by the socket-owning task below on some paths
use crate::protocol::codec::{Decoder, Encoder};
use crate::protocol::{detect, Credentials, ProtocolError};
use crate::relay::outbound::OutboundConfig;
use crate::relay::outbound_state::{self, OutboundState};
#[allow(unused_imports)] // used by the socket-owning task below on some paths
use crate::relay::{connect, write_chunked};

/// Total bytes the reorder buffer may hold for one session.
const MAX_BUFFER_BYTES: usize = 4 * 1024 * 1024;

/// Ceiling on bytes accumulated while waiting for a complete protocol header.
///
/// A VLESS header is at most a few hundred bytes. Without a cap, a peer could
/// dribble one byte per POST forever and hold an isolate open on a connection
/// that never authenticates.
const MAX_HEADER_BYTES: usize = 8 * 1024;

/// Seconds of complete inactivity (no bytes in either direction) before the
/// session is torn down. This releases the Durable Object instance so it stops
/// consuming duration quota on the free tier. Active streaming resets the
/// counter continuously, so only truly abandoned sessions are affected.
const IDLE_TIMEOUT_SECS: u32 = 60;

/// Seconds a session may sit before its protocol header completes.
///
/// A client sends the header with its first uplink chunk, so anything longer
/// than a slow-link round trip means the client is gone. Without this bound
/// the pre-socket phase has no timer at all: every abandoned half-session --
/// and a client retry storm creates them by the hundred -- pins an object for
/// as long as the platform tolerates, burning duration quota the whole time.
/// Generous by design; this bounds a leak, it does not time out real traffic.
const HEADER_TIMEOUT_SECS: u64 = 10;

/// Size of one downlink read from the destination socket.
///
/// The old code reused [`relay::INITIAL_BUFFER`] (16.5 KB), which sized for
/// TLS-record boundaries on the *uplink* side. The downlink carries bulk
/// response bodies, where per-read overhead dominates: at 16 KB a 10 MB
/// download costs ~640 reads, channel hops, and HTTP frames each, versus ~160
/// at 64 KB, with no memory concern -- the isolate holds 128 MB and this
/// buffer lives only while the session does.
const DOWNLINK_BUFFER: usize = 64 * 1024;

/// How long the downlink pump keeps collecting reads after the first byte of a
/// burst before flushing, in milliseconds.
///
/// workerd returns at most one 4 KiB segment per `read_buf` regardless of the
/// buffer size (measured: 524 reads per 1 MB), so the only way to send fewer,
/// larger chunks is to wait for neighbours. 3 ms is well below the ~300 ms
/// inter-burst gaps the diag counters show on real downloads, so interactive
/// traffic never waits for bytes that are not already in flight; bulk traffic
/// collapses ~260 sends per MB into a few.
const COALESCE_WINDOW_MS: u64 = 3;

/// Depth of the uplink hand-off channel.
///
/// Small on purpose. This is the backpressure valve: once the owner task is
/// this far behind, uplink `POST`s block rather than queueing more memory.
const UPLINK_DEPTH: usize = 8;

type DownSender = mpsc::Sender<core::result::Result<Bytes, worker::Error>>;
type DownReceiver = mpsc::Receiver<core::result::Result<Bytes, worker::Error>>;

/// Session state. Nothing here is ever borrowed across an `.await`.
struct Inner {
    queue: UploadQueue,
    /// Hand-off to the single task that owns the socket. `None` until the
    /// first uplink starts it.
    uplink: Option<mpsc::Sender<Bytes>>,
    down_rx: Option<DownReceiver>,
    down_tx: Option<DownSender>,
    /// Set when the session is unusable, so later requests fail fast.
    poisoned: bool,
}

/// One XHTTP session: an outbound socket plus its uplink reordering.
#[durable_object]
pub struct XhttpSession {
    /// Load-bearing: `state.wait_until` is what keeps the socket-owner task
    /// alive. Work spawned with a bare `spawn_local` belongs to the request
    /// that spawned it and is cancelled the moment that request's response is
    /// returned — which for an uplink `POST` is almost immediately. The
    /// observable symptom is subtle and was worth the debugging: the task
    /// lives just long enough to send the protocol reply header, so the client
    /// sees a successful handshake and then silence forever.
    state: State,
    env: Env,
    inner: RefCell<Inner>,
}

impl DurableObject for XhttpSession {
    fn new(state: State, env: Env) -> Self {
        // Bounded so a fast destination cannot outrun a slow client and buffer
        // the whole response in memory. Backpressure reaches the socket read,
        // which reaches the destination's send window.
        let (tx, rx) = mpsc::channel(16);
        Self {
            state,
            env,
            inner: RefCell::new(Inner {
                queue: UploadQueue::new(DEFAULT_MAX_BUFFERED_POSTS, MAX_BUFFER_BYTES),
                uplink: None,
                down_rx: Some(rx),
                down_tx: Some(tx),
                poisoned: false,
            }),
        }
    }

    async fn fetch(&self, req: Request) -> Result<Response> {
        let method = req.method().to_string();
        let path = req.path();
        let prefix = self.env.var("XHTTP_PATH").map(|v| v.to_string()).unwrap_or_default();

        // Xray's server validates the padding length and answers 400 when it
        // falls outside the configured range. Matching that is not decoration:
        // an active prober comparing us against a known XHTTP origin would
        // otherwise see a server that accepts padding no real one accepts.
        let referer = req.headers().get("Referer").ok().flatten();
        let query = req.url().ok().and_then(|u| u.query().map(str::to_owned)).unwrap_or_default();
        if wire::validate_padding(&wire::PaddingConfig::default(), &query, |name| {
            if name.eq_ignore_ascii_case("Referer") {
                referer.as_deref()
            } else {
                None
            }
        })
        .is_err()
        {
            return reply(Status::Rejected);
        }

        match wire::classify(&method, &path, &prefix) {
            // stream-one never reaches a Durable Object — it carries both
            // directions in one request and needs no cross-request state, so
            // the entry point serves it directly.
            Class::Downlink { .. } => self.downlink(),
            Class::PacketUp { session, seq } => {
                self.uplink(req, seq, session.as_str().to_owned()).await
            }
            _ => reply(Status::NotFound),
        }
    }
}

/// The only outcomes this object exposes.
///
/// An earlier version returned seven distinguishable statuses (409, 410, 500,
/// 502 among them), which handed a prober a map of our internal state — it
/// could tell a poisoned session from a missing one from an upstream failure.
///
/// The fix is not "return the same thing always": a real Xray XHTTP origin
/// *does* differentiate, and always answering 200 would be its own tell. It is
/// to expose exactly the statuses Xray itself uses — 200, 400, 404, 413 — and
/// fold every internal condition onto them.
#[derive(Clone, Copy)]
enum Status {
    Ok,
    /// Anything refused: bad padding, unparseable header, dead session,
    /// upstream failure, internal error. Xray answers 400 for its own
    /// rejections, so they are indistinguishable from ours.
    Rejected,
    NotFound,
    /// Body above `scMaxEachPostBytes`, exactly as Xray answers.
    TooLarge,
}

fn reply(status: Status) -> Result<Response> {
    let code = match status {
        Status::Ok => 200,
        Status::Rejected => 400,
        Status::NotFound => 404,
        Status::TooLarge => 413,
    };
    Response::empty().map(|r| r.with_status(code))
}

impl XhttpSession {
    /// Hand the client the downlink stream.
    ///
    /// Returns immediately with a streaming body, before any bytes exist. The
    /// response headers are what tell intermediaries not to buffer, so they
    /// need to be on the wire ahead of the first payload rather than behind it.
    fn downlink(&self) -> Result<Response> {
        let rx = self.inner.borrow_mut().down_rx.take();
        let Some(rx) = rx else {
            // Only one downlink exists per session, so a second `GET` is a
            // retry or a probe. Reported as a plain rejection so it cannot be
            // told apart from any other refusal.
            return reply(Status::Rejected);
        };

        let mut resp = Response::from_stream(rx)?;
        let headers = resp.headers_mut();
        for (k, v) in wire::downlink_headers(true) {
            headers.set(k, v)?;
        }
        Ok(resp)
    }

    /// Accept one uplink chunk and hand any newly-ordered bytes to the owner.
    ///
    /// `sid` rides along for the session diagnostics only — the relay is
    /// indifferent to it.
    async fn uplink(&self, mut req: Request, seq: u64, sid: String) -> Result<Response> {
        if self.inner.borrow().poisoned {
            return reply(Status::Rejected);
        }

        // Refuse on the declared length BEFORE reading. Checking after
        // `req.bytes()` is theatre: by then the whole body is already in
        // linear memory, so a peer can force an arbitrary allocation and the
        // 413 protects nothing. A missing or unparseable Content-Length is
        // treated as untrusted and refused rather than read optimistically.
        let declared = req
            .headers()
            .get("Content-Length")
            .ok()
            .flatten()
            .and_then(|v| v.parse::<usize>().ok());
        match declared {
            Some(n) if n > DEFAULT_MAX_POST_BYTES => return reply(Status::TooLarge),
            Some(_) => {}
            None => return reply(Status::Rejected),
        }

        let body = req.bytes().await?;
        // Belt and braces: the edge is what makes Content-Length authoritative,
        // but this costs nothing and the invariant is worth asserting locally.
        if body.len() > DEFAULT_MAX_POST_BYTES {
            return reply(Status::TooLarge);
        }

        // Reorder, and start the owner task if this is the first chunk. Both
        // happen under one borrow that is dropped before any await, so two
        // concurrent requests cannot both decide they are first.
        let (mut sender, ready) = {
            let mut inner = self.inner.borrow_mut();
            let Ok(accepted) = inner.queue.push(seq, Bytes::from(body)) else {
                inner.poisoned = true;
                drop(inner);
                return reply(Status::Rejected);
            };

            if inner.uplink.is_none() {
                let (tx, rx) = mpsc::channel(UPLINK_DEPTH);
                let Some(down) = inner.down_tx.take() else {
                    inner.poisoned = true;
                    drop(inner);
                    return reply(Status::Rejected);
                };
                inner.uplink = Some(tx);
                // Tied to the object, not to this request.
                //
                // The outbound config is loaded inside `own_session` rather
                // than here on purpose. Reading it needs an await, and this
                // block holds a `RefCell` borrow of the session state: a
                // concurrent POST reaching `borrow_mut` while this one was
                // suspended on KV would panic, and a panic in a WASM isolate
                // takes every connection on it down. The owner task has to
                // wait for header bytes before it can dial anyway, so it
                // loads the config there at no cost.
                self.state.wait_until(own_session(
                    rx,
                    down,
                    sid,
                    self.credentials(),
                    self.env.clone(),
                ));
            }

            // A clone is an independent handle to the same queue, so the
            // borrow can end here and the send can await freely.
            let sender = inner.uplink.clone();
            (sender, accepted.ready)
        };

        let Some(sender) = sender.as_mut() else {
            return reply(Status::Rejected);
        };

        for chunk in ready {
            // Awaits when the owner is behind. That is the intended
            // backpressure: the client's POST is what slows down, not memory.
            if sender.send(chunk).await.is_err() {
                // The owner task is gone, which means the session ended.
                self.inner.borrow_mut().poisoned = true;
                return reply(Status::Rejected);
            }
        }

        reply(Status::Ok)
    }

    /// Credentials for every enabled protocol.
    ///
    /// Malformed entries are skipped rather than failing the whole list, so one
    /// bad paste in the panel does not lock every user out. An empty list for a
    /// protocol disables it, which is how a protocol is turned off.
    fn credentials(&self) -> Credentials {
        let read = |name: &str| self.env.var(name).map(|v| v.to_string()).unwrap_or_default();
        crate::config::credentials_from_env(&crate::config::UserLists {
            vless: read("VLESS_USERS"),
            trojan: read("TROJAN_USERS"),
            vmess: read("VMESS_USERS"),
            shadowsocks: read("SS_USERS"),
        })
    }
}

/// Current Unix time, for VMess's replay window.
///
/// Cloudflare's clock rather than the client's, and reliable — but note the
/// runtime freezes time between I/O operations, so this is the timestamp of
/// the last external event rather than a live reading. That is well inside
/// VMess's two-minute window and does not affect the check.
fn now_secs() -> u64 {
    worker::Date::now().as_millis() / 1000
}

fn now_ms() -> u64 {
    worker::Date::now().as_millis()
}

/// The single task that owns the outbound socket for one session.
///
/// Everything that touches the socket happens here, sequentially. No request
/// handler ever holds it, so no interleaving of requests can corrupt it and no
/// cancelled request can lose it.
async fn own_session(
    mut uplink: mpsc::Receiver<Bytes>,
    mut down: DownSender,
    sid: String,
    creds: Credentials,
    env: Env,
) {
    // The settings read and the arrival of the first header bytes are
    // independent waits, so they run concurrently. Loading the config before
    // listening for the header put the full KV round-trip on every session's
    // critical path ahead of the dial; joined like this, establishment costs
    // whichever wait is longer, not their sum. Still falls back to Off mode
    // when KV is unavailable or the settings document is missing.
    // A clone for the settings read; the original stays here for the
    // SESSION_DIAG-gated publication at teardown.
    let settings_env = env.clone();
    let settings_load = async move {
        match settings_env.kv("SETTINGS") {
            Ok(kv) => match kv.get(crate::panel::store::KEY).text().await {
                Ok(Some(raw)) => crate::relay::outbound::from_settings_json(&raw),
                _ => OutboundConfig::default(),
            },
            Err(_) => OutboundConfig::default(),
        }
    };

    // The last-known-good outbound preference rides along in the same join:
    // one KV round trip that overlaps the header wait, and — like the settings
    // read — any failure degrades to "nothing known" rather than blocking or
    // failing the session.
    let state_env = env.clone();
    let state_load = async move {
        match state_env.kv("SETTINGS") {
            Ok(kv) => match kv.get(outbound_state::KV_KEY).text().await {
                Ok(Some(raw)) => OutboundState::from_json(&raw),
                _ => OutboundState::default(),
            },
            Err(_) => OutboundState::default(),
        }
    };

    // Accumulate until a complete header parses. A header CAN arrive split
    // across chunks -- transport framing does not align with protocol framing,
    // and a small scMaxEachPostBytes or an edge flush boundary is enough to
    // split it. Treating that as a failure would kill legitimate sessions.
    //
    // Each chunk wait races HEADER_TIMEOUT_SECS. This phase has no other
    // timer: without it, a client that opens posts and then vanishes -- which
    // a retry storm produces en masse -- pins this object until the
    // platform's idle reaping notices, burning duration quota the entire
    // time. Real clients deliver the first chunk in well under a second; ten
    // seconds is generous even for a bad mobile link.
    //
    // Borrows `uplink` rather than moving it: the receiver outlives this
    // phase and feeds the upstream relay for the rest of the session. Returns
    // the completed buffer rather than the parsed request, because the parse
    // borrows the buffer; the buffer is re-parsed once after the join, which
    // is microseconds against a once-per-session cost.
    let header_phase = async {
        let mut header = BytesMut::new();
        loop {
            let waited = {
                match futures_util::future::select(
                    Box::pin(uplink.next()),
                    Box::pin(gloo_timers::future::sleep(std::time::Duration::from_secs(
                        HEADER_TIMEOUT_SECS,
                    ))),
                )
                .await
                {
                    futures_util::future::Either::Left((chunk, _)) => chunk,
                    futures_util::future::Either::Right(((), _)) => return None, // header never came
                }
            };
            let Some(chunk) = waited else {
                return None; // client vanished before completing the header
            };
            header.extend_from_slice(&chunk);
            if header.len() > MAX_HEADER_BYTES {
                return None;
            }

            match detect::detect(&header, &creds, now_secs()) {
                // A valid prefix of some enabled protocol. Keep it, loop for more.
                Err(ProtocolError::Incomplete) => {}
                Err(_) => return None,
                Ok(_) => return Some(header),
            }
        }
    };

    let (Some(header), outbound_cfg, known_state) =
        futures_util::future::join3(header_phase, settings_load, state_load).await
    else {
        return;
    };
    let Ok(req) = detect::detect(&header, &creds, now_secs()) else {
        return;
    };

    // Vision splices the TLS record stream and cannot survive a CDN, which
    // terminates TLS at the edge.
    if req.flow_requested {
        return;
    }
    let Some(target) = req.target else { return };
    if !req.is_tcp {
        // UDP needs a datagram API this runtime does not have;
        // Mux needs framing this server does not implement.
        return;
    }
    // Before the socket, because it can fail: a client that negotiated a body
    // mode this server cannot frame is refused rather than served a corrupted
    // tunnel. Authenticating and then garbling every byte is strictly worse
    // than declining. (`req.payload` borrows `header`, so both stay alive for
    // the rest of establishment -- an 8 KB buffer, not worth contorting for.)
    let Ok((mut decoder, mut encoder)) = req.body.split(&crate::random::bytes32()) else {
        return;
    };
    // Route through the outbound layer using the session's loaded config. In
    // Off mode this is a single direct candidate; with Proxy IP or NAT64 each
    // candidate's handshake is verified before the session commits to it.
    //
    // A fresh last-known-good preference (see `outbound_state`) moves its
    // candidate to the front before anything dials. Pure reorder: every
    // candidate stays in the plan, so a stale preference costs nothing.
    let plan = outbound_state::order_plan(
        outbound_cfg.resolve(&target),
        &known_state,
        now_ms(),
    );
    let started_ms = now_ms();
    let Ok((sock, winner_idx)) = connect::open_with_plan_tracked(&plan).await else { return };

    // Session diagnostics: counted always (a few adds per chunk), published
    // only when the deployment opts in via the SESSION_DIAG binding. The sid
    // comes from the uplink path prefix; when unavailable a short hash stands
    // in so bench keys still sort uniquely.
    let diag = Arc::new(SessionDiag::new());
    diag.setup_ms.set(now_ms().saturating_sub(started_ms));
    let down_diag = diag.clone();

    let leading = Bytes::copy_from_slice(req.payload);
    let (mut read_half, mut writer) = tokio::io::split(sock);

    // One buffer for the session's whole uplink. Reused across chunks so a
    // steady stream costs no allocations once its capacity has settled.
    let mut ready: Vec<Bytes> = Vec::new();

    // Forward whatever payload arrived alongside the header -- through the
    // codec, because for an encrypted protocol these bytes are ciphertext.
    // Dropping them is the classic bug whose symptom is a destination TLS
    // handshake that hangs forever: the ClientHello was parsed off and
    // discarded.
    //
    // The codec is called even when `leading` is empty, and that is
    // load-bearing rather than tidiness. Not every protocol puts its first
    // payload after the header: Shadowsocks-2022 carries it *inside* the
    // encrypted header, so there are no leading bytes at all and the codec is
    // holding the client's first request. Guarding this call on
    // `!leading.is_empty()` strands that payload -- the destination waits for a
    // request that was already delivered to us, the client waits for a
    // response, and the session hangs with nothing logged anywhere.
    if decoder.decode(leading, &mut ready).is_err() {
        return;
    }
    for piece in ready.drain(..) {
        if write_chunked(&mut writer, &piece).await.is_err() {
            return;
        }
    }

    // Idle timeout: if no bytes flow in either direction for IDLE_TIMEOUT_SECS,
    // tear down the session to release DO duration. The activity flag is set by
    // both relay directions whenever bytes are successfully transferred.
    let activity = Arc::new(AtomicBool::new(true));
    let upstream_activity = activity.clone();
    let downstream_activity = activity.clone();

    // Both directions run as one task rather than two. A nested `spawn_local`
    // would belong to whichever request happened to be executing, and would be
    // cancelled when that request finished -- the same trap the outer task hit.
    // Joining them here means the single future handed to `wait_until` owns
    // everything, and neither direction can outlive or orphan the other.
    let upstream = async move {
        while let Some(chunk) = uplink.next().await {
            if decoder.decode(chunk, &mut ready).is_err() {
                break; // corrupt or forged; nothing recoverable follows
            }
            let mut failed = false;
            for piece in ready.drain(..) {
                if write_chunked(&mut writer, &piece).await.is_err() {
                    failed = true;
                    break;
                }
                upstream_activity.store(true, Ordering::Relaxed);
            }
            if failed {
                break;
            }
        }
        // Closing the write half signals EOF to the destination rather than
        // leaving it waiting for a request body that will never arrive.
        let _ = writer.shutdown().await;
    };

    let downlink = async move {
        let pump_started_ms = now_ms();
        let Ok(prologue) = encoder.prologue() else { return };
        if !prologue.is_empty() && down.send(Ok(prologue)).await.is_err() {
            return;
        }

        let mut buf = BytesMut::with_capacity(DOWNLINK_BUFFER);
        let mut last_send_ms = now_ms();
        loop {
            if buf.capacity() < DOWNLINK_BUFFER {
                buf.reserve(DOWNLINK_BUFFER - buf.capacity());
            }

            // workerd caps each `read_buf` at one 4 KiB segment, so forwarding
            // per read costs hundreds of channel messages and HTTP chunks per
            // megabyte. Reads that arrive close together describe one TCP
            // segment train: block for the first, then keep collecting while
            // more arrive within COALESCE_WINDOW_MS, and flush once. An idle
            // link pays only the single blocking read it always paid; a burst
            // is flushed at most one window after its last byte.
            let mut eof_or_error = false;
            match read_half.read_buf(&mut buf).await {
                // EOF and read errors were one silent arm before the
                // diagnostic; recording which ending actually happened changes
                // nothing observable on the wire.
                Ok(0) => {
                    down_diag.down_exit.set(Some(DownExit::Eof));
                    eof_or_error = true;
                }
                Err(e) => {
                    *down_diag.read_error.borrow_mut() = Some(e.to_string());
                    down_diag.down_exit.set(Some(DownExit::ReadError));
                    eof_or_error = true;
                }
                Ok(n) => {
                    down_diag.record_read(n);
                    downstream_activity.store(true, Ordering::Relaxed);
                }
            }

            if !eof_or_error {
                while buf.len() < DOWNLINK_BUFFER {
                    let read = Box::pin(read_half.read_buf(&mut buf));
                    let window =
                        gloo_timers::future::sleep(std::time::Duration::from_millis(
                            COALESCE_WINDOW_MS,
                        ));
                    match futures_util::future::select(read, window).await {
                        futures_util::future::Either::Left((Ok(0), _)) => {
                            down_diag.down_exit.set(Some(DownExit::Eof));
                            eof_or_error = true;
                            break;
                        }
                        futures_util::future::Either::Left((Err(e), _)) => {
                            *down_diag.read_error.borrow_mut() = Some(e.to_string());
                            down_diag.down_exit.set(Some(DownExit::ReadError));
                            eof_or_error = true;
                            break;
                        }
                        futures_util::future::Either::Left((Ok(n), _)) => {
                            down_diag.record_read(n);
                            downstream_activity.store(true, Ordering::Relaxed);
                        }
                        // Window closed: whatever the train delivered so far
                        // goes out as one chunk.
                        futures_util::future::Either::Right(_) => break,
                    }
                }
            }

            if buf.is_empty() {
                if eof_or_error {
                    break;
                }
                continue;
            }
            let chunk = buf.split().freeze();
            let Ok(wrapped) = encoder.encode(chunk) else {
                down_diag.down_exit.set(Some(DownExit::EncodeFailed));
                break;
            };
            let sent_len = wrapped.len();
            if down.send(Ok(wrapped)).await.is_err() {
                down_diag.down_exit.set(Some(DownExit::ReceiverGone));
                break;
            }
            down_diag.record_send(sent_len);
            let now = now_ms();
            if now.saturating_sub(last_send_ms) > down_diag.max_send_gap_ms.get() {
                down_diag.max_send_gap_ms.set(now - last_send_ms);
            }
            last_send_ms = now;
        }
        down_diag.pump_ms.set(now_ms().saturating_sub(pump_started_ms));
    };

    // Race the relay against an idle timer. The timer checks the activity flag
    // every second; if no bytes flowed for IDLE_TIMEOUT_SECS consecutive checks,
    // the session is considered abandoned and the select drops both relay futures.
    let idle_timer = async {
        let mut idle_secs: u32 = 0;
        loop {
            gloo_timers::future::sleep(std::time::Duration::from_secs(1)).await;
            if activity.swap(false, Ordering::Relaxed) {
                idle_secs = 0;
            } else {
                idle_secs += 1;
                if idle_secs >= IDLE_TIMEOUT_SECS {
                    return;
                }
            }
        }
    };

    let winner = futures_util::future::select(
        Box::pin(futures_util::future::join(upstream, downlink)),
        Box::pin(idle_timer),
    )
    .await;

    // Which side won decides how the client experienced this session: the
    // timer's win drops both relays mid-await and the GET body just stops,
    // indistinguishable from a clean end on an unframed codec. That is exactly
    // the truncation signature we are hunting.
    match winner {
        Either::Left(_) => diag.session_end.set(Some(SessionEnd::RelaysDone)),
        Either::Right(_) => {
            diag.session_end.set(Some(SessionEnd::IdleTimerFired));
            // A timer kill is never normal; surface it even without the KV
            // binding so a bench run sees it in the worker logs.
            worker::console_log!("trinity-diag sid={} idle_timer_fired", sid);
        }
    }
    // Last-known-good bookkeeping, once per session at teardown. Only a win
    // by a genuine proxy candidate records a preference: a direct win would
    // write this session's destination host into shared state where it could
    // never help another session. Every error on the way out is ignored — a
    // failed bookkeeping write must never turn a finished tunnel into an
    // observable failure.
    if let Some(winner_target) = plan.candidates.get(winner_idx) {
        if *winner_target != plan.logical
            && outbound_state::should_record(winner_target, &known_state, now_ms())
        {
            let learned = OutboundState {
                preferred: Some(outbound_state::candidate_key(winner_target)),
                updated_at_ms: now_ms(),
            };
            if let Ok(document) = serde_json::to_string(&learned) {
                if let Ok(kv) = env.kv("SETTINGS") {
                    if let Ok(pending) = kv.put(outbound_state::KV_KEY, document) {
                        let _ = pending.execute().await;
                    }
                }
            }
        }
    }
    publish(&diag, &sid, &env).await;
}

/// Opt-in publication: only when the deployment carries a `SESSION_DIAG`
/// binding does teardown write the counters to KV. Production never sets it,
/// so its sessions skip both the KV write and the log line entirely.
///
/// The lookup is `env.kv` rather than `env.var` deliberately: `var` demands
/// the bound value be a JS string and rejects a KV namespace outright, while
/// `kv` succeeds exactly when the binding exists — which is the whole opt-in.
async fn publish(diag: &SessionDiag, sid: &str, env: &Env) {
    let Ok(kv) = env.kv("SESSION_DIAG") else {
        return;
    };
    let key = format!("diag:{}-{}", now_ms(), sanitize_sid(sid));
    // Fire-and-forget would risk the isolate dying before the write lands;
    // this is once per session at teardown, so awaiting it costs nothing.
    // A one-day TTL keeps the namespace self-cleaning.
    match kv.put_bytes(&key, diag.to_json(sid).as_bytes()) {
        Ok(p) => {
            let _ = p.expiration_ttl(86_400).execute().await;
        }
        Err(_) => {}
    }
    worker::console_log!("trinity-diag {}", diag.to_json(sid));
}

/// Diag keys go into a KV name; keep it to the same charset `SessionId` already
/// enforces so a hostile id cannot smuggle separators into the key.
fn sanitize_sid(sid: &str) -> String {
    sid.chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        // Same bound the wire already imposes on a session id.
        .take(super::wire::MAX_SESSION_LEN)
        .collect()
}
