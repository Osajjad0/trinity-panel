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

use bytes::{Bytes, BytesMut};
use futures_channel::mpsc;
use futures_util::{SinkExt, StreamExt};
use tokio::io::AsyncWriteExt;
// `wasm_bindgen` and `DurableObject` are not referenced anywhere below — the
// `#[durable_object]` macro expands to code that names them directly, so they
// must be in scope at the expansion site or the macro fails to compile.
use worker::{
    durable_object, wasm_bindgen, DurableObject, Env, Request, Response, Result, Socket, State,
};

use super::wire::{self, Class};
use super::{UploadQueue, DEFAULT_MAX_BUFFERED_POSTS, DEFAULT_MAX_POST_BYTES};
use crate::protocol::codec::{Decoder, Encoder};
use crate::protocol::{detect, Credentials, ProtocolError};
use crate::relay::{self, connect};

/// Total bytes the reorder buffer may hold for one session.
const MAX_BUFFER_BYTES: usize = 4 * 1024 * 1024;

/// Ceiling on bytes accumulated while waiting for a complete protocol header.
///
/// A VLESS header is at most a few hundred bytes. Without a cap, a peer could
/// dribble one byte per POST forever and hold an isolate open on a connection
/// that never authenticates.
const MAX_HEADER_BYTES: usize = 8 * 1024;

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
            Class::PacketUp { seq, .. } => self.uplink(req, seq).await,
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
    async fn uplink(&self, mut req: Request, seq: u64) -> Result<Response> {
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
                self.state.wait_until(own_session(rx, down, self.credentials()));
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

/// The single task that owns the outbound socket for one session.
///
/// Everything that touches the socket happens here, sequentially. No request
/// handler ever holds it, so no interleaving of requests can corrupt it and no
/// cancelled request can lose it.
async fn own_session(mut uplink: mpsc::Receiver<Bytes>, down: DownSender, creds: Credentials) {
    // Accumulate until a complete header parses. A header CAN arrive split
    // across chunks — transport framing does not align with protocol framing,
    // and a small scMaxEachPostBytes or an edge flush boundary is enough to
    // split it. Treating that as a failure would kill legitimate sessions.
    let mut header = BytesMut::new();
    let mut opened: Option<(Socket, Decoder, Encoder, Bytes)> = None;

    while opened.is_none() {
        let Some(chunk) = uplink.next().await else {
            return; // client vanished before completing the header
        };
        header.extend_from_slice(&chunk);
        if header.len() > MAX_HEADER_BYTES {
            return;
        }

        match detect::detect(&header, &creds, now_secs()) {
            // A valid prefix of some enabled protocol. Keep it, loop for more.
            Err(ProtocolError::Incomplete) => {}
            Err(_) => return,
            Ok(req) => {
                // Vision splices the TLS record stream and cannot survive a
                // CDN, which terminates TLS at the edge.
                if req.flow_requested {
                    return;
                }
                let Some(target) = req.target else { return };
                if !req.is_tcp {
                    // UDP needs a datagram API this runtime does not have;
                    // Mux needs framing this server does not implement.
                    return;
                }
                // Before the socket, because it can fail: a client that
                // negotiated a body mode this server cannot frame is refused
                // rather than served a corrupted tunnel. Authenticating and
                // then garbling every byte is strictly worse than declining.
                let Ok((decoder, encoder)) = req.body.split(&crate::random::bytes32())
                else {
                    return;
                };
                let Ok(sock) = connect::open(&target) else { return };
                opened = Some((sock, decoder, encoder, Bytes::copy_from_slice(req.payload)));
            }
        }
    }

    let Some((sock, mut decoder, encoder, leading)) = opened else { return };
    let (read_half, mut writer) = tokio::io::split(sock);

    // One buffer for the session's whole uplink. Reused across chunks so a
    // steady stream costs no allocations once its capacity has settled.
    let mut ready: Vec<Bytes> = Vec::new();

    // Forward whatever payload arrived alongside the header — through the
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
    // `!leading.is_empty()` strands that payload — the destination waits for a
    // request that was already delivered to us, the client waits for a
    // response, and the session hangs with nothing logged anywhere.
    if decoder.decode(leading, &mut ready).is_err() {
        return;
    }
    for piece in ready.drain(..) {
        if writer.write_all(&piece).await.is_err() {
            return;
        }
    }

    // Both directions run as one task rather than two. A nested `spawn_local`
    // would belong to whichever request happened to be executing, and would be
    // cancelled when that request finished — the same trap the outer task hit.
    // Joining them here means the single future handed to `wait_until` owns
    // everything, and neither direction can outlive or orphan the other.
    //
    // The two halves of the codec are owned one per direction, so neither
    // needs to reach the other's state and no shared borrow exists to be held
    // across an await.
    let upstream = async move {
        while let Some(chunk) = uplink.next().await {
            if decoder.decode(chunk, &mut ready).is_err() {
                break; // corrupt or forged; nothing recoverable follows
            }
            let mut failed = false;
            for piece in ready.drain(..) {
                if writer.write_all(&piece).await.is_err() {
                    failed = true;
                    break;
                }
            }
            if failed {
                break;
            }
        }
        // Closing the write half signals EOF to the destination rather than
        // leaving it waiting for a request body that will never arrive.
        let _ = writer.shutdown().await;
    };

    futures_util::future::join(upstream, pump_downlink(read_half, down, encoder)).await;
}

/// Read the destination's output and feed the downlink response body.
///
/// Sends the protocol's prologue first — VLESS's two reply bytes, VMess's
/// sealed response header, or nothing for Trojan — then relays until either
/// side closes.
async fn pump_downlink<R>(mut read_half: R, mut tx: DownSender, mut encoder: Encoder)
where
    R: tokio::io::AsyncRead + Unpin + 'static,
{
    use tokio::io::AsyncReadExt;

    let Ok(prologue) = encoder.prologue() else { return };
    if !prologue.is_empty() && tx.send(Ok(prologue)).await.is_err() {
        return;
    }

    let mut buf = BytesMut::with_capacity(relay::INITIAL_BUFFER);
    loop {
        if buf.capacity() < relay::INITIAL_BUFFER {
            buf.reserve(relay::INITIAL_BUFFER - buf.capacity());
        }
        match read_half.read_buf(&mut buf).await {
            // Destination closed, or failed. Dropping `tx` ends the client's
            // response stream, which is how the client learns.
            Ok(0) | Err(_) => break,
            Ok(n) => {
                // O(1) detach; the payload is not copied. For a plaintext
                // protocol the encoder hands the same handle straight back.
                let chunk = buf.split_to(n).freeze();
                let Ok(wrapped) = encoder.encode(chunk) else { break };
                if tx.send(Ok(wrapped)).await.is_err() {
                    break; // client hung up, which is ordinary
                }
            }
        }
    }
}
