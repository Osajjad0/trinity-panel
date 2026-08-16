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

use bytes::{Bytes, BytesMut};
use futures_util::StreamExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use worker::{
    wasm_bindgen_futures::spawn_local, Env, Request, Response, Result, WebSocket, WebSocketPair,
    WebsocketEvent,
};

use crate::config::{credentials_from_env, UserLists};
use crate::protocol::{detect, vless, ProtocolError};
use crate::relay::{self, connect};

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
pub fn handle(_req: &Request, env: &Env) -> Result<Response> {
    let pair = WebSocketPair::new()?;
    let server = pair.server;
    server.accept()?;

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

    spawn_local(async move {
        let outbound_cfg = crate::relay::outbound::load(&env_clone).await;
        // Errors are deliberately swallowed: there is nobody to report them to
        // that is not also the untrusted peer.
        let _ = serve(&server, creds, outbound_cfg).await;
        let _ = server.close(Some(1000), Some("bye"));
    });

    Response::from_websocket(pair.client)
}

/// Drive one accepted WebSocket connection.
/// Drive one accepted WebSocket connection.
async fn serve(
    server: &WebSocket,
    creds: detect::Credentials,
    outbound_cfg: crate::relay::outbound::OutboundConfig,
) -> core::result::Result<(), ()> {
    let mut events = server.events().map_err(|_| ())?;

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
                // Route through the outbound layer using the loaded config.
                // In Off mode this is a single direct candidate; with Proxy IP
                // or NAT64 each candidate's handshake is verified before use.
                let plan = outbound_cfg.resolve(&target);
                let sock = connect::open_with_plan(&plan).await.map_err(|_| ())?;

                match req.kind {
                    // VLESS needs its two-zero-byte reply, then any payload that
                    // rode in with the header. Dropping that payload is the
                    // classic bug whose symptom is a destination TLS handshake
                    // that hangs forever.
                    detect::Kind::Vless => {
                        if req.flow_requested {
                            return Err(());
                        }
                        server
                            .send_with_bytes(vless::RESPONSE_HEADER)
                            .map_err(|_| ())?;
                    }
                    // Trojan has no reply header. Authentication succeeded, the
                    // header was consumed by `detect`.
                    detect::Kind::Trojan => {}
                    _ => return Err(()),
                }
                pending.clear();
                break sock;
            }
        }
    };

    // Opened the upstream socket. From here the two directions must run in the
    // *same* task, joined. A downlink spawned as a separate `spawn_local`
    // belongs to whichever request happened to be executing and is cancelled
    // the moment that request's context finishes — the exact trap the XHTTP
    // relay documents. Joining here means this single `serve` task owns both
    // directions and neither can be orphaned or cancelled beneath the other.
    let (mut read_half, mut write_half) = tokio::io::split(socket);
    let who = server.clone();
    let downlink = async move {
        let mut buf = BytesMut::with_capacity(relay::INITIAL_BUFFER);
        loop {
            if buf.capacity() < relay::INITIAL_BUFFER {
                buf.reserve(relay::INITIAL_BUFFER - buf.capacity());
            }
            match read_half.read_buf(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    // O(1) detach; the payload is not copied.
                    let chunk: Bytes = buf.split_to(n).freeze();
                    if who.send_with_bytes(&chunk).is_err() {
                        break;
                    }
                }
            }
        }
        let _ = who.close(Some(1000), Some("eof"));
    };

    let uplink = async {
        while let Some(event) = events.next().await {
            let Ok(WebsocketEvent::Message(msg)) = event else {
                break;
            };
            let Some(bytes) = msg.bytes() else {
                break;
            };
            if AsyncWriteExt::write_all(&mut write_half, &bytes).await.is_err() {
                break;
            }
        }
    };

    futures_util::future::join(downlink, uplink).await;
    Ok(())
}
