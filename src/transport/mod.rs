//! Transports that carry a proxy protocol over an HTTP request.
//!
//! # What this runtime can and cannot serve
//!
//! | Transport            | Servable | Why                                            |
//! |----------------------|----------|------------------------------------------------|
//! | XHTTP `packet-up`    | Yes      | Needs no duplex; needs a Durable Object         |
//! | XHTTP `stream-up`    | Probe    | Needs duplex; needs a Durable Object            |
//! | XHTTP `stream-one`   | Probe    | Needs duplex; single request, so no DO          |
//! | WebSocket            | Yes      | Single request; framed by the runtime           |
//! | gRPC                 | **No**   | Both modes are bidirectional HTTP/2 streams     |
//! | httpupgrade          | **No**   | A bare `101` cannot be constructed              |
//!
//! gRPC is worth being precise about, because `multiMode` is often described
//! as the CDN-friendly variant. It is not. Both modes are declared
//! `rpc Tun (stream Hunk) returns (stream Hunk)`; `multiMode` only batches
//! more buffers into each frame, cutting per-frame overhead by roughly a
//! fifth. It does not reduce the duplex requirement, so it is no more
//! deliverable here than plain `gun` mode.
//!
//! httpupgrade fails for a different reason. The runtime will only build a
//! `101` response that carries a `webSocket` property; a bare `101` throws,
//! and there is no API anywhere that yields the raw socket after the upgrade.
//! Xray's httpupgrade speaks unframed bytes after the handshake, so even a
//! successful upgrade would be unusable.
//!
//! # Fingerprint notes
//!
//! WebSocket is the most heavily classified transport in this space because
//! nearly every public panel uses nothing else, and its `Sec-WebSocket-Key`
//! handshake plus `ALPN: http/1.1` are trivially recognisable. It is therefore
//! opt-in and off by default here. See `docs/research/phase-0-report.md` §2 for
//! why running it alongside XHTTP couples the two transports' survival at the
//! hostname level rather than isolating them by path.

#[cfg(target_arch = "wasm32")]
pub mod websocket;
pub mod xhttp;
