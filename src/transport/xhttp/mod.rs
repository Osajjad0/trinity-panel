//! XHTTP (formerly SplitHTTP) server implementation.
//!
//! XHTTP carries a bidirectional byte stream over ordinary HTTP requests, which
//! is what makes it survivable behind a CDN that cannot do full-duplex HTTP/2.
//! It is the centrepiece of this project and the default transport.
//!
//! # Where the state lives
//!
//! `packet-up` and `stream-up` split one logical connection across separate
//! HTTP requests — a long-lived `GET` for the downlink and one or more `POST`s
//! for the uplink. The outbound TCP socket must therefore outlive the request
//! that opened it, and on this runtime only a Durable Object can do that:
//! sockets may not be created in global scope or shared across requests, and
//! module-level state has no isolate affinity. `stream-one` is the exception —
//! one request carries both directions, so it needs no Durable Object at all.
//!
//! [`wire`] holds everything that does *not* need that state: request
//! classification, session and sequence extraction, and padding validation.
//! Keeping it free of runtime types is what lets it be tested on the host.

#[cfg(target_arch = "wasm32")]
pub mod durable;
pub mod deadlines;
pub mod diag;
pub mod session;
pub mod supervise;
pub mod wire;

pub use session::{Accepted, QueueError, UploadQueue};
pub use wire::{
    classify, downlink_headers, validate_padding, Class, PaddingConfig, PaddingError,
    PaddingPlacement, PaddingRange, SessionId,
};

/// Default ceiling on a single uplink POST body, matching Xray's
/// `scMaxEachPostBytes`. A larger body is answered with `413`.
///
/// Measured 2026-09-24 (10 MB POST through this panel, enforced-US pool):
/// Xray's 1 MB default ceilings upload at ~1.2 MB/s while WS does ~2.8 MB/s on
/// the identical path; `scMaxEachPostBytes=2_000_000` on the client lifts the
/// same tunnel to ~4.8 MB/s, reproducibly. The 1 MB shape-consistency argument
/// is outweighed by a 4x upload win, and the URI emitter now advertises the
/// matching client knob, so the shapes stay in sync. `DEFAULT_MAX_BUFFERED_POSTS`
/// bounds the memory: 2 MB × 30 posts is far inside the isolate.
pub const DEFAULT_MAX_POST_BYTES: usize = 2_000_000;

/// Default reorder-buffer depth, matching Xray's `scMaxBufferedPosts`.
///
/// Uplink POSTs may arrive out of order; this is how many out-of-sequence
/// chunks are held before the session gives up. Raising it costs isolate
/// memory against a 128 MB limit shared with every other connection.
pub const DEFAULT_MAX_BUFFERED_POSTS: usize = 30;

/// Default minimum gap between uplink POSTs, matching `scMinPostsIntervalMs`.
///
/// Client-side hint only; the server does not enforce it. Lowering it
/// multiplies request count against the daily quota for negligible latency
/// benefit.
pub const DEFAULT_MIN_POST_INTERVAL_MS: u32 = 30;
