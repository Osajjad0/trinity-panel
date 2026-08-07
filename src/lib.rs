//! An XHTTP-first proxy panel for the Cloudflare Workers runtime, with a
//! translation layer that emits Xray, sing-box and mihomo configurations from
//! one source of truth.
//!
//! # Layout
//!
//! | Module          | Responsibility                                          |
//! |-----------------|---------------------------------------------------------|
//! | [`protocol`]    | Inbound protocol parsers. Pure, no I/O, no panics.       |
//! | [`transport`]   | XHTTP, WebSocket, and the decoy page.                    |
//! | `core_schema`   | Typed models of each core's configuration schema.        |
//! | `translate`     | One config in, three cores out, with honest degradation. |
//! | `panel`         | Authenticated admin UI and its API.                      |
//! | `subscription`  | Per-client subscription rendering.                       |
//! | `config`        | Runtime settings, bindings, and the unified model.       |
//!
//! Rust module paths cannot contain hyphens, so the `core-schema` directory
//! named in the project brief is `core_schema` here.
//!
//! # Testing strategy
//!
//! Everything that can be a pure function over bytes is one, and lives behind
//! no runtime dependency at all. That is why the `worker` crate is pulled in
//! only for `wasm32` targets: the protocol parsers and the XHTTP wire layer
//! compile and test on the host, so their test suites run in milliseconds
//! without a WASM harness or a live Cloudflare deployment.

#![forbid(unsafe_code)]
// A panic inside a WASM isolate is unrecoverable and kills every connection
// multiplexed onto that request. These two lints turn the project brief's "no
// unwrap or expect in any request-handling path" from a review convention into
// something the compiler enforces. Tests are exempt: a panic there is a test
// failure, which is exactly what it should be.
#![deny(clippy::unwrap_used, clippy::expect_used)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]
#![warn(clippy::pedantic)]
// The relay path deals in byte counts that are provably in range; the noise
// from these outweighs the signal.
#![allow(clippy::missing_errors_doc, clippy::module_name_repetitions)]
// These docs name products and protocols constantly — Xray, Cloudflare,
// WebSocket, ClientHello, SplitHTTP. Backticking a product name in prose is
// wrong: backticks mean "this is an identifier", and these are not.
#![allow(clippy::doc_markdown)]
// The fuzz helpers deliberately truncate a PRNG state down to a byte to
// generate input. That is the point of them, not an oversight.
#![cfg_attr(test, allow(clippy::cast_possible_truncation))]

pub mod config;
pub mod crypto;
pub mod panel;
pub mod path;
pub mod protocol;
pub mod relay;
pub mod router;
pub mod subscription;
pub mod translate;
pub mod transport;

// The Worker entry point and the Durable Object exist only on the deployment
// target. Gating them here is what keeps every other module testable on the
// host without a WASM harness.
#[cfg(target_arch = "wasm32")]
mod entry;

// Runtime randomness. Only the wasm target has a `crypto` global, and only
// Shadowsocks-2022 needs it; everything else takes entropy as an argument so
// it stays testable on the host.
#[cfg(target_arch = "wasm32")]
pub mod random;
