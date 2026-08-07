//! The administration panel: what it stores, who may use it, and what it serves.
//!
//! Split by responsibility rather than by request: [`auth`] decides whether a
//! request may proceed, [`store`] decides what state it acts on, and the
//! transport layer above wires them to HTTP. Keeping the decisions out of the
//! request handler is what lets both be tested on the host, with no runtime.

pub mod advisor;
pub mod api;
pub mod auth;

// The HTTP layer exists only on the runtime that has HTTP. Keeping it behind
// a cfg is what lets the decision modules above compile and test on the host.
#[cfg(target_arch = "wasm32")]
pub mod serve;
pub mod store;
