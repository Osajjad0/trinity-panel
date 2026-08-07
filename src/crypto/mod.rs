//! Cryptographic primitives written in-tree.
//!
//! Only what cannot be taken from a crate lives here, and each module states
//! why. Hand-rolled cryptography is a bad default; the bar for admitting
//! something to this directory is that a published, independent set of test
//! vectors exists to check it against.

pub mod base64;
pub mod blake3;
