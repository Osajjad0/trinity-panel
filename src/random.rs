//! Randomness from the runtime.
//!
//! Only Shadowsocks-2022 needs this, and it genuinely needs it: the response
//! salt derives the whole downlink key schedule, so a predictable or repeated
//! salt repeats a nonce sequence under a key an attacker may have seen traffic
//! under. It is not padding, and `Math.random` is not adequate for it.
//!
//! Bound directly to the platform's `crypto.getRandomValues` rather than
//! pulling in the usual crate. Every dependency added to this project has to
//! survive a toolchain that cannot link anything whose build script wants a C
//! compiler — the reason BLAKE3 and base64 are also written in-tree — and a
//! five-line import is not worth the risk of finding that out later.
//!
//! Compiled only for `wasm32`, because there is no other target this runs on.
//! The protocol code takes entropy as an argument precisely so it stays pure
//! and testable on the host without this module.

use worker::wasm_bindgen;
use worker::wasm_bindgen::prelude::wasm_bindgen;

#[wasm_bindgen]
extern "C" {
    /// The Web Crypto API, present in the Workers runtime as a global.
    #[wasm_bindgen(js_namespace = crypto, js_name = getRandomValues)]
    fn get_random_values(buf: &mut [u8]);
}

/// Thirty-two cryptographically random bytes.
///
/// Sized for the longest salt any supported method uses; shorter methods take
/// a prefix.
#[must_use]
pub fn bytes32() -> [u8; 32] {
    let mut buf = [0u8; 32];
    get_random_values(&mut buf);
    buf
}
