//! Inbound proxy protocol parsers.
//!
//! Every parser in this module is a pure function over a byte slice. None of
//! them perform I/O, allocate per packet, or panic. That is deliberate: they
//! are the only code that touches attacker-controlled bytes before
//! authentication succeeds, so they are the part most worth keeping boring.
//!
//! # Behaviour behind Cloudflare's CDN
//!
//! | Protocol      | Behind CDN | Caveats                                        |
//! |---------------|------------|------------------------------------------------|
//! | VLESS         | Yes        | `flow` must be empty; Vision needs raw TLS      |
//! | VMess (AEAD)  | Yes        | `alterId` must be 0; Xray removed the field     |
//! | Trojan        | Yes        | Xray hard-errors on any non-empty `flow`        |
//! | Shadowsocks   | Yes        | 2022 ciphers only; needs a transport wrapper    |
//!
//! None of them can carry UDP, because the runtime has no outbound datagram
//! API. See `docs/research/phase-0-report.md` §3.

pub mod addr;
pub mod codec;
pub mod detect;
pub mod shadowsocks;
pub mod shadowsocks_body;
pub mod vmess;
pub mod vmess_body;
pub mod trojan;
pub mod uuid;
pub mod vless;

pub use addr::{AddrKind, Host, Target};
pub use detect::{Credentials, Kind};
pub use uuid::Uuid;

/// Why a parse did not produce a request.
///
/// [`ProtocolError::Incomplete`] is not a failure. Transport framing does not
/// align with protocol framing — a header can arrive split across two XHTTP
/// POSTs or two WebSocket frames — so the caller is expected to retain the
/// buffer and retry once more bytes arrive. Every other variant is terminal
/// and the connection should be dropped without a reply.
///
/// Dropping silently rather than returning an error to the peer is intentional:
/// a probe that can distinguish "wrong UUID" from "malformed header" learns
/// that something is listening. See `transport::decoy`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolError {
    /// Not enough bytes yet. Retain the buffer and retry.
    Incomplete,
    /// Version byte the parser does not implement.
    UnsupportedVersion(u8),
    /// Address type byte outside the protocol's enumeration.
    UnknownAddressType(u8),
    /// Address field was structurally invalid (empty domain, bad UTF-8, or a
    /// length that disagrees with the enumerated type).
    MalformedAddress,
    /// Command byte the runtime cannot service.
    UnsupportedCommand(u8),
    /// Credentials did not match. Never distinguish this from the others in
    /// anything observable by the peer.
    AuthFailed,
    /// A length prefix exceeded the protocol's own bound. Distinct from
    /// `Incomplete` so a caller never waits forever for bytes that would be
    /// rejected anyway.
    LengthExceeded,
}

impl core::fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Incomplete => f.write_str("incomplete header"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported version {v:#04x}"),
            Self::UnknownAddressType(t) => write!(f, "unknown address type {t:#04x}"),
            Self::MalformedAddress => f.write_str("malformed address"),
            Self::UnsupportedCommand(c) => write!(f, "unsupported command {c:#04x}"),
            Self::AuthFailed => f.write_str("authentication failed"),
            Self::LengthExceeded => f.write_str("length prefix out of range"),
        }
    }
}

/// A bounds-checked forward cursor.
///
/// Every read returns [`ProtocolError::Incomplete`] rather than panicking, so
/// no parse path can take down the isolate. This exists instead of
/// `std::io::Cursor` because `Cursor`'s `Read` impl reports a short read as
/// `Ok(n)` with a partial fill, which is exactly the case that must not be
/// confused with success here.
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

/// Largest single read [`Reader::take`] will serve.
///
/// Every header field in every supported protocol is orders of magnitude below
/// this — the largest is a 253-byte domain name. Payload is taken with
/// [`Reader::rest`], never `take`, so this bound never applies to bulk data.
const MAX_TAKE: usize = 64 * 1024;

impl<'a> Reader<'a> {
    #[inline]
    #[must_use]
    pub const fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Bytes consumed so far. Used by callers to split the header off the
    /// leading payload without re-scanning.
    #[inline]
    #[must_use]
    pub const fn position(&self) -> usize {
        self.pos
    }

    #[inline]
    #[must_use]
    pub const fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    #[inline]
    pub fn u8(&mut self) -> Result<u8, ProtocolError> {
        let b = *self.buf.get(self.pos).ok_or(ProtocolError::Incomplete)?;
        self.pos += 1;
        Ok(b)
    }

    #[inline]
    pub fn u16_be(&mut self) -> Result<u16, ProtocolError> {
        let s = self.take(2)?;
        Ok(u16::from_be_bytes([s[0], s[1]]))
    }

    /// Borrow the next `n` bytes. Borrowing rather than copying is what keeps
    /// header parsing allocation-free; the only allocation in the whole module
    /// is the domain name in [`Host::Domain`], which happens once per
    /// connection rather than once per packet.
    #[inline]
    pub fn take(&mut self, n: usize) -> Result<&'a [u8], ProtocolError> {
        // Reject implausible reads as terminal rather than resumable. Without
        // this, a corrupted length prefix yields `Incomplete`, and a caller
        // doing the correct thing — retain the buffer, wait for more bytes —
        // buffers forever for data that is never coming. That is a memory
        // exhaustion vector reachable before authentication.
        if n > MAX_TAKE {
            return Err(ProtocolError::LengthExceeded);
        }
        let end = self.pos.checked_add(n).ok_or(ProtocolError::LengthExceeded)?;
        let s = self.buf.get(self.pos..end).ok_or(ProtocolError::Incomplete)?;
        self.pos = end;
        Ok(s)
    }

    /// Remaining bytes without consuming them.
    #[inline]
    #[must_use]
    pub fn rest(&self) -> &'a [u8] {
        // `pos` is only ever advanced by checked reads, so it cannot exceed
        // `len` and this slice cannot panic.
        &self.buf[self.pos..]
    }
}

/// Constant-time equality for credential comparison.
///
/// A `==` on byte slices short-circuits on the first differing byte. Over many
/// attempts that leak is measurable even across a network, and the cost of
/// avoiding it on a 16-byte UUID is nil, so there is no reason to take the
/// risk. `black_box` prevents LLVM from reintroducing the early exit.
#[inline]
#[must_use]
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    core::hint::black_box(diff) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reader_reports_incomplete_not_panic() {
        let mut r = Reader::new(&[0x01]);
        assert_eq!(r.u8(), Ok(0x01));
        assert_eq!(r.u8(), Err(ProtocolError::Incomplete));
        assert_eq!(r.u16_be(), Err(ProtocolError::Incomplete));
        assert_eq!(r.take(4), Err(ProtocolError::Incomplete));
    }

    #[test]
    fn reader_rejects_overflowing_length() {
        let mut r = Reader::new(&[0u8; 8]);
        assert_eq!(r.take(usize::MAX), Err(ProtocolError::LengthExceeded));
    }

    #[test]
    fn reader_tracks_position_and_rest() {
        let mut r = Reader::new(&[1, 2, 3, 4, 5]);
        assert_eq!(r.take(2), Ok(&[1u8, 2][..]));
        assert_eq!(r.position(), 2);
        assert_eq!(r.remaining(), 3);
        assert_eq!(r.rest(), &[3, 4, 5]);
    }

    #[test]
    fn ct_eq_matches_semantics_of_eq() {
        assert!(ct_eq(b"abcd", b"abcd"));
        assert!(!ct_eq(b"abcd", b"abce"));
        assert!(!ct_eq(b"abc", b"abcd"));
        assert!(ct_eq(b"", b""));
    }
}
