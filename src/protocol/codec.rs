//! Body codecs.
//!
//! The relay was built on an assumption that holds for only half the
//! protocols: that once the header is parsed, bytes can be forwarded
//! untouched. That is true of VLESS and Trojan, whose payload is plaintext
//! inside the transport's own TLS. It is false of VMess and Shadowsocks-2022,
//! both of which wrap the payload in chunked AEAD under keys negotiated during
//! the handshake.
//!
//! Both were confirmed by capturing a real client handshake rather than by
//! reading a specification: a Shadowsocks-2022 capture from Xray contains no
//! plaintext at all — not even the destination hostname — from the salt
//! onward.
//!
//! # Why this is a type rather than an `if`
//!
//! Forwarding raw bytes for an encrypted protocol does not fail loudly. The
//! handshake succeeds, the connection establishes, data flows, and both ends
//! receive garbage. Nothing at the transport layer reports a problem, and the
//! symptom a user sees — "it connects but nothing loads" — points nowhere
//! near the cause.
//!
//! Making the transform explicit means a protocol cannot be registered for
//! serving without someone deciding what its body transform is. A new protocol
//! either supplies one or is not servable; there is no path where the question
//! goes unasked. The `match` arms below are exhaustive, so adding a protocol
//! without answering the question does not compile.
//!
//! # Why the two directions are separate types
//!
//! The relay runs uplink and downlink concurrently as one joined future, and
//! each direction needs `&mut` access for the whole session — an AEAD codec
//! carries a counter and a keystream that advance per chunk. One object owned
//! by both halves would need a `RefCell`, and a borrow held across an `.await`
//! there is a panic in a runtime where a panic kills the connection.
//!
//! Splitting removes the problem rather than guarding against it: the two
//! directions share no state to begin with, since each has its own key, IV,
//! counter and keystream. [`Decoder`] goes to the uplink task and [`Encoder`]
//! to the downlink, and neither can observe the other.
//!
//! # Contract
//!
//! Codecs are stateful and see the byte stream in arbitrary pieces. A chunk
//! boundary does not align with a transport frame — an AEAD chunk can arrive
//! split across two XHTTP POSTs — so an implementation must buffer a partial
//! chunk and emit nothing rather than failing. Emitting nothing is normal and
//! is not an error.
//!
//! Both halves take and return [`Bytes`] rather than slices so the plaintext
//! protocols stay genuinely zero-copy: forwarding a VLESS payload moves a
//! refcount and copies nothing.

use bytes::Bytes;

use super::shadowsocks_body::{SsDecoder, SsEncoder};
use super::vmess_body::{VmessDecoder, VmessEncoder};

/// Why a codec could not process a stream.
///
/// Every variant is terminal: an AEAD failure means the stream is corrupt or
/// forged, and there is no recovery that preserves integrity. The caller drops
/// the connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodecError {
    /// Authentication failed on a chunk. Corrupt stream, wrong key, or an
    /// attempt at tampering — indistinguishable, and all three end the same way.
    Auth,
    /// A chunk length exceeded what the protocol permits. Refused before it is
    /// used to size an allocation.
    LengthExceeded,
    /// The peer's framing is not what the protocol allows.
    Malformed,
    /// The peer negotiated a mode this server does not implement.
    ///
    /// Deliberately distinct from [`Self::Malformed`]: the client is not
    /// misbehaving, it asked for something honest that is not on offer. The
    /// refusal is the point — carrying a mode we cannot frame correctly would
    /// corrupt the tunnel silently.
    Unsupported,
}

impl core::fmt::Display for CodecError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Auth => f.write_str("chunk authentication failed"),
            Self::LengthExceeded => f.write_str("chunk length out of range"),
            Self::Malformed => f.write_str("malformed framing"),
            Self::Unsupported => f.write_str("unsupported body mode"),
        }
    }
}

/// Client to destination: unwraps whatever the protocol wraps the uplink in.
///
/// Boxed because the VMess half carries a cipher and a SHAKE reader, and an
/// enum sized for that would make the plaintext case pay for it. One
/// allocation per session, never per chunk.
pub enum Decoder {
    /// Payload is already plaintext; the transport's TLS is the confidentiality
    /// boundary. VLESS and Trojan.
    Plain,
    Vmess(Box<VmessDecoder>),
    Shadowsocks(Box<SsDecoder>),
}

impl Decoder {
    /// Unwrap one transport-sized piece of the uplink, appending whole
    /// plaintext chunks to `out`.
    ///
    /// `out` is supplied by the caller and reused across calls, so a steady
    /// stream costs no allocations once its capacity has settled. Appending
    /// nothing is normal — it means `input` completed less than one chunk.
    ///
    /// # Errors
    /// [`CodecError`] on authentication failure or invalid framing.
    pub fn decode(&mut self, input: Bytes, out: &mut Vec<Bytes>) -> Result<(), CodecError> {
        match self {
            // Moves a refcount; the payload is not copied.
            Self::Plain => {
                if !input.is_empty() {
                    out.push(input);
                }
                Ok(())
            }
            Self::Vmess(v) => v.decode(&input, out),
            Self::Shadowsocks(s) => s.decode(&input, out),
        }
    }
}

/// Destination to client: wraps the downlink as the protocol requires.
pub enum Encoder {
    /// Passes payload through, after an optional fixed reply header.
    ///
    /// The header differs per protocol and must be sent exactly once: VLESS
    /// expects two zero bytes, Trojan expects nothing at all. Sending VLESS's
    /// bytes on a Trojan stream would inject them into the client's data as
    /// though the destination had sent them.
    Plain { prologue: &'static [u8] },
    Vmess(Box<VmessEncoder>),
    /// Emits nothing at connect time. Its session header names the length of
    /// the payload that follows it, so it cannot be built before there is data
    /// to send — see [`super::shadowsocks_body`].
    Shadowsocks(Box<SsEncoder>),
}

impl Encoder {
    /// Bytes owed to the client before any payload. Empty after the first call.
    ///
    /// # Errors
    /// [`CodecError`] if the prologue cannot be constructed.
    pub fn prologue(&mut self) -> Result<Bytes, CodecError> {
        match self {
            Self::Plain { prologue } => {
                // Taking it is what makes a second call empty. A reply header
                // sent twice is corruption in the client's payload stream.
                let owed = core::mem::take(prologue);
                Ok(Bytes::from_static(owed))
            }
            Self::Vmess(v) => Ok(v.take_prologue()),
            Self::Shadowsocks(_) => Ok(Bytes::new()),
        }
    }

    /// Wrap one read from the destination.
    ///
    /// # Errors
    /// [`CodecError`] if the chunk cannot be sealed.
    pub fn encode(&mut self, input: Bytes) -> Result<Bytes, CodecError> {
        match self {
            Self::Plain { .. } => Ok(input),
            Self::Vmess(v) => v.encode(&input),
            Self::Shadowsocks(s) => s.encode(&input),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::vless;

    fn decode_all(d: &mut Decoder, input: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        d.decode(Bytes::copy_from_slice(input), &mut out).expect("decodes");
        out.concat()
    }

    #[test]
    fn plain_is_the_identity_on_the_payload() {
        let mut d = Decoder::Plain;
        assert_eq!(decode_all(&mut d, b"hello world"), b"hello world");

        let mut e = Encoder::Plain { prologue: &[] };
        assert_eq!(&e.encode(Bytes::from_static(b"back")).expect("encodes")[..], b"back");
    }

    #[test]
    fn plain_decode_does_not_copy_the_payload() {
        // The zero-copy property stated as a test: the handle that comes out
        // must point at the same allocation that went in, or the relay is
        // copying every byte it forwards.
        let input = Bytes::from(vec![7u8; 4096]);
        let addr = input.as_ptr();
        let mut out = Vec::new();
        Decoder::Plain.decode(input, &mut out).expect("decodes");
        assert_eq!(out.len(), 1);
        assert!(core::ptr::eq(out[0].as_ptr(), addr), "payload was copied");
    }

    #[test]
    fn a_reply_header_is_emitted_exactly_once() {
        let mut e = Encoder::Plain { prologue: &vless::RESPONSE_HEADER };
        assert_eq!(&e.prologue().expect("first")[..], &[0x00, 0x00]);
        assert!(e.prologue().expect("second").is_empty());
        assert!(e.prologue().expect("third").is_empty());
    }

    #[test]
    fn an_empty_prologue_stays_empty() {
        // Trojan's case: sending anything would corrupt the stream.
        let mut e = Encoder::Plain { prologue: &[] };
        assert!(e.prologue().expect("prologue").is_empty());
    }

    #[test]
    fn empty_input_produces_no_chunks_rather_than_an_empty_one() {
        // An empty chunk forwarded downstream is indistinguishable from EOF
        // for some consumers, so it must not be manufactured.
        let mut out = Vec::new();
        Decoder::Plain.decode(Bytes::new(), &mut out).expect("decodes");
        assert!(out.is_empty());
    }

    #[test]
    fn splitting_the_input_does_not_change_the_output() {
        // The property every codec must hold: transport framing is arbitrary,
        // so the concatenated output cannot depend on how input was chopped.
        let payload = b"the quick brown fox jumps over the lazy dog";
        let expected = decode_all(&mut Decoder::Plain, payload);

        for split in [1usize, 7, 20, payload.len() - 1] {
            let mut d = Decoder::Plain;
            let mut got: Vec<u8> = Vec::new();
            for part in [&payload[..split], &payload[split..]] {
                got.extend_from_slice(&decode_all(&mut d, part));
            }
            assert_eq!(got, expected, "split at {split}");
        }
    }

    #[test]
    fn the_output_buffer_is_reusable_across_calls() {
        // The relay keeps one `Vec` for the whole session, so a codec that
        // assumed an empty buffer would drop or duplicate chunks.
        let mut d = Decoder::Plain;
        let mut out = Vec::new();
        d.decode(Bytes::from_static(b"one"), &mut out).expect("decodes");
        d.decode(Bytes::from_static(b"two"), &mut out).expect("decodes");
        assert_eq!(out.concat(), b"onetwo");
    }

    #[test]
    fn codec_errors_describe_themselves_without_leaking() {
        // The text reaches logs, never the peer, and must not echo stream data.
        for e in [
            CodecError::Auth,
            CodecError::LengthExceeded,
            CodecError::Malformed,
            CodecError::Unsupported,
        ] {
            let s = e.to_string();
            assert!(!s.is_empty());
            assert!(s.is_ascii());
        }
    }
}
