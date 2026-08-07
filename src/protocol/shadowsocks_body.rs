//! Shadowsocks-2022 body codec.
//!
//! Shadowsocks-2022 encrypts everything from the salt onward, so the relay
//! cannot forward bytes for it. This module is what makes it servable:
//! [`split`] turns a parsed request into the halves the relay owns.
//!
//! # Response format, read off a reference server
//!
//! ```text
//! salt (fresh, same length as the request's)
//! AEAD #0: type(1)=1 | timestamp(8 BE) | request_salt(N) | first_len(2 BE) + tag
//! AEAD #1: first payload, exactly first_len bytes                         + tag
//! AEAD #2: chunk_length(2 BE)                                             + tag
//! AEAD #3: chunk                                                          + tag
//! ...
//! ```
//!
//! Two things follow from that shape, and both are why this was measured
//! rather than assumed.
//!
//! **The response header cannot be sent before there is data to send.** Its
//! `first_len` field describes a payload that has to be in hand when the header
//! is built, so there is no prologue to emit at connect time. A reference
//! server behaves the same way — nothing goes downstream until the destination
//! speaks. [`SsEncoder::encode`] therefore emits the salt and header on its
//! first call rather than [`prologue`](super::codec::Encoder::prologue)
//! returning them.
//!
//! **The echoed request salt is load-bearing.** The client checks that the
//! response echoes the salt it sent; getting it wrong is a connection the
//! client drops after apparently succeeding.
//!
//! # Counters count AEAD operations, not chunks
//!
//! Each payload chunk spends two: one on its two-byte length and one on its
//! body. The request stream has already spent two on the header, so the codec
//! resumes at 2. Counting chunks instead desynchronises after the first one,
//! and the symptom appears well downstream of the mistake.

use bytes::{Bytes, BytesMut};

use super::codec::CodecError;
use super::shadowsocks::{session_subkey, Cipher, Session, TAG};

/// Largest plaintext this codec puts in one downlink chunk.
///
/// The length field is a `u16`; implementations settle well below its maximum,
/// and 16 KiB is what the reference uses.
const MAX_PLAINTEXT: usize = 16 * 1024;

/// Largest chunk length this codec will accept on the uplink.
///
/// The length arrives authenticated, so this is a sanity bound rather than a
/// security boundary — but it still caps a single allocation.
const MAX_CHUNK: usize = u16::MAX as usize;

/// Header type byte for a server-to-client response.
const TYPE_RESPONSE: u8 = 1;

/// Build the two halves of a Shadowsocks-2022 session.
///
/// `entropy` supplies the response salt. It is passed in rather than generated
/// here so this module stays pure and testable on the host; the runtime is
/// what has access to a real random source.
///
/// # Errors
/// [`CodecError`] if the response direction's key cannot be derived.
pub fn split(session: &Session, entropy: &[u8; 32]) -> Result<(SsDecoder, SsEncoder), CodecError> {
    let key_len = session.method.key_len();

    let request_cipher = Cipher::new(session.method, &session.request_subkey[..key_len]);

    // A fresh salt per session is what keeps the response subkey — and so the
    // nonce sequence under it — from ever repeating across connections.
    let mut response_salt = [0u8; 32];
    response_salt[..key_len].copy_from_slice(&entropy[..key_len]);
    let response_subkey = session_subkey(&session.psk[..key_len], &response_salt[..key_len]);
    let response_cipher = Cipher::new(session.method, &response_subkey[..key_len]);

    let decoder = SsDecoder {
        cipher: request_cipher,
        counter: session.next_counter,
        pending: BytesMut::new(),
        pending_len: None,
        initial: (!session.initial.is_empty()).then(|| Bytes::from(session.initial.clone())),
        finished: false,
    };
    let encoder = SsEncoder {
        cipher: response_cipher,
        counter: 0,
        key_len,
        response_salt,
        request_salt: session.request_salt,
        now_secs: session.now_secs,
        sent_header: false,
    };
    Ok((decoder, encoder))
}

/// The uplink half: client ciphertext to destination plaintext.
pub struct SsDecoder {
    cipher: Cipher,
    counter: u64,
    /// Bytes of an incomplete chunk, retained between calls.
    pending: BytesMut,
    /// Length of a chunk whose body has not fully arrived.
    ///
    /// Held because its length chunk has already been opened and the counter
    /// already advanced; redrawing would use the wrong nonce for the body.
    pending_len: Option<usize>,
    /// Plaintext that came inside the request header, owed to the destination
    /// before anything else.
    initial: Option<Bytes>,
    finished: bool,
}

impl SsDecoder {
    /// Unwrap as many whole chunks as `input` completes.
    ///
    /// # Errors
    /// [`CodecError::Auth`] on a failed tag, [`CodecError::LengthExceeded`] on
    /// an implausible length.
    pub fn decode(&mut self, input: &[u8], out: &mut Vec<Bytes>) -> Result<(), CodecError> {
        // The header's own payload goes first, ahead of anything that arrives
        // later. Dropping it is the bug whose symptom is a destination TLS
        // handshake that hangs: the ClientHello was parsed off and discarded.
        if let Some(initial) = self.initial.take() {
            out.push(initial);
        }
        if self.finished {
            return Ok(());
        }
        self.pending.extend_from_slice(input);

        loop {
            match self.pending_len {
                None => {
                    if self.pending.len() < 2 + TAG {
                        return Ok(());
                    }
                    let sealed = self.pending.split_to(2 + TAG);
                    let plain =
                        self.cipher.open(self.counter, &sealed).ok_or(CodecError::Auth)?;
                    self.counter += 1;
                    let n = usize::from(u16::from_be_bytes([plain[0], plain[1]]));
                    if n == 0 || n > MAX_CHUNK {
                        return Err(CodecError::LengthExceeded);
                    }
                    self.pending_len = Some(n);
                }
                Some(n) => {
                    if self.pending.len() < n + TAG {
                        return Ok(()); // wait for the rest
                    }
                    let sealed = self.pending.split_to(n + TAG);
                    let plain =
                        self.cipher.open(self.counter, &sealed).ok_or(CodecError::Auth)?;
                    self.counter += 1;
                    self.pending_len = None;
                    out.push(Bytes::from(plain));
                }
            }
        }
    }
}

/// The downlink half: destination plaintext to client ciphertext.
pub struct SsEncoder {
    cipher: Cipher,
    counter: u64,
    key_len: usize,
    response_salt: [u8; 32],
    request_salt: [u8; 32],
    now_secs: u64,
    sent_header: bool,
}

impl SsEncoder {
    /// Wrap `input`, prefixing the session header on the first call.
    ///
    /// # Errors
    /// [`CodecError`] if a chunk cannot be sealed.
    pub fn encode(&mut self, input: &[u8]) -> Result<Bytes, CodecError> {
        if input.is_empty() {
            return Ok(Bytes::new());
        }
        let mut out = BytesMut::with_capacity(input.len() + 128);
        let mut rest = input;

        if !self.sent_header {
            // The header names the length of the payload that follows it, so
            // the first chunk is carried by the header rather than by a length
            // chunk of its own.
            let first = &rest[..rest.len().min(MAX_PLAINTEXT)];
            rest = &rest[first.len()..];

            let mut header = Vec::with_capacity(1 + 8 + self.key_len + 2);
            header.push(TYPE_RESPONSE);
            header.extend_from_slice(&self.now_secs.to_be_bytes());
            header.extend_from_slice(&self.request_salt[..self.key_len]);
            let first_len =
                u16::try_from(first.len()).map_err(|_| CodecError::LengthExceeded)?;
            header.extend_from_slice(&first_len.to_be_bytes());

            out.extend_from_slice(&self.response_salt[..self.key_len]);
            out.extend_from_slice(&self.seal(&header)?);
            out.extend_from_slice(&self.seal(first)?);
            self.sent_header = true;
        }

        for piece in rest.chunks(MAX_PLAINTEXT) {
            let len = u16::try_from(piece.len()).map_err(|_| CodecError::LengthExceeded)?;
            out.extend_from_slice(&self.seal(&len.to_be_bytes())?);
            out.extend_from_slice(&self.seal(piece)?);
        }
        Ok(out.freeze())
    }

    fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, CodecError> {
        let sealed = self.cipher.seal(self.counter, plaintext).ok_or(CodecError::Auth)?;
        self.counter += 1;
        Ok(sealed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::addr::Host;
    use crate::protocol::shadowsocks::{self, Credential};

    /// The pre-shared keys used by the capture harness. Throwaway test values,
    /// generated deterministically so a capture stays decodable.
    fn test_psk(key_len: usize) -> String {
        let raw: Vec<u8> = (0..key_len).map(|i| ((i * 7 + 3) % 256) as u8).collect();
        crate::subscription::encode::base64(&raw)
    }

    /// Real Xray v26.6.1 client handshakes, one per cipher, captured against a
    /// bare TCP listener. Ground truth for the request direction.
    mod capture {
        pub const AES128: &str = include_str!("../../tests/fixtures/ss2022_aes128.hex");
        pub const AES256: &str = include_str!("../../tests/fixtures/ss2022_aes256.hex");
        pub const CHACHA: &str = include_str!("../../tests/fixtures/ss2022_chacha.hex");
        pub const TIME_AES128: u64 = 1_785_099_257;
        pub const TIME_AES256: u64 = 1_785_099_264;
        pub const TIME_CHACHA: u64 = 1_785_099_272;
    }

    fn unhex(s: &str) -> Vec<u8> {
        let clean: String = s.chars().filter(char::is_ascii_hexdigit).collect();
        (0..clean.len() / 2)
            .map(|i| u8::from_str_radix(&clean[i * 2..i * 2 + 2], 16).unwrap_or(0))
            .collect()
    }

    struct Case {
        method: &'static str,
        hex: &'static str,
        time: u64,
        key_len: usize,
    }

    fn cases() -> Vec<Case> {
        vec![
            Case {
                method: "2022-blake3-aes-128-gcm",
                hex: capture::AES128,
                time: capture::TIME_AES128,
                key_len: 16,
            },
            Case {
                method: "2022-blake3-aes-256-gcm",
                hex: capture::AES256,
                time: capture::TIME_AES256,
                key_len: 32,
            },
            Case {
                method: "2022-blake3-chacha20-poly1305",
                hex: capture::CHACHA,
                time: capture::TIME_CHACHA,
                key_len: 32,
            },
        ]
    }

    fn parse_case(c: &Case) -> (shadowsocks::Request<'static>, Vec<u8>) {
        let buf: &'static [u8] = Box::leak(unhex(c.hex).into_boxed_slice());
        let cred = Credential::new(c.method, &test_psk(c.key_len)).expect("credential");
        let req = shadowsocks::parse(buf, std::slice::from_ref(&cred), c.time)
            .expect("real capture must parse");
        let payload = req.payload.to_vec();
        (req, payload)
    }

    #[test]
    fn decodes_every_real_capture_to_the_request_the_client_made() {
        // The test this module exists for: real ciphertext from a real client,
        // for all three ciphers, decrypted to the request it actually made.
        for c in cases() {
            let (req, payload) = parse_case(&c);
            assert_eq!(
                req.target.host,
                Host::Domain("example.com".into()),
                "{}",
                c.method
            );
            assert_eq!(req.target.port, 80);

            let (mut dec, _) = split(&req.session, &[0u8; 32]).expect("codec builds");
            let mut out = Vec::new();
            dec.decode(&payload, &mut out).expect("body decodes");
            let text = String::from_utf8_lossy(&out.concat()).into_owned();
            assert!(text.starts_with("GET / HTTP/1.1\r\n"), "{}: {text:?}", c.method);
            assert!(text.contains("Host: example.com"), "{}: {text:?}", c.method);
        }
    }

    #[test]
    fn a_wrong_key_length_is_refused_at_configuration_time() {
        // The most common Shadowsocks-2022 misconfiguration. Caught here it is
        // a startup error; missed, it fails inside a vendored library at
        // connection time with a message that points nowhere useful.
        assert!(Credential::new("2022-blake3-aes-256-gcm", &test_psk(16)).is_none());
        assert!(Credential::new("2022-blake3-aes-128-gcm", &test_psk(32)).is_none());
        assert!(Credential::new("2022-blake3-aes-128-gcm", &test_psk(16)).is_some());
        assert!(Credential::new("2022-blake3-aes-256-gcm", &test_psk(32)).is_some());
    }

    #[test]
    fn an_unknown_method_is_refused() {
        // Pre-2022 methods are deliberately not offered.
        for m in ["aes-128-gcm", "chacha20-ietf-poly1305", "rc4-md5", ""] {
            assert!(Credential::new(m, &test_psk(16)).is_none(), "{m} must be refused");
        }
    }

    #[test]
    fn the_replay_window_matches_the_measured_boundary() {
        // Measured against a reference server: ±29 accepted, ±31 rejected.
        let c = &cases()[0];
        let buf = unhex(c.hex);
        let cred = Credential::new(c.method, &test_psk(c.key_len)).expect("credential");
        let creds = std::slice::from_ref(&cred);

        for ahead in [0u64, 29] {
            for now in [c.time + ahead, c.time - ahead] {
                assert!(
                    shadowsocks::parse(&buf, creds, now).is_ok(),
                    "a clock {ahead}s out must still be accepted"
                );
            }
        }
        for ahead in [31u64, 600] {
            for now in [c.time + ahead, c.time - ahead] {
                assert!(
                    shadowsocks::parse(&buf, creds, now).is_err(),
                    "a clock {ahead}s out must be refused"
                );
            }
        }
    }

    #[test]
    fn a_prefix_of_a_real_handshake_stays_resumable() {
        // Transport framing does not align with protocol framing, so a header
        // split across two POSTs must not be treated as a failure.
        let c = &cases()[0];
        let buf = unhex(c.hex);
        let cred = Credential::new(c.method, &test_psk(c.key_len)).expect("credential");
        let creds = std::slice::from_ref(&cred);
        for cut in 1..buf.len().min(200) {
            // `Request` holds session key material and deliberately has no
            // `Debug`, so compare the error rather than the whole result.
            assert_eq!(
                shadowsocks::parse(&buf[..cut], creds, c.time).err(),
                Some(crate::protocol::ProtocolError::Incomplete),
                "prefix of {cut} bytes must remain resumable"
            );
        }
    }

    #[test]
    fn a_tampered_handshake_is_rejected() {
        let c = &cases()[0];
        let mut buf = unhex(c.hex);
        let cred = Credential::new(c.method, &test_psk(c.key_len)).expect("credential");
        // Flip a bit inside the AEAD-protected fixed header.
        buf[c.key_len + 2] ^= 0x01;
        assert!(shadowsocks::parse(&buf, std::slice::from_ref(&cred), c.time).is_err());
    }

    #[test]
    fn a_different_key_does_not_authenticate() {
        let c = &cases()[0];
        let buf = unhex(c.hex);
        let other = Credential::new(c.method, &crate::subscription::encode::base64(&[9u8; 16]))
            .expect("credential");
        assert!(shadowsocks::parse(&buf, std::slice::from_ref(&other), c.time).is_err());
    }

    #[test]
    fn the_response_begins_with_a_fresh_salt_and_echoes_the_request_salt() {
        // The client checks the echoed salt; getting it wrong is a connection
        // that appears to succeed and is then dropped.
        let c = &cases()[0];
        let (req, _) = parse_case(c);
        let entropy = [0x5au8; 32];
        let (_, mut enc) = split(&req.session, &entropy).expect("codec builds");

        let wire = enc.encode(b"hello").expect("encodes");
        assert_eq!(&wire[..c.key_len], &entropy[..c.key_len], "salt goes first, verbatim");
        // salt + sealed header + sealed payload.
        let header_len = 1 + 8 + c.key_len + 2;
        assert_eq!(wire.len(), c.key_len + header_len + TAG + 5 + TAG);
    }

    #[test]
    fn the_session_header_is_sent_only_once() {
        let c = &cases()[0];
        let (req, _) = parse_case(c);
        let (_, mut enc) = split(&req.session, &[7u8; 32]).expect("codec builds");
        let first = enc.encode(b"one").expect("encodes");
        let second = enc.encode(b"two").expect("encodes");
        // The second carries only a length chunk and its payload.
        assert_eq!(second.len(), 2 + TAG + 3 + TAG);
        assert!(first.len() > second.len());
    }

    #[test]
    fn an_empty_read_encodes_to_nothing() {
        // A zero-length chunk would be meaningless framing, and the header must
        // not be emitted with nothing behind it.
        let c = &cases()[0];
        let (req, _) = parse_case(c);
        let (_, mut enc) = split(&req.session, &[1u8; 32]).expect("codec builds");
        assert!(enc.encode(b"").expect("encodes").is_empty());
    }

    #[test]
    fn a_long_read_is_split_across_chunks_rather_than_refused() {
        let c = &cases()[0];
        let (req, _) = parse_case(c);
        let (_, mut enc) = split(&req.session, &[2u8; 32]).expect("codec builds");
        let big = vec![0x33u8; MAX_PLAINTEXT * 2 + 10];
        let wire = enc.encode(&big).expect("encodes");
        assert!(wire.len() > big.len(), "all of it must be carried");
    }

    /// A decoder keyed to read what an encoder built from the same session and
    /// entropy produces, positioned after the response header.
    ///
    /// The captures all carry their whole payload inside the request header, so
    /// they never exercise the chunked path. Pointing a decoder at the response
    /// stream is what reaches it. This is self-consistency rather than external
    /// truth, and is labelled as such — the captures above are the real check.
    fn mirror_after_header(session: &Session, entropy: &[u8; 32], key_len: usize) -> SsDecoder {
        let mut mirror = session.clone();
        mirror.request_subkey =
            super::session_subkey(&session.psk[..key_len], &entropy[..key_len]);
        mirror.initial = Vec::new();
        // The header and its first payload spend two operations.
        mirror.next_counter = 2;
        split(&mirror, &[0u8; 32]).expect("builds").0
    }

    #[test]
    fn chunked_payload_round_trips_through_its_own_framing() {
        for c in cases() {
            let (req, _) = parse_case(&c);
            let entropy = [0x11u8; 32];
            let (_, mut enc) = split(&req.session, &entropy).expect("builds");
            let _ = enc.encode(b"first").expect("encodes"); // spends the header

            let payload = b"the quick brown fox jumps over the lazy dog";
            let wire = enc.encode(payload).expect("encodes");
            let mut dec = mirror_after_header(&req.session, &entropy, c.key_len);
            let mut out = Vec::new();
            dec.decode(&wire, &mut out).expect("decodes");
            assert_eq!(out.concat(), payload, "{}", c.method);
        }
    }

    #[test]
    fn a_chunk_split_across_calls_still_decodes() {
        // A chunk can arrive across two XHTTP POSTs. The counter advances per
        // AEAD operation, so a length already opened must not be re-opened.
        let c = &cases()[0];
        let (req, _) = parse_case(c);
        let entropy = [0x21u8; 32];
        let (_, mut enc) = split(&req.session, &entropy).expect("builds");
        let _ = enc.encode(b"prime").expect("encodes");
        let wire = enc.encode(b"payload-across-a-boundary").expect("encodes");

        for cut in 1..wire.len() {
            let mut dec = mirror_after_header(&req.session, &entropy, c.key_len);
            let mut out = Vec::new();
            dec.decode(&wire[..cut], &mut out).expect("decodes");
            dec.decode(&wire[cut..], &mut out).expect("decodes");
            assert_eq!(out.concat(), b"payload-across-a-boundary", "split at {cut}");
        }
    }

    #[test]
    fn byte_at_a_time_delivery_decodes_identically() {
        let c = &cases()[0];
        let (req, _) = parse_case(c);
        let entropy = [0x22u8; 32];
        let (_, mut enc) = split(&req.session, &entropy).expect("builds");
        let _ = enc.encode(b"prime").expect("encodes");
        let wire = enc.encode(b"one-byte-at-a-time").expect("encodes");

        let mut dec = mirror_after_header(&req.session, &entropy, c.key_len);
        let mut out = Vec::new();
        for byte in &wire {
            dec.decode(&[*byte], &mut out).expect("decodes");
        }
        assert_eq!(out.concat(), b"one-byte-at-a-time");
    }

    #[test]
    fn a_tampered_chunk_is_rejected() {
        let c = &cases()[0];
        let (req, _) = parse_case(c);
        let entropy = [0x31u8; 32];
        let (_, mut enc) = split(&req.session, &entropy).expect("builds");
        let _ = enc.encode(b"prime").expect("encodes");
        let mut wire = enc.encode(b"payload").expect("encodes").to_vec();
        wire[3] ^= 0x01;

        let mut dec = mirror_after_header(&req.session, &entropy, c.key_len);
        let mut out = Vec::new();
        assert_eq!(dec.decode(&wire, &mut out), Err(CodecError::Auth));
    }

    #[test]
    fn the_initial_payload_is_emitted_before_anything_else() {
        let c = &cases()[0];
        let (req, _) = parse_case(c);
        let (mut dec, _) = split(&req.session, &[0u8; 32]).expect("builds");
        let mut out = Vec::new();
        dec.decode(b"", &mut out).expect("decodes");
        assert!(!out.is_empty(), "the header's payload must not be withheld");
        assert!(String::from_utf8_lossy(&out.concat()).starts_with("GET / "));
    }

    #[test]
    fn never_panics_on_arbitrary_input() {
        let cred = Credential::new("2022-blake3-aes-128-gcm", &test_psk(16)).expect("credential");
        let creds = std::slice::from_ref(&cred);
        let mut seed = 0x7a3c_1199_ffee_2210u64;
        for _ in 0..3000 {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            let len = (seed % 300) as usize;
            let junk: Vec<u8> = (0..len).map(|i| (seed >> (i % 56)) as u8).collect();
            let _ = shadowsocks::parse(&junk, creds, 1_785_099_257);
        }
    }
}
