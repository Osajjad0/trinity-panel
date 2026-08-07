//! VMess AEAD body codec.
//!
//! VMess encrypts its payload, so the relay cannot forward bytes for it. This
//! module is what makes VMess servable: [`split`] turns a decoded handshake
//! into the [`Decoder`](super::codec::Decoder) and
//! [`Encoder`](super::codec::Encoder) halves the relay owns.
//!
//! # Chunk framing, established empirically
//!
//! Each direction is a sequence of chunks:
//!
//! ```text
//! +----------------------+---------------------+---------+
//! | masked length (2 BE) | ciphertext + tag    | padding |
//! +----------------------+---------------------+---------+
//! ```
//!
//! The length covers **ciphertext + tag + padding**, so the AEAD input is
//! `length - padding` bytes and the padding follows it unauthenticated.
//!
//! Both the mask and the padding length come from a SHAKE128 stream seeded
//! with that direction's IV, read two bytes at a time. **The padding length is
//! drawn before the mask**, and that ordering was not taken from a
//! specification — it was determined by decoding a real Xray handshake. The
//! other order was tried first, produced a plausible-looking 18553-byte chunk,
//! and failed. It is exactly the kind of detail that round-trips perfectly
//! against one's own encoder and fails against every real client.
//!
//! The AEAD nonce is the direction's IV with its first two bytes replaced by a
//! big-endian chunk counter, truncated to twelve bytes.
//!
//! # What the client negotiates, and what is refused
//!
//! The header's option byte and security byte together decide the framing.
//! Rather than assume one shape, both are read and anything unimplemented is
//! refused outright. The table below is measured, not remembered — each row is
//! a real Xray v26.6.1 client handshake captured against a bare listener:
//!
//! | client `security`   | option | flags                                    | served |
//! |---------------------|--------|------------------------------------------|--------|
//! | `auto` (default)    | `0x0d` | ChunkStream, ChunkMasking, GlobalPadding | yes    |
//! | `aes-128-gcm`       | `0x0d` | ChunkStream, ChunkMasking, GlobalPadding | yes    |
//! | `chacha20-poly1305` | `0x0d` | ChunkStream, ChunkMasking, GlobalPadding | yes    |
//! | `none`              | `0x05` | ChunkStream, ChunkMasking                | no     |
//! | `zero`              | `0x00` | *(none)*                                 | no     |
//!
//! Two findings from that table are load-bearing. `auto` — what a client uses
//! when the field is omitted, and therefore the overwhelmingly common case —
//! resolves to AES-128-GCM on any CPU with AES instructions and to
//! ChaCha20-Poly1305 otherwise, so **both ciphers are required** to serve the
//! default configuration across architectures. And `AuthenticatedLength`
//! (`0x10`) was never set by any of them, which is what makes the XOR-masked
//! two-byte length above the right thing to implement; it is still refused
//! explicitly rather than ignored, because a client that did set it would
//! otherwise have every chunk misread.
//!
//! `none` and `zero` disable body encryption. They are refused rather than
//! implemented: they are never chosen by default, they add a second framing
//! axis to every path in this file, and the failure mode of getting them
//! subtly wrong is a silently corrupt tunnel. Refusing is honest and the
//! client reports a clean failure. See `docs/` for the operator-facing note.
//!
//! # Direction keys
//!
//! The response uses different material from the request:
//! `respKey = SHA256(bodyKey)[..16]` and `respIV = SHA256(bodyIV)[..16]`, each
//! with its own counter and its own SHAKE stream. Under ChaCha20-Poly1305 that
//! 16-byte value is then widened by the same schedule as the request key.

use aes_gcm::aead::Aead;
use aes_gcm::{Aes128Gcm, Key, KeyInit, Nonce};
use bytes::{Bytes, BytesMut};
use chacha20poly1305::ChaCha20Poly1305;
use md5::Md5;
use sha2::{Digest, Sha256};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake128;

use super::codec::CodecError;

/// Largest chunk this codec will accept on the uplink.
///
/// The length arrives masked and unauthenticated, so it is bounded before it
/// is used to size anything.
const MAX_CHUNK: usize = 17 * 1024;

/// Largest plaintext this codec puts in one downlink chunk.
///
/// Matches the buffer size upstream clients read into. Longer reads from the
/// destination are split across several chunks rather than refused.
const MAX_PLAINTEXT: usize = 8 * 1024;

/// AEAD tag length. The same for both supported ciphers.
const TAG: usize = 16;

/// Padding is drawn modulo this, per the protocol.
const PADDING_MODULUS: u16 = 64;

// Option bits. Named here because the numbers alone say nothing about which
// ones change the framing.
const OPT_CHUNK_STREAM: u8 = 0x01;
const OPT_CHUNK_MASKING: u8 = 0x04;
const OPT_GLOBAL_PADDING: u8 = 0x08;

/// Security byte for AES-128-GCM.
const SEC_AES_128_GCM: u8 = 3;
/// Security byte for ChaCha20-Poly1305.
const SEC_CHACHA20_POLY1305: u8 = 4;

/// Everything the codec needs from a decoded handshake.
///
/// Grouped into one type so a caller cannot supply four of the five values and
/// have the fifth silently default — the security and option bytes are exactly
/// the ones an implementation is tempted to assume.
#[derive(Clone, Copy)]
pub struct Params {
    pub body_key: [u8; 16],
    pub body_iv: [u8; 16],
    pub security: u8,
    pub options: u8,
    pub response_v: u8,
}

// Manual, redacting: the derived form would print live session keys, and
// anything reachable by a stray debug log is one line away from a key in a
// production log stream.
impl core::fmt::Debug for Params {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Params")
            .field("body_key", &"<redacted>")
            .field("body_iv", &"<redacted>")
            .field("security", &self.security)
            .field("options", &self.options)
            .finish_non_exhaustive()
    }
}

// Key material must not participate in equality either; comparing sessions is
// never wanted and a derived `PartialEq` would be a non-constant-time compare
// over secrets.
impl PartialEq for Params {
    fn eq(&self, other: &Self) -> bool {
        self.security == other.security && self.options == other.options
    }
}
impl Eq for Params {}

/// Which AEAD wraps the body.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Security {
    Aes128Gcm,
    ChaCha20Poly1305,
}

impl Security {
    fn from_byte(b: u8) -> Result<Self, CodecError> {
        match b {
            SEC_AES_128_GCM => Ok(Self::Aes128Gcm),
            SEC_CHACHA20_POLY1305 => Ok(Self::ChaCha20Poly1305),
            // `none` (5) and `zero` (6) among others: honestly refused.
            _ => Err(CodecError::Unsupported),
        }
    }
}

/// How chunk lengths are framed, as negotiated by the option byte.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct Framing {
    masking: bool,
    padding: bool,
}

impl Framing {
    fn from_options(options: u8) -> Result<Self, CodecError> {
        // Anything outside the implemented set is refused rather than masked
        // off. `AuthenticatedLength` (0x10) in particular replaces the
        // two-byte masked length with an AEAD-sealed one, so ignoring the bit
        // would misread every chunk boundary.
        const KNOWN: u8 = OPT_CHUNK_STREAM | OPT_CHUNK_MASKING | OPT_GLOBAL_PADDING;
        if options & !KNOWN != 0 {
            return Err(CodecError::Unsupported);
        }
        // Without ChunkStream there is no chunk framing at all — the body is a
        // raw stream, which is the `zero` security mode.
        if options & OPT_CHUNK_STREAM == 0 {
            return Err(CodecError::Unsupported);
        }
        let masking = options & OPT_CHUNK_MASKING != 0;
        let padding = options & OPT_GLOBAL_PADDING != 0;
        // Padding is drawn from the masking keystream, so it cannot be present
        // without it. No client produces this; refuse rather than guess.
        if padding && !masking {
            return Err(CodecError::Unsupported);
        }
        Ok(Self { masking, padding })
    }
}

/// Either supported AEAD, chosen once per session.
///
/// An enum rather than a boxed trait object: the branch predicts perfectly and
/// this sits on the per-chunk path.
enum Cipher {
    Aes(Box<Aes128Gcm>),
    ChaCha(Box<ChaCha20Poly1305>),
}

impl Cipher {
    /// Build from a 16-byte VMess key.
    ///
    /// ChaCha20-Poly1305 needs 32 bytes, and VMess widens the 16 it has by
    /// `MD5(k) || MD5(MD5(k))`. Verified by decrypting a real capture, not
    /// taken from memory.
    fn new(security: Security, key: &[u8; 16]) -> Self {
        match security {
            Security::Aes128Gcm => {
                Self::Aes(Box::new(Aes128Gcm::new(Key::<Aes128Gcm>::from_slice(key))))
            }
            Security::ChaCha20Poly1305 => {
                let first = Md5::digest(key);
                let second = Md5::digest(first);
                let mut wide = [0u8; 32];
                wide[..16].copy_from_slice(&first);
                wide[16..].copy_from_slice(&second);
                Self::ChaCha(Box::new(ChaCha20Poly1305::new((&wide).into())))
            }
        }
    }

    fn seal(&self, nonce: &[u8; 12], plaintext: &[u8]) -> Result<Vec<u8>, CodecError> {
        match self {
            Self::Aes(c) => c.encrypt(Nonce::from_slice(nonce), plaintext),
            Self::ChaCha(c) => c.encrypt(nonce.into(), plaintext),
        }
        .map_err(|_| CodecError::Auth)
    }

    fn open(&self, nonce: &[u8; 12], ciphertext: &[u8]) -> Result<Vec<u8>, CodecError> {
        match self {
            Self::Aes(c) => c.decrypt(Nonce::from_slice(nonce), ciphertext),
            Self::ChaCha(c) => c.decrypt(nonce.into(), ciphertext),
        }
        .map_err(|_| CodecError::Auth)
    }
}

/// One direction's cipher, keystream and counter.
struct Direction {
    cipher: Cipher,
    iv: [u8; 16],
    shake: sha3::Shake128Reader,
    counter: u16,
    framing: Framing,
}

impl Direction {
    fn new(security: Security, key: &[u8; 16], iv: &[u8; 16], framing: Framing) -> Self {
        let mut hasher = Shake128::default();
        hasher.update(iv);
        Self {
            cipher: Cipher::new(security, key),
            iv: *iv,
            shake: hasher.finalize_xof(),
            counter: 0,
            framing,
        }
    }

    /// Next two bytes of the keystream, big-endian.
    fn next_u16(&mut self) -> u16 {
        let mut b = [0u8; 2];
        self.shake.read(&mut b);
        u16::from_be_bytes(b)
    }

    /// Draw this chunk's padding length and length mask, in that order.
    ///
    /// The order is not arbitrary and neither draw may be skipped
    /// conditionally at the call site: both come from one stream, so reading
    /// them out of order or reading one when the peer read two desynchronises
    /// every chunk that follows.
    fn next_framing(&mut self) -> (usize, u16) {
        let padding =
            if self.framing.padding { usize::from(self.next_u16() % PADDING_MODULUS) } else { 0 };
        let mask = if self.framing.masking { self.next_u16() } else { 0 };
        (padding, mask)
    }

    /// The nonce for the current chunk, advancing the counter.
    fn next_nonce(&mut self) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&self.iv[..12]);
        nonce[..2].copy_from_slice(&self.counter.to_be_bytes());
        self.counter = self.counter.wrapping_add(1);
        nonce
    }
}

/// Build the two halves of a VMess session.
///
/// # Errors
/// [`CodecError::Unsupported`] if the client negotiated a cipher or framing
/// this server does not implement — see the table in the module docs. Refusing
/// here is deliberate: the alternative is a tunnel that connects and corrupts.
pub fn split(params: &Params) -> Result<(VmessDecoder, VmessEncoder), CodecError> {
    let security = Security::from_byte(params.security)?;
    let framing = Framing::from_options(params.options)?;

    let resp_key = sha256_16(&params.body_key);
    let resp_iv = sha256_16(&params.body_iv);

    let decoder = VmessDecoder {
        dir: Direction::new(security, &params.body_key, &params.body_iv, framing),
        pending: BytesMut::new(),
        peeked: None,
        finished: false,
    };
    let encoder = VmessEncoder {
        dir: Direction::new(security, &resp_key, &resp_iv, framing),
        prologue: Some(seal_response_header(&resp_key, &resp_iv, params.response_v)?),
    };
    Ok((decoder, encoder))
}

/// First sixteen bytes of SHA-256, used to derive the response direction.
fn sha256_16(input: &[u8; 16]) -> [u8; 16] {
    let digest = Sha256::digest(input);
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest[..16]);
    out
}

/// Build the AEAD-sealed response header.
///
/// Four plaintext bytes: the echoed verification byte, an options byte, and a
/// command with its length — both zero here, since this server issues no
/// dynamic-port commands.
///
/// Always AES-128-GCM regardless of the body cipher: the response header is
/// part of the AEAD handshake, not of the body stream.
fn seal_response_header(
    resp_key: &[u8; 16],
    resp_iv: &[u8; 16],
    response_v: u8,
) -> Result<Bytes, CodecError> {
    let header = [response_v, 0x00, 0x00, 0x00];

    let len_key = super::vmess::kdf16(resp_key, b"AEAD Resp Header Len Key");
    let len_iv = super::vmess::kdf12(resp_iv, b"AEAD Resp Header Len IV");
    let payload_key = super::vmess::kdf16(resp_key, b"AEAD Resp Header Key");
    let payload_iv = super::vmess::kdf12(resp_iv, b"AEAD Resp Header IV");

    let len_cipher = Aes128Gcm::new(Key::<Aes128Gcm>::from_slice(&len_key));
    let header_len = u16::try_from(header.len()).map_err(|_| CodecError::LengthExceeded)?;
    let sealed_len = len_cipher
        .encrypt(Nonce::from_slice(&len_iv), &header_len.to_be_bytes()[..])
        .map_err(|_| CodecError::Auth)?;

    let payload_cipher = Aes128Gcm::new(Key::<Aes128Gcm>::from_slice(&payload_key));
    let sealed_header = payload_cipher
        .encrypt(Nonce::from_slice(&payload_iv), &header[..])
        .map_err(|_| CodecError::Auth)?;

    let mut out = BytesMut::with_capacity(sealed_len.len() + sealed_header.len());
    out.extend_from_slice(&sealed_len);
    out.extend_from_slice(&sealed_header);
    Ok(out.freeze())
}

/// The uplink half: client ciphertext to destination plaintext.
pub struct VmessDecoder {
    dir: Direction,
    /// Bytes of an incomplete chunk, retained between calls.
    pending: BytesMut,
    /// Keystream values drawn for a chunk whose body has not fully arrived.
    ///
    /// The SHAKE stream advances once per chunk, not once per call. Redrawing
    /// it when a partial chunk is retried would desynchronise the mask for the
    /// remainder of the session — which surfaces as corruption several chunks
    /// later, nowhere near the cause.
    peeked: Option<(usize, u16)>,
    /// Set by the protocol's zero-length end-of-stream marker.
    finished: bool,
}

impl VmessDecoder {
    /// Unwrap as many whole chunks as `input` completes.
    ///
    /// # Errors
    /// [`CodecError`] on authentication failure or an out-of-range length.
    pub fn decode(&mut self, input: &[u8], out: &mut Vec<Bytes>) -> Result<(), CodecError> {
        if self.finished {
            return Ok(());
        }
        self.pending.extend_from_slice(input);

        loop {
            if self.pending.len() < 2 {
                return Ok(());
            }

            // Peek without consuming: the keystream must not advance until a
            // whole chunk is present, or a chunk split across two transport
            // frames would desynchronise the mask permanently.
            let (padding, mask) = if let Some(v) = self.peeked {
                v
            } else {
                let v = self.dir.next_framing();
                self.peeked = Some(v);
                v
            };
            let size = usize::from(u16::from_be_bytes([self.pending[0], self.pending[1]]) ^ mask);

            if size < TAG + padding || size > MAX_CHUNK {
                return Err(CodecError::LengthExceeded);
            }
            if self.pending.len() < 2 + size {
                return Ok(()); // wait for the rest
            }

            // Commit: the chunk is whole, so the drawn keystream is spent.
            self.peeked = None;
            let _ = self.pending.split_to(2);
            let chunk = self.pending.split_to(size);
            let nonce = self.dir.next_nonce();
            let plaintext = self.dir.cipher.open(&nonce, &chunk[..size - padding])?;

            // A zero-length chunk is the protocol's end-of-stream marker.
            if plaintext.is_empty() {
                self.finished = true;
                return Ok(());
            }
            out.push(Bytes::from(plaintext));
        }
    }
}

/// The downlink half: destination plaintext to client ciphertext.
pub struct VmessEncoder {
    dir: Direction,
    prologue: Option<Bytes>,
}

impl VmessEncoder {
    /// The encrypted response header, owed to the client before any payload.
    pub fn take_prologue(&mut self) -> Bytes {
        self.prologue.take().unwrap_or_default()
    }

    /// Wrap `input`, splitting it across chunks if it exceeds one.
    ///
    /// Splitting rather than refusing keeps the caller free to read whatever
    /// size the destination happens to deliver.
    ///
    /// # Errors
    /// [`CodecError`] if a chunk cannot be sealed.
    pub fn encode(&mut self, input: &[u8]) -> Result<Bytes, CodecError> {
        if input.is_empty() {
            return Ok(Bytes::new());
        }
        // Upper bound, so the common single-chunk case allocates exactly once.
        let chunks = input.len().div_ceil(MAX_PLAINTEXT);
        let mut out = BytesMut::with_capacity(
            input.len() + chunks * (2 + TAG + usize::from(PADDING_MODULUS)),
        );

        for piece in input.chunks(MAX_PLAINTEXT) {
            let (padding, mask) = self.dir.next_framing();
            let nonce = self.dir.next_nonce();
            let sealed = self.dir.cipher.seal(&nonce, piece)?;

            let size = sealed.len() + padding;
            let size_u16 = u16::try_from(size).map_err(|_| CodecError::LengthExceeded)?;
            out.extend_from_slice(&(size_u16 ^ mask).to_be_bytes());
            out.extend_from_slice(&sealed);
            // Padding content is never inspected by the peer; zeros are as
            // valid as anything and avoid needing randomness on the hot path.
            out.extend_from_slice(&[0u8; PADDING_MODULUS as usize][..padding]);
        }
        Ok(out.freeze())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::vmess;

    /// UUID that produced the capture below.
    const CAPTURE_UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

    /// A real Xray v26.6.1 client handshake, captured against a bare TCP
    /// listener with a known UUID and destination.
    ///
    /// This is the ground truth for the module. Every framing decision in it is
    /// checked by decrypting bytes a real client produced, because an encoder
    /// and decoder that share one misunderstanding agree perfectly.
    const CAPTURE: &[&str] = &[
        "85eba963bc26d8436ed75d24718da61fd3ed9daaf5eb0ab647f81a9bf2687227a99ea2a53c3dd7f6ebd53bb285663e7d",
        "25e8e8baccc8fa175136a2f7c05e1cf5645c5a39fe20caad76ad1d1c55df3bbf8d67fad13bc513d590e7d350aa817dd7",
        "34796e45f5cbf66ba8418e1c219fa040a257ee277a1a6b75472524107ce3d5c1da8045f9243839311d7540730fabe890",
        "06e754a8e1e85f4377f4a2c6e0a351276b9a26d80b5672c4fb0622df45853779aa8ff436745a7b5e3633968ad721a4af",
        "bf6811be400b197c02392e297388185a2a3672c61fe92949924ee2793312d52077961cd5d9e5f1cf54670029a3d8442e",
        "7c34c9",
    ];
    const CAPTURE_TIME: u64 = 1_785_094_069;

    fn capture_bytes() -> Vec<u8> {
        let hex: String = CAPTURE.concat();
        (0..hex.len() / 2)
            .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap_or(0))
            .collect()
    }

    fn params_of(req: &vmess::Request<'_>) -> Params {
        Params {
            body_key: req.body_key,
            body_iv: req.body_iv,
            security: req.security,
            options: req.options,
            response_v: req.response_v,
        }
    }

    /// Parse the capture and return its halves plus the encrypted body bytes.
    fn halves_and_body() -> (VmessDecoder, VmessEncoder, Vec<u8>) {
        let buf = capture_bytes();
        let uuid = crate::protocol::uuid::parse(CAPTURE_UUID).unwrap_or([0; 16]);
        let cred = vmess::credential_for(&uuid);
        let req =
            vmess::parse(&buf, std::slice::from_ref(&cred), CAPTURE_TIME).expect("capture parses");
        let (d, e) = split(&params_of(&req)).expect("codec builds");
        (d, e, req.payload.to_vec())
    }

    fn decode_all(d: &mut VmessDecoder, input: &[u8]) -> Vec<Bytes> {
        let mut out = Vec::new();
        d.decode(input, &mut out).expect("decodes");
        out
    }

    #[test]
    fn the_capture_negotiated_the_framing_this_module_implements() {
        // Pins the measurement the module docs describe. If a future capture
        // is swapped in with different options, this fails loudly rather than
        // letting the table drift out of date.
        let buf = capture_bytes();
        let uuid = crate::protocol::uuid::parse(CAPTURE_UUID).unwrap_or([0; 16]);
        let cred = vmess::credential_for(&uuid);
        let req =
            vmess::parse(&buf, std::slice::from_ref(&cred), CAPTURE_TIME).expect("capture parses");
        assert_eq!(req.options, 0x0d, "ChunkStream | ChunkMasking | GlobalPadding");
        assert_eq!(req.security, SEC_AES_128_GCM);
    }

    #[test]
    fn decodes_the_real_encrypted_body() {
        // The test this module exists for: real ciphertext from a real client,
        // decrypted to the request that client actually made.
        let (mut d, _, body) = halves_and_body();
        let plaintext: Vec<u8> = decode_all(&mut d, &body).concat();
        let text = String::from_utf8_lossy(&plaintext);

        assert!(text.starts_with("GET / HTTP/1.1\r\n"), "got: {text:?}");
        assert!(text.contains("Host: example.com"), "got: {text:?}");
    }

    #[test]
    fn a_chunk_split_across_calls_still_decodes() {
        // Transport framing does not align with chunk framing: an AEAD chunk
        // can arrive across two XHTTP POSTs. The keystream must advance once
        // per chunk, not once per call, or the mask desynchronises and every
        // later chunk fails.
        let (_, _, body) = halves_and_body();
        let expected: Vec<u8> = {
            let (mut d, _, b) = halves_and_body();
            decode_all(&mut d, &b).concat()
        };

        for split_at in [1usize, 2, 3, 17, body.len() / 2, body.len() - 1] {
            let (mut d, _, _) = halves_and_body();
            let mut got: Vec<u8> = Vec::new();
            for part in [&body[..split_at], &body[split_at..]] {
                got.extend_from_slice(&decode_all(&mut d, part).concat());
            }
            assert_eq!(got, expected, "split at {split_at}");
        }
    }

    #[test]
    fn byte_at_a_time_delivery_decodes_identically() {
        // The pathological case, and the one that catches a keystream drawn
        // per call rather than per chunk.
        let expected: Vec<u8> = {
            let (mut d, _, b) = halves_and_body();
            decode_all(&mut d, &b).concat()
        };
        let (mut d, _, body) = halves_and_body();
        let mut got: Vec<u8> = Vec::new();
        for byte in &body {
            got.extend_from_slice(&decode_all(&mut d, &[*byte]).concat());
        }
        assert_eq!(got, expected);
    }

    #[test]
    fn a_tampered_chunk_is_rejected() {
        let (mut d, _, mut body) = halves_and_body();
        // Flip a bit inside the AEAD-protected region, past the length field.
        body[8] ^= 0x01;
        let mut out = Vec::new();
        assert_eq!(d.decode(&body, &mut out), Err(CodecError::Auth));
    }

    #[test]
    fn the_response_header_is_produced_once() {
        let (_, mut e, _) = halves_and_body();
        // 2-byte length + 16 tag, then 4-byte header + 16 tag.
        assert_eq!(e.take_prologue().len(), 18 + 20);
        assert!(e.take_prologue().is_empty());
    }

    #[test]
    fn encode_produces_framing_of_the_expected_shape() {
        let (_, mut e, _) = halves_and_body();
        let out = e.encode(b"hello").expect("encodes");
        // 2-byte masked length, then ciphertext+tag, then padding under 64.
        assert!(out.len() >= 2 + 5 + TAG);
        assert!(out.len() < 2 + 5 + TAG + usize::from(PADDING_MODULUS));
    }

    #[test]
    fn a_long_read_is_split_across_chunks_rather_than_refused() {
        // The destination decides how much arrives at once, so refusing a
        // large read would drop traffic the relay is obliged to carry.
        let (_, mut e, _) = halves_and_body();
        let big = vec![0x5au8; MAX_PLAINTEXT * 2 + 100];
        let out = e.encode(&big).expect("encodes");
        assert!(out.len() > big.len(), "must carry all of it plus framing");
        assert!(out.len() < big.len() + 3 * (2 + TAG + usize::from(PADDING_MODULUS)));
    }

    #[test]
    fn an_empty_read_encodes_to_nothing() {
        // A zero-length chunk is the end-of-stream marker, so it must never be
        // manufactured from an ordinary empty read.
        let (_, mut e, _) = halves_and_body();
        assert!(e.encode(b"").expect("encodes").is_empty());
    }

    #[test]
    fn never_panics_on_arbitrary_ciphertext() {
        let mut seed = 0x1234_9876_abcd_ef01u64;
        for _ in 0..1500 {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            let (mut d, _, _) = halves_and_body();
            let len = (seed % 400) as usize;
            let junk: Vec<u8> = (0..len).map(|i| (seed >> (i % 56)) as u8).collect();
            let mut out = Vec::new();
            let _ = d.decode(&junk, &mut out);
        }
    }

    // --- negotiation ------------------------------------------------------

    fn params_with(security: u8, options: u8) -> Params {
        Params { body_key: [1u8; 16], body_iv: [2u8; 16], security, options, response_v: 0x2a }
    }

    /// Why a negotiation was refused, or `None` if it was accepted.
    ///
    /// Deliberately not `unwrap_err`: that needs `Debug` on the success type,
    /// and the codec halves hold a live IV that has no business being
    /// printable.
    fn refusal(security: u8, options: u8) -> Option<CodecError> {
        split(&params_with(security, options)).err()
    }

    #[test]
    fn both_aead_ciphers_are_accepted() {
        // `auto` resolves to one or the other depending on whether the
        // client's CPU has AES instructions, so refusing either would break
        // the default configuration on half the devices in use.
        for sec in [SEC_AES_128_GCM, SEC_CHACHA20_POLY1305] {
            assert!(split(&params_with(sec, 0x0d)).is_ok(), "security {sec} must be servable");
        }
    }

    #[test]
    fn unencrypted_body_modes_are_refused_not_misread() {
        // `none` (security 5, option 0x05) and `zero` (security 5, option
        // 0x00) are measured captures. Serving them with AEAD framing would
        // corrupt every byte; refusing gives the client a clean failure.
        assert_eq!(refusal(5, 0x05), Some(CodecError::Unsupported));
        assert_eq!(refusal(5, 0x00), Some(CodecError::Unsupported));
        assert_eq!(refusal(6, 0x00), Some(CodecError::Unsupported));
    }

    #[test]
    fn authenticated_length_is_refused_rather_than_ignored() {
        // The bit replaces the two-byte masked length with an AEAD-sealed one.
        // Masking it off would leave every chunk boundary misread — the exact
        // silent corruption this module exists to prevent.
        assert_eq!(refusal(SEC_AES_128_GCM, 0x0d | 0x10), Some(CodecError::Unsupported));
    }

    #[test]
    fn framing_without_chunk_stream_is_refused() {
        assert_eq!(refusal(SEC_AES_128_GCM, 0x00), Some(CodecError::Unsupported));
    }

    #[test]
    fn padding_without_masking_is_refused() {
        // Padding is drawn from the masking keystream, so the combination is
        // incoherent. No client emits it; guessing would desynchronise.
        assert_eq!(
            refusal(SEC_AES_128_GCM, OPT_CHUNK_STREAM | OPT_GLOBAL_PADDING),
            Some(CodecError::Unsupported)
        );
    }

    #[test]
    fn a_session_round_trips_through_its_own_framing() {
        // Weaker evidence than the capture above — an encoder and decoder that
        // share a misunderstanding agree perfectly — but it does cover the
        // combinations no capture exercises, such as masking without padding.
        for options in [OPT_CHUNK_STREAM, OPT_CHUNK_STREAM | OPT_CHUNK_MASKING, 0x0d] {
            for sec in [SEC_AES_128_GCM, SEC_CHACHA20_POLY1305] {
                let p = params_with(sec, options);
                // The encoder writes the response direction, so pair it with a
                // decoder keyed the same way to read it back.
                let (_, mut enc) = split(&p).expect("builds");
                let resp_key = sha256_16(&p.body_key);
                let resp_iv = sha256_16(&p.body_iv);
                let mirror = Params { body_key: resp_key, body_iv: resp_iv, ..p };
                let (mut dec, _) = split(&mirror).expect("builds");

                let payload = b"the quick brown fox jumps over the lazy dog";
                let wire = enc.encode(payload).expect("encodes");
                assert_eq!(
                    decode_all(&mut dec, &wire).concat(),
                    payload,
                    "options {options:#04x} security {sec}"
                );
            }
        }
    }

    #[test]
    fn params_debug_does_not_print_key_material() {
        // A stray debug log must not put a live session key in a log stream,
        // and the derived `Debug` would print all sixteen bytes of both.
        let p = Params {
            body_key: [0xAB; 16],
            body_iv: [0xCD; 16],
            security: SEC_AES_128_GCM,
            options: 0x0d,
            response_v: 0x2a,
        };
        let s = format!("{p:?}");
        assert_eq!(s.matches("<redacted>").count(), 2, "both key fields must be hidden");
        for leak in ["171", "205", "ab", "cd", "AB", "CD"] {
            assert!(!s.contains(leak), "key material leaked as {leak:?}: {s}");
        }
    }
}
