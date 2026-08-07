//! Shadowsocks-2022 (SIP022) inbound.
//!
//! **2022 ciphers only.** The pre-2022 AEAD methods derive their key from a
//! password with a construction nobody should still be deploying, and the
//! original stream ciphers are unauthenticated. Offering them would invite
//! clients into a mode this server should not be helping anyone use.
//!
//! # Wire format
//!
//! ```text
//! salt (16 or 32, matching the key length)
//! AEAD #0: type(1) | timestamp(8 BE) | variable_length(2 BE)      + 16 tag
//! AEAD #1: address | padding_len(2 BE) | padding | initial_payload + 16 tag
//! AEAD #2: chunk_length(2 BE) + 16 tag
//! AEAD #3: chunk + 16 tag
//! ...
//! ```
//!
//! The session key is `BLAKE3::derive_key("shadowsocks 2022 session subkey",
//! psk || salt)`, and the AEAD nonce is a little-endian counter in the low
//! eight bytes of twelve, incremented once per AEAD operation rather than once
//! per chunk — the length and its payload are two separate operations.
//!
//! Addresses use the **SOCKS5** table (`0x03` domain, `0x04` IPv6), not the
//! VLESS one.
//!
//! # Everything here was measured
//!
//! Nothing in the layout above was taken from a specification. Each row was
//! recovered by decrypting real Xray v26.6.1 client handshakes, one per cipher,
//! and the response format in [`super::shadowsocks_body`] was read off a
//! sing-box v1.13.13 server. Two details that a specification reading would
//! plausibly have got wrong:
//!
//! - The initial payload lives **inside** the variable-length header, after the
//!   padding, not in a chunk of its own. The captured lengths only add up that
//!   way: `15 + 2 + 815 + 75 = 907`.
//! - The replay window is **±30 seconds**, measured by walking a reference
//!   server's acceptance boundary, not the two minutes VMess uses.
//!
//! A real server also refuses a request carrying neither payload nor padding
//! (`bad request: missing payload or padding`). This parser accepts it: being
//! strict about it would reject nothing an attacker cannot trivially fix, while
//! risking rejection of a legitimate client that pads differently.
//!
//! # Behind Cloudflare's CDN
//!
//! Works, but only with a core that can wrap Shadowsocks in a transport — Xray
//! and sing-box can, and standard Shadowsocks clients cannot. It carries no
//! transport of its own, so on its own it is a raw TCP protocol with no TLS to
//! hide in.
//!
//! # Replay protection is weaker here than the specification intends
//!
//! SIP022 expects a server-wide cache of recently-seen salts. Each XHTTP
//! session is a separate Durable Object with no shared state, so there is
//! nowhere to keep one without a storage round trip on every connection. What
//! remains is the ±30 second timestamp window, which bounds a captured
//! handshake's usefulness but does not make it single-use. This is stated
//! rather than quietly ignored; see `docs/` for the operator-facing note.

use aes_gcm::aead::Aead;
use aes_gcm::{Aes128Gcm, Aes256Gcm, Key, KeyInit, Nonce};
use chacha20poly1305::ChaCha20Poly1305;

use super::addr::{read_host, AddrKind};
use super::{ProtocolError, Reader, Target};

/// BLAKE3 derivation context. One byte different and nothing interoperates.
pub(super) const SUBKEY_CONTEXT: &str = "shadowsocks 2022 session subkey";

/// AEAD tag length, the same for all three ciphers.
pub(super) const TAG: usize = 16;

/// Fixed-length request header: type, timestamp, variable-header length.
const FIXED_HEADER_LEN: usize = 1 + 8 + 2;

/// Header type byte for a client-to-server request.
const TYPE_REQUEST: u8 = 0;

/// How far the header timestamp may be from server time.
///
/// Measured against a reference server rather than assumed: it accepts ±29
/// seconds and rejects ±31. Matching it matters in both directions — wider
/// accepts replays the reference would refuse, narrower rejects clients the
/// reference would serve.
const MAX_CLOCK_SKEW_SECS: u64 = 30;

/// Longest variable-length header this parser will wait for.
///
/// The field is a `u16`, so this is its natural maximum. It is reached only by
/// a client padding heavily; real captures sit under a kilobyte.
const MAX_VARIABLE_LEN: usize = u16::MAX as usize;

/// Which AEAD, and therefore how long the key and salt are.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
}

impl Method {
    /// Key length in bytes. The salt is the same length.
    #[must_use]
    pub const fn key_len(self) -> usize {
        match self {
            Self::Aes128Gcm => 16,
            Self::Aes256Gcm | Self::ChaCha20Poly1305 => 32,
        }
    }

    /// Parse the method name as it appears in every core's configuration.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        match name.trim() {
            "2022-blake3-aes-128-gcm" => Some(Self::Aes128Gcm),
            "2022-blake3-aes-256-gcm" => Some(Self::Aes256Gcm),
            "2022-blake3-chacha20-poly1305" => Some(Self::ChaCha20Poly1305),
            _ => None,
        }
    }

    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Aes128Gcm => "2022-blake3-aes-128-gcm",
            Self::Aes256Gcm => "2022-blake3-aes-256-gcm",
            Self::ChaCha20Poly1305 => "2022-blake3-chacha20-poly1305",
        }
    }
}

/// A configured user: one method and one pre-shared key.
///
/// The key is stored at its natural length rather than as the base64 text it
/// was configured with, so the decode happens once at startup instead of on
/// every connection.
#[derive(Clone)]
pub struct Credential {
    pub(super) method: Method,
    /// Only the first `method.key_len()` bytes are meaningful.
    pub(super) psk: [u8; 32],
}

// Redacting, and comparing only the method: the derived form would print a
// long-term pre-shared key, and equality over secrets is never wanted.
impl core::fmt::Debug for Credential {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Credential")
            .field("method", &self.method)
            .field("psk", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl PartialEq for Credential {
    fn eq(&self, other: &Self) -> bool {
        self.method == other.method && super::ct_eq(&self.psk, &other.psk)
    }
}
impl Eq for Credential {}

impl Credential {
    /// Build from a method name and a base64 pre-shared key.
    ///
    /// Returns `None` if the method is unknown, the key is not valid base64,
    /// or its decoded length does not match the method. That last check is the
    /// one worth having: a 16-byte key configured against a 256-bit method is
    /// the most common Shadowsocks-2022 misconfiguration, and it fails deep
    /// inside a vendored library at connection time rather than at startup.
    #[must_use]
    pub fn new(method: &str, password_base64: &str) -> Option<Self> {
        let method = Method::from_name(method)?;
        let raw = crate::crypto::base64::decode(password_base64.trim())?;
        if raw.len() != method.key_len() {
            return None;
        }
        let mut psk = [0u8; 32];
        psk[..raw.len()].copy_from_slice(&raw);
        Some(Self { method, psk })
    }

    #[must_use]
    pub const fn method(&self) -> Method {
        self.method
    }
}

/// One direction's AEAD, chosen by the method.
pub(super) enum Cipher {
    Aes128(Box<Aes128Gcm>),
    Aes256(Box<Aes256Gcm>),
    ChaCha(Box<ChaCha20Poly1305>),
}

impl Cipher {
    /// `key` must already be the method's key length.
    pub(super) fn new(method: Method, key: &[u8]) -> Self {
        match method {
            Method::Aes128Gcm => {
                Self::Aes128(Box::new(Aes128Gcm::new(Key::<Aes128Gcm>::from_slice(key))))
            }
            Method::Aes256Gcm => {
                Self::Aes256(Box::new(Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key))))
            }
            Method::ChaCha20Poly1305 => {
                Self::ChaCha(Box::new(ChaCha20Poly1305::new(key.into())))
            }
        }
    }

    pub(super) fn open(&self, counter: u64, ciphertext: &[u8]) -> Option<Vec<u8>> {
        let n = nonce_for(counter);
        match self {
            Self::Aes128(c) => c.decrypt(Nonce::from_slice(&n), ciphertext),
            Self::Aes256(c) => c.decrypt(Nonce::from_slice(&n), ciphertext),
            Self::ChaCha(c) => c.decrypt((&n).into(), ciphertext),
        }
        .ok()
    }

    pub(super) fn seal(&self, counter: u64, plaintext: &[u8]) -> Option<Vec<u8>> {
        let n = nonce_for(counter);
        match self {
            Self::Aes128(c) => c.encrypt(Nonce::from_slice(&n), plaintext),
            Self::Aes256(c) => c.encrypt(Nonce::from_slice(&n), plaintext),
            Self::ChaCha(c) => c.encrypt((&n).into(), plaintext),
        }
        .ok()
    }
}

/// Twelve-byte nonce: a little-endian counter in the low eight bytes.
///
/// Note this counts **AEAD operations, not chunks** — a payload chunk spends
/// two, one on its length and one on its body. Counting chunks instead would
/// desynchronise after the first one.
pub(super) fn nonce_for(counter: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[..8].copy_from_slice(&counter.to_le_bytes());
    nonce
}

/// Derive a session subkey from a pre-shared key and a salt.
///
/// `BLAKE3::derive_key(context, psk || salt)`, truncated by the caller to the
/// method's key length. Both inputs are at most 32 bytes, so the concatenation
/// is built on the stack.
pub(super) fn session_subkey(psk: &[u8], salt: &[u8]) -> [u8; 32] {
    let mut material = [0u8; 64];
    let end = psk.len() + salt.len();
    material[..psk.len()].copy_from_slice(psk);
    material[psk.len()..end].copy_from_slice(salt);
    crate::crypto::blake3::derive_key(SUBKEY_CONTEXT, &material[..end])
}

/// A decoded, authenticated Shadowsocks-2022 request.
pub struct Request<'a> {
    pub user: usize,
    pub target: Target,
    /// Session material the body codec needs to continue the stream.
    pub session: Session,
    /// Remaining ciphertext after the header, still to be fed to the codec.
    pub payload: &'a [u8],
}

/// What the codec needs to carry on where the parser stopped.
#[derive(Clone)]
pub struct Session {
    pub method: Method,
    pub psk: [u8; 32],
    /// The client's salt, echoed back in the response header.
    pub request_salt: [u8; 32],
    pub request_subkey: [u8; 32],
    /// Plaintext that arrived inside the variable-length header.
    pub initial: Vec<u8>,
    /// Next AEAD counter on the request stream. Two operations are spent on
    /// the header, so this starts at 2.
    pub next_counter: u64,
    /// Server time when the request was parsed, for the response header.
    pub now_secs: u64,
}

impl core::fmt::Debug for Session {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Session")
            .field("method", &self.method)
            .field("psk", &"<redacted>")
            .field("request_subkey", &"<redacted>")
            .field("initial_len", &self.initial.len())
            .field("next_counter", &self.next_counter)
            .finish_non_exhaustive()
    }
}

impl PartialEq for Session {
    fn eq(&self, other: &Self) -> bool {
        self.method == other.method
            && self.next_counter == other.next_counter
            && self.initial == other.initial
    }
}
impl Eq for Session {}

/// Parse and authenticate a Shadowsocks-2022 request.
///
/// `now_secs` is the current Unix time, supplied by the caller so this stays a
/// pure function — the replay window is otherwise untestable.
///
/// # Errors
/// [`ProtocolError::Incomplete`] while the buffer may still grow into a valid
/// header, or a terminal variant otherwise. The caller must render every
/// terminal outcome identically.
pub fn parse<'a>(
    buf: &'a [u8],
    creds: &[Credential],
    now_secs: u64,
) -> Result<Request<'a>, ProtocolError> {
    let mut incomplete = false;

    // Credentials may use different key lengths, and the salt length follows
    // the key length, so each has to be tried on its own terms rather than
    // against one fixed prefix.
    for (index, cred) in creds.iter().enumerate() {
        let key_len = cred.method.key_len();
        let fixed_end = key_len + FIXED_HEADER_LEN + TAG;
        if buf.len() < fixed_end {
            incomplete = true;
            continue;
        }

        let salt = &buf[..key_len];
        let subkey = session_subkey(&cred.psk[..key_len], salt);
        let cipher = Cipher::new(cred.method, &subkey[..key_len]);

        // The tag check is what identifies the user; a wrong key simply fails.
        let Some(fixed) = cipher.open(0, &buf[key_len..fixed_end]) else {
            continue;
        };

        match decode_after_fixed(buf, &fixed, &cipher, key_len, fixed_end, now_secs) {
            Ok((target, initial, consumed)) => {
                let mut request_salt = [0u8; 32];
                request_salt[..key_len].copy_from_slice(salt);
                return Ok(Request {
                    user: index,
                    target,
                    session: Session {
                        method: cred.method,
                        psk: cred.psk,
                        request_salt,
                        request_subkey: subkey,
                        initial,
                        // Two AEAD operations were spent on the header.
                        next_counter: 2,
                        now_secs,
                    },
                    payload: &buf[consumed..],
                });
            }
            Err(ProtocolError::Incomplete) => incomplete = true,
            Err(e) => return Err(e),
        }
    }

    if incomplete {
        Err(ProtocolError::Incomplete)
    } else {
        Err(ProtocolError::AuthFailed)
    }
}

/// Everything after the fixed header has been authenticated.
///
/// Returns the destination, the initial payload, and how many bytes of `buf`
/// the header consumed.
fn decode_after_fixed(
    buf: &[u8],
    fixed: &[u8],
    cipher: &Cipher,
    key_len: usize,
    fixed_end: usize,
    now_secs: u64,
) -> Result<(Target, Vec<u8>, usize), ProtocolError> {
    let mut r = Reader::new(fixed);
    if r.u8()? != TYPE_REQUEST {
        // A response header arriving on the request stream: not something a
        // client sends, so treat it as terminal rather than waiting.
        return Err(ProtocolError::UnsupportedVersion(TYPE_REQUEST));
    }
    let mut ts = [0u8; 8];
    ts.copy_from_slice(r.take(8)?);
    let timestamp = u64::from_be_bytes(ts);
    // `abs_diff` avoids the underflow a subtraction would hit when the client's
    // clock is ahead of ours.
    if timestamp.abs_diff(now_secs) > MAX_CLOCK_SKEW_SECS {
        return Err(ProtocolError::AuthFailed);
    }

    let variable_len = usize::from(r.u16_be()?);
    if variable_len > MAX_VARIABLE_LEN {
        return Err(ProtocolError::LengthExceeded);
    }
    let variable_end = fixed_end
        .checked_add(variable_len)
        .and_then(|v| v.checked_add(TAG))
        .ok_or(ProtocolError::LengthExceeded)?;
    if buf.len() < variable_end {
        return Err(ProtocolError::Incomplete);
    }

    let variable = cipher
        .open(1, &buf[fixed_end..variable_end])
        .ok_or(ProtocolError::AuthFailed)?;

    let mut v = Reader::new(&variable);
    // SOCKS5 table here, unlike VLESS and VMess.
    let host = read_host(&mut v, AddrKind::Socks5)?;
    let port = v.u16_be()?;
    let padding = usize::from(v.u16_be()?);
    let _ = v.take(padding)?;
    let initial = v.rest().to_vec();

    let _ = key_len;
    Ok((Target { host, port }, initial, variable_end))
}
