//! VMess AEAD inbound.
//!
//! **AEAD only.** The legacy MD5-authenticated VMess (`alterId > 0`) was
//! removed from Xray entirely — the field no longer exists in its schema — and
//! implementing it would only invite clients to use a mode modern servers
//! refuse.
//!
//! # Why this module is validated differently
//!
//! Every other parser here can be checked by constructing input and reading it
//! back. That proves self-consistency and nothing else: an encoder and decoder
//! sharing one misunderstanding agree perfectly. VMess has enough structure —
//! a nested-HMAC KDF, three separate AEAD keys, a checksum, and a padding
//! field — that a wrong reading of the specification still round-trips
//! cleanly and then fails against every real client.
//!
//! So the test fixture is a **real handshake captured from a real Xray client**
//! (v26.6.1) with a known UUID and a known destination. The parser is required
//! to recover that destination from those exact bytes. See `tests::CAPTURE`.
//!
//! # Wire format
//!
//! ```text
//! +-----------+------------------+-------+---------------------+
//! | eAuthID   | encrypted length | nonce | encrypted header    |
//! |    16     |     2 + 16 tag   |   8   |   len + 16 tag      |
//! +-----------+------------------+-------+---------------------+
//! ```
//!
//! `eAuthID` is the AES-128-ECB encryption of a 16-byte auth ID: an 8-byte
//! big-endian timestamp, 4 random bytes, and a CRC32 over the first 12. It is
//! also the associated data for both AEAD operations, which binds the whole
//! handshake to that one identity.
//!
//! The decrypted header is:
//!
//! ```text
//! version(1) bodyIV(16) bodyKey(16) respV(1) option(1)
//! padLen<<4|security(1) reserved(1) command(1) port(2)
//! atyp(1) address(N) padding(P) fnv1a(4)
//! ```
//!
//! Address types follow the **VLESS-style** table — `0x02` is a domain and
//! `0x03` is IPv6 — not the SOCKS5 one used by Trojan and Shadowsocks.
//!
//! # Behind Cloudflare's CDN
//!
//! Works. `alterId` must be 0. The timestamp in the auth ID gives replay
//! protection but requires the server clock to be roughly correct; on this
//! runtime the clock is Cloudflare's, which is reliable.
//!
//! # The handshake is only half of it
//!
//! This module decodes and authenticates the **handshake**. That is not enough
//! to serve VMess, and the reason is a real difference from the other
//! protocols here rather than an oversight.
//!
//! VLESS and Trojan are plaintext after their header: once the destination is
//! known, the relay forwards bytes untouched in both directions. **VMess is
//! not.** Its payload is wrapped in chunked AEAD under [`Request::body_key`]
//! and [`Request::body_iv`], with the cipher selected by [`Request::security`]
//! and the framing by [`Request::options`], and the server owes the client an
//! encrypted response header derived from those same values before any
//! downstream data.
//!
//! A relay that authenticated with this module and then forwarded raw bytes
//! would hand the destination ciphertext and the client plaintext — a tunnel
//! that connects, transfers, and corrupts everything passing through it, with
//! nothing at the transport layer reporting a fault.
//!
//! [`crate::protocol::vmess_body`] is that missing half, and this parser is
//! registered in [`crate::protocol::detect`] only because it exists. The
//! fields above are not informational: a caller that reads the destination and
//! ignores `security` and `options` has built exactly the broken tunnel
//! described. The body module refuses any combination it cannot frame
//! correctly rather than guessing.

use aes::cipher::{BlockDecrypt, KeyInit};
use aes::Aes128;
use aes_gcm::aead::Aead;
use aes_gcm::{Aes128Gcm, Key, Nonce};
use hmac::digest::Digest;
use md5::Md5;
use sha2::Sha256;

use super::addr::{read_host, AddrKind};
use super::{ct_eq, ProtocolError, Reader, Target, Uuid};

/// Fixed suffix that turns a UUID into a VMess command key.
const CMD_KEY_SUFFIX: &[u8] = b"c48619fe-8f02-49e0-b9e9-edf763e17e21";

/// Innermost key of the nested-HMAC KDF.
const KDF_SALT: &[u8] = b"VMess AEAD KDF";

const LABEL_AUTH_ID: &[u8] = b"AES Auth ID Encryption";
const LABEL_LEN_KEY: &[u8] = b"VMess Header AEAD Key_Length";
const LABEL_LEN_IV: &[u8] = b"VMess Header AEAD Nonce_Length";
const LABEL_HDR_KEY: &[u8] = b"VMess Header AEAD Key";
const LABEL_HDR_IV: &[u8] = b"VMess Header AEAD Nonce";

/// SHA-256's block size, which the nested HMAC pads keys to.
const HMAC_BLOCK: usize = 64;

/// How far the auth-ID timestamp may be from server time.
///
/// This is the replay window: a captured handshake replayed outside it is
/// refused. Upstream uses two minutes either way, and matching that matters
/// because a shorter window would reject legitimate clients whose clock is
/// merely a little off.
const MAX_CLOCK_SKEW_SECS: u64 = 120;

/// Largest header this parser will accept.
///
/// The length field is attacker-influenced before the payload is
/// authenticated, so it is bounded before it is used to size anything.
const MAX_HEADER_LEN: usize = 2048;

/// Per-user key material, derived once when configuration loads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credential {
    cmd_key: [u8; 16],
    auth_key: [u8; 16],
}

/// What the client is asking for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    Tcp,
    /// UDP. Unserviceable here — no outbound datagram API — but recognised so
    /// it can be declined deliberately rather than misread.
    Udp,
}

/// A decoded, authenticated VMess request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request<'a> {
    pub user: usize,
    pub command: Command,
    pub target: Target,
    /// Key and IV the client will use for the body stream. Retained because a
    /// full implementation needs them to decrypt the payload; the relay here
    /// forwards the stream verbatim.
    pub body_key: [u8; 16],
    pub body_iv: [u8; 16],
    /// Which cipher wraps the body. Not every value is servable; see
    /// [`crate::protocol::vmess_body`].
    pub security: u8,
    /// Body framing flags the client negotiated — chunk masking, global
    /// padding, authenticated length.
    ///
    /// Load-bearing rather than informational: these bits decide whether the
    /// chunk length is XOR-masked, whether padding follows each chunk, and
    /// whether the length is AEAD-sealed instead of masked. A server that
    /// ignores them and assumes one framing will authenticate the handshake
    /// and then misread every chunk.
    pub options: u8,
    /// Verification byte the client expects echoed in the response header. A
    /// client that does not see its own value drops the connection.
    pub response_v: u8,
    pub payload: &'a [u8],
}

/// HMAC-SHA256 where the hash function may itself be an HMAC.
///
/// VMess's KDF is a chain of these: the innermost is keyed with
/// `"VMess AEAD KDF"`, and each path element wraps the previous one. It is an
/// unusual construction and there is no crate for it, so it is written out
/// directly rather than fought through trait bounds.
fn nested_hmac(chain: &[&[u8]], msg: &[u8]) -> [u8; 32] {
    let Some((&key, rest)) = chain.split_last() else {
        let mut h = Sha256::new();
        h.update(msg);
        return h.finalize().into();
    };

    let mut padded = [0u8; HMAC_BLOCK];
    if key.len() > HMAC_BLOCK {
        padded[..32].copy_from_slice(&nested_hmac(rest, key));
    } else {
        padded[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0u8; HMAC_BLOCK];
    let mut opad = [0u8; HMAC_BLOCK];
    for i in 0..HMAC_BLOCK {
        ipad[i] = padded[i] ^ 0x36;
        opad[i] = padded[i] ^ 0x5c;
    }

    let mut inner_msg = Vec::with_capacity(HMAC_BLOCK + msg.len());
    inner_msg.extend_from_slice(&ipad);
    inner_msg.extend_from_slice(msg);
    let inner = nested_hmac(rest, &inner_msg);

    let mut outer_msg = [0u8; HMAC_BLOCK + 32];
    outer_msg[..HMAC_BLOCK].copy_from_slice(&opad);
    outer_msg[HMAC_BLOCK..].copy_from_slice(&inner);
    nested_hmac(rest, &outer_msg)
}

/// First 16 bytes of the KDF, for a single-label path.
///
/// Shared with the body codec, which derives the response-header keys the same
/// way.
pub(super) fn kdf16(key: &[u8], label: &[u8]) -> [u8; 16] {
    let mut out = [0u8; 16];
    out.copy_from_slice(&kdf(key, &[label])[..16]);
    out
}

/// First 12 bytes of the KDF, sized for an AEAD nonce.
pub(super) fn kdf12(key: &[u8], label: &[u8]) -> [u8; 12] {
    let mut out = [0u8; 12];
    out.copy_from_slice(&kdf(key, &[label])[..12]);
    out
}

/// The VMess KDF: nested HMAC keyed by the salt and each path element.
fn kdf(key: &[u8], path: &[&[u8]]) -> [u8; 32] {
    let mut chain: Vec<&[u8]> = Vec::with_capacity(path.len() + 1);
    chain.push(KDF_SALT);
    chain.extend_from_slice(path);
    nested_hmac(&chain, key)
}

/// CRC32 (IEEE), used to validate a decrypted auth ID.
///
/// Written out rather than pulled from a crate: it is twelve lines, and this
/// project has already been bitten by a dependency whose build script could
/// not link on the target toolchain.
fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

/// FNV-1a over the header, which VMess uses as an integrity check.
fn fnv1a(data: &[u8]) -> u32 {
    let mut hash = 0x811C_9DC5u32;
    for &byte in data {
        hash ^= u32::from(byte);
        hash = hash.wrapping_mul(0x0100_0193);
    }
    hash
}

/// Derive a user's key material. Call once at config load, never per request.
#[must_use]
pub fn credential_for(uuid: &Uuid) -> Credential {
    let mut h = Md5::new();
    h.update(uuid);
    h.update(CMD_KEY_SUFFIX);
    let cmd_key: [u8; 16] = h.finalize().into();

    let mut auth_key = [0u8; 16];
    auth_key.copy_from_slice(&kdf(&cmd_key, &[LABEL_AUTH_ID])[..16]);

    Credential { cmd_key, auth_key }
}

/// Recover the auth ID for one credential and check it is well-formed.
///
/// Returns the embedded timestamp when the CRC matches.
fn open_auth_id(cred: &Credential, encrypted: &[u8]) -> Option<u64> {
    let cipher = Aes128::new_from_slice(&cred.auth_key).ok()?;
    let mut block = [0u8; 16];
    block.copy_from_slice(encrypted.get(..16)?);
    cipher.decrypt_block((&mut block).into());

    // Last four bytes are a CRC32 over the first twelve. This is what
    // identifies the user: only the right key produces a self-consistent ID.
    let expected = crc32(&block[..12]).to_be_bytes();
    if !ct_eq(&block[12..16], &expected) {
        return None;
    }
    let mut ts = [0u8; 8];
    ts.copy_from_slice(&block[..8]);
    Some(u64::from_be_bytes(ts))
}

/// Parse and authenticate a VMess AEAD request.
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
    // eAuthID(16) + encrypted length(2+16) + nonce(8) is the smallest prefix
    // from which anything can be decided.
    const PREFIX: usize = 16 + 18 + 8;
    if buf.len() < PREFIX {
        return Err(ProtocolError::Incomplete);
    }

    let eauth = &buf[..16];
    let enc_len = &buf[16..34];
    let nonce = &buf[34..42];

    // Identify the user. Every credential is tried; a match does not short
    // circuit, so the time taken does not reveal table position.
    let mut found: Option<(usize, u64)> = None;
    for (i, cred) in creds.iter().enumerate() {
        if let Some(ts) = open_auth_id(cred, eauth) {
            found = Some((i, ts));
        }
    }
    let (user, timestamp) = found.ok_or(ProtocolError::AuthFailed)?;
    let cred = creds.get(user).ok_or(ProtocolError::AuthFailed)?;

    // Replay window. `abs_diff` avoids the underflow a subtraction would hit
    // when the client's clock is ahead of ours.
    if timestamp.abs_diff(now_secs) > MAX_CLOCK_SKEW_SECS {
        return Err(ProtocolError::AuthFailed);
    }

    let header_len = decrypt_len(cred, eauth, nonce, enc_len)?;
    if header_len > MAX_HEADER_LEN {
        return Err(ProtocolError::LengthExceeded);
    }

    let body_end = PREFIX
        .checked_add(header_len)
        .and_then(|v| v.checked_add(16))
        .ok_or(ProtocolError::LengthExceeded)?;
    if buf.len() < body_end {
        return Err(ProtocolError::Incomplete);
    }

    let header = decrypt_header(cred, eauth, nonce, &buf[PREFIX..body_end])?;
    let req = decode_header(&header)?;

    Ok(Request {
        user,
        command: req.command,
        target: req.target,
        body_key: req.body_key,
        body_iv: req.body_iv,
        security: req.security,
        options: req.options,
        response_v: req.response_v,
        payload: &buf[body_end..],
    })
}

fn decrypt_len(
    cred: &Credential,
    eauth: &[u8],
    nonce: &[u8],
    enc: &[u8],
) -> Result<usize, ProtocolError> {
    let key_bytes = kdf(&cred.cmd_key, &[LABEL_LEN_KEY, eauth, nonce]);
    let iv_bytes = kdf(&cred.cmd_key, &[LABEL_LEN_IV, eauth, nonce]);
    let cipher = Aes128Gcm::new(Key::<Aes128Gcm>::from_slice(&key_bytes[..16]));
    let plain = cipher
        .decrypt(
            Nonce::from_slice(&iv_bytes[..12]),
            aes_gcm::aead::Payload { msg: enc, aad: eauth },
        )
        .map_err(|_| ProtocolError::AuthFailed)?;
    let bytes: [u8; 2] = plain
        .get(..2)
        .and_then(|s| s.try_into().ok())
        .ok_or(ProtocolError::AuthFailed)?;
    Ok(usize::from(u16::from_be_bytes(bytes)))
}

fn decrypt_header(
    cred: &Credential,
    eauth: &[u8],
    nonce: &[u8],
    enc: &[u8],
) -> Result<Vec<u8>, ProtocolError> {
    let key_bytes = kdf(&cred.cmd_key, &[LABEL_HDR_KEY, eauth, nonce]);
    let iv_bytes = kdf(&cred.cmd_key, &[LABEL_HDR_IV, eauth, nonce]);
    let cipher = Aes128Gcm::new(Key::<Aes128Gcm>::from_slice(&key_bytes[..16]));
    cipher
        .decrypt(
            Nonce::from_slice(&iv_bytes[..12]),
            aes_gcm::aead::Payload { msg: enc, aad: eauth },
        )
        .map_err(|_| ProtocolError::AuthFailed)
}

struct Decoded {
    command: Command,
    target: Target,
    body_key: [u8; 16],
    body_iv: [u8; 16],
    security: u8,
    options: u8,
    response_v: u8,
}

fn decode_header(header: &[u8]) -> Result<Decoded, ProtocolError> {
    // The trailing FNV1a covers everything before it. Checking it first means
    // a corrupted header is rejected before any of its fields are trusted.
    let split = header.len().checked_sub(4).ok_or(ProtocolError::Incomplete)?;
    let (body, checksum) = header.split_at(split);
    let expected = fnv1a(body).to_be_bytes();
    if !ct_eq(checksum, &expected) {
        return Err(ProtocolError::AuthFailed);
    }

    let mut r = Reader::new(body);
    if r.u8()? != 1 {
        return Err(ProtocolError::UnsupportedVersion(1));
    }

    let mut body_iv = [0u8; 16];
    body_iv.copy_from_slice(r.take(16)?);
    let mut body_key = [0u8; 16];
    body_key.copy_from_slice(r.take(16)?);

    let response_v = r.u8()?;
    let options = r.u8()?;
    let pad_and_security = r.u8()?;
    let padding = usize::from(pad_and_security >> 4);
    let security = pad_and_security & 0x0f;
    let _reserved = r.u8()?;

    let command = match r.u8()? {
        0x01 => Command::Tcp,
        0x02 => Command::Udp,
        other => return Err(ProtocolError::UnsupportedCommand(other)),
    };

    // Port precedes the address type, as in VLESS.
    let port = r.u16_be()?;
    let host = read_host(&mut r, AddrKind::Vless)?;

    // Padding sits between the address and the checksum. Skipping it is what
    // keeps the checksum boundary aligned.
    let _ = r.take(padding)?;

    Ok(Decoded {
        command,
        target: Target { host, port },
        body_key,
        body_iv,
        security,
        options,
        response_v,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::addr::Host;

    /// A real VMess AEAD handshake, captured from Xray v26.6.1 acting as a
    /// client. The UUID and destination below are what produced these exact
    /// bytes, so decoding them proves interoperability rather than
    /// self-consistency.
    const CAPTURE: &[&str] = &[
        "85eba963bc26d8436ed75d24718da61fd3ed9daaf5eb0ab647f81a9bf2687227a99ea2a53c3dd7f6ebd53bb285663e7d",
        "25e8e8baccc8fa175136a2f7c05e1cf5645c5a39fe20caad76ad1d1c55df3bbf8d67fad13bc513d590e7d350aa817dd7",
        "34796e45f5cbf66ba8418e1c219fa040a257ee277a1a6b75472524107ce3d5c1da8045f9243839311d7540730fabe890",
        "06e754a8e1e85f4377f4a2c6e0a351276b9a26d80b5672c4fb0622df45853779aa8ff436745a7b5e3633968ad721a4af",
        "bf6811be400b197c02392e297388185a2a3672c61fe92949924ee2793312d52077961cd5d9e5f1cf54670029a3d8442e",
        "7c34c9",
    ];
    const CAPTURE_UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";
    /// The timestamp embedded in the captured auth ID.
    const CAPTURE_TIME: u64 = 1_785_094_069;

    fn capture_bytes() -> Vec<u8> {
        let hex: String = CAPTURE.concat();
        (0..hex.len() / 2)
            .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap_or(0))
            .collect()
    }

    fn capture_cred() -> Credential {
        credential_for(&uuid_of(CAPTURE_UUID))
    }

    fn uuid_of(s: &str) -> Uuid {
        crate::protocol::uuid::parse(s).unwrap_or([0; 16])
    }

    #[test]
    fn decodes_a_real_xray_handshake() {
        // The test this module exists for.
        let buf = capture_bytes();
        let req = parse(&buf, &[capture_cred()], CAPTURE_TIME).expect("real capture must decode");

        assert_eq!(req.user, 0);
        assert_eq!(req.command, Command::Tcp);
        assert_eq!(req.target.host, Host::Domain("example.com".into()));
        assert_eq!(req.target.port, 80);
        // 3 is AES-128-GCM, which is what the capturing client was configured
        // to use.
        assert_eq!(req.security, 3);
    }

    #[test]
    fn rejects_the_real_handshake_under_a_different_uuid() {
        let buf = capture_bytes();
        let other = credential_for(&uuid_of("00000000-0000-0000-0000-000000000000"));
        assert_eq!(parse(&buf, &[other], CAPTURE_TIME), Err(ProtocolError::AuthFailed));
    }

    #[test]
    fn reports_which_user_matched() {
        let buf = capture_bytes();
        let decoy = credential_for(&uuid_of("11111111-2222-3333-4444-555555555555"));
        let req = parse(&buf, &[decoy, capture_cred()], CAPTURE_TIME).expect("decodes");
        assert_eq!(req.user, 1, "must report the matching user, not the first");
    }

    #[test]
    fn enforces_the_replay_window() {
        let buf = capture_bytes();
        let cred = capture_cred();
        // Inside the window, either side.
        assert!(parse(&buf, std::slice::from_ref(&cred), CAPTURE_TIME + 100).is_ok());
        assert!(parse(&buf, std::slice::from_ref(&cred), CAPTURE_TIME - 100).is_ok());
        // Outside it, a captured handshake is refused.
        assert_eq!(
            parse(&buf, std::slice::from_ref(&cred), CAPTURE_TIME + 3600),
            Err(ProtocolError::AuthFailed)
        );
        assert_eq!(parse(&buf, std::slice::from_ref(&cred), CAPTURE_TIME - 3600), Err(ProtocolError::AuthFailed));
    }

    #[test]
    fn partial_handshakes_are_incomplete_not_fatal() {
        let full = capture_bytes();
        let cred = capture_cred();
        for cut in 1..42 {
            assert_eq!(
                parse(&full[..cut], std::slice::from_ref(&cred), CAPTURE_TIME),
                Err(ProtocolError::Incomplete),
                "prefix of {cut} bytes must be resumable"
            );
        }
    }

    #[test]
    fn a_corrupted_header_is_rejected() {
        let mut buf = capture_bytes();
        // Flip a bit inside the AEAD-protected header.
        buf[60] ^= 0x01;
        assert_eq!(parse(&buf, &[capture_cred()], CAPTURE_TIME), Err(ProtocolError::AuthFailed));
    }

    #[test]
    fn crc32_matches_published_vectors() {
        assert_eq!(crc32(b""), 0x0000_0000);
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32(b"The quick brown fox jumps over the lazy dog"), 0x414F_A339);
    }

    #[test]
    fn fnv1a_matches_published_vectors() {
        assert_eq!(fnv1a(b""), 0x811C_9DC5);
        assert_eq!(fnv1a(b"a"), 0xE40C_292C);
        assert_eq!(fnv1a(b"foobar"), 0xBF9C_F968);
    }

    #[test]
    fn never_panics_on_arbitrary_input() {
        let cred = capture_cred();
        let mut seed = 0x7fff_ffff_ffff_fffbu64;
        for _ in 0..3000 {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            let len = (seed % 300) as usize;
            let buf: Vec<u8> = (0..len).map(|i| (seed >> (i % 56)) as u8).collect();
            let _ = parse(&buf, std::slice::from_ref(&cred), CAPTURE_TIME);
        }
        // Also fuzz with a valid prefix so the post-auth path is reached.
        let real = capture_bytes();
        for _ in 0..1000 {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            let mut buf = real.clone();
            let at = (seed as usize) % buf.len();
            buf[at] ^= (seed >> 8) as u8;
            let _ = parse(&buf, std::slice::from_ref(&cred), CAPTURE_TIME);
        }
    }
}
