//! Trojan inbound.
//!
//! Trojan's whole design premise is that an unauthenticated peer should be
//! unable to tell it apart from an ordinary web server. There is no error
//! reply, no version negotiation, and no server greeting — on bad credentials
//! the server is expected to serve normal web content and say nothing.
//!
//! That maps exactly onto this project's decoy page, so the rule is: any
//! failure from this module produces the same response as a request to an
//! unrelated path. Never a 400, never a distinct timing, never a hint.
//!
//! # Wire format
//!
//! ```text
//! +-----------------------+------+---------+------+------+------+---------+
//! | hex(SHA-224(password))| CRLF | command | atyp | addr | port |  CRLF   |
//! |          56           |  2   |    1    |  1   | var  |  2   |    2    |
//! +-----------------------+------+---------+------+------+------+---------+
//! ```
//!
//! The address block is **SOCKS5-style** — domain is `0x03` and IPv6 is
//! `0x04`, unlike VLESS. There is no reply header: the server begins relaying
//! immediately, so the client's first payload byte is the destination's first
//! payload byte.
//!
//! # Behind Cloudflare's CDN
//!
//! Works. One constraint worth knowing: Xray removed `flow` for Trojan
//! entirely and now hard-errors on any non-empty value, so a client config
//! carrying `flow` will refuse to load. The model has no Trojan flow field for
//! that reason — it is unrepresentable rather than merely discouraged.

use sha2::{Digest, Sha224};

use super::addr::read_target_socks5;
use super::{ct_eq, ProtocolError, Reader, Target};

/// Lowercase hex of the SHA-224 of a password, as it appears on the wire.
pub type Key = [u8; 56];

const CRLF: [u8; 2] = [0x0d, 0x0a];

/// What the client is asking for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    Connect,
    /// UDP associate. Unserviceable here — the runtime has no outbound
    /// datagram API — but recognised so the caller can decline deliberately
    /// rather than misparsing it as a malformed CONNECT.
    UdpAssociate,
}

/// A decoded, authenticated Trojan request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request<'a> {
    /// Index into the key table that authenticated this request.
    pub user: usize,
    pub command: Command,
    pub target: Target,
    /// Payload that arrived alongside the header, borrowed not copied.
    pub payload: &'a [u8],
}

/// Derive the wire key for a password.
///
/// Call this once when configuration loads, never per connection. Hashing on
/// the relay path would add a SHA-224 to every handshake for no benefit, and
/// would make connection setup time depend on the size of the user table.
#[must_use]
pub fn key_for(password: &str) -> Key {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha224::digest(password.as_bytes());
    let mut out = [0u8; 56];
    for (i, byte) in digest.iter().enumerate() {
        out[i * 2] = HEX[usize::from(byte >> 4)];
        out[i * 2 + 1] = HEX[usize::from(byte & 0x0f)];
    }
    out
}

/// Match a presented key against the table without early exit.
#[must_use]
pub fn authenticate(presented: &[u8], keys: &[Key]) -> Option<usize> {
    let mut found = None;
    for (i, k) in keys.iter().enumerate() {
        if ct_eq(presented, k) {
            found = Some(i);
        }
    }
    found
}

/// Parse and authenticate a Trojan request header.
///
/// # Errors
/// Any terminal variant of [`ProtocolError`], or [`ProtocolError::Incomplete`]
/// when `buf` holds only a prefix. The caller must render every terminal
/// outcome as the decoy page — see the module docs.
pub fn parse<'a>(buf: &'a [u8], keys: &[Key]) -> Result<Request<'a>, ProtocolError> {
    let mut r = Reader::new(buf);

    let presented = r.take(56)?;
    // Read the separator before authenticating so that a wrong-length or
    // malformed header takes the same path as a wrong password.
    let sep = r.take(2)?;

    let user = authenticate(presented, keys).ok_or(ProtocolError::AuthFailed)?;
    if sep != CRLF {
        return Err(ProtocolError::MalformedAddress);
    }

    let command = match r.u8()? {
        0x01 => Command::Connect,
        0x03 => Command::UdpAssociate,
        other => return Err(ProtocolError::UnsupportedCommand(other)),
    };

    let target = read_target_socks5(&mut r)?;

    if r.take(2)? != CRLF {
        return Err(ProtocolError::MalformedAddress);
    }

    Ok(Request { user, command, target, payload: r.rest() })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::addr::Host;
    use std::net::{IpAddr, Ipv4Addr};

    const PW: &str = "correct horse battery staple";

    fn frame(key: &Key, cmd: u8, addr: &[u8], payload: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(key);
        v.extend_from_slice(&CRLF);
        v.push(cmd);
        v.extend_from_slice(addr);
        v.extend_from_slice(&CRLF);
        v.extend_from_slice(payload);
        v
    }

    /// atyp 0x01, 93.184.216.34, port 443.
    fn addr_v4() -> Vec<u8> {
        vec![0x01, 93, 184, 216, 34, 0x01, 0xbb]
    }

    #[test]
    fn key_is_hex_sha224_of_the_password() {
        let k = key_for(PW);
        assert_eq!(k.len(), 56);
        assert!(k.iter().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        // Known-answer: SHA-224 of the empty string.
        let empty = key_for("");
        assert_eq!(
            core::str::from_utf8(&empty).expect("hex is ascii"),
            "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
        );
    }

    #[test]
    fn parses_connect_and_borrows_payload() {
        let k = key_for(PW);
        let buf = frame(&k, 0x01, &addr_v4(), b"GET / HTTP/1.1\r\n");
        let req = parse(&buf, &[k]).expect("valid request");
        assert_eq!(req.user, 0);
        assert_eq!(req.command, Command::Connect);
        assert_eq!(
            req.target,
            Target {
                host: Host::Ip(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))),
                port: 443
            }
        );
        assert_eq!(req.payload, b"GET / HTTP/1.1\r\n");
    }

    #[test]
    fn uses_the_socks5_address_table_not_the_vless_one() {
        // 0x03 must mean domain here. Under the VLESS table it would be IPv6
        // and would consume 16 bytes, dialling something entirely different.
        let k = key_for(PW);
        let mut addr = vec![0x03, 11];
        addr.extend_from_slice(b"example.com");
        addr.extend_from_slice(&[0x01, 0xbb]);
        let buf = frame(&k, 0x01, &addr, b"");
        let req = parse(&buf, &[k]).expect("valid request");
        assert_eq!(req.target.host, Host::Domain("example.com".into()));
        assert_eq!(req.target.port, 443);
    }

    #[test]
    fn identifies_which_user_authenticated() {
        let a = key_for("first");
        let b = key_for("second");
        let buf = frame(&b, 0x01, &addr_v4(), b"");
        assert_eq!(parse(&buf, &[a, b]).expect("valid").user, 1);
    }

    #[test]
    fn rejects_wrong_password() {
        let good = key_for(PW);
        let bad = key_for("wrong");
        let buf = frame(&bad, 0x01, &addr_v4(), b"");
        assert_eq!(parse(&buf, &[good]), Err(ProtocolError::AuthFailed));
    }

    #[test]
    fn recognises_udp_associate_so_it_can_be_declined_deliberately() {
        let k = key_for(PW);
        let buf = frame(&k, 0x03, &addr_v4(), b"");
        let req = parse(&buf, &[k]).expect("parses");
        assert_eq!(req.command, Command::UdpAssociate);
    }

    #[test]
    fn rejects_missing_separators() {
        let k = key_for(PW);
        let mut buf = frame(&k, 0x01, &addr_v4(), b"");
        buf[56] = b'X'; // corrupt the first CRLF
        assert!(parse(&buf, &[k]).is_err());

        let mut buf = frame(&k, 0x01, &addr_v4(), b"");
        let trailer = buf.len() - 2;
        buf[trailer] = b'X'; // corrupt the trailing CRLF
        assert_eq!(parse(&buf, &[k]), Err(ProtocolError::MalformedAddress));
    }

    #[test]
    fn partial_headers_are_incomplete_not_fatal() {
        let k = key_for(PW);
        let full = frame(&k, 0x01, &addr_v4(), b"");
        for cut in 1..full.len() {
            assert_eq!(
                parse(&full[..cut], &[k]),
                Err(ProtocolError::Incomplete),
                "prefix of length {cut} must be resumable"
            );
        }
    }

    #[test]
    fn never_panics_on_arbitrary_input() {
        let k = key_for(PW);
        let mut seed = 0x243f_6a88_85a3_08d3u64;
        for _ in 0..4000 {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            let len = (seed % 96) as usize;
            let buf: Vec<u8> = (0..len).map(|i| (seed >> (i % 56)) as u8).collect();
            let _ = parse(&buf, &[k]);
        }
        // Also fuzz with a valid prefix so the post-auth path is exercised.
        for _ in 0..2000 {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            let mut buf = Vec::from(&k[..]);
            let len = (seed % 32) as usize;
            buf.extend((0..len).map(|i| (seed >> (i % 56)) as u8));
            let _ = parse(&buf, &[k]);
        }
    }
}
