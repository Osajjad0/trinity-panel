//! VLESS inbound.
//!
//! VLESS carries no encryption or authentication of its own beyond a plaintext
//! UUID — it relies entirely on the transport underneath. Behind Cloudflare
//! that transport is the CDN's own TLS, which is exactly why VLESS is the
//! right primary protocol here: there is no second layer of crypto to pay for.
//!
//! # Wire format
//!
//! ```text
//! +---------+------+--------+--------+---------+------+------+---------+
//! | version | UUID | addLen | addons | command | port | atyp | address |
//! |   1     |  16  |   1    | addLen |    1    |  2   |  1   |   var   |
//! +---------+------+--------+--------+---------+------+------+---------+
//! ```
//!
//! Note the ordering: **port precedes the address type**, the opposite of
//! SOCKS5. The address block is omitted entirely when the command is Mux.
//!
//! The reply is two bytes, `[version, addonLen]`, both zero, sent once before
//! the first downstream byte.
//!
//! # Behind Cloudflare's CDN
//!
//! Works, with one hard constraint: **`flow` must be empty**. XTLS Vision
//! splices at the TLS record layer and needs the raw `tls.Conn`; behind a CDN
//! the TLS session is terminated at the edge and re-originated, so Vision has
//! nothing to splice. Xray itself rejects Vision on any framed transport. A
//! client configured with `xtls-rprx-vision` sends a non-empty addon block,
//! which [`Request::flow_requested`] surfaces so the caller can refuse with a
//! useful message instead of producing a tunnel that stalls.

use super::addr::{read_host, AddrKind, Target};
use super::{ct_eq, ProtocolError, Reader, Uuid};

/// Bytes written back to the client before any downstream payload.
pub const RESPONSE_HEADER: [u8; 2] = [0x00, 0x00];

/// The only protocol version that exists.
const VERSION: u8 = 0x00;

/// What the client is asking the proxy to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    /// Ordinary TCP relay. The only fully supported mode.
    Tcp,
    /// UDP association. The runtime has no outbound datagram API, so this is
    /// serviceable only for DNS on port 53, by re-issuing the query over
    /// DoH. See `relay::dns`.
    Udp,
    /// Mux (`v1.mux.cool`). Carries many logical streams over one connection
    /// with its own framing, and notably arrives with **no address block**.
    /// Not implemented — see the note on [`Request::target`].
    Mux,
}

impl Command {
    const fn from_byte(b: u8) -> Result<Self, ProtocolError> {
        match b {
            0x01 => Ok(Self::Tcp),
            0x02 => Ok(Self::Udp),
            0x03 => Ok(Self::Mux),
            other => Err(ProtocolError::UnsupportedCommand(other)),
        }
    }
}

/// A decoded, authenticated VLESS request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request<'a> {
    /// Index into the user table that authenticated this request.
    ///
    /// Carrying the identity onto the data path is what makes per-user
    /// accounting possible at all. Panels that authenticate once and then
    /// forget who it was cannot tell whose traffic is whose, which is how
    /// their operators end up serving terabytes for strangers.
    pub user: usize,
    pub command: Command,
    /// Destination, or `None` for [`Command::Mux`], which encodes no address.
    pub target: Option<Target>,
    /// The client asked for a non-empty addon block, which in practice means
    /// a `flow` such as `xtls-rprx-vision`. Cannot work behind a CDN.
    pub flow_requested: bool,
    /// Payload that arrived in the same buffer as the header.
    ///
    /// Borrowed, not copied. Transport framing does not align with protocol
    /// framing, so the first application bytes very often ride along with the
    /// header and must be forwarded before anything else.
    pub payload: &'a [u8],
}

/// Match a presented UUID against the user table.
///
/// Every candidate is compared even after a match is found. Returning early
/// would make the response time a function of the user's position in the
/// table, which leaks table order and, with enough samples, membership.
#[must_use]
pub fn authenticate(presented: &[u8], users: &[Uuid]) -> Option<usize> {
    let mut found: Option<usize> = None;
    for (i, u) in users.iter().enumerate() {
        if ct_eq(presented, u) {
            found = Some(i);
        }
    }
    found
}

/// Parse and authenticate a VLESS request header.
///
/// Returns [`ProtocolError::Incomplete`] when `buf` holds a prefix of a valid
/// header; the caller should retain the buffer and retry once more bytes
/// arrive rather than dropping the connection.
///
/// # Errors
/// Any terminal variant of [`ProtocolError`]. The caller must not report which
/// one to the peer — see [`crate::protocol`] on why failures are silent.
pub fn parse<'a>(buf: &'a [u8], users: &[Uuid]) -> Result<Request<'a>, ProtocolError> {
    let mut r = Reader::new(buf);

    let version = r.u8()?;
    if version != VERSION {
        return Err(ProtocolError::UnsupportedVersion(version));
    }

    let id = r.take(16)?;
    // Authenticate before parsing anything else. Everything past this point is
    // attacker-controlled length arithmetic, and there is no reason to run it
    // for a peer that has not proven it knows a UUID.
    let user = authenticate(id, users).ok_or(ProtocolError::AuthFailed)?;

    let addon_len = usize::from(r.u8()?);
    // Addons are protobuf and the only field anyone sets is `flow`, which
    // cannot work here. Skip the bytes rather than decoding them: parsing
    // protobuf from an unauthenticated-shaped field buys nothing when the only
    // possible outcome is rejection.
    let _addons = r.take(addon_len)?;

    let command = Command::from_byte(r.u8()?)?;

    // Mux encodes no address block; reading one would consume payload bytes.
    let target = if matches!(command, Command::Mux) {
        None
    } else {
        let port = r.u16_be()?;
        let host = read_host(&mut r, AddrKind::Vless)?;
        Some(Target { host, port })
    };

    Ok(Request {
        user,
        command,
        target,
        flow_requested: addon_len != 0,
        payload: r.rest(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::addr::Host;
    use std::net::{IpAddr, Ipv4Addr};

    const UID: Uuid = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd,
        0xef,
    ];

    fn header(uuid: &Uuid, addons: &[u8], cmd: u8, tail: &[u8], payload: &[u8]) -> Vec<u8> {
        let mut v = vec![VERSION];
        v.extend_from_slice(uuid);
        v.push(addons.len() as u8);
        v.extend_from_slice(addons);
        v.push(cmd);
        v.extend_from_slice(tail);
        v.extend_from_slice(payload);
        v
    }

    /// port 443, then atyp 0x01, then the v4 octets.
    fn tcp_tail_v4() -> Vec<u8> {
        vec![0x01, 0xbb, 0x01, 93, 184, 216, 34]
    }

    #[test]
    fn parses_tcp_request_and_borrows_leading_payload() {
        let buf = header(&UID, &[], 0x01, &tcp_tail_v4(), b"GET / HTTP/1.1\r\n");
        let req = parse(&buf, &[UID]).expect("valid request");

        assert_eq!(req.user, 0);
        assert_eq!(req.command, Command::Tcp);
        assert_eq!(
            req.target,
            Some(Target {
                host: Host::Ip(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))),
                port: 443
            })
        );
        assert!(!req.flow_requested);
        assert_eq!(req.payload, b"GET / HTTP/1.1\r\n");
    }

    #[test]
    fn identifies_which_user_authenticated() {
        let other: Uuid = [0xaa; 16];
        let buf = header(&UID, &[], 0x01, &tcp_tail_v4(), b"");
        let req = parse(&buf, &[other, UID]).expect("valid request");
        assert_eq!(req.user, 1, "must report the matching user, not the first");
    }

    #[test]
    fn rejects_unknown_uuid() {
        let buf = header(&[0xff; 16], &[], 0x01, &tcp_tail_v4(), b"");
        assert_eq!(parse(&buf, &[UID]), Err(ProtocolError::AuthFailed));
        // And with an empty user table.
        assert_eq!(parse(&buf, &[]), Err(ProtocolError::AuthFailed));
    }

    #[test]
    fn surfaces_flow_request_rather_than_silently_ignoring_it() {
        // A Vision client sends a populated addon block.
        let buf = header(&UID, &[0x01, 0x02, 0x03], 0x01, &tcp_tail_v4(), b"");
        let req = parse(&buf, &[UID]).expect("parses");
        assert!(req.flow_requested, "caller must be able to refuse Vision");
    }

    #[test]
    fn mux_carries_no_address_block() {
        // If the parser wrongly read an address here it would eat the payload.
        let buf = header(&UID, &[], 0x03, &[], b"muxpayload");
        let req = parse(&buf, &[UID]).expect("parses");
        assert_eq!(req.command, Command::Mux);
        assert_eq!(req.target, None);
        assert_eq!(req.payload, b"muxpayload");
    }

    #[test]
    fn port_is_read_before_address_type() {
        // 0x01bb is 443. If the parser read the address type first it would
        // see 0x01 as IPv4 and produce a wrong host, so this pins the order.
        let buf = header(&UID, &[], 0x01, &tcp_tail_v4(), b"");
        let req = parse(&buf, &[UID]).expect("parses");
        assert_eq!(req.target.expect("has target").port, 443);
    }

    #[test]
    fn partial_headers_are_incomplete_not_fatal() {
        let full = header(&UID, &[], 0x01, &tcp_tail_v4(), b"");
        for cut in 1..full.len() {
            assert_eq!(
                parse(&full[..cut], &[UID]),
                Err(ProtocolError::Incomplete),
                "prefix of length {cut} must be resumable"
            );
        }
        assert!(parse(&full, &[UID]).is_ok());
    }

    #[test]
    fn rejects_bad_version_and_command() {
        let mut buf = header(&UID, &[], 0x01, &tcp_tail_v4(), b"");
        buf[0] = 0x01;
        assert_eq!(parse(&buf, &[UID]), Err(ProtocolError::UnsupportedVersion(1)));

        let buf = header(&UID, &[], 0x09, &tcp_tail_v4(), b"");
        assert_eq!(parse(&buf, &[UID]), Err(ProtocolError::UnsupportedCommand(9)));
    }

    #[test]
    fn never_panics_on_arbitrary_input() {
        // Cheap structured fuzz: a panic here would kill the isolate and take
        // every multiplexed connection on it down with the request.
        let mut seed = 0x2545_f491_4f6c_dd1du64;
        for _ in 0..4000 {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            let len = (seed % 64) as usize;
            let buf: Vec<u8> = (0..len).map(|i| (seed >> (i % 56)) as u8).collect();
            let _ = parse(&buf, &[UID]);
        }
    }
}
