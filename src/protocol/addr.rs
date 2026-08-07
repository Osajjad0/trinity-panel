//! Target address decoding.
//!
//! Two incompatible wire encodings are in play, and confusing them is the
//! classic source of "the proxy dials the wrong host" bugs, because the two
//! disagree on exactly the bytes that look interchangeable:
//!
//! ```text
//!   VLESS / VMess : 0x01 IPv4   0x02 domain   0x03 IPv6
//!   SOCKS5-style  : 0x01 IPv4   0x03 domain   0x04 IPv6
//! ```
//!
//! Trojan and Shadowsocks both use the SOCKS5-style table. A decoder that
//! assumes one table and is fed the other will read a domain length byte as
//! the first octet of an IPv6 address and silently connect somewhere
//! unintended, so the table is selected by an explicit [`AddrKind`] rather
//! than inferred.

use core::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::{ProtocolError, Reader};

/// Which address-type table applies to the protocol being decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddrKind {
    /// VLESS and VMess: domain is `0x02`, IPv6 is `0x03`.
    Vless,
    /// Trojan and Shadowsocks: domain is `0x03`, IPv6 is `0x04`.
    Socks5,
}

/// A destination host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Host {
    Ip(IpAddr),
    /// Boxed rather than `String` because this is written once and never
    /// grown; dropping the capacity field keeps [`Target`] at two words plus
    /// the port on 32-bit wasm.
    Domain(Box<str>),
}

/// A destination host and port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub host: Host,
    pub port: u16,
}

impl Target {
    /// Render as the `host:port` string the runtime's `connect()` expects.
    ///
    /// IPv6 literals must be bracketed or the port is parsed as part of the
    /// address. This allocates once per connection, not per packet.
    #[must_use]
    pub fn to_socket_string(&self) -> String {
        match &self.host {
            Host::Ip(IpAddr::V6(v6)) => format!("[{v6}]:{}", self.port),
            Host::Ip(IpAddr::V4(v4)) => format!("{v4}:{}", self.port),
            Host::Domain(d) => format!("{d}:{}", self.port),
        }
    }

    /// Whether this destination is one the runtime refuses to dial.
    ///
    /// The runtime blocks outbound TCP to Cloudflare's own ranges, to private
    /// and loopback addresses, and to port 25. Catching the cases we can see
    /// locally turns an opaque runtime rejection into a clear log line, and
    /// stops the Worker being used to probe its own internal network. Domains
    /// cannot be checked here because resolution happens inside `connect()`.
    #[must_use]
    pub fn is_locally_rejectable(&self) -> bool {
        if self.port == 25 {
            return true;
        }
        match &self.host {
            Host::Domain(_) => false,
            Host::Ip(IpAddr::V4(v4)) => {
                v4.is_private()
                    || v4.is_loopback()
                    || v4.is_link_local()
                    || v4.is_broadcast()
                    || v4.is_documentation()
                    || v4.is_unspecified()
                    || v4.is_multicast()
                    // 100.64.0.0/10, carrier-grade NAT — not covered by std.
                    || (v4.octets()[0] == 100 && (v4.octets()[1] & 0xc0) == 64)
            }
            Host::Ip(IpAddr::V6(v6)) => {
                v6.is_loopback()
                    || v6.is_unspecified()
                    || v6.is_multicast()
                    // fc00::/7 unique-local and fe80::/10 link-local.
                    || (v6.segments()[0] & 0xfe00) == 0xfc00
                    || (v6.segments()[0] & 0xffc0) == 0xfe80
                    // Unwrap any embedded IPv4 and re-test it. `to_ipv4`
                    // covers both the mapped form (::ffff:127.0.0.1) and the
                    // deprecated IPv4-compatible form (::127.0.0.1); handling
                    // only the mapped one leaves ::10.0.0.1 and
                    // ::169.254.169.254 as a route straight to the private
                    // network and the cloud metadata endpoint.
                    || v6.to_ipv4().is_some_and(|m| {
                        Target { host: Host::Ip(IpAddr::V4(m)), port: self.port }
                            .is_locally_rejectable()
                    })
            }
        }
    }
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_socket_string())
    }
}

/// Longest legal DNS name. A length prefix above this is rejected outright
/// rather than treated as `Incomplete`, so a malformed header can never make
/// the caller wait for bytes that would be refused on arrival.
const MAX_DOMAIN_LEN: usize = 253;

/// Decode an address whose type byte precedes it, using `kind`'s table.
///
/// The port is *not* read here — VLESS puts the port before the address type
/// while SOCKS5-style protocols put it after, so ordering stays with the
/// protocol parser that knows its own layout.
pub fn read_host(r: &mut Reader<'_>, kind: AddrKind) -> Result<Host, ProtocolError> {
    let ty = r.u8()?;
    let (v4, domain, v6) = match kind {
        AddrKind::Vless => (0x01u8, 0x02u8, 0x03u8),
        AddrKind::Socks5 => (0x01u8, 0x03u8, 0x04u8),
    };

    if ty == v4 {
        let o = r.take(4)?;
        Ok(Host::Ip(IpAddr::V4(Ipv4Addr::new(o[0], o[1], o[2], o[3]))))
    } else if ty == domain {
        let len = usize::from(r.u8()?);
        if len == 0 {
            return Err(ProtocolError::MalformedAddress);
        }
        if len > MAX_DOMAIN_LEN {
            return Err(ProtocolError::LengthExceeded);
        }
        let raw = r.take(len)?;
        let s = core::str::from_utf8(raw).map_err(|_| ProtocolError::MalformedAddress)?;
        // A domain arriving with a NUL or whitespace is either a broken client
        // or an attempt at request smuggling through whatever we hand it to.
        if s.bytes().any(|b| b <= 0x20 || b == 0x7f) {
            return Err(ProtocolError::MalformedAddress);
        }
        // Some clients send a literal IP in the domain slot. Normalising here
        // means the private-range check above sees the real address instead of
        // waving it through as an opaque name.
        if let Ok(ip) = s.parse::<IpAddr>() {
            return Ok(Host::Ip(ip));
        }
        Ok(Host::Domain(s.into()))
    } else if ty == v6 {
        let o = r.take(16)?;
        let mut seg = [0u16; 8];
        for (i, s) in seg.iter_mut().enumerate() {
            *s = u16::from_be_bytes([o[i * 2], o[i * 2 + 1]]);
        }
        Ok(Host::Ip(IpAddr::V6(Ipv6Addr::new(
            seg[0], seg[1], seg[2], seg[3], seg[4], seg[5], seg[6], seg[7],
        ))))
    } else {
        Err(ProtocolError::UnknownAddressType(ty))
    }
}

/// Decode a SOCKS5-style `ATYP | ADDR | PORT` triple, as used by Trojan and
/// Shadowsocks.
pub fn read_target_socks5(r: &mut Reader<'_>) -> Result<Target, ProtocolError> {
    let host = read_host(r, AddrKind::Socks5)?;
    let port = r.u16_be()?;
    Ok(Target { host, port })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vless_and_socks5_tables_differ_on_the_same_byte() {
        // 0x03 is IPv6 under VLESS and a domain under SOCKS5. Feeding the same
        // bytes to both tables must not produce the same answer.
        let bytes = [0x03, 0x04, b't', b'e', b's', b't'];

        let mut r = Reader::new(&bytes);
        assert_eq!(
            read_host(&mut r, AddrKind::Socks5),
            Ok(Host::Domain("test".into()))
        );

        let mut r = Reader::new(&bytes);
        // Under the VLESS table 0x03 means IPv6, which needs 16 bytes.
        assert_eq!(read_host(&mut r, AddrKind::Vless), Err(ProtocolError::Incomplete));
    }

    #[test]
    fn reads_ipv4_under_both_tables() {
        let bytes = [0x01, 93, 184, 216, 34];
        for kind in [AddrKind::Vless, AddrKind::Socks5] {
            let mut r = Reader::new(&bytes);
            assert_eq!(
                read_host(&mut r, kind),
                Ok(Host::Ip(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))))
            );
        }
    }

    #[test]
    fn reads_ipv6_with_correct_type_byte() {
        let mut bytes = vec![0x03];
        bytes.extend_from_slice(&Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).octets());
        let mut r = Reader::new(&bytes);
        assert_eq!(
            read_host(&mut r, AddrKind::Vless),
            Ok(Host::Ip(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))))
        );
    }

    #[test]
    fn rejects_empty_oversized_and_dirty_domains() {
        let mut r = Reader::new(&[0x03, 0x00]);
        assert_eq!(read_host(&mut r, AddrKind::Socks5), Err(ProtocolError::MalformedAddress));

        let mut over = vec![0x03, 255];
        over.extend(std::iter::repeat_n(b'a', 255));
        let mut r = Reader::new(&over);
        assert_eq!(read_host(&mut r, AddrKind::Socks5), Err(ProtocolError::LengthExceeded));

        let mut r = Reader::new(&[0x03, 0x04, b'a', 0x00, b'b', b'c']);
        assert_eq!(read_host(&mut r, AddrKind::Socks5), Err(ProtocolError::MalformedAddress));
    }

    #[test]
    fn ip_literal_in_domain_slot_is_normalised() {
        let d = b"127.0.0.1";
        let mut bytes = vec![0x03, d.len() as u8];
        bytes.extend_from_slice(d);
        let mut r = Reader::new(&bytes);
        let host = read_host(&mut r, AddrKind::Socks5).expect("parses");
        // Must come back as an IP so the private-range guard actually sees it.
        assert!(matches!(host, Host::Ip(_)));
        assert!(Target { host, port: 443 }.is_locally_rejectable());
    }

    #[test]
    fn blocks_destinations_the_runtime_refuses() {
        let cases: [(IpAddr, bool); 7] = [
            ("127.0.0.1".parse().expect("literal"), true),
            ("10.1.2.3".parse().expect("literal"), true),
            ("100.64.0.1".parse().expect("literal"), true),
            ("169.254.1.1".parse().expect("literal"), true),
            ("::1".parse().expect("literal"), true),
            ("::ffff:127.0.0.1".parse().expect("literal"), true),
            ("93.184.216.34".parse().expect("literal"), false),
        ];
        for (ip, blocked) in cases {
            let t = Target { host: Host::Ip(ip), port: 443 };
            assert_eq!(t.is_locally_rejectable(), blocked, "{ip}");
        }

        // The IPv4-compatible form is deprecated but still parses, and is a
        // route to the private network if only the mapped form is unwrapped.
        let compat: [(IpAddr, bool); 4] = [
            ("::10.0.0.1".parse().expect("literal"), true),
            ("::169.254.169.254".parse().expect("literal"), true),
            ("::192.168.1.1".parse().expect("literal"), true),
            ("::93.184.216.34".parse().expect("literal"), false),
        ];
        let cases = compat;
        for (ip, blocked) in cases {
            let t = Target { host: Host::Ip(ip), port: 443 };
            assert_eq!(t.is_locally_rejectable(), blocked, "{ip}");
        }
        // Port 25 is refused regardless of host.
        let smtp = Target { host: Host::Domain("example.com".into()), port: 25 };
        assert!(smtp.is_locally_rejectable());
    }

    #[test]
    fn socket_string_brackets_ipv6_only() {
        let v6 = Target { host: Host::Ip("2001:db8::1".parse().expect("literal")), port: 443 };
        assert_eq!(v6.to_socket_string(), "[2001:db8::1]:443");
        let v4 = Target { host: Host::Ip("1.2.3.4".parse().expect("literal")), port: 80 };
        assert_eq!(v4.to_socket_string(), "1.2.3.4:80");
        let d = Target { host: Host::Domain("example.com".into()), port: 8443 };
        assert_eq!(d.to_socket_string(), "example.com:8443");
    }
}
