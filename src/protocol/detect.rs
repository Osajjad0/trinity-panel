//! Protocol detection.
//!
//! Every enabled protocol arrives on the same transport path, so the server
//! has to work out which one it is looking at from the bytes alone. There is
//! no negotiation and no discriminator byte that is common across them — each
//! protocol simply expects to be understood.
//!
//! # Why the outcome must be uniform
//!
//! The detector's failure result carries no information about *which* parser
//! rejected the input or why. A caller that could distinguish "valid VLESS
//! header, unknown UUID" from "not VLESS at all" would hand that distinction
//! to anyone probing the endpoint, and the set of protocols a server speaks is
//! itself a fingerprint.
//!
//! # The Incomplete rule
//!
//! If **any** enabled parser reports [`ProtocolError::Incomplete`], detection
//! reports `Incomplete`. A short buffer may be a valid prefix of one protocol
//! while being definitively malformed for another, and giving up because some
//! other parser was certain would break exactly the case the `Incomplete`
//! distinction exists to protect: a header split across two chunks.
//!
//! # A note on timing
//!
//! Parsers run in sequence, so total time varies slightly by which protocol
//! matched. Credential comparison within each parser is constant-time, which
//! is the leak that matters — it is repeatable and attacker-controlled. The
//! ordering difference is bounded by a few hundred nanoseconds of header
//! parsing and is swamped by network jitter, so it is not worth the complexity
//! of running every parser unconditionally.

use super::addr::Target;
use super::codec::{CodecError, Decoder, Encoder};
use super::{shadowsocks, shadowsocks_body, trojan, vless, vmess, vmess_body, ProtocolError, Uuid};

/// Which protocol a request turned out to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Vless,
    Trojan,
    Vmess,
    Shadowsocks,
}

impl Kind {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Vless => "VLESS",
            Self::Trojan => "Trojan",
            Self::Vmess => "VMess",
            Self::Shadowsocks => "Shadowsocks-2022",
        }
    }
}

/// How the payload after the header is framed.
///
/// This is the piece that stops an encrypted protocol being relayed as though
/// it were plaintext. It is carried on every decoded request rather than
/// inferred from [`Kind`] at the call site, so a caller physically cannot
/// forward bytes without first asking what wraps them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Body {
    /// Plaintext inside the transport's TLS, preceded by a fixed reply header.
    ///
    /// VLESS's header is two zero bytes and Trojan's is empty; sending the
    /// wrong one injects bytes into the client's stream as though the
    /// destination had sent them.
    Plain(&'static [u8]),
    /// Chunked AEAD under keys negotiated in the handshake.
    Vmess(vmess_body::Params),
    /// Chunked AEAD from the salt onward, keyed by a pre-shared key.
    Shadowsocks(Box<shadowsocks::Session>),
}

impl Body {
    /// Build the two halves the relay owns, one per direction.
    ///
    /// `entropy` is fresh randomness from the runtime. Shadowsocks-2022 needs
    /// it for the response salt, which must never repeat across sessions;
    /// every other protocol ignores it. It is threaded through rather than
    /// generated here so this stays a pure function that tests on the host.
    ///
    /// # Errors
    /// [`CodecError::Unsupported`] if the client negotiated a body mode this
    /// server does not implement. Refusing is the correct outcome — see
    /// [`crate::protocol::vmess_body`].
    pub fn split(&self, entropy: &[u8; 32]) -> Result<(Decoder, Encoder), CodecError> {
        match self {
            Self::Plain(prologue) => Ok((Decoder::Plain, Encoder::Plain { prologue })),
            Self::Vmess(params) => {
                let (d, e) = vmess_body::split(params)?;
                Ok((Decoder::Vmess(Box::new(d)), Encoder::Vmess(Box::new(e))))
            }
            Self::Shadowsocks(session) => {
                let (d, e) = shadowsocks_body::split(session, entropy)?;
                Ok((Decoder::Shadowsocks(Box::new(d)), Encoder::Shadowsocks(Box::new(e))))
            }
        }
    }
}

/// Credentials for every protocol the deployment accepts.
///
/// All derived once when configuration loads. An empty table disables that
/// protocol entirely, which is both the default and the way an operator turns
/// one off.
#[derive(Debug, Default, Clone)]
pub struct Credentials {
    pub vless: Vec<Uuid>,
    pub trojan: Vec<trojan::Key>,
    pub vmess: Vec<vmess::Credential>,
    pub shadowsocks: Vec<shadowsocks::Credential>,
}

impl Credentials {
    /// Whether any protocol is enabled at all.
    ///
    /// A deployment with no credentials accepts nothing; the caller should
    /// treat that as a configuration error rather than silently serving a
    /// tunnel nobody can use.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.vless.is_empty()
            && self.trojan.is_empty()
            && self.vmess.is_empty()
            && self.shadowsocks.is_empty()
    }
}

/// A decoded request, normalised across protocols.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request<'a> {
    pub kind: Kind,
    /// Index into that protocol's credential table.
    pub user: usize,
    /// Destination. `None` for requests that carry no address, such as VLESS
    /// Mux, which the caller must refuse.
    pub target: Option<Target>,
    /// Whether this is an ordinary TCP relay. UDP and Mux are recognised so
    /// they can be declined deliberately rather than misparsed.
    pub is_tcp: bool,
    /// The client asked for a flow (Vision), which cannot work behind a CDN.
    pub flow_requested: bool,
    /// What wraps the payload, and therefore how it must be relayed.
    pub body: Body,
    /// Payload that arrived with the header, borrowed rather than copied.
    pub payload: &'a [u8],
}

/// Identify and authenticate a request.
///
/// `now_secs` is the current Unix time, needed by VMess's replay window and
/// passed in so this stays a pure function.
///
/// # Errors
/// [`ProtocolError::Incomplete`] when more bytes could still complete a valid
/// header, or [`ProtocolError::AuthFailed`] for every terminal outcome. The
/// caller must render all terminal outcomes identically.
pub fn detect<'a>(
    buf: &'a [u8],
    creds: &Credentials,
    now_secs: u64,
) -> Result<Request<'a>, ProtocolError> {
    let mut incomplete = false;

    if !creds.vless.is_empty() {
        match vless::parse(buf, &creds.vless) {
            Ok(r) => {
                return Ok(Request {
                    kind: Kind::Vless,
                    user: r.user,
                    target: r.target,
                    is_tcp: matches!(r.command, vless::Command::Tcp),
                    flow_requested: r.flow_requested,
                    body: Body::Plain(&vless::RESPONSE_HEADER),
                    payload: r.payload,
                })
            }
            Err(ProtocolError::Incomplete) => incomplete = true,
            Err(_) => {}
        }
    }

    if !creds.trojan.is_empty() {
        match trojan::parse(buf, &creds.trojan) {
            Ok(r) => {
                return Ok(Request {
                    kind: Kind::Trojan,
                    user: r.user,
                    target: Some(r.target),
                    is_tcp: matches!(r.command, trojan::Command::Connect),
                    // Trojan has no flow field; Xray hard-errors on any value.
                    flow_requested: false,
                    // The server starts relaying immediately; anything sent
                    // ahead of the destination's own bytes would corrupt it.
                    body: Body::Plain(&[]),
                    payload: r.payload,
                })
            }
            Err(ProtocolError::Incomplete) => incomplete = true,
            Err(_) => {}
        }
    }

    if !creds.vmess.is_empty() {
        match vmess::parse(buf, &creds.vmess, now_secs) {
            Ok(r) => {
                return Ok(Request {
                    kind: Kind::Vmess,
                    user: r.user,
                    target: Some(r.target),
                    is_tcp: matches!(r.command, vmess::Command::Tcp),
                    // VMess has no flow field at all.
                    flow_requested: false,
                    body: Body::Vmess(vmess_body::Params {
                        body_key: r.body_key,
                        body_iv: r.body_iv,
                        security: r.security,
                        options: r.options,
                        response_v: r.response_v,
                    }),
                    payload: r.payload,
                })
            }
            Err(ProtocolError::Incomplete) => incomplete = true,
            Err(_) => {}
        }
    }

    if !creds.shadowsocks.is_empty() {
        match shadowsocks::parse(buf, &creds.shadowsocks, now_secs) {
            Ok(r) => {
                return Ok(Request {
                    kind: Kind::Shadowsocks,
                    user: r.user,
                    target: Some(r.target),
                    // Shadowsocks carries a TCP stream and nothing else here;
                    // its UDP mode needs a datagram API this runtime lacks.
                    is_tcp: true,
                    flow_requested: false,
                    body: Body::Shadowsocks(Box::new(r.session)),
                    payload: r.payload,
                })
            }
            Err(ProtocolError::Incomplete) => incomplete = true,
            Err(_) => {}
        }
    }

    if incomplete {
        Err(ProtocolError::Incomplete)
    } else {
        // Deliberately uniform: never reveal which parser got closest.
        Err(ProtocolError::AuthFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::addr::Host;
    use std::net::{IpAddr, Ipv4Addr};

    const UID: Uuid = [
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0x00,
    ];
    const PW: &str = "trojan-password";

    /// Any time at all: only VMess consults it, and only these tests' VMess
    /// cases care about the value.
    const NOW: u64 = 1_785_094_069;

    /// Fixed stand-in for runtime randomness. Only Shadowsocks reads it, and a
    /// fixed value makes its output reproducible.
    const ENTROPY: [u8; 32] = [0x5a; 32];

    fn creds() -> Credentials {
        Credentials {
            vless: vec![UID],
            trojan: vec![trojan::key_for(PW)],
            ..Default::default()
        }
    }

    fn vless_frame(payload: &[u8]) -> Vec<u8> {
        let mut v = vec![0x00];
        v.extend_from_slice(&UID);
        v.push(0x00); // no addons
        v.push(0x01); // TCP
        v.extend_from_slice(&[0x01, 0xbb]); // port 443
        v.extend_from_slice(&[0x01, 93, 184, 216, 34]); // IPv4
        v.extend_from_slice(payload);
        v
    }

    fn trojan_frame(payload: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&trojan::key_for(PW));
        v.extend_from_slice(&[0x0d, 0x0a]);
        v.push(0x01); // CONNECT
        v.extend_from_slice(&[0x01, 93, 184, 216, 34, 0x01, 0xbb]); // v4 + port
        v.extend_from_slice(&[0x0d, 0x0a]);
        v.extend_from_slice(payload);
        v
    }

    #[test]
    fn identifies_each_protocol_on_the_same_path() {
        let c = creds();

        let vbuf = vless_frame(b"hello");
        let v = detect(&vbuf, &c, NOW).expect("vless");
        assert_eq!(v.kind, Kind::Vless);
        assert_eq!(v.payload, b"hello");
        assert!(v.is_tcp);
        assert_eq!(
            v.target,
            Some(Target { host: Host::Ip(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))), port: 443 })
        );

        let tbuf = trojan_frame(b"world");
        let t = detect(&tbuf, &c, NOW).expect("trojan");
        assert_eq!(t.kind, Kind::Trojan);
        assert_eq!(t.payload, b"world");
    }

    #[test]
    fn reply_headers_differ_and_trojan_sends_nothing() {
        // Sending VLESS's two bytes on a Trojan stream would inject them into
        // the client's data as though the destination had sent them.
        let c = creds();
        let vbuf = vless_frame(b"");
        let tbuf = trojan_frame(b"");
        let mut vless_enc = detect(&vbuf, &c, NOW).expect("vless").body.split(&ENTROPY).expect("codec").1;
        let mut trojan_enc = detect(&tbuf, &c, NOW).expect("trojan").body.split(&ENTROPY).expect("codec").1;

        assert_eq!(&vless_enc.prologue().expect("vless prologue")[..], &[0x00, 0x00]);
        assert!(trojan_enc.prologue().expect("trojan prologue").is_empty());
    }

    #[test]
    fn plaintext_protocols_relay_without_transforming_the_payload() {
        // The other half of the body question: VLESS and Trojan must forward
        // bytes untouched. A codec that wrapped them would corrupt the tunnel
        // just as surely as relaying VMess raw.
        let c = creds();
        let buf = vless_frame(b"");
        let (mut dec, mut enc) = detect(&buf, &c, NOW).expect("vless").body.split(&ENTROPY).expect("codec");
        let _ = enc.prologue();

        let mut out = Vec::new();
        dec.decode(bytes::Bytes::from_static(b"up"), &mut out).expect("decodes");
        assert_eq!(out.concat(), b"up");
        assert_eq!(&enc.encode(bytes::Bytes::from_static(b"down")).expect("encodes")[..], b"down");
    }

    /// Long enough that no enabled parser can still be waiting for bytes.
    ///
    /// A Trojan header begins with a 56-byte key, so any buffer shorter than
    /// that is a possible Trojan prefix regardless of what it really is. Tests
    /// that want a *terminal* answer have to clear that bar first.
    const PAST_ALL_PREFIXES: usize = 80;

    #[test]
    fn a_disabled_protocol_is_not_accepted() {
        let mut v = vless_frame(b"");
        v.resize(PAST_ALL_PREFIXES, 0x41);
        let mut t = trojan_frame(b"");
        t.resize(PAST_ALL_PREFIXES.max(t.len()), 0x41);

        let only_trojan =
            Credentials { trojan: vec![trojan::key_for(PW)], ..Default::default() };
        assert_eq!(detect(&v, &only_trojan, NOW), Err(ProtocolError::AuthFailed));

        let only_vless = Credentials { vless: vec![UID], ..Default::default() };
        assert_eq!(detect(&t, &only_vless, NOW), Err(ProtocolError::AuthFailed));
    }

    #[test]
    fn wrong_credentials_are_indistinguishable_from_garbage() {
        let c = creds();
        let mut bad = vless_frame(b"");
        bad[1] = 0xff; // corrupt the UUID
        bad.resize(PAST_ALL_PREFIXES, 0x41);
        assert_eq!(detect(&bad, &c, NOW), Err(ProtocolError::AuthFailed));

        let garbage = vec![0x99u8; PAST_ALL_PREFIXES];
        assert_eq!(detect(&garbage, &c, NOW), Err(ProtocolError::AuthFailed));
    }

    #[test]
    fn incomplete_wins_over_a_terminal_error_from_another_parser() {
        // The rule this module turns on, stated as a test. A short buffer is
        // definitively not a valid Trojan header *yet*, but it might become
        // one — so even though VLESS has already rejected it outright, the
        // answer must be "ask again later". Reporting a terminal error here
        // would kill any header that arrives split across two chunks.
        let c = creds();
        let mut nonsense = vec![0x99u8; 20];
        nonsense[0] = 0x99; // not a VLESS version byte, so VLESS fails hard
        assert_eq!(
            detect(&nonsense, &c, NOW),
            Err(ProtocolError::Incomplete),
            "Trojan could still complete, so the verdict must stay open"
        );

        // Once the buffer is longer than any protocol's fixed prefix, no
        // parser can still be waiting and the answer becomes terminal.
        let long = vec![0x99u8; PAST_ALL_PREFIXES];
        assert_eq!(detect(&long, &c, NOW), Err(ProtocolError::AuthFailed));
    }

    #[test]
    fn a_prefix_of_any_enabled_protocol_stays_resumable() {
        // The rule that matters: Trojan is definitively malformed at 10 bytes,
        // but those bytes may be a valid VLESS prefix. Reporting a terminal
        // error because one parser was certain would kill a split header.
        let c = creds();
        let full = vless_frame(b"");
        for cut in 1..full.len() {
            assert_eq!(
                detect(&full[..cut], &c, NOW),
                Err(ProtocolError::Incomplete),
                "vless prefix of {cut} bytes must remain resumable"
            );
        }

        let full = trojan_frame(b"");
        for cut in 1..full.len() {
            assert_eq!(
                detect(&full[..cut], &c, NOW),
                Err(ProtocolError::Incomplete),
                "trojan prefix of {cut} bytes must remain resumable"
            );
        }
    }

    /// The same real Xray VMess handshake the parser and codec are validated
    /// against, exercised through the detector this time — which is the layer
    /// that decides whether it is servable at all.
    mod vmess_capture {
        pub const HEX: &[&str] = &[
            "85eba963bc26d8436ed75d24718da61fd3ed9daaf5eb0ab647f81a9bf2687227a99ea2a53c3dd7f6ebd53bb285663e7d",
            "25e8e8baccc8fa175136a2f7c05e1cf5645c5a39fe20caad76ad1d1c55df3bbf8d67fad13bc513d590e7d350aa817dd7",
            "34796e45f5cbf66ba8418e1c219fa040a257ee277a1a6b75472524107ce3d5c1da8045f9243839311d7540730fabe890",
            "06e754a8e1e85f4377f4a2c6e0a351276b9a26d80b5672c4fb0622df45853779aa8ff436745a7b5e3633968ad721a4af",
            "bf6811be400b197c02392e297388185a2a3672c61fe92949924ee2793312d52077961cd5d9e5f1cf54670029a3d8442e",
            "7c34c9",
        ];
        pub const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";
        pub const TIME: u64 = 1_785_094_069;

        pub fn bytes() -> Vec<u8> {
            let hex: String = HEX.concat();
            (0..hex.len() / 2)
                .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap_or(0))
                .collect()
        }
    }

    fn vmess_creds() -> Credentials {
        let uuid = crate::protocol::uuid::parse(vmess_capture::UUID).unwrap_or([0; 16]);
        Credentials {
            vmess: vec![crate::protocol::vmess::credential_for(&uuid)],
            ..Default::default()
        }
    }

    #[test]
    fn a_real_vmess_handshake_is_detected_and_its_body_decodes() {
        // End to end through the layer the relay actually calls: detect the
        // protocol, build the codec its body demands, and recover the request
        // the real client made. Anything less proves only that the pieces
        // compile together.
        let buf = vmess_capture::bytes();
        let req = detect(&buf, &vmess_creds(), vmess_capture::TIME).expect("vmess detected");

        assert_eq!(req.kind, Kind::Vmess);
        assert!(req.is_tcp);
        assert!(!req.flow_requested);
        assert_eq!(
            req.target,
            Some(Target { host: Host::Domain("example.com".into()), port: 80 })
        );

        let (mut dec, mut enc) = req.body.split(&ENTROPY).expect("body is servable");
        // The client must receive its echoed verification byte before payload.
        assert_eq!(enc.prologue().expect("prologue").len(), 18 + 20);

        let mut out = Vec::new();
        dec.decode(bytes::Bytes::copy_from_slice(req.payload), &mut out).expect("body decodes");
        let text = String::from_utf8_lossy(&out.concat()).into_owned();
        assert!(text.starts_with("GET / HTTP/1.1\r\n"), "got: {text:?}");
        assert!(text.contains("Host: example.com"), "got: {text:?}");
    }

    #[test]
    fn a_vmess_handshake_outside_the_replay_window_is_refused() {
        let buf = vmess_capture::bytes();
        let stale = vmess_capture::TIME + 3600;
        assert_eq!(detect(&buf, &vmess_creds(), stale), Err(ProtocolError::AuthFailed));
    }

    #[test]
    fn vmess_is_not_accepted_when_disabled() {
        // An empty credential table is how a protocol is turned off, and it
        // must be indistinguishable from any other refusal.
        let buf = vmess_capture::bytes();
        assert_eq!(
            detect(&buf, &creds(), vmess_capture::TIME),
            Err(ProtocolError::AuthFailed)
        );
    }

    #[test]
    fn three_protocols_coexist_on_one_path() {
        // The property the whole module exists for, now with an encrypted
        // protocol in the mix: each is identified from its bytes alone.
        let uuid = crate::protocol::uuid::parse(vmess_capture::UUID).unwrap_or([0; 16]);
        let all = Credentials {
            vless: vec![UID],
            trojan: vec![trojan::key_for(PW)],
            vmess: vec![crate::protocol::vmess::credential_for(&uuid)],
            ..Default::default()
        };

        let v = vless_frame(b"hello");
        assert_eq!(detect(&v, &all, vmess_capture::TIME).expect("vless").kind, Kind::Vless);
        let t = trojan_frame(b"world");
        assert_eq!(detect(&t, &all, vmess_capture::TIME).expect("trojan").kind, Kind::Trojan);
        let m = vmess_capture::bytes();
        assert_eq!(detect(&m, &all, vmess_capture::TIME).expect("vmess").kind, Kind::Vmess);
    }

    #[test]
    fn empty_credentials_accept_nothing() {
        let none = Credentials::default();
        assert!(none.is_empty());
        let v = vless_frame(b"");
        assert_eq!(detect(&v, &none, NOW), Err(ProtocolError::AuthFailed));
        assert_eq!(detect(b"", &none, NOW), Err(ProtocolError::AuthFailed));
    }

    #[test]
    fn never_panics_on_arbitrary_input() {
        let c = creds();
        let mut seed = 0x0bad_c0de_dead_10ccu64;
        for _ in 0..5000 {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            let len = (seed % 128) as usize;
            let buf: Vec<u8> = (0..len).map(|i| (seed >> (i % 56)) as u8).collect();
            let _ = detect(&buf, &c, NOW);
        }
    }
}
