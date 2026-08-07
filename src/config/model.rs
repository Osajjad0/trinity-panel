//! The unified node model — the single source of truth a config is expressed
//! in, before it is emitted for any particular core.
//!
//! Every other panel in this space either hand-concatenates a string per output
//! format or delegates to an external subscription converter. Both approaches
//! make it impossible to answer "is this combination actually valid?", because
//! there is no model to ask. This module is that model.
//!
//! Deliberately *not* a lowest-common-denominator subset. Fields exist here
//! that only one core supports; [`crate::config::conflicts`] is what reports
//! honestly which ones survive translation to a given target and which do not.

use core::fmt;

use serde::{Deserialize, Serialize};

/// A proxy core, as a translation target.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum Core {
    Xray,
    SingBox,
    Mihomo,
}

impl Core {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Xray => "Xray",
            Self::SingBox => "sing-box",
            Self::Mihomo => "mihomo",
        }
    }
}

/// A client application, as an export target.
///
/// Clients are not cores, and conflating them loses real capability. Upstream
/// sing-box has never supported XHTTP, but Hiddify and Karing ship patched
/// forks that do, and v2rayN executes XHTTP through bundled Xray while its own
/// sing-box config builder rejects it. Exporting per client rather than per
/// core is what lets an XHTTP node reach Hiddify at all.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum ClientTarget {
    V2rayN,
    V2rayNg,
    Hiddify,
    Karing,
    /// Generic upstream sing-box. Strictly less capable than Hiddify/Karing.
    SingBoxUpstream,
    Mihomo,
    NekoBox,
}

impl ClientTarget {
    /// Which core actually executes the config this client imports.
    #[must_use]
    pub const fn core(self) -> Core {
        match self {
            Self::V2rayN | Self::V2rayNg => Core::Xray,
            Self::Hiddify | Self::Karing | Self::SingBoxUpstream | Self::NekoBox => Core::SingBox,
            Self::Mihomo => Core::Mihomo,
        }
    }

    /// Whether this client can import an XHTTP node.
    ///
    /// Note this is *not* `self.core() != Core::SingBox` — that is exactly the
    /// oversimplification that costs Hiddify and Karing users a working node.
    #[must_use]
    // The two `true` arms are kept apart on purpose. Merging them would delete
    // the distinction this whole function exists to record: the first group
    // supports XHTTP natively, the second only because it ships a patched
    // sing-box. That is the fact a future reader needs.
    #[allow(clippy::match_same_arms)]
    pub const fn supports_xhttp(self) -> bool {
        match self {
            Self::V2rayN | Self::V2rayNg | Self::Mihomo => true,
            // Ship patched sing-box forks carrying transport/v2rayxhttp.
            Self::Hiddify | Self::Karing => true,
            Self::SingBoxUpstream | Self::NekoBox => false,
        }
    }

    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::V2rayN => "v2rayN",
            Self::V2rayNg => "v2rayNG",
            Self::Hiddify => "Hiddify",
            Self::Karing => "Karing",
            Self::SingBoxUpstream => "sing-box",
            Self::Mihomo => "mihomo / Clash Meta",
            Self::NekoBox => "NekoBox",
        }
    }
}

/// VLESS flow control.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "kebab-case")]
pub enum Flow {
    /// The only value that works behind a CDN.
    #[default]
    None,
    Vision,
    /// Outbound-only in Xray; rejected on an inbound.
    VisionUdp443,
}

/// VMess payload cipher. `alterId` is deliberately absent — Xray removed the
/// field entirely and VMess is AEAD-only.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "kebab-case")]
pub enum VmessCipher {
    #[default]
    Auto,
    Aes128Gcm,
    Chacha20Poly1305,
    /// Accepted by sing-box and mihomo; Xray silently maps unknown values to
    /// `auto`, so this does not mean what it appears to on Xray.
    Zero,
}

/// Shadowsocks cipher.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum SsMethod {
    Aes128Gcm,
    Aes256Gcm,
    Chacha20Poly1305,
    Xchacha20Poly1305,
    Blake3Aes128Gcm,
    Blake3Aes256Gcm,
    Blake3Chacha20Poly1305,
}

impl SsMethod {
    /// Whether the password must be base64 of an exact key length.
    #[must_use]
    pub const fn is_2022(self) -> bool {
        matches!(
            self,
            Self::Blake3Aes128Gcm | Self::Blake3Aes256Gcm | Self::Blake3Chacha20Poly1305
        )
    }

    /// Required decoded key length in bytes, for the 2022 family.
    ///
    /// Nothing in Xray validates this — the check lives in a vendored library
    /// and fires at service construction, so a config with a plausible-looking
    /// key of the wrong length parses cleanly and then fails at start.
    #[must_use]
    pub const fn key_len(self) -> Option<usize> {
        match self {
            Self::Blake3Aes128Gcm => Some(16),
            Self::Blake3Aes256Gcm | Self::Blake3Chacha20Poly1305 => Some(32),
            _ => None,
        }
    }

    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Aes128Gcm => "aes-128-gcm",
            Self::Aes256Gcm => "aes-256-gcm",
            Self::Chacha20Poly1305 => "chacha20-ietf-poly1305",
            Self::Xchacha20Poly1305 => "xchacha20-ietf-poly1305",
            Self::Blake3Aes128Gcm => "2022-blake3-aes-128-gcm",
            Self::Blake3Aes256Gcm => "2022-blake3-aes-256-gcm",
            Self::Blake3Chacha20Poly1305 => "2022-blake3-chacha20-poly1305",
        }
    }
}

/// The proxy protocol and its credentials.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum Protocol {
    Vless { uuid: String, flow: Flow },
    Vmess { uuid: String, cipher: VmessCipher },
    Trojan { password: String },
    Shadowsocks { method: SsMethod, password: String },
}

impl Protocol {
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Vless { .. } => "VLESS",
            Self::Vmess { .. } => "VMess",
            Self::Trojan { .. } => "Trojan",
            Self::Shadowsocks { .. } => "Shadowsocks",
        }
    }
}

/// XHTTP transmission mode.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "kebab-case")]
pub enum XhttpMode {
    /// Needs no duplex anywhere in the path. The only mode guaranteed to work.
    #[default]
    PacketUp,
    /// One unbounded uplink POST plus a separate downlink GET. Needs duplex.
    StreamUp,
    /// One request carrying both directions. Needs duplex, but no
    /// cross-request state and therefore no Durable Object.
    StreamOne,
}

/// The transport carrying the protocol.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum Transport {
    Xhttp {
        mode: XhttpMode,
        path: String,
        host: Option<String>,
    },
    WebSocket {
        path: String,
        host: Option<String>,
        /// Seconds between WebSocket Pings. Cloudflare's WebSocket idle
        /// timeout is real but unpublished, and its docs prescribe a
        /// client-side heartbeat; `0` disables.
        heartbeat_secs: u32,
    },
    Grpc {
        service_name: String,
        multi_mode: bool,
    },
    HttpUpgrade {
        path: String,
        host: Option<String>,
    },
    /// Raw TCP. Xray v26 renamed this from `tcp` to `raw`.
    Raw,
}

impl Transport {
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Xhttp { .. } => "XHTTP",
            Self::WebSocket { .. } => "WebSocket",
            Self::Grpc { .. } => "gRPC",
            Self::HttpUpgrade { .. } => "HTTPUpgrade",
            Self::Raw => "raw",
        }
    }

    /// Whether this transport frames the byte stream.
    ///
    /// Any framing layer destroys the TLS record boundaries that XTLS Vision
    /// splices on, which is why Vision is incompatible with all of them.
    #[must_use]
    pub const fn is_framed(&self) -> bool {
        !matches!(self, Self::Raw)
    }

    /// Whether a Cloudflare Worker can serve this transport at all.
    #[must_use]
    pub const fn servable_on_worker(&self) -> bool {
        match self {
            Self::Xhttp { .. } | Self::WebSocket { .. } => true,
            // Both gRPC modes are bidirectional HTTP/2 streams; httpupgrade
            // needs a raw post-101 socket the runtime never exposes.
            Self::Grpc { .. } | Self::HttpUpgrade { .. } | Self::Raw => false,
        }
    }
}

/// Transport security.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum Security {
    None,
    Tls(TlsSettings),
    Reality(RealitySettings),
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub struct TlsSettings {
    pub sni: Option<String>,
    pub alpn: Vec<String>,
    /// uTLS fingerprint. `None` leaves the core's default.
    pub fingerprint: Option<String>,
    /// Xray removed this: functional through v26.1.13, a hard config error
    /// from v26.2.2 onward. Kept in the model so imported configs can be read
    /// and the user told why it was dropped.
    pub allow_insecure: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub struct RealitySettings {
    pub public_key: String,
    pub short_id: String,
    pub server_name: String,
    pub fingerprint: Option<String>,
}

/// Stream multiplexing.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub struct Mux {
    pub enabled: bool,
    pub concurrency: u16,
}

/// A network endpoint.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Endpoint {
    pub address: String,
    pub port: u16,
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.address.contains(':') {
            write!(f, "[{}]:{}", self.address, self.port)
        } else {
            write!(f, "{}:{}", self.address, self.port)
        }
    }
}

/// One outbound node, expressed once.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Node {
    pub tag: String,
    pub server: Endpoint,
    pub protocol: Protocol,
    pub transport: Transport,
    pub security: Security,
    pub mux: Mux,
    /// Tag of the node this one dials through, for multi-hop chains.
    ///
    /// Expressed as `sockopt.dialerProxy` in Xray, `detour` in sing-box, and
    /// `dialer-proxy` in mihomo. Xray's other mechanism, `proxySettings.tag`,
    /// is deliberately not used: it discards this outbound's own
    /// `streamSettings` unless `transportLayer` is set, which silently drops
    /// the transport and TLS the user configured.
    pub chain_via: Option<String>,
    /// Whether this node is served by our own Worker, as opposed to being an
    /// external hop the user supplied. Worker-served nodes are subject to the
    /// runtime's transport restrictions; external ones are not.
    pub worker_served: bool,
}

impl Node {
    /// Whether this node is a Worker-served XHTTP node needing cross-request
    /// state, and therefore a Durable Object.
    ///
    /// `stream-one` is the exception: a single request carries both directions,
    /// so nothing outlives it.
    #[must_use]
    pub const fn needs_durable_object(&self) -> bool {
        if !self.worker_served {
            return false;
        }
        match &self.transport {
            Transport::Xhttp { mode, .. } => !matches!(mode, XhttpMode::StreamOne),
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hiddify_and_karing_take_xhttp_despite_being_sing_box() {
        // The distinction the whole export layer turns on.
        assert_eq!(ClientTarget::Hiddify.core(), Core::SingBox);
        assert!(ClientTarget::Hiddify.supports_xhttp());
        assert!(ClientTarget::Karing.supports_xhttp());
        assert!(!ClientTarget::SingBoxUpstream.supports_xhttp());
        assert!(!ClientTarget::NekoBox.supports_xhttp());
    }

    #[test]
    fn ss2022_key_lengths_match_the_cipher() {
        assert_eq!(SsMethod::Blake3Aes128Gcm.key_len(), Some(16));
        assert_eq!(SsMethod::Blake3Aes256Gcm.key_len(), Some(32));
        assert_eq!(SsMethod::Blake3Chacha20Poly1305.key_len(), Some(32));
        assert_eq!(SsMethod::Aes256Gcm.key_len(), None);
        assert!(SsMethod::Blake3Aes128Gcm.is_2022());
        assert!(!SsMethod::Chacha20Poly1305.is_2022());
    }

    #[test]
    fn only_xhttp_and_websocket_are_servable_here() {
        let ws = Transport::WebSocket { path: "/".into(), host: None, heartbeat_secs: 30 };
        let xh = Transport::Xhttp {
            mode: XhttpMode::PacketUp,
            path: "/".into(),
            host: None,
        };
        assert!(ws.servable_on_worker());
        assert!(xh.servable_on_worker());
        for t in [
            Transport::Grpc { service_name: "s".into(), multi_mode: true },
            Transport::HttpUpgrade { path: "/".into(), host: None },
            Transport::Raw,
        ] {
            assert!(!t.servable_on_worker(), "{} must not be servable", t.name());
        }
    }

    #[test]
    fn multi_mode_grpc_is_still_not_servable() {
        // multiMode batches buffers per frame; it does not remove the duplex
        // requirement, so it is no more deliverable than plain gun mode.
        let g = Transport::Grpc { service_name: "s".into(), multi_mode: true };
        assert!(!g.servable_on_worker());
    }

    fn node_with(transport: Transport, worker_served: bool) -> Node {
        Node {
            tag: "n".into(),
            server: Endpoint { address: "example.com".into(), port: 443 },
            protocol: Protocol::Vless { uuid: "u".into(), flow: Flow::None },
            transport,
            security: Security::Tls(TlsSettings::default()),
            mux: Mux::default(),
            chain_via: None,
            worker_served,
        }
    }

    #[test]
    fn durable_object_needed_only_for_multi_request_xhttp() {
        let packet_up = node_with(
            Transport::Xhttp { mode: XhttpMode::PacketUp, path: "/p".into(), host: None },
            true,
        );
        let stream_up = node_with(
            Transport::Xhttp { mode: XhttpMode::StreamUp, path: "/p".into(), host: None },
            true,
        );
        let stream_one = node_with(
            Transport::Xhttp { mode: XhttpMode::StreamOne, path: "/p".into(), host: None },
            true,
        );
        let ws = node_with(
            Transport::WebSocket { path: "/w".into(), host: None, heartbeat_secs: 30 },
            true,
        );

        assert!(packet_up.needs_durable_object());
        assert!(stream_up.needs_durable_object());
        // Single request carries both directions, so nothing outlives it.
        assert!(!stream_one.needs_durable_object());
        assert!(!ws.needs_durable_object());

        // An external hop is not our Worker's problem.
        let external = node_with(
            Transport::Xhttp { mode: XhttpMode::PacketUp, path: "/p".into(), host: None },
            false,
        );
        assert!(!external.needs_durable_object());
    }

    #[test]
    fn endpoint_display_brackets_ipv6() {
        let v6 = Endpoint { address: "2001:db8::1".into(), port: 443 };
        assert_eq!(v6.to_string(), "[2001:db8::1]:443");
        let d = Endpoint { address: "example.com".into(), port: 443 };
        assert_eq!(d.to_string(), "example.com:443");
    }

    #[test]
    fn only_raw_is_unframed() {
        assert!(!Transport::Raw.is_framed());
        assert!(Transport::Xhttp {
            mode: XhttpMode::PacketUp,
            path: "/".into(),
            host: None
        }
        .is_framed());
    }
}
