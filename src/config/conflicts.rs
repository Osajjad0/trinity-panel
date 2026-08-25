//! Combination validation — the rules the UI enforces and the emitter refuses
//! to violate.
//!
//! Every panel surveyed in `docs/research/phase-0-report.md` is a free-text
//! toggle form. None of them reject `flow=xtls-rprx-vision` with a WebSocket
//! transport, or REALITY behind a CDN, or an XHTTP node exported to upstream
//! sing-box. They accept the input and emit a configuration that cannot work,
//! and the user discovers this as "it just doesn't connect".
//!
//! This module is the answer to that. Each rule states what breaks, how badly,
//! and why — in language a non-expert can act on, because a warning nobody
//! understands is a warning nobody heeds.
//!
//! The rules are derived from `docs/research/parameter-inventory.md` §7, which
//! records the upstream source or error string each one came from.

use super::model::{
    ClientTarget, Core, Flow, Mux, Node, Protocol, Security, SsMethod, Transport, VmessCipher,
    XhttpMode,
};

/// How badly a combination fails.
#[derive(serde::Serialize, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub enum Severity {
    /// Works, but something the user asked for was dropped or weakened.
    Degraded,
    /// Cannot be expressed in the chosen target at all.
    Untranslatable,
    /// The configuration loads and then silently does not work. The worst kind
    /// for a user, because there is no error message to search for.
    Broken,
    /// The core refuses to start with this configuration.
    Fatal,
}

impl Severity {
    /// Whether the UI should make this combination unselectable rather than
    /// merely warn about it.
    #[must_use]
    pub const fn blocks_selection(self) -> bool {
        matches!(self, Self::Fatal | Self::Broken)
    }
}

/// One problem with a node, addressed to the person configuring it.
#[derive(serde::Serialize, Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub severity: Severity,
    /// Stable identifier of the control this concerns, so the UI can attach
    /// the message to the right input rather than dumping it in a list.
    pub field: &'static str,
    /// One line, shown inline.
    pub summary: String,
    /// The reason, in plain language. Shown on expand.
    pub detail: String,
}

impl Finding {
    fn new(severity: Severity, field: &'static str, summary: &str, detail: &str) -> Self {
        Self {
            severity,
            field,
            summary: summary.to_owned(),
            detail: detail.to_owned(),
        }
    }
}

/// Decoded length of a base64 string, without decoding it.
///
/// Used to check Shadowsocks-2022 key lengths. Returns `None` if the input is
/// not valid base64.
fn b64_decoded_len(s: &str) -> Option<usize> {
    let b = s.as_bytes();
    if b.is_empty() || b.len() % 4 != 0 {
        return None;
    }
    let pad = b.iter().rev().take_while(|&&c| c == b'=').count();
    if pad > 2 {
        return None;
    }
    let body = &b[..b.len() - pad];
    if !body
        .iter()
        .all(|&c| c.is_ascii_alphanumeric() || c == b'+' || c == b'/' || c == b'-' || c == b'_')
    {
        return None;
    }
    Some(b.len() / 4 * 3 - pad)
}

/// Check a node against everything that can go wrong for a given client.
///
/// Returns findings ordered most severe first, so a UI that shows only the
/// first one shows the one that matters.
#[must_use]
pub fn check(node: &Node, target: ClientTarget, enhanced: bool) -> Vec<Finding> {
    let mut f = Vec::new();
    check_worker_serving(node, &mut f);
    check_flow(node, target, &mut f);
    check_transport_translation(node, target, &mut f);
    check_security(node, target, enhanced, &mut f);
    check_protocol(node, target, &mut f);
    check_mux(node, target, &mut f);
    f.sort_by_key(|x| core::cmp::Reverse(x.severity));
    f
}

/// Restrictions imposed by the Cloudflare runtime on nodes we serve ourselves.
fn check_worker_serving(node: &Node, out: &mut Vec<Finding>) {
    if !node.worker_served {
        return;
    }

    if !node.transport.servable_on_worker() {
        let detail = match &node.transport {
            Transport::Grpc { .. } => {
                "Both gRPC modes are bidirectional HTTP/2 streams, and Cloudflare's proxy layer \
                 does not offer full-duplex HTTP/2 in the direction a Worker needs. multiMode \
                 does not help — it batches more buffers into each frame to cut overhead, but \
                 the duplex requirement is unchanged."
            }
            Transport::HttpUpgrade { .. } => {
                "The runtime will only build a 101 response that carries a WebSocket object; a \
                 bare 101 throws, and no API returns the raw socket afterwards. HTTPUpgrade \
                 speaks unframed bytes after the handshake, so even a successful upgrade would \
                 be unusable."
            }
            _ => "This transport needs a raw socket the Workers runtime does not expose.",
        };
        out.push(Finding::new(
            Severity::Fatal,
            "transport",
            &format!("{} cannot be served from a Cloudflare Worker", node.transport.name()),
            detail,
        ));
    }

    if let Transport::Xhttp { mode, .. } = &node.transport {
        if !matches!(mode, XhttpMode::PacketUp) {
            out.push(Finding::new(
                Severity::Degraded,
                "xhttp_mode",
                "This mode needs full-duplex streaming, which is not guaranteed here",
                "packet-up needs no duplex anywhere and always works. stream-up and stream-one \
                 require the edge to deliver request-body bytes before the client finishes \
                 sending, which Cloudflare does not document as supported. Run the built-in \
                 duplex self-test against this deployment before relying on it.",
            ));
        }
    }

    if matches!(node.transport, Transport::WebSocket { .. }) {
        out.push(Finding::new(
            Severity::Degraded,
            "transport",
            "WebSocket is the most heavily fingerprinted transport in this space",
            "Nearly every public panel uses WebSocket and nothing else, so classifiers are \
             trained on it. Running it on the same hostname as XHTTP couples their fates: paths \
             are invisible inside TLS, so a classifier that flags the hostname takes both down. \
             Use a separate hostname if you need real isolation.",
        ));
    }
}

/// XTLS Vision constraints.
fn check_flow(node: &Node, target: ClientTarget, out: &mut Vec<Finding>) {
    let Protocol::Vless { flow, .. } = &node.protocol else {
        return;
    };
    if matches!(flow, Flow::None) {
        return;
    }

    if node.transport.is_framed() {
        out.push(Finding::new(
            Severity::Broken,
            "flow",
            &format!("Vision cannot work over {}", node.transport.name()),
            "Vision splices at the TLS record layer and needs direct access to the record \
             stream. Any framing layer destroys those boundaries. mihomo accepts this \
             combination without complaint and then simply never applies Vision, which is why \
             it is easy to ship by accident.",
        ));
    }

    if matches!(node.security, Security::None) {
        out.push(Finding::new(
            Severity::Fatal,
            "flow",
            "Vision requires TLS or REALITY",
            "Xray refuses to run this: \"XTLS only supports TLS and REALITY directly for now.\" \
             There is no TLS record layer to splice without one of them.",
        ));
    }

    if node.worker_served {
        out.push(Finding::new(
            Severity::Broken,
            "flow",
            "Vision cannot work behind a CDN",
            "Cloudflare terminates TLS at the edge and originates a new session to the Worker, \
             so there is no end-to-end TLS session for Vision to splice. Leave flow empty for \
             any node served through Cloudflare.",
        ));
    }

    if matches!(flow, Flow::VisionUdp443) && target.core() != Core::Xray {
        out.push(Finding::new(
            Severity::Untranslatable,
            "flow",
            "xtls-rprx-vision-udp443 exists only in Xray",
            "sing-box and mihomo accept only xtls-rprx-vision. In mihomo, plain \
             xtls-rprx-vision already behaves as the udp443 variant; block UDP/443 with a rule \
             instead if you need that behaviour.",
        ));
    }

    if node.mux.enabled {
        let (sev, detail) = if target.core() == Core::SingBox {
            (
                Severity::Fatal,
                "sing-box rejects flow together with multiplex: Vision requires one TLS \
                 connection per stream.",
            )
        } else {
            (
                Severity::Degraded,
                "Xray does not reject this, and the Mux path is partly load-bearing for Vision \
                 because Vision refuses bare UDP and rewrites it through v1.mux.cool. But \
                 bundling many streams onto one connection defeats the kernel splice fast path \
                 Vision exists for, so it costs throughput.",
            )
        };
        out.push(Finding::new(sev, "mux", "Vision with multiplexing", detail));
    }
}

/// Whether the transport can be expressed in the target at all.
fn check_transport_translation(node: &Node, target: ClientTarget, out: &mut Vec<Finding>) {
    let Transport::Xhttp { .. } = &node.transport else {
        return;
    };

    if !target.supports_xhttp() {
        out.push(Finding::new(
            Severity::Untranslatable,
            "transport",
            &format!("{} cannot import an XHTTP node", target.name()),
            "Upstream sing-box has never implemented XHTTP in any version — its transport list \
             is http, ws, quic, grpc and httpupgrade, and two contributed patches were closed \
             unmerged. There is no near-equivalent: its http transport is HTTP/1.1 and HTTP/2 \
             only, with none of the packet-up semantics. Use Hiddify or Karing, which ship \
             patched builds that do support XHTTP, or give this client a WebSocket node.",
        ));
        return;
    }

    if target.core() == Core::Mihomo && matches!(node.protocol, Protocol::Vmess { .. }) {
        out.push(Finding::new(
            Severity::Untranslatable,
            "protocol",
            "mihomo supports XHTTP for VLESS only",
            "mihomo's VMess options have no XHTTP settings block — the transport was added for \
             VLESS alone. Switch this node to VLESS, or give mihomo a different transport.",
        ));
    }

    // Xray is the exception, and it is the exception in a way worth stating
    // precisely: `streamSettings` is a property of an Xray outbound, not of a
    // protocol, so Shadowsocks carries XHTTP there exactly as VLESS does.
    //
    // This rule previously applied to every core, which silently removed a
    // working combination from every subscription. The correction is not a
    // reading of anyone's documentation: `xray -test` accepts a Shadowsocks
    // outbound with `xhttpSettings`, and all three 2022 ciphers were carried
    // end to end through a live deployment by a real Xray client. sing-box
    // meanwhile refuses the field outright — `unknown field "transport"` on a
    // shadowsocks outbound — which is what the rest of this rule records.
    if matches!(node.protocol, Protocol::Shadowsocks { .. }) && target.core() != Core::Xray {
        out.push(Finding::new(
            Severity::Broken,
            "protocol",
            &format!("{} cannot carry Shadowsocks over XHTTP", target.core().name()),
            "Outside Xray, Shadowsocks has no transport layer of its own. sing-box rejects a \
             `transport` field on a shadowsocks outbound outright, and in sing-box and mihomo \
             the protocol reaches WebSocket only through the v2ray-plugin, which is a different \
             framing entirely and is not interchangeable with a transport block. Xray is the \
             exception: `streamSettings` there belongs to the outbound rather than to the \
             protocol, so Shadowsocks carries XHTTP exactly as VLESS does.",
        ));
    }
}

/// TLS and REALITY constraints.
fn check_security(node: &Node, target: ClientTarget, enhanced: bool, out: &mut Vec<Finding>) {
    match &node.security {
        Security::Tls(t) => {
            if t.allow_insecure && target.core() == Core::Xray {
                out.push(Finding::new(
                    Severity::Fatal,
                    "allow_insecure",
                    "Xray removed allowInsecure",
                    "It worked through v26.1.13 and became a hard configuration error from \
                     v26.2.2. Xray's own TLS documentation still calls it merely deprecated, \
                     which understates it. Use certificate pinning instead, or fix the \
                     certificate. This is the single most common reason an imported \
                     sing-box or mihomo config fails to load on current Xray.",
                ));
            }
        }
        Security::Reality(r) => {
            if node.worker_served {
                out.push(Finding::new(
                    Severity::Fatal,
                    "security",
                    "REALITY cannot be used behind Cloudflare, and is dangerous if forced",
                    "REALITY borrows a real site's TLS handshake, so it needs to own the TLS \
                     session end to end — a CDN that terminates TLS breaks it. Worse, Xray \
                     forwards traffic that fails REALITY authentication to the target site, so \
                     a misconfigured deployment becomes an open relay that others can abuse.",
                ));
            }
            match &node.transport {
                Transport::Xhttp { .. } | Transport::Grpc { .. } | Transport::Raw => {}
                other => out.push(Finding::new(
                    Severity::Fatal,
                    "security",
                    &format!("REALITY does not support {}", other.name()),
                    "Xray permits REALITY only with raw, XHTTP and gRPC, and rejects the \
                     configuration outright otherwise.",
                )),
            }
            // Enhanced reachability completes a missing REALITY fingerprint
            // with a browser identity, so the emitter resolves this finding
            // and the gate must not refuse the node for it.
            if r.fingerprint.is_none() && target.core() == Core::Mihomo && !enhanced {
                out.push(Finding::new(
                    Severity::Broken,
                    "fingerprint",
                    "REALITY needs a client fingerprint in mihomo",
                    "REALITY's handshake is generated by uTLS, which needs a ClientHello \
                     identity. mihomo raises no error when it is missing — it just cannot \
                     complete the handshake.",
                ));
            }
        }
        Security::None => {
            let public = !node.server.address.starts_with("192.168.")
                && !node.server.address.starts_with("10.")
                && node.server.address != "127.0.0.1"
                && node.server.address != "localhost";
            let bare = matches!(
                node.protocol,
                Protocol::Vless { .. } | Protocol::Trojan { .. }
            );
            if public && bare && target.core() == Core::Xray {
                out.push(Finding::new(
                    Severity::Fatal,
                    "security",
                    "VLESS and Trojan require TLS to a public address",
                    "Xray refuses this outright — neither protocol encrypts anything itself, so \
                     without TLS the traffic is in the clear. It is permitted only when the \
                     server address is private.",
                ));
            }
        }
    }
}

/// Protocol-specific credential and cipher constraints.
fn check_protocol(node: &Node, target: ClientTarget, out: &mut Vec<Finding>) {
    match &node.protocol {
        Protocol::Shadowsocks { method, password } => {
            if let Some(need) = method.key_len() {
                let got = b64_decoded_len(password);
                if got != Some(need) {
                    out.push(Finding::new(
                        Severity::Fatal,
                        "password",
                        &format!("{} needs a base64 key of exactly {need} bytes", method.wire_name()),
                        "Shadowsocks-2022 uses a pre-shared key, not a passphrase. Nothing in \
                         Xray validates this at parse time — the check lives in a bundled \
                         library and fires when the service starts, so a wrong-length key looks \
                         like a perfectly valid config right up until it refuses to run.",
                    ));
                }
            }
            if matches!(method, SsMethod::Blake3Chacha20Poly1305) && target.core() == Core::Xray {
                out.push(Finding::new(
                    Severity::Degraded,
                    "method",
                    "Xray restricts this cipher to single-user servers",
                    "In multi-user mode Xray accepts only the blake3-aes variants. Fine for a \
                     single user; it will refuse to start with a client list.",
                ));
            }
        }
        Protocol::Vmess { cipher, .. } => {
            if matches!(cipher, VmessCipher::Zero) && target.core() == Core::Xray {
                out.push(Finding::new(
                    Severity::Broken,
                    "cipher",
                    "Xray silently ignores this cipher",
                    "Xray maps any unrecognised VMess security value — including zero and \
                     none — to auto without warning. You will get AES-GCM or ChaCha20 rather \
                     than the unencrypted payload you asked for.",
                ));
            }
        }
        Protocol::Vless { .. } | Protocol::Trojan { .. } => {}
    }
}

/// Multiplexing constraints not already covered by the flow rules.
fn check_mux(node: &Node, _target: ClientTarget, out: &mut Vec<Finding>) {
    let Mux { enabled: true, .. } = node.mux else {
        return;
    };
    if node.worker_served {
        out.push(Finding::new(
            Severity::Degraded,
            "mux",
            "Multiplexing gains little here and costs isolate memory",
            "Every stream on a multiplexed connection is served by one Worker request, so a \
             stall on any stream stalls all of them, and the whole bundle dies together when \
             Cloudflare cycles the runtime. Connection reuse at the transport layer already \
             covers most of the benefit.",
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::model::{Endpoint, RealitySettings, TlsSettings};

    fn base() -> Node {
        Node {
            tag: "n".into(),
            server: Endpoint { address: "example.com".into(), port: 443 },
            protocol: Protocol::Vless { uuid: "u".into(), flow: Flow::None },
            transport: Transport::Xhttp {
                mode: XhttpMode::PacketUp,
                path: "/p".into(),
                host: None,
            },
            security: Security::Tls(TlsSettings::default()),
            mux: Mux::default(),
            chain_via: None,
            worker_served: true,
        }
    }

    fn has(f: &[Finding], field: &str, sev: Severity) -> bool {
        f.iter().any(|x| x.field == field && x.severity == sev)
    }

    #[test]
    fn clean_packet_up_node_has_no_blocking_findings() {
        let f = check(&base(), ClientTarget::V2rayN, false);
        assert!(
            !f.iter().any(|x| x.severity.blocks_selection()),
            "unexpected blocking findings: {f:#?}"
        );
    }

    #[test]
    fn xhttp_is_untranslatable_to_upstream_singbox_but_fine_for_hiddify() {
        let n = base();
        let up = check(&n, ClientTarget::SingBoxUpstream, false);
        assert!(has(&up, "transport", Severity::Untranslatable));

        let hid = check(&n, ClientTarget::Hiddify, false);
        assert!(
            !hid.iter().any(|x| x.field == "transport" && x.severity == Severity::Untranslatable),
            "Hiddify ships a patched sing-box that does support XHTTP"
        );
    }

    #[test]
    fn vision_over_a_framed_transport_is_reported_broken() {
        let mut n = base();
        n.protocol = Protocol::Vless { uuid: "u".into(), flow: Flow::Vision };
        let f = check(&n, ClientTarget::V2rayN, false);
        assert!(has(&f, "flow", Severity::Broken));
    }

    #[test]
    fn vision_without_tls_is_fatal() {
        let mut n = base();
        n.protocol = Protocol::Vless { uuid: "u".into(), flow: Flow::Vision };
        n.security = Security::None;
        n.transport = Transport::Raw;
        n.worker_served = false;
        let f = check(&n, ClientTarget::V2rayN, false);
        assert!(has(&f, "flow", Severity::Fatal));
    }

    #[test]
    fn reality_behind_cloudflare_is_fatal_and_says_why() {
        let mut n = base();
        n.security = Security::Reality(RealitySettings::default());
        let f = check(&n, ClientTarget::V2rayN, false);
        assert!(has(&f, "security", Severity::Fatal));
        assert!(
            f.iter().any(|x| x.detail.contains("open relay")),
            "the open-relay consequence must be stated, not just 'unsupported'"
        );
    }

    #[test]
    fn reality_rejects_websocket_outright() {
        let mut n = base();
        n.worker_served = false;
        n.security = Security::Reality(RealitySettings::default());
        n.transport = Transport::WebSocket {
            path: "/w".into(),
            host: None,
            heartbeat_secs: 30,
        };
        let f = check(&n, ClientTarget::V2rayN, false);
        assert!(has(&f, "security", Severity::Fatal));
    }

    #[test]
    fn reality_missing_a_fingerprint_blocks_mihomo_unless_enhanced_completes_it() {
        let mut n = base();
        n.worker_served = false;
        n.security = Security::Reality(RealitySettings::default());
        assert!(has(&check(&n, ClientTarget::Mihomo, false), "fingerprint", Severity::Broken));
        // Enhanced reachability supplies a browser fingerprint, so the gate
        // must let the node through for the emitter to complete it.
        assert!(!has(&check(&n, ClientTarget::Mihomo, true), "fingerprint", Severity::Broken));
    }

    #[test]
    fn allow_insecure_is_fatal_on_xray_only() {
        let mut n = base();
        n.security = Security::Tls(TlsSettings { allow_insecure: true, ..Default::default() });
        assert!(has(&check(&n, ClientTarget::V2rayN, false), "allow_insecure", Severity::Fatal));
        // mihomo still accepts skip-cert-verify.
        assert!(!has(&check(&n, ClientTarget::Mihomo, false), "allow_insecure", Severity::Fatal));
    }

    #[test]
    fn grpc_and_httpupgrade_cannot_be_served_here() {
        for t in [
            Transport::Grpc { service_name: "s".into(), multi_mode: true },
            Transport::HttpUpgrade { path: "/u".into(), host: None },
        ] {
            let mut n = base();
            let name = t.name();
            n.transport = t;
            let f = check(&n, ClientTarget::V2rayN, false);
            assert!(has(&f, "transport", Severity::Fatal), "{name} should be fatal");
        }
    }

    #[test]
    fn external_hops_are_not_bound_by_worker_restrictions() {
        let mut n = base();
        n.worker_served = false;
        n.transport = Transport::Grpc { service_name: "s".into(), multi_mode: false };
        let f = check(&n, ClientTarget::V2rayN, false);
        assert!(!has(&f, "transport", Severity::Fatal));
    }


    #[test]
    fn xray_carries_shadowsocks_over_xhttp_and_the_others_do_not() {
        // Pinned because this rule was wrong in the other direction first, and
        // being wrong here removes a working combination from every export
        // without saying so.
        //
        // The evidence is execution, not documentation: `xray -test` accepts a
        // Shadowsocks outbound carrying `xhttpSettings`, and all three 2022
        // ciphers were carried end to end through a live deployment by a real
        // Xray client. sing-box refuses the field outright.
        let mut n = base();
        n.protocol = Protocol::Shadowsocks {
            method: SsMethod::Blake3Aes256Gcm,
            password: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
        };
        n.transport = Transport::Xhttp {
            mode: XhttpMode::PacketUp,
            path: "/x".into(),
            host: None,
        };

        for xray_client in [ClientTarget::V2rayN, ClientTarget::V2rayNg] {
            let f = check(&n, xray_client, false);
            assert!(
                !has(&f, "protocol", Severity::Broken),
                "{} runs Xray, which carries this fine",
                xray_client.name()
            );
        }

        // Everything else genuinely cannot, and must still say so.
        for other in [ClientTarget::Hiddify, ClientTarget::Karing, ClientTarget::Mihomo] {
            let f = check(&n, other, false);
            assert!(
                has(&f, "protocol", Severity::Broken),
                "{} cannot carry Shadowsocks over XHTTP",
                other.name()
            );
        }
    }

    #[test]
    fn ss2022_key_length_is_validated_against_the_cipher() {
        let mut n = base();
        // 32 bytes base64 supplied where 16 are required.
        n.protocol = Protocol::Shadowsocks {
            method: SsMethod::Blake3Aes128Gcm,
            password: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
        };
        n.transport = Transport::WebSocket { path: "/w".into(), host: None, heartbeat_secs: 30 };
        assert!(has(&check(&n, ClientTarget::V2rayN, false), "password", Severity::Fatal));

        // Exactly 16 bytes is accepted.
        n.protocol = Protocol::Shadowsocks {
            method: SsMethod::Blake3Aes128Gcm,
            password: "AAAAAAAAAAAAAAAAAAAAAA==".into(),
        };
        assert!(!has(&check(&n, ClientTarget::V2rayN, false), "password", Severity::Fatal));
    }

    #[test]
    fn b64_length_arithmetic_is_right() {
        assert_eq!(b64_decoded_len("AAAAAAAAAAAAAAAAAAAAAA=="), Some(16));
        assert_eq!(b64_decoded_len("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="), Some(32));
        assert_eq!(b64_decoded_len("not!base64"), None);
        assert_eq!(b64_decoded_len(""), None);
        assert_eq!(b64_decoded_len("AAA"), None);
    }

    #[test]
    fn findings_are_ordered_most_severe_first() {
        let mut n = base();
        n.protocol = Protocol::Vless { uuid: "u".into(), flow: Flow::Vision };
        n.security = Security::None;
        let f = check(&n, ClientTarget::SingBoxUpstream, false);
        assert!(f.len() > 1);
        for w in f.windows(2) {
            assert!(w[0].severity >= w[1].severity, "not sorted: {f:#?}");
        }
    }

    #[test]
    fn every_finding_explains_itself() {
        // A warning a user cannot act on is noise. Guard against a rule being
        // added with a terse or empty explanation.
        let mut n = base();
        n.protocol = Protocol::Vless { uuid: "u".into(), flow: Flow::Vision };
        n.mux = Mux { enabled: true, concurrency: 8 };
        for t in [
            ClientTarget::V2rayN,
            ClientTarget::SingBoxUpstream,
            ClientTarget::Mihomo,
            ClientTarget::Hiddify,
        ] {
            for f in check(&n, t, false) {
                assert!(!f.summary.is_empty(), "empty summary for {}", f.field);
                assert!(f.detail.len() > 60, "detail too thin for {}: {}", f.field, f.detail);
            }
        }
    }
}
