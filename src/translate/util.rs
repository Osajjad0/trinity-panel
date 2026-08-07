//! Values shared by every emitter.
//!
//! These are researched defaults, not the cores' own defaults. Each one is
//! documented with what it costs, because shipping a tuned value without
//! saying why is how a project accumulates settings nobody dares change.

/// ALPN advertised on TLS to the edge, **for transports that ride HTTP/2**.
///
/// `h2` only, deliberately. HTTP/2 multiplexes XHTTP's parallel uplink POSTs
/// over a single connection; offering `http/1.1` alongside invites a downgrade
/// that serialises them, which on `packet-up` directly costs throughput
/// because every POST then waits for the previous one's response.
///
/// Cost: a client on a network that cannot do h2 fails rather than degrading.
/// That is the right trade here — such a network cannot carry this transport
/// usefully anyway.
///
/// **Do not apply this unconditionally** — see [`default_alpn`]. An earlier
/// version of this doc said only "h2 only", and an emitter written against it
/// forced `h2` onto every TLS node including WebSocket, which cannot work.
pub const ALPN: &[&str] = &["h2"];

/// The ALPN a node should advertise when the user has not chosen one.
///
/// This is transport-dependent and getting it wrong produces a node that
/// connects and then hangs, which reads to a user as a dead server.
///
/// WebSocket and HTTPUpgrade complete an **HTTP/1.1 Upgrade handshake**. If
/// TLS negotiates `h2`, there is no HTTP/1.1 connection for that handshake to
/// happen on, and the upgrade never completes. So those transports must
/// advertise no ALPN and let the dialer pick `http/1.1` itself.
///
/// XHTTP and gRPC genuinely want `h2` and benefit from pinning it.
///
/// Returns `None` when nothing should be emitted.
#[must_use]
pub fn default_alpn(transport: &crate::config::model::Transport) -> Option<&'static [&'static str]> {
    use crate::config::model::Transport;
    match transport {
        Transport::Xhttp { .. } | Transport::Grpc { .. } => Some(ALPN),
        Transport::WebSocket { .. } | Transport::HttpUpgrade { .. } | Transport::Raw => None,
    }
}

/// The SNI a node should present when the user has not set one explicitly.
///
/// The three emitters previously disagreed here: one fell back to the server
/// address, two to the transport host. Both are defensible in isolation and
/// they produce different TLS handshakes for the same node, which is exactly
/// the divergence this translation layer exists to prevent.
///
/// The resolution: SNI names the host you are speaking TLS *to*. Prefer an
/// explicit value, then the transport host — which is the real hostname when a
/// node connects to a bare "clean IP" — and fall back to the server address
/// only when it is a name. **An IP literal is never a valid SNI**, so if that
/// is all we have, emit nothing rather than something a server will reject.
#[must_use]
pub fn effective_sni<'a>(
    explicit: Option<&'a str>,
    transport_host: Option<&'a str>,
    server: &'a str,
) -> Option<&'a str> {
    let pick = explicit
        .filter(|s| !s.is_empty())
        .or_else(|| transport_host.filter(|s| !s.is_empty()))
        .unwrap_or(server);

    if pick.is_empty() || pick.parse::<std::net::IpAddr>().is_ok() {
        None
    } else {
        Some(pick)
    }
}

/// Seconds between WebSocket pings when that transport is enabled.
///
/// Cloudflare's WebSocket idle timeout is real but unpublished; their docs
/// prescribe a client heartbeat without naming a number, and the widely-cited
/// 100 seconds appears in no Cloudflare document. 30 s is comfortably inside
/// any plausible value and inside the documented 400 s client-to-edge idle
/// limit.
///
/// Cost: one tiny frame every 30 s per idle connection. Negligible for
/// bandwidth, but it does keep a connection observably alive, which is a
/// (small) traffic-analysis signal on an otherwise silent link.
pub const WS_HEARTBEAT_SECS: u32 = 30;

/// Xray's `xmux` defaults, which must be emitted as a complete set.
///
/// If `xmux` is omitted entirely Xray injects `maxConnections=6`,
/// `hMaxRequestTimes=600-900`, `hMaxReusableSecs=1800-3000`. But if **any**
/// single `xmux` field is present, that whole bundle is skipped and every
/// unspecified sub-field silently falls back to 0 — meaning unlimited. So a
/// partially-populated `xmux` is strictly worse than none at all, and an
/// emitter must write all of these or none.
pub const XMUX_MAX_CONNECTIONS: &str = "6";
pub const XMUX_H_MAX_REQUEST_TIMES: &str = "600-900";
pub const XMUX_H_MAX_REUSABLE_SECS: &str = "1800-3000";

/// Xray transport key spellings.
///
/// v26.7.11 renamed `network` to `method`, `tcpSettings` to `rawSettings` and
/// `splithttpSettings` to `xhttpSettings`, keeping the old names as accepted
/// aliases. We emit the **older** spellings for `network` and `tcpSettings`
/// because the new ones do not exist on any build before v26.7.11 — which is
/// essentially every client currently installed — while the old ones are still
/// parsed by current releases.
///
/// `xhttpSettings` is the exception: it has been accepted since late October
/// 2024 and is what mihomo and v2rayN already expect.
pub mod xray_keys {
    pub const NETWORK: &str = "network";
    pub const RAW_SETTINGS: &str = "tcpSettings";
    pub const XHTTP_SETTINGS: &str = "xhttpSettings";
}

/// Render an optional host, falling back to the server address.
///
/// Every core resolves an absent transport host to the connection address, so
/// emitting it explicitly makes the generated config self-describing and
/// survives a later edit that changes the address.
#[must_use]
pub fn host_or_server<'a>(host: Option<&'a str>, server: &'a str) -> &'a str {
    match host {
        Some(h) if !h.is_empty() => h,
        _ => server,
    }
}

/// Normalise a transport path to a leading slash and no trailing slash.
///
/// The three cores disagree about what they tolerate, and a path that differs
/// only by a slash is one of the least obvious ways for a node to fail: the
/// client connects, the server 404s, and nothing says why.
#[must_use]
pub fn normalise_path(path: &str) -> String {
    let trimmed = path.trim();
    if trimmed.is_empty() || trimmed == "/" {
        return "/".to_owned();
    }
    let with_lead = if trimmed.starts_with('/') {
        trimmed.to_owned()
    } else {
        format!("/{trimmed}")
    };
    let out = with_lead.trim_end_matches('/');
    if out.is_empty() {
        "/".to_owned()
    } else {
        out.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::config::model::{Transport, XhttpMode};

    #[test]
    fn alpn_is_h2_only() {
        assert_eq!(ALPN, &["h2"]);
    }

    #[test]
    fn h2_is_advertised_only_where_the_transport_rides_it() {
        let xhttp = Transport::Xhttp {
            mode: XhttpMode::PacketUp,
            path: "/p".into(),
            host: None,
        };
        assert_eq!(default_alpn(&xhttp), Some(ALPN));
        assert_eq!(
            default_alpn(&Transport::Grpc { service_name: "s".into(), multi_mode: false }),
            Some(ALPN)
        );

        // These need an HTTP/1.1 Upgrade handshake. Pinning h2 leaves no
        // HTTP/1.1 connection for the upgrade to happen on, so the node
        // connects and then hangs — indistinguishable from a dead server.
        for t in [
            Transport::WebSocket { path: "/w".into(), host: None, heartbeat_secs: 30 },
            Transport::HttpUpgrade { path: "/u".into(), host: None },
            Transport::Raw,
        ] {
            assert_eq!(default_alpn(&t), None, "{} must not pin h2", t.name());
        }
    }

    #[test]
    fn sni_prefers_explicit_then_transport_host_then_server_name() {
        assert_eq!(
            effective_sni(Some("a.example"), Some("b.example"), "c.example"),
            Some("a.example")
        );
        assert_eq!(effective_sni(None, Some("b.example"), "c.example"), Some("b.example"));
        assert_eq!(effective_sni(None, None, "c.example"), Some("c.example"));
        // Empty strings are not choices.
        assert_eq!(effective_sni(Some(""), Some(""), "c.example"), Some("c.example"));
    }

    #[test]
    fn an_ip_literal_is_never_emitted_as_sni() {
        // The clean-IP case: connecting to a bare address with the real
        // hostname carried by the transport. An IP is not a valid SNI, so
        // emitting nothing beats emitting something the server rejects.
        assert_eq!(effective_sni(None, None, "93.184.216.34"), None);
        assert_eq!(effective_sni(None, None, "2001:db8::1"), None);
        assert_eq!(
            effective_sni(None, Some("real.example"), "93.184.216.34"),
            Some("real.example")
        );
    }

    #[test]
    fn host_falls_back_to_the_server_address() {
        assert_eq!(host_or_server(Some("cdn.example"), "srv.example"), "cdn.example");
        assert_eq!(host_or_server(None, "srv.example"), "srv.example");
        assert_eq!(host_or_server(Some(""), "srv.example"), "srv.example");
    }

    #[test]
    fn paths_are_normalised_consistently() {
        for (input, want) in [
            ("abc", "/abc"),
            ("/abc", "/abc"),
            ("/abc/", "/abc"),
            ("abc/def/", "/abc/def"),
            ("  /abc  ", "/abc"),
            ("/", "/"),
            ("", "/"),
            ("///", "/"),
        ] {
            assert_eq!(normalise_path(input), want, "input {input:?}");
        }
    }

    #[test]
    fn normalise_path_never_panics() {
        let mut seed = 0x9e37_79b9u64;
        let alphabet = b"/abc .%\0\t";
        for _ in 0..2000 {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            let len = (seed % 24) as usize;
            let s: String = (0..len)
                .map(|i| alphabet[((seed >> (i % 56)) as usize) % alphabet.len()] as char)
                .collect();
            let out = normalise_path(&s);
            assert!(out.starts_with('/'), "must always be rooted: {s:?} -> {out:?}");
        }
    }
}

/// Make a set of node tags unique and non-empty, preserving order.
///
/// Every core refuses a config containing two outbounds with the same tag, and
/// two of them refuse it in a way that names neither node. Deduplicating here
/// means a user who pasted a node twice gets a working export with an obvious
/// `-2` suffix rather than a parse error naming a tag they cannot find.
///
/// `reserved` are names the core uses itself, which a node must never take.
#[must_use]
pub fn unique_tags(nodes: &[crate::config::model::Node], reserved: &[&str], fallback: &str)
    -> Vec<String>
{
    let mut used: Vec<String> = reserved.iter().map(|s| (*s).to_owned()).collect();
    let mut out = Vec::with_capacity(nodes.len());

    for node in nodes {
        let base = {
            let t = node.tag.trim();
            if t.is_empty() { fallback.to_owned() } else { t.to_owned() }
        };
        let mut candidate = base.clone();
        let mut n = 1u32;
        while used.contains(&candidate) {
            n += 1;
            candidate = format!("{base}-{n}");
        }
        used.push(candidate.clone());
        out.push(candidate);
    }
    out
}

#[cfg(test)]
mod unique_tag_tests {
    use super::unique_tags;
    use crate::config::model::{
        Endpoint, Flow, Mux, Node, Protocol, Security, Transport,
    };

    fn node(tag: &str) -> Node {
        Node {
            tag: tag.to_owned(),
            server: Endpoint { address: "h".into(), port: 443 },
            protocol: Protocol::Vless { uuid: "u".into(), flow: Flow::None },
            transport: Transport::Raw,
            security: Security::None,
            mux: Mux::default(),
            chain_via: None,
            worker_served: false,
        }
    }

    #[test]
    fn distinct_tags_are_left_alone() {
        let nodes = [node("a"), node("b")];
        assert_eq!(unique_tags(&nodes, &[], "proxy"), ["a", "b"]);
    }

    #[test]
    fn duplicates_are_suffixed_rather_than_dropped() {
        // A core refuses the whole config on a tag clash, naming neither node.
        let nodes = [node("a"), node("a"), node("a")];
        assert_eq!(unique_tags(&nodes, &[], "proxy"), ["a", "a-2", "a-3"]);
    }

    #[test]
    fn a_reserved_name_is_never_taken_by_a_node() {
        // sing-box's own `direct` outbound, for instance.
        let nodes = [node("direct")];
        assert_eq!(unique_tags(&nodes, &["direct"], "proxy"), ["direct-2"]);
    }

    #[test]
    fn an_empty_tag_becomes_the_fallback_and_still_deduplicates() {
        let nodes = [node(""), node("  "), node("proxy")];
        assert_eq!(unique_tags(&nodes, &[], "proxy"), ["proxy", "proxy-2", "proxy-3"]);
    }

    #[test]
    fn suffixing_does_not_collide_with_an_existing_suffixed_name() {
        let nodes = [node("a"), node("a-2"), node("a")];
        assert_eq!(unique_tags(&nodes, &[], "proxy"), ["a", "a-2", "a-3"]);
    }
}
