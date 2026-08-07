//! mihomo (Clash.Meta) emitter — one [`Node`] rendered as a complete, runnable
//! YAML configuration.
//!
//! Targets **v1.19.22 or newer**, the release that added `network: xhttp`.
//! Everything here was checked against a real v1.19.25 binary with `mihomo -t`,
//! because §9.7 of the parameter inventory is right: mihomo's config decoder
//! ignores keys it does not recognise, so a misspelled field is invisible to
//! any schema check and shows up only as a node that connects and misbehaves.
//! Several of the rules below (`dialer-proxy` must resolve, `DIRECT` is a
//! reserved proxy name, a group may not share a name with its own member, a
//! REALITY public key must be *raw* URL-safe base64) come from that binary
//! rejecting or silently swallowing a config, not from documentation.
//!
//! # Why the YAML is hand-emitted
//!
//! The crate ships no YAML serialiser and may not gain one. Hand-emitting is
//! therefore not a shortcut but the constraint, and it moves the whole risk
//! into quoting: an unquoted password containing `#` truncates at the comment,
//! an unquoted `on` becomes a boolean, an unquoted `1.10` becomes a float. Any
//! of those produce a file mihomo loads happily and authenticates with wrongly.
//! [`needs_quoting`] is deliberately over-eager for that reason — a needlessly
//! quoted scalar costs two bytes; a wrongly plain one costs the node.

use super::util::{host_or_server, normalise_path, ALPN, XMUX_H_MAX_REQUEST_TIMES,
    XMUX_H_MAX_REUSABLE_SECS, XMUX_MAX_CONNECTIONS};
use super::{gate, Dropped, Emit, EmitError, Emitted, Format};
use core::fmt::Write as _;
use crate::config::model::{
    ClientTarget, Core, Flow, Node, Protocol, RealitySettings, Security, TlsSettings, Transport,
    VmessCipher, XhttpMode,
};

/// Local SOCKS+HTTP listener. mihomo has no default — a config without a
/// listener starts and then accepts nothing, which reads as "it doesn't work".
const MIXED_PORT: u16 = 7890;

/// Name of the selector group the rules point at.
///
/// mihomo rejects a group that contains a proxy of the same name with
/// `loop is detected in ProxyGroup`, so [`group_name`] moves off this value if
/// the node happens to be called `PROXY`.
const GROUP_BASE: &str = "PROXY";

/// Outbound names mihomo has already taken.
///
/// A proxy carrying one of these is refused at load with
/// `proxy DIRECT is the duplicate name`. The comparison is case-sensitive —
/// a node called `direct` loads fine. `GLOBAL` is *not* on this list: it names
/// an auto-generated group, and the binary accepts a proxy called `GLOBAL`.
const RESERVED_PROXY_NAMES: [&str; 5] = ["DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE"];

/// uTLS ClientHello identities mihomo can build.
///
/// An unrecognised value is *not* an error: mihomo looks the name up, gets
/// nothing back, and dials with Go's own ClientHello instead. For REALITY that
/// means the handshake cannot complete and nothing is logged, which is why an
/// unknown fingerprint is a refusal there rather than a warning.
const FINGERPRINTS: [&str; 10] = [
    "chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random", "randomized",
];

/// Maximum bytes per uplink POST, as the string mihomo's range parser expects.
///
/// Inventory §8: larger chunks mean fewer requests, and on the free plan the
/// binding limit is request *count*, not bandwidth. Same value as the core
/// default, pinned so a future core change cannot move it under us.
const SC_MAX_EACH_POST_BYTES: &str = "1000000";

/// Minimum gap between uplink POSTs, in milliseconds.
///
/// Inventory §8: lowering this multiplies request count against the 100k/day
/// cap for negligible latency gain.
const SC_MIN_POSTS_INTERVAL_MS: &str = "30";

/// Padding length range. Inventory §8: padding is mandatory in XHTTP and the
/// cost is already priced into the protocol, so the core default is kept.
/// `crate::transport::xhttp::wire` validates against exactly this range, and
/// the padding key and placement are left at the default both sides assume.
const X_PADDING_BYTES: &str = "100-1000";

/// Renders a node as mihomo YAML.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Mihomo;

impl Emit for Mihomo {
    fn core(&self) -> Core {
        Core::Mihomo
    }

    fn emit(&self, node: &Node, target: ClientTarget) -> Result<Emitted, EmitError> {
        // The conflict engine answers per *client*, and its answers differ by
        // core. Rendering mihomo YAML for a client that runs Xray would gate
        // the node against the wrong rule set and hand the user a file their
        // client cannot even read.
        if target.core() != Core::Mihomo {
            return Err(EmitError::Refused(vec![format!(
                "{} does not run mihomo, so a mihomo YAML file is not what it can import — \
                 export it for {} instead",
                target.name(),
                target.core().name()
            )]));
        }

        let mut dropped = gate(node, target)?;
        let proxy = proxy_block(node, &mut dropped)?;
        let group = group_name(&node.tag);

        let mut out = String::with_capacity(1024);
        out.push_str("# Generated by Trinity Panel for mihomo (Clash.Meta) v1.19.22+.\n");
        out.push_str("# Verified with `mihomo -t`; see docs/research/parameter-inventory.md.\n");
        kv(&mut out, 0, "mixed-port", &MIXED_PORT.to_string());
        // Both are mihomo's own defaults, written out because this file may be
        // imported into a client that remembers a previous profile's value.
        // `allow-lan: false` in particular is the difference between a local
        // listener and an open proxy on the user's network.
        kv(&mut out, 0, "allow-lan", "false");
        kv(&mut out, 0, "mode", "rule");
        kv(&mut out, 0, "log-level", "info");

        kv_open(&mut out, 0, "proxies");
        out.push_str(&proxy);

        kv_open(&mut out, 0, "proxy-groups");
        line(&mut out, 1, &format!("- name: {}", scalar(&group)));
        // `select` and never `relay`: mihomo's docs retired the relay strategy
        // in favour of dialer-proxy, and it never handled UDP relaying
        // correctly (inventory §7, mihomo table).
        kv(&mut out, 2, "type", "select");
        kv_open(&mut out, 2, "proxies");
        line(&mut out, 3, &format!("- {}", scalar(&node.tag)));
        line(&mut out, 3, "- DIRECT");

        kv_open(&mut out, 0, "rules");
        // Deliberately geo-free. A GEOIP or GEOSITE rule makes mihomo fetch or
        // load a database before it will run, turning a config test into a
        // network operation and failing on a machine that has neither.
        for rule in [
            "DOMAIN-SUFFIX,localhost,DIRECT",
            "IP-CIDR,127.0.0.0/8,DIRECT,no-resolve",
            "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
            "IP-CIDR,172.16.0.0/12,DIRECT,no-resolve",
            "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",
            "IP-CIDR6,fc00::/7,DIRECT,no-resolve",
        ] {
            line(&mut out, 1, &format!("- {}", quoted(rule)));
        }
        line(&mut out, 1, &format!("- {}", quoted(&format!("MATCH,{group}"))));

        Ok(Emitted { config: out, format: Format::Yaml, dropped })
    }
}

/// A group name that cannot collide with the node it contains.
///
/// mihomo refuses the whole file with `loop is detected in ProxyGroup` when a
/// group lists a proxy of its own name, and it cannot tell that collision from
/// a genuine cycle.
fn group_name(tag: &str) -> String {
    if tag == GROUP_BASE {
        // Reached only when the node itself is called PROXY, and the suffixed
        // form cannot then collide with it in turn.
        return format!("{GROUP_BASE}-1");
    }
    GROUP_BASE.to_owned()
}

/// Render the single `proxies:` entry.
fn proxy_block(node: &Node, dropped: &mut Vec<Dropped>) -> Result<String, EmitError> {
    check_name(&node.tag)?;

    let mut out = String::with_capacity(512);
    line(&mut out, 1, &format!("- name: {}", quoted(&node.tag)));
    // Always quoted: a bare IPv6 literal is full of colons, and a hostname
    // that starts a number-like label would otherwise change type.
    kv(&mut out, 2, "server", &quoted(&node.server.address));
    kv(&mut out, 2, "port", &node.server.port.to_string());

    if let Some(hop) = &node.chain_via {
        // Emitting `dialer-proxy` here would produce a file mihomo refuses to
        // load at all — `proxy [tag] dialer-proxy [hop] not found` — because
        // this export renders exactly one proxy and the hop is not in it. A
        // node the user cannot even import is worse than a node that does not
        // chain, so the chain is dropped and said out loud.
        dropped.push(Dropped::new(
            "chain_via",
            format!(
                "mihomo chains with dialer-proxy, which must name another proxy in the same \
                 file. This export contains only this node, so a dialer-proxy pointing at \
                 \"{hop}\" would make mihomo refuse the whole config with \"dialer-proxy not \
                 found\". Export both hops into one profile and add dialer-proxy by hand, or \
                 chain on the server side."
            ),
        ));
    }

    match &node.protocol {
        Protocol::Vless { uuid, flow } => vless(node, uuid, *flow, &mut out, dropped)?,
        Protocol::Vmess { uuid, cipher } => vmess(node, uuid, *cipher, &mut out, dropped)?,
        Protocol::Trojan { password } => trojan(node, password, &mut out, dropped)?,
        Protocol::Shadowsocks { method, password } => {
            shadowsocks(node, method.wire_name(), password, &mut out, dropped)?;
        }
    }

    Ok(out)
}

/// Reject a name mihomo cannot carry.
fn check_name(tag: &str) -> Result<(), EmitError> {
    if tag.is_empty() {
        return Err(EmitError::Refused(vec![
            "this node has no name. mihomo loads a nameless proxy without complaint, but it \
             then appears as a blank row that cannot be told apart from any other, and the \
             proxy-group entry selecting it is equally blank. Give the node a name."
                .to_owned(),
        ]));
    }
    if RESERVED_PROXY_NAMES.contains(&tag) {
        return Err(EmitError::Refused(vec![format!(
            "\"{tag}\" is one of mihomo's built-in outbounds, so it refuses the config with \
             \"proxy {tag} is the duplicate name\". The check is case-sensitive — \
             \"{}\" would be accepted — but rename the node to something meaningful instead.",
            tag.to_lowercase()
        )]));
    }
    Ok(())
}

/// VLESS: the only mihomo outbound with an `xhttp-opts` block.
fn vless(
    node: &Node,
    uuid: &str,
    flow: Flow,
    out: &mut String,
    dropped: &mut Vec<Dropped>,
) -> Result<(), EmitError> {
    kv(out, 2, "type", "vless");
    kv(out, 2, "uuid", &quoted(uuid));
    kv(out, 2, "udp", "true");

    match flow {
        Flow::None => {}
        // gate() has already refused Vision over a framed transport (Broken)
        // and, for a non-Xray target, the udp443 variant (Untranslatable), so
        // reaching here means raw TCP with TLS or REALITY.
        Flow::Vision | Flow::VisionUdp443 => kv(out, 2, "flow", "xtls-rprx-vision"),
    }
    // Tri-state elsewhere, but not here: mihomo already defaults VLESS to
    // xUDP. Written out because `packet-addr` and `xudp` are mutually
    // exclusive and mihomo silently prefers xudp, so an explicit value is the
    // only way this file states what UDP encoding it expects.
    kv(out, 2, "packet-encoding", "xudp");

    security(node, out, dropped, SniKey::Servername)?;
    transport(node, out, dropped);
    smux(node, out, dropped);
    Ok(())
}

/// VMess. `alterId: 0` is emitted because mihomo still reads the field and a
/// non-zero value selects the removed pre-AEAD handshake.
fn vmess(
    node: &Node,
    uuid: &str,
    cipher: VmessCipher,
    out: &mut String,
    dropped: &mut Vec<Dropped>,
) -> Result<(), EmitError> {
    if matches!(node.transport, Transport::Xhttp { .. }) {
        // Belt and braces: conflicts.rs rates this Untranslatable so gate()
        // refuses it first. Repeated here because the cost of the check being
        // dropped upstream is a config that loads with the transport silently
        // ignored — mihomo does not reject an unknown `network`.
        return Err(EmitError::Refused(vec![
            "mihomo implements XHTTP for VLESS only; its VMess outbound has no xhttp-opts \
             block, and an unknown network value is silently treated as plain TCP rather than \
             reported. Switch this node to VLESS for mihomo."
                .to_owned(),
        ]));
    }

    kv(out, 2, "type", "vmess");
    kv(out, 2, "uuid", &quoted(uuid));
    kv(out, 2, "alterId", "0");
    kv(
        out,
        2,
        "cipher",
        match cipher {
            VmessCipher::Auto => "auto",
            VmessCipher::Aes128Gcm => "aes-128-gcm",
            VmessCipher::Chacha20Poly1305 => "chacha20-poly1305",
            // Genuinely honoured here, unlike Xray, which maps it to auto.
            VmessCipher::Zero => "zero",
        },
    );
    kv(out, 2, "udp", "true");

    security(node, out, dropped, SniKey::Servername)?;
    transport(node, out, dropped);
    smux(node, out, dropped);
    Ok(())
}

/// Trojan. Its TLS is implicit and cannot be switched off, and the SNI field
/// is spelled `sni` rather than `servername`.
fn trojan(
    node: &Node,
    password: &str,
    out: &mut String,
    dropped: &mut Vec<Dropped>,
) -> Result<(), EmitError> {
    if matches!(node.transport, Transport::Xhttp { .. }) {
        return Err(EmitError::Refused(vec![
            "mihomo implements XHTTP for VLESS only; its Trojan outbound has no xhttp-opts \
             block, and an unrecognised network value is silently downgraded to plain TCP \
             instead of being reported. Switch this node to VLESS for mihomo."
                .to_owned(),
        ]));
    }

    kv(out, 2, "type", "trojan");
    kv(out, 2, "password", &quoted(password));
    kv(out, 2, "udp", "true");

    if matches!(node.security, Security::None) {
        dropped.push(Dropped::new(
            "security",
            "mihomo's Trojan outbound always performs a TLS handshake — there is no way to \
             turn it off, because Trojan's whole design is to be indistinguishable from HTTPS. \
             This node was configured without TLS; mihomo will use TLS anyway, so the server \
             must terminate TLS or the connection will fail.",
        ));
    }
    security(node, out, dropped, SniKey::Sni)?;
    transport(node, out, dropped);
    smux(node, out, dropped);
    Ok(())
}

/// Shadowsocks. It has no transport block in any core; a transport is reachable
/// only through `v2ray-plugin`, which is a different framing (inventory §5).
fn shadowsocks(
    node: &Node,
    method: &str,
    password: &str,
    out: &mut String,
    dropped: &mut Vec<Dropped>,
) -> Result<(), EmitError> {
    kv(out, 2, "type", "ss");
    kv(out, 2, "cipher", &scalar(method));
    // Always quoted: a Shadowsocks-2022 key is base64 and ends in `=`, and a
    // passphrase is arbitrary user text.
    kv(out, 2, "password", &quoted(password));
    kv(out, 2, "udp", "true");

    match &node.transport {
        Transport::Raw => {
            if !matches!(node.security, Security::None) {
                dropped.push(Dropped::new(
                    "security",
                    "Shadowsocks carries its own encryption and mihomo gives it no TLS layer of \
                     its own, so the TLS settings on this node cannot be expressed. The \
                     connection is still encrypted by the Shadowsocks cipher, but it is not \
                     wrapped in TLS and will not look like HTTPS on the wire.",
                ));
            }
        }
        Transport::WebSocket { path, host, heartbeat_secs } => {
            let host = host_or_server(host.as_deref(), &node.server.address);
            kv(out, 2, "plugin", "v2ray-plugin");
            kv_open(out, 2, "plugin-opts");
            kv(out, 3, "mode", "websocket");
            kv(out, 3, "host", &quoted(host));
            kv(out, 3, "path", &quoted(&normalise_path(path)));
            match &node.security {
                Security::Tls(t) => {
                    kv(out, 3, "tls", "true");
                    kv(out, 3, "skip-cert-verify", bool_str(t.allow_insecure));
                    if t.fingerprint.is_some() {
                        dropped.push(Dropped::new(
                            "fingerprint",
                            "v2ray-plugin builds its own TLS connection and takes no uTLS \
                             fingerprint, so this node's ClientHello will be Go's rather than \
                             the browser profile you chose.",
                        ));
                    }
                }
                Security::None => kv(out, 3, "tls", "false"),
                Security::Reality(_) => {
                    return Err(EmitError::Refused(vec![
                        "REALITY cannot be combined with Shadowsocks in mihomo. The transport \
                         is provided by v2ray-plugin, which has no REALITY support, and \
                         mihomo's Shadowsocks outbound has no reality-opts field."
                            .to_owned(),
                    ]))
                }
            }
            if *heartbeat_secs > 0 {
                dropped.push(ws_heartbeat_dropped(*heartbeat_secs));
            }
        }
        other => {
            return Err(EmitError::Refused(vec![format!(
                "Shadowsocks cannot use {} in mihomo. Shadowsocks has no transport layer of its \
                 own; the only framing mihomo offers it is v2ray-plugin's WebSocket mode, and \
                 that is not interchangeable with a transport block. Use WebSocket, or switch \
                 this node to VLESS.",
                other.name()
            )]))
        }
    }

    smux(node, out, dropped);
    Ok(())
}

/// Which key this outbound spells the TLS server name with.
#[derive(Clone, Copy)]
enum SniKey {
    /// VLESS and VMess.
    Servername,
    /// Trojan, alone among the four.
    Sni,
}

impl SniKey {
    const fn key(self) -> &'static str {
        match self {
            Self::Servername => "servername",
            Self::Sni => "sni",
        }
    }
}

/// TLS, REALITY, ALPN and the uTLS fingerprint.
fn security(
    node: &Node,
    out: &mut String,
    dropped: &mut Vec<Dropped>,
    sni_key: SniKey,
) -> Result<(), EmitError> {
    match &node.security {
        Security::None => kv(out, 2, "tls", "false"),
        Security::Tls(t) => tls(node, t, out, dropped, sni_key),
        // Only one security mode may be present and every one of them needs
        // `tls: true`; mihomo fails with "security modes are mutually
        // exclusive" and "%s requires TLS" respectively. The model can hold
        // only one, so emitting exactly this block is what keeps that true.
        Security::Reality(r) => reality(r, out, sni_key)?,
    }
    Ok(())
}

fn tls(
    node: &Node,
    t: &TlsSettings,
    out: &mut String,
    dropped: &mut Vec<Dropped>,
    sni_key: SniKey,
) {
    kv(out, 2, "tls", "true");
    let sni = match &t.sni {
        Some(s) if !s.is_empty() => s.as_str(),
        _ => transport_host(node),
    };
    kv(out, 2, sni_key.key(), &quoted(sni));

    // ALPN is only defaulted for XHTTP. util::ALPN is `h2` alone, which is
    // right there because HTTP/2 multiplexes the parallel uplink POSTs — but
    // forcing it on a WebSocket node would be actively harmful: mihomo's
    // WebSocket client speaks the HTTP/1.1 Upgrade handshake, and a connection
    // that negotiated h2 has no upgrade to offer. Anything the user set
    // explicitly is emitted as given, for every transport.
    let alpn: Vec<&str> = if t.alpn.is_empty() {
        if matches!(node.transport, Transport::Xhttp { .. }) {
            ALPN.to_vec()
        } else {
            Vec::new()
        }
    } else {
        t.alpn.iter().map(String::as_str).collect()
    };
    if !alpn.is_empty() {
        kv_open(out, 2, "alpn");
        for a in alpn {
            line(out, 3, &format!("- {}", quoted(a)));
        }
    }

    match &t.fingerprint {
        Some(f) if FINGERPRINTS.contains(&f.as_str()) => kv(out, 2, "client-fingerprint", &scalar(f)),
        Some(f) => dropped.push(Dropped::new(
            "fingerprint",
            format!(
                "mihomo does not know the uTLS fingerprint \"{f}\". It does not report this — \
                 it looks the name up, finds nothing, and dials with Go's own ClientHello, \
                 which is distinctive. Use one of: {}.",
                FINGERPRINTS.join(", ")
            ),
        )),
        // Left unset rather than defaulted: injecting a browser ClientHello
        // changes what the server and every middlebox on the path see, and
        // that is the user's decision to make, not this emitter's.
        None => {}
    }

    // Still accepted here, unlike Xray, which made it a hard error in v26.2.2.
    kv(out, 2, "skip-cert-verify", bool_str(t.allow_insecure));
}

fn reality(r: &RealitySettings, out: &mut String, sni_key: SniKey) -> Result<(), EmitError> {
    // mihomo builds a REALITY client only when the public key parses. An
    // empty or malformed key does not stop the config from loading — either
    // the whole block is skipped, leaving a plain TLS connection the server
    // will reject, or the load fails with "invalid REALITY public key". Both
    // are worth catching here, where the reason can be explained.
    if !is_reality_public_key(&r.public_key) {
        return Err(EmitError::Refused(vec![
            "REALITY needs a public key of 32 bytes in raw URL-safe base64 — 43 characters, \
             no `=` padding, using `-` and `_` rather than `+` and `/`. mihomo rejects any \
             other form with \"invalid REALITY public key\", and if the field is left empty it \
             quietly drops REALITY altogether and dials ordinary TLS, which the server will \
             refuse. Copy the key from the server's REALITY key pair."
                .to_owned(),
        ]));
    }
    if !is_reality_short_id(&r.short_id) {
        return Err(EmitError::Refused(vec![
            "A REALITY short ID must be an even number of hex digits, at most 16 of them (8 \
             bytes). mihomo refuses the config with \"invalid REALITY short ID\". An empty \
             short ID is valid and means the server accepts any client that omits it."
                .to_owned(),
        ]));
    }
    let Some(fp) = r.fingerprint.as_deref().filter(|f| FINGERPRINTS.contains(f)) else {
        return Err(EmitError::Refused(vec![format!(
            "REALITY's handshake is generated by uTLS, which needs a ClientHello identity, and \
             mihomo raises no error when it is missing or unrecognised — it simply cannot \
             complete the handshake. Set a client fingerprint to one of: {}.",
            FINGERPRINTS.join(", ")
        )]));
    };
    if r.server_name.is_empty() {
        return Err(EmitError::Refused(vec![
            "REALITY borrows another site's TLS handshake, so it needs that site's name. With \
             no server name mihomo sends this node's own address as the SNI, the server's \
             REALITY handler will not recognise it, and the connection is dropped with nothing \
             logged on either side."
                .to_owned(),
        ]));
    }

    kv(out, 2, "tls", "true");
    kv(out, 2, sni_key.key(), &quoted(&r.server_name));
    kv(out, 2, "client-fingerprint", &scalar(fp));
    kv_open(out, 2, "reality-opts");
    kv(out, 3, "public-key", &quoted(&r.public_key));
    if !r.short_id.is_empty() {
        kv(out, 3, "short-id", &quoted(&r.short_id));
    }
    Ok(())
}

/// `network:` plus the matching `*-opts` block.
fn transport(node: &Node, out: &mut String, dropped: &mut Vec<Dropped>) {
    match &node.transport {
        Transport::Xhttp { mode, path, host } => {
            let host = host_or_server(host.as_deref(), &node.server.address);
            kv(out, 2, "network", "xhttp");
            kv_open(out, 2, "xhttp-opts");
            kv(out, 3, "path", &quoted(&normalise_path(path)));
            kv(out, 3, "host", &quoted(host));
            // Pinned rather than left at `auto`: auto resolves to packet-up
            // today, but flips to stream-one once REALITY is configured
            // (inventory §8).
            kv(
                out,
                3,
                "mode",
                match mode {
                    XhttpMode::PacketUp => "packet-up",
                    XhttpMode::StreamUp => "stream-up",
                    XhttpMode::StreamOne => "stream-one",
                },
            );
            // Numeric-looking, but range-valued and therefore strings.
            kv(out, 3, "x-padding-bytes", &quoted(X_PADDING_BYTES));
            kv(out, 3, "sc-max-each-post-bytes", &quoted(SC_MAX_EACH_POST_BYTES));
            kv(out, 3, "sc-min-posts-interval-ms", &quoted(SC_MIN_POSTS_INTERVAL_MS));
            // Xray's `xmux`, kebab-cased. Emitted as a complete set: a
            // partially populated block makes every unnamed sub-field fall
            // back to 0, meaning unlimited, which is strictly worse than
            // omitting the block (inventory §9.2).
            kv_open(out, 3, "reuse-settings");
            kv(out, 4, "max-connections", &quoted(XMUX_MAX_CONNECTIONS));
            kv(out, 4, "h-max-request-times", &quoted(XMUX_H_MAX_REQUEST_TIMES));
            kv(out, 4, "h-max-reusable-secs", &quoted(XMUX_H_MAX_REUSABLE_SECS));
            // No `extra` key exists in mihomo; everything Xray nests under
            // `xhttpSettings.extra` belongs here, flattened (inventory §9.4).
            // `sc-max-buffered-posts` and `sc-stream-up-server-secs` are
            // server-side only and are deliberately not emitted on a client.
        }
        Transport::WebSocket { path, host, heartbeat_secs } => {
            ws_opts(node, path, host.as_deref(), false, out);
            if *heartbeat_secs > 0 {
                dropped.push(ws_heartbeat_dropped(*heartbeat_secs));
            }
        }
        // Not a network of its own here: mihomo expresses HTTPUpgrade as the
        // WebSocket transport with the upgrade flag set (inventory §2).
        Transport::HttpUpgrade { path, host } => ws_opts(node, path, host.as_deref(), true, out),
        Transport::Grpc { service_name, multi_mode } => {
            kv(out, 2, "network", "grpc");
            kv_open(out, 2, "grpc-opts");
            kv(out, 3, "grpc-service-name", &quoted(service_name));
            if *multi_mode {
                dropped.push(Dropped::new(
                    "transport",
                    "gRPC multi-mode is an Xray extension; mihomo's grpc-opts carries only the \
                     service name, so this node will use ordinary gun mode. Throughput may be \
                     slightly lower, but it interoperates — an Xray server accepts both.",
                ));
            }
        }
        // mihomo's name for what Xray v26 renamed to `raw`. Worth writing
        // explicitly: mihomo does not reject an unknown network value, it
        // falls back to TCP, so a wrong name here would never be reported.
        Transport::Raw => kv(out, 2, "network", "tcp"),
    }
}

/// `ws-opts`, shared by the WebSocket and HTTPUpgrade transports.
fn ws_opts(node: &Node, path: &str, host: Option<&str>, http_upgrade: bool, out: &mut String) {
    let host = host_or_server(host, &node.server.address);
    kv(out, 2, "network", "ws");
    kv_open(out, 2, "ws-opts");
    kv(out, 3, "path", &quoted(&normalise_path(path)));
    kv_open(out, 3, "headers");
    // The dedicated field would be `host`, but mihomo has none for WebSocket:
    // the Host header is the header. This is the one transport where placing
    // Host in `headers` is correct — Xray hard-errors on it for xhttp and
    // httpupgrade (inventory §9.3).
    kv(out, 4, "Host", &quoted(host));
    if http_upgrade {
        kv(out, 3, "v2ray-http-upgrade", "true");
        // Left off deliberately: fast-open writes the first payload alongside
        // the upgrade request, which saves a round trip but produces a request
        // shape no browser emits.
        kv(out, 3, "v2ray-http-upgrade-fast-open", "false");
    }
}

/// The heartbeat that mihomo has no field for.
fn ws_heartbeat_dropped(secs: u32) -> Dropped {
    Dropped::new(
        "heartbeat_secs",
        format!(
            "mihomo's WebSocket client has no keepalive setting, so the {secs}s ping this node \
             asks for cannot be emitted — Xray's wsSettings.heartbeatPeriod has no counterpart \
             here. An idle connection may be closed by the CDN without either end noticing \
             until the next write fails. Keep the connection in use, or accept the reconnect."
        ),
    )
}

/// `smux`, mihomo's multiplexing — which is *not* Xray's.
fn smux(node: &Node, out: &mut String, dropped: &mut Vec<Dropped>) {
    if !node.mux.enabled {
        return;
    }
    if node.worker_served {
        // mihomo's smux is sing-box's multiplex protocol (h2mux/smux/yamux),
        // an entirely different session layer from Xray's `v1.mux.cool`. This
        // Worker implements neither, so switching it on would produce a node
        // that connects, negotiates nothing the server understands, and
        // carries no traffic.
        dropped.push(Dropped::new(
            "mux",
            "mihomo multiplexes with smux, which speaks sing-box's protocol rather than Xray's \
             v1.mux.cool, and this node's server implements neither. Enabling it would give \
             you a node that connects and then carries nothing, so it was left off. \
             Connection reuse in the transport already covers most of the benefit.",
        ));
        return;
    }

    kv_open(out, 2, "smux");
    kv(out, 3, "enabled", "true");
    // mihomo's own default, stated because the server must agree and this file
    // is the only place the choice is visible.
    kv(out, 3, "protocol", "h2mux");
    if node.mux.concurrency > 0 {
        // Xray's `concurrency` is streams per connection, which is
        // `max-streams` here. `max-connections` and `min-streams` are the
        // alternative sizing policy and are mutually exclusive with it, so
        // only one of the two may ever appear.
        kv(out, 3, "max-streams", &node.mux.concurrency.to_string());
    }
}

/// The host this node presents at the transport layer, used as the TLS SNI
/// fallback so that the two cannot silently disagree.
fn transport_host(node: &Node) -> &str {
    let host = match &node.transport {
        Transport::Xhttp { host, .. }
        | Transport::HttpUpgrade { host, .. }
        | Transport::WebSocket { host, .. } => host.as_deref(),
        Transport::Grpc { .. } | Transport::Raw => None,
    };
    host_or_server(host, &node.server.address)
}

/// A 32-byte X25519 key in raw URL-safe base64.
///
/// mihomo decodes with Go's `base64.RawURLEncoding`, so padded or `+/`
/// standard base64 — the form most panels print — is rejected outright.
fn is_reality_public_key(k: &str) -> bool {
    k.len() == 43
        && k.bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
}

/// Hex, an even number of digits, at most 8 bytes. Empty is legal.
fn is_reality_short_id(s: &str) -> bool {
    s.len() <= 16 && s.len() % 2 == 0 && s.bytes().all(|c| c.is_ascii_hexdigit())
}

const fn bool_str(b: bool) -> &'static str {
    if b {
        "true"
    } else {
        "false"
    }
}

// ---------------------------------------------------------------------------
// YAML rendering
// ---------------------------------------------------------------------------

/// Two spaces per level — the only indentation YAML guarantees is safe, since
/// tabs are forbidden as indentation by the specification.
fn line(out: &mut String, indent: usize, text: &str) {
    for _ in 0..indent {
        out.push_str("  ");
    }
    out.push_str(text);
    out.push('\n');
}

fn kv(out: &mut String, indent: usize, key: &str, value: &str) {
    line(out, indent, &format!("{key}: {value}"));
}

/// A key introducing a nested block or sequence.
fn kv_open(out: &mut String, indent: usize, key: &str) {
    line(out, indent, &format!("{key}:"));
}

/// Characters that give a *plain* scalar a second meaning anywhere in it.
///
/// `#` starts a comment, `:` ends a key, `,[]{}` structure flow collections,
/// `&*!` are anchors/aliases/tags, `|>` are block scalars, quotes open quoted
/// scalars, and `%@\`` are reserved by the specification. A password is exactly
/// the kind of value that contains these.
const INDICATORS: [char; 17] = [
    ':', '#', '{', '}', '[', ']', ',', '&', '*', '!', '|', '>', '\'', '"', '%', '@', '`',
];

/// Whether a plain scalar would be misread.
///
/// Errs towards quoting. The failure it guards against is not a parse error —
/// it is a value that parses as something other than the string it was: `on`
/// as a boolean, `1.10` as a float that loses its trailing zero, a password
/// truncated at a `#`.
fn needs_quoting(s: &str) -> bool {
    if s.is_empty() {
        return true;
    }
    // Leading or trailing whitespace does not survive a plain scalar at all —
    // YAML strips it, and a password with a trailing space would authenticate
    // nowhere with no visible difference in the file.
    if s.trim() != s {
        return true;
    }
    if s.chars().any(|c| INDICATORS.contains(&c) || c.is_control()) {
        return true;
    }
    // Only special in first position, but decisive there.
    if s.starts_with(['-', '?', '~', '\\', '\u{feff}']) {
        return true;
    }
    resembles_non_string(s)
}

/// Whether a plain scalar would be typed as something other than a string.
///
/// YAML 1.1, which mihomo's parser follows, resolves a longer list of words to
/// booleans than YAML 1.2 does — `yes`, `no`, `on` and `off` among them.
fn resembles_non_string(s: &str) -> bool {
    const WORDS: [&str; 15] = [
        "y", "n", "yes", "no", "true", "false", "on", "off", "null", "nil", "none", "~", "inf",
        "-inf", "nan",
    ];
    let lower = s.to_ascii_lowercase();
    if WORDS.contains(&lower.as_str()) {
        return true;
    }
    // Numbers, including the hex, octal and underscore-grouped forms YAML 1.1
    // accepts, and the sexagesimals it also accepts. Anything made only of
    // digits and number punctuation is treated as suspect rather than parsed
    // exactly — a false positive costs two quote characters.
    s.bytes()
        .all(|c| c.is_ascii_digit() || b"+-._eExXaAbBcCdDfFoO:".contains(&c))
        && s.bytes().any(|c| c.is_ascii_digit())
}

/// A double-quoted scalar, always. Used for every value whose exact bytes
/// matter — names, addresses, UUIDs, passwords, paths, keys — regardless of
/// whether the plain form would have survived.
fn quoted(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            // Control characters and the Unicode line breaks YAML also treats
            // as line breaks inside double quotes. Left as escapes so the
            // emitted file is a single line per value no matter what the user
            // pasted into the field.
            '\u{0}'..='\u{1f}' | '\u{7f}' => {
                // Writing into a String cannot fail; the result is discarded
                // rather than unwrapped because this crate forbids unwrap.
                let _ = write!(out, "\\x{:02x}", c as u32);
            }
            '\u{85}' | '\u{2028}' | '\u{2029}' | '\u{feff}' => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            _ => out.push(c),
        }
    }
    out.push('"');
    out
}

/// A scalar quoted only if it needs to be. For values that are ours rather
/// than the user's — enum spellings and the like — where a plain scalar keeps
/// the file readable.
fn scalar(s: &str) -> String {
    if needs_quoting(s) {
        quoted(s)
    } else {
        s.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::model::{Endpoint, Mux, SsMethod};

    // -- quoting -----------------------------------------------------------

    #[test]
    fn every_yaml_indicator_forces_quoting() {
        for c in INDICATORS {
            let s = format!("pa{c}ss");
            assert!(needs_quoting(&s), "{s:?} must be quoted");
        }
    }

    #[test]
    fn whitespace_and_emptiness_force_quoting() {
        for s in ["", " ", "  pass", "pass  ", "\tpass", "pass\n", " "] {
            assert!(needs_quoting(s), "{s:?} must be quoted");
        }
    }

    #[test]
    fn values_that_would_change_type_are_quoted() {
        for s in [
            "yes", "no", "YES", "No", "on", "off", "true", "False", "null", "~", "1", "0755",
            "1.10", "1e5", "0x1f", "12:30", "-1", "nan",
        ] {
            assert!(needs_quoting(s), "{s:?} would not survive as a string");
        }
    }

    #[test]
    fn leading_only_indicators_are_caught() {
        assert!(needs_quoting("-dash"));
        assert!(needs_quoting("?query"));
        assert!(needs_quoting("~tilde"));
        // The same characters inside a word are harmless.
        assert!(!needs_quoting("packet-up"));
        assert!(!needs_quoting("aes-256-gcm"));
        assert!(!needs_quoting("chrome"));
    }

    #[test]
    fn quoting_escapes_what_would_break_out_of_the_quotes() {
        assert_eq!(quoted(r#"a"b"#), r#""a\"b""#);
        assert_eq!(quoted(r"a\b"), r#""a\\b""#);
        assert_eq!(quoted("a\nb"), r#""a\nb""#);
        assert_eq!(quoted("a\tb"), r#""a\tb""#);
        assert_eq!(quoted("a\u{0}b"), r#""a\x00b""#);
        assert_eq!(quoted("a\u{2028}b"), r#""a\u2028b""#);
        assert_eq!(quoted(""), r#""""#);
    }

    #[test]
    fn a_password_full_of_indicators_survives_intact() {
        // The case this whole helper exists for: every one of these characters
        // is legal in a Trojan password.
        let pw = r#"p@ss: #1 {a}[b] & *c ! |x >y 'q' "d" 100% `tick` \esc"#;
        let rendered = quoted(pw);
        assert!(rendered.starts_with('"') && rendered.ends_with('"'));
        // Unescape and compare, so the test proves round-trip fidelity rather
        // than matching a literal we could have got wrong in the same way.
        assert_eq!(unescape(&rendered), pw);
    }

    /// Minimal double-quoted YAML unescaper, for the round-trip test only.
    fn unescape(s: &str) -> String {
        let inner = &s[1..s.len() - 1];
        let mut out = String::new();
        let mut it = inner.chars();
        while let Some(c) = it.next() {
            if c != '\\' {
                out.push(c);
                continue;
            }
            match it.next() {
                Some('n') => out.push('\n'),
                Some('r') => out.push('\r'),
                Some('t') => out.push('\t'),
                Some('x') => {
                    let hex: String = it.by_ref().take(2).collect();
                    let n = u32::from_str_radix(&hex, 16).unwrap();
                    out.push(char::from_u32(n).unwrap());
                }
                Some('u') => {
                    let hex: String = it.by_ref().take(4).collect();
                    let n = u32::from_str_radix(&hex, 16).unwrap();
                    out.push(char::from_u32(n).unwrap());
                }
                Some(other) => out.push(other),
                None => break,
            }
        }
        out
    }

    #[test]
    fn scalar_leaves_ordinary_words_plain() {
        assert_eq!(scalar("vless"), "vless");
        assert_eq!(scalar("packet-up"), "packet-up");
        assert_eq!(scalar("PROXY"), "PROXY");
        assert_eq!(scalar("no"), "\"no\"");
    }

    // -- emission ----------------------------------------------------------

    fn node() -> Node {
        Node {
            tag: "cf-xhttp".into(),
            server: Endpoint { address: "edge.example.com".into(), port: 443 },
            protocol: Protocol::Vless {
                uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".into(),
                flow: Flow::None,
            },
            transport: Transport::Xhttp {
                mode: XhttpMode::PacketUp,
                path: "/xh".into(),
                host: None,
            },
            security: Security::Tls(TlsSettings::default()),
            mux: Mux::default(),
            chain_via: None,
            worker_served: true,
        }
    }

    fn emit(n: &Node) -> Emitted {
        Mihomo.emit(n, ClientTarget::Mihomo).expect("node should emit")
    }

    #[test]
    fn emits_a_complete_document() {
        let e = emit(&node());
        assert_eq!(e.format, Format::Yaml);
        for key in [
            "mixed-port: 7890",
            "mode: rule",
            "log-level: info",
            "proxies:",
            "proxy-groups:",
            "rules:",
            "- \"MATCH,PROXY\"",
        ] {
            assert!(e.config.contains(key), "missing {key}:\n{}", e.config);
        }
        assert!(e.config.contains("type: vless"));
        assert!(e.config.contains("network: xhttp"));
        assert!(!e.config.contains('\t'), "tabs are illegal as YAML indentation");
    }

    #[test]
    fn xhttp_opts_are_kebab_case_and_string_valued() {
        let e = emit(&node());
        for want in [
            "      path: \"/xh\"",
            "      host: \"edge.example.com\"",
            "      mode: packet-up",
            "      x-padding-bytes: \"100-1000\"",
            "      sc-max-each-post-bytes: \"1000000\"",
            "      sc-min-posts-interval-ms: \"30\"",
            "      reuse-settings:",
            "        max-connections: \"6\"",
            "        h-max-request-times: \"600-900\"",
            "        h-max-reusable-secs: \"1800-3000\"",
        ] {
            assert!(e.config.contains(want), "missing {want:?}:\n{}", e.config);
        }
        // mihomo has no `extra`; §9.4 says those settings are flattened.
        assert!(!e.config.contains("extra:"));
        // Server-side only — emitting them on a client is noise at best.
        assert!(!e.config.contains("sc-max-buffered-posts"));
        assert!(!e.config.contains("sc-stream-up-server-secs"));
    }

    #[test]
    fn alpn_is_forced_only_where_it_helps() {
        let e = emit(&node());
        assert!(e.config.contains("alpn:"), "xhttp should pin h2");

        let mut ws = node();
        ws.transport = Transport::WebSocket { path: "/w".into(), host: None, heartbeat_secs: 0 };
        // h2 would leave mihomo's HTTP/1.1 upgrade handshake with nothing to
        // upgrade, so no ALPN is emitted unless the user asked for one.
        assert!(!emit(&ws).config.contains("alpn:"));
    }

    #[test]
    fn httpupgrade_is_websocket_plus_a_flag() {
        let mut n = node();
        n.worker_served = false;
        n.transport = Transport::HttpUpgrade { path: "u".into(), host: Some("cdn.example".into()) };
        let e = emit(&n);
        assert!(e.config.contains("network: ws"));
        assert!(e.config.contains("v2ray-http-upgrade: true"));
        assert!(e.config.contains("Host: \"cdn.example\""));
        assert!(!e.config.contains("network: httpupgrade"));
        assert!(e.config.contains("path: \"/u\""), "path must be normalised");
    }

    #[test]
    fn websocket_heartbeat_is_reported_lost_rather_than_dropped_silently() {
        let mut n = node();
        n.transport = Transport::WebSocket { path: "/w".into(), host: None, heartbeat_secs: 30 };
        let e = emit(&n);
        let d = e
            .dropped
            .iter()
            .find(|d| d.field == "heartbeat_secs")
            .expect("the lost heartbeat must reach the user");
        assert!(d.reason.contains("30s"));
    }

    #[test]
    fn relay_group_type_is_never_emitted() {
        let e = emit(&node());
        assert!(e.config.contains("type: select"));
        assert!(!e.config.contains("relay"));
    }

    #[test]
    fn a_node_named_like_the_group_does_not_create_a_loop() {
        let mut n = node();
        n.tag = "PROXY".into();
        let e = emit(&n);
        assert!(e.config.contains("- name: \"PROXY\""));
        assert!(e.config.contains("- name: PROXY-1"));
        assert!(e.config.contains("\"MATCH,PROXY-1\""));
    }

    #[test]
    fn reserved_and_empty_names_are_refused_with_a_reason() {
        for tag in ["DIRECT", "REJECT", "PASS", ""] {
            let mut n = node();
            n.tag = tag.into();
            let err = Mihomo.emit(&n, ClientTarget::Mihomo).expect_err("must refuse");
            let EmitError::Refused(reasons) = err else { panic!("wrong error") };
            assert!(reasons.iter().all(|r| r.len() > 60), "{reasons:?}");
        }
        // Case-sensitive, as the binary is.
        let mut n = node();
        n.tag = "direct".into();
        assert!(Mihomo.emit(&n, ClientTarget::Mihomo).is_ok());
    }

    #[test]
    fn chaining_is_dropped_rather_than_emitted_as_a_dangling_reference() {
        let mut n = node();
        n.chain_via = Some("hop-1".into());
        let e = emit(&n);
        // A dialer-proxy naming a proxy that is not in the file makes mihomo
        // refuse the whole config, so it must not appear.
        assert!(!e.config.contains("dialer-proxy"));
        let d = e.dropped.iter().find(|d| d.field == "chain_via").expect("must be reported");
        assert!(d.reason.contains("hop-1"));
    }

    #[test]
    fn reality_needs_a_key_a_fingerprint_and_a_borrowed_name() {
        let mut n = node();
        n.worker_served = false;
        n.transport = Transport::Raw;
        n.security = Security::Reality(RealitySettings {
            public_key: "xbnMTmz7HHhLbLmGnb1UnZfxOKmnPGnGnZmSPMHZfXc".into(),
            short_id: "6ba85179e30d4fc2".into(),
            server_name: "www.microsoft.com".into(),
            fingerprint: Some("chrome".into()),
        });
        let e = emit(&n);
        assert!(e.config.contains("reality-opts:"));
        assert!(e.config.contains("client-fingerprint: chrome"));
        assert!(e.config.contains("tls: true"));
        assert!(e.config.contains("public-key: \"xbnMTmz7HHhLbLmGnb1UnZfxOKmnPGnGnZmSPMHZfXc\""));

        // Padded standard base64 is what most panels print, and mihomo rejects
        // it outright.
        let mut bad = n.clone();
        bad.security = Security::Reality(RealitySettings {
            public_key: "xbnMTmz7HHhLbLmGnb1UnZfxOKmnPGnGnZmSPMHZfXc=".into(),
            short_id: "6ba85179e30d4fc2".into(),
            server_name: "www.microsoft.com".into(),
            fingerprint: Some("chrome".into()),
        });
        assert!(matches!(
            Mihomo.emit(&bad, ClientTarget::Mihomo),
            Err(EmitError::Refused(_))
        ));

        // An empty key silently disables REALITY, which is exactly the failure
        // this project exists to prevent.
        let mut empty = n.clone();
        empty.security = Security::Reality(RealitySettings {
            fingerprint: Some("chrome".into()),
            server_name: "www.microsoft.com".into(),
            ..Default::default()
        });
        assert!(matches!(
            Mihomo.emit(&empty, ClientTarget::Mihomo),
            Err(EmitError::Refused(_))
        ));

        // An odd-length short ID is refused by the binary too.
        let mut odd = n;
        odd.security = Security::Reality(RealitySettings {
            public_key: "xbnMTmz7HHhLbLmGnb1UnZfxOKmnPGnGnZmSPMHZfXc".into(),
            short_id: "abc".into(),
            server_name: "www.microsoft.com".into(),
            fingerprint: Some("chrome".into()),
        });
        assert!(matches!(
            Mihomo.emit(&odd, ClientTarget::Mihomo),
            Err(EmitError::Refused(_))
        ));
    }

    #[test]
    fn an_unknown_fingerprint_is_reported_not_passed_through() {
        let mut n = node();
        n.security = Security::Tls(TlsSettings {
            fingerprint: Some("netscape".into()),
            ..Default::default()
        });
        let e = emit(&n);
        assert!(!e.config.contains("client-fingerprint"));
        assert!(e.dropped.iter().any(|d| d.field == "fingerprint"));
    }

    #[test]
    fn trojan_uses_sni_and_says_that_tls_cannot_be_switched_off() {
        let mut n = node();
        n.worker_served = false;
        n.protocol = Protocol::Trojan { password: "p@ss: #1".into() };
        n.transport = Transport::WebSocket { path: "/w".into(), host: None, heartbeat_secs: 0 };
        n.security = Security::None;
        let e = emit(&n);
        assert!(e.config.contains("password: \"p@ss: #1\""));
        assert!(e.dropped.iter().any(|d| d.field == "security"));

        n.security = Security::Tls(TlsSettings { sni: Some("cdn.example".into()), ..Default::default() });
        let e = emit(&n);
        assert!(e.config.contains("sni: \"cdn.example\""));
        assert!(!e.config.contains("servername:"));
    }

    #[test]
    fn shadowsocks_over_websocket_goes_through_the_plugin() {
        let mut n = node();
        n.worker_served = false;
        n.protocol = Protocol::Shadowsocks {
            method: SsMethod::Blake3Aes256Gcm,
            password: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
        };
        n.transport = Transport::WebSocket { path: "/w".into(), host: None, heartbeat_secs: 0 };
        let e = emit(&n);
        assert!(e.config.contains("plugin: v2ray-plugin"));
        assert!(e.config.contains("mode: websocket"));
        // The trailing `=` of a 2022 key is why this must always be quoted.
        assert!(e.config.contains("password: \"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\""));
        assert!(!e.config.contains("network: ws"), "ss has no transport block");

        // gRPC has no plugin mode at all, and silently dropping the transport
        // would leave a node that cannot reach the server.
        let mut g = n;
        g.transport = Transport::Grpc { service_name: "s".into(), multi_mode: false };
        assert!(matches!(Mihomo.emit(&g, ClientTarget::Mihomo), Err(EmitError::Refused(_))));
    }

    #[test]
    fn vmess_with_xhttp_is_refused_even_if_the_gate_is_bypassed() {
        let mut n = node();
        n.protocol = Protocol::Vmess {
            uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".into(),
            cipher: VmessCipher::Auto,
        };
        // gate() rates this Untranslatable, so this is the refusal we get.
        let err = Mihomo.emit(&n, ClientTarget::Mihomo).expect_err("VMess + XHTTP is refused");
        assert!(matches!(err, EmitError::Refused(_)));

        // With a transport mihomo does support, VMess emits normally.
        n.transport = Transport::WebSocket { path: "/w".into(), host: None, heartbeat_secs: 0 };
        let e = emit(&n);
        assert!(e.config.contains("type: vmess"));
        assert!(e.config.contains("alterId: 0"));
        assert!(e.config.contains("cipher: auto"));
    }

    #[test]
    fn smux_is_withheld_from_worker_served_nodes_and_explained() {
        let mut n = node();
        n.mux = Mux { enabled: true, concurrency: 8 };
        let e = emit(&n);
        assert!(!e.config.contains("smux:"));
        assert!(
            e.dropped
                .iter()
                .any(|d| d.field == "mux" && d.reason.contains("v1.mux.cool")),
            "the reason smux was withheld must reach the user: {:?}",
            e.dropped
        );

        // An external hop may well run a server that speaks sing-mux.
        let mut ext = n;
        ext.worker_served = false;
        ext.transport = Transport::WebSocket { path: "/w".into(), host: None, heartbeat_secs: 0 };
        let e = emit(&ext);
        assert!(e.config.contains("smux:"));
        assert!(e.config.contains("max-streams: 8"));
        assert!(!e.config.contains("max-connections"), "sizing policies are exclusive");
    }

    #[test]
    fn a_non_mihomo_client_is_refused_rather_than_handed_yaml_it_cannot_read() {
        let err = Mihomo
            .emit(&node(), ClientTarget::V2rayN)
            .expect_err("v2rayN runs Xray");
        let EmitError::Refused(reasons) = err else { panic!("wrong error") };
        assert!(reasons.iter().any(|r| r.contains("Xray")));
    }

    #[test]
    fn degradations_from_the_gate_survive_into_the_output() {
        let mut n = node();
        n.transport = Transport::Xhttp {
            mode: XhttpMode::StreamUp,
            path: "/xh".into(),
            host: None,
        };
        let e = emit(&n);
        assert!(
            e.dropped.iter().any(|d| d.field == "xhttp_mode"),
            "the duplex caveat must reach the user"
        );
    }

    #[test]
    fn hostile_field_values_never_break_the_document_shape() {
        let mut n = node();
        n.tag = "node: #1 [prod]".into();
        n.protocol = Protocol::Vless {
            uuid: "*not-a-uuid & {weird}".into(),
            flow: Flow::None,
        };
        n.transport = Transport::Xhttp {
            mode: XhttpMode::PacketUp,
            path: "/p#1".into(),
            host: Some("h:1".into()),
        };
        let e = emit(&n);
        for l in e.config.lines() {
            // Every line is either a comment, a key, or a sequence item; none
            // of the injected characters may start a new one.
            assert!(
                l.starts_with('#') || l.trim_start().starts_with('-') || l.contains(": ") || l.ends_with(':'),
                "line escaped its structure: {l:?}"
            );
        }
        assert!(e.config.contains("- name: \"node: #1 [prod]\""));
        assert!(e.config.contains("uuid: \"*not-a-uuid & {weird}\""));
    }
}

/// Render several nodes as one mihomo config.
///
/// A multi-node profile is not several single-node files concatenated: mihomo
/// takes one `proxies` list and one `proxy-groups` block, and a group that
/// lists a proxy of its own name is refused as a loop.
///
/// # Errors
/// [`EmitError::Refused`] when the list is empty, when the target does not run
/// mihomo, or when every node is rejected by [`gate`].
pub fn emit_nodes(nodes: &[Node], target: ClientTarget) -> Result<Emitted, EmitError> {
    if target.core() != Core::Mihomo {
        return Err(EmitError::Refused(vec![format!(
            "{} does not run mihomo, so a mihomo YAML file is not what it can import — \
             export it for {} instead",
            target.name(),
            target.core().name()
        )]));
    }
    if nodes.is_empty() {
        return Err(EmitError::Refused(vec![
            "no nodes to export; a mihomo profile with an empty proxies list has nothing to \
             proxy through"
                .to_owned(),
        ]));
    }

    // The group name is reserved so no proxy can take it: mihomo reports
    // `loop is detected in ProxyGroup` and cannot tell that collision from a
    // genuine cycle.
    let tags = crate::translate::util::unique_tags(nodes, &[GROUP_BASE, "DIRECT"], "proxy");
    let label = nodes.len() > 1;

    let mut dropped = Vec::new();
    let mut refusals = Vec::new();
    let mut blocks = Vec::new();
    let mut usable_tags: Vec<String> = Vec::new();

    for (node, tag) in nodes.iter().zip(&tags) {
        // Render under the deduplicated tag, so the `proxies` entry and the
        // group member always agree.
        let mut renamed = node.clone();
        renamed.tag.clone_from(tag);

        let mut node_dropped = match gate(&renamed, target) {
            Ok(f) => f,
            Err(EmitError::Refused(reasons)) => {
                refusals.extend(reasons.iter().map(|r| label_reason(r, tag, label)));
                continue;
            }
            Err(other) => return Err(other),
        };
        match proxy_block(&renamed, &mut node_dropped) {
            Ok(block) => {
                blocks.push(block);
                usable_tags.push(tag.clone());
                dropped.extend(node_dropped.into_iter().map(|d| Dropped {
                    field: d.field,
                    reason: label_reason(&d.reason, tag, label),
                }));
            }
            Err(EmitError::Refused(reasons)) => {
                refusals.extend(reasons.iter().map(|r| label_reason(r, tag, label)));
            }
            Err(other) => return Err(other),
        }
    }

    if usable_tags.is_empty() {
        return Err(EmitError::Refused(refusals));
    }
    dropped.extend(refusals.into_iter().map(|r| Dropped::new("node", r)));

    let mut out = String::with_capacity(1024 + blocks.len() * 512);
    out.push_str("# Generated by Trinity Panel for mihomo (Clash.Meta) v1.19.22+.\n");
    out.push_str("# Verified with `mihomo -t`; see docs/research/parameter-inventory.md.\n");
    kv(&mut out, 0, "mixed-port", &MIXED_PORT.to_string());
    kv(&mut out, 0, "allow-lan", "false");
    kv(&mut out, 0, "mode", "rule");
    kv(&mut out, 0, "log-level", "info");

    kv_open(&mut out, 0, "proxies");
    for block in &blocks {
        out.push_str(block);
    }

    kv_open(&mut out, 0, "proxy-groups");
    line(&mut out, 1, &format!("- name: {}", scalar(GROUP_BASE)));
    // `select` and never `relay`: mihomo retired the relay strategy in favour
    // of dialer-proxy, and it never handled UDP relaying correctly.
    kv(&mut out, 2, "type", "select");
    kv_open(&mut out, 2, "proxies");
    for tag in &usable_tags {
        line(&mut out, 3, &format!("- {}", scalar(tag)));
    }
    line(&mut out, 3, "- DIRECT");

    kv_open(&mut out, 0, "rules");
    // Deliberately geo-free. A GEOIP or GEOSITE rule makes mihomo fetch or load
    // a database before it will run, turning a config test into a network
    // operation and failing on a machine that has neither.
    for rule in [
        "DOMAIN-SUFFIX,localhost,DIRECT",
        "IP-CIDR,127.0.0.0/8,DIRECT,no-resolve",
        "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
        "IP-CIDR,172.16.0.0/12,DIRECT,no-resolve",
        "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",
        "IP-CIDR6,fc00::/7,DIRECT,no-resolve",
    ] {
        line(&mut out, 1, &format!("- {}", quoted(rule)));
    }
    line(&mut out, 1, &format!("- {}", quoted(&format!("MATCH,{GROUP_BASE}"))));

    Ok(Emitted { config: out, format: Format::Yaml, dropped })
}

/// Attach a node's name to a message, but only when there is more than one.
fn label_reason(reason: &str, tag: &str, label: bool) -> String {
    if label {
        format!("{tag}: {reason}")
    } else {
        reason.to_owned()
    }
}

#[cfg(test)]
mod multi_node_tests {
    use super::*;
    use crate::config::model::{
        Endpoint, Flow, Mux, Protocol, Security, TlsSettings, Transport, XhttpMode,
    };

    fn node(tag: &str) -> Node {
        Node {
            tag: tag.to_owned(),
            server: Endpoint { address: "example.com".into(), port: 443 },
            protocol: Protocol::Vless {
                uuid: "01234567-89ab-cdef-0123-456789abcdef".into(),
                flow: Flow::None,
            },
            transport: Transport::WebSocket {
                path: "/ws".into(),
                host: None,
                heartbeat_secs: 0,
            },
            security: Security::Tls(TlsSettings {
                sni: Some("example.com".into()),
                ..TlsSettings::default()
            }),
            mux: Mux::default(),
            chain_via: None,
            worker_served: false,
        }
    }

    fn emit(nodes: &[Node]) -> String {
        emit_nodes(nodes, ClientTarget::Mihomo).expect("emits").config
    }

    #[test]
    fn several_nodes_share_one_group() {
        let yaml = emit(&[node("tokyo"), node("paris")]);
        // Proxy names are quoted scalars; group members are plain.
        assert!(yaml.contains(r#"name: "tokyo""#), "{yaml}");
        assert!(yaml.contains(r#"name: "paris""#), "{yaml}");
        // One group, listing both and DIRECT.
        assert_eq!(yaml.matches("proxy-groups:").count(), 1);
        assert!(yaml.contains("- tokyo
"));
        assert!(yaml.contains("- paris
"));
        assert!(yaml.contains("- DIRECT"));
        assert!(yaml.contains("MATCH,PROXY"));
    }

    #[test]
    fn a_node_named_after_the_group_is_renamed() {
        // mihomo reports `loop is detected in ProxyGroup` and cannot tell that
        // collision from a genuine cycle.
        let yaml = emit(&[node(GROUP_BASE)]);
        assert!(yaml.contains(r#"name: "PROXY-2""#), "{yaml}");
        // And the group itself keeps the reserved name.
        assert!(yaml.contains("- name: PROXY
"), "{yaml}");
    }

    #[test]
    fn duplicate_names_are_made_unique() {
        let yaml = emit(&[node("same"), node("same")]);
        assert!(yaml.contains(r#"name: "same""#), "{yaml}");
        assert!(yaml.contains(r#"name: "same-2""#), "{yaml}");
    }

    #[test]
    fn one_untranslatable_node_does_not_lose_the_others() {
        let mut bad = node("xh");
        bad.transport = Transport::Xhttp {
            mode: XhttpMode::StreamOne,
            path: "/x".into(),
            host: None,
        };
        bad.worker_served = true;
        let e = emit_nodes(&[node("good"), bad], ClientTarget::Mihomo).expect("emits");
        assert!(e.config.contains(r#"name: "good""#), "{}", e.config);
        assert!(!e.dropped.is_empty());
    }

    #[test]
    fn an_empty_list_is_refused() {
        assert!(emit_nodes(&[], ClientTarget::Mihomo).is_err());
    }

    #[test]
    fn a_client_running_another_core_is_refused() {
        assert!(emit_nodes(&[node("a")], ClientTarget::V2rayN).is_err());
        assert!(emit_nodes(&[node("a")], ClientTarget::Hiddify).is_err());
    }
}
