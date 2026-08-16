//! Xray-core v26.x JSON.
//!
//! Emits a complete client configuration — log, a local SOCKS inbound, the
//! node as an outbound, and routing — rather than a bare outbound fragment.
//! A fragment cannot be handed to `xray run -test`, and the project brief's
//! validation rule (`docs/research/parameter-inventory.md` §9.7) is that the
//! real binary is the authority on whether a config is valid. Something that
//! cannot be executed cannot be validated.
//!
//! # What this file encodes that a hand-written string would not
//!
//! Every trap in §9 of the parameter inventory is a case where a config that
//! reads correctly is rejected, or worse, accepted and then quietly wrong:
//!
//! * §9.1 — three transport keys were renamed 19 days before this was written.
//!   The old spellings are what installed clients understand, so those are what
//!   is emitted. See [`crate::translate::util::xray_keys`].
//! * §9.2 — a partially populated `xmux` is strictly worse than none, because
//!   the presence of any one field cancels Xray's whole default bundle.
//! * §9.3 — a `Host` entry inside `headers` is a hard error on XHTTP and
//!   HTTPUpgrade. The dedicated `host` field is the only spelling used here.
//! * §9.8 — multiple servers are multiple outbounds plus a balancer. Xray
//!   hard-errors on a second member of `vnext[]`, `users[]` or `servers[]`,
//!   so [`emit_nodes`] expands a node list rather than an array of servers.
//!
//! `allowInsecure` is never emitted under any circumstance: it became a hard
//! configuration error in v26.2.2, and emitting it turns a working config into
//! one that will not load at all.

use std::collections::BTreeSet;

use serde_json::{json, Map, Value};

use super::util::{self, xray_keys};
use super::{gate, Dropped, Emit, EmitError, Emitted, Format};
use crate::config::model::{
    ClientTarget, Core, Flow, Node, Protocol, Security, Transport, VmessCipher, XhttpMode,
};

/// Tag of the local SOCKS inbound the generated config listens on.
const INBOUND_TAG: &str = "socks-in";
/// Tag of the freedom outbound that LAN and loopback traffic is routed to.
const DIRECT_TAG: &str = "direct";
/// Tag of the balancer that fans traffic across the nodes, when there is more
/// than one.
const BALANCER_TAG: &str = "balancer";

/// Loopback port of the generated SOCKS inbound.
///
/// 10808 is what v2rayN, v2rayNG and NekoBox all default to, so a config
/// generated here drops into an existing client setup without the user having
/// to re-point their system proxy.
const SOCKS_PORT: u16 = 10808;

/// Xray refuses a `mux.concurrency` above this, and the field is an `int16`
/// besides — a larger value fails to decode before any range check runs
/// (verified: `cannot unmarshal number 65535 into … MuxConfig … of type int16`).
const MUX_MAX_CONCURRENCY: u16 = 1024;

/// Xray's own `mux.concurrency` default, used when a node asks for
/// multiplexing without naming a width.
const MUX_DEFAULT_CONCURRENCY: u16 = 8;

/// The Xray emitter.
#[derive(Debug, Clone, Copy, Default)]
pub struct XrayEmitter;

impl Emit for XrayEmitter {
    fn core(&self) -> Core {
        Core::Xray
    }

    fn emit(&self, node: &Node, target: ClientTarget) -> Result<Emitted, EmitError> {
        emit_nodes(core::slice::from_ref(node), target)
    }
}

/// Render one or more nodes as a single runnable Xray configuration.
///
/// Takes a slice rather than a node because Xray expresses multi-server as
/// multiple outbounds plus a routing balancer (§9.8) — a second member of
/// `vnext[]` or `servers[]` is a hard error, not a shorthand. Accepting a slice
/// here is what keeps that fact in one place instead of leaving a future caller
/// to discover it from Xray's error message.
///
/// # Errors
/// [`EmitError::Refused`] when the list is empty, when tags collide or are
/// unusable, when the target is not executed by Xray, or when any node is
/// rejected by [`gate`].
pub fn emit_nodes(nodes: &[Node], target: ClientTarget) -> Result<Emitted, EmitError> {
    if target.core() != Core::Xray {
        return Err(EmitError::Refused(vec![format!(
            "{} runs {}, not Xray — an Xray JSON config would not be read by it",
            target.name(),
            target.core().name()
        )]));
    }
    if nodes.is_empty() {
        return Err(EmitError::Refused(vec![
            "no nodes to export; an Xray config with an empty outbound list has nothing to \
             proxy through"
                .to_owned(),
        ]));
    }

    check_tags(nodes)?;

    let known: BTreeSet<&str> = nodes.iter().map(tag_of).collect();
    let label = nodes.len() > 1;

    let mut dropped = Vec::new();
    let mut refusals = Vec::new();
    let mut outbounds = Vec::with_capacity(nodes.len() + 1);

    for node in nodes {
        match gate(node, target) {
            Ok(findings) => {
                dropped.extend(findings.into_iter().map(|d| relabel(d, tag_of(node), label)));
            }
            // Collect every node's reasons rather than stopping at the first.
            // A user fixing a ten-node export should see all ten problems.
            Err(EmitError::Refused(reasons)) => {
                refusals.extend(reasons.into_iter().map(|r| {
                    if label {
                        format!("{}: {r}", tag_of(node))
                    } else {
                        r
                    }
                }));
                continue;
            }
            Err(other) => return Err(other),
        }
        outbounds.push(outbound(node, &known, label, &mut dropped));
    }

    if !refusals.is_empty() {
        return Err(EmitError::Refused(refusals));
    }

    outbounds.push(json!({ "tag": DIRECT_TAG, "protocol": "freedom" }));

    let root = json!({
        "log": { "loglevel": "warning" },
        "inbounds": [ socks_inbound() ],
        "outbounds": outbounds,
        "routing": routing(nodes),
    });

    // to_string_pretty fails only on a non-string map key or a non-finite
    // float, neither of which this builder can produce; the arm exists so the
    // emitter never has to unwrap.
    let config = serde_json::to_string_pretty(&root)
        .map_err(|e| EmitError::Serialisation(e.to_string()))?;

    Ok(Emitted { config, format: Format::Json, dropped })
}

/// Node tag with surrounding whitespace removed.
///
/// A tag is a routing key inside the emitted JSON, and `"proxy "` and `"proxy"`
/// are different keys to Xray while being indistinguishable in a UI text field.
fn tag_of(node: &Node) -> &str {
    node.tag.trim()
}

/// Prefix a finding with its node's tag when the export covers several nodes.
fn relabel(d: Dropped, tag: &str, label: bool) -> Dropped {
    if label {
        Dropped { field: d.field, reason: format!("{tag}: {}", d.reason) }
    } else {
        d
    }
}

/// Reject tag sets Xray cannot route.
///
/// Xray resolves outbounds by tag, and a duplicate silently shadows rather than
/// erroring — traffic goes to whichever outbound the dispatcher finds first.
/// Refusing is the only way to keep that from becoming an unexplainable
/// "the wrong node is being used".
fn check_tags(nodes: &[Node]) -> Result<(), EmitError> {
    let reserved = [INBOUND_TAG, DIRECT_TAG, BALANCER_TAG];
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    let mut problems = Vec::new();

    for node in nodes {
        let tag = tag_of(node);
        if tag.is_empty() {
            problems.push(
                "a node has an empty name; Xray addresses outbounds by tag, and routing rules \
                 cannot refer to a nameless one"
                    .to_owned(),
            );
            continue;
        }
        if reserved.contains(&tag) {
            problems.push(format!(
                "the name {tag:?} is used by the generated config's own inbound, direct outbound \
                 or balancer — rename the node"
            ));
        }
        if !seen.insert(tag) {
            problems.push(format!(
                "two nodes are both named {tag:?}; Xray would route all traffic to whichever one \
                 it resolved first, with no error to explain it"
            ));
        }
    }

    if problems.is_empty() {
        Ok(())
    } else {
        Err(EmitError::Refused(problems))
    }
}

/// The local SOCKS inbound.
///
/// Bound to loopback deliberately: a SOCKS proxy with `auth: noauth` on a
/// routable address is an open proxy for anything else on the network.
fn socks_inbound() -> Value {
    json!({
        "tag": INBOUND_TAG,
        "listen": "127.0.0.1",
        "port": SOCKS_PORT,
        "protocol": "socks",
        "settings": { "auth": "noauth", "udp": true },
        // Xray leaves sniffing off by default. Turned on here because without
        // it every destination reaching the proxy is an IP the client already
        // resolved locally, which defeats remote DNS and any domain routing
        // rule. Cost: the connection's first bytes are parsed before dialling.
        "sniffing": {
            "enabled": true,
            "destOverride": ["http", "tls", "quic"],
            "routeOnly": false
        }
    })
}

/// Routing: keep local traffic local, and fan out across nodes when there are
/// several.
///
/// The private-range list is spelled out as CIDRs rather than `geoip:private`
/// because the latter needs `geoip.dat` next to the binary, and a config that
/// fails to load on a bare install is worse than one carrying a handful of
/// extra lines.
fn routing(nodes: &[Node]) -> Value {
    let mut rules = vec![json!({
        "type": "field",
        "ip": [
            "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
            "169.254.0.0/16", "::1/128", "fc00::/7", "fe80::/10"
        ],
        "outboundTag": DIRECT_TAG
    })];

    let mut out = Map::new();
    // Xray's own default. Stated explicitly so that a later edit adding domain
    // rules has to make a conscious choice about resolution rather than
    // inheriting one.
    out.insert("domainStrategy".to_owned(), json!("AsIs"));

    if nodes.len() > 1 {
        let selector: Vec<&str> = nodes.iter().map(tag_of).collect();
        rules.push(json!({
            "type": "field",
            "inboundTag": [INBOUND_TAG],
            "balancerTag": BALANCER_TAG
        }));
        out.insert(
            "balancers".to_owned(),
            json!([{
                "tag": BALANCER_TAG,
                "selector": selector,
                // roundRobin, not leastPing: the latency strategies need an
                // `observatory` block probing every node continuously, which
                // is a cost the user did not ask for and a fingerprint of its
                // own. Cost: a slow node keeps getting its share of traffic.
                "strategy": { "type": "roundRobin" }
            }]),
        );
    }

    out.insert("rules".to_owned(), Value::Array(rules));
    Value::Object(out)
}

/// One node as one Xray outbound.
fn outbound(node: &Node, known: &BTreeSet<&str>, label: bool, dropped: &mut Vec<Dropped>) -> Value {
    let mut ob = Map::new();
    ob.insert("tag".to_owned(), json!(tag_of(node)));
    ob.insert("protocol".to_owned(), json!(protocol_name(&node.protocol)));
    ob.insert("settings".to_owned(), protocol_settings(node));
    ob.insert("streamSettings".to_owned(), stream_settings(node, known, label, dropped));

    if node.mux.enabled {
        ob.insert("mux".to_owned(), mux(node, label, dropped));
    }
    Value::Object(ob)
}

const fn protocol_name(p: &Protocol) -> &'static str {
    match p {
        Protocol::Vless { .. } => "vless",
        Protocol::Vmess { .. } => "vmess",
        Protocol::Trojan { .. } => "trojan",
        Protocol::Shadowsocks { .. } => "shadowsocks",
    }
}

/// Protocol credentials.
///
/// Every array here carries exactly one member. §9.8: Xray hard-errors on a
/// second one — *"should have one and only one member. Multiple members …
/// should use multiple VLESS outbounds and routing balancer instead"* — which
/// is why the node list is expanded into outbounds by [`emit_nodes`] and never
/// into these arrays.
fn protocol_settings(node: &Node) -> Value {
    let address = node.server.address.as_str();
    let port = node.server.port;

    match &node.protocol {
        Protocol::Vless { uuid, flow } => {
            let mut user = Map::new();
            user.insert("id".to_owned(), json!(uuid));
            // Not optional and not a default. Without it Xray refuses the whole
            // config: "please add/set \"encryption\":\"none\" for every user".
            // It is the single most common reason a hand-written VLESS
            // outbound does not load.
            user.insert("encryption".to_owned(), json!("none"));
            if let Some(f) = flow_name(*flow) {
                user.insert("flow".to_owned(), json!(f));
            }
            json!({ "vnext": [ { "address": address, "port": port, "users": [ Value::Object(user) ] } ] })
        }
        Protocol::Vmess { uuid, cipher } => json!({
            // No alterId: Xray removed the field entirely and VMess is
            // AEAD-only. Emitting `alterId: 0` is harmless on sing-box and
            // mihomo but is dead weight here.
            "vnext": [ { "address": address, "port": port,
                "users": [ { "id": uuid, "security": vmess_security(*cipher) } ] } ]
        }),
        // No `flow` key, ever: any non-empty flow on Trojan is a hard error in
        // v26 — the feature was explicitly removed.
        Protocol::Trojan { password } => json!({
            "servers": [ { "address": address, "port": port, "password": password } ]
        }),
        Protocol::Shadowsocks { method, password } => json!({
            "servers": [ { "address": address, "port": port,
                "method": method.wire_name(), "password": password } ]
        }),
    }
}

const fn flow_name(flow: Flow) -> Option<&'static str> {
    match flow {
        Flow::None => None,
        Flow::Vision => Some("xtls-rprx-vision"),
        Flow::VisionUdp443 => Some("xtls-rprx-vision-udp443"),
    }
}

/// VMess payload cipher.
///
/// `Zero` maps to Xray's `zero`, which Xray then silently rewrites to `auto`.
/// [`crate::config::conflicts`] rates that `Broken` for Xray targets so
/// [`gate`] refuses it before this is reached; the arm exists so that the
/// mapping is not silently wrong if that rule ever changes.
const fn vmess_security(c: VmessCipher) -> &'static str {
    match c {
        VmessCipher::Auto => "auto",
        VmessCipher::Aes128Gcm => "aes-128-gcm",
        VmessCipher::Chacha20Poly1305 => "chacha20-poly1305",
        VmessCipher::Zero => "zero",
    }
}

/// Transport, security and dialer settings.
fn stream_settings(
    node: &Node,
    known: &BTreeSet<&str>,
    label: bool,
    dropped: &mut Vec<Dropped>,
) -> Value {
    let mut s = Map::new();

    // `network` and `tcpSettings`, never `method`/`rawSettings` (§9.1): the new
    // spellings did not exist before v26.7.11 and would make this config
    // unreadable to essentially every installed client, while the old ones are
    // still parsed by current builds.
    s.insert(xray_keys::NETWORK.to_owned(), json!(network_name(&node.transport)));
    s.insert(transport_key(&node.transport).to_owned(), transport_settings(node));

    match &node.security {
        Security::None => {
            // Xray's default is already "none"; stated anyway so the emitted
            // config never leaves a reader guessing whether TLS was intended.
            s.insert("security".to_owned(), json!("none"));
        }
        Security::Tls(t) => {
            s.insert("security".to_owned(), json!("tls"));
            let mut tls = Map::new();
            tls.insert(
                "serverName".to_owned(),
                json!(t.sni.as_deref().map_or_else(
                    || transport_host(node).to_owned(),
                    ToOwned::to_owned
                )),
            );
            if let Some(alpn) = alpn_for(&node.transport, &t.alpn) {
                tls.insert("alpn".to_owned(), json!(alpn));
            }
            if let Some(fp) = t.fingerprint.as_deref().filter(|f| !f.is_empty()) {
                tls.insert("fingerprint".to_owned(), json!(fp));
            }
            // allowInsecure is deliberately unreachable, not merely omitted.
            // It is a hard configuration error from v26.2.2 onward, so a config
            // carrying it does not load at all. gate() already refuses the node
            // for Xray targets; this arm keeps the guarantee even if that rule
            // is ever relaxed.
            if t.allow_insecure {
                dropped.push(Dropped::new(
                    "allow_insecure",
                    tagged(
                        "Certificate checks cannot be skipped on Xray: allowInsecure became a \
                         hard configuration error in v26.2.2, so emitting it would stop the \
                         config loading at all. Fix the certificate, or pin it with \
                         pinnedPeerCertSha256.",
                        tag_of(node),
                        label,
                    ),
                ));
            }
            s.insert("tlsSettings".to_owned(), Value::Object(tls));
        }
        Security::Reality(r) => {
            s.insert("security".to_owned(), json!("reality"));
            let mut re = Map::new();
            re.insert("serverName".to_owned(), json!(r.server_name));
            // `publicKey`, not `password`. v26 renamed the field and accepts
            // both (verified on v26.6.1); the old name is the one older clients
            // understand, which is the same reasoning as §9.1. Revisit when the
            // rename has propagated to the mobile clients.
            re.insert("publicKey".to_owned(), json!(r.public_key));
            re.insert("shortId".to_owned(), json!(r.short_id));
            if let Some(fp) = r.fingerprint.as_deref().filter(|f| !f.is_empty()) {
                re.insert("fingerprint".to_owned(), json!(fp));
            }
            s.insert("realitySettings".to_owned(), Value::Object(re));
        }
    }

    if let Some(via) = node.chain_via.as_deref().filter(|v| !v.is_empty()) {
        // sockopt.dialerProxy, never proxySettings.tag: the latter discards
        // this outbound's own streamSettings unless transportLayer is set,
        // which silently throws away the transport and TLS configured above.
        s.insert("sockopt".to_owned(), json!({ "dialerProxy": via }));
        if !known.contains(via) {
            // Xray accepts a dangling dialerProxy at config-check time and only
            // fails when it dials, so nothing would ever tell the user.
            dropped.push(Dropped::new(
                "chain_via",
                tagged(
                    &format!(
                        "This node dials through {via:?}, which is not part of this export. Xray \
                         accepts the reference when it loads the config and only fails when the \
                         connection is made, so export that node too or the chain will appear to \
                         work until it is used."
                    ),
                    tag_of(node),
                    label,
                ),
            ));
        }
    }

    Value::Object(s)
}

/// Prefix a message with its node's tag when several nodes share the output.
fn tagged(reason: &str, tag: &str, label: bool) -> String {
    if label {
        format!("{tag}: {reason}")
    } else {
        reason.to_owned()
    }
}

const fn network_name(t: &Transport) -> &'static str {
    match t {
        Transport::Xhttp { .. } => "xhttp",
        Transport::WebSocket { .. } => "ws",
        Transport::Grpc { .. } => "grpc",
        Transport::HttpUpgrade { .. } => "httpupgrade",
        // `raw`, the v24.11.30 rename of `tcp`. Unlike the v26.7.11 renames in
        // §9.1 this one has had over a year to propagate, and `tcp` is the
        // spelling being retired rather than the compatible one.
        Transport::Raw => "raw",
    }
}

/// Which `streamSettings` key carries this transport's options.
const fn transport_key(t: &Transport) -> &'static str {
    match t {
        Transport::Xhttp { .. } => xray_keys::XHTTP_SETTINGS,
        Transport::WebSocket { .. } => "wsSettings",
        Transport::Grpc { .. } => "grpcSettings",
        Transport::HttpUpgrade { .. } => "httpupgradeSettings",
        Transport::Raw => xray_keys::RAW_SETTINGS,
    }
}

/// The Host header / TLS name this transport presents.
fn transport_host(node: &Node) -> &str {
    let server = node.server.address.as_str();
    match &node.transport {
        Transport::Xhttp { host, .. }
        | Transport::WebSocket { host, .. }
        | Transport::HttpUpgrade { host, .. } => util::host_or_server(host.as_deref(), server),
        Transport::Grpc { .. } | Transport::Raw => server,
    }
}

/// ALPN to advertise, or `None` to leave the transport's own default alone.
///
/// **This is not simply [`util::ALPN`].** Xray's WebSocket and HTTPUpgrade
/// dialers speak an HTTP/1.1 upgrade and set `http/1.1` themselves — but only
/// when the user has not set ALPN, since the option is applied with
/// "if empty". Forcing `h2` on those transports makes the edge negotiate HTTP/2
/// and the HTTP/1.1 upgrade handshake then fails, which looks exactly like a
/// dead server. h2-only is right for XHTTP (whose parallel POSTs need
/// multiplexing) and required for gRPC, and wrong everywhere else.
///
/// An ALPN the user set explicitly always wins; this only fills a blank.
fn alpn_for(transport: &Transport, configured: &[String]) -> Option<Vec<String>> {
    if !configured.is_empty() {
        return Some(configured.to_vec());
    }
    match transport {
        Transport::Xhttp { .. } | Transport::Grpc { .. } => {
            Some(util::ALPN.iter().map(|s| (*s).to_owned()).collect())
        }
        Transport::WebSocket { .. } | Transport::HttpUpgrade { .. } | Transport::Raw => None,
    }
}

/// Transport-specific options.
fn transport_settings(node: &Node) -> Value {
    let host = transport_host(node).to_owned();
    match &node.transport {
        Transport::Xhttp { mode, path, .. } => xhttp_settings(*mode, path, &host),
        Transport::WebSocket { path, heartbeat_secs, .. } => {
            let mut ws = Map::new();
            ws.insert("path".to_owned(), json!(util::normalise_path(path)));
            // Dedicated field, never headers.Host (§9.3): on ws that spelling
            // is merely deprecated, but on XHTTP and HTTPUpgrade it is a hard
            // error, so there is one rule here and no exceptions to remember.
            ws.insert("host".to_owned(), json!(host));
            if *heartbeat_secs > 0 {
                // Xray's default is 0, meaning no ping at all. Deviating
                // because Cloudflare's WebSocket idle timeout is real and
                // unpublished, and their docs prescribe a client heartbeat.
                // Cost: one frame per interval keeps an idle connection
                // observably alive, which is a small traffic-analysis signal.
                ws.insert("heartbeatPeriod".to_owned(), json!(heartbeat_secs));
            }
            Value::Object(ws)
        }
        Transport::Grpc { service_name, multi_mode } => json!({
            "serviceName": service_name,
            "multiMode": multi_mode,
        }),
        Transport::HttpUpgrade { path, .. } => json!({
            "path": util::normalise_path(path),
            "host": host,
        }),
        // Xray's own default for raw, written out so the config says what it
        // does. `header` on mKCP is now a hard error, but on raw it is still
        // the supported obfuscation switch.
        Transport::Raw => json!({ "header": { "type": "none" } }),
    }
}

/// XHTTP client settings.
///
/// The `sc*` values here are the tuned defaults from §8, which happen to equal
/// Xray's own — they are written out because they are the numbers this project
/// has reasoned about, and a silent default is a number nobody can audit.
/// `scMaxBufferedPosts` and `scStreamUpServerSecs` are deliberately absent:
/// both are server-side settings, and a client that sets them is describing a
/// role it does not have.
fn xhttp_settings(mode: XhttpMode, path: &str, host: &str) -> Value {
    json!({
        "path": util::normalise_path(path),
        // Dedicated field; a Host inside `headers` is a hard error here (§9.3).
        "host": host,
        // Pinned rather than left at `auto`. auto resolves to packet-up today,
        // but flips to stream-one under REALITY, so pinning keeps the transport
        // from changing shape because an unrelated field changed.
        "mode": xhttp_mode(mode),
        // Range-syntax fields are strings even when they look numeric.
        "xPaddingBytes": "100-1000",
        "scMaxEachPostBytes": "1000000",
        "scMinPostsIntervalMs": "30",
        // All three or none (§9.2). Any single field present cancels Xray's
        // whole default bundle and the rest fall back to 0 — unlimited — which
        // is strictly worse than omitting xmux altogether.
        "xmux": {
            "maxConnections": util::XMUX_MAX_CONNECTIONS,
            "hMaxRequestTimes": util::XMUX_H_MAX_REQUEST_TIMES,
            "hMaxReusableSecs": util::XMUX_H_MAX_REUSABLE_SECS,
        },
    })
}

const fn xhttp_mode(mode: XhttpMode) -> &'static str {
    match mode {
        XhttpMode::PacketUp => "packet-up",
        XhttpMode::StreamUp => "stream-up",
        XhttpMode::StreamOne => "stream-one",
    }
}

/// Xray's own multiplexing (not XHTTP's `xmux`, which is a different mechanism
/// at a different layer).
fn mux(node: &Node, label: bool, dropped: &mut Vec<Dropped>) -> Value {
    let asked = node.mux.concurrency;
    let concurrency = match asked {
        0 => MUX_DEFAULT_CONCURRENCY,
        n if n > MUX_MAX_CONCURRENCY => {
            dropped.push(Dropped::new(
                "mux",
                tagged(
                    &format!(
                        "Multiplexing width was reduced from {asked} to {MUX_MAX_CONCURRENCY}, \
                         which is Xray's maximum. The field is a 16-bit integer, so a larger \
                         number does not merely get clamped — the config fails to parse."
                    ),
                    tag_of(node),
                    label,
                ),
            ));
            MUX_MAX_CONCURRENCY
        }
        n => n,
    };
    json!({ "enabled": true, "concurrency": concurrency })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::model::{
        Endpoint, Mux, RealitySettings, SsMethod, TlsSettings, XhttpMode,
    };
    use serde_json::Value;

    fn xhttp_node() -> Node {
        Node {
            tag: "proxy".into(),
            server: Endpoint { address: "edge.example.com".into(), port: 443 },
            protocol: Protocol::Vless {
                uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".into(),
                flow: Flow::None,
            },
            transport: Transport::Xhttp {
                mode: XhttpMode::PacketUp,
                path: "/tunnel".into(),
                host: None,
            },
            security: Security::Tls(TlsSettings::default()),
            mux: Mux::default(),
            chain_via: None,
            worker_served: true,
        }
    }

    fn ws_node() -> Node {
        Node {
            transport: Transport::WebSocket {
                path: "/ws".into(),
                host: Some("cdn.example.com".into()),
                heartbeat_secs: util::WS_HEARTBEAT_SECS,
            },
            ..xhttp_node()
        }
    }

    fn emit_one(node: &Node) -> Emitted {
        XrayEmitter
            .emit(node, ClientTarget::V2rayN)
            .expect("node should be emittable")
    }

    fn parse(e: &Emitted) -> Value {
        serde_json::from_str(&e.config).expect("emitter must produce valid JSON")
    }

    fn first_outbound(v: &Value) -> &Value {
        &v["outbounds"][0]
    }

    #[test]
    fn emits_the_legacy_transport_key_spellings() {
        // §9.1: `method` and `rawSettings` do not exist before v26.7.11.
        let e = emit_one(&xhttp_node());
        let v = parse(&e);
        let stream = &first_outbound(&v)["streamSettings"];
        assert_eq!(stream["network"], "xhttp");
        assert!(stream.get("method").is_none(), "must not emit the v26.7.11 spelling");
        assert!(stream.get("rawSettings").is_none());
        assert!(stream.get("xhttpSettings").is_some());
    }

    #[test]
    fn raw_transport_uses_tcp_settings_not_raw_settings() {
        let node = Node {
            transport: Transport::Raw,
            worker_served: false,
            ..xhttp_node()
        };
        let e = emit_one(&node);
        let v = parse(&e);
        let stream = &first_outbound(&v)["streamSettings"];
        assert_eq!(stream["network"], "raw");
        assert!(stream.get("tcpSettings").is_some());
        assert!(stream.get("rawSettings").is_none());
    }

    #[test]
    fn every_vless_user_carries_encryption_none() {
        // Without it Xray refuses the whole config outright.
        let e = emit_one(&xhttp_node());
        let v = parse(&e);
        let user = &first_outbound(&v)["settings"]["vnext"][0]["users"][0];
        assert_eq!(user["encryption"], "none");
    }

    #[test]
    fn xmux_is_emitted_as_a_complete_bundle() {
        // §9.2: a partial xmux cancels Xray's defaults and everything absent
        // silently becomes unlimited.
        let e = emit_one(&xhttp_node());
        let v = parse(&e);
        let xmux = &first_outbound(&v)["streamSettings"]["xhttpSettings"]["xmux"];
        for key in ["maxConnections", "hMaxRequestTimes", "hMaxReusableSecs"] {
            assert!(xmux.get(key).is_some(), "xmux must be complete, missing {key}");
        }
        // maxConcurrency is mutually exclusive with maxConnections — a build
        // error if both are set.
        assert!(xmux.get("maxConcurrency").is_none());
    }

    #[test]
    fn host_is_never_placed_inside_headers() {
        // §9.3: a hard error on xhttp and httpupgrade.
        for node in [xhttp_node(), ws_node()] {
            let e = emit_one(&node);
            let v = parse(&e);
            let stream = &first_outbound(&v)["streamSettings"];
            let settings = &stream[transport_key(&node.transport)];
            assert!(settings.get("headers").is_none(), "no headers map at all");
            assert!(settings["host"].is_string(), "the dedicated host field is used");
        }
    }

    #[test]
    fn allow_insecure_never_reaches_the_output() {
        let node = Node {
            security: Security::Tls(TlsSettings { allow_insecure: true, ..Default::default() }),
            ..xhttp_node()
        };
        // gate() refuses it outright for an Xray target, which is the stronger
        // guarantee: the string cannot appear because the config is not built.
        assert!(matches!(
            XrayEmitter.emit(&node, ClientTarget::V2rayN),
            Err(EmitError::Refused(_))
        ));
    }

    #[test]
    fn websocket_does_not_get_h2_alpn_but_xhttp_does() {
        let xh = parse(&emit_one(&xhttp_node()));
        assert_eq!(
            first_outbound(&xh)["streamSettings"]["tlsSettings"]["alpn"],
            json!(["h2"])
        );

        let ws = parse(&emit_one(&ws_node()));
        let tls = &first_outbound(&ws)["streamSettings"]["tlsSettings"];
        assert!(
            tls.get("alpn").is_none(),
            "forcing h2 on a WebSocket makes the HTTP/1.1 upgrade fail"
        );
    }

    #[test]
    fn an_explicit_alpn_is_honoured_over_the_project_default() {
        let node = Node {
            security: Security::Tls(TlsSettings {
                alpn: vec!["http/1.1".into()],
                ..Default::default()
            }),
            ..xhttp_node()
        };
        let v = parse(&emit_one(&node));
        assert_eq!(
            first_outbound(&v)["streamSettings"]["tlsSettings"]["alpn"],
            json!(["http/1.1"])
        );
    }

    #[test]
    fn websocket_heartbeat_uses_the_native_field() {
        // §9.9: heartbeatPeriod, not application-level keepalive traffic.
        let v = parse(&emit_one(&ws_node()));
        let ws = &first_outbound(&v)["streamSettings"]["wsSettings"];
        assert_eq!(ws["heartbeatPeriod"], json!(util::WS_HEARTBEAT_SECS));

        let off = Node {
            transport: Transport::WebSocket {
                path: "/ws".into(),
                host: None,
                heartbeat_secs: 0,
            },
            ..xhttp_node()
        };
        let v = parse(&emit_one(&off));
        assert!(
            first_outbound(&v)["streamSettings"]["wsSettings"]
                .get("heartbeatPeriod")
                .is_none(),
            "0 is Xray's default and means no ping; do not write it out"
        );
    }

    #[test]
    fn host_falls_back_to_the_server_address() {
        let v = parse(&emit_one(&xhttp_node()));
        let xs = &first_outbound(&v)["streamSettings"]["xhttpSettings"];
        assert_eq!(xs["host"], "edge.example.com");
        assert_eq!(
            first_outbound(&v)["streamSettings"]["tlsSettings"]["serverName"],
            "edge.example.com"
        );
    }

    #[test]
    fn multi_node_becomes_multiple_outbounds_and_a_balancer() {
        // §9.8: a second member of vnext[] is a hard error, not a shorthand.
        let a = xhttp_node();
        let b = Node { tag: "second".into(), ..xhttp_node() };
        let e = emit_nodes(&[a, b], ClientTarget::V2rayN).expect("two nodes are emittable");
        let v = parse(&e);

        let obs = v["outbounds"].as_array().expect("outbounds is an array");
        assert_eq!(obs.len(), 3, "two nodes plus the direct outbound");
        for ob in obs.iter().take(2) {
            let users = ob["settings"]["vnext"][0]["users"]
                .as_array()
                .expect("users is an array");
            assert_eq!(users.len(), 1, "Xray hard-errors on a second user");
            assert_eq!(
                ob["settings"]["vnext"].as_array().map(Vec::len),
                Some(1),
                "and on a second vnext member"
            );
        }
        let balancers = v["routing"]["balancers"].as_array().expect("balancers");
        assert_eq!(balancers[0]["selector"], json!(["proxy", "second"]));
    }

    #[test]
    fn a_single_node_gets_no_balancer() {
        let v = parse(&emit_one(&xhttp_node()));
        assert!(v["routing"].get("balancers").is_none());
        assert_eq!(first_outbound(&v)["tag"], "proxy");
    }

    #[test]
    fn duplicate_and_reserved_tags_are_refused() {
        let dup = [xhttp_node(), xhttp_node()];
        assert!(matches!(
            emit_nodes(&dup, ClientTarget::V2rayN),
            Err(EmitError::Refused(_))
        ));

        for bad in ["direct", "socks-in", "balancer", "  "] {
            let n = Node { tag: bad.into(), ..xhttp_node() };
            assert!(
                matches!(emit_nodes(&[n], ClientTarget::V2rayN), Err(EmitError::Refused(_))),
                "tag {bad:?} must be refused"
            );
        }
    }

    #[test]
    fn chaining_uses_dialer_proxy_and_reports_a_dangling_hop() {
        let hop = Node { tag: "hop".into(), ..xhttp_node() };
        let node = Node { chain_via: Some("hop".into()), ..xhttp_node() };

        // Hop present: no complaint.
        let e = emit_nodes(&[hop, node.clone()], ClientTarget::V2rayN).expect("emittable");
        assert!(e.dropped.iter().all(|d| d.field != "chain_via"));
        let v = parse(&e);
        assert_eq!(
            v["outbounds"][1]["streamSettings"]["sockopt"]["dialerProxy"],
            "hop"
        );
        // proxySettings.tag silently discards this outbound's streamSettings.
        assert!(v["outbounds"][1].get("proxySettings").is_none());

        // Hop absent: Xray accepts the config and only fails when it dials, so
        // the user must be told.
        let e = emit_one(&node);
        assert!(e.dropped.iter().any(|d| d.field == "chain_via"));
    }

    #[test]
    fn mux_concurrency_is_clamped_rather_than_breaking_the_parse() {
        let node = Node {
            mux: Mux { enabled: true, concurrency: u16::MAX },
            worker_served: false,
            ..xhttp_node()
        };
        let e = emit_one(&node);
        let v = parse(&e);
        assert_eq!(first_outbound(&v)["mux"]["concurrency"], json!(1024));
        assert!(e.dropped.iter().any(|d| d.field == "mux"));

        let node = Node {
            mux: Mux { enabled: true, concurrency: 0 },
            worker_served: false,
            ..xhttp_node()
        };
        let v = parse(&emit_one(&node));
        assert_eq!(first_outbound(&v)["mux"]["concurrency"], json!(8));
    }

    #[test]
    fn a_target_that_does_not_run_xray_is_refused() {
        for t in [ClientTarget::Mihomo, ClientTarget::Hiddify, ClientTarget::SingBoxUpstream] {
            assert!(
                matches!(
                    XrayEmitter.emit(&xhttp_node(), t),
                    Err(EmitError::Refused(_))
                ),
                "{} does not execute Xray JSON",
                t.name()
            );
        }
        assert_eq!(XrayEmitter.core(), Core::Xray);
    }

    #[test]
    fn gate_degradations_are_carried_into_the_output() {
        let e = emit_one(&ws_node());
        assert!(
            e.dropped.iter().any(|d| d.field == "transport"),
            "the WebSocket fingerprint warning must reach the user"
        );
    }

    #[test]
    fn reality_uses_the_spelling_older_clients_understand() {
        let node = Node {
            worker_served: false,
            transport: Transport::Raw,
            security: Security::Reality(RealitySettings {
                public_key: "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0".into(),
                short_id: "6ba85179e30d4fc2".into(),
                server_name: "www.microsoft.com".into(),
                fingerprint: Some("chrome".into()),
            }),
            ..xhttp_node()
        };
        let v = parse(&emit_one(&node));
        let re = &first_outbound(&v)["streamSettings"]["realitySettings"];
        assert_eq!(re["publicKey"], "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0");
        assert_eq!(re["fingerprint"], "chrome");
        assert!(re.get("password").is_none(), "one spelling only, or both are ambiguous");
    }

    #[test]
    fn trojan_never_carries_a_flow_field() {
        // Any non-empty flow on Trojan is a removed feature and a hard error.
        let node = Node {
            protocol: Protocol::Trojan { password: "pw".into() },
            ..xhttp_node()
        };
        let v = parse(&emit_one(&node));
        let server = &first_outbound(&v)["settings"]["servers"][0];
        assert!(server.get("flow").is_none());
        assert_eq!(server["password"], "pw");
    }

    #[test]
    fn vmess_omits_alter_id_entirely() {
        let node = Node {
            protocol: Protocol::Vmess {
                uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".into(),
                cipher: VmessCipher::Auto,
            },
            transport: Transport::WebSocket {
                path: "/w".into(),
                host: None,
                heartbeat_secs: 30,
            },
            ..xhttp_node()
        };
        let v = parse(&emit_one(&node));
        let user = &first_outbound(&v)["settings"]["vnext"][0]["users"][0];
        assert!(user.get("alterId").is_none(), "Xray removed the field");
        assert_eq!(user["security"], "auto");
    }

    #[test]
    fn the_inbound_is_loopback_only() {
        // A noauth SOCKS listener on a routable address is an open proxy.
        let v = parse(&emit_one(&xhttp_node()));
        assert_eq!(v["inbounds"][0]["listen"], "127.0.0.1");
        assert_eq!(v["inbounds"][0]["protocol"], "socks");
    }

    #[test]
    fn an_empty_node_list_is_refused_rather_than_producing_an_inert_config() {
        assert!(matches!(
            emit_nodes(&[], ClientTarget::V2rayN),
            Err(EmitError::Refused(_))
        ));
    }

    /// Every shape the emitter has to cover, emitted in one pass.
    ///
    /// Not a substitute for `xray run -test` against the real binary, which is
    /// what §9.7 asks for — but a config that fails to emit at all cannot be
    /// validated by anything, so the shapes are exercised here.
    #[test]
    fn every_supported_shape_emits() {
        let ss = Node {
            protocol: Protocol::Shadowsocks {
                method: SsMethod::Blake3Aes128Gcm,
                password: "AAAAAAAAAAAAAAAAAAAAAA==".into(),
            },
            transport: Transport::WebSocket {
                path: "/s".into(),
                host: None,
                heartbeat_secs: util::WS_HEARTBEAT_SECS,
            },
            tag: "ss".into(),
            ..xhttp_node()
        };
        let grpc = Node {
            tag: "grpc".into(),
            worker_served: false,
            transport: Transport::Grpc { service_name: "gs".into(), multi_mode: true },
            protocol: Protocol::Trojan { password: "pw".into() },
            ..xhttp_node()
        };
        let reality = Node {
            tag: "reality".into(),
            worker_served: false,
            transport: Transport::Raw,
            protocol: Protocol::Vless {
                uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".into(),
                flow: Flow::Vision,
            },
            security: Security::Reality(RealitySettings {
                public_key: "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0".into(),
                short_id: "6ba85179e30d4fc2".into(),
                server_name: "www.microsoft.com".into(),
                fingerprint: Some("chrome".into()),
            }),
            chain_via: Some("ss".into()),
            ..xhttp_node()
        };
        let hu = Node {
            tag: "hu".into(),
            worker_served: false,
            transport: Transport::HttpUpgrade { path: "u".into(), host: None },
            mux: Mux { enabled: true, concurrency: u16::MAX },
            ..xhttp_node()
        };
        let stream_one = Node {
            tag: "one".into(),
            transport: Transport::Xhttp {
                mode: XhttpMode::StreamOne,
                path: "/one/".into(),
                host: Some("cdn.example.com".into()),
            },
            ..xhttp_node()
        };

        let samples: Vec<(&str, Vec<Node>)> = vec![
            ("xhttp_packet_up", vec![xhttp_node()]),
            ("websocket", vec![ws_node()]),
            ("shadowsocks_ws", vec![ss]),
            ("trojan_grpc", vec![grpc]),
            ("vless_reality_vision", vec![reality.clone()]),
            ("httpupgrade_mux", vec![hu]),
            ("xhttp_stream_one", vec![stream_one.clone()]),
            ("multi_balancer", vec![xhttp_node(), stream_one, reality]),
        ];

        for (name, nodes) in samples {
            emit_nodes(&nodes, ClientTarget::V2rayN)
                .unwrap_or_else(|err| panic!("{name} should emit: {err}"));
        }
    }
}
