//! Share links — the `vless://`, `vmess://`, `trojan://` and `ss://` forms.
//!
//! These are what a user actually pastes into a phone, so their failure mode
//! matters: a malformed link does not error, it imports as a node that quietly
//! connects nowhere. Everything interpolated is percent-encoded, and the
//! formats follow the conventions v2rayN and v2rayNG actually parse rather
//! than an idealised spec, because those are the clients on the other end.
//!
//! Links are gated through [`crate::translate::gate`] exactly like full
//! configs. A share link that cannot work for the chosen client is refused
//! with the reason, not emitted and left to fail on the user's phone.

use crate::config::model::{
    ClientTarget, Flow, Node, Protocol, Security, Transport, VmessCipher, XhttpMode,
};
use crate::translate::util::{default_alpn, normalise_path};
use crate::translate::{gate, EmitError};

use super::encode::{base64, base64_url_nopad, fragment, percent};

/// uTLS fingerprint defaulted under Enhanced Reachability.
///
/// `fp` is a real share-link parameter that v2rayN/v2rayNG pass through to
/// Xray's TLS settings, so it belongs in a link; Xray's fragment cannot be
/// expressed in any link format and is only ever carried by the JSON export.
const ENHANCED_FINGERPRINT: &str = "chrome";

/// Render `node` as a share link for `target`.
///
/// # Errors
/// [`EmitError::Refused`] when the node cannot work for this client.
pub fn to_uri(node: &Node, target: ClientTarget, enhanced: bool) -> Result<String, EmitError> {
    gate(node, target, enhanced)?;

    match &node.protocol {
        Protocol::Vless { uuid, flow } => Ok(vless(node, uuid, *flow, enhanced, target)),
        Protocol::Trojan { password } => Ok(trojan(node, password, enhanced, target)),
        Protocol::Vmess { uuid, cipher } => vmess(node, uuid, *cipher, enhanced, target),
        Protocol::Shadowsocks { method, password } => {
            shadowsocks(node, method.wire_name(), password, enhanced)
        }
    }
}

/// The XHTTP tuning blob PattN and PattNG carry under `extra`.
///
/// Xray copies this blob into `xhttpSettings.extra`. These are Xray-core's own
/// `xhttpSettings` field names, taken from `translate::xray`'s emitted block -
/// NOT `sc*` query keys, which are a share-link convention no client reads
/// except v2rayN's own dialect. Range-syntax and byte-count fields are strings
/// even where they look numeric; Xray rejects a number there.
///
/// Every key here was confirmed present in the installed Xray 26.10.8 binary
/// (its `sc*` fields are exactly: scMaxBufferedPosts, scMaxEachPostBytes,
/// scMinPostsIntervalMs, scStreamUpServerSecs). `scMaxConcurrentPosts` is NOT
/// one of them, which is why the blob carries only three keys.
///
/// Note `xray run -test` does not validate `xhttpSettings` contents - a bogus
/// key there still passes - so `Configuration OK` is not proof for this blob.
/// What proves it is the binary's own field table plus `translate::xray`'s
/// matching output. Kept in one place because the same
/// numbers are also emitted as `sc*` query keys for other clients, and the two
/// must never drift apart.
/// The query-key name PattN/PattNG use for the tuning blob.
const XHTTP_EXTRA_KEY: &str = "extra";

const XHTTP_EXTRA_TUNING: &str =
    r#"{"xPaddingBytes":"100-1000","scMaxEachPostBytes":"1000000","scMinPostsIntervalMs":"0"}"#;

/// Transport and security query parameters shared by VLESS and Trojan.
///
/// Emitted in a stable order. Clients do not care, but a stable order means a
/// regenerated subscription is byte-identical when nothing changed, which is
/// what lets a user diff two links and see whether anything actually moved.
fn common_params(
    node: &Node,
    enhanced: bool,
    target: ClientTarget,
) -> Vec<(&'static str, String)> {
    let mut p: Vec<(&'static str, String)> = Vec::new();

    let (net, transport_host, path, mode) = match &node.transport {
        Transport::Xhttp { mode, path, host } => (
            "xhttp",
            host.clone(),
            Some(normalise_path(path)),
            Some(match mode {
                XhttpMode::PacketUp => "packet-up",
                XhttpMode::StreamUp => "stream-up",
                XhttpMode::StreamOne => "stream-one",
            }),
        ),
        Transport::WebSocket { path, host, .. } => {
            ("ws", host.clone(), Some(normalise_path(path)), None)
        }
        Transport::Grpc { service_name, .. } => {
            ("grpc", None, Some(service_name.clone()), None)
        }
        Transport::HttpUpgrade { path, host } => {
            ("httpupgrade", host.clone(), Some(normalise_path(path)), None)
        }
        // Xray v26 renamed this to "raw", but "tcp" is what every installed
        // client still parses, and both are accepted.
        Transport::Raw => ("tcp", None, None, None),
    };
    p.push(("type", net.to_owned()));

    match &node.security {
        Security::None => p.push(("security", "none".to_owned())),
        Security::Tls(t) => {
            p.push(("security", "tls".to_owned()));
            if let Some(sni) = &t.sni {
                p.push(("sni", sni.clone()));
            }
            // WebSocket/HTTPUpgrade complete an HTTP/1.1 upgrade: advertising h2
            // makes TLS negotiate HTTP/2 and the upgrade has no connection to run
            // on — the client sees EOF right after the dial. Only transports that
            // actually ride h2 advertise an ALPN (see util::default_alpn).
            if let Some(alpn) = if t.alpn.is_empty() { default_alpn(&node.transport) } else { None } {
                p.push(("alpn", alpn.join(",")));
            } else if !t.alpn.is_empty() {
                p.push(("alpn", t.alpn.join(",")));
            }
            if let Some(fp) = &t.fingerprint {
                p.push(("fp", fp.clone()));
            } else if enhanced {
                p.push(("fp", ENHANCED_FINGERPRINT.to_owned()));
            }
        }
        Security::Reality(r) => {
            p.push(("security", "reality".to_owned()));
            p.push(("sni", r.server_name.clone()));
            p.push(("pbk", r.public_key.clone()));
            if !r.short_id.is_empty() {
                p.push(("sid", r.short_id.clone()));
            }
            if let Some(fp) = &r.fingerprint {
                p.push(("fp", fp.clone()));
            } else if enhanced {
                p.push(("fp", ENHANCED_FINGERPRINT.to_owned()));
            }
        }
    }

    if let Some(h) = transport_host {
        if !h.is_empty() {
            p.push(("host", h));
        }
    }
    if let Some(path) = path {
        p.push(("path", path));
    }
    if let Some(m) = mode {
        p.push(("mode", m.to_owned()));
        if target == ClientTarget::PattN {
            // PattN and PattNG read XHTTP tuning from ONE JSON blob under
            // `extra` (BaseFmt.ToUriQuery -> TransportExtraItem.XhttpExtra ->
            // V2rayOutboundService xhttpSettings.extra), not from `sc*` keys.
            // Verified in both forks: PattN BaseFmt.cs `case nameof(
            // ETransport.xhttp)` and PattNG FmtBase.kt `config.xhttpExtra =
            // queryParam["extra"]`. Xray takes this blob verbatim as
            // `xhttpSettings.extra`, so the keys are Xray's own names.
            //
            // Measured 2026-09-28 Phase 3B (fiber, 8 interleaved randomized
            // rounds, fresh session per run, per-round direct controls, 10 MB
            // POST): UL medians 512K 1.017 / 1M 1.362 / 1.5M 1.145 / 2M 0.996
            // MB/s (direct same-window 1.89); 1M also leads DL (2.21 vs 1.90)
            // and is the only large-chunk family with zero 100-continue
            // stalls (2M had two, one a 120 s crawl). Paired same-window 1M
            // beats 2M in 3/4. Cost: 1M doubles DO ops per uploaded byte vs 2M
            // -- accepted for the +37% UL; 4 MB deadlocks outright (3/3). JEV
            // decision engine on the full measurement table: 1M, confidence
            // 0.975.
            //
            // 30ms pacing (scMinPostsIntervalMs=30) collapsed tunnelled upload
            // to ~0.6 Mbps where the same path carries ~14 Mbps direct; 0
            // pipelines POSTs and the server still guarantees ordering.
            p.push((
                "extra",
                XHTTP_EXTRA_TUNING.to_owned(),
            ));
            return p;
        }
        // Measured 2026-09-28 Phase 3B (fiber, 8 interleaved randomized rounds,
        // fresh session per run, per-round direct controls, 10 MB POST):
        // UL medians 512K 1.017 / 1M 1.362 / 1.5M 1.145 / 2M 0.996 MB/s
        // (direct same-window 1.89); 1M also leads DL (2.21 vs 1.90) and is
        // the only large-chunk family with zero 100-continue stalls (2M had
        // two, one a 120 s crawl). Paired same-window 1M beats 2M in 3/4.
        // Cost: 1M doubles DO ops per uploaded byte vs 2M — accepted for the
        // +37% UL; 4 MB deadlocks outright (3/3). JEV decision engine on the
        // full measurement table: 1M, confidence 0.975.
        p.push(("scMaxEachPostBytes", "1000000".to_owned()));
        p.push(("scMaxConcurrentPosts", "10".to_owned()));
        // Measured live 2026-09-28: 30ms pacing collapsed tunnelled upload to
        // ~0.6 Mbps where the same path carries ~14 Mbps direct; 0 pipelines
        // POSTs (ordering stays guaranteed by the server's sequence
        // reordering). `translate::xray` already ships 0 for config output.
        p.push(("scMinPostsIntervalMs", "0".to_owned()));
    }
    p
}

/// Render a server address for the authority position of a URI.
///
/// Two things go wrong without this. An IPv6 literal contains colons, so
/// `vless://id@2001:db8::1:443` is ambiguous — the port cannot be told from
/// the address — and RFC 3986 requires brackets. And any character that is a
/// URI delimiter must be escaped, or it silently ends the authority early: an
/// address containing `#` makes everything after it the fragment, producing a
/// link that imports cleanly and points somewhere else entirely.
fn host_for_uri(addr: &str) -> String {
    // Already bracketed by the caller.
    if addr.starts_with('[') && addr.ends_with(']') {
        return addr.to_owned();
    }
    if addr.parse::<std::net::Ipv6Addr>().is_ok() {
        return format!("[{addr}]");
    }
    // A well-formed domain or IPv4 address passes through untouched, since
    // every character in one is unreserved. Anything else is escaped rather
    // than trusted.
    percent(addr)
}

fn query(params: &[(&'static str, String)]) -> String {
    params
        .iter()
        .map(|(k, v)| format!("{k}={}", percent(v)))
        .collect::<Vec<_>>()
        .join("&")
}

/// `vless://uuid@host:port?params#label`
fn vless(node: &Node, uuid: &str, flow: Flow, enhanced: bool, target: ClientTarget) -> String {
    let mut p = client_params(node, enhanced, target);
    // VLESS requires an explicit encryption value; omitting it makes Xray
    // refuse the config outright rather than assume a default.
    p.insert(0, ("encryption", "none".to_owned()));
    if let Some(f) = match flow {
        Flow::None => None,
        Flow::Vision => Some("xtls-rprx-vision"),
        Flow::VisionUdp443 => Some("xtls-rprx-vision-udp443"),
    } {
        p.push(("flow", f.to_owned()));
    }
    format!(
        "vless://{}@{}:{}?{}#{}",
        percent(uuid),
        host_for_uri(&node.server.address),
        node.server.port,
        query(&p),
        fragment(&node.tag)
    )
}

/// Emit share-link params. Xray defaults XHTTP to packet-up when `mode` is absent,
/// so omit `mode` here to avoid the malformed `x-phtml packet-up` shape observed
/// during client imports.
fn client_params(
    node: &Node,
    enhanced: bool,
    target: ClientTarget,
) -> Vec<(&'static str, String)> {
    let mut out = common_params(node, enhanced, target);
    out.retain(|(k, _)| *k != "mode");
    out
}
///
/// No `flow` parameter is ever emitted: Xray removed flow for Trojan and now
/// hard-errors on any non-empty value, so a link carrying one fails to load.
fn trojan(node: &Node, password: &str, enhanced: bool, target: ClientTarget) -> String {
    format!(
        "trojan://{}@{}:{}?{}#{}",
        percent(password),
        host_for_uri(&node.server.address),
        node.server.port,
        query(&client_params(node, enhanced, target)),
        fragment(&node.tag)
    )
}

/// `vmess://` + base64 of a JSON object.
///
/// The oddest of the four formats and the least specified — the field names
/// are short, untyped, and several are strings that look like numbers. This
/// follows what v2rayN emits, since that is what the ecosystem parses.
fn vmess(node: &Node, uuid: &str, cipher: VmessCipher, enhanced: bool,
    target: ClientTarget,) -> Result<String, EmitError> {
    let p: std::collections::HashMap<&str, String> =
        client_params(node, enhanced, target).into_iter().collect();

    // Auto must name a real AEAD: sing-box-based importers (Hiddify, Karing,
    // NekoBox) turn scy=auto into VMess security 0x05 (none) on the wire —
    // live-proven against Trinity 2026-09-24 — while Xray maps it to AES.
    // Naming aes-128-gcm is correct for both cores.
    let scy = match cipher {
        VmessCipher::Auto => "aes-128-gcm",
        VmessCipher::Aes128Gcm => "aes-128-gcm",
        VmessCipher::Chacha20Poly1305 => "chacha20-poly1305",
        VmessCipher::Zero => "zero",
    };

    let obj = serde_json::json!({
        "v": "2",
        "ps": node.tag,
        "add": node.server.address,
        // Port is a string here. Numeric ports are accepted by some clients
        // and rejected by others; the string form is universally parsed.
        "port": node.server.port.to_string(),
        "id": uuid,
        // Always zero. Xray removed alterId entirely and VMess is AEAD-only;
        // any non-zero value selects a legacy mode modern servers refuse.
        "aid": "0",
        "scy": scy,
        "net": p.get("type").cloned().unwrap_or_else(|| "tcp".to_owned()),
        "type": "none",
        "host": p.get("host").cloned().unwrap_or_default(),
        "path": p.get("path").cloned().unwrap_or_default(),
        "tls": if p.get("security").map(String::as_str) == Some("none") { "" } else { "tls" },
        "sni": p.get("sni").cloned().unwrap_or_default(),
        "alpn": p.get("alpn").cloned().unwrap_or_default(),
        "fp": p.get("fp").cloned().unwrap_or_default(),
    });
    // This object enumerates keys, so a transport setting that only exists in
    // `p` would be dropped here. The XHTTP tuning blob is exactly that case:
    // vmess:// carries net=xhttp but has no `sc*` query keys of its own, so
    // without this line a PattN vmess node would import and then silently run
    // Xray's default posting instead of the measured 1 MB / 0 pacing.
    let mut obj = obj;
    if let Some(extra) = p.get(XHTTP_EXTRA_KEY) {
        obj[XHTTP_EXTRA_KEY] = serde_json::Value::String(extra.clone());
    }

    let json = serde_json::to_string(&obj).map_err(|e| EmitError::Serialisation(e.to_string()))?;
    Ok(format!("vmess://{}", base64(json.as_bytes())))
}

/// `ss://base64url(method:password)@host:port#label`, the SIP002 form.
///
/// The older form base64-encoded the whole `method:password@host:port`, which
/// several clients no longer accept. SIP002 encodes only the userinfo and
/// leaves the host readable, which is also what makes the link diagnosable by
/// eye.
///
/// Transport is carried through the SIP003 plugin mechanism: a Shadowsocks
/// link's only transport path in any client is v2ray-plugin's WebSocket mode,
/// so a WebSocket node emits `plugin=v2ray-plugin` plus the semicolon-form
/// `plugin-opts` (percent-encoded inside the query string, as SIP003
/// requires). Enhanced Reachability adds nothing here: a plugin connection is
/// not an Xray TLS connection, so fragment and fingerprint have nowhere to go.
fn shadowsocks(node: &Node, method: &str, password: &str, _enhanced: bool) -> Result<String, EmitError> {
    // gate() has already refused every client that cannot carry this node —
    // which, for XHTTP, is every client (the SIP002 link format has no way to
    // express a transport other than SIP003 plugins).
    let mut plugin_params: Vec<(&'static str, String)> = Vec::new();

    match &node.transport {
        Transport::Raw => {}
        Transport::WebSocket { path, host, .. } => {
            plugin_params.push(("plugin", "v2ray-plugin".to_owned()));

            // SIP003 semicolon form. Xray's `security: none` is not a state
            // v2ray-plugin can express — its dialer is either TLS or plain —
            // and its fingerprint takes no uTLS profile at all, so only the
            // framing is carried.
            let mut opts = vec!["ws".to_owned()];
            let mut host_val: Option<String> = None;
            let mut tls = false;

            match &node.security {
                Security::Tls(t) => {
                    tls = true;
                    if let Some(sni) = t.sni.as_deref().filter(|s| !s.is_empty()) {
                        host_val = Some(sni.to_owned());
                    }
                }
                // mihomo's own WS carrier documents this gap the same way:
                // the plugin builds its own connection and the node's TLS
                // settings cannot reach it.
                Security::Reality(_) | Security::None => {}
            }
            // v2ray-plugin falls back to the server address for Host/SNI.
            // Emitting it explicitly would only pin the link to the address
            // where this node is served today.
            if let Some(h) = host.as_deref().filter(|h| !h.is_empty()) {
                host_val = Some(h.to_owned());
            }
            if tls {
                opts.push("tls".to_owned());
            }
            if let Some(h) = host_val {
                opts.push(format!("host={h}"));
            }
            opts.push(format!("path={}", normalise_path(path)));

            plugin_params.push(("plugin-opts", opts.join(";")));
        }
        other => {
            return Err(EmitError::Refused(vec![format!(
                "Shadowsocks over {} cannot be expressed in a share link. The ss:// format \
                 reaches a transport only through the SIP003 plugin mechanism, and the only \
                 plugin framing clients parse is v2ray-plugin's WebSocket. {} carries this node \
                 with its {} transport intact, so use that export instead of a link.",
                other.name(),
                "Xray's JSON export",
                other.name(),
            )]));
        }
    }

    let userinfo = base64_url_nopad(format!("{method}:{password}").as_bytes());
    let params = if plugin_params.is_empty() {
        String::new()
    } else {
        format!("?{}", query(&plugin_params))
    };
    Ok(format!(
        "ss://{}@{}:{}{}#{}",
        userinfo,
        host_for_uri(&node.server.address),
        node.server.port,
        params,
        fragment(&node.tag)
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::model::{Endpoint, Mux, SsMethod, TlsSettings};

    fn node(protocol: Protocol, transport: Transport) -> Node {
        Node {
            tag: "my node".into(),
            server: Endpoint { address: "example.com".into(), port: 443 },
            protocol,
            transport,
            security: Security::Tls(TlsSettings {
                sni: Some("example.com".into()),
                ..Default::default()
            }),
            mux: Mux::default(),
            chain_via: None,
            worker_served: true,
        }
    }

    fn xhttp() -> Transport {
        Transport::Xhttp { mode: XhttpMode::PacketUp, path: "/p".into(), host: None }
    }

    fn ws() -> Transport {
        Transport::WebSocket { path: "/ws".into(), host: None, heartbeat_secs: 30 }
    }

    #[test]
    fn ws_link_never_advertises_h2_alpn() {
        // An h2 ALPN makes TLS negotiate HTTP/2, and the HTTP/1.1 WS upgrade has
        // no connection to run on: the client dials fine, then gets EOF. This is
        // the regression that killed every WS link in the 2026-09-24 sub.
        let xh = node(Protocol::Vless { uuid: "u".into(), flow: Flow::None }, xhttp());
        assert!(to_uri(&xh, ClientTarget::V2rayN, false).expect("emits").contains("alpn=h2"),
            "xhttp rides h2 and keeps its ALPN");

        let w = node(Protocol::Vless { uuid: "u".into(), flow: Flow::None }, ws());
        let uri = to_uri(&w, ClientTarget::V2rayN, false).expect("emits");
        assert!(uri.contains("type=ws"), "{uri}");
        assert!(!uri.contains("alpn="), "WS must let the dialer pick http/1.1: {uri}");

        let tr = node(Protocol::Trojan { password: "p".into() }, ws());
        assert!(!to_uri(&tr, ClientTarget::V2rayN, false).expect("emits").contains("alpn="));
    }

    #[test]
    /// The whole point of the PattN target: its parser reads XHTTP tuning from
    /// the `extra` JSON blob, not from `sc*` query keys. Verified in both
    /// forks - PattN `BaseFmt.ToUriQuery` writes `extra` from
    /// `TransportExtraItem.XhttpExtra`, PattNG `FmtBase.kt` reads
    /// `queryParam["extra"]`. Xray takes that blob verbatim as
    /// `xhttpSettings.extra`.
    #[test]
    fn pattn_links_carry_xhttp_tuning_in_the_extra_blob() {
        let n = node(Protocol::Vless { uuid: "abc-123".into(), flow: Flow::None }, xhttp());
        let uri = to_uri(&n, ClientTarget::PattN, false).expect("emits");

        assert!(uri.contains("type=xhttp"), "transport must still be xhttp");
        // `mode` is deliberately absent from every link (client_params strips
        // it: a malformed `x-phtml packet-up` import was observed). Not added
        // back here - that is a separate, verified concern.
        assert!(uri.contains("extra="), "PattN/PattNG carry tuning under extra");
        // The sc* keys are unreadable to these clients: emitting them would
        // look configured while silently running Xray defaults.
        for dead in ["scMaxEachPostBytes=", "scMaxConcurrentPosts=", "scMinPostsIntervalMs="] {
            assert!(!uri.contains(dead), "{dead} is ignored by PattN/PattNG");
        }
        let blob = uri.split("extra=").nth(1).expect("extra present").split('#').next().expect("no fragment yet");
        // `extra` is percent-encoded by the shared `percent()` helper.
        let decoded = blob
            .replace("%3A", ":")
            .replace("%2C", ",")
            .replace("%22", "\"");
        // The blob must match what translate::xray emits into xhttpSettings,
        // or a PattN node would run different tuning from a Full Normal one.
        for key in ["xPaddingBytes", "scMaxEachPostBytes", "scMinPostsIntervalMs"] {
            assert!(decoded.contains(key), "the blob must carry {key}: {decoded}");
        }
        assert!(decoded.contains("1000000"), "same 1 MB post size as the config path");
        assert!(decoded.contains("\"scMinPostsIntervalMs\":\"0\""), "0 pipelines POSTs");
    }

    /// Every other client keeps the sc* keys exactly as before: this target is
    /// additive and must not move a byte of existing output.
    #[test]
    fn non_pattn_clients_keep_the_sc_query_keys() {
        let n = node(Protocol::Vless { uuid: "abc-123".into(), flow: Flow::None }, xhttp());
        for target in [ClientTarget::V2rayN, ClientTarget::V2rayNg, ClientTarget::Mihomo] {
            let uri = to_uri(&n, target, false).expect("emits");
            assert!(uri.contains("scMaxEachPostBytes=1000000"), "{target:?} lost its sc keys");
            assert!(uri.contains("scMaxConcurrentPosts=10"), "{target:?} lost its sc keys");
            assert!(!uri.contains("extra="), "{target:?} must not gain an extra blob");
        }
    }

    /// The same gap exists on the vmess carrier: `net=xhttp` there is just a
    /// string, so the blob is the only way the tuning survives the import.
    /// Decoded independently of our own encoder, like the test above.
    #[test]
    fn pattn_vmess_links_carry_the_extra_blob() {
        let n = node(
            Protocol::Vmess { uuid: "uid".into(), cipher: VmessCipher::Auto },
            xhttp(),
        );
        let uri = to_uri(&n, ClientTarget::PattN, false).expect("emits");
        let b64 = uri.strip_prefix("vmess://").expect("has scheme");
        let b64 = b64.split('#').next().expect("no fragment");

        let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let (mut acc, mut bits) = (0u32, 0u32);
        let mut out = Vec::new();
        for c in b64.bytes().filter(|&c| c != b'=') {
            let v = alphabet.iter().position(|&x| x == c).unwrap_or(0) as u32;
            acc = (acc << 6) | v;
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                out.push((acc >> bits) as u8);
            }
        }
        let json: serde_json::Value = serde_json::from_slice(&out).expect("valid JSON");

        assert_eq!(json["net"], "xhttp");
        let extra = json["extra"].as_str().expect("extra must be present");
        assert!(extra.contains("scMaxEachPostBytes"), "real blob, not a placeholder: {extra}");
        assert!(extra.contains("scMinPostsIntervalMs"));
    }

    /// PattN is Xray-capable in this panel, so XHTTP must import and the
    /// Xray-only fragment gate stays available to it.
    #[test]
    fn pattn_is_an_xray_capable_target() {
        assert_eq!(ClientTarget::PattN.core(), crate::config::model::Core::Xray);
        assert!(ClientTarget::PattN.supports_xhttp());
        assert_eq!(ClientTarget::PattN.name(), "PattN / PattNG");
    }

    fn vless_link_has_the_shape_clients_expect() {
        let n = node(Protocol::Vless { uuid: "abc-123".into(), flow: Flow::None }, xhttp());
        let uri = to_uri(&n, ClientTarget::V2rayN, false).expect("emits");

        assert!(uri.starts_with("vless://abc-123@example.com:443?"));
        assert!(uri.contains("encryption=none"), "Xray refuses VLESS without it");
        assert!(uri.contains("type=xhttp"));
        
        assert!(uri.contains("security=tls"));
        assert!(uri.contains("path=%2Fp"));
        // Measured uplink sizing (see common_params): fiber Phase 3B 09-28 —
        // 1 MB posts (UL median 1.362 vs 2M 0.996, zero 100-continue stalls,
        // JEV confidence 0.975).
        assert!(uri.contains("scMaxEachPostBytes=1000000"));
        assert!(uri.contains("scMaxConcurrentPosts=10"));
        // Label is percent-encoded, so the space cannot break the fragment.
        assert!(uri.ends_with("#my%20node"));
    }

    #[test]
    fn labels_and_paths_with_delimiters_cannot_truncate_the_link() {
        let mut n = node(Protocol::Vless { uuid: "u".into(), flow: Flow::None }, xhttp());
        n.tag = "node #2 & co".into();
        n.transport = Transport::Xhttp {
            mode: XhttpMode::PacketUp,
            path: "/a#b?c".into(),
            host: None,
        };
        let uri = to_uri(&n, ClientTarget::V2rayN, false).expect("emits");

        // Exactly one '#', and it introduces the label. An unescaped '#' in
        // the path would make everything after it the fragment.
        assert_eq!(uri.matches('#').count(), 1);
        assert!(uri.contains("%23"));
        assert!(uri.ends_with("#node%20%232%20%26%20co"));
    }

    #[test]
    fn trojan_never_emits_flow() {
        let n = node(Protocol::Trojan { password: "p@ss word".into() }, xhttp());
        let uri = to_uri(&n, ClientTarget::V2rayN, false).expect("emits");
        assert!(uri.starts_with("trojan://p%40ss%20word@example.com:443?"));
        assert!(
            !uri.contains("flow="),
            "Xray hard-errors on any flow value for Trojan"
        );
    }

    #[test]
    fn vmess_is_base64_json_with_alterid_zero() {
        let n = node(
            Protocol::Vmess { uuid: "uid".into(), cipher: VmessCipher::Auto },
            Transport::WebSocket { path: "/w".into(), host: None, heartbeat_secs: 30 },
        );
        let uri = to_uri(&n, ClientTarget::V2rayN, false).expect("emits");
        let b64 = uri.strip_prefix("vmess://").expect("has scheme");

        // Decode independently rather than trusting our own encoder.
        let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut acc = 0u32;
        let mut bits = 0u32;
        let mut out = Vec::new();
        for c in b64.bytes().filter(|&c| c != b'=') {
            let v = alphabet.iter().position(|&x| x == c).unwrap_or(0) as u32;
            acc = (acc << 6) | v;
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                out.push((acc >> bits) as u8);
            }
        }
        let json: serde_json::Value =
            serde_json::from_slice(&out).expect("payload is valid JSON");

        assert_eq!(json["aid"], "0", "VMess is AEAD-only; alterId must be 0");
        assert_eq!(json["port"], "443", "port must be a string for wide client support");
        assert_eq!(json["net"], "ws");
        assert_eq!(json["ps"], "my node");
    }

    #[test]
    fn shadowsocks_uses_the_sip002_form() {
        let mut n = node(
            Protocol::Shadowsocks {
                method: SsMethod::Blake3Aes128Gcm,
                password: "AAAAAAAAAAAAAAAAAAAAAA==".into(),
            },
            Transport::Raw,
        );
        // A plain-TCP Shadowsocks node is an external server, not one this
        // Worker serves — the runtime cannot serve a raw transport.
        n.worker_served = false;
        let uri = to_uri(&n, ClientTarget::V2rayN, false).expect("emits");
        assert!(uri.starts_with("ss://"));
        // Host stays readable under SIP002; only userinfo is encoded.
        assert!(uri.contains("@example.com:443"));
        assert!(!uri.contains('='), "SIP002 userinfo is unpadded base64url");
    }

    #[test]
    fn refuses_a_link_that_cannot_work_for_the_client() {
        let n = node(Protocol::Vless { uuid: "u".into(), flow: Flow::None }, xhttp());
        let err = to_uri(&n, ClientTarget::SingBoxUpstream, false)
            .expect_err("upstream sing-box cannot import XHTTP");
        assert!(matches!(err, EmitError::Refused(_)));
    }

    #[test]
    fn ipv6_server_addresses_are_bracketed() {
        // Without brackets the port cannot be distinguished from the address
        // and the link is ambiguous.
        let mut n = node(Protocol::Vless { uuid: "u".into(), flow: Flow::None }, xhttp());
        n.server.address = "2001:db8::1".into();
        let uri = to_uri(&n, ClientTarget::V2rayN, false).expect("emits");
        assert!(uri.contains("@[2001:db8::1]:443"), "got {uri}");

        // An already-bracketed address must not be double-wrapped.
        n.server.address = "[2001:db8::1]".into();
        let uri = to_uri(&n, ClientTarget::V2rayN, false).expect("emits");
        assert!(uri.contains("@[2001:db8::1]:443"), "got {uri}");
    }

    #[test]
    fn ordinary_hosts_pass_through_unescaped() {
        let mut n = node(Protocol::Vless { uuid: "u".into(), flow: Flow::None }, xhttp());
        for addr in ["example.com", "sub.example.co.uk", "93.184.216.34"] {
            n.server.address = addr.into();
            let uri = to_uri(&n, ClientTarget::V2rayN, false).expect("emits");
            assert!(uri.contains(&format!("@{addr}:443")), "{addr} should not be escaped");
        }
    }

    #[test]
    fn output_is_stable_across_regeneration() {
        // A regenerated subscription must be byte-identical when nothing
        // changed, or users cannot tell a real change from noise.
        let n = node(Protocol::Vless { uuid: "u".into(), flow: Flow::None }, xhttp());
        let a = to_uri(&n, ClientTarget::V2rayN, false).expect("emits");
        let b = to_uri(&n, ClientTarget::V2rayN, false).expect("emits");
        assert_eq!(a, b);
    }

    #[test]
    fn never_panics_on_hostile_field_content() {
        let nasty = "\u{0}\u{7f} #&?=/:%\"'\\<>\u{4e2d}\u{6587}";
        let mut n = node(
            Protocol::Vless { uuid: nasty.into(), flow: Flow::Vision },
            Transport::WebSocket { path: nasty.into(), host: Some(nasty.into()), heartbeat_secs: 0 },
        );
        n.tag = nasty.into();
        n.server.address = nasty.into();
        // Vision over a framed transport is refused, which is itself correct;
        // the point is that nothing panics on the way to that decision.
        let _ = to_uri(&n, ClientTarget::V2rayN, false);

        n.protocol = Protocol::Trojan { password: nasty.into() };
        if let Ok(uri) = to_uri(&n, ClientTarget::V2rayN, false) {
            assert_eq!(uri.matches('#').count(), 1);
        }
    }
}

/// Enhanced Reachability coverage. Off-state behaviour is pinned by the tests
/// above, which all emit with the flag off.
#[cfg(test)]
mod enhanced_tests {
    use super::*;
    use crate::config::model::{Endpoint, Mux, SsMethod, TlsSettings};

    fn node(protocol: Protocol, transport: Transport) -> Node {
        Node {
            tag: "my node".into(),
            server: Endpoint { address: "example.com".into(), port: 443 },
            protocol,
            transport,
            security: Security::Tls(TlsSettings {
                sni: Some("example.com".into()),
                ..Default::default()
            }),
            mux: Mux::default(),
            chain_via: None,
            worker_served: true,
        }
    }

    fn xhttp() -> Transport {
        Transport::Xhttp { mode: XhttpMode::PacketUp, path: "/p".into(), host: None }
    }

    fn decode_vmess(uri: &str) -> serde_json::Value {
        let b64 = uri.strip_prefix("vmess://").expect("has scheme");
        let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut acc = 0u32;
        let mut bits = 0u32;
        let mut out = Vec::new();
        for c in b64.bytes().filter(|&c| c != b'=') {
            let v = alphabet.iter().position(|&x| x == c).unwrap_or(0) as u32;
            acc = (acc << 6) | v;
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                out.push((acc >> bits) as u8);
            }
        }
        serde_json::from_slice(&out).expect("payload is valid JSON")
    }

    /// `fp` is a real share-link parameter every Xray client parses, so all
    /// three URI protocols carry it under the toggle. The fragment cannot be
    /// expressed in any link format, so nothing fragment-shaped may appear.
    #[test]
    fn vless_and_trojan_links_carry_fp_chrome() {
        let vless = to_uri(
            &node(Protocol::Vless { uuid: "u".into(), flow: Flow::None }, xhttp()),
            ClientTarget::V2rayN,
            true,
        )
        .expect("emits");
        assert!(vless.contains("fp=chrome"), "got {vless}");
        assert!(!vless.contains("fragment"));

        let trojan = to_uri(
            &node(Protocol::Trojan { password: "pw".into() }, xhttp()),
            ClientTarget::V2rayN,
            true,
        )
        .expect("emits");
        assert!(trojan.contains("fp=chrome"), "got {trojan}");
    }

    #[test]
    fn vmess_json_carrying_the_fingerprint() {
        let uri = to_uri(
            &node(
                Protocol::Vmess { uuid: "uid".into(), cipher: VmessCipher::Auto },
                Transport::WebSocket { path: "/w".into(), host: None, heartbeat_secs: 30 },
            ),
            ClientTarget::V2rayN,
            true,
        )
        .expect("emits");
        assert_eq!(decode_vmess(&uri)["fp"], "chrome");
    }

    #[test]
    fn reality_links_carry_fp_chrome() {
        let mut n = node(Protocol::Vless { uuid: "u".into(), flow: Flow::None }, Transport::Raw);
        n.worker_served = false;
        n.security = Security::Reality(crate::config::model::RealitySettings {
            public_key: "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0".into(),
            short_id: "6ba85179e30d4fc2".into(),
            server_name: "www.microsoft.com".into(),
            fingerprint: None,
        });
        let uri = to_uri(&n, ClientTarget::V2rayN, true).expect("emits");
        assert!(uri.contains("security=reality"));
        assert!(uri.contains("fp=chrome"), "got {uri}");
    }

    #[test]
    fn an_explicit_fingerprint_is_never_overridden() {
        let mut n = node(Protocol::Vless { uuid: "u".into(), flow: Flow::None }, xhttp());
        n.security = Security::Tls(TlsSettings {
            sni: Some("example.com".into()),
            fingerprint: Some("firefox".into()),
            ..Default::default()
        });
        let uri = to_uri(&n, ClientTarget::V2rayN, true).expect("emits");
        assert!(uri.contains("fp=firefox"));
        assert!(!uri.contains("chrome"));
    }

    #[test]
    fn off_and_enhanced_differ_only_in_fp() {
        let n = node(Protocol::Vless { uuid: "u".into(), flow: Flow::None }, xhttp());
        let off = to_uri(&n, ClientTarget::V2rayN, false).expect("emits");
        let on = to_uri(&n, ClientTarget::V2rayN, true).expect("emits");
        assert!(!off.contains("fp="), "off-state links carry no fingerprint");
        assert_eq!(off, on.replace("fp=chrome&", ""),
            "fp=chrome is the only addition");
    }

    /// The SIP003 plugin connection is built by v2ray-plugin, not by Xray, so
    /// Enhanced Reachability has nothing it can add to a Shadowsocks link.
    #[test]
    fn shadowsocks_links_are_identical_with_the_toggle() {
        let mut n = node(
            Protocol::Shadowsocks {
                method: SsMethod::Blake3Aes128Gcm,
                password: "AAAAAAAAAAAAAAAAAAAAAA==".into(),
            },
            Transport::Raw,
        );
        n.worker_served = false;
        let off = to_uri(&n, ClientTarget::V2rayN, false).expect("emits");
        let on = to_uri(&n, ClientTarget::V2rayN, true).expect("emits");
        assert_eq!(off, on, "the toggle must not touch a raw ss:// link");

        // Transport is preserved through the plugin mechanism in both states.
        n.transport = Transport::WebSocket { path: "/sw".into(), host: None, heartbeat_secs: 0 };
        let ws = to_uri(&n, ClientTarget::V2rayN, true).expect("emits");
        assert!(ws.contains("plugin=v2ray-plugin"), "got {ws}");
        assert!(ws.contains("plugin-opts=ws%3Btls%3Bhost%3Dexample.com%3Bpath%3D%2Fsw"), "got {ws}");
        assert!(!ws.contains("fp="), "v2ray-plugin takes no fingerprint");

        // XHTTP has no plugin encoding; the link points at the JSON export.
        n.transport = xhttp();
        match to_uri(&n, ClientTarget::V2rayN, true) {
            Err(EmitError::Refused(reasons)) => {
                assert!(reasons.iter().any(|r| r.contains("JSON export")));
            }
            other => panic!("ss://+xhttp must be refused, got {other:?}"),
        }
    }
}