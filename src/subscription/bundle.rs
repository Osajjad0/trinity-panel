//! Rendering a set of nodes into what a particular client will import.
//!
//! # Why the unit is a client, not a core
//!
//! v2rayN wants a base64 blob of share links. Clash Meta wants YAML with a
//! proxy list and groups. sing-box wants a JSON document with outbounds and a
//! route block. Handing any of them the wrong one produces an import that
//! fails with a message pointing at the file rather than at the mismatch.
//!
//! # Partial success is the normal case
//!
//! A subscription usually contains nodes some clients cannot express — an
//! XHTTP node in an upstream sing-box bundle, say. Refusing the whole bundle
//! because one node does not translate would deny the user the nodes that do,
//! and silently omitting it would leave them wondering where it went. So every
//! bundle carries [`Bundle::skipped`], and the panel shows it.

use crate::config::model::{ClientTarget, Core, Node};
use crate::translate::{mihomo, singbox, xray, Emit, EmitError, Mihomo, SingBox, XrayEmitter};

use super::uri;

/// What the caller asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shape {
    /// Newline-separated share links, base64-encoded as a whole.
    ///
    /// The historical Shadowsocks subscription format, and what every
    /// v2ray-family client still expects from a subscription URL.
    ShareLinks,
    /// Newline-separated share links, not encoded. Easier to inspect, and what
    /// the panel shows on screen.
    ShareLinksPlain,
    /// A full config document for the client's core.
    FullConfig,
}

/// A node that could not be included, and why.
#[derive(serde::Serialize, Debug, Clone, PartialEq, Eq)]
pub struct Skipped {
    pub tag: String,
    pub reason: String,
}

/// A rendered subscription.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bundle {
    pub body: String,
    pub content_type: &'static str,
    /// Suggested filename, for a browser download.
    pub filename: String,
    /// Nodes left out, with the reason. Never silently empty.
    pub skipped: Vec<Skipped>,
    /// How many nodes made it in.
    pub included: usize,
}

/// Render `nodes` for `target` in `shape`.
///
/// # Errors
/// [`EmitError`] only when the whole bundle cannot be produced — a single node
/// failing is reported in [`Bundle::skipped`] rather than failing the request.
pub fn render(nodes: &[Node], target: ClientTarget, shape: Shape) -> Result<Bundle, EmitError> {
    match shape {
        Shape::ShareLinks | Shape::ShareLinksPlain => {
            Ok(share_links(nodes, target, shape == Shape::ShareLinks))
        }
        Shape::FullConfig => full_config(nodes, target),
    }
}

fn share_links(nodes: &[Node], target: ClientTarget, encode: bool) -> Bundle {
    let mut links = Vec::new();
    let mut skipped = Vec::new();

    for node in nodes {
        match uri::to_uri(node, target) {
            Ok(link) => links.push(link),
            Err(e) => skipped.push(Skipped { tag: node.tag.clone(), reason: e.to_string() }),
        }
    }

    let joined = links.join("\n");
    let body = if encode {
        crate::subscription::encode::base64(joined.as_bytes())
    } else {
        joined
    };

    Bundle {
        body,
        content_type: "text/plain; charset=utf-8",
        filename: format!("{}-links.txt", slug(target.name())),
        skipped,
        included: links.len(),
    }
}

fn full_config(nodes: &[Node], target: ClientTarget) -> Result<Bundle, EmitError> {
    let mut skipped = Vec::new();
    let mut usable = Vec::new();

    // Gate every node first so one bad node never reaches the emitter, and the
    // reason reaches the user instead.
    for node in nodes {
        match emit_one(node, target) {
            Ok(()) => usable.push(node.clone()),
            Err(e) => skipped.push(Skipped { tag: node.tag.clone(), reason: e.to_string() }),
        }
    }

    if usable.is_empty() {
        let reasons = skipped.iter().map(|s| format!("{}: {}", s.tag, s.reason)).collect();
        return Err(EmitError::Refused(reasons));
    }

    // Emitters take the whole set, because a multi-node config is not a
    // concatenation of single-node ones: it needs one outbound list, one
    // selector group, and one route block referring to them.
    let emitted = match target.core() {
        Core::Xray => xray::emit_nodes(&usable, target)?,
        Core::SingBox => singbox::emit_nodes(&usable, target)?,
        Core::Mihomo => mihomo::emit_nodes(&usable, target)?,
    };

    let format = emitted.format;
    Ok(Bundle {
        body: emitted.config,
        content_type: format.content_type(),
        filename: format!("{}.{}", slug(target.name()), format.extension()),
        skipped,
        included: usable.len(),
    })
}

/// Whether one node survives translation for this target.
fn emit_one(node: &Node, target: ClientTarget) -> Result<(), EmitError> {
    match target.core() {
        Core::Xray => XrayEmitter.emit(node, target).map(|_| ()),
        Core::SingBox => SingBox.emit(node, target).map(|_| ()),
        Core::Mihomo => Mihomo.emit(node, target).map(|_| ()),
    }
}

/// Filename-safe form of a client name.
fn slug(name: &str) -> String {
    name.chars()
        .map(|c| if c.is_ascii_alphanumeric() { c.to_ascii_lowercase() } else { '-' })
        .collect::<String>()
        .trim_matches('-')
        .replace("--", "-")
}

/// Parse the path remainder of a subscription URL.
///
/// Accepts `<client>`, `<client>.json`, `<client>.yaml`, and `<client>/links`.
/// Returns `None` for anything unrecognised, which the caller renders as the
/// decoy — a subscription path that answers differently for a known and an
/// unknown client name is a way to enumerate it.
#[must_use]
pub fn parse_request(rest: &str) -> Option<(ClientTarget, Shape)> {
    let rest = rest.trim_matches('/');
    let (name, shape) = match rest.rsplit_once('.') {
        Some((n, "json" | "yaml" | "yml")) => (n, Shape::FullConfig),
        Some((n, "txt")) => (n, Shape::ShareLinksPlain),
        _ => match rest.split_once('/') {
            Some((n, "links")) => (n, Shape::ShareLinksPlain),
            Some((n, "config")) => (n, Shape::FullConfig),
            _ => (rest, Shape::ShareLinks),
        },
    };
    Some((client_from_name(name)?, shape))
}

/// Map a URL segment to a client.
///
/// Several spellings per client on purpose: a user typing the URL by hand
/// should not have to guess our capitalisation.
#[must_use]
pub fn client_from_name(name: &str) -> Option<ClientTarget> {
    let n = name.trim().to_ascii_lowercase();
    match n.as_str() {
        "v2rayn" => Some(ClientTarget::V2rayN),
        "v2rayng" => Some(ClientTarget::V2rayNg),
        "hiddify" => Some(ClientTarget::Hiddify),
        "karing" => Some(ClientTarget::Karing),
        "sing-box" | "singbox" => Some(ClientTarget::SingBoxUpstream),
        "mihomo" | "clash" | "clash-meta" | "clashmeta" => Some(ClientTarget::Mihomo),
        "nekobox" => Some(ClientTarget::NekoBox),
        _ => None,
    }
}

/// Every client, for the panel's export list.
#[must_use]
pub const fn all_clients() -> [ClientTarget; 7] {
    [
        ClientTarget::V2rayN,
        ClientTarget::V2rayNg,
        ClientTarget::Hiddify,
        ClientTarget::Karing,
        ClientTarget::SingBoxUpstream,
        ClientTarget::Mihomo,
        ClientTarget::NekoBox,
    ]
}

/// The URL segment for a client, matching what [`client_from_name`] accepts.
#[must_use]
pub const fn client_slug(target: ClientTarget) -> &'static str {
    match target {
        ClientTarget::V2rayN => "v2rayn",
        ClientTarget::V2rayNg => "v2rayng",
        ClientTarget::Hiddify => "hiddify",
        ClientTarget::Karing => "karing",
        ClientTarget::SingBoxUpstream => "sing-box",
        ClientTarget::Mihomo => "mihomo",
        ClientTarget::NekoBox => "nekobox",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::model::{
        Endpoint, Flow, Mux, Protocol, Security, TlsSettings, Transport, XhttpMode,
    };

    fn xhttp_node(tag: &str) -> Node {
        Node {
            tag: tag.to_owned(),
            server: Endpoint { address: "example.com".into(), port: 443 },
            protocol: Protocol::Vless {
                uuid: "01234567-89ab-cdef-0123-456789abcdef".into(),
                flow: Flow::None,
            },
            transport: Transport::Xhttp {
                mode: XhttpMode::PacketUp,
                path: "/abc".into(),
                host: Some("example.com".into()),
            },
            security: Security::Tls(TlsSettings {
                sni: Some("example.com".into()),
                ..TlsSettings::default()
            }),
            mux: Mux::default(),
            chain_via: None,
            worker_served: true,
        }
    }

    #[test]
    fn share_links_are_base64_by_default_and_plain_on_request() {
        let nodes = [xhttp_node("a"), xhttp_node("b")];
        let encoded = render(&nodes, ClientTarget::V2rayN, Shape::ShareLinks).expect("renders");
        let plain =
            render(&nodes, ClientTarget::V2rayN, Shape::ShareLinksPlain).expect("renders");

        assert_eq!(encoded.included, 2);
        assert_eq!(plain.body.lines().count(), 2);
        assert!(plain.body.starts_with("vless://"));
        // The encoded form is what a subscription URL must return.
        assert!(!encoded.body.contains("vless://"));
        assert_eq!(
            crate::crypto::base64::decode(&encoded.body).as_deref(),
            Some(plain.body.as_bytes())
        );
    }

    #[test]
    fn a_node_a_client_cannot_express_is_skipped_with_a_reason() {
        // The behaviour that matters: the other nodes still arrive, and the
        // user is told what was left out rather than left guessing.
        let nodes = [xhttp_node("xhttp-one")];
        let bundle = render(&nodes, ClientTarget::SingBoxUpstream, Shape::ShareLinks)
            .expect("renders");
        assert_eq!(bundle.included, 0);
        assert_eq!(bundle.skipped.len(), 1);
        assert_eq!(bundle.skipped[0].tag, "xhttp-one");
        assert!(!bundle.skipped[0].reason.is_empty());
    }

    #[test]
    fn a_client_that_supports_xhttp_gets_the_node() {
        for target in [ClientTarget::V2rayN, ClientTarget::Hiddify, ClientTarget::Mihomo] {
            let bundle =
                render(&[xhttp_node("n")], target, Shape::ShareLinks).expect("renders");
            assert_eq!(bundle.included, 1, "{}", target.name());
            assert!(bundle.skipped.is_empty(), "{}", target.name());
        }
    }

    #[test]
    fn a_full_config_is_refused_when_nothing_translates() {
        // Distinct from an empty bundle: there is nothing to import, so a
        // client should be told rather than handed an empty document.
        let err = render(&[xhttp_node("n")], ClientTarget::SingBoxUpstream, Shape::FullConfig)
            .expect_err("must refuse");
        assert!(matches!(err, EmitError::Refused(_)));
    }

    #[test]
    fn full_configs_carry_the_right_content_type_and_extension() {
        let xray = render(&[xhttp_node("n")], ClientTarget::V2rayN, Shape::FullConfig)
            .expect("renders");
        assert_eq!(xray.filename, "v2rayn.json");
        assert!(xray.content_type.contains("json"));

        let clash = render(&[xhttp_node("n")], ClientTarget::Mihomo, Shape::FullConfig)
            .expect("renders");
        assert_eq!(clash.filename, "mihomo--clash-meta.yaml");
    }

    #[test]
    fn url_shapes_map_to_client_and_format() {
        assert_eq!(parse_request("v2rayn"), Some((ClientTarget::V2rayN, Shape::ShareLinks)));
        assert_eq!(
            parse_request("mihomo.yaml"),
            Some((ClientTarget::Mihomo, Shape::FullConfig))
        );
        assert_eq!(
            parse_request("hiddify.json"),
            Some((ClientTarget::Hiddify, Shape::FullConfig))
        );
        assert_eq!(
            parse_request("karing/links"),
            Some((ClientTarget::Karing, Shape::ShareLinksPlain))
        );
        assert_eq!(parse_request("/v2rayng/"), Some((ClientTarget::V2rayNg, Shape::ShareLinks)));
    }

    #[test]
    fn an_unknown_client_is_not_distinguishable_from_a_wrong_path() {
        // Both render the decoy at the caller, so neither confirms the prefix.
        assert_eq!(parse_request("nope"), None);
        assert_eq!(parse_request(""), None);
        assert_eq!(parse_request("v2rayn.exe"), None);
    }

    #[test]
    fn every_client_has_a_slug_that_round_trips() {
        for target in all_clients() {
            assert_eq!(client_from_name(client_slug(target)), Some(target));
        }
    }

    #[test]
    fn client_names_are_accepted_in_the_spellings_people_type() {
        for (text, want) in [
            ("Clash", ClientTarget::Mihomo),
            ("clash-meta", ClientTarget::Mihomo),
            ("SingBox", ClientTarget::SingBoxUpstream),
            ("V2rayN", ClientTarget::V2rayN),
        ] {
            assert_eq!(client_from_name(text), Some(want), "{text}");
        }
    }

    #[test]
    fn parsing_never_panics() {
        let mut seed = 0x9f2a_7c11_3345_8890u64;
        for _ in 0..3000 {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            let len = (seed % 40) as usize;
            let s: String = (0..len).map(|i| (seed >> (i % 56)) as u8 as char).collect();
            let _ = parse_request(&s);
        }
    }
}
