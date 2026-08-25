//! The panel's HTTP surface, decided without touching HTTP.
//!
//! Route parsing and every response body are built here, from values, so they
//! run in the host test suite. [`super::serve`] does nothing but read the
//! request, call into this module, and write the result — which is the only
//! part a unit test could not reach anyway.
//!
//! # What is behind a session and what is not
//!
//! Only the shell page is served without one. That is a deliberate exception to
//! the rule that every negative outcome renders the decoy, and it is worth
//! stating plainly rather than leaving as an accident: there has to be
//! *somewhere* to type the password, and a login form that is itself behind a
//! login is not a design.
//!
//! What makes it acceptable is that the panel prefix is already a secret. A
//! scanner sweeping this hostname tries `/`, `/admin`, `/wp-login.php` and gets
//! the decoy for all of them, because none of them match the prefix. Only a
//! request that already carries the prefix — which is generated random and
//! never guessed — sees a login form at all. Confirming "yes, this is the
//! panel" to someone who has already produced that secret costs nothing they
//! did not already have.
//!
//! Every other route requires a valid session, and a deployment with no
//! password configured has no panel at all rather than an open one.

use serde::{Deserialize, Serialize};

use crate::config::model::{ClientTarget, Node};
use crate::relay::outbound::{OutboundConfig, ProxyMode};
use crate::subscription::bundle::{self, Shape, Skipped};

use super::store::Settings;

/// What a panel request is asking for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Api {
    /// The panel page itself. The only route served without a session.
    Page,
    Login,
    Logout,
    /// Everything the panel needs to render.
    State,
    /// Replace the node set.
    Save,
    /// Re-evaluate a draft node without saving it.
    Check,
    /// A rendered subscription body, for preview and download.
    Export,
    /// A QR image for a subscription or a node.
    Qr,
    /// Anything else. Renders the decoy.
    Unknown,
}

impl Api {
    /// Whether this route may be reached without a valid session.
    #[must_use]
    pub const fn is_public(self) -> bool {
        matches!(self, Self::Page | Self::Login)
    }
}

/// Classify a panel request from its method and the path after the prefix.
#[must_use]
pub fn route(method: &str, rest: &str) -> Api {
    let rest = rest.trim_matches('/');
    match (method, rest) {
        ("GET", "") => Api::Page,
        ("POST", "api/login") => Api::Login,
        ("POST", "api/logout") => Api::Logout,
        ("GET", "api/state") => Api::State,
        ("PUT" | "POST", "api/nodes") => Api::Save,
        ("POST", "api/check") => Api::Check,
        ("GET", "api/export") => Api::Export,
        ("GET", "api/qr") => Api::Qr,
        _ => Api::Unknown,
    }
}

/// What the browser posts to log in.
#[derive(Deserialize, Debug)]
pub struct LoginRequest {
    pub password: String,
}

/// What the browser posts to save.
#[derive(Deserialize, Debug)]
pub struct SaveRequest {
    pub nodes: Vec<Node>,
    /// Outbound routing config. Defaults to Off when absent (old clients).
    #[serde(default)]
    pub outbound: OutboundConfig,
    /// Enhanced Reachability toggle. Defaults to off when absent (old
    /// clients), and off is the byte-identical existing behaviour.
    #[serde(default)]
    pub enhanced_reachability: bool,
}

/// What the browser posts to re-check a draft.
///
/// The edit is sent as a field name and a value rather than as an already
/// modified node, so the browser never has to know how a [`Node`] is shaped.
/// The server applies it with [`super::advisor::apply`] — the same function
/// that builds the candidates deciding which choices are blocked — and returns
/// the resulting node. That is what keeps "this option is disabled" and "this
/// is what saving would produce" from being two different pieces of logic.
#[derive(Deserialize, Debug)]
pub struct CheckRequest {
    pub node: Node,
    /// Client slug the editor is currently showing.
    pub client: String,
    /// The change to apply first, if any.
    #[serde(default)]
    pub edit: Option<Edit>,
    /// The toggle's local state, so advice matches what saving would render.
    #[serde(default)]
    pub enhanced_reachability: bool,
}

#[derive(Deserialize, Debug)]
pub struct Edit {
    pub field: String,
    pub value: String,
}

/// The advice for a draft node, together with the node the edit produced.
#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
pub struct Checked {
    pub node: Node,
    #[serde(flatten)]
    pub advice: super::advisor::Advice,
}

/// One client, as the simple view lists it.
#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
pub struct ClientView {
    pub name: &'static str,
    pub slug: &'static str,
    pub core: &'static str,
    /// Subscription URL to paste into the app. Empty when nothing translates.
    pub subscription: String,
    /// Direct download of a full configuration file, where the client takes one.
    pub config: Option<String>,
    /// How many of the deployment's nodes this client can actually use.
    pub included: usize,
    /// Nodes it cannot, and why. Never silently omitted.
    pub skipped: Vec<Skipped>,
}

/// One node, as the editor and the simple view list it.
#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
pub struct NodeView {
    pub tag: String,
    pub protocol: &'static str,
    pub transport: &'static str,
    /// Share links by client slug, for the clients that can express this node.
    pub links: Vec<NodeLink>,
    /// Every client's verdict on this node.
    pub matrix: Vec<super::advisor::TargetVerdict>,
}

#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
pub struct NodeLink {
    pub client: &'static str,
    pub uri: String,
}

/// Everything the panel needs on load.
#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct State {
    pub host: String,
    /// `stored` when the operator has saved a set, `derived` when these are the
    /// nodes the deployment's own bindings imply. Shown, because "I never
    /// configured this" is otherwise a confusing thing to be looking at.
    pub source: &'static str,
    /// Present when a stored document could not be read. The deployment keeps
    /// serving the derived set; this is how the operator finds out why.
    pub warning: Option<String>,
    pub nodes: Vec<Node>,
    pub views: Vec<NodeView>,
    pub clients: Vec<ClientView>,
    /// An empty connection to start from, built by the same code that builds
    /// every other node. The browser adding one of its own would be a second
    /// place that knows the model's shape.
    pub blank: Node,
    /// Outbound routing configuration (Proxy IP / NAT64).
    pub outbound: OutboundConfig,
    /// The Enhanced Reachability toggle's current value. Shown so the panel
    /// renders the same on/off state the subscriptions are being served with.
    pub enhanced_reachability: bool,
}

/// Where the settings a request is serving came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    Stored,
    Derived,
}

/// Build the panel state.
///
/// `sub_base` is the absolute URL prefix subscriptions are served from, so the
/// browser never has to reassemble it and get the secret prefix wrong.
#[must_use]
pub fn state(
    settings: &Settings,
    host: &str,
    sub_base: &str,
    xhttp_path: &str,
    source: Source,
    warning: Option<String>,
) -> State {
    let clients = bundle::all_clients()
        .into_iter()
        .map(|client| client_view(&settings.nodes, client, sub_base, settings.enhanced_reachability))
        .collect();

    let views = settings
        .nodes
        .iter()
        .map(|node| node_view(node, settings.enhanced_reachability))
        .collect();

    State {
        host: host.to_owned(),
        source: match source {
            Source::Stored => "stored",
            Source::Derived => "derived",
        },
        warning,
        nodes: settings.nodes.clone(),
        views,
        clients,
        blank: super::advisor::blank(host, xhttp_path),
        outbound: settings.outbound.clone(),
        enhanced_reachability: settings.enhanced_reachability,
    }
}

fn client_view(nodes: &[Node], client: ClientTarget, sub_base: &str, enhanced: bool) -> ClientView {
    let slug = bundle::client_slug(client);
    // The share-link bundle is what a subscription URL returns, so its skip
    // list is the honest answer to "what will this app actually receive".
    let links = bundle::render(nodes, client, Shape::ShareLinks, enhanced);
    let (included, skipped) = links
        .as_ref()
        .map_or_else(|_| (0, Vec::new()), |b| (b.included, b.skipped.clone()));

    let subscription = if included > 0 {
        format!("{sub_base}/{slug}")
    } else {
        String::new()
    };
    // Offered only when the emitter really produces a document for this
    // client; a download link that returns the decoy is worse than no link.
    let config = bundle::render(nodes, client, Shape::FullConfig, enhanced)
        .ok()
        .map(|b| format!("{sub_base}/{slug}.{}", extension(&b.filename)));

    ClientView {
        name: client.name(),
        slug,
        core: client.core().name(),
        subscription,
        config,
        included,
        skipped,
    }
}

/// The extension of a rendered filename, defaulting to JSON.
fn extension(filename: &str) -> &str {
    filename.rsplit_once('.').map_or("json", |(_, ext)| ext)
}

fn node_view(node: &Node, enhanced: bool) -> NodeView {
    let links = bundle::all_clients()
        .into_iter()
        .filter_map(|client| {
            crate::subscription::to_uri(node, client, enhanced)
                .ok()
                .map(|uri| NodeLink { client: bundle::client_slug(client), uri })
        })
        .collect();

    NodeView {
        tag: node.tag.clone(),
        protocol: node.protocol.name(),
        transport: node.transport.name(),
        links,
        matrix: super::advisor::matrix(node, enhanced),
    }
}

/// Reject a node set that cannot be stored or served.
///
/// Only structural refusals belong here. A node that merely fails for one
/// client is reported by the advisor and left saveable, because the operator is
/// allowed to keep a node that only some of their apps can use.
///
/// # Errors
/// A message addressed to the operator.
pub fn validate(nodes: &[Node]) -> Result<(), String> {
    if nodes.len() > MAX_NODES {
        return Err(format!("{MAX_NODES} connections is the limit"));
    }
    for node in nodes {
        if node.tag.trim().is_empty() {
            return Err("every connection needs a name".to_owned());
        }
        if node.server.address.trim().is_empty() {
            return Err(format!("\"{}\" has no server address", node.tag));
        }
    }
    // Tags identify a node in every export and in the chain field, so two nodes
    // sharing one would make both unaddressable.
    for (i, node) in nodes.iter().enumerate() {
        if nodes.iter().skip(i + 1).any(|other| other.tag == node.tag) {
            return Err(format!("two connections are both called \"{}\"", node.tag));
        }
    }
    for node in nodes {
        if let Some(via) = &node.chain_via {
            if via == &node.tag {
                return Err(format!("\"{}\" cannot chain through itself", node.tag));
            }
            if !nodes.iter().any(|n| &n.tag == via) {
                return Err(format!(
                    "\"{}\" chains through \"{via}\", which is not one of your connections",
                    node.tag
                ));
            }
        }
    }
    Ok(())
}

/// A generous ceiling. It exists so a malformed or hostile request cannot make
/// the settings document unbounded, not to constrain real use.
const MAX_NODES: usize = 64;

/// Same reasoning as [`MAX_NODES`], for the outbound candidate lists.
const MAX_OUTBOUND_ENTRIES: usize = 64;

/// Reject an outbound config that cannot be stored or dialled.
///
/// Validated here rather than only at dial time because a candidate that the
/// relay silently skips is indistinguishable, from the panel, from one that is
/// being used — the operator would see a saved Proxy IP and a connection that
/// still goes direct, with nothing to explain it.
///
/// Only entries that would be *dropped* are refused. Reachability is
/// deliberately not checked: whether a proxy actually forwards traffic is
/// something only the real relay path can answer, and guessing here would
/// produce exactly the fake verdict this project refuses to ship.
///
/// # Errors
/// A message addressed to the operator.
pub fn validate_outbound(cfg: &OutboundConfig) -> Result<(), String> {
    use crate::relay::outbound::{validate_nat64_prefix, validate_proxy_candidate};

    if cfg.proxy_candidates.len() > MAX_OUTBOUND_ENTRIES
        || cfg.nat64_prefixes.len() > MAX_OUTBOUND_ENTRIES
    {
        return Err(format!("{MAX_OUTBOUND_ENTRIES} outbound entries is the limit"));
    }
    for candidate in &cfg.proxy_candidates {
        if !validate_proxy_candidate(candidate) {
            return Err(format!(
                "\"{candidate}\" is not a usable proxy address. Give a public IP or a hostname, \
                 with no port and no path."
            ));
        }
    }
    for prefix in &cfg.nat64_prefixes {
        if !validate_nat64_prefix(prefix) {
            return Err(format!(
                "\"{prefix}\" is not a valid NAT64 prefix. It must be a /96 whose last 32 bits \
                 are zero, like 64:ff9b::/96."
            ));
        }
    }
    // A mode that needs entries it does not have would save cleanly and then
    // behave as Off, which looks like the feature is broken rather than unset.
    if cfg.mode == ProxyMode::ProxyIp && cfg.proxy_candidates.is_empty() {
        return Err("Proxy IP mode needs at least one proxy address.".to_owned());
    }
    Ok(())
}

/// What a QR request is for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QrSubject {
    /// The subscription URL for a client.
    Subscription(ClientTarget),
    /// One node's share link, as a given client would import it.
    Node { tag: String, client: ClientTarget },
}

/// Parse the query of a QR request.
///
/// Takes already-decoded pairs so this stays free of any URL library.
#[must_use]
pub fn qr_subject<'a>(pairs: impl Iterator<Item = (&'a str, &'a str)>) -> Option<QrSubject> {
    let mut kind = "";
    let mut client = "";
    let mut tag = String::new();
    for (k, v) in pairs {
        match k {
            "kind" => kind = v,
            "client" => client = v,
            "tag" => v.clone_into(&mut tag),
            _ => {}
        }
    }
    let client = bundle::client_from_name(client)?;
    match kind {
        "sub" => Some(QrSubject::Subscription(client)),
        "node" if !tag.is_empty() => Some(QrSubject::Node { tag, client }),
        _ => None,
    }
}

/// Parse the query of an export request into a client and a shape.
#[must_use]
pub fn export_subject<'a>(
    pairs: impl Iterator<Item = (&'a str, &'a str)>,
) -> Option<(ClientTarget, Shape)> {
    let mut client = "";
    let mut shape = "";
    for (k, v) in pairs {
        match k {
            "client" => client = v,
            "shape" => shape = v,
            _ => {}
        }
    }
    let client = bundle::client_from_name(client)?;
    let shape = match shape {
        "config" => Shape::FullConfig,
        "links" => Shape::ShareLinksPlain,
        "base64" => Shape::ShareLinks,
        _ => return None,
    };
    Some((client, shape))
}

#[cfg(test)]
mod tests {
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

    fn settings() -> Settings {
        Settings {
            version: super::super::store::VERSION,
            nodes: vec![node("a"), node("b")],
            outbound: OutboundConfig::default(),
            enhanced_reachability: false,
        }
    }

    #[test]
    fn routes_map_to_actions_and_everything_else_is_unknown() {
        assert_eq!(route("GET", ""), Api::Page);
        assert_eq!(route("GET", "/"), Api::Page);
        assert_eq!(route("POST", "api/login"), Api::Login);
        assert_eq!(route("GET", "api/state"), Api::State);
        assert_eq!(route("PUT", "api/nodes"), Api::Save);
        assert_eq!(route("POST", "api/check"), Api::Check);
        assert_eq!(route("GET", "api/qr"), Api::Qr);

        for (m, p) in [
            ("GET", "api/login"),
            ("POST", "api/state"),
            ("GET", "api/nodes"),
            ("DELETE", "api/nodes"),
            ("GET", "../etc/passwd"),
            ("GET", "api"),
            ("GET", "index.html"),
        ] {
            assert_eq!(route(m, p), Api::Unknown, "{m} {p}");
        }
    }

    #[test]
    fn only_the_page_and_the_login_are_reachable_without_a_session() {
        // The panel can read every credential the deployment serves, so this
        // list is the whole security boundary and is pinned deliberately.
        for api in [Api::State, Api::Save, Api::Check, Api::Export, Api::Qr, Api::Logout] {
            assert!(!api.is_public(), "{api:?} must require a session");
        }
        assert!(Api::Page.is_public());
        assert!(Api::Login.is_public());
    }

    #[test]
    fn the_state_names_every_client_and_what_it_will_actually_receive() {
        let s = state(&settings(), "example.com", "https://example.com/sub", "/x", Source::Derived, None);
        assert_eq!(s.clients.len(), bundle::all_clients().len());
        assert_eq!(s.source, "derived");

        let v2rayn = s.clients.iter().find(|c| c.slug == "v2rayn").expect("listed");
        assert_eq!(v2rayn.subscription, "https://example.com/sub/v2rayn");
        assert_eq!(v2rayn.included, 2);
        assert!(v2rayn.skipped.is_empty());
        assert_eq!(v2rayn.config.as_deref(), Some("https://example.com/sub/v2rayn.json"));

        // Upstream sing-box cannot take an XHTTP node, and must say so rather
        // than be offered a subscription that would arrive empty.
        let upstream = s.clients.iter().find(|c| c.slug == "sing-box").expect("listed");
        assert_eq!(upstream.included, 0);
        assert!(upstream.subscription.is_empty());
        assert_eq!(upstream.skipped.len(), 2);
        assert!(upstream.config.is_none());
    }

    #[test]
    fn a_mihomo_config_is_offered_with_its_own_extension() {
        let s = state(&settings(), "example.com", "https://example.com/sub", "/x", Source::Stored, None);
        let mihomo = s.clients.iter().find(|c| c.slug == "mihomo").expect("listed");
        assert_eq!(mihomo.config.as_deref(), Some("https://example.com/sub/mihomo.yaml"));
    }

    #[test]
    fn each_node_carries_its_links_and_its_verdicts() {
        let s = state(&settings(), "example.com", "https://example.com/sub", "/x", Source::Stored, None);
        let first = &s.views[0];
        assert_eq!(first.tag, "a");
        assert_eq!(first.protocol, "VLESS");
        assert_eq!(first.transport, "XHTTP");
        assert!(first.links.iter().any(|l| l.client == "v2rayn" && l.uri.starts_with("vless://")));
        assert!(!first.links.iter().any(|l| l.client == "sing-box"));
        assert_eq!(first.matrix.len(), bundle::all_clients().len());
    }

    #[test]
    fn validation_refuses_what_would_make_a_node_unaddressable() {
        assert!(validate(&[node("a"), node("b")]).is_ok());

        assert!(validate(&[node("a"), node("a")]).is_err(), "duplicate names");

        let mut blank = node("");
        blank.tag = "  ".into();
        assert!(validate(&[blank]).is_err(), "blank name");

        let mut no_address = node("a");
        no_address.server.address = String::new();
        assert!(validate(&[no_address]).is_err());

        let mut self_chain = node("a");
        self_chain.chain_via = Some("a".into());
        assert!(validate(&[self_chain]).is_err(), "self chain");

        let mut dangling = node("a");
        dangling.chain_via = Some("nowhere".into());
        assert!(validate(&[dangling]).is_err(), "chain to a node that does not exist");

        let mut chain = vec![node("a"), node("b")];
        chain[1].chain_via = Some("a".into());
        assert!(validate(&chain).is_ok(), "a real chain is fine");
    }

    #[test]
    fn a_node_set_is_bounded() {
        let many: Vec<Node> = (0..=MAX_NODES).map(|i| node(&i.to_string())).collect();
        assert!(validate(&many).is_err());
    }

    #[test]
    fn qr_requests_name_their_subject_or_are_refused() {
        assert_eq!(
            qr_subject([("kind", "sub"), ("client", "v2rayn")].into_iter()),
            Some(QrSubject::Subscription(ClientTarget::V2rayN))
        );
        assert_eq!(
            qr_subject([("kind", "node"), ("client", "hiddify"), ("tag", "a")].into_iter()),
            Some(QrSubject::Node { tag: "a".into(), client: ClientTarget::Hiddify })
        );
        for bad in [
            vec![("kind", "sub")],
            vec![("kind", "node"), ("client", "v2rayn")],
            vec![("kind", "other"), ("client", "v2rayn")],
            vec![("client", "nonesuch"), ("kind", "sub")],
            vec![],
        ] {
            assert_eq!(qr_subject(bad.clone().into_iter()), None, "{bad:?}");
        }
    }

    #[test]
    fn export_requests_name_a_client_and_a_shape() {
        assert_eq!(
            export_subject([("client", "mihomo"), ("shape", "config")].into_iter()),
            Some((ClientTarget::Mihomo, Shape::FullConfig))
        );
        assert_eq!(
            export_subject([("client", "v2rayn"), ("shape", "links")].into_iter()),
            Some((ClientTarget::V2rayN, Shape::ShareLinksPlain))
        );
        assert_eq!(export_subject([("client", "v2rayn")].into_iter()), None);
        assert_eq!(
            export_subject([("client", "v2rayn"), ("shape", "exe")].into_iter()),
            None
        );
    }

    #[test]
    fn routing_never_panics() {
        let mut seed = 0x77c1_2ba9_4410_9f31u64;
        for _ in 0..3000 {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            let len = (seed % 40) as usize;
            let s: String = (0..len).map(|i| (seed >> (i % 56)) as u8 as char).collect();
            for m in ["GET", "POST", "PUT", ""] {
                let _ = route(m, &s);
            }
        }
    }

    // --- outbound validation at the save boundary ---

    #[test]
    fn the_default_outbound_config_saves_cleanly() {
        // Off with nothing set is what every existing deployment posts. If this
        // ever refuses, saving nodes breaks for everyone who never touched the
        // feature.
        assert!(validate_outbound(&OutboundConfig::default()).is_ok());
    }

    #[test]
    fn a_usable_proxy_config_is_accepted() {
        let cfg = OutboundConfig {
            mode: ProxyMode::ProxyIp,
            proxy_candidates: vec!["93.184.216.34".into(), "edge.example.com".into()],
            ..Default::default()
        };
        assert!(validate_outbound(&cfg).is_ok());
    }

    #[test]
    fn candidates_the_relay_would_drop_are_refused_at_save_time() {
        // Each of these parses as a string but cannot be dialled, so the relay
        // would skip it. Saving it silently is what makes a working-looking
        // config that goes direct.
        for bad in ["127.0.0.1", "10.0.0.1", "host:443", "host/path", "   "] {
            let cfg = OutboundConfig {
                mode: ProxyMode::ProxyIp,
                proxy_candidates: vec![bad.into()],
                ..Default::default()
            };
            let err = validate_outbound(&cfg).expect_err(&format!("{bad:?} must be refused"));
            assert!(err.contains(bad.trim()) || !bad.trim().is_empty());
        }
    }

    #[test]
    fn nat64_prefixes_must_be_96_with_a_zero_tail() {
        for bad in ["64:ff9b::/64", "64:ff9b::1/96", "64:ff9b::", "nonsense"] {
            let cfg = OutboundConfig {
                mode: ProxyMode::Nat64,
                nat64_prefixes: vec![bad.into()],
                ..Default::default()
            };
            assert!(validate_outbound(&cfg).is_err(), "{bad:?} must be refused");
        }
        let good = OutboundConfig {
            mode: ProxyMode::Nat64,
            nat64_prefixes: vec!["64:ff9b::/96".into()],
            ..Default::default()
        };
        assert!(validate_outbound(&good).is_ok());
    }

    #[test]
    fn nat64_mode_with_no_prefix_is_allowed_because_a_default_exists() {
        // Unlike Proxy IP, NAT64 has a well-known prefix to fall back on, so an
        // empty list is a complete config rather than an unset one.
        let cfg = OutboundConfig { mode: ProxyMode::Nat64, ..Default::default() };
        assert!(validate_outbound(&cfg).is_ok());
    }

    #[test]
    fn proxy_ip_mode_without_candidates_is_refused_rather_than_saved_as_a_no_op() {
        let cfg = OutboundConfig { mode: ProxyMode::ProxyIp, ..Default::default() };
        assert!(validate_outbound(&cfg).is_err());
    }

    #[test]
    fn unused_lists_are_still_validated() {
        // Off mode with a malformed leftover entry: refused, because the entry
        // becomes live the moment the mode changes and the operator would not
        // be told then.
        let cfg = OutboundConfig {
            mode: ProxyMode::Off,
            proxy_candidates: vec!["127.0.0.1".into()],
            ..Default::default()
        };
        assert!(validate_outbound(&cfg).is_err());
    }

    #[test]
    fn the_entry_count_is_bounded() {
        let cfg = OutboundConfig {
            mode: ProxyMode::ProxyIp,
            proxy_candidates: (0..=MAX_OUTBOUND_ENTRIES)
                .map(|i| format!("198.51.100.{}", i % 200))
                .collect(),
            ..Default::default()
        };
        assert!(validate_outbound(&cfg).is_err());
    }
}
