//! What the panel persists, and what it falls back to.
//!
//! # Why there is a fallback at all
//!
//! A deployment that has just been created has nothing in KV. The obvious
//! behaviour — show an empty panel and ask the operator to build a node — is
//! also the behaviour that makes "a working config in under a minute"
//! impossible, because the operator has to retype values the deployment
//! already knows: its own hostname, its own path, its own credentials.
//!
//! So an empty store is not an empty panel. [`Settings::derive_from_env`]
//! synthesises one node per enabled protocol from the bindings the Worker was
//! deployed with, and the subscription endpoints serve those immediately. The
//! operator edits from a working starting point rather than a blank form.
//!
//! # Why credentials live in bindings and not here
//!
//! The Durable Object reads its credentials from secret bindings on the
//! request path. Moving them into KV would put a storage round trip in front
//! of every new session, and would mean a panel bug could lock every user out
//! of a working deployment. So the panel *reads* credentials to build client
//! configs and does not own them: adding a user is a redeploy, not a KV write.
//!
//! That is a real limitation and it is stated rather than hidden. What the
//! panel does own is everything client-side — hostnames, SNI, transport
//! parameters, per-core options, chains — which is where the configuration
//! effort actually is.

use serde::{Deserialize, Serialize};

use crate::config::model::{
    Endpoint, Flow, Mux, Node, Protocol, Security, SsMethod, TlsSettings, Transport, VmessCipher,
    XhttpMode,
};
use crate::relay::outbound::OutboundConfig;

/// KV key holding the settings document.
pub const KEY: &str = "panel:settings";

/// Schema version of the stored document.
///
/// Bumped when a field changes meaning. Stored explicitly so a future version
/// can migrate rather than silently misread an older document — a settings
/// file that half-loads is worse than one that is recognised as old.
pub const VERSION: u32 = 1;

/// Shared client-configuration preferences (the panel's "Common" section).
///
/// None of this is read by the proxy data path: these fields shape the
/// *generated client configs* (Xray / sing-box / Mihomo) and nothing else, so
/// the common case — a relay session — pays zero storage reads for them. They
/// ride the existing settings document and its save path.
///
/// Empty strings mean "use the built-in default", which keeps stored documents
/// forward- and backward-compatible without migrations.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommonSettings {
    /// Primary resolver written to the generated DNS block (IP, DoH or DoT
    /// URL, or `localhost`). Empty = the built-in default.
    #[serde(default)]
    pub routing_dns: String,
    /// Second resolver dedicated to sanctioned domains; generated configs add
    /// a domain-filtered rule for it. Empty = no bypass entry.
    #[serde(default)]
    pub bypass_dns: String,
    /// DNS-over-HTTPS primary (URL). Empty = the built-in AdGuard DoH.
    #[serde(default)]
    pub secure_doh: String,
    /// Xray fakedns (client-side). Off by default: opt-in, can confuse apps
    /// that pin IPs.
    #[serde(default)]
    pub fakedns: bool,
    /// IPv6 preference for client-side resolution. `Auto` preserves today's
    /// behaviour.
    #[serde(default)]
    pub ipv6: Ipv6Mode,
    /// Expose the client's inbound to LAN peers (`0.0.0.0` listen). Off keeps
    /// today's loopback-only inbound.
    #[serde(default)]
    pub lan_access: bool,
    /// Xray/sing-box log level for generated configs. Empty = `warning`.
    #[serde(default)]
    pub log_level: String,
}

/// IPv6 handling in generated client configs.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum Ipv6Mode {
    /// Leave the client core's own strategy in place (`AsIs` / untouched).
    #[default]
    Auto,
    /// Client resolves and prefers IPv6 where the system has it.
    Prefer,
    /// Force IPv4 resolution only.
    Off,
}

/// Everything the panel persists.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Settings {
    pub version: u32,
    pub nodes: Vec<Node>,
    /// Outbound routing configuration (Proxy IP / NAT64).
    /// Defaults to Off when absent from stored JSON.
    #[serde(default)]
    pub outbound: OutboundConfig,
    /// When true, share links and configs include client-side reachability
    /// hints (e.g. `fp=chrome`) that improve TLS compatibility on restricted
    /// networks. Defaults to false when absent from stored JSON.
    #[serde(default)]
    pub enhanced_reachability: bool,
    /// Optimistic-concurrency revision, bumped on every successful save.
    /// A client may send the revision it loaded as `expectedRev`; a mismatch
    /// means another tab (or session) saved first and the edit is refused
    /// rather than silently overwriting it. Defaults to 0 for documents that
    /// predate the field, so the very first save after an upgrade always
    /// succeeds.
    #[serde(default)]
    pub rev: u32,
    /// Shared client-config preferences. Absent in pre-1.9.7 documents; serde
    /// default fills it, so old documents load unchanged.
    #[serde(default)]
    pub common: CommonSettings,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            version: VERSION,
            nodes: Vec::new(),
            outbound: OutboundConfig::default(),
            enhanced_reachability: false,
            rev: 0,
            common: CommonSettings::default(),
        }
    }
}

impl CommonSettings {
    /// Built-in DoH primary when none is configured.
    pub const DEFAULT_DOH: &'static str = "https://dns.adguard-dns.com/dns-query";
    /// Built-in routing resolver when none is configured.
    pub const DEFAULT_ROUTING_DNS: &'static str = "8.8.8.8";
    /// Known-good preset resolvers (plain IP form).
    pub const PRESETS: &'static [&'static str] = &[
        "8.8.8.8",
        "8.8.4.4",
        "1.1.1.1",
        "1.0.0.1",
        "94.140.14.14",
        "94.140.15.15",
        "localhost",
    ];
    /// Known-good DoH presets.
    pub const DOH_PRESETS: &'static [&'static str] = &[
        "https://dns.adguard-dns.com/dns-query",
        "https://cloudflare-dns.com/dns-query",
        "https://dns.google/dns-query",
    ];

    /// Normalise in place: trim whitespace, drop empty strings to "", clamp
    /// unknown log levels. Idempotent.
    pub fn normalize(&mut self) {
        let trim = |s: &mut String| {
            *s = s.trim().to_owned();
        };
        trim(&mut self.routing_dns);
        trim(&mut self.bypass_dns);
        trim(&mut self.secure_doh);
        trim(&mut self.log_level);
        if !matches!(
            self.log_level.as_str(),
            "" | "debug" | "info" | "warning" | "error" | "none"
        ) {
            self.log_level.clear();
        }
    }

    /// Validate after normalisation. `Err` carries a user-presentable reason
    /// naming the offending field. Empty values are always valid (defaults).
    pub fn validate(&self) -> Result<(), String> {
        if !self.routing_dns.is_empty() {
            Self::validate_resolver(&self.routing_dns, "Routing DNS")?;
        }
        if !self.bypass_dns.is_empty() {
            Self::validate_resolver(&self.bypass_dns, "Bypass DNS")?;
        }
        if !self.secure_doh.is_empty() {
            Self::validate_doh(&self.secure_doh)?;
        }
        Ok(())
    }

    /// IP literal, `localhost`, or a `dns://`-style URL (DoH/DoT accepted by
    /// the cores). Rejects anything else with a precise message.
    fn validate_resolver(value: &str, label: &str) -> Result<(), String> {
        if value.eq_ignore_ascii_case("localhost") {
            return Ok(());
        }
        if value.parse::<std::net::IpAddr>().is_ok() {
            return Ok(());
        }
        if (value.starts_with("https://") || value.starts_with("hickory://") || value.starts_with("tcp://") || value.starts_with("udp://"))
            && value.len() > 8
        {
            return Ok(());
        }
        Err(format!("{label}: not an IP, `localhost`, or a valid DoH/DoT/TCP/UDP DNS URL"))
    }

    /// DoH URLs must be https and carry a host; cores require both.
    fn validate_doh(value: &str) -> Result<(), String> {
        let rest = value
            .strip_prefix("https://")
            .ok_or("Secure DNS Upstream: must be an https:// DoH URL")?;
        let host = rest.split('/').next().unwrap_or_default();
        if host.is_empty() || host.contains('@') {
            return Err("Secure DNS Upstream: URL has no usable host".to_owned());
        }
        Ok(())
    }
}

/// The bindings a node can be derived from.
///
/// Borrowed rather than owned so the caller can pass values straight out of the
/// environment without a copy.
#[derive(Debug, Default, Clone, Copy)]
pub struct Deployment<'a> {
    /// Hostname the request arrived on, which is also the hostname a client
    /// must dial. Taken from the request rather than configured, so a custom
    /// domain works with no extra setup.
    pub host: &'a str,
    pub xhttp_path: &'a str,
    pub ws_path: &'a str,
    pub vless_users: &'a str,
    pub trojan_users: &'a str,
    pub vmess_users: &'a str,
    pub shadowsocks_users: &'a str,
}

impl Settings {
    /// Build the default node set from what the Worker was deployed with.
    ///
    /// One node per enabled protocol, all sharing the deployment's hostname,
    /// path and transport. Only the first credential of each list is used: the
    /// rest are other people's, and a subscription that handed every user
    /// everyone else's credentials would be a serious leak.
    #[must_use]
    pub fn derive_from_env(deployment: &Deployment<'_>) -> Self {
        let mut nodes = Vec::new();
        if deployment.host.is_empty() || deployment.xhttp_path.is_empty() {
            return Self::default();
        }

        let xhttp_transport = Transport::Xhttp {
            mode: XhttpMode::PacketUp,
            path: deployment.xhttp_path.to_owned(),
            host: Some(deployment.host.to_owned()),
        };
        // The edge terminates TLS, so SNI is the hostname and ALPN is decided
        // by the shared emitter defaults rather than guessed here.
        let security = Security::Tls(TlsSettings {
            sni: Some(deployment.host.to_owned()),
            ..TlsSettings::default()
        });
        let server = Endpoint { address: deployment.host.to_owned(), port: 443 };

        if let Some(uuid) = first(deployment.vless_users) {
            nodes.push(Node {
                tag: format!("{} VLESS", deployment.host),
                server: server.clone(),
                protocol: Protocol::Vless { uuid: uuid.to_owned(), flow: Flow::None },
                transport: xhttp_transport.clone(),
                security: security.clone(),
                mux: Mux::default(),
                chain_via: None,
                worker_served: true,
            });
        }
        if let Some(password) = first(deployment.trojan_users) {
            // Trojan rides XHTTP packet-up like VLESS. This is the transport
            // the Worker's relay actually serves end-to-end (verified live);
            // a WebSocket variant is kept only as an optional fallback and is
            // not the default node, because the WS relay path gives EOF.
            nodes.push(Node {
                tag: format!("{} Trojan", deployment.host),
                server: server.clone(),
                protocol: Protocol::Trojan { password: password.to_owned() },
                transport: xhttp_transport.clone(),
                security: security.clone(),
                mux: Mux::default(),
                chain_via: None,
                worker_served: true,
            });
        }
        if let Some(uuid) = first(deployment.vmess_users) {
            nodes.push(Node {
                tag: format!("{} VMess", deployment.host),
                server: server.clone(),
                protocol: Protocol::Vmess { uuid: uuid.to_owned(), cipher: VmessCipher::Auto },
                transport: xhttp_transport.clone(),
                security: security.clone(),
                mux: Mux::default(),
                chain_via: None,
                worker_served: true,
            });
        }
        if let Some(entry) = first(deployment.shadowsocks_users) {
            // Entries are `method:base64key`; a malformed one yields no node
            // rather than a node that cannot possibly connect.
            if let Some((method, password)) = entry.split_once(':') {
                if let Some(method) = ss_method(method) {
                    nodes.push(Node {
                        tag: format!("{} Shadowsocks", deployment.host),
                        server: server.clone(),
                        protocol: Protocol::Shadowsocks { method, password: password.to_owned() },
                        transport: xhttp_transport.clone(),
                        security: security.clone(),
                        mux: Mux::default(),
                        chain_via: None,
                        worker_served: true,
                    });
                }
            }
        }

        Self {
            version: VERSION,
            nodes,
            outbound: OutboundConfig::default(),
            enhanced_reachability: false,
            rev: 0,
            common: CommonSettings::default(),
        }
    }

    /// Parse a stored document, rejecting one from a future schema.
    ///
    /// # Errors
    /// The serde message, when the document is malformed or too new.
    pub fn parse(raw: &str) -> Result<Self, String> {
        let settings: Self = serde_json::from_str(raw).map_err(|e| e.to_string())?;
        if settings.version > VERSION {
            return Err(format!(
                "settings were written by a newer version ({}, this build understands {VERSION})",
                settings.version
            ));
        }
        Ok(settings)
    }

    /// Serialise for storage.
    ///
    /// # Errors
    /// The serde message, which should not occur for a well-formed document.
    pub fn to_json(&self) -> Result<String, String> {
        serde_json::to_string(self).map_err(|e| e.to_string())
    }

    /// The node with this tag, if any.
    #[must_use]
    pub fn node(&self, tag: &str) -> Option<&Node> {
        self.nodes.iter().find(|n| n.tag == tag)
    }
}

/// First entry of a separated list, trimmed.
///
/// Accepts the same separators as the credential loader, because these values
/// come from the same bindings.
fn first(raw: &str) -> Option<&str> {
    raw.split([',', '\n', ';']).map(str::trim).find(|s| !s.is_empty())
}

/// Map a Shadowsocks method name to the model's enum.
fn ss_method(name: &str) -> Option<SsMethod> {
    match name.trim() {
        "2022-blake3-aes-128-gcm" => Some(SsMethod::Blake3Aes128Gcm),
        "2022-blake3-aes-256-gcm" => Some(SsMethod::Blake3Aes256Gcm),
        "2022-blake3-chacha20-poly1305" => Some(SsMethod::Blake3Chacha20Poly1305),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOST: &str = "example.workers.dev";
    const UUID: &str = "01234567-89ab-cdef-0123-456789abcdef";
    const SS: &str = "2022-blake3-aes-256-gcm:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
 fn deployment() -> Deployment<'static> {
 Deployment {
        host: HOST,
        xhttp_path: "/abc123",
        ws_path: "",
        vless_users: UUID,
        trojan_users: "hunter2",
        vmess_users: UUID,
        shadowsocks_users: SS,
    }
 }


    #[test]
    fn a_fresh_deployment_yields_one_node_per_enabled_protocol() {
        // The property that makes the panel useful before anything is
        // configured: no empty state to fill in by hand.
        let s = Settings::derive_from_env(&deployment());
        assert_eq!(s.nodes.len(), 4);
        let names: Vec<&str> = s.nodes.iter().map(|n| n.protocol.name()).collect();
        assert_eq!(names, ["VLESS", "Trojan", "VMess", "Shadowsocks"]);
        for n in &s.nodes {
            assert!(n.worker_served);
            assert_eq!(n.server.port, 443);
            assert!(matches!(n.transport, Transport::Xhttp { .. }));
        }
    }

    #[test]
    fn all_four_protocols_ride_xhttp_packet_up() {
        // Trojan rides XHTTP like VLESS: the Worker's XHTTP relay is the path
        // verified to work end-to-end. Empirically the WebSocket relay gives
        // EOF on this runtime, so there must be exactly one transport for all
        // four protocols and it must be XHTTP, not a per-protocol WS split.
        let d = Deployment { ws_path: "/ws", ..deployment() };
        let s = Settings::derive_from_env(&d);
        assert_eq!(s.nodes.len(), 4);
        let names: Vec<&str> = s.nodes.iter().map(|n| n.protocol.name()).collect();
        assert_eq!(names, ["VLESS", "Trojan", "VMess", "Shadowsocks"]);
        for n in &s.nodes {
            assert!(n.worker_served);
            assert_eq!(n.server.port, 443);
            assert!(matches!(n.transport, Transport::Xhttp { mode: XhttpMode::PacketUp, .. }),
                "{} must use XHTTP packet-up, got {:?}", n.protocol.name(), n.transport);
        }
    }

  #[test]
    fn a_disabled_protocol_produces_no_node() {
        let d = Deployment { trojan_users: "", vmess_users: "", ..deployment() };
        let s = Settings::derive_from_env(&d);
        assert_eq!(s.nodes.len(), 2);
        assert!(s.nodes.iter().all(|n| n.protocol.name() != "Trojan"));
    }

    #[test]
    fn only_the_first_credential_of_each_list_is_used() {
        // A subscription built from every credential would hand each user
        // everyone else's, which is a credential leak rather than a feature.
        let second = "fedcba98-7654-3210-fedc-ba9876543210";
        let d = Deployment { vless_users: &format!("{UUID},{second}"), ..deployment() };
        let s = Settings::derive_from_env(&d);
        let vless: Vec<&Node> = s.nodes.iter().filter(|n| n.protocol.name() == "VLESS").collect();
        assert_eq!(vless.len(), 1);
        assert!(!format!("{:?}", vless[0].protocol).contains(second));
    }

    #[test]
    fn an_unconfigured_deployment_yields_nothing_rather_than_a_broken_node() {
        for d in [
            Deployment { host: "", ..deployment() },
            Deployment { xhttp_path: "", ..deployment() },
        ] {
            assert!(Settings::derive_from_env(&d).nodes.is_empty());
        }
    }

    #[test]
    fn a_malformed_shadowsocks_entry_is_skipped_not_guessed() {
        for bad in ["nonsense", "aes-128-gcm:AAAA", "2022-blake3-aes-256-gcm"] {
            let d = Deployment { shadowsocks_users: bad, ..deployment() };
            let s = Settings::derive_from_env(&d);
            assert!(s.nodes.iter().all(|n| n.protocol.name() != "Shadowsocks"), "{bad}");
        }
    }

    #[test]
    fn settings_round_trip_through_storage() {
        let mut s = Settings::derive_from_env(&deployment());
        s.rev = 7;
        let json = s.to_json().expect("serialises");
        assert_eq!(Settings::parse(&json).expect("parses"), s);
        // The wire name is camelCase, like every other field here.
        assert!(json.contains("\"rev\":7"));
    }

    #[test]
    fn a_document_without_a_revision_loads_as_revision_zero() {
        // Documents written before optimistic concurrency existed must keep
        // loading, and their first save must succeed.
        let raw = r#"{"version":1,"nodes":[]}"#;
        let s = Settings::parse(raw).expect("parses");
        assert_eq!(s.rev, 0);
    }

    #[test]
    fn a_document_from_a_newer_schema_is_refused_rather_than_misread() {
        // Half-loading a settings file is worse than recognising it as too new.
        let raw = format!(r#"{{"version":{},"nodes":[]}}"#, VERSION + 1);
        assert!(Settings::parse(&raw).is_err());
    }

    #[test]
    fn a_malformed_document_is_refused() {
        for bad in ["", "{", "null", r#"{"version":1}"#] {
            assert!(Settings::parse(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn nodes_are_addressable_by_tag() {
        let s = Settings::derive_from_env(&deployment());
        let tag = s.nodes[0].tag.clone();
        assert!(s.node(&tag).is_some());
        assert!(s.node("no such node").is_none());
    }
}

#[cfg(test)]
mod common_tests {
    use super::*;

    #[test]
    fn normalize_trims_and_clamps() {
        let mut c = CommonSettings {
            routing_dns: "  1.1.1.1  ".into(),
            secure_doh: " https://example.com/dns-query ".into(),
            log_level: "verbose".into(), // unknown -> ""
            ..Default::default()
        };
        c.normalize();
        assert_eq!(c.routing_dns, "1.1.1.1");
        assert_eq!(c.secure_doh, "https://example.com/dns-query");
        assert_eq!(c.log_level, "");
    }

    #[test]
    fn validation_accepts_every_documented_form() {
        for good in ["8.8.8.8", "94.140.14.14", "2001:4860:4860::8888", "localhost",
                     "https://dns.google/dns-query", "tcp://9.9.9.9:53"] {
            let c = CommonSettings { routing_dns: good.into(), ..Default::default() };
            assert!(c.validate().is_ok(), "{good} rejected");
        }
        for bad in ["dns.example", "8.8.8.8.8", "http://insecure/dns", ""] {
            if bad.is_empty() { continue; }
            let c = CommonSettings { routing_dns: bad.into(), ..Default::default() };
            assert!(c.validate().is_err(), "{bad} accepted");
        }
    }

    #[test]
    fn doh_validation_requires_https_with_host() {
        let ok = CommonSettings { secure_doh: "https://dns.adguard-dns.com/dns-query".into(), ..Default::default() };
        assert!(ok.validate().is_ok());
        let no_host = CommonSettings { secure_doh: "https:///dns-query".into(), ..Default::default() };
        assert!(no_host.validate().is_err());
        let plain = CommonSettings { secure_doh: "http://dns.example/query".into(), ..Default::default() };
        assert!(plain.validate().is_err());
    }

    #[test]
    fn defaults_are_production_safe() {
        let c = CommonSettings::default();
        assert!(!c.fakedns, "fakedns must stay opt-in");
        assert!(!c.lan_access, "LAN exposure must stay off by default");
        assert!(matches!(c.ipv6, Ipv6Mode::Auto));
        assert_eq!(c.log_level, "");
        assert_eq!(CommonSettings::DEFAULT_DOH, "https://dns.adguard-dns.com/dns-query");
    }
}
