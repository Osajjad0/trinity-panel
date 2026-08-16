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
}

impl Default for Settings {
    fn default() -> Self {
        Self { version: VERSION, nodes: Vec::new(), outbound: OutboundConfig::default() }
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

        Self { version: VERSION, nodes, outbound: OutboundConfig::default() }
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
        let s = Settings::derive_from_env(&deployment());
        let json = s.to_json().expect("serialises");
        assert_eq!(Settings::parse(&json).expect("parses"), s);
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
