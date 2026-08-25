//! Config translation — one node in, three cores out.
//!
//! This is the project's reason to exist. Every other panel in this space
//! either concatenates a string per output format by hand or delegates to an
//! external subscription converter; both approaches make it impossible to say
//! what was lost on the way out, because nothing ever modelled it.
//!
//! Here, a [`Node`] is expressed once and each core's emitter renders it. When
//! a field cannot survive the trip, the emitter records a [`Dropped`] entry
//! saying which field and why, and the panel shows it. **Silently emitting a
//! config that omits what the user asked for is the failure mode this module
//! exists to prevent** — it is how a user ends up with a node that connects
//! but does not behave as configured, with nothing anywhere to explain it.
//!
//! # Contract for an emitter
//!
//! 1. Never emit a configuration that [`crate::config::conflicts`] rates
//!    `Fatal` or `Untranslatable` for the target. Refuse instead.
//! 2. Record every field that was dropped or altered, with a reason a
//!    non-expert can act on.
//! 3. Emit the field spellings the *current* core release accepts. Where old
//!    and new spellings both parse, prefer whichever reaches more installed
//!    clients, and say why in a comment.

use crate::config::model::{ClientTarget, Core, Node};
use crate::config::{check, Severity};

pub mod mihomo;
pub mod singbox;
pub mod util;
pub mod xray;

pub use mihomo::Mihomo;
pub use singbox::SingBox;
pub use xray::XrayEmitter;

/// Serialisation format of an emitted config.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Json,
    Yaml,
}

impl Format {
    #[must_use]
    pub const fn extension(self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Yaml => "yaml",
        }
    }

    #[must_use]
    pub const fn content_type(self) -> &'static str {
        match self {
            Self::Json => "application/json; charset=utf-8",
            // No registered type for YAML that clients reliably accept, and
            // text/plain is what every subscription consumer expects.
            Self::Yaml => "text/plain; charset=utf-8",
        }
    }
}

/// Something the user configured that did not survive translation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dropped {
    /// Stable field identifier, matching the names used by
    /// [`crate::config::conflicts`] so the UI can highlight the same control.
    pub field: &'static str,
    /// Why, in plain language. Shown to the user verbatim.
    pub reason: String,
}

impl Dropped {
    pub fn new(field: &'static str, reason: impl Into<String>) -> Self {
        Self { field, reason: reason.into() }
    }
}

/// A rendered configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Emitted {
    pub config: String,
    pub format: Format,
    /// Empty when the node translated with full fidelity.
    pub dropped: Vec<Dropped>,
}

/// Why a node could not be rendered at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EmitError {
    /// The node is invalid or inexpressible for this target. Carries the
    /// user-facing explanations from the conflict engine.
    Refused(Vec<String>),
    /// Serialisation failed. Should not happen for a validated node; kept so
    /// the emitter never has to unwrap.
    Serialisation(String),
}

impl core::fmt::Display for EmitError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Refused(reasons) => {
                f.write_str("cannot be expressed for this client: ")?;
                f.write_str(&reasons.join("; "))
            }
            Self::Serialisation(e) => write!(f, "could not serialise config: {e}"),
        }
    }
}

/// Renders a [`Node`] for one core.
pub trait Emit {
    /// Which core this emitter targets.
    fn core(&self) -> Core;

    /// Render `node` for `target`.
    ///
    /// # Errors
    /// [`EmitError::Refused`] when the node cannot work for this target.
    fn emit(&self, node: &Node, target: ClientTarget) -> Result<Emitted, EmitError>;
}

/// Gate a node before rendering.
///
/// Every emitter calls this first. Centralising it means a new emitter cannot
/// forget the check and quietly ship a config the conflict engine already
/// knows is broken — the failure mode being guarded against is a *silent* one,
/// so it must not depend on each emitter remembering.
///
/// Returns the non-blocking findings as [`Dropped`] entries, so degradations
/// the user should know about are carried into the output rather than lost.
///
/// # Errors
/// [`EmitError::Refused`] if any finding blocks selection or is untranslatable.
pub fn gate(node: &Node, target: ClientTarget, enhanced: bool) -> Result<Vec<Dropped>, EmitError> {
    let findings = check(node, target, enhanced);

    let blocking: Vec<String> = findings
        .iter()
        .filter(|f| f.severity.blocks_selection() || f.severity == Severity::Untranslatable)
        .map(|f| format!("{} — {}", f.summary, f.detail))
        .collect();

    if !blocking.is_empty() {
        return Err(EmitError::Refused(blocking));
    }

    Ok(findings
        .into_iter()
        .filter(|f| f.severity == Severity::Degraded)
        .map(|f| Dropped { field: f.field, reason: f.detail })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::model::{
        Endpoint, Flow, Mux, Protocol, Security, TlsSettings, Transport, XhttpMode,
    };

    fn xhttp_node() -> Node {
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

    #[test]
    fn gate_allows_a_clean_node() {
        assert_eq!(gate(&xhttp_node(), ClientTarget::V2rayN, false), Ok(Vec::new()));
    }

    #[test]
    fn gate_refuses_an_untranslatable_node_with_a_readable_reason() {
        let err = gate(&xhttp_node(), ClientTarget::SingBoxUpstream, false)
            .expect_err("XHTTP cannot be expressed in upstream sing-box");
        let EmitError::Refused(reasons) = err else {
            panic!("expected refusal");
        };
        assert!(!reasons.is_empty());
        // The explanation must be actionable, not just "unsupported".
        assert!(
            reasons.iter().any(|r| r.contains("Hiddify") || r.contains("Karing")),
            "refusal should point at a client that does work: {reasons:?}"
        );
    }

    #[test]
    fn gate_refuses_reality_behind_a_cdn() {
        let mut n = xhttp_node();
        n.security = Security::Reality(crate::config::model::RealitySettings::default());
        assert!(matches!(
            gate(&n, ClientTarget::V2rayN, false),
            Err(EmitError::Refused(_))
        ));
    }

    #[test]
    fn gate_carries_degradations_through_instead_of_discarding_them() {
        let mut n = xhttp_node();
        // WebSocket is servable but carries a fingerprint warning.
        n.transport = Transport::WebSocket {
            path: "/w".into(),
            host: None,
            heartbeat_secs: 30,
        };
        let dropped = gate(&n, ClientTarget::V2rayN, false).expect("websocket is allowed");
        assert!(
            !dropped.is_empty(),
            "a degradation the user should know about must reach the output"
        );
        assert!(dropped.iter().all(|d| d.reason.len() > 40));
    }

    #[test]
    fn format_metadata_is_what_clients_expect() {
        assert_eq!(Format::Json.extension(), "json");
        assert_eq!(Format::Yaml.extension(), "yaml");
        assert!(Format::Json.content_type().starts_with("application/json"));
        assert!(Format::Yaml.content_type().starts_with("text/plain"));
    }
}
