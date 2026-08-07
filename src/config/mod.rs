//! The unified configuration model and the rules that keep it honest.
//!
//! [`model`] defines a node once, in terms that are not specific to any core.
//! [`conflicts`] answers the question every other panel in this space leaves
//! unanswered: given this node and a chosen target, what actually works, what
//! silently will not, and why.

pub mod conflicts;
pub mod env;
pub mod model;

pub use conflicts::{check, Finding, Severity};
pub use env::{credentials_from_env, UserLists};
pub use model::{
    ClientTarget, Core, Endpoint, Flow, Mux, Node, Protocol, RealitySettings, Security, SsMethod,
    TlsSettings, Transport, VmessCipher, XhttpMode,
};
