//! Subscription rendering — turning nodes into something a client can import.
//!
//! Two shapes exist and both are needed. A **share link** is a single URI a
//! user pastes or scans; it is compact but can only express what the URI
//! conventions cover. A **full config** is the complete core configuration
//! from [`crate::translate`], which can express everything but has to be saved
//! as a file.
//!
//! Split into small pieces because the failure modes are different: encoding
//! bugs corrupt links silently, while format bugs are usually loud.

pub mod bundle;
pub mod encode;
pub mod qr;
pub mod uri;

pub use uri::to_uri;
