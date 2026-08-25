//! Opening outbound connections.
//!
//! Small on purpose: this is the only place the project reaches out to an
//! arbitrary destination supplied by a peer, so the checks that belong here
//! should be visible in one screen rather than scattered.
//!
//! # What the runtime refuses
//!
//! The Workers runtime blocks outbound TCP to Cloudflare's own address ranges,
//! to private and loopback addresses, and to port 25. Those refusals surface
//! as opaque errors well after the fact, so [`Target::is_locally_rejectable`]
//! catches the cases visible from here first and turns them into a clear
//! decision. Domains cannot be pre-checked because resolution happens inside
//! `connect()` — that residual gap is the runtime's own guard to close, and it
//! does.
//!
//! There is no UDP path here and there cannot be: the runtime exposes no
//! datagram API at all.

use crate::protocol::Target;

/// Why an outbound connection was not attempted or did not succeed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectError {
    /// Destination is one this runtime will not dial. Refused before any
    /// syscall, so it costs nothing and leaks nothing.
    Forbidden,
    /// The runtime declined or the peer was unreachable.
    Failed(String),
}

impl core::fmt::Display for ConnectError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Forbidden => f.write_str("destination not permitted"),
            Self::Failed(e) => write!(f, "connect failed: {e}"),
        }
    }
}

/// Whether a destination is worth attempting at all.
///
/// Split out from the connect call so it can be exercised on the host, where
/// there is no runtime to dial with.
#[must_use]
pub fn is_permitted(target: &Target) -> bool {
    !target.is_locally_rejectable()
}

#[cfg(target_arch = "wasm32")]
mod imp {
    use super::{is_permitted, ConnectError};
    use crate::protocol::Target;
    use crate::relay::outbound::DialPlan;
    use worker::{Socket, SecureTransport};

    /// Dial `target` over plain TCP.
    ///
    /// TLS to the destination is not started here. Whatever is being tunnelled
    /// supplies its own encryption end to end, and terminating a second TLS
    /// session at this hop would both cost a handshake and give this Worker
    /// sight of plaintext it has no business seeing.
    ///
    /// # Errors
    /// [`ConnectError::Forbidden`] when the destination is one the runtime
    /// refuses, or [`ConnectError::Failed`] when the dial itself fails.
    pub fn open(target: &Target) -> Result<Socket, ConnectError> {
        if !is_permitted(target) {
            return Err(ConnectError::Forbidden);
        }
        let host = match &target.host {
            crate::protocol::Host::Domain(d) => d.to_string(),
            crate::protocol::Host::Ip(ip) => ip.to_string(),
        };
        Socket::builder()
            // Let the destination's FIN through rather than tearing the whole
            // socket down on it. Half-close is normal for HTTP/1.1 and for
            // anything that signals end-of-request by shutting down its write
            // side; collapsing it would truncate the response.
            .allow_half_open(true)
            .secure_transport(SecureTransport::Off)
            .connect(host, target.port)
            .map_err(|e| ConnectError::Failed(e.to_string()))
    }

    /// Try each candidate in a dial plan until one actually connects.
    ///
    /// # Why this awaits `opened()` and `open()` does not
    ///
    /// `Socket::connect()` on this runtime is lazy: it hands back a socket
    /// before the TCP handshake has been attempted, and a dial to a dead or
    /// refused address still returns `Ok`. The handshake result only surfaces
    /// at `opened().await`. A fallback loop built on `open()` alone therefore
    /// always "succeeds" on the first candidate and never falls through — the
    /// feature would look wired up and do nothing.
    ///
    /// # Why the single-candidate case is special-cased
    ///
    /// In `Off` mode the plan holds exactly one entry. Awaiting `opened()`
    /// there would introduce a handshake wait the pre-feature path did not
    /// have, and there is no second candidate to fall back to, so the result
    /// could not change any decision. That path returns the lazy socket
    /// untouched and stays behaviourally identical to calling [`open`]
    /// directly. Every caller already awaits the handshake at its own first
    /// read or write.
    ///
    /// # Errors
    /// The error from the last candidate attempted, so the caller sees the
    /// most relevant failure rather than the first.
    pub async fn open_with_plan(plan: &DialPlan) -> Result<Socket, ConnectError> {
        use futures_util::future::Either;
        // A candidate that accepts the dial but never completes its handshake
        // would otherwise hold the session — and on the free tier, real quota —
        // for as long as the runtime lets a socket sit half-open. Five seconds
        // covers every healthy round trip; a blackholed candidate costs at most
        // HANDSHAKE_TIMEOUT_SECS per attempt instead of an unbounded hang.
        const HANDSHAKE_TIMEOUT_SECS: u64 = 5;

        if let [only] = plan.candidates.as_slice() {
            return open(only);
        }

        let mut last_err = ConnectError::Failed("no candidates".into());
        for candidate in &plan.candidates {
            match open(candidate) {
                // A candidate that dials but never completes its handshake is
                // not a working route. Verify before committing to it.
                Ok(sock) => {
                    // `opened` borrows the socket, so the select's pinned
                    // future must be dropped before the socket can move out
                    // on success. Scoping the whole select does that; the
                    // verdict is a plain enum by the time it is matched.
                    let handshook = {
                        match futures_util::future::select(
                            Box::pin(sock.opened()),
                            Box::pin(gloo_timers::future::sleep(std::time::Duration::from_secs(
                                HANDSHAKE_TIMEOUT_SECS,
                            ))),
                        )
                        .await
                        {
                            Either::Left((Ok(_), _)) => Ok(()),
                            Either::Left((Err(e), _)) => Err(e.to_string()),
                            // The timer won. The half-open socket dies with
                            // this scope.
                            Either::Right(((), _)) => Err("handshake timed out".into()),
                        }
                    };
                    match handshook {
                        Ok(()) => return Ok(sock),
                        Err(msg) => last_err = ConnectError::Failed(msg),
                    }
                }
                Err(e) => last_err = e,
            }
        }
        Err(last_err)
    }
}

#[cfg(target_arch = "wasm32")]
pub use imp::{open, open_with_plan};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::Host;

    fn t(addr: &str, port: u16) -> Target {
        addr.parse::<std::net::IpAddr>().map_or_else(
            |_| Target { host: Host::Domain(addr.into()), port },
            |ip| Target { host: Host::Ip(ip), port },
        )
    }

    #[test]
    fn refuses_destinations_the_runtime_blocks() {
        for (addr, port) in [
            ("127.0.0.1", 443),
            ("10.0.0.5", 443),
            ("192.168.1.1", 443),
            ("169.254.169.254", 80), // cloud metadata endpoint
            ("::1", 443),
            ("example.com", 25),     // SMTP is blocked regardless of host
        ] {
            assert!(!is_permitted(&t(addr, port)), "{addr}:{port} must be refused");
        }
    }

    #[test]
    fn permits_ordinary_public_destinations() {
        for (addr, port) in [("93.184.216.34", 443), ("example.com", 443), ("example.com", 8080)] {
            assert!(is_permitted(&t(addr, port)), "{addr}:{port} should be allowed");
        }
    }

    #[test]
    fn error_messages_do_not_leak_the_destination() {
        // A refusal must not echo where the peer was trying to reach; logs of
        // these are a record of who connected where.
        let e = ConnectError::Forbidden.to_string();
        assert!(!e.contains("127.0.0.1"));
        assert_eq!(e, "destination not permitted");
    }
}
