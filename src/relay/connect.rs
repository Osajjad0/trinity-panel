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

/// Await one candidate's handshake, bounded by an injected timeout future.
///
/// Shared by every arm of [`imp::open_with_plan`] so a blackholed destination
/// costs a bounded wait whether or not a fallback exists to try next. Generic
/// over both futures: the runtime passes its timer, host tests pass synthetic
/// ones, and neither side needs a real socket.
// Host-only builds reach this through the tests below; the wasm build reaches
// it from `imp`. Either way exactly one side uses it per compilation.
#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
async fn verify_or_timeout<F, T, S, E>(opened: F, budget: T) -> Result<(), ConnectError>
where
    F: core::future::Future<Output = Result<S, E>>,
    E: core::fmt::Display,
    T: core::future::Future<Output = ()>,
{
    match futures_util::future::select(Box::pin(opened), Box::pin(budget)).await {
        futures_util::future::Either::Left((Ok(_), _)) => Ok(()),
        futures_util::future::Either::Left((Err(e), _)) => {
            Err(ConnectError::Failed(e.to_string()))
        }
        futures_util::future::Either::Right(((), _)) => {
            Err(ConnectError::Failed("handshake timed out".into()))
        }
    }
}

#[cfg(target_arch = "wasm32")]
mod imp {
    use super::{is_permitted, ConnectError};
    use crate::protocol::Target;
    use crate::relay::outbound::DialPlan;
    use worker::{Socket, SecureTransport};

    /// Seconds a candidate gets to finish its TCP handshake before it is
    /// declared blackholed. Five covers every healthy round trip; a dead
    /// candidate costs this much per attempt instead of an unbounded hang.
    const HANDSHAKE_TIMEOUT_SECS: u64 = 5;

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
    /// In `Off` mode the plan holds exactly one entry, so there is nothing to
    /// fall back to and the loop below would buy nothing. That path dials and
    /// verifies the handshake exactly like one iteration of the loop — same
    /// bound, same failure reporting — and returns on the first (only)
    /// candidate. Success is behaviourally identical to calling [`open`] and
    /// awaiting the first read or write; the difference is that a blackholed
    /// dial now fails within [`HANDSHAKE_TIMEOUT_SECS`] instead of pinning
    /// the session until some later I/O notices.
    ///
    /// # Errors
    /// The error from the last candidate attempted, so the caller sees the
    /// most relevant failure rather than the first.
    pub async fn open_with_plan(plan: &DialPlan) -> Result<Socket, ConnectError> {
        if let [only] = plan.candidates.as_slice() {
            let sock = open(only)?;
            let handshook = {
                super::verify_or_timeout(
                    sock.opened(),
                    gloo_timers::future::sleep(std::time::Duration::from_secs(
                        HANDSHAKE_TIMEOUT_SECS,
                    )),
                )
                .await
            };
            handshook?;
            return Ok(sock);
        }

        let mut last_err = ConnectError::Failed("no candidates".into());
        for candidate in &plan.candidates {
            match open(candidate) {
                // A candidate that dials but never completes its handshake is
                // not a working route. Verify before committing to it.
                Ok(sock) => {
                    // `opened` borrows the socket, so the select's pinned
                    // future must be dropped before the socket can move out
                    // on success. Scoping the whole call does that; the
                    // verdict is a plain Result by the time it is matched.
                    let handshook = {
                        super::verify_or_timeout(
                            sock.opened(),
                            gloo_timers::future::sleep(std::time::Duration::from_secs(
                                HANDSHAKE_TIMEOUT_SECS,
                            )),
                        )
                        .await
                    };
                    match handshook {
                        Ok(()) => return Ok(sock),
                        Err(e) => last_err = e,
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

    mod handshake_bound {
        use super::*;

        /// A dial whose handshake never completes — the blackhole case.
        struct Never;
        impl core::future::Future for Never {
            type Output = Result<(), std::io::Error>;
            fn poll(
                self: Pin<&mut Self>,
                _: &mut Context<'_>,
            ) -> Poll<Self::Output> {
                Poll::Pending
            }
        }

        #[tokio::test]
        async fn blackholed_handshake_fails_at_the_budget() {
            let verdict =
                verify_or_timeout(Never, core::future::ready(())).await;
            assert_eq!(
                verdict,
                Err(ConnectError::Failed("handshake timed out".into()))
            );
        }

        #[tokio::test]
        async fn healthy_handshake_passes_under_an_open_budget() {
            let verdict = verify_or_timeout(
                core::future::ready(Ok::<(), std::io::Error>(())),
                std::future::pending::<()>(),
            )
            .await;
            assert_eq!(verdict, Ok(()));
        }

        #[tokio::test]
        async fn refused_handshake_surfaces_its_own_error() {
            let verdict = verify_or_timeout(
                core::future::ready(Err::<(), _>(std::io::Error::from(
                    std::io::ErrorKind::ConnectionRefused,
                ))),
                std::future::pending::<()>(),
            )
            .await;
            assert!(matches!(verdict, Err(ConnectError::Failed(_))));
            assert!(verdict
                .unwrap_err()
                .to_string()
                .contains("connection refused"));
        }

        #[tokio::test]
        async fn budget_winning_is_not_confused_with_success() {
            // Both resolve on the first poll; select must report Left.
            let verdict = verify_or_timeout(
                core::future::ready(Ok::<(), std::io::Error>(())),
                core::future::ready(()),
            )
            .await;
            assert_eq!(verdict, Ok(()));
        }

        use super::{verify_or_timeout, ConnectError};
        use core::pin::Pin;
        use core::task::{Context, Poll};
    }
}
