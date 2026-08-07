//! Request routing.
//!
//! Pure decision logic: given a method, path and a small amount of request
//! metadata, decide what this request is. No I/O, so it tests on the host.
//!
//! # The property that matters
//!
//! Anything not positively identified as ours resolves to [`Route::Decoy`],
//! and the decoy response must be **byte-identical** regardless of why it was
//! reached. A scanner that can tell "wrong password" from "no such path" from
//! "bad padding" learns that something is here worth attacking. That is why
//! there is no `NotFound` variant and no error route: every negative outcome
//! is the same outcome.
//!
//! This is also why path prefixes must be unguessable. A prefix of `/vless`
//! is found by the first dictionary scan; a random one is not, and the decoy
//! makes scanning uninformative rather than merely slow.

use crate::transport::xhttp::{self, wire::Class};

/// Where a request should be handled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Route<'a> {
    /// An XHTTP request, already classified into its mode.
    Xhttp(Class<'a>),
    /// A WebSocket upgrade on the configured path.
    WebSocket,
    /// The admin panel UI or its API. The path after the prefix is carried
    /// through so the panel can dispatch its own sub-routes.
    Panel { rest: &'a str },
    /// A subscription download. `rest` selects client target and format.
    Subscription { rest: &'a str },
    /// The duplex self-test, used to decide whether the streaming XHTTP modes
    /// are usable on this deployment rather than guessing.
    DuplexProbe,
    /// Outbound connectivity self-test: dial a host, write, read, report.
    ///
    /// Exists because a failed outbound connection and a silent destination
    /// are indistinguishable from the relay's point of view — both surface as
    /// a read that never yields. This isolates the socket from the session
    /// machinery so the two can be told apart.
    ConnectProbe,
    /// Everything else, including every failure. Serves the decoy page.
    Decoy,
}

/// Path prefixes for the routes we serve. All are operator-configured and
/// should be random; the defaults here are placeholders that the setup wizard
/// replaces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Routes {
    pub xhttp: String,
    /// `None` disables the WebSocket transport entirely, which is the default.
    /// Enabling it is opt-in because it is the most heavily classified
    /// transport in this space and shares a hostname's fate with XHTTP.
    pub websocket: Option<String>,
    pub panel: String,
    pub subscription: String,
}

impl Routes {
    /// Whether any two prefixes overlap such that one shadows another.
    ///
    /// Checked at startup rather than per request. An operator who sets the
    /// panel prefix to a prefix of the XHTTP one would otherwise find the
    /// transport intermittently answering with HTML, which is close to
    /// impossible to diagnose from the client side.
    #[must_use]
    pub fn shadowing_conflict(&self) -> Option<(&'static str, &'static str)> {
        let mut named: Vec<(&'static str, &str)> = vec![
            ("xhttp", self.xhttp.as_str()),
            ("panel", self.panel.as_str()),
            ("subscription", self.subscription.as_str()),
        ];
        if let Some(ws) = &self.websocket {
            named.push(("websocket", ws.as_str()));
        }
        for (i, (an, a)) in named.iter().enumerate() {
            for (bn, b) in named.iter().skip(i + 1) {
                // `covers` already returns true for equal prefixes, since the
                // remainder is empty and that satisfies the boundary rule.
                if crate::path::covers(a, b) || crate::path::covers(b, a) {
                    return Some((an, bn));
                }
            }
        }
        None
    }
}

/// Decide what a request is.
///
/// `is_upgrade` is whether the request carries `Upgrade: websocket`. It is
/// evaluated before path matching because it is the one signal that cannot be
/// forged into a different transport: the runtime will only hand back a
/// WebSocket for a request that actually asked for one.
#[must_use]
pub fn route<'a>(method: &str, path: &'a str, is_upgrade: bool, routes: &Routes) -> Route<'a> {
    if is_upgrade {
        // A WebSocket upgrade is only ever a WebSocket. If it arrives while
        // the transport is disabled, or on the wrong path, it is a probe.
        return match &routes.websocket {
            Some(p) if crate::path::covers(p, path) => Route::WebSocket,
            _ => Route::Decoy,
        };
    }

    if let Some(rest) = crate::path::strip(path, &routes.panel) {
        return Route::Panel { rest };
    }
    if let Some(rest) = crate::path::strip(path, &routes.subscription) {
        return Route::Subscription { rest };
    }

    // The probe lives under the XHTTP prefix so it is not separately
    // discoverable, and so it exercises the same path the transport uses.
    match crate::path::strip(path, &routes.xhttp) {
        Some("__duplex_probe") => return Route::DuplexProbe,
        Some("__connect_probe") => return Route::ConnectProbe,
        _ => {}
    }

    match xhttp::classify(method, path, &routes.xhttp) {
        Class::NotOurs => Route::Decoy,
        other => Route::Xhttp(other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn routes() -> Routes {
        Routes {
            xhttp: "/x7f3a".into(),
            websocket: None,
            panel: "/p9c2e".into(),
            subscription: "/s4b1d".into(),
        }
    }

    #[test]
    fn routes_xhttp_downlink_and_uplink() {
        let r = routes();
        assert!(matches!(
            route("GET", "/x7f3a/sess1", false, &r),
            Route::Xhttp(Class::Downlink { .. })
        ));
        assert!(matches!(
            route("POST", "/x7f3a/sess1/0", false, &r),
            Route::Xhttp(Class::PacketUp { .. })
        ));
    }

    #[test]
    fn routes_panel_and_subscription_with_remainder() {
        let r = routes();
        assert_eq!(route("GET", "/p9c2e/api/nodes", false, &r), Route::Panel { rest: "api/nodes" });
        assert_eq!(route("GET", "/p9c2e", false, &r), Route::Panel { rest: "" });
        assert_eq!(
            route("GET", "/s4b1d/hiddify.json", false, &r),
            Route::Subscription { rest: "hiddify.json" }
        );
    }

    #[test]
    fn duplex_probe_hides_under_the_xhttp_prefix() {
        let r = routes();
        assert_eq!(route("GET", "/x7f3a/__duplex_probe", false, &r), Route::DuplexProbe);
        // And is not reachable at the root, where it would be discoverable.
        assert_eq!(route("GET", "/__duplex_probe", false, &r), Route::Decoy);
    }

    #[test]
    fn websocket_is_refused_while_disabled() {
        let r = routes();
        assert_eq!(route("GET", "/x7f3a/sess1", true, &r), Route::Decoy);
        assert_eq!(route("GET", "/anything", true, &r), Route::Decoy);
    }

    #[test]
    fn websocket_routes_only_on_its_own_prefix_when_enabled() {
        let mut r = routes();
        r.websocket = Some("/w2a8c".into());
        assert_eq!(route("GET", "/w2a8c", true, &r), Route::WebSocket);
        assert_eq!(route("GET", "/w2a8c/sub", true, &r), Route::WebSocket);
        // Right path, but no upgrade header: not a WebSocket.
        assert_ne!(route("GET", "/w2a8c", false, &r), Route::WebSocket);
        // Upgrade header on the XHTTP path is a probe, not a transport.
        assert_eq!(route("GET", "/x7f3a/sess1", true, &r), Route::Decoy);
    }

    #[test]
    fn everything_unrecognised_reaches_the_decoy() {
        let r = routes();
        for p in [
            "/", "/index.html", "/vless", "/api", "/x7f3a_notours", "/p9c2extra",
            "/../etc/passwd", "/wp-login.php", "",
        ] {
            assert_eq!(route("GET", p, false, &r), Route::Decoy, "path {p:?}");
        }
    }

    #[test]
    fn prefixes_match_only_on_component_boundaries() {
        let r = routes();
        // A prefix must not match a longer path segment that merely starts
        // with it, or the panel leaks onto unrelated URLs.
        assert_eq!(route("GET", "/p9c2extra/api", false, &r), Route::Decoy);
        assert_eq!(route("GET", "/x7f3abc/sess", false, &r), Route::Decoy);
    }

    #[test]
    fn detects_prefixes_that_would_shadow_each_other() {
        let mut r = routes();
        assert_eq!(r.shadowing_conflict(), None);

        r.panel = "/x7f3a".into();
        assert!(r.shadowing_conflict().is_some(), "identical prefixes must be caught");

        r.panel = "/x7f3a/admin".into();
        assert!(r.shadowing_conflict().is_some(), "nested prefixes must be caught");

        r.panel = "/x7f3admin".into();
        assert_eq!(r.shadowing_conflict(), None, "shared text is not shadowing");
    }

    #[test]
    fn routing_never_panics() {
        let r = routes();
        let mut seed = 0x1234_5678_9abc_def0u64;
        let alphabet = b"/x7f3ap9c2es4b1d._%\0 ";
        for _ in 0..4000 {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            let len = (seed % 40) as usize;
            let path: String = (0..len)
                .map(|i| alphabet[((seed >> (i % 58)) as usize) % alphabet.len()] as char)
                .collect();
            for m in ["GET", "POST", "OPTIONS", ""] {
                let _ = route(m, &path, seed & 1 == 0, &r);
            }
        }
    }
}
