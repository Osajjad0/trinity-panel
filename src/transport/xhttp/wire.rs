//! XHTTP request classification and padding validation.
//!
//! Pure functions over request metadata. No I/O, no session state, no
//! allocation on the classification path. Everything here is derived from
//! Xray's `transport/internet/splithttp` server implementation, because there
//! is no field-level specification published for XHTTP — the upstream docs
//! page is a stub that redirects to a discussion thread.
//!
//! # The three modes, on the wire
//!
//! ```text
//! packet-up   downlink  GET  <prefix>/<session>
//!             uplink    POST <prefix>/<session>/<seq>     seq from 0, reordered
//!
//! stream-up   downlink  GET  <prefix>/<session>
//!             uplink    POST <prefix>/<session>           one unbounded body
//!
//! stream-one  both      POST <prefix>                     no session at all
//! ```
//!
//! # Fingerprint characteristics
//!
//! `packet-up` looks like a browser doing a long-poll plus a series of small
//! form posts — an extremely common shape. It is the only mode that needs no
//! duplex support anywhere in the path, which is why it is the default here.
//! Its cost is one HTTP request per uplink chunk, which is charged against the
//! account's daily request quota rather than against bandwidth.
//!
//! `stream-one` is a single long-lived POST. Cheaper and lower-latency, but a
//! multi-minute POST with a slowly-trickling body is a much rarer shape, and
//! it requires true full duplex — see `docs/research/phase-0-report.md` §4.

use core::fmt;

/// Longest session identifier accepted.
///
/// Session ids arrive in the URL from an unauthenticated peer and become keys
/// in a lookup table. Bounding the length keeps a flood of junk sessions from
/// turning into unbounded key storage. Xray's own generator emits 16–32
/// characters.
const MAX_SESSION_LEN: usize = 64;

/// Upper bound on the sequence number.
///
/// At the default 1 MB per post this is far more data than a Worker will ever
/// carry on one session, and it keeps a malicious `seq` from being used to
/// force a huge sparse reorder buffer.
const MAX_SEQ: u64 = 1 << 32;

/// A validated session identifier.
///
/// Borrowed from the request path rather than copied; it is only promoted to
/// an owned key once a session is actually created.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionId<'a>(&'a str);

impl<'a> SessionId<'a> {
    /// Accept only characters Xray's own session tables can emit.
    ///
    /// Rejecting anything else means a session id can never contain a path
    /// separator, a percent-escape, or a NUL, so it cannot be used to confuse
    /// whatever the id is later interpolated into.
    fn parse(s: &'a str) -> Option<Self> {
        if s.is_empty() || s.len() > MAX_SESSION_LEN {
            return None;
        }
        if s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
            Some(Self(s))
        } else {
            None
        }
    }

    #[must_use]
    pub const fn as_str(&self) -> &'a str {
        self.0
    }
}

impl fmt::Display for SessionId<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

/// What a given request is asking for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Class<'a> {
    /// CORS/browser-dialer preflight. Answer `200` immediately.
    Preflight,
    /// The long-lived downlink. Response body streams to the client.
    Downlink { session: SessionId<'a> },
    /// A `stream-one` request: request body is the uplink, response body is
    /// the downlink, on one request. Requires full duplex.
    StreamOne,
    /// One ordered chunk of uplink data.
    PacketUp { session: SessionId<'a>, seq: u64 },
    /// The single unbounded uplink body of `stream-up`.
    StreamUp { session: SessionId<'a> },
    /// Not addressed to us. The caller serves the decoy page — never a 404
    /// that differs from what the decoy would return for any other path.
    NotOurs,
}

/// Classify a request from its method and path.
///
/// Mirrors Xray's server-side discrimination exactly:
///
/// ```text
/// GET    -> uplink if a seq component is present, else downlink
/// other  -> uplink
/// then   uplink + session + seq  -> packet-up
///          uplink + session      -> stream-up
///          no session            -> stream-one / downlink
/// ```
///
/// `prefix` is the configured base path, with or without a trailing slash.
#[must_use]
pub fn classify<'a>(method: &str, path: &'a str, prefix: &str) -> Class<'a> {
    // Shared with the router rather than reimplemented. An earlier inline copy
    // here lacked the empty-prefix guard, so a deployment with `XHTTP_PATH`
    // unset matched every path and routed the whole internet at its Durable
    // Objects instead of at the decoy.
    let Some(rest) = crate::path::strip(path, prefix) else {
        return Class::NotOurs;
    };

    if method.eq_ignore_ascii_case("OPTIONS") {
        return Class::Preflight;
    }

    let mut parts = rest.split('/').filter(|s| !s.is_empty());
    let session_raw = parts.next();
    let seq_raw = parts.next();
    // A third component means the client is not speaking XHTTP to us.
    if parts.next().is_some() {
        return Class::NotOurs;
    }

    let is_get = method.eq_ignore_ascii_case("GET");

    match (session_raw, seq_raw) {
        // No session at all: stream-one, or a downlink probe.
        (None, _) => {
            if is_get {
                Class::NotOurs
            } else {
                Class::StreamOne
            }
        }
        (Some(s), None) => {
            let Some(session) = SessionId::parse(s) else {
                return Class::NotOurs;
            };
            if is_get {
                Class::Downlink { session }
            } else {
                Class::StreamUp { session }
            }
        }
        (Some(s), Some(q)) => {
            let Some(session) = SessionId::parse(s) else {
                return Class::NotOurs;
            };
            let Ok(seq) = q.parse::<u64>() else {
                return Class::NotOurs;
            };
            if seq >= MAX_SEQ {
                return Class::NotOurs;
            }
            Class::PacketUp { session, seq }
        }
    }
}

/// Inclusive byte-length range that padding must fall within.
///
/// Xray's default is `100-1000` and padding cannot be disabled. Keeping the
/// default means our traffic shape matches every other XHTTP deployment rather
/// than standing out as the one with unusual padding bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PaddingRange {
    pub min: usize,
    pub max: usize,
}

impl Default for PaddingRange {
    fn default() -> Self {
        Self { min: 100, max: 1000 }
    }
}

/// Where the client was told to put its padding.
///
/// `QueryInHeader` is Xray's default: the full request URL is repeated in the
/// `Referer` header with `?x_padding=XXXX…` appended. Putting it there rather
/// than on the real query string avoids triggering a CORS preflight from
/// browser-based dialers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PaddingPlacement {
    #[default]
    QueryInHeader,
    Query,
    Header,
    Cookie,
}

/// Padding configuration, mirroring Xray's `xPadding*` fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaddingConfig {
    pub range: PaddingRange,
    pub placement: PaddingPlacement,
    /// Query/cookie parameter name. Xray's default is `x_padding`.
    pub key: String,
    /// Header name used by `Header` placement. Xray's default is `X-Padding`.
    pub header: String,
}

impl Default for PaddingConfig {
    fn default() -> Self {
        Self {
            range: PaddingRange::default(),
            placement: PaddingPlacement::default(),
            key: "x_padding".into(),
            header: "X-Padding".into(),
        }
    }
}

/// Why padding validation failed. Every variant maps to `400`, deliberately
/// indistinguishable from the others.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaddingError {
    Missing,
    OutOfRange,
}

/// Extract the padding value's length from wherever it was placed.
///
/// `lookup` resolves a header name to its value; taking it as a closure keeps
/// this module free of any dependency on the runtime's header type, so the
/// whole thing is testable on the host.
fn padding_len<'a, F>(cfg: &PaddingConfig, url_query: &str, lookup: F) -> Option<usize>
where
    F: Fn(&str) -> Option<&'a str>,
{
    let from_query = |q: &str| -> Option<usize> {
        q.split('&')
            .find_map(|kv| kv.strip_prefix(&cfg.key).and_then(|r| r.strip_prefix('=')))
            .map(str::len)
    };

    match cfg.placement {
        PaddingPlacement::Query => from_query(url_query),
        PaddingPlacement::QueryInHeader => {
            let referer = lookup("Referer")?;
            let q = referer.split_once('?').map(|(_, q)| q)?;
            from_query(q)
        }
        PaddingPlacement::Header => lookup(&cfg.header).map(str::len),
        PaddingPlacement::Cookie => {
            let cookies = lookup("Cookie")?;
            cookies.split(';').find_map(|kv| {
                kv.trim_start()
                    .strip_prefix(&cfg.key)
                    .and_then(|r| r.strip_prefix('='))
                    .map(str::len)
            })
        }
    }
}

/// Validate that padding is present and within the configured range.
///
/// Xray's server returns `400` when the length falls outside its own range, so
/// matching that behaviour keeps us indistinguishable from a stock XHTTP
/// origin under active probing.
///
/// # Errors
/// [`PaddingError`] when absent or out of range.
pub fn validate_padding<'a, F>(
    cfg: &PaddingConfig,
    url_query: &str,
    lookup: F,
) -> Result<(), PaddingError>
where
    F: Fn(&str) -> Option<&'a str>,
{
    let len = padding_len(cfg, url_query, lookup).ok_or(PaddingError::Missing)?;
    if len < cfg.range.min || len > cfg.range.max {
        return Err(PaddingError::OutOfRange);
    }
    Ok(())
}

/// Headers that must accompany a downlink response.
///
/// `X-Accel-Buffering: no` and `Cache-Control: no-store` stop intermediaries
/// buffering the stream. The `text/event-stream` content type makes the
/// response look like Server-Sent Events, which middleboxes are already
/// trained not to buffer — that is why it is the default, and why disabling it
/// costs streaming reliability.
#[must_use]
pub fn downlink_headers(sse: bool) -> &'static [(&'static str, &'static str)] {
    if sse {
        &[
            ("X-Accel-Buffering", "no"),
            ("Cache-Control", "no-store"),
            ("Content-Type", "text/event-stream"),
        ]
    } else {
        &[("X-Accel-Buffering", "no"), ("Cache-Control", "no-store")]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const P: &str = "/abc123";

    fn sid(s: &str) -> SessionId<'_> {
        SessionId::parse(s).expect("valid session id")
    }

    #[test]
    fn classifies_the_three_modes() {
        assert_eq!(
            classify("GET", "/abc123/sess01", P),
            Class::Downlink { session: sid("sess01") }
        );
        assert_eq!(
            classify("POST", "/abc123/sess01/0", P),
            Class::PacketUp { session: sid("sess01"), seq: 0 }
        );
        assert_eq!(
            classify("POST", "/abc123/sess01", P),
            Class::StreamUp { session: sid("sess01") }
        );
        assert_eq!(classify("POST", "/abc123", P), Class::StreamOne);
        assert_eq!(classify("OPTIONS", "/abc123/sess01", P), Class::Preflight);
    }

    #[test]
    fn get_with_seq_is_an_uplink_not_a_downlink() {
        // Xray allows GET to carry uplink data when a seq is present. Reading
        // this as a downlink would open a second stream per session.
        assert_eq!(
            classify("GET", "/abc123/sess01/7", P),
            Class::PacketUp { session: sid("sess01"), seq: 7 }
        );
    }

    #[test]
    fn prefix_must_match_on_a_path_boundary() {
        assert_eq!(classify("GET", "/abc123456/sess01", P), Class::NotOurs);
        assert_eq!(classify("GET", "/other/sess01", P), Class::NotOurs);
        assert_eq!(classify("GET", "/", P), Class::NotOurs);
    }

    #[test]
    fn an_unconfigured_prefix_claims_nothing() {
        // With XHTTP_PATH unset or "/", every request must fall through to the
        // decoy. Matching everything here would point the whole internet at a
        // Durable Object.
        for prefix in ["", "/"] {
            for path in ["/", "/anything", "/a/b", "/sess01"] {
                assert_eq!(
                    classify("GET", path, prefix),
                    Class::NotOurs,
                    "prefix {prefix:?} path {path:?}"
                );
                assert_eq!(classify("POST", path, prefix), Class::NotOurs);
            }
        }
    }

    #[test]
    fn tolerates_trailing_slash_in_configured_prefix() {
        assert_eq!(
            classify("GET", "/abc123/sess01", "/abc123/"),
            Class::Downlink { session: sid("sess01") }
        );
    }

    #[test]
    fn rejects_hostile_session_ids_and_extra_components() {
        for path in [
            "/abc123/../etc",
            "/abc123/sess%2f01",
            "/abc123/sess01/0/extra",
            "/abc123/a.b",
        ] {
            assert_eq!(classify("POST", path, P), Class::NotOurs, "{path}");
        }
        let long = format!("/abc123/{}", "a".repeat(MAX_SESSION_LEN + 1));
        assert_eq!(classify("GET", &long, P), Class::NotOurs);
    }

    #[test]
    fn rejects_non_numeric_and_oversized_seq() {
        assert_eq!(classify("POST", "/abc123/s/abc", P), Class::NotOurs);
        assert_eq!(classify("POST", "/abc123/s/-1", P), Class::NotOurs);
        let big = format!("/abc123/s/{}", u64::MAX);
        assert_eq!(classify("POST", &big, P), Class::NotOurs);
    }

    #[test]
    fn validates_padding_from_the_referer_by_default() {
        let cfg = PaddingConfig::default();
        let pad = "X".repeat(200);
        let referer = format!("https://example.com/abc123/s?x_padding={pad}");
        let ok = validate_padding(&cfg, "", |h| {
            h.eq_ignore_ascii_case("Referer").then_some(referer.as_str())
        });
        assert_eq!(ok, Ok(()));
    }

    #[test]
    fn rejects_padding_outside_the_configured_range() {
        let cfg = PaddingConfig::default();
        for n in [10usize, 5000] {
            let referer = format!("https://e.com/p?x_padding={}", "X".repeat(n));
            assert_eq!(
                validate_padding(&cfg, "", |_| Some(referer.as_str())),
                Err(PaddingError::OutOfRange),
                "length {n} should be refused"
            );
        }
        assert_eq!(
            validate_padding(&cfg, "", |_| None::<&str>),
            Err(PaddingError::Missing)
        );
    }

    #[test]
    fn honours_alternate_padding_placements() {
        let pad = "X".repeat(150);

        let q = PaddingConfig { placement: PaddingPlacement::Query, ..Default::default() };
        let query = format!("x_padding={pad}");
        assert_eq!(validate_padding(&q, &query, |_| None::<&str>), Ok(()));

        let h = PaddingConfig { placement: PaddingPlacement::Header, ..Default::default() };
        assert_eq!(
            validate_padding(&h, "", |n| (n == "X-Padding").then_some(pad.as_str())),
            Ok(())
        );

        let c = PaddingConfig { placement: PaddingPlacement::Cookie, ..Default::default() };
        let cookie = format!("a=1; x_padding={pad}; b=2");
        assert_eq!(
            validate_padding(&c, "", |n| (n == "Cookie").then_some(cookie.as_str())),
            Ok(())
        );
    }

    #[test]
    fn downlink_headers_defeat_intermediary_buffering() {
        let h = downlink_headers(true);
        assert!(h.contains(&("X-Accel-Buffering", "no")));
        assert!(h.contains(&("Cache-Control", "no-store")));
        assert!(h.contains(&("Content-Type", "text/event-stream")));
        assert_eq!(downlink_headers(false).len(), 2);
    }

    #[test]
    fn classification_never_panics() {
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        let alphabet = b"/abc123-_.%\0 \x7f";
        for _ in 0..4000 {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            let len = (seed % 48) as usize;
            let path: String = (0..len)
                .map(|i| alphabet[((seed >> (i % 60)) as usize) % alphabet.len()] as char)
                .collect();
            for m in ["GET", "POST", "OPTIONS", "PUT", ""] {
                let _ = classify(m, &path, P);
            }
        }
    }
}
