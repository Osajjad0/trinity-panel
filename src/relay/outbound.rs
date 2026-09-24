//! Outbound route resolution for Proxy IP and NAT64 fallback.
//!
//! This module sits between the protocol layer (which knows the *logical*
//! destination) and [`super::connect`] (which opens a socket to a *physical*
//! address). In `Off` mode it is a zero-cost passthrough — the dial plan
//! contains exactly one entry pointing at the original target, and no extra
//! allocation or lookup occurs.
//!
//! # Why this is not in `connect.rs`
//!
//! `connect.rs` is deliberately small: one function that dials and one guard
//! that refuses private addresses. Mixing retry logic, candidate rotation and
//! NAT64 synthesis into it would make the hot path harder to audit and the
//! off-mode path slower. Keeping them separate means `Off` stays byte-for-byte
//! identical to the pre-feature behaviour, and every alternative route is
//! visible in one place.
//!
//! # What "Proxy IP" actually means here
//!
//! A Proxy IP is an alternate *dial address*. The logical destination (the
//! host the client asked for, and the SNI/Host header presented to it) does
//! not change. Only the TCP connect target is replaced. This is the same
//! semantic as EdgeTunnel's proxy-IP and zizifn's relay address: the Worker
//! reaches a cooperating endpoint that forwards traffic to the real
//! destination, while TLS still validates against the original server name.
//!
//! # NAT64
//!
//! NAT64 is an address-construction mechanism, not a proxy. Given an IPv4
//! destination and a /96 prefix, it synthesises an IPv6 address that a
//! NAT64 gateway translates back to IPv4. Whether this bypasses any
//! particular Cloudflare restriction depends on the runtime environment and
//! must be verified empirically — this module does not claim it does.
//!
//! ## Domain destination limitation
//!
//! NAT64 synthesis requires a known IPv4 address. The Workers runtime does
//! not expose a DNS resolution API — `Socket::connect()` accepts hostnames
//! and resolves them internally, but the resolved addresses are never visible
//! to Worker code. This means NAT64 can only be applied when the client sends
//! an IPv4 literal as the destination (e.g. a VLESS header with address type
//! `0x01`). For domain destinations, NAT64 mode falls back to direct-only.
//! This is a hard runtime constraint, not an implementation gap.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::protocol::{Host, Target};

/// How the Worker should reach the logical destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ProxyMode {
    /// Dial the destination directly. Zero overhead.
    #[default]
    Off,
    /// Try configured proxy candidates before falling back.
    ProxyIp,
    /// Dial the verified catalog pool for the operator's location. The pool
    /// (healthy, scanner-verified endpoints) is supplied per session as the
    /// `generated` list of [`OutboundConfig::resolve_with_catalog`]; with an
    /// empty list Pool degrades to the same plan as ProxyIp/Off.
    Pool,
    /// Synthesise NAT64 addresses for IPv4 destinations.
    Nat64,
}

/// A resolved dial plan: one or more physical targets to try, in order.
///
/// The logical destination is carried alongside so callers can set SNI/Host
/// from it regardless of which physical address is dialed. In `Off` mode
/// there is exactly one entry and it equals the logical target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DialPlan {
    /// What the client asked for. Never mutated by this module.
    pub logical: Target,
    /// Physical addresses to attempt, in priority order.
    pub candidates: Vec<Target>,
}

impl DialPlan {
    /// Build a direct-only plan. This is the `Off` fast path.
    #[must_use]
    pub fn direct(target: Target) -> Self {
        Self { logical: target.clone(), candidates: vec![target] }
    }
}

/// Configuration for outbound route resolution.
///
/// Stored in KV alongside the rest of the panel settings. All fields have
/// safe defaults that produce `Off` behaviour when absent.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct OutboundConfig {
    pub mode: ProxyMode,
    /// Proxy IP candidates: IPv4 addresses or hostnames.
    /// Each entry is validated at parse time; invalid entries are dropped.
    pub proxy_candidates: Vec<String>,
    /// NAT64 prefixes (/96). Only the first valid prefix is used.
    pub nat64_prefixes: Vec<String>,
    /// Maximum proxy candidates to try before giving up.
    /// Clamped to `[1, MAX_PROXY_ATTEMPTS]`.
    pub max_proxy_attempts: u32,
    /// Whether verified catalog endpoints participate in the dial plan
    /// (appended behind the manual candidates). Legacy flag from the
    /// pre-Pool releases; Pool mode implies it.
    #[serde(default)]
    pub catalog_pool: bool,
    /// Operator's catalog location: empty, "AUTO", or a two-letter country
    /// code. Selects the pool; never rewritten at runtime.
    #[serde(default)]
    pub catalog_country: String,
    /// EXACT host:port candidates generated from the verified catalog
    /// (healthy-only). The only catalog input the dial path sees.
    #[serde(default)]
    pub verified_catalog_candidates: Vec<String>,
    /// Manual proxy candidate that always dials first among proxies.
    #[serde(default)]
    pub pinned_proxy: String,
}

impl Default for OutboundConfig {
    fn default() -> Self {
        Self {
            mode: ProxyMode::Off,
            proxy_candidates: Vec::new(),
            nat64_prefixes: Vec::new(),
            max_proxy_attempts: 3,
            catalog_pool: false,
            catalog_country: String::new(),
            verified_catalog_candidates: Vec::new(),
            pinned_proxy: String::new(),
        }
    }
}

/// Upper bound on proxy attempts. Prevents retry storms from misconfiguration.
const MAX_PROXY_ATTEMPTS: u32 = 8;

/// Default NAT64 prefix (RFC 6052 well-known prefix), pre-parsed.
/// Only used if no user-configured prefix is valid. Computed at compile time
/// so there is no runtime parse and no `expect` for clippy to object to.
const DEFAULT_NAT64_PREFIX: Ipv6Addr = Ipv6Addr::new(0x64, 0xff9b, 0, 0, 0, 0, 0, 0);

impl OutboundConfig {
    /// Resolve a logical target into a dial plan using this configuration.
    ///
    /// Pure function — no I/O, no async, fully testable on the host.
    #[must_use]
    pub fn resolve(&self, target: &Target) -> DialPlan {
        match self.mode {
            ProxyMode::Off => DialPlan::direct(target.clone()),
            ProxyMode::ProxyIp => self.resolve_proxy_ip(target),
            ProxyMode::Pool => self.resolve_proxy_ip(target),
            ProxyMode::Nat64 => self.resolve_nat64(target),
        }
    }

    /// Resolve with the catalog candidates the caller generated from the
    /// verified snapshot (healthy-only; the ONLY catalog input here).
    ///
    /// Order is fixed: direct first, then the manual candidates (with the
    /// manual pin first among them), then verified catalog entries — each
    /// keeping its own host:port, deduped by host+effective port against
    /// everything already in the plan, capped so the manual list can never
    /// be crowded out. An empty `generated` list degrades to plain
    /// `resolve`, for every mode.
    ///
    /// EXCEPTION — enforced location: Pool mode with a concrete country is
    /// the operator's explicit egress selection. The plan is the selected
    /// country's candidates ONLY (pin still first); the direct destination
    /// never enters the plan, so a working direct route cannot win over the
    /// chosen country. `AUTO`/empty country keep legacy direct-first.
    #[must_use]
    pub fn resolve_with_catalog(&self, target: &Target, generated: &[String]) -> DialPlan {
        if generated.is_empty() {
            return self.resolve(target);
        }
        if self.enforces_location() {
            return self.resolve_enforced(target, generated);
        }
        let mut plan = self.resolve(target);
        // Manual pin first among the proxies (its own entry stays; dedupe
        // below keeps the pin from reappearing as a catalog candidate).
        let pin = self.pinned_proxy.trim();
        if !pin.is_empty() {
            if let Some(pos) = plan.candidates[1..].iter().position(|c| {
                candidate_host(c).eq_ignore_ascii_case(pin)
            }) {
                let picked = plan.candidates.remove(1 + pos);
                plan.candidates.insert(1, picked);
            }
        }
        // Catalog entries keep their own source port; the pool itself is
        // capped at MAX_POOL_CANDIDATES (manual candidates are bounded
        // separately by max_proxy_attempts in resolve_proxy_ip).
        let mut appended = 0usize;
        for entry in generated {
            // Catalog entries keep their own source port.
            let Some(candidate) = parse_candidate(entry) else {
                continue;
            };
            // Dedupe by host + effective port against the whole plan: the
            // same host already dialable at this port adds nothing.
            if plan.candidates.iter().any(|c| {
                candidate_host(c) == candidate_host(&candidate) && c.port == candidate.port
            }) {
                continue;
            }
            plan.candidates.push(candidate);
            appended += 1;
            if appended >= crate::catalog::MAX_POOL_CANDIDATES {
                break;
            }
        }
        plan
    }

    /// Pool mode with a concrete (non-AUTO, non-empty) catalog country =
    /// the operator explicitly selected that egress location. Enforced.
    #[must_use]
    pub fn enforces_location(&self) -> bool {
        self.mode == ProxyMode::Pool && {
            let cc = self.catalog_country.trim();
            !cc.is_empty() && !cc.eq_ignore_ascii_case("AUTO") && cc.len() == 2
        }
    }

    /// The enforced-location plan: pinned proxy (if still present in the
    /// pool), then the selected country's verified candidates. No direct
    /// candidate — the session fails rather than silently leaving the
    /// selected country. Candidates keep catalog order (health ranking may
    /// reorder them, [`crate::relay::outbound_state::order_plan_ranked`]);
    /// nothing outside `generated` can appear.
    fn resolve_enforced(&self, target: &Target, generated: &[String]) -> DialPlan {
        let pin = self.pinned_proxy.trim();
        let mut candidates: Vec<Target> = Vec::with_capacity(generated.len() + 1);
        let mut appended = 0usize;
        for entry in generated {
            let Some(candidate) = parse_candidate(entry) else {
                continue;
            };
            // Dedupe by host+port: a pool listing the pin twice must not
            // dial it twice after promotion.
            let host = candidate_host(&candidate);
            if candidates
                .iter()
                .any(|c| candidate_host(c) == host && c.port == candidate.port)
            {
                continue;
            }
            candidates.push(candidate);
            appended += 1;
            if appended >= crate::catalog::MAX_POOL_CANDIDATES {
                break;
            }
        }
        if !pin.is_empty() {
            if let Some(idx) = candidates.iter().position(|c| {
                let host = candidate_host(c);
                host.eq_ignore_ascii_case(pin)
                    || format!("{host}:{}", c.port).eq_ignore_ascii_case(pin)
            }) {
                let pinned = candidates.remove(idx);
                candidates.insert(0, pinned);
            }
        }
        DialPlan { logical: target.clone(), candidates }
    }

    fn resolve_proxy_ip(&self, target: &Target) -> DialPlan {
        let port = target.port;
        let limit = self.max_proxy_attempts.clamp(1, MAX_PROXY_ATTEMPTS) as usize;
        let mut candidates = Vec::with_capacity(limit + 1);

        // Direct attempt first — if it works, no proxy needed.
        candidates.push(target.clone());

        for candidate in self.proxy_candidates.iter().take(limit) {
            let trimmed = candidate.trim();
            if trimmed.is_empty() {
                continue;
            }
            // Parse as IP or treat as hostname.
            let host = if let Ok(ip) = trimmed.parse::<IpAddr>() {
                Host::Ip(ip)
            } else {
                Host::Domain(trimmed.into())
            };
            candidates.push(Target { host, port });
        }

        DialPlan { logical: target.clone(), candidates }
    }

    fn resolve_nat64(&self, target: &Target) -> DialPlan {
        // NAT64 only applies to IPv4 destinations. A domain cannot be
        // synthesised without resolving it first, and resolution happens
        // inside connect() — we cannot do it here without adding a DNS
        // dependency. An IPv6 destination already has a native path.
        let v4 = match &target.host {
            Host::Ip(IpAddr::V4(v4)) => *v4,
            _ => return DialPlan::direct(target.clone()),
        };

        let prefix = self.first_valid_nat64_prefix();
        let synthetic = synthesize_nat64(prefix, v4);

        DialPlan {
            logical: target.clone(),
            candidates: vec![
                target.clone(),
                Target { host: Host::Ip(IpAddr::V6(synthetic)), port: target.port },
            ],
        }
    }

    /// Return the first valid /96 prefix from the configured list,
    /// falling back to the RFC 6052 well-known prefix.
    fn first_valid_nat64_prefix(&self) -> Ipv6Addr {
        for raw in &self.nat64_prefixes {
            if let Some(prefix) = parse_nat64_prefix(raw.trim()) {
                return prefix;
            }
        }
        // Fallback: well-known prefix. Valid by construction.
        DEFAULT_NAT64_PREFIX
    }
}

/// Parse a generated catalog candidate `host:port` into a dial target.
///
/// Accepts IPv4/IPv6 literals and hostnames; IPv6 must be bracketed
/// (`[2001:db8::1]:2053`). A bare host with no port is REJECTED — the caller
/// (panel save validation) turns that into a visible save error rather than
/// a silently ignored candidate.
#[must_use]
pub fn parse_candidate(s: &str) -> Option<Target> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    // Bracketed IPv6: [h]:p
    if let Some(rest) = s.strip_prefix('[') {
        let (h, p) = rest.split_once("]:")?;
        let ip: IpAddr = h.parse().ok()?;
        let port: u16 = p.parse().ok()?;
        return Some(Target { host: Host::Ip(ip), port });
    }
    // Bare IPv6 literal has no port separator it could own.
    if s.matches(':').count() > 1 {
        return None;
    }
    let (h, p) = s.rsplit_once(':')?;
    let port: u16 = p.parse().ok()?;
    let host = if let Ok(ip) = h.parse::<IpAddr>() {
        Host::Ip(ip)
    } else {
        Host::Domain(h.trim().into())
    };
    Some(Target { host, port })
}

/// Host string of a candidate, canonically cased for comparisons.
#[must_use]
fn candidate_host(t: &Target) -> String {
    match &t.host {
        Host::Ip(ip) => ip.to_string(),
        Host::Domain(d) => d.trim().to_ascii_lowercase(),
    }
}

/// Parse a NAT64 prefix string like `64:ff9b::/96` into its base IPv6 address.
///
/// Returns `None` for anything that is not a valid `/96` prefix.
#[must_use]
pub fn parse_nat64_prefix(s: &str) -> Option<Ipv6Addr> {
    let (addr_part, len_part) = s.split_once('/')?;
    if len_part != "96" {
        return None;
    }
    let addr: Ipv6Addr = addr_part.parse().ok()?;
    // A /96 prefix must have its last 32 bits clear.
    let octets = addr.octets();
    if octets[12..] != [0, 0, 0, 0] {
        return None;
    }
    Some(addr)
}

/// Synthesise a NAT64 IPv6 address from a /96 prefix and an IPv4 address.
///
/// The IPv4 address occupies the last 32 bits of the resulting address.
#[must_use]
pub fn synthesize_nat64(prefix: Ipv6Addr, v4: Ipv4Addr) -> Ipv6Addr {
    let mut octets = prefix.octets();
    let v4_octets = v4.octets();
    octets[12] = v4_octets[0];
    octets[13] = v4_octets[1];
    octets[14] = v4_octets[2];
    octets[15] = v4_octets[3];
    Ipv6Addr::from(octets)
}

/// Validate a proxy candidate string.
///
/// Accepts IPv4, IPv6, or a non-empty hostname. Rejects empty strings,
/// strings with whitespace, and strings containing path separators or ports.
#[must_use]
pub fn validate_proxy_candidate(s: &str) -> bool {
    let s = s.trim();
    if s.is_empty() || s.contains(['/', '\\', ':']) {
        return false;
    }
    // If it parses as an IP, it must not be private/loopback/etc.
    if let Ok(ip) = s.parse::<IpAddr>() {
        let t = Target { host: Host::Ip(ip), port: 443 };
        return !t.is_locally_rejectable();
    }
    // Otherwise treat as hostname — basic sanity.
    s.len() <= 253 && s.bytes().all(|b| b.is_ascii_graphic() && b != b'@')
}

/// Validate a NAT64 prefix string.
#[must_use]
pub fn validate_nat64_prefix(s: &str) -> bool {
    parse_nat64_prefix(s.trim()).is_some()
}

/// Extract an `OutboundConfig` from a raw settings JSON string.
///
/// Used by both the Worker entry point and the Durable Object to load the
/// outbound routing config from the same KV document the panel writes.
/// Returns the default (Off mode) if the JSON is malformed or the field is
/// absent — same safety net as the panel itself.
#[must_use]
pub fn from_settings_json(raw: &str) -> OutboundConfig {
    let settings: serde_json::Value = match serde_json::from_str(raw) {
        Ok(v) => v,
        Err(_) => return OutboundConfig::default(),
    };
    let Some(outbound) = settings.get("outbound") else {
        return OutboundConfig::default();
    };
    serde_json::from_value(outbound.clone()).unwrap_or_default()
}

/// Read the outbound config out of the panel's settings document in KV.
///
/// Every failure — no binding, no document, unreadable, malformed — yields the
/// default (`Off`), because a relay that refuses to dial because its optional
/// routing config could not be read is worse than one that dials directly.
#[cfg(target_arch = "wasm32")]
pub async fn load(env: &worker::Env) -> OutboundConfig {
    let Ok(kv) = env.kv("SETTINGS") else {
        return OutboundConfig::default();
    };
    match kv.get(crate::panel::store::KEY).text().await {
        Ok(Some(raw)) => from_settings_json(&raw),
        _ => OutboundConfig::default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(host: &str, port: u16) -> Target {
        host.parse::<IpAddr>().map_or_else(
            |_| Target { host: Host::Domain(host.into()), port },
            |ip| Target { host: Host::Ip(ip), port },
        )
    }

    // --- Off mode ---

    #[test]
    fn off_mode_produces_a_single_direct_candidate() {
        let cfg = OutboundConfig::default();
        let t = target("example.com", 443);
        let plan = cfg.resolve(&t);
        assert_eq!(plan.logical, t);
        assert_eq!(plan.candidates.len(), 1);
        assert_eq!(plan.candidates[0], t);
    }

    #[test]
    fn off_mode_is_identical_for_ip_and_domain_targets() {
        let cfg = OutboundConfig::default();
        for addr in ["example.com", "93.184.216.34", "::1"] {
            let t = target(addr, 443);
            let plan = cfg.resolve(&t);
            assert_eq!(plan.candidates, vec![t]);
        }
    }

    // --- Proxy IP mode ---

    #[test]
    fn proxy_ip_prepends_direct_then_appends_candidates() {
        let cfg = OutboundConfig {
            mode: ProxyMode::ProxyIp,
            proxy_candidates: vec!["203.0.113.10".into(), "proxy.example.com".into()],
            ..Default::default()
        };
        let t = target("example.com", 443);
        let plan = cfg.resolve(&t);
        assert_eq!(plan.logical, t);
        assert_eq!(plan.candidates.len(), 3);
        assert_eq!(plan.candidates[0], t); // direct first
        assert_eq!(plan.candidates[1].host, Host::Ip("203.0.113.10".parse().unwrap()));
        assert_eq!(plan.candidates[2].host, Host::Domain("proxy.example.com".into()));
        // Port preserved across all candidates.
        for c in &plan.candidates {
            assert_eq!(c.port, 443);
        }
    }

    #[test]
    fn proxy_ip_respects_max_attempts() {
        let cfg = OutboundConfig {
            mode: ProxyMode::ProxyIp,
            proxy_candidates: (0..10).map(|i| format!("198.51.100.{i}")).collect(),
            max_proxy_attempts: 2,
            ..Default::default()
        };
        let t = target("example.com", 443);
        let plan = cfg.resolve(&t);
        // 1 direct + 2 proxy = 3 total.
        assert_eq!(plan.candidates.len(), 3);
    }

    #[test]
    fn proxy_ip_skips_empty_candidates() {
        let cfg = OutboundConfig {
            mode: ProxyMode::ProxyIp,
            proxy_candidates: vec![String::new(), "  ".into(), "203.0.113.1".into()],
            ..Default::default()
        };
        let t = target("example.com", 443);
        let plan = cfg.resolve(&t);
        assert_eq!(plan.candidates.len(), 2); // direct + one valid
    }

    #[test]
    fn proxy_ip_with_no_candidates_falls_back_to_direct_only() {
        let cfg = OutboundConfig {
            mode: ProxyMode::ProxyIp,
            proxy_candidates: vec![],
            ..Default::default()
        };
        let t = target("example.com", 443);
        let plan = cfg.resolve(&t);
        assert_eq!(plan.candidates, vec![t]);
    }

    // --- Pool mode (verified catalog pool) ---

    fn gen(s: &str) -> Vec<String> {
        s.split(',').map(|x| x.trim().to_owned()).collect()
    }

    #[test]
    fn pool_mode_verified_candidates_flow_to_runtime() {
        let cfg = OutboundConfig {
            mode: ProxyMode::Pool,
            proxy_candidates: vec!["di.nscl.ir".into()],
            catalog_pool: true,
            verified_catalog_candidates: gen("91.187.93.166:443, 193.108.112.248:443"),
            ..Default::default()
        };
        let t = target("example.com", 443);
        let plan = cfg.resolve_with_catalog(&t, &cfg.verified_catalog_candidates);
        let hosts: Vec<String> = plan.candidates[1..].iter().map(|c| match &c.host {
            Host::Ip(ip) => format!("{ip}:{}", c.port),
            Host::Domain(d) => format!("{d}:{}", c.port),
        }).collect();
        assert_eq!(hosts, vec!["di.nscl.ir:443", "91.187.93.166:443", "193.108.112.248:443"]);
    }

    #[test]
    fn pool_mode_candidates_parse_host_port_and_dedupe() {
        let cfg = OutboundConfig {
            mode: ProxyMode::Pool,
            catalog_pool: true,
            verified_catalog_candidates: gen(
                "91.187.93.166:443, 91.187.93.166:8443, proxy.example.com:2053",
            ),
            ..Default::default()
        };
        let t = target("example.com", 443);
        let plan = cfg.resolve_with_catalog(&t, &cfg.verified_catalog_candidates);
        // Same host on two ports = two candidates (port preserved); no dup of host+port.
        let keys: Vec<String> = plan.candidates[1..].iter().map(|c| match &c.host {
            Host::Ip(ip) => format!("{ip}:{}", c.port),
            Host::Domain(d) => format!("{d}:{}", c.port),
        }).collect();
        assert_eq!(keys, vec!["91.187.93.166:443", "91.187.93.166:8443", "proxy.example.com:2053"]);
    }

    #[test]
    fn pool_mode_dedupes_against_configured_and_caps_at_eight() {
        let cfg = OutboundConfig {
            mode: ProxyMode::Pool,
            proxy_candidates: vec!["198.51.100.9".into()], // same host as pool[0]
            catalog_pool: true,
            ..Default::default()
        };
        let t = target("example.com", 443);
        let gen: Vec<_> = (0..12).map(|i| format!("198.51.100.{i}:443")).collect();
        let plan = cfg.resolve_with_catalog(&t, &gen);
        let hosts: Vec<_> = plan.candidates[1..].iter().map(|c| match &c.host {
            Host::Ip(ip) => ip.to_string(),
            Host::Domain(d) => d.to_string(),
        }).collect();
        assert_eq!(hosts.len(), 9); // 1 configured + 8 catalog max
        assert_eq!(hosts.iter().filter(|h| **h == "198.51.100.9").count(), 1); // deduped
    }

    #[test]
    fn catalog_pool_true_appends_behind_configured_and_direct() {
        let cfg = OutboundConfig {
            mode: ProxyMode::Pool,
            proxy_candidates: vec!["203.0.113.10".into()],
            catalog_pool: true,
            ..Default::default()
        };
        let t = target("example.com", 443);
        let gen = vec![
            "198.51.100.9:443".to_owned(),
            "proxy.example.com:8443".to_owned(),
        ];
        let plan = cfg.resolve_with_catalog(&t, &gen);
        assert_eq!(plan.candidates[0], t); // direct first, always
        assert_eq!(plan.candidates[1].host, Host::Ip("203.0.113.10".parse().unwrap()));
        // Catalog candidates keep their own source port.
        assert_eq!(plan.candidates[2].host, Host::Ip("198.51.100.9".parse().unwrap()));
        assert_eq!(plan.candidates[2].port, 443);
        assert_eq!(plan.candidates[3].host, Host::Domain("proxy.example.com".into()));
        assert_eq!(plan.candidates[3].port, 8443);
    }

    #[test]
    fn catalog_endpoints_keep_their_own_port() {
        // AZ fixture: one endpoint on 8443. It must NOT be rewritten to 443.
        // This fixture is an ENFORCED location (Pool + concrete country): the
        // direct candidate is not in the plan at all — candidates are only
        // the selected country's verified endpoints, in order.
        let cfg = OutboundConfig {
            mode: ProxyMode::Pool,
            proxy_candidates: vec!["203.0.113.10".into()],
            catalog_pool: true,
            catalog_country: "AZ".into(),
            ..Default::default()
        };
        let t = target("example.com", 443);
        let gen = vec!["180.149.44.124:8443".to_owned(), "85.185.86.111:2053".to_owned()];
        let plan = cfg.resolve_with_catalog(&t, &gen);
        assert_eq!(plan.candidates[0].port, 8443);
        assert_eq!(plan.candidates[1].port, 2053);
        // Enforcement keeps out the direct candidate AND the manual
        // candidate from another country (203.0.113.10 is a manual proxy,
        // not part of the AZ pool).
        assert!(!plan.candidates.iter().any(|c| candidate_host(c) == "203.0.113.10"));
        assert!(!plan.candidates.iter().any(|c| c.host == t.host && c.port == t.port));
        assert_eq!(plan.logical, t);
    }

    #[test]
    fn enforced_location_plan_is_pool_only_and_pin_leads() {
        // Pool + concrete country = enforced: no direct, pin first, pool order kept.
        let cfg = OutboundConfig {
            mode: ProxyMode::Pool,
            proxy_candidates: vec!["203.0.113.10".into()],
            catalog_pool: true,
            catalog_country: "DE".into(),
            pinned_proxy: "de-two.example:443".into(),
            ..Default::default()
        };
        let t = target("gemini.example", 443);
        let gen = vec![
            "de-one.example:443".to_owned(),
            "de-two.example:443".to_owned(),
            "198.51.100.9:443".to_owned(), // NOT the pin; stays behind
        ];
        let plan = cfg.resolve_with_catalog(&t, &gen);
        assert_eq!(plan.candidates.len(), 3);
        assert_eq!(plan.candidates[0].host, Host::Domain("de-two.example".into()));
        assert_eq!(plan.candidates[1].host, Host::Domain("de-one.example".into()));
        assert_eq!(plan.candidates[2].host, Host::Ip("198.51.100.9".parse().unwrap()));
        assert!(plan.candidates.iter().all(|c| c.host != t.host || c.port != t.port),
            "no direct candidate in an enforced plan");
    }

    #[test]
    fn empty_or_auto_country_keeps_direct_first() {
        for cc in ["", "AUTO", "auto"] {
            let cfg = OutboundConfig {
                mode: ProxyMode::Pool,
                catalog_pool: true,
                catalog_country: cc.into(),
                ..Default::default()
            };
            let t = target("example.com", 443);
            let plan = cfg.resolve_with_catalog(&t, &["198.51.100.9:443".to_owned()]);
            assert_eq!(plan.candidates[0], t, "cc={cc:?} keeps direct-first");
        }
    }

    #[test]
    fn empty_generated_degrades_to_plain_resolve_even_enforced() {
        let cfg = OutboundConfig {
            mode: ProxyMode::Pool,
            catalog_pool: true,
            catalog_country: "DE".into(),
            ..Default::default()
        };
        let t = target("example.com", 443);
        let plan = cfg.resolve_with_catalog(&t, &[]);
        assert_eq!(plan.candidates, vec![t.clone()]);
    }

    #[test]
    fn failed_or_unknown_catalog_entries_never_enter_runtime() {
        // resolve_with_catalog takes only the generated healthy list; an
        // empty list means no extra candidates, whatever the snapshot holds.
        let cfg = OutboundConfig {
            mode: ProxyMode::ProxyIp,
            proxy_candidates: vec!["203.0.113.10".into()],
            catalog_pool: true,
            catalog_country: "AZ".into(),
            ..Default::default()
        };
        let t = target("example.com", 443);
        assert_eq!(cfg.resolve_with_catalog(&t, &[]).candidates.len(), 2);
        // Malformed entries are skipped, not dialled.
        let plan = cfg.resolve_with_catalog(&t, &["not-a-candidate".to_owned()]);
        assert_eq!(plan.candidates.len(), 2);
    }

    #[test]
    fn changing_location_field_does_not_leak_generated_entries_across_tests() {
        // The generated list is data, not logic: switching catalogCountry alone
        // must not invent candidates. Empty generated list stays empty.
        let cfg = OutboundConfig {
            mode: ProxyMode::ProxyIp,
            proxy_candidates: vec!["di.nscl.ir".into()],
            catalog_pool: true,
            catalog_country: "AZ".into(),
            ..Default::default()
        };
        let t = target("example.com", 443);
        assert_eq!(cfg.resolve_with_catalog(&t, &[]).candidates.len(), 2);
    }

    #[test]
    fn catalog_pool_with_empty_pool_matches_resolve() {
        let cfg = OutboundConfig {
            mode: ProxyMode::Pool,
            proxy_candidates: vec!["203.0.113.10".into()],
            catalog_pool: true,
            ..Default::default()
        };
        let t = target("example.com", 443);
        assert_eq!(cfg.resolve_with_catalog(&t, &[]).candidates, cfg.resolve(&t).candidates);
    }

    #[test]
    fn pool_mode_manual_pin_dials_first_among_proxies() {
        let cfg = OutboundConfig {
            mode: ProxyMode::Pool,
            proxy_candidates: vec!["203.0.113.10".into(), "slow.example.com".into()],
            catalog_pool: true,
            pinned_proxy: "slow.example.com".into(),
            ..Default::default()
        };
        let t = target("example.com", 443);
        let gen = vec!["198.51.100.9:443".to_owned()];
        let plan = cfg.resolve_with_catalog(&t, &gen);
        assert_eq!(plan.candidates[0], t); // direct first, always
        assert_eq!(plan.candidates[1].host, Host::Domain("slow.example.com".into()));
        assert_eq!(plan.candidates[2].host, Host::Ip("203.0.113.10".parse().unwrap()));
        assert_eq!(plan.candidates[3].host, Host::Ip("198.51.100.9".parse().unwrap()));
    }

    #[test]
    fn generated_candidates_parse_with_bracketed_ipv6_and_reject_bare_hosts() {
        assert!(parse_candidate("91.187.93.166:443").is_some());
        assert!(parse_candidate("[2001:db8::1]:2053").is_some());
        assert!(parse_candidate("proxy.example.com:8443").is_some());
        // Bare host / bare IPv6: no port, never dialable.
        assert!(parse_candidate("91.187.93.166").is_none());
        assert!(parse_candidate("2001:db8::1").is_none());
        assert!(parse_candidate("proxy.example.com").is_none());
        assert!(parse_candidate("").is_none());
        // Out-of-range port.
        assert!(parse_candidate("91.187.93.166:99999").is_none());
    }

    // --- Generated (healthy-only) catalog candidates (V24.3.4) end ---

    // --- NAT64 mode ---

    #[test]
    fn nat64_synthesises_ipv6_for_ipv4_destination() {
        let cfg = OutboundConfig {
            mode: ProxyMode::Nat64,
            nat64_prefixes: vec!["64:ff9b::/96".into()],
            ..Default::default()
        };
        let t = target("93.184.216.34", 443);
        let plan = cfg.resolve(&t);
        assert_eq!(plan.candidates.len(), 2);
        assert_eq!(plan.candidates[0], t); // direct first
        let expected: Ipv6Addr = "64:ff9b::5db8:d822".parse().unwrap();
        assert_eq!(plan.candidates[1].host, Host::Ip(IpAddr::V6(expected)));
        assert_eq!(plan.candidates[1].port, 443);
    }

    #[test]
    fn nat64_does_nothing_for_domain_destinations() {
        let cfg = OutboundConfig {
            mode: ProxyMode::Nat64,
            nat64_prefixes: vec!["64:ff9b::/96".into()],
            ..Default::default()
        };
        let t = target("example.com", 443);
        let plan = cfg.resolve(&t);
        assert_eq!(plan.candidates, vec![t]);
    }

    #[test]
    fn nat64_does_nothing_for_ipv6_destinations() {
        let cfg = OutboundConfig {
            mode: ProxyMode::Nat64,
            nat64_prefixes: vec!["64:ff9b::/96".into()],
            ..Default::default()
        };
        let t = target("2001:db8::1", 443);
        let plan = cfg.resolve(&t);
        assert_eq!(plan.candidates, vec![t]);
    }

    #[test]
    fn nat64_does_nothing_for_ipv4_mapped_ipv6_destinations() {
        // ::ffff:x.x.x.x is an IPv6 address, not a native IPv4. NAT64
        // synthesis only applies to Host::Ip(IpAddr::V4(_)).
        let cfg = OutboundConfig {
            mode: ProxyMode::Nat64,
            nat64_prefixes: vec!["64:ff9b::/96".into()],
            ..Default::default()
        };
        let t = target("::ffff:93.184.216.34", 443);
        let plan = cfg.resolve(&t);
        assert_eq!(plan.candidates, vec![t]);
    }

    #[test]
    fn nat64_uses_well_known_prefix_when_none_configured() {
        let cfg = OutboundConfig { mode: ProxyMode::Nat64, ..Default::default() };
        let t = target("1.2.3.4", 80);
        let plan = cfg.resolve(&t);
        assert_eq!(plan.candidates.len(), 2);
        let expected: Ipv6Addr = "64:ff9b::102:304".parse().unwrap();
        assert_eq!(plan.candidates[1].host, Host::Ip(IpAddr::V6(expected)));
    }

    // --- NAT64 synthesis ---

    #[test]
    fn synthesize_nat64_places_v4_in_last_four_bytes() {
        let prefix: Ipv6Addr = "64:ff9b::".parse().unwrap();
        let v4: Ipv4Addr = "192.0.2.1".parse().unwrap();
        let result = synthesize_nat64(prefix, v4);
        assert_eq!(result.to_string(), "64:ff9b::c000:201");
    }

    #[test]
    fn synthesize_nat64_works_with_custom_prefix() {
        let prefix: Ipv6Addr = "2001:db8::".parse().unwrap();
        let v4: Ipv4Addr = "10.0.0.1".parse().unwrap();
        let result = synthesize_nat64(prefix, v4);
        let octets = result.octets();
        assert_eq!(&octets[..12], &[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(&octets[12..], &[10, 0, 0, 1]);
    }

    // --- Prefix parsing ---

    #[test]
    fn parse_nat64_prefix_accepts_valid_96_prefixes() {
        assert!(parse_nat64_prefix("64:ff9b::/96").is_some());
        assert!(parse_nat64_prefix("2001:db8::/96").is_some());
    }

    #[test]
    fn parse_nat64_prefix_rejects_non_96_lengths() {
        assert!(parse_nat64_prefix("64:ff9b::/64").is_none());
        assert!(parse_nat64_prefix("64:ff9b::/128").is_none());
        assert!(parse_nat64_prefix("64:ff9b::").is_none());
    }

    #[test]
    fn parse_nat64_prefix_rejects_nonzero_tail_bits() {
        // Last 32 bits must be zero for a /96.
        assert!(parse_nat64_prefix("64:ff9b::1/96").is_none());
    }

    // --- Validation ---

    #[test]
    fn validate_proxy_candidate_accepts_ips_and_hostnames() {
        assert!(validate_proxy_candidate("93.184.216.34"));
        assert!(validate_proxy_candidate("proxy.example.com"));
        assert!(validate_proxy_candidate("  93.184.216.34  "));
    }

    #[test]
    fn validate_proxy_candidate_rejects_private_and_loopback() {
        assert!(!validate_proxy_candidate("127.0.0.1"));
        assert!(!validate_proxy_candidate("10.0.0.1"));
        assert!(!validate_proxy_candidate("192.168.1.1"));
        assert!(!validate_proxy_candidate("::1"));
    }

    #[test]
    fn validate_proxy_candidate_rejects_malformed_entries() {
        assert!(!validate_proxy_candidate(""));
        assert!(!validate_proxy_candidate("   "));
        assert!(!validate_proxy_candidate("host:443"));
        assert!(!validate_proxy_candidate("host/path"));
    }

    #[test]
    fn validate_nat64_prefix_accepts_and_rejects_correctly() {
        assert!(validate_nat64_prefix("64:ff9b::/96"));
        assert!(!validate_nat64_prefix("64:ff9b::/64"));
        assert!(!validate_nat64_prefix("not-a-prefix"));
        assert!(!validate_nat64_prefix(""));
    }

    // --- Serialisation round-trip ---

    #[test]
    fn config_round_trips_through_json() {
        let cfg = OutboundConfig {
            mode: ProxyMode::ProxyIp,
            proxy_candidates: vec!["203.0.113.10".into(), "proxy.example.com".into()],
            nat64_prefixes: vec!["64:ff9b::/96".into()],
            max_proxy_attempts: 5,
            catalog_pool: true,
            catalog_country: "DE".into(),
            verified_catalog_candidates: vec!["198.51.100.9:443".into()],
            pinned_proxy: "203.0.113.10".into(),
        };
        let json = serde_json::to_string(&cfg).expect("serialises");
        let back: OutboundConfig = serde_json::from_str(&json).expect("deserialises");
        assert_eq!(back, cfg);
    }

    #[test]
    fn missing_fields_default_to_off() {
        let json = "{}";
        let cfg: OutboundConfig = serde_json::from_str(json).expect("deserialises");
        assert_eq!(cfg.mode, ProxyMode::Off);
        assert!(cfg.proxy_candidates.is_empty());
        assert!(cfg.nat64_prefixes.is_empty());
        assert_eq!(cfg.max_proxy_attempts, 3);
    }

    // --- Settings → relay config boundary ---

    #[test]
    fn from_settings_json_extracts_outbound_config() {
        let raw = r#"{"version":1,"nodes":[],"outbound":{"mode":"proxyIp","proxyCandidates":["93.184.216.34"],"nat64Prefixes":[],"maxProxyAttempts":2}}"#;
        let cfg = from_settings_json(raw);
        assert_eq!(cfg.mode, ProxyMode::ProxyIp);
        assert_eq!(cfg.proxy_candidates, vec!["93.184.216.34"]);
        assert_eq!(cfg.max_proxy_attempts, 2);
    }

    #[test]
    fn from_settings_json_defaults_to_off_when_field_absent() {
        let raw = r#"{"version":1,"nodes":[]}"#;
        let cfg = from_settings_json(raw);
        assert_eq!(cfg.mode, ProxyMode::Off);
        assert!(cfg.proxy_candidates.is_empty());
    }

    #[test]
    fn from_settings_json_defaults_on_malformed_json() {
        let cfg = from_settings_json("not json");
        assert_eq!(cfg.mode, ProxyMode::Off);
    }

    #[test]
    fn from_settings_json_defaults_on_empty_string() {
        let cfg = from_settings_json("");
        assert_eq!(cfg.mode, ProxyMode::Off);
    }

    #[test]
    fn from_settings_json_defaults_on_malformed_outbound_field() {
        // The outbound field exists but is not a valid OutboundConfig.
        // Must fall back to Off, not panic.
        let raw = r#"{"outbound":"not an object"}"#;
        let cfg = from_settings_json(raw);
        assert_eq!(cfg.mode, ProxyMode::Off);
    }

    #[test]
    fn proxy_ip_config_reaches_the_relay_resolver() {
        // Simulate the full boundary: settings JSON → OutboundConfig → resolve.
        // A Proxy IP config must produce a dial plan with proxy candidates.
        let raw = r#"{"version":1,"nodes":[],"outbound":{"mode":"proxyIp","proxyCandidates":["93.184.216.34","proxy.example.com"],"nat64Prefixes":[],"maxProxyAttempts":3}}"#;
        let cfg = from_settings_json(raw);
        let t = target("example.com", 443);
        let plan = cfg.resolve(&t);
        // Direct + 2 proxy candidates = 3.
        assert_eq!(plan.candidates.len(), 3);
        assert_eq!(plan.candidates[0], t);
        assert_eq!(plan.candidates[1].host, Host::Ip("93.184.216.34".parse().unwrap()));
        assert_eq!(plan.candidates[2].host, Host::Domain("proxy.example.com".into()));
        // The logical destination is preserved.
        assert_eq!(plan.logical, t);
    }

    #[test]
    fn nat64_config_reaches_the_relay_resolver() {
        // A NAT64 config must produce a dial plan with a synthetic IPv6
        // candidate for an IPv4 destination.
        let raw = r#"{"version":1,"nodes":[],"outbound":{"mode":"nat64","proxyCandidates":[],"nat64Prefixes":["64:ff9b::/96"],"maxProxyAttempts":3}}"#;
        let cfg = from_settings_json(raw);
        let t = target("93.184.216.34", 443);
        let plan = cfg.resolve(&t);
        assert_eq!(plan.candidates.len(), 2);
        assert_eq!(plan.candidates[0], t);
        let expected: std::net::Ipv6Addr = "64:ff9b::5db8:d822".parse().unwrap();
        assert_eq!(plan.candidates[1].host, Host::Ip(IpAddr::V6(expected)));
    }

    #[test]
    fn default_config_remains_off_through_the_boundary() {
        // No outbound field → Off mode → single direct candidate.
        let raw = r#"{"version":1,"nodes":[]}"#;
        let cfg = from_settings_json(raw);
        let t = target("example.com", 443);
        let plan = cfg.resolve(&t);
        assert_eq!(plan.candidates, vec![t]);
    }

    #[test]
    fn malformed_persisted_config_safely_falls_back_to_off() {
        // A corrupted settings document must not crash the relay.
        // It must produce Off mode (direct-only), which is the safe default.
        let raw = r#"{"outbound":{"mode":"invalidMode","proxyCandidates":[]}}"#;
        let cfg = from_settings_json(raw);
        assert_eq!(cfg.mode, ProxyMode::Off);
        let t = target("example.com", 443);
        let plan = cfg.resolve(&t);
        assert_eq!(plan.candidates, vec![t]);
    }
}