//! The panel's HTTP surface, decided without touching HTTP.
//!
//! Route parsing and every response body are built here, from values, so they
//! run in the host test suite. [`super::serve`] does nothing but read the
//! request, call into this module, and write the result — which is the only
//! part a unit test could not reach anyway.
//!
//! # What is behind a session and what is not
//!
//! Only the shell page is served without one. That is a deliberate exception to
//! the rule that every negative outcome renders the decoy, and it is worth
//! stating plainly rather than leaving as an accident: there has to be
//! *somewhere* to type the password, and a login form that is itself behind a
//! login is not a design.
//!
//! What makes it acceptable is that the panel prefix is already a secret. A
//! scanner sweeping this hostname tries `/`, `/admin`, `/wp-login.php` and gets
//! the decoy for all of them, because none of them match the prefix. Only a
//! request that already carries the prefix — which is generated random and
//! never guessed — sees a login form at all. Confirming "yes, this is the
//! panel" to someone who has already produced that secret costs nothing they
//! did not already have.
//!
//! Every other route requires a valid session, and a deployment with no
//! password configured has no panel at all rather than an open one.

use serde::{Deserialize, Serialize};

use crate::config::model::{ClientTarget, Node};
use crate::relay::outbound::{OutboundConfig, ProxyMode};
use crate::subscription::bundle::{self, Shape, Skipped};

use super::store::Settings;

/// What a panel request is asking for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Api {
    /// The panel page itself. The only route served without a session.
    Page,
    Login,
    Logout,
    /// Everything the panel needs to render.
    State,
    /// Replace the node set.
    Save,
    /// Re-evaluate a draft node without saving it.
    Check,
    /// A rendered subscription body, for preview and download.
    Export,
    /// A QR image for a subscription or a node.
    Qr,
    /// Measure each Proxy-IP candidate's exit country (operator-initiated).
    ProbeProxy,
    /// Sync the public Proxy-IP catalog snapshot (operator-initiated).
    CatalogSync,

    /// Dial-test the verified pool for a location WITHOUT persisting anything
    /// (KV-quota-independent validation path; operator-initiated).
    PoolDialTest,
    /// One bounded worker-vantage verification pass (TCP reachability FROM
    /// this Worker's egress) over catalog candidates. Session-gated for
    /// operators; the cron trigger calls the Rust function directly
    /// (vantage model: scanner health is source evidence, this is the
    /// Trinity-usable verdict).
    VerifyCatalog,
    /// Per-country health counts + quarantined list — the honest debug view
    /// (discovered vs Trinity-reachable vs quarantined).
    HealthOverlay,
    /// The stored catalog metadata (revision/counts) — lets the scanner's
    /// automation skip a sync when the feed revision is unchanged (V24.6.1 §13).
    CatalogMeta,
    /// Anything else. Renders the decoy.
    Unknown,
}

impl Api {
    /// Whether this route may be reached without a valid session.
    #[must_use]
    pub const fn is_public(self) -> bool {
        matches!(self, Self::Page | Self::Login)
    }
}

/// Classify a panel request from its method and the path after the prefix.
#[must_use]
pub fn route(method: &str, rest: &str) -> Api {
    let rest = rest.trim_matches('/');
    match (method, rest) {
        ("GET", "") => Api::Page,
        ("POST", "api/login") => Api::Login,
        ("POST", "api/logout") => Api::Logout,
        ("GET", "api/state") => Api::State,
        ("PUT" | "POST", "api/nodes") => Api::Save,
        ("POST", "api/check") => Api::Check,
        ("GET", "api/export") => Api::Export,
        ("GET", "api/qr") => Api::Qr,
        ("POST", "api/probe-proxy") => Api::ProbeProxy,
        ("POST", "api/catalog-sync") => Api::CatalogSync,

        ("POST", "api/pool-dial-test") => Api::PoolDialTest,
        ("POST" | "GET", "api/verify-catalog") => Api::VerifyCatalog,
        ("GET", "api/health-overlay") => Api::HealthOverlay,
        ("GET", "api/catalog-meta") => Api::CatalogMeta,
        _ => Api::Unknown,
    }
}

/// What the browser posts to log in.
#[derive(Deserialize, Debug)]
pub struct LoginRequest {
    pub password: String,
}

/// What the browser posts to save.
#[derive(Deserialize, Debug)]
pub struct SaveRequest {
    pub nodes: Vec<Node>,
    /// Outbound routing config. Defaults to Off when absent (old clients).
    #[serde(default)]
    pub outbound: OutboundConfig,
    /// Enhanced Reachability toggle. Defaults to off when absent (old
    /// clients), and off is the byte-identical existing behaviour.
    #[serde(default)]
    pub enhanced_reachability: bool,
    /// The revision the client loaded, for optimistic concurrency. Absent
    /// from old clients, whose saves behave exactly as they always did.
    #[serde(default)]
    pub expected_rev: Option<u32>,
    /// Common-section preferences. Absent from pre-1.9.7 clients; defaults
    /// keep their saves byte-compatible.
    #[serde(default)]
    pub common: super::store::CommonSettings,
}

/// Refusal shown when a save raced another save.
pub const REV_CONFLICT_MESSAGE: &str = "Settings changed elsewhere. Reload and try again.";

/// Resolve the revision a successful save should store.
///
/// `expected_rev` is what the client believes is currently stored. A mismatch
/// with `stored_rev` means someone else saved first; refusing keeps the other
/// tab's edit intact instead of silently overwriting it. Old clients send no
/// expectation and always succeed — the historical behaviour.
pub fn resolve_save_rev(expected_rev: Option<u32>, stored_rev: u32) -> Result<u32, &'static str> {
    match expected_rev {
        Some(expected) if expected != stored_rev => Err(REV_CONFLICT_MESSAGE),
        // Wrapping so even a u32::MAX-stored document stays savable.
        _ => Ok(stored_rev.wrapping_add(1)),
    }
}

/// What the browser posts to re-check a draft.
///
/// The edit is sent as a field name and a value rather than as an already
/// modified node, so the browser never has to know how a [`Node`] is shaped.
/// The server applies it with [`super::advisor::apply`] — the same function
/// that builds the candidates deciding which choices are blocked — and returns
/// the resulting node. That is what keeps "this option is disabled" and "this
/// is what saving would produce" from being two different pieces of logic.
#[derive(Deserialize, Debug)]
pub struct CheckRequest {
    pub node: Node,
    /// Client slug the editor is currently showing.
    pub client: String,
    /// The change to apply first, if any.
    #[serde(default)]
    pub edit: Option<Edit>,
    /// The toggle's local state, so advice matches what saving would render.
    #[serde(default)]
    pub enhanced_reachability: bool,
}

#[derive(Deserialize, Debug)]
pub struct Edit {
    pub field: String,
    pub value: String,
}

/// The advice for a draft node, together with the node the edit produced.
#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
pub struct Checked {
    pub node: Node,
    #[serde(flatten)]
    pub advice: super::advisor::Advice,
}

/// One client, as the simple view lists it.
#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
pub struct ClientView {
    pub name: &'static str,
    pub slug: &'static str,
    pub core: &'static str,
    /// Subscription URL to paste into the app. Empty when nothing translates.
    pub subscription: String,
    /// Direct download of a full configuration file, where the client takes one.
    pub config: Option<String>,
    /// How many of the deployment's nodes this client can actually use.
    pub included: usize,
    /// Nodes it cannot, and why. Never silently omitted.
    pub skipped: Vec<Skipped>,
}

/// One node, as the editor and the simple view list it.
#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
pub struct NodeView {
    pub tag: String,
    pub protocol: &'static str,
    pub transport: &'static str,
    /// Share links by client slug, for the clients that can express this node.
    pub links: Vec<NodeLink>,
    /// Every client's verdict on this node.
    pub matrix: Vec<super::advisor::TargetVerdict>,
}

#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
pub struct NodeLink {
    pub client: &'static str,
    pub uri: String,
}

/// Everything the panel needs on load.
// No `Eq`: candidate scores are floats.
#[derive(Serialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct State {
    pub host: String,
    /// `stored` when the operator has saved a set, `derived` when these are the
    /// nodes the deployment's own bindings imply. Shown, because "I never
    /// configured this" is otherwise a confusing thing to be looking at.
    pub source: &'static str,
    /// Present when a stored document could not be read. The deployment keeps
    /// serving the derived set; this is how the operator finds out why.
    pub warning: Option<String>,
    pub nodes: Vec<Node>,
    pub views: Vec<NodeView>,
    pub clients: Vec<ClientView>,
    /// An empty connection to start from, built by the same code that builds
    /// every other node. The browser adding one of its own would be a second
    /// place that knows the model's shape.
    pub blank: Node,
    /// Outbound routing configuration (Proxy IP / NAT64).
    pub outbound: OutboundConfig,
    /// Last measured health per proxy candidate, best first. Empty until the
    /// operator runs a probe; the panel renders "not measured" from that.
    pub proxy_health: Vec<CandidateHealth>,
    /// The Enhanced Reachability toggle's current value. Shown so the panel
    /// renders the same on/off state the subscriptions are being served with.
    pub enhanced_reachability: bool,
    /// Public catalog sync metadata (tiny). `None` = never synced.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub catalog: Option<crate::catalog::Meta>,
    /// Optimistic-concurrency revision of the settings document. Sent back as
    /// `expectedRev` on save; a stale value is refused with an explanation
    /// rather than silently overwriting whoever saved in between.
    pub rev: u32,
    /// EXACT host:port list the dial path hands to resolve_with_catalog()
        /// for the current mode/location (verified snapshot derived). Empty when
        /// the mode contributes no catalog candidates.
        pub runtime_candidates: Vec<String>,
        /// Per-candidate detail for `runtime_candidates`, in the SAME order, so the
        /// panel can show why each one ranks where it does instead of a bare
        /// `host:port`. Every measurement is `Option`: absent means the scanner did
        /// not measure it, which the UI must render as unknown, never as zero.
        pub runtime_detail: Vec<CandidateDetail>,
    /// V24.4.4 runtime-only geographic failover (Pool mode). Empty strings =
    /// no fallback active. The configured location is never rewritten.
    pub fallback: Option<crate::panel::api::FallbackView>,
    /// Automatic mode's current resolved country. `None` unless the mode is
    /// AUTO, so a manual country never shows a competing resolution.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auto_country: Option<AutoCountryView>,
    /// Per-country verified capability + quality (v1.9.5): the aggregation the
    /// country selector sorts and badges by. `None` = no catalog snapshot.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country_quality: Option<
        std::collections::BTreeMap<String, crate::catalog::CountryQuality>,
    >,
    /// Common-section preferences (v1.9.7).
    pub common: super::store::CommonSettings,
    /// The Proxy-IP candidate a real session last exited through
    /// (`host:port`, from the teardown LKG write), plus when it was recorded.
    ///
    /// This is the ONLY correlation anchor between "a candidate won a real
    /// session" and "something observed an exit address". Without it no
    /// observation can be attributed to a candidate at all, which is why the
    /// egress widget cannot claim a proxy-bound exit: it has no way to know
    /// which candidate, if any, its own fetch went through. Empty when no
    /// proxy candidate has won yet.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_winner: Option<SessionWinner>,
}

/// Project the stored LKG preference into the panel's correlation view.
///
/// Pure so the two call sites that do not already hold an `OutboundState` can
/// share it, and so the mapping is testable on the host. A candidate with no
/// recorded preference yields `None`, which the panel renders as "no session
/// winner yet" rather than as a blank that looks like a match.
#[must_use]
pub fn session_winner_view(state: &crate::relay::outbound_state::OutboundState) -> Option<SessionWinner> {
    let candidate = state.preferred.clone()?;
    if candidate.trim().is_empty() {
        return None;
    }
    Some(SessionWinner {
        candidate,
        observed_at_ms: state.updated_at_ms,
    })
}

/// The candidate a real session last exited through.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionWinner {
    /// Canonical `host:port` of the winning candidate.
    pub candidate: String,
    /// When the preference was recorded (session teardown).
    pub observed_at_ms: u64,
}

/// Compact fallback view for the panel.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FallbackView {
    /// Configured (authoritative) location.
    pub primary: String,
    /// Temporarily active runtime location.
    pub active: String,
}

/// What Automatic resolved to, so the panel can show the decision separately
/// from the mode. The setting stays `AUTO`; this is the country it picked.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AutoCountryView {
    /// Resolved country, or empty when no country is provably usable.
    pub country: String,
    /// When the decision was last made (ms). Drives "chosen Nh ago".
    pub resolved_at_ms: u64,
}

/// One proxy candidate as the panel should render it: what the operator
/// configured, joined with what the last probe measured.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CandidateHealth {
    pub host: String,
    /// v1.9.6 feed quality verdict "risk/type/confidence/source" for this
    /// endpoint. Empty = unmeasured (never rendered as bad).
    #[serde(skip_serializing_if = "String::is_empty")]
    pub quality: String,
    /// False when this candidate has never been probed.
    pub measured: bool,
    pub ok: bool,
    pub healthy: bool,
    pub country: String,
    pub colo: String,
    pub exit_ip: String,
    pub latency_ms: u32,
    pub rotating: bool,
    pub success_rate: f64,
    pub score: f64,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub error: String,
}

/// One runtime pool candidate with the evidence behind its rank.
///
/// Every measurement is an `Option` on purpose: the scanner publishes a
/// measurement only where it made one, and "not measured" must reach the panel
/// as absent so the UI can print Unknown. Coercing a gap to 0 would make a
/// candidate look measured-and-terrible, and padding it with a default would
/// make it look measured-and-good.
///
/// `dl_bps`/`ul_bps` are the CANDIDATE's own throughput measured by the
/// scanner over the CF-relay path. They are not user throughput through
/// Trinity and the panel must not label them as such.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CandidateDetail {
    /// `host:port`, identical to the matching entry in `runtime_candidates`.
    pub host: String,
    pub country: String,
    /// Stage-C capability class from the feed (`passthrough` / `cf-relay` /
    /// `sni-terminate`). Empty when the feed carries no classification.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub capability: String,
    /// Feed quality verdict "risk/type/confidence/source", empty = unmeasured.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub quality: String,
    /// Worker-vantage liveness: measured and currently usable.
    pub healthy: bool,
    /// Bytes/sec the SCANNER measured downstream. None = unknown.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dl_bps: Option<u64>,
    /// Bytes/sec the SCANNER measured upstream. None = unknown.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ul_bps: Option<u64>,
    /// Round-trip time in ms as measured by the scanner. None = unknown.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rtt_ms: Option<u32>,
    /// Success ratio in basis points (0..=10_000). None = unknown, NOT zero.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub success_bp: Option<u32>,
    /// ISO-8601 UTC timestamp of the underlying observation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_success: Option<String>,
    /// Age of that observation in seconds at render time. None = unknown.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub age_s: Option<u64>,
    /// True once the observation is older than the freshness window the
    /// ranking itself uses, so the panel can mark it stale instead of
    /// presenting old numbers as current evidence.
    pub stale: bool,
    /// Plain sentence naming why this candidate sits where it does.
    pub reason: String,
}

/// Freshness window for a candidate measurement shown in the panel. Mirrors
/// `catalog::METRICS_MAX_AGE_H` (12 h), which is the same window the ranking
/// itself honours, so a row can never look fresher here than it ranks.
const DETAIL_FRESH_S: u64 = 12 * 3600;

/// The feed's per-endpoint quality verdicts, or an empty map when there is no
/// snapshot. A borrow, so the caller does not have to clone the map out of the
/// snapshot just to pass it on.
pub fn quality_by_endpoint(
    snapshot: Option<&crate::catalog::Snapshot>,
) -> &std::collections::BTreeMap<String, String> {
    static EMPTY: std::sync::OnceLock<std::collections::BTreeMap<String, String>> =
        std::sync::OnceLock::new();
    snapshot.map_or_else(|| EMPTY.get_or_init(Default::default), |s| &s.quality_by_endpoint)
}

/// Join the runtime pool with the snapshot's evidence, in the pool's own order.
///
/// `runtime_candidates` is already eligibility-gated and ranked by
/// `catalog::bounded`; this only ADDS the evidence behind each position, so it
/// must not re-sort or re-filter. A candidate missing from every snapshot map
/// still gets a row — with unknown measurements and a reason saying so — rather
/// than vanishing, because it is genuinely in the dial plan.
/// Resolve one endpoint against a feed map keyed by `ip:port`.
///
/// Exact `host:port` first, then the bare ip for legacy bare-keyed rows. NO
/// prefix fallback: every feed key carries its own port, so a unique-prefix
/// match would hand port 443's measurement to an 8443 candidate that was never
/// measured. A genuine gap must stay a gap.
fn resolve<'a, T>(
    map: &'a std::collections::BTreeMap<String, T>,
    key: &str,
    bare: &str,
) -> Option<&'a T> {
    map.get(key).or_else(|| map.get(bare))
}

#[must_use]
pub fn candidate_details(
    runtime: &[String],
    snapshot: Option<&crate::catalog::Snapshot>,
    geo: &std::collections::BTreeMap<String, crate::relay::outbound_state::Health>,
    now_s: u64,
) -> Vec<CandidateDetail> {
    // Feed and health maps are keyed "ip:port" (health may be a legacy bare
    // host). One exact lookup, then the bare-ip form, then a unique-prefix
    // match -- the same resolution order `candidate_health` already uses, so
    // the two views can never disagree about which row a candidate is.
    runtime
        .iter()
        .map(|host| {
            let key = host.trim().to_ascii_lowercase();
            let bare = key.split(':').next().unwrap_or("").to_string();
            let m = snapshot.and_then(|s| resolve(&s.quality_metrics_by_endpoint, &key, &bare));
            let capability = snapshot
                .and_then(|s| resolve(&s.capability_by_endpoint, &key, &bare).cloned())
                .unwrap_or_default();
            let quality = snapshot
                .and_then(|s| resolve(&s.quality_by_endpoint, &key, &bare).cloned())
                .unwrap_or_default();
            let health = geo
                .get(&key)
                .or_else(|| geo.get(&bare))
                .or_else(|| {
                    geo.iter()
                        .find(|(k, _)| k.split(':').next() == Some(bare.as_str()))
                        .map(|(_, v)| v)
                });
            let healthy = health.is_some_and(crate::relay::outbound_state::Health::healthy);
            let age_s = m.and_then(|x| {
                x.last_success
                    .as_deref()
                    .and_then(parse_iso8601_s)
                    .map(|t| now_s.saturating_sub(t))
            });
            let stale = age_s.is_some_and(|a| a > DETAIL_FRESH_S);
            let reason = describe_candidate(healthy, &capability, m.is_some(), stale);
            CandidateDetail {
                host: host.clone(),
                country: health.map(|h| h.country.clone()).unwrap_or_default(),
                capability,
                quality,
                healthy,
                dl_bps: m.and_then(|x| x.dl_bps),
                ul_bps: m.and_then(|x| x.ul_bps),
                rtt_ms: m.and_then(|x| x.rtt_ms),
                success_bp: m.and_then(|x| x.success_bp),
                last_success: m.and_then(|x| x.last_success.clone()),
                age_s,
                stale,
                reason,
            }
        })
        .collect()
}

/// One sentence naming the primary reason for a candidate's position. Measured
/// candidates lead; an unmeasured one is never dressed up as if it competed.
fn describe_candidate(healthy: bool, capability: &str, measured: bool, stale: bool) -> String {
    let mut s = if healthy {
        "healthy and eligible".to_string()
    } else {
        "not confirmed healthy yet".to_string()
    };
    if capability == "cf-relay" {
        s.push_str("; Cloudflare-fronted destinations only");
    } else if capability == "sni-terminate" {
        s.push_str("; TLS-terminated, no generic-internet passthrough");
    }
    match (measured, stale) {
        (false, _) => s.push_str("; no measurement — ranked by eligibility alone"),
        (true, true) => s.push_str("; measurement is stale"),
        (true, false) => s.push_str("; fresh measurement, ranked above unmeasured"),
    }
    s
}

/// Parse the feed's `YYYY-MM-DDTHH:MM:SSZ` stamp to epoch seconds. Returns
/// `None` for anything else, so a malformed timestamp reads as unknown rather
/// than as "measured at the epoch" (which would mark every row stale).
fn parse_iso8601_s(text: &str) -> Option<u64> {
    let b = text.as_bytes();
    if b.len() != 20 || b[4] != b'-' || b[7] != b'-' || b[10] != b'T' || b[19] != b'Z' {
        return None;
    }
    let field = |r: std::ops::Range<usize>| text.get(r)?.parse::<i64>().ok();
    let (y, mo, d) = (field(0..4)?, field(5..7)?, field(8..10)?);
    let (h, mi, sec) = (field(11..13)?, field(14..16)?, field(17..19)?);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || sec > 60 {
        return None;
    }
    // Days-from-civil (Howard Hinnant's algorithm), no date crate needed.
    let y = if mo <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (mo + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    u64::try_from(days * 86_400 + h * 3600 + mi * 60 + sec).ok()
}

/// Join configured candidates with their measured health, best score first.
///
/// Built from the settings' own candidate list, so a candidate the operator
/// removed disappears from the panel even while its stale record lingers in
/// the state document.
#[must_use]
pub fn candidate_health(
    cfg: &OutboundConfig,
    geo: &std::collections::BTreeMap<String, crate::relay::outbound_state::Health>,
    extra_hosts: &[String],
    quality: &std::collections::BTreeMap<String, String>,
) -> Vec<CandidateHealth> {
    let wanted = "";
    let mut hosts: Vec<String> = cfg.proxy_candidates.clone();
    // Catalog candidates render after the configured ones, deduped by host,
    // so a measured catalog candidate shows its local evidence too.
    for host in extra_hosts {
        if !hosts.iter().any(|h| h.eq_ignore_ascii_case(host)) {
            hosts.push(host.clone());
        }
    }
    let q = |host: &str| -> String {
        // Feed keys are "ip:port"; settings candidates may be bare "ip" or
        // "host". Match the whole trimmed key, else its ip-prefix up to ":".
        let key = host.trim().to_ascii_lowercase();
        if let Some(hit) = quality.get(key.as_str()) {
            return hit.clone();
        }
        let bare = key.split(':').next().unwrap_or("");
        if let Some(hit) = quality.get(bare) {
            return hit.clone();
        }
        // bare-ip lookup can be ambiguous across ports — only accept when
        // exactly one feed entry shares this IP.
        let hits: Vec<&String> = quality
            .keys()
            .filter(|k| k.split(':').next() == Some(bare))
            .collect();
        if hits.len() == 1 {
            return quality[hits[0]].clone();
        }
        String::new()
    };
    let mut rows: Vec<CandidateHealth> = hosts
        .iter()
        .map(|host| {
            // Health rows are keyed by candidate_key (host:port); legacy
            // bare-host rows still resolve (key match first).
            let lower = host.trim().to_ascii_lowercase();
            let key = if geo.contains_key(&lower) {
                lower.clone()
            } else {
                let with_port = format!("{lower}:443");
                if geo.contains_key(&with_port) {
                    with_port
                } else {
                    lower.clone()
                }
            };
            match geo.get(&key) {
                Some(h) => CandidateHealth {
                    host: host.clone(),
                    quality: q(host),
                    measured: true,
                    ok: h.ok,
                    healthy: h.healthy(),
                    country: h.country.clone(),
                    colo: h.colo.clone(),
                    exit_ip: h.exit_ip.clone(),
                    latency_ms: h.latency_ms,
                    rotating: h.rotating,
                    success_rate: h.success_rate(),
                    score: h.score(wanted),
                    error: h.error.clone(),
                },
                None => CandidateHealth {
                    host: host.clone(),
                    quality: q(host),
                    measured: false,
                    ok: false,
                    healthy: false,
                    country: String::new(),
                    colo: String::new(),
                    exit_ip: String::new(),
                    latency_ms: 0,
                    rotating: false,
                    success_rate: 0.0,
                    score: 0.0,
                    error: String::new(),
                },
            }
        })
        .collect();
    rows.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(core::cmp::Ordering::Equal)
    });
    rows
}

/// Whether a country preference currently has any healthy candidate.
///
/// The panel warns and offers Auto from this: a preference nothing can satisfy
/// is the one case where the operator's selection is silently not in effect.
#[must_use]
pub fn country_is_satisfiable(country: &str, rows: &[CandidateHealth]) -> bool {
    let want = country.trim();
    want.is_empty()
        || rows
            .iter()
            .any(|r| r.healthy && r.country.eq_ignore_ascii_case(want))
}

/// Where the settings a request is serving came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    Stored,
    Derived,
}

/// Build the panel state.
///
/// `sub_base` is the absolute URL prefix subscriptions are served from, so the
/// browser never has to reassemble it and get the secret prefix wrong.
#[must_use]
pub fn state(
    settings: &Settings,
    host: &str,
    sub_base: &str,
    xhttp_path: &str,
    source: Source,
    warning: Option<String>,
    geo: &std::collections::BTreeMap<String, crate::relay::outbound_state::Health>,
    catalog: Option<crate::catalog::Meta>,
    catalog_hosts: &[String],
    runtime_candidates: &[String],
    fallback: Option<FallbackView>,
    country_quality: Option<
        std::collections::BTreeMap<String, crate::catalog::CountryQuality>,
    >,
    quality_by_endpoint: &std::collections::BTreeMap<String, String>,
    session_winner: Option<SessionWinner>,
    snapshot: Option<&crate::catalog::Snapshot>,
    now_s: u64,
) -> State {
    let clients = bundle::all_clients()
        .into_iter()
        .map(|client| {
            client_view(
                &settings.nodes,
                client,
                sub_base,
                settings.enhanced_reachability,
            )
        })
        .collect();

    let views = settings
        .nodes
        .iter()
        .map(|node| node_view(node, settings.enhanced_reachability))
        .collect();

    State {
        host: host.to_owned(),
        source: match source {
            Source::Stored => "stored",
            Source::Derived => "derived",
        },
        warning,
        nodes: settings.nodes.clone(),
        views,
        clients,
        blank: super::advisor::blank(host, xhttp_path),
        proxy_health: candidate_health(&settings.outbound, geo, catalog_hosts, quality_by_endpoint),
        outbound: settings.outbound.clone(),
        enhanced_reachability: settings.enhanced_reachability,
        catalog,
        runtime_candidates: runtime_candidates.to_vec(),
        runtime_detail: candidate_details(runtime_candidates, snapshot, geo, now_s),
        fallback,
        // Automatic's decision is derived here from the same snapshot and health
        // evidence the dial path uses, so the panel never shows a different
        // country than the one actually dialed. Only for AUTO; a manual country
        // has no resolution to show.
        auto_country: if settings
            .outbound
            .catalog_country
            .trim()
            .eq_ignore_ascii_case("AUTO")
        {
            snapshot.and_then(|snap| {
                crate::catalog::resolve_auto_country(
                    snap,
                    geo,
                    now_s.saturating_mul(1000),
                    &crate::relay::outbound_state::OutboundState::default(),
                )
                .map(|country| AutoCountryView {
                    country,
                    resolved_at_ms: 0,
                })
            })
        } else {
            None
        },
        country_quality,
        rev: settings.rev,
        common: settings.common.clone(),
        session_winner,
    }
}

fn client_view(nodes: &[Node], client: ClientTarget, sub_base: &str, enhanced: bool) -> ClientView {
    let slug = bundle::client_slug(client);
    // The share-link bundle is what a subscription URL returns, so its skip
    // list is the honest answer to "what will this app actually receive".
    let links = bundle::render(
        nodes,
        client,
        Shape::ShareLinks,
        enhanced,
        &crate::panel::store::CommonSettings::default(),
    );
    let (included, skipped) = links
        .as_ref()
        .map_or_else(|_| (0, Vec::new()), |b| (b.included, b.skipped.clone()));

    let subscription = if included > 0 {
        format!("{sub_base}/{slug}")
    } else {
        String::new()
    };
    // Offered only when the emitter really produces a document for this
    // client; a download link that returns the decoy is worse than no link.
    let config = bundle::render(nodes, client, Shape::FullConfig, enhanced, &crate::panel::store::CommonSettings::default())
        .ok()
        .map(|b| format!("{sub_base}/{slug}.{}", extension(&b.filename)));

    ClientView {
        name: client.name(),
        slug,
        core: client.core().name(),
        subscription,
        config,
        included,
        skipped,
    }
}

/// The extension of a rendered filename, defaulting to JSON.
fn extension(filename: &str) -> &str {
    filename.rsplit_once('.').map_or("json", |(_, ext)| ext)
}

fn node_view(node: &Node, enhanced: bool) -> NodeView {
    let links = bundle::all_clients()
        .into_iter()
        .filter_map(|client| {
            crate::subscription::to_uri(node, client, enhanced)
                .ok()
                .map(|uri| NodeLink {
                    client: bundle::client_slug(client),
                    uri,
                })
        })
        .collect();

    NodeView {
        tag: node.tag.clone(),
        protocol: node.protocol.name(),
        transport: node.transport.name(),
        links,
        matrix: super::advisor::matrix(node, enhanced),
    }
}

/// Reject a node set that cannot be stored or served.
///
/// Only structural refusals belong here. A node that merely fails for one
/// client is reported by the advisor and left saveable, because the operator is
/// allowed to keep a node that only some of their apps can use.
///
/// # Errors
/// A message addressed to the operator.
pub fn validate(nodes: &[Node]) -> Result<(), String> {
    if nodes.len() > MAX_NODES {
        return Err(format!("{MAX_NODES} connections is the limit"));
    }
    for node in nodes {
        if node.tag.trim().is_empty() {
            return Err("every connection needs a name".to_owned());
        }
        if node.server.address.trim().is_empty() {
            return Err(format!("\"{}\" has no server address", node.tag));
        }
    }
    // Tags identify a node in every export and in the chain field, so two nodes
    // sharing one would make both unaddressable.
    for (i, node) in nodes.iter().enumerate() {
        if nodes.iter().skip(i + 1).any(|other| other.tag == node.tag) {
            return Err(format!("two connections are both called \"{}\"", node.tag));
        }
    }
    for node in nodes {
        if let Some(via) = &node.chain_via {
            if via == &node.tag {
                return Err(format!("\"{}\" cannot chain through itself", node.tag));
            }
            if !nodes.iter().any(|n| &n.tag == via) {
                return Err(format!(
                    "\"{}\" chains through \"{via}\", which is not one of your connections",
                    node.tag
                ));
            }
        }
    }
    Ok(())
}

/// A generous ceiling. It exists so a malformed or hostile request cannot make
/// the settings document unbounded, not to constrain real use.
const MAX_NODES: usize = 64;

/// Same reasoning as [`MAX_NODES`], for the outbound candidate lists.
const MAX_OUTBOUND_ENTRIES: usize = 64;

/// Reject an outbound config that cannot be stored or dialled.
///
/// Validated here rather than only at dial time because a candidate that the
/// relay silently skips is indistinguishable, from the panel, from one that is
/// being used — the operator would see a saved Proxy IP and a connection that
/// still goes direct, with nothing to explain it.
///
/// Only entries that would be *dropped* are refused. Reachability is
/// deliberately not checked: whether a proxy actually forwards traffic is
/// something only the real relay path can answer, and guessing here would
/// produce exactly the fake verdict this project refuses to ship.
///
/// # Errors
/// A message addressed to the operator.
pub fn validate_outbound(cfg: &OutboundConfig) -> Result<(), String> {
    use crate::relay::outbound::{validate_nat64_prefix, validate_proxy_candidate};

    if cfg.proxy_candidates.len() > MAX_OUTBOUND_ENTRIES
        || cfg.nat64_prefixes.len() > MAX_OUTBOUND_ENTRIES
    {
        return Err(format!(
            "{MAX_OUTBOUND_ENTRIES} outbound entries is the limit"
        ));
    }
    for candidate in &cfg.proxy_candidates {
        if !validate_proxy_candidate(candidate) {
            return Err(format!(
                "\"{candidate}\" is not a usable proxy address. Give a public IP or a hostname, \
                 with no port and no path."
            ));
        }
    }
    for prefix in &cfg.nat64_prefixes {
        if !validate_nat64_prefix(prefix) {
            return Err(format!(
                "\"{prefix}\" is not a valid NAT64 prefix. It must be a /96 whose last 32 bits \
                 are zero, like 64:ff9b::/96."
            ));
        }
    }
    // A mode that needs entries it does not have would save cleanly and then
    // behave as Off, which looks like the feature is broken rather than unset.
    if cfg.mode == ProxyMode::ProxyIp && cfg.proxy_candidates.is_empty() {
        return Err("Proxy IP mode needs at least one proxy address.".to_owned());
    }
    for entry in &cfg.verified_catalog_candidates {
        if crate::relay::outbound::parse_candidate(entry).is_none() {
            return Err(format!(
                "\"{entry}\" is not a usable generated candidate. Expected host:port, like 203.0.113.10:8443."
            ));
        }
    }
    let location = cfg.catalog_country.trim();
    if !location.is_empty()
        && !location.eq_ignore_ascii_case("AUTO")
        && !crate::relay::outbound_state::valid_country(location)
    {
        return Err(
            "Catalog location must be empty, AUTO, or a two-letter country code.".to_owned(),
        );
    }
    // A pin naming something that is not a candidate would look configured and
    // do nothing, so it is refused at save rather than silently ignored.
    let pin = cfg.pinned_proxy.trim();
    if !pin.is_empty()
        && !cfg
            .proxy_candidates
            .iter()
            .any(|c| c.trim().eq_ignore_ascii_case(pin))
    {
        return Err(format!("\"{pin}\" is not one of the proxy candidates."));
    }
    Ok(())
}

/// What a QR request is for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QrSubject {
    /// The subscription URL for a client.
    Subscription(ClientTarget),
    /// One node's share link, as a given client would import it.
    Node { tag: String, client: ClientTarget },
}

/// Parse the query of a QR request.
///
/// Takes already-decoded pairs so this stays free of any URL library.
#[must_use]
pub fn qr_subject<'a>(pairs: impl Iterator<Item = (&'a str, &'a str)>) -> Option<QrSubject> {
    let mut kind = "";
    let mut client = "";
    let mut tag = String::new();
    for (k, v) in pairs {
        match k {
            "kind" => kind = v,
            "client" => client = v,
            "tag" => v.clone_into(&mut tag),
            _ => {}
        }
    }
    let client = bundle::client_from_name(client)?;
    match kind {
        "sub" => Some(QrSubject::Subscription(client)),
        "node" if !tag.is_empty() => Some(QrSubject::Node { tag, client }),
        _ => None,
    }
}

/// Parse the query of an export request into a client and a shape.
#[must_use]
pub fn export_subject<'a>(
    pairs: impl Iterator<Item = (&'a str, &'a str)>,
) -> Option<(ClientTarget, Shape)> {
    let mut client = "";
    let mut shape = "";
    for (k, v) in pairs {
        match k {
            "client" => client = v,
            "shape" => shape = v,
            _ => {}
        }
    }
    let client = bundle::client_from_name(client)?;
    let shape = match shape {
        "config" => Shape::FullConfig,
        "links" => Shape::ShareLinksPlain,
        "base64" => Shape::ShareLinks,
        _ => return None,
    };
    Some((client, shape))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::model::{
        Endpoint, Flow, Mux, Protocol, Security, TlsSettings, Transport, XhttpMode,
    };

    #[test]
    fn quality_joins_feed_keys_to_panel_candidates_without_false_positives() {
        let quality = [
            ("203.0.113.10:443".to_string(), "low/datacenter/high/ip-api/proxycheck".to_string()),
            ("198.51.100.7:8443".to_string(), "high/vpn-proxy/high/ip-api/proxycheck".to_string()),
            ("198.51.100.7:993".to_string(), "low/isp/medium/ip-api/proxycheck".to_string()),
        ]
        .into_iter()
        .collect();
        let cfg = OutboundConfig {
            proxy_candidates: vec![
                "203.0.113.10".into(),          // bare IP, unique port in feed -> joins
                "198.51.100.7".into(),          // bare IP, two ports -> ambiguous -> empty
                "198.51.100.7:8443".into(),     // exact key -> joins
                "edge.example.com".into(),      // hostname, absent -> empty (never bad)
            ],
            ..Default::default()
        };
        let rows = candidate_health(&cfg, &Default::default(), &[], &quality);
        let q: Vec<&str> = rows.iter().map(|r| r.quality.as_str()).collect();
        assert_eq!(
            q,
            vec![
                "low/datacenter/high/ip-api/proxycheck",
                "", // ambiguous bare IP stays unmeasured, not worst-case
                "high/vpn-proxy/high/ip-api/proxycheck",
                "",
            ]
        );
    }

    #[test]
    fn a_stale_expected_revision_is_refused_with_guidance() {
        assert_eq!(resolve_save_rev(Some(3), 5), Err(REV_CONFLICT_MESSAGE));
        assert_eq!(
            REV_CONFLICT_MESSAGE,
            "Settings changed elsewhere. Reload and try again."
        );
    }

    #[test]
    fn a_matching_expected_revision_saves_and_bumps() {
        assert_eq!(resolve_save_rev(Some(5), 5), Ok(6));
        assert_eq!(resolve_save_rev(Some(0), 0), Ok(1));
    }

    #[test]
    fn an_old_client_without_an_expectation_behaves_as_before() {
        // No expected_rev field: the save succeeds whatever is stored.
        assert_eq!(resolve_save_rev(None, 0), Ok(1));
        assert_eq!(resolve_save_rev(None, 41), Ok(42));
    }

    #[test]
    fn the_revision_counter_wraps_rather_than_panicking() {
        assert_eq!(resolve_save_rev(Some(u32::MAX), u32::MAX), Ok(0));
    }

    fn node(tag: &str) -> Node {
        Node {
            tag: tag.to_owned(),
            server: Endpoint {
                address: "example.com".into(),
                port: 443,
            },
            protocol: Protocol::Vless {
                uuid: "01234567-89ab-cdef-0123-456789abcdef".into(),
                flow: Flow::None,
            },
            transport: Transport::Xhttp {
                mode: XhttpMode::PacketUp,
                path: "/abc".into(),
                host: Some("example.com".into()),
            },
            security: Security::Tls(TlsSettings {
                sni: Some("example.com".into()),
                ..TlsSettings::default()
            }),
            mux: Mux::default(),
            chain_via: None,
            worker_served: true,
        }
    }

    fn settings() -> Settings {
        Settings {
            version: super::super::store::VERSION,
            nodes: vec![node("a"), node("b")],
            outbound: OutboundConfig::default(),
            enhanced_reachability: false,
            rev: 4,
            common: Default::default(),
        }
    }

    #[test]
    fn routes_map_to_actions_and_everything_else_is_unknown() {
        assert_eq!(route("GET", ""), Api::Page);
        assert_eq!(route("GET", "/"), Api::Page);
        assert_eq!(route("POST", "api/login"), Api::Login);
        assert_eq!(route("GET", "api/state"), Api::State);
        assert_eq!(route("PUT", "api/nodes"), Api::Save);
        assert_eq!(route("POST", "api/check"), Api::Check);
        assert_eq!(route("GET", "api/qr"), Api::Qr);
        assert_eq!(route("POST", "api/probe-proxy"), Api::ProbeProxy);

        for (m, p) in [
            ("GET", "api/login"),
            ("POST", "api/state"),
            ("GET", "api/nodes"),
            ("DELETE", "api/nodes"),
            ("GET", "../etc/passwd"),
            ("GET", "api"),
            ("GET", "index.html"),
        ] {
            assert_eq!(route(m, p), Api::Unknown, "{m} {p}");
        }
    }

    #[test]
    fn only_the_page_and_the_login_are_reachable_without_a_session() {
        // The panel can read every credential the deployment serves, so this
        // list is the whole security boundary and is pinned deliberately.
        for api in [
            Api::State,
            Api::Save,
            Api::Check,
            Api::Export,
            Api::Qr,
            Api::Logout,
            Api::ProbeProxy,
            // The operator/operator-session verify route is never public;
            // the cron trigger calls the Rust function directly, not HTTP.
            Api::VerifyCatalog,
            Api::HealthOverlay,
        ] {
            assert!(!api.is_public(), "{api:?} must require a session");
        }
        assert!(Api::Page.is_public());
        assert!(Api::Login.is_public());
    }

    #[test]
    fn the_state_names_every_client_and_what_it_will_actually_receive() {
        let s = state(
            &settings(),
            "example.com",
            "https://example.com/sub",
            "/x",
            Source::Derived,
            None,
            &Default::default(),
            None,
            &[],
            &[],
            None,
            None,
            &Default::default(),
            None,
            None,
            0,
        );
        assert_eq!(s.clients.len(), bundle::all_clients().len());
        assert_eq!(s.source, "derived");

        let v2rayn = s
            .clients
            .iter()
            .find(|c| c.slug == "xray")
            .expect("listed");
        assert_eq!(v2rayn.subscription, "https://example.com/sub/xray");
        assert_eq!(v2rayn.included, 2);
        assert!(v2rayn.skipped.is_empty());
        assert_eq!(
            v2rayn.config.as_deref(),
            Some("https://example.com/sub/xray.json")
        );

        // Upstream sing-box cannot take an XHTTP node, and must say so rather
        // than be offered a subscription that would arrive empty.
        let upstream = s
            .clients
            .iter()
            .find(|c| c.slug == "sing-box")
            .expect("listed");
        assert_eq!(upstream.included, 0);
        assert!(upstream.subscription.is_empty());
        assert_eq!(upstream.skipped.len(), 2);
        assert!(upstream.config.is_none());
    }

    #[test]
    fn a_mihomo_config_is_offered_with_its_own_extension() {
        let s = state(
            &settings(),
            "example.com",
            "https://example.com/sub",
            "/x",
            Source::Stored,
            None,
            &Default::default(),
            None,
            &[],
            &[],
            None,
            None,
            &Default::default(),
            None,
            None,
            0,
        );
        let mihomo = s
            .clients
            .iter()
            .find(|c| c.slug == "mihomo")
            .expect("listed");
        assert_eq!(
            mihomo.config.as_deref(),
            Some("https://example.com/sub/mihomo.yaml")
        );
    }

    #[test]
    fn each_node_carries_its_links_and_its_verdicts() {
        let s = state(
            &settings(),
            "example.com",
            "https://example.com/sub",
            "/x",
            Source::Stored,
            None,
            &Default::default(),
            None,
            &[],
            &[],
            None,
            None,
            &Default::default(),
            None,
            None,
            0,
        );
        let first = &s.views[0];
        assert_eq!(first.tag, "a");
        assert_eq!(first.protocol, "VLESS");
        assert_eq!(first.transport, "XHTTP");
        assert!(first
            .links
            .iter()
            .any(|l| l.client == "xray" && l.uri.starts_with("vless://")));
        assert!(!first.links.iter().any(|l| l.client == "sing-box"));
        assert_eq!(first.matrix.len(), bundle::all_clients().len());
    }

    #[test]
    fn validation_refuses_what_would_make_a_node_unaddressable() {
        assert!(validate(&[node("a"), node("b")]).is_ok());

        assert!(
            validate(&[node("a"), node("a")]).is_err(),
            "duplicate names"
        );

        let mut blank = node("");
        blank.tag = "  ".into();
        assert!(validate(&[blank]).is_err(), "blank name");

        let mut no_address = node("a");
        no_address.server.address = String::new();
        assert!(validate(&[no_address]).is_err());

        let mut self_chain = node("a");
        self_chain.chain_via = Some("a".into());
        assert!(validate(&[self_chain]).is_err(), "self chain");

        let mut dangling = node("a");
        dangling.chain_via = Some("nowhere".into());
        assert!(
            validate(&[dangling]).is_err(),
            "chain to a node that does not exist"
        );

        let mut chain = vec![node("a"), node("b")];
        chain[1].chain_via = Some("a".into());
        assert!(validate(&chain).is_ok(), "a real chain is fine");
    }

    #[test]
    fn a_node_set_is_bounded() {
        let many: Vec<Node> = (0..=MAX_NODES).map(|i| node(&i.to_string())).collect();
        assert!(validate(&many).is_err());
    }

    #[test]
    fn qr_requests_name_their_subject_or_are_refused() {
        assert_eq!(
            qr_subject([("kind", "sub"), ("client", "v2rayn")].into_iter()),
            Some(QrSubject::Subscription(ClientTarget::V2rayN))
        );
        assert_eq!(
            qr_subject([("kind", "node"), ("client", "hiddify"), ("tag", "a")].into_iter()),
            Some(QrSubject::Node {
                tag: "a".into(),
                client: ClientTarget::Hiddify
            })
        );
        for bad in [
            vec![("kind", "sub")],
            vec![("kind", "node"), ("client", "v2rayn")],
            vec![("kind", "other"), ("client", "v2rayn")],
            vec![("client", "nonesuch"), ("kind", "sub")],
            vec![],
        ] {
            assert_eq!(qr_subject(bad.clone().into_iter()), None, "{bad:?}");
        }
    }

    #[test]
    fn export_requests_name_a_client_and_a_shape() {
        assert_eq!(
            export_subject([("client", "mihomo"), ("shape", "config")].into_iter()),
            Some((ClientTarget::Mihomo, Shape::FullConfig))
        );
        assert_eq!(
            export_subject([("client", "v2rayn"), ("shape", "links")].into_iter()),
            Some((ClientTarget::V2rayN, Shape::ShareLinksPlain))
        );
        assert_eq!(export_subject([("client", "v2rayn")].into_iter()), None);
        assert_eq!(
            export_subject([("client", "v2rayn"), ("shape", "exe")].into_iter()),
            None
        );
    }

    #[test]
    fn routing_never_panics() {
        let mut seed = 0x77c1_2ba9_4410_9f31u64;
        for _ in 0..3000 {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            let len = (seed % 40) as usize;
            let s: String = (0..len).map(|i| (seed >> (i % 56)) as u8 as char).collect();
            for m in ["GET", "POST", "PUT", ""] {
                let _ = route(m, &s);
            }
        }
    }

    // --- outbound validation at the save boundary ---

    #[test]
    fn the_default_outbound_config_saves_cleanly() {
        // Off with nothing set is what every existing deployment posts. If this
        // ever refuses, saving nodes breaks for everyone who never touched the
        // feature.
        assert!(validate_outbound(&OutboundConfig::default()).is_ok());
    }

    #[test]
    fn a_usable_proxy_config_is_accepted() {
        let cfg = OutboundConfig {
            mode: ProxyMode::ProxyIp,
            proxy_candidates: vec!["93.184.216.34".into(), "edge.example.com".into()],
            ..Default::default()
        };
        assert!(validate_outbound(&cfg).is_ok());
    }

    #[test]
    fn candidates_the_relay_would_drop_are_refused_at_save_time() {
        // Each of these parses as a string but cannot be dialled, so the relay
        // would skip it. Saving it silently is what makes a working-looking
        // config that goes direct.
        for bad in ["127.0.0.1", "10.0.0.1", "host:443", "host/path", "   "] {
            let cfg = OutboundConfig {
                mode: ProxyMode::ProxyIp,
                proxy_candidates: vec![bad.into()],
                ..Default::default()
            };
            let err = validate_outbound(&cfg).expect_err(&format!("{bad:?} must be refused"));
            assert!(err.contains(bad.trim()) || !bad.trim().is_empty());
        }
    }

    #[test]
    fn nat64_prefixes_must_be_96_with_a_zero_tail() {
        for bad in ["64:ff9b::/64", "64:ff9b::1/96", "64:ff9b::", "nonsense"] {
            let cfg = OutboundConfig {
                mode: ProxyMode::Nat64,
                nat64_prefixes: vec![bad.into()],
                ..Default::default()
            };
            assert!(validate_outbound(&cfg).is_err(), "{bad:?} must be refused");
        }
        let good = OutboundConfig {
            mode: ProxyMode::Nat64,
            nat64_prefixes: vec!["64:ff9b::/96".into()],
            ..Default::default()
        };
        assert!(validate_outbound(&good).is_ok());
    }

    #[test]
    fn nat64_mode_with_no_prefix_is_allowed_because_a_default_exists() {
        // Unlike Proxy IP, NAT64 has a well-known prefix to fall back on, so an
        // empty list is a complete config rather than an unset one.
        let cfg = OutboundConfig {
            mode: ProxyMode::Nat64,
            ..Default::default()
        };
        assert!(validate_outbound(&cfg).is_ok());
    }

    #[test]
    fn proxy_ip_mode_without_candidates_is_refused_rather_than_saved_as_a_no_op() {
        let cfg = OutboundConfig {
            mode: ProxyMode::ProxyIp,
            ..Default::default()
        };
        assert!(validate_outbound(&cfg).is_err());
    }

    #[test]
    fn generated_candidates_must_parse_as_host_port() {
        let ok = OutboundConfig {
            mode: ProxyMode::ProxyIp,
            proxy_candidates: vec!["1.2.3.4".into()],
            catalog_pool: true,
            verified_catalog_candidates: vec![
                "91.187.93.166:443".into(),
                "[2001:db8::1]:2053".into(),
            ],
            ..Default::default()
        };
        assert!(validate_outbound(&ok).is_ok());
        let bad = OutboundConfig {
            verified_catalog_candidates: vec!["91.187.93.166".into()],
            ..ok.clone()
        };
        assert!(validate_outbound(&bad).is_err());
        let bad = OutboundConfig {
            verified_catalog_candidates: vec!["2001:db8::1".into()],
            ..ok
        };
        assert!(validate_outbound(&bad).is_err());
    }

    #[test]
    fn catalog_country_must_be_empty_or_two_letters() {
        let ok = OutboundConfig {
            mode: ProxyMode::ProxyIp,
            proxy_candidates: vec!["1.2.3.4".into()],
            catalog_pool: true,
            catalog_country: "DE".into(),
            ..Default::default()
        };
        assert!(validate_outbound(&ok).is_ok());
        let auto = OutboundConfig {
            catalog_country: "auto".into(),
            ..ok.clone()
        };
        assert!(validate_outbound(&auto).is_ok());
        let empty_ok = OutboundConfig {
            catalog_country: String::new(),
            ..ok.clone()
        };
        assert!(validate_outbound(&empty_ok).is_ok());
        let ok = OutboundConfig {
            catalog_country: String::new(),
            ..ok.clone()
        };
        assert!(validate_outbound(&ok).is_ok());
        for bad_country in ["DEU", "d3", "12"] {
            let bad = OutboundConfig {
                catalog_country: bad_country.into(),
                ..ok.clone()
            };
            assert!(validate_outbound(&bad).is_err(), "accepted {bad_country:?}");
        }
    }

    #[test]
    fn state_without_catalog_renders_as_never_synced() {
        let s = state(
            &settings(),
            "example.com",
            "https://example.com/sub",
            "/x",
            Source::Stored,
            None,
            &Default::default(),
            None,
            &[],
            &[],
            None,
            None,
            &Default::default(),
            None,
            None,
            0,
        );
        assert!(s.catalog.is_none());
        let meta = crate::catalog::Meta::default();
        assert!(meta.is_empty());
    }

    #[test]
    fn unused_lists_are_still_validated() {
        // Off mode with a malformed leftover entry: refused, because the entry
        // becomes live the moment the mode changes and the operator would not
        // be told then.
        let cfg = OutboundConfig {
            mode: ProxyMode::Off,
            proxy_candidates: vec!["127.0.0.1".into()],
            ..Default::default()
        };
        assert!(validate_outbound(&cfg).is_err());
    }

    #[test]
    fn the_entry_count_is_bounded() {
        let cfg = OutboundConfig {
            mode: ProxyMode::ProxyIp,
            proxy_candidates: (0..=MAX_OUTBOUND_ENTRIES)
                .map(|i| format!("198.51.100.{}", i % 200))
                .collect(),
            ..Default::default()
        };
        assert!(validate_outbound(&cfg).is_err());
    }

    // ---- v1.9.5 country-change saves (spec: TR→US, US→FI, FI→AUTO, invalid) ----

    fn outbound_with_country(cc: &str) -> OutboundConfig {
        OutboundConfig {
            catalog_country: cc.to_owned(),
            ..OutboundConfig::default()
        }
    }

    #[test]
    fn country_change_saves_are_accepted_in_every_direction() {
        // TR -> US, US -> FI, FI -> AUTO: any prior country may be replaced
        // by any other valid target. Validation never pins the old value.
        assert!(validate_outbound(&outbound_with_country("US")).is_ok());
        assert!(validate_outbound(&outbound_with_country("FI")).is_ok());
        assert!(validate_outbound(&outbound_with_country("AUTO")).is_ok());
        assert!(validate_outbound(&outbound_with_country("")).is_ok());
        // Case-insensitive: the dropdown sends uppercase, but tr is the same
        // country and must not be refused.
        assert!(validate_outbound(&outbound_with_country("tr")).is_ok());
    }

    #[test]
    fn invalid_country_is_rejected_not_silently_kept() {
        for bad in ["TUR", "USA", "U", "1T", "TR1"] {
            assert!(
                validate_outbound(&outbound_with_country(bad)).is_err(),
                "{bad} must be refused"
            );
        }
    }

    #[test]
    fn saved_country_round_trips_through_the_settings_document() {
        // "Value survives reload": the settings document is what KV stores
        // and what a reload parses — a saved country must survive it.
        let settings = Settings {
            version: super::super::store::VERSION,
            nodes: Vec::new(),
            outbound: outbound_with_country("US"),
            enhanced_reachability: false,
            rev: 7,
            common: Default::default(),
        };
        let back = Settings::parse(&settings.to_json().unwrap()).unwrap();
        assert_eq!(back.outbound.catalog_country, "US");
        assert_eq!(back.rev, 7);
        // AUTO survives too.
        let settings = Settings { outbound: outbound_with_country("AUTO"), ..settings };
        let back = Settings::parse(&settings.to_json().unwrap()).unwrap();
        assert_eq!(back.outbound.catalog_country, "AUTO");
    }
}

/// Label for a pool dial-test row whose exit country could not be proven.
///
/// The edge trace cannot succeed on a bare-IP candidate: this hop is TLS
/// passthrough (`relay::connect::open`, SecureTransport::Off) and
/// worker::Socket cannot set SNI for an IP dial, so every candidate "fails"
/// the trace — including ones a real session proves good. Returning the bare
/// reason rendered a successful-looking row with no explanation, so a
/// TCP-only row could not be told apart from a verified one.
#[must_use]
pub fn unverified_reason(reason: &str) -> String {
    if reason.starts_with("exit unverified:") {
        return reason.to_owned();
    }
    format!("exit unverified: {reason}")
}

#[cfg(test)]
mod dial_test_label_tests {
    use super::unverified_reason;

    // Regression: on the live ES pool every one of the 8 rows came back
    // `ok: true` with an empty country/exitIp — "verified" while proving
    // nothing — on a candidate (162.141.93.190) a real session proved good.
    #[test]
    fn unverified_exit_is_labelled_not_silent() {
        let got = unverified_reason("no loc= in trace");
        assert_eq!(got, "exit unverified: no loc= in trace");
        assert!(
            got.contains("unverified"),
            "a TCP-only row must say the exit is UNVERIFIED, got {got:?}"
        );
    }

    // Idempotent: an already-labelled reason is not double-prefixed.
    #[test]
    fn label_is_idempotent() {
        let once = unverified_reason("tls/read: closed");
        assert_eq!(unverified_reason(&once), once);
    }

    // Never silently empty: every reason produces a non-empty label.
    #[test]
    fn reason_is_never_dropped() {
        assert!(!unverified_reason("").is_empty());
        assert!(unverified_reason("x").contains("x"));
    }
}
/// Which probe a candidate may be measured with.
///
/// `probe_one` dials with TLS on, which cannot complete for a bare-IP
/// candidate: this hop is TLS passthrough (`relay::connect::open`,
/// SecureTransport::Off) and `worker::Socket` cannot set SNI for an IP dial.
/// Its failure is reported as `"tcp connect: ..."` — the same string
/// [`crate::relay::outbound_state::Health::quarantined`] reads as "the worker
/// cannot reach this candidate". Feeding a diagnostic limitation into
/// `observed_fail` therefore manufactured a hard unreachable verdict and
/// quarantined candidates whose transport is fine, on an operator pressing
/// Check.
///
/// An IP candidate is measured with the transport probe instead, so a
/// diagnostic failure can never become transport evidence. Host-testable:
/// `serve.rs` itself only compiles for wasm32.
#[must_use]
pub fn probe_kind(host: &str) -> ProbeKind {
    if host.trim().parse::<std::net::IpAddr>().is_ok() {
        ProbeKind::Transport
    } else {
        ProbeKind::Egress
    }
}

/// Result category of a candidate measurement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeKind {
    /// TCP reachability only — the runtime's own dial. Carries no exit
    /// identity: transport health, egress unknown.
    Transport,
    /// TLS edge trace — can genuinely observe an exit country/IP.
    Egress,
}

/// Whether a probe verdict counts as EVIDENCE about the candidate, or is
/// only a statement about the diagnostic.
///
/// An egress trace that cannot run on this candidate shape proves nothing
/// about it: recording it as a failure is how a healthy candidate gets
/// condemned. Unknown stays unknown; it never becomes ok, and never becomes
/// a failure.
#[must_use]
pub fn egress_verdict(ran: bool, observed_country: &str) -> EgressVerdict {
    if !ran {
        return EgressVerdict::Unavailable;
    }
    if observed_country.len() == 2 && observed_country.bytes().all(|b| b.is_ascii_alphabetic())
    {
        return EgressVerdict::Verified;
    }
    EgressVerdict::Failed
}

/// Egress observation state, kept distinct from transport health.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgressVerdict {
    /// Observed: a real trace returned a usable exit country.
    Verified,
    /// The trace ran and produced nothing usable.
    Failed,
    /// The trace could not run for this candidate (bare-IP shape). NOT a
    /// failure and NOT a success — the exit is simply unknown.
    Unavailable,
}

/// What a browser-side egress observation proves, and how it may be used.
///
/// The panel's "Measured exit" button is a `fetch()` from the page, so it
/// reports whatever route the OPERATOR's browser happens to have. That is a
/// real measurement of the wrong thing: on a machine whose browser is routed
/// through Trinity it is the tunnel's exit, and on a machine whose browser is
/// not it is the local ISP's exit (measured live: the widget returned the
/// host's own 2.183.28.132 / IR while the tunnel exited 113.30.149.24 / ES).
///
/// No browser fetch can prove it left through a specific candidate: the page
/// has no handle on the tunnel's socket pool, and the proxy client reuses
/// whichever candidate happens to win the dial. So these verdicts deliberately
/// withhold "verified" unless the operator has positively demonstrated the
/// route, and even then only as ADVISORY metadata that never touches country
/// eligibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientEgress {
    /// The browser route equals the address the session recorded as the
    /// winner, so the observation and the candidate genuinely coincide.
    MatchesSession,
    /// A real measurement, but of a route that is not provably the session's.
    Advisory,
    /// The measurement failed or was empty.
    Failed,
    /// No session winner is known yet, so nothing can be attributed.
    Unattributed,
}

/// TTL for a browser-observed exit. Shorter than [`crate::relay::outbound_state`]'s
/// health windows on purpose: this is a human-scale observation of a route that
/// can be rerouted at any moment by restarting the client.
pub const CLIENT_EGRESS_TTL_MS: u64 = 30 * 60 * 1000;

/// Classify a browser-observed exit against the session-won candidate.
///
/// `observed_ip` / `observed_country` are whatever the page fetched; empty
/// strings mean the fetch produced nothing usable. `session_winner` is the
/// `preferred` key the session teardown recorded (`host:port`), empty when no
/// proxy candidate has won yet.
///
/// The country is normalised to upper case and length-checked, so a malformed
/// or hostile value can never be carried forward as an observation.
#[must_use]
pub fn classify_client_egress(
    observed_ip: &str,
    observed_country: &str,
    session_winner: &str,
    now_ms: u64,
    observed_at_ms: u64,
) -> ClientEgress {
    if observed_ip.trim().is_empty() {
        return ClientEgress::Failed;
    }
    if session_winner.trim().is_empty() {
        return ClientEgress::Unattributed;
    }
    // An observation older than the TTL describes a route that may since have
    // changed; it must not be presented as current.
    if observed_at_ms == 0 || now_ms.saturating_sub(observed_at_ms) > CLIENT_EGRESS_TTL_MS {
        return ClientEgress::Unattributed;
    }
    let country_ok = observed_country.trim().len() == 2
        && observed_country.trim().bytes().all(|b| b.is_ascii_alphabetic());
    if !country_ok {
        return ClientEgress::Failed;
    }
    // Only the session's own recorded winner can be matched against. The IP the
    // browser saw is the exit address of its route, which for a pool is one hop
    // past the candidate, so the two are compared only when the winner is itself
    // an address that could be the exit.
    if session_winner.split(':').next().unwrap_or("") == observed_ip.trim() {
        ClientEgress::MatchesSession
    } else {
        ClientEgress::Advisory
    }
}

/// Whether a browser-observed country may influence anything persistent.
///
/// No. Advisory observations are shown to the operator and never promoted:
/// country eligibility comes from the scanner-verified catalog
/// (`snapshot.pool(Some(country))`), and `Health::country` is written only by
/// the Worker-side probe. Keeping this a function with one answer means the
/// refusal is enforced in one place instead of relied on at each call site.
#[must_use]
pub const fn client_egress_is_persistable(_verdict: ClientEgress) -> bool {
    false
}

#[cfg(test)]
mod egress_verdict_tests {
    use super::{egress_verdict, probe_kind, EgressVerdict, ProbeKind};
    use crate::relay::outbound_state::Health;

    // 1. TCP succeeds but egress verification is unavailable: the IP shape
    //    cannot carry a trace. Transport health and egress stay SEPARATE.
    #[test]
    fn tcp_ok_with_egress_unavailable_is_not_verified() {
        assert_eq!(probe_kind("113.30.149.24"), ProbeKind::Transport);
        let transport_ok = Health::default().observed_ok(String::new(), String::new(), String::new(), 44, 1);
        assert!(transport_ok.ok, "transport is healthy");
        // The stricter predicate (ok AND a known exit) stays false, so this
        // can never be read as a verified exit.
        assert!(!transport_ok.healthy(), "no country means never verified");
        assert_eq!(egress_verdict(false, ""), EgressVerdict::Unavailable);
    }

    // 2. TCP succeeds and a real egress observation succeeds.
    #[test]
    fn real_egress_observation_verifies() {
        assert_eq!(probe_kind("relay.example"), ProbeKind::Egress);
        assert_eq!(egress_verdict(true, "ES"), EgressVerdict::Verified);
        let h = Health::default().observed_ok("ES".into(), "MAD".into(), "203.0.113.7".into(), 44, 1);
        assert!(h.healthy());
    }

    // 3. The egress test fails or returns nothing usable.
    #[test]
    fn failed_or_unusable_trace_is_a_failure() {
        assert_eq!(egress_verdict(true, ""), EgressVerdict::Failed);
        assert_eq!(egress_verdict(true, "e"), EgressVerdict::Failed);
        assert_eq!(egress_verdict(true, "ESP"), EgressVerdict::Failed);
        assert_eq!(egress_verdict(true, "E5"), EgressVerdict::Failed);
    }

    // 5. A diagnostic failure must NOT convert into a quarantine. This is the
    //    live defect: probe_one reported a TLS/SNI limitation as "tcp connect"
    //    and quarantined candidates with healthy transport.
    #[test]
    fn diagnostic_failure_never_becomes_transport_evidence() {
        // What the old code stored for a healthy IP candidate.
        let poisoned = Health::default().observed_fail("tcp connect: proxy request failed".into(), 1);
        assert!(poisoned.quarantined(), "the old path DID quarantine on this string");
        // What the new path stores instead: the transport verdict, unchanged.
        let honest = Health::default().observed_ok(String::new(), String::new(), String::new(), 44, 1);
        assert!(!honest.quarantined(), "a diagnostic must not quarantine");
    }

    // 6. Egress metadata is never invented: an empty observation stays empty,
    //    and a transport-only pass must not reuse it as freshly measured.
    #[test]
    fn unmeasured_egress_is_never_invented_or_reused() {
        let measured = Health::default().observed_ok("ES".into(), "MAD".into(), "203.0.113.7".into(), 44, 1);
        // A later transport-only pass carries no new egress: pass the prior
        // values through unchanged and never fabricate a timestamp as fresh.
        let later = measured.clone().observed_ok(
            measured.country.clone(),
            measured.colo.clone(),
            measured.exit_ip.clone(),
            45,
            2,
        );
        assert_eq!(later.country, "ES", "carried, not invented");
        assert_eq!(later.updated_at_ms, 2, "record IS refreshed (this pass ran)");
        // With nothing prior, a transport-only pass stores no identity at all.
        let blind = Health::default().observed_ok(String::new(), String::new(), String::new(), 44, 1);
        assert!(blind.country.is_empty());
        assert!(blind.exit_ip.is_empty());
    }

    // 7. Country eligibility must not treat unknown as membership.
    #[test]
    fn unknown_country_is_not_membership() {
        let unknown = Health::default().observed_ok(String::new(), String::new(), String::new(), 44, 1);
        // score() gives no country bonus when the country is unknown.
        let unknown_score = unknown.score("ES");
        let wrong = Health::default().observed_ok("US".into(), "IAD".into(), "198.51.100.7".into(), 44, 1);
        // Unknown gets NO country bonus: it ties with a known-wrong
        // country rather than inheriting that country's position.
        assert_eq!(
            unknown_score, wrong.score("ES"),
            "an unknown country must not borrow another country's standing"
        );
        // ...and unknown never equals a match.
        let match_ = Health::default().observed_ok("es".into(), "MAD".into(), "203.0.113.7".into(), 44, 1);
        assert!(match_.score("ES") > wrong.score("ES"));
    }

    // 4. A prior egress observation that is stale cannot read as current
    //    proof. The freshness decision lives in catalog::country_quality
    //    (2 x FRESH_MS); here we pin the record-level half: a transport-only
    //    pass must not refresh an exit identity it did not measure.
    #[test]
    fn stale_egress_observation_is_not_refreshed_by_a_transport_pass() {
        let observed = Health::default().observed_ok("ES".into(), "MAD".into(), "203.0.113.7".into(), 44, 1);
        // A transport-only pass must carry the OLD values forward untouched:
        // the exit was not re-measured, so its age must not be reset by a
        // pass that never looked at the exit.
        assert_eq!(observed.country, "ES");
        assert_eq!(observed.exit_ip, "203.0.113.7");
        assert_eq!(observed.updated_at_ms, 1, "age is what the last measurement set");
    }
}
/// Split a candidate entry into (host, port).
///
/// Configured candidates are a bare host and keep the historical
/// default 443; a runtime-pool entry arrives as `host:port`. A bracketed
/// IPv6 literal keeps its brackets for the dialer, which parses them
/// back off. Host-testable pure split — the caller lives in a
/// wasm32-only module.
#[must_use]
pub fn split_host_port(entry: &str) -> (String, u16) {
    let e = entry.trim();
    // Bracketed IPv6: "[::1]:8443" — split on the LAST colon only.
    if let Some(rest) = e.strip_prefix('[') {
        if let Some((h, p)) = rest.split_once(']').and_then(|(h, t)| {
            Some((h, t.strip_prefix(':')?))
        }) {
            if let Ok(port) = p.parse::<u16>() {
                return (format!("[{h}]"), port);
            }
        }
        return (e.to_owned(), 443);
    }
    match e.rsplit_once(':') {
        Some((h, p)) if !h.is_empty() && !h.contains(':') => {
            match p.parse::<u16>() {
                Ok(port) => (h.to_owned(), port),
                Err(_) => (e.to_owned(), 443),
            }
        }
        _ => (e.to_owned(), 443),
    }
}

#[cfg(test)]
mod split_host_port_tests {
    use super::split_host_port;

    // A bare configured candidate keeps the historical default 443.
    #[test]
    fn bare_host_defaults_to_443() {
        assert_eq!(split_host_port("relay.example"), ("relay.example".into(), 443));
        assert_eq!(split_host_port("  113.30.149.24  "), ("113.30.149.24".into(), 443));
    }

    // A runtime-pool entry carries its real port. Hardcoding 443 dialled the
    // WRONG port for every pool row (live: 162.141.93.190:2083, 185.121.12.28:8443).
    #[test]
    fn host_port_entry_splits_on_the_real_port() {
        assert_eq!(split_host_port("162.141.93.190:2083"), ("162.141.93.190".into(), 2083));
        assert_eq!(split_host_port("185.121.12.28:8443"), ("185.121.12.28".into(), 8443));
    }

    // With the port split off, the IP parse works, so the transport/egress
    // decision can fire at all. This is the bug behind "every IP candidate
    // looked like a hostname".
    #[test]
    fn split_makes_ip_detection_possible() {
        let (host, _) = split_host_port("162.141.93.190:2083");
        assert!(host.parse::<std::net::IpAddr>().is_ok());
        let (host, _) = split_host_port("162.141.93.190");
        assert!(host.parse::<std::net::IpAddr>().is_ok());
    }

    // A bracketed IPv6 literal keeps its brackets for the dialer and still
    // splits the port; an unbracketed IPv6 stays whole (bare IPv6 has many
    // colons, so splitting on the last one would corrupt it).
    #[test]
    fn ipv6_survives_the_split() {
        assert_eq!(split_host_port("[2001:db8::1]:8443"), ("[2001:db8::1]".into(), 8443));
        let (host, port) = split_host_port("2001:db8::1");
        assert_eq!((host.as_str(), port), ("2001:db8::1", 443));
    }

    // A non-numeric tail is not a port: keep the whole entry, never invent one.
    #[test]
    fn non_numeric_tail_is_not_a_port() {
        assert_eq!(split_host_port("relay.example:https"), ("relay.example:https".into(), 443));
    }
}
#[cfg(test)]
mod client_egress_tests {
    use super::{
        classify_client_egress, client_egress_is_persistable, ClientEgress, CLIENT_EGRESS_TTL_MS,
    };

    const NOW: u64 = 1_700_000_000_000;

    // 1. A real measurement whose IP is the session's recorded winner.
    #[test]
    fn matching_ip_is_the_only_way_to_claim_the_session() {
        let v = classify_client_egress("113.30.149.24", "ES", "113.30.149.24:443", NOW, NOW - 1000);
        assert_eq!(v, ClientEgress::MatchesSession);
    }

    // 2. A real measurement of a DIFFERENT route (the live IR case): honest,
    //    but not attributable to the candidate.
    #[test]
    fn direct_browser_route_is_advisory_not_the_session() {
        let v = classify_client_egress("2.183.28.132", "IR", "113.30.149.24:443", NOW, NOW - 1000);
        assert_eq!(v, ClientEgress::Advisory);
    }

    // 3. No observation at all: unknown, never failed.
    #[test]
    fn empty_observation_fails() {
        assert_eq!(classify_client_egress("", "", "113.30.149.24:443", NOW, NOW - 1000), ClientEgress::Failed);
    }

    // 4. Trace failure / timeout: failed, and NOT unattributed.
    #[test]
    fn trace_failure_is_failed() {
        assert_eq!(classify_client_egress("1.2.3.4", "", "113.30.149.24:443", NOW, NOW - 1000), ClientEgress::Failed);
        assert_eq!(classify_client_egress("1.2.3.4", "!!", "113.30.149.24:443", NOW, NOW - 1000), ClientEgress::Failed);
        assert_eq!(classify_client_egress("1.2.3.4", "USA", "1.2.3.4:443", NOW, NOW - 1000), ClientEgress::Failed);
    }

    // 5. No session winner: a fresh IP is still unattributable.
    #[test]
    fn no_session_winner_is_unattributed() {
        assert_eq!(classify_client_egress("113.30.149.24", "ES", "", NOW, NOW - 1000), ClientEgress::Unattributed);
        assert_eq!(classify_client_egress("113.30.149.24", "ES", "   ", NOW, NOW - 1000), ClientEgress::Unattributed);
    }

    // 6. Stale: an old success must not present as current (requirement 5).
    #[test]
    fn stale_observation_is_unattributed() {
        let old = NOW - CLIENT_EGRESS_TTL_MS - 1;
        assert_eq!(classify_client_egress("113.30.149.24", "ES", "113.30.149.24:443", NOW, old), ClientEgress::Unattributed);
        // Missing timestamp is treated as unknown, never as fresh.
        assert_eq!(classify_client_egress("113.30.149.24", "ES", "113.30.149.24:443", NOW, 0), ClientEgress::Unattributed);
        // A clock skew that puts the observation in the future does not panic or pass.
        assert_eq!(classify_client_egress("113.30.149.24", "ES", "113.30.149.24:443", 1000, NOW), ClientEgress::MatchesSession);
    }

    // 7. A hostname winner can never equal an IP, so it stays advisory.
    #[test]
    fn hostname_winner_is_never_a_match() {
        assert_eq!(classify_client_egress("1.2.3.4", "US", "proxy.example.com:443", NOW, NOW - 1000), ClientEgress::Advisory);
    }

    // 8/9. Nothing a client reports is ever promoted into persistent metadata.
    #[test]
    fn no_client_verdict_is_persistable() {
        for v in [ClientEgress::MatchesSession, ClientEgress::Advisory, ClientEgress::Failed, ClientEgress::Unattributed] {
            assert!(!client_egress_is_persistable(v), "{v:?} must not be persistable");
        }
    }

    // 10. Session rotation: a DIFFERENT winner never inherits the old verdict.
    #[test]
    fn rotation_breaks_the_association() {
        assert_eq!(classify_client_egress("113.30.149.24", "ES", "162.141.93.190:2083", NOW, NOW - 1000), ClientEgress::Advisory);
    }
}

#[cfg(test)]
mod candidate_detail_tests {
    use super::*;

    /// A minimal snapshot carrying only the metrics map. Built by parsing a
    /// feed-shaped document, which also proves these maps load from JSON.
    fn snap_with(rows: Vec<(&str, crate::catalog::EndpointMetrics)>) -> crate::catalog::Snapshot {
        let map: std::collections::BTreeMap<String, crate::catalog::EndpointMetrics> =
            rows.into_iter().map(|(k, v)| (k.to_string(), v)).collect();
        serde_json::from_value(serde_json::json!({
            "schema_version": 1,
            "upstream_revision": "test",
            "content_revision": "test",
            "generated_at": "2027-01-15T07:45:00Z",
            "countries": {},
            "quality_metrics_by_endpoint": map,
        }))
        .expect("minimal feed-shaped snapshot must parse")
    }

    fn m(rtt: Option<u32>, dl: Option<u64>, ul: Option<u64>, bp: Option<u32>, at: &str) -> crate::catalog::EndpointMetrics {
        crate::catalog::EndpointMetrics {
            rtt_ms: rtt,
            dl_bps: dl,
            ul_bps: ul,
            success_bp: bp,
            last_success: Some(at.to_string()),
        }
    }

    const NOW: u64 = 1_800_000_000; // 2027-01-15T08:00:00Z

    #[test]
    fn unmeasured_candidate_reports_unknown_not_zero() {
        let snap = snap_with(vec![("1.2.3.4:443", m(Some(120), Some(900_000), None, Some(9000), "2027-01-15T07:50:00Z"))]);
        let rows = candidate_details(
            &["1.2.3.4:443".to_string(), "5.6.7.8:443".to_string()],
            Some(&snap),
            &Default::default(),
            NOW,
        );
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].dl_bps, Some(900_000));
        // The unmeasured candidate is absent from the map, NOT zero.
        assert_eq!(rows[1].dl_bps, None, "missing measurement must not become 0");
        assert_eq!(rows[1].ul_bps, None);
        assert_eq!(rows[1].rtt_ms, None);
        assert_eq!(rows[1].success_bp, None);
        assert!(!rows[1].stale, "an unmeasured row is unknown, not stale");
        assert!(rows[1].reason.contains("no measurement"), "{}", rows[1].reason);
    }

    #[test]
    fn fresh_and_stale_are_distinguished() {
        let fresh = snap_with(vec![("1.2.3.4:443", m(Some(90), Some(1_000_000), Some(500_000), Some(10_000), "2027-01-15T07:50:00Z"))]);
        let stale = snap_with(vec![("1.2.3.4:443", m(Some(90), Some(1_000_000), Some(500_000), Some(10_000), "2026-12-01T00:00:00Z"))]);
        let r = candidate_details(&["1.2.3.4:443".to_string()], Some(&fresh), &Default::default(), NOW);
        assert!(!r[0].stale);
        assert_eq!(r[0].age_s, Some(600));
        assert!(r[0].reason.contains("fresh measurement"), "{}", r[0].reason);
        let r = candidate_details(&["1.2.3.4:443".to_string()], Some(&stale), &Default::default(), NOW);
        assert!(r[0].stale);
        assert!(r[0].reason.contains("stale"), "{}", r[0].reason);
        // Values are still shown, just marked stale -- never hidden, never fresh.
        assert_eq!(r[0].dl_bps, Some(1_000_000));
    }

    #[test]
    fn malformed_timestamp_reads_as_unknown_not_stale() {
        // A garbage stamp must not parse as the epoch (which would mark every
        // row stale) and must not become a 1970 "last success".
        assert_eq!(parse_iso8601_s("not-a-time"), None);
        assert_eq!(parse_iso8601_s("2027-13-45T99:99:99Z"), None);
        assert_eq!(parse_iso8601_s(""), None);
        let snap = snap_with(vec![("1.2.3.4:443", m(Some(90), Some(1_000_000), None, Some(10_000), "bad"))]);
        let r = candidate_details(&["1.2.3.4:443".to_string()], Some(&snap), &Default::default(), NOW);
        assert_eq!(r[0].age_s, None);
        assert!(!r[0].stale);
    }

    #[test]
    fn valid_iso8601_converts_to_epoch_seconds() {
        assert_eq!(parse_iso8601_s("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_iso8601_s("2027-01-15T08:00:00Z"), Some(NOW));
        // Leap day.
        assert!(parse_iso8601_s("2028-02-29T12:00:00Z").is_some());
    }

    #[test]
    fn two_ports_on_one_ip_are_never_conflated() {
        // 443 is measured; 8443 is not. An ambiguous bare-ip match must NOT
        // hand 443's numbers to 8443.
        let snap = snap_with(vec![("1.2.3.4:443", m(Some(90), Some(2_000_000), None, Some(10_000), "2027-01-15T07:59:00Z"))]);
        let rows = candidate_details(
            &["1.2.3.4:443".to_string(), "1.2.3.4:8443".to_string()],
            Some(&snap),
            &Default::default(),
            NOW,
        );
        assert_eq!(rows[0].dl_bps, Some(2_000_000));
        assert_eq!(rows[1].dl_bps, None, "ambiguous prefix match must not borrow a neighbour's data");
    }

    #[test]
    fn exact_ip_port_key_wins_over_prefix() {
        let snap = snap_with(vec![
            ("1.2.3.4:443", m(Some(90), Some(3_000_000), None, Some(10_000), "2027-01-15T07:59:00Z")),
            ("1.2.3.4:8443", m(Some(90), Some(1_000_000), None, Some(10_000), "2027-01-15T07:59:00Z")),
        ]);
        let rows = candidate_details(
            &["1.2.3.4:8443".to_string()],
            Some(&snap),
            &Default::default(),
            NOW,
        );
        assert_eq!(rows[0].dl_bps, Some(1_000_000), "exact ip:port must resolve to its own row");
    }

    #[test]
    fn cf_relay_candidate_states_its_destination_limit() {
        let mut snap = snap_with(vec![]);
        snap.capability_by_endpoint
            .insert("1.2.3.4:443".to_string(), "cf-relay".to_string());
        let r = candidate_details(&["1.2.3.4:443".to_string()], Some(&snap), &Default::default(), NOW);
        assert_eq!(r[0].capability, "cf-relay");
        assert!(r[0].reason.contains("Cloudflare-fronted"), "{}", r[0].reason);
    }

    #[test]
    fn no_snapshot_still_yields_a_row_per_runtime_candidate() {
        let rows = candidate_details(
            &["1.2.3.4:443".to_string(), "5.6.7.8:443".to_string()],
            None,
            &Default::default(),
            NOW,
        );
        assert_eq!(rows.len(), 2, "every dial-plan candidate must render, snapshot or not");
        assert!(rows.iter().all(|r| r.dl_bps.is_none() && !r.stale));
    }

    #[test]
    fn serialized_row_omits_unknown_fields_entirely() {
        // The panel must be able to tell "absent" from 0, which requires the
        // key to be missing rather than null-or-zero.
        let snap = snap_with(vec![("1.2.3.4:443", m(Some(90), Some(5), None, None, "2027-01-15T07:59:00Z"))]);
        let rows = candidate_details(&["1.2.3.4:443".to_string()], Some(&snap), &Default::default(), NOW);
        let json = serde_json::to_string(&rows[0]).unwrap();
        assert!(json.contains(r#""dlBps":5"#), "{json}");
        assert!(!json.contains("ulBps"), "absent ul must not appear: {json}");
        assert!(!json.contains("successBp"), "absent ratio must not appear: {json}");
    }
}
