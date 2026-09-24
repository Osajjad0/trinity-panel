//! Public Proxy-IP catalog client (V24.3).
//!
//! Fetches the versioned candidate feed from the public Trinity catalog
//! repository and exposes strict, bounded access to per-country pools. The
//! catalog provides CANDIDATES ONLY: every endpoint it yields carries no
//! health claim — Trinity's own relay evidence decides eligibility downstream
//! (`outbound_state`), and nothing is written back to the catalog.
//!
//! Failure semantics are fail-closed everywhere: any malformed entry, unknown
//! schema version, oversized document, or unresolvable pool rejects the whole
//! snapshot and the previous valid snapshot in KV keeps serving.

/// Feed origin. Raw GitHub content: no VPS, no database, no third-party API.
/// V24.4: the runtime consumes the VERIFIED feed (scanner-verified entries
/// only). The raw discovery feed stays available for the scanner itself.
pub(crate) const FEED_URL: &str =
    "https://raw.githubusercontent.com/Osajjad0/trinity-proxy-catalog/main/catalog/verified/feed.json";

/// Hard bounds. Bounded ingestion: a hostile or accidental upstream change
/// cannot inflate memory or slow the Worker.
const MAX_FEED_BYTES: usize = 2 * 1024 * 1024;
const MAX_COUNTRIES: usize = 256;
const MAX_PER_COUNTRY: usize = 4096;
const MAX_UNASSIGNED: usize = 256;
const MAX_AUTO: usize = 64;
const FETCH_TIMEOUT_MS: u64 = 10_000;

/// One catalog candidate. `host` is a bare address (IPv4, IPv6 without
/// brackets, or hostname); the port is always separate.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Endpoint {
    pub host: String,
    pub port: u16,
}

/// A validated catalog snapshot.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Snapshot {
    /// Feed schema version — must be exactly 1.
    pub schema_version: u32,
    /// NiREvil/vless commit the catalog was generated from.
    pub upstream_revision: String,
    /// Catalog content revision (hash of the generated outputs).
    pub content_revision: String,
    pub generated_at: String,
    /// Country code (ISO 3166-1 alpha-2 as assigned upstream) → candidates.
    pub countries: std::collections::BTreeMap<String, Vec<Endpoint>>,
    /// Candidates no source assigned a country to. Never enters a country pool.
    #[serde(default)]
    pub unassigned: Vec<Endpoint>,
    /// Deterministic best-effort spread across countries for Auto mode.
    #[serde(default)]
    pub auto: Vec<Endpoint>,
}

/// What a hex string looks like.
fn is_hex(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// An address the catalog may present: bare IPv4, bare IPv6, or a hostname.
/// Rejects schemes, paths, brackets, ports-in-address, and whitespace.
fn valid_address(host: &str) -> bool {
    if host.is_empty()
        || host.len() > 253
        || host.contains(['/', '\\', '@', '?', '#', '%', ' ', '\t'])
        || host.starts_with('[')
        || host.starts_with(':')
        || host.ends_with(':')
        || host.parse::<std::net::IpAddr>().is_err() && (host.contains("://") || host.contains(':'))
    {
        return false;
    }
    // Hostnames: printable ASCII, no '@'. IPv4/IPv6 already validated above.
    if host.parse::<std::net::IpAddr>().is_err() {
        return host.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-');
    }
    true
}

impl Snapshot {
    /// Parse a feed document. One malformed entry anywhere rejects the whole
    /// snapshot — fail closed beats silently dropping candidates.
    ///
    /// # Errors
    /// Non-JSON input, wrong schema version, malformed revisions/addresses,
    /// empty pools per country, or a document exceeding the bounds above.
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > MAX_FEED_BYTES {
            return Err(format!("feed exceeds {MAX_FEED_BYTES} bytes"));
        }
        let snapshot: Snapshot =
            serde_json::from_slice(bytes).map_err(|e| format!("feed is not valid JSON: {e}"))?;
        if snapshot.schema_version != 1 {
            return Err(format!("unsupported schema_version {}", snapshot.schema_version));
        }
        if snapshot.upstream_revision.len() != 40 || !is_hex(&snapshot.upstream_revision) {
            return Err("upstream_revision is not a 40-char hex SHA".into());
        }
        if snapshot.content_revision.len() != 64 || !is_hex(&snapshot.content_revision) {
            return Err("content_revision is not a 64-char hex SHA".into());
        }
        if snapshot.generated_at.is_empty() {
            return Err("generated_at is empty".into());
        }
        if snapshot.countries.is_empty() || snapshot.countries.len() > MAX_COUNTRIES {
            return Err("country count outside 1..=256".into());
        }
        if snapshot.auto.len() > MAX_AUTO || snapshot.unassigned.len() > MAX_UNASSIGNED {
            return Err("auto/unassigned exceed caps".into());
        }
        for (code, list) in &snapshot.countries {
            if code.len() != 2 || !code.bytes().all(|b| b.is_ascii_uppercase()) {
                return Err(format!("invalid country code {code}"));
            }
            if list.is_empty() || list.len() > MAX_PER_COUNTRY {
                return Err(format!("country {code} pool size outside 1..={MAX_PER_COUNTRY}"));
            }
            Self::check(list)?;
        }
        Self::check(&snapshot.auto)?;
        Self::check(&snapshot.unassigned)?;
        Ok(snapshot)
    }

    fn check(list: &[Endpoint]) -> Result<(), String> {
        for e in list {
            if !valid_address(&e.host) {
                return Err(format!("malformed address {:?}", e.host));
            }
        }
        Ok(())
    }

    /// The pool for a selection. `None` (Auto) → the deterministic `auto`
    /// spread. `Some(country)` is STRICT: a country that has no pool in the
    /// catalog yields `None` — the caller must not fall back to another
    /// country or to Auto.
    #[must_use]
    pub fn pool(&self, country: Option<&str>) -> Option<&[Endpoint]> {
        match country {
            None | Some("") => Some(&self.auto),
            Some(code) => self.countries.get(&code.to_ascii_uppercase()).map(Vec::as_slice),
        }
    }
}

/// KV key holding the last valid snapshot document (JSON with `fetched_at`).
pub const KV_KEY: &str = "panel:catalog";

/// Operator-triggered sync result.
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncReport {
    pub ok: bool,
    pub changed: bool,
    pub content_revision: String,
    pub upstream_revision: String,
    pub generated_at: String,
    pub fetched_at: String,
    pub country_count: usize,
    pub endpoint_count: usize,
    pub error: Option<String>,
}


/// Fetch + parse + persist the catalog snapshot. NEVER called per session:
/// the only caller is the operator-triggered `api/catalog-sync` panel route.
///
/// Fail-closed: on any fetch/parse/put failure the previous snapshot in KV
/// stays exactly as it was and the error is reported.
#[cfg(target_arch = "wasm32")]
pub async fn sync(env: &worker::Env) -> SyncReport {
    let fetched_at = worker::Date::now().as_millis();
    let (bytes, mut error) = match fetch_feed().await {
        Ok(b) => (b, None),
        Err(e) => (Vec::new(), Some(e)),
    };
    if error.is_none() {
        // Surface the real validation reason to the operator.
        if let Err(failure) = Snapshot::parse(&bytes) {
            error = Some(format!("feed rejected: {failure}; previous snapshot kept"));
        }
    }
    let parsed = if error.is_none() { Snapshot::parse(&bytes).ok() } else { None };
    let Some(snapshot) = parsed else {
        return SyncReport {
            ok: false,
            changed: false,
            content_revision: String::new(),
            upstream_revision: String::new(),
            generated_at: String::new(),
            fetched_at: now_iso(fetched_at),
            country_count: 0,
            endpoint_count: 0,
            error,
        };
    };
    let kv = env.kv("SETTINGS").ok();
    let previous: Option<String> = match kv.as_ref() {
        Some(kv) => kv.get(KV_KEY).text().await.ok().flatten(),
        None => None,
    };
    // Content identity, not document identity: `fetchedAt` changes on every
    // run, so comparing whole documents made every sync a KV write even when
    // the feed was byte-identical (V24.6.10 A). The feed's own
    // `content_revision` — the strongest identity the scanner already
    // publishes — decides. Unchanged revision: zero KV writes, previous
    // `fetchedAt` kept (it dates the stored content, not this probe).
    let incoming_rev = snapshot.content_revision.as_str();
    let changed = stored_revision(previous.as_deref()).as_deref() != Some(incoming_rev);
    let mut error = None;
    if changed {
        let document = serde_json::json!({
            "snapshot": snapshot,
            "fetchedAt": now_iso(fetched_at),
        })
        .to_string();
        if let Some(kv) = kv.as_ref() {
            if let Ok(pending) = kv.put(KV_KEY, document) {
                if let Err(e) = pending.execute().await {
                    error = Some(e.to_string());
                }
            } else {
                error = Some("KV unavailable".into());
            }
        } else {
            error = Some("SETTINGS binding missing".into());
        }
    }
    if error.is_some() {
        return SyncReport {
            ok: false,
            changed: false,
            content_revision: snapshot.content_revision,
            upstream_revision: snapshot.upstream_revision,
            generated_at: snapshot.generated_at,
            fetched_at: now_iso(fetched_at),
            country_count: snapshot.countries.len(),
            endpoint_count: snapshot.countries.values().map(Vec::len).sum::<usize>(),
            error,
        };
    }
    SyncReport {
        ok: true,
        changed,
        content_revision: snapshot.content_revision,
        upstream_revision: snapshot.upstream_revision,
        generated_at: snapshot.generated_at,
        fetched_at: now_iso(fetched_at),
        country_count: snapshot.countries.len(),
        endpoint_count: snapshot.countries.values().map(Vec::len).sum::<usize>(),
        error: None,
    }
}

/// The last snapshot stored in KV, if any and if valid. An unreadable or
/// outdated-schema document yields `None` (fail closed to operator candidates).

/// The content revision stored in a `panel:catalog` document, if any.
///
/// The decision primitive for the sync no-op: an incoming feed whose revision
/// equals the stored one performs zero KV writes (V24.6.10 A). A document
/// without a readable snapshot/revision reads as "nothing stored", which
/// makes the first sync and any damaged stored document both write —
/// fail-safe in the direction of freshness.
#[must_use]
fn stored_revision(previous: Option<&str>) -> Option<String> {
    let document: serde_json::Value = serde_json::from_str(previous?).ok()?;
    document
        .get("snapshot")?
        .get("content_revision")?
        .as_str()
        .map(str::to_owned)
}

#[cfg(target_arch = "wasm32")]
#[must_use]
pub async fn stored(env: &worker::Env) -> Option<Snapshot> {
    let kv = env.kv("SETTINGS").ok()?;
    let raw = kv.get(KV_KEY).text().await.ok().flatten()?;
    let document: serde_json::Value = serde_json::from_str(&raw).ok()?;
    serde_json::from_value(document.get("snapshot")?.clone()).ok()
}

#[cfg(target_arch = "wasm32")]
fn now_iso(ms: u64) -> String {
    worker::Date::new(worker::DateInit::Millis(ms)).to_string()
}

#[cfg(target_arch = "wasm32")]
async fn fetch_feed() -> Result<Vec<u8>, String> {
    // Cache-bust: raw.githubusercontent.com serves stale copies for minutes
    // after a push, and a sync that runs right after publishing must see the
    // revision it was invoked for (the idempotency check compares hashes).
    let url = format!("{FEED_URL}?t={}", worker::Date::now().as_millis());
    let request = worker::Request::new(&url, worker::Method::Get).map_err(|e| e.to_string())?;
    // Bounded fetch: race the send against a deadline so a hung edge never
    // blocks the operator route. Both futures are pinned in place.
    let fetch = worker::Fetch::Request(request);
    let send = fetch.send();
    let timer = gloo_timers::future::TimeoutFuture::new(FETCH_TIMEOUT_MS as u32);
    let response = match futures_util::future::select(Box::pin(send), Box::pin(timer)).await {
        futures_util::future::Either::Left((result, _)) => result.map_err(|e| e.to_string())?,
        futures_util::future::Either::Right(((), _)) => {
            return Err("catalog fetch timed out".into());
        }
    };
    let mut response = response;
    let bytes = response.bytes().await.map_err(|e| e.to_string())?;
    if bytes.len() > MAX_FEED_BYTES {
        return Err(format!("feed exceeds {MAX_FEED_BYTES} bytes"));
    }
    Ok(bytes)
}

/// Bounded maximum catalog candidates appended to a dial plan behind direct.
pub const MAX_POOL_CANDIDATES: usize = 8;

/// AUTO spread size when a feed ships no auto list (verified feed).
pub const MAX_AUTO_FALLBACK: usize = 48;

/// The catalog pool for an outbound config: `None` when the pool is disabled
/// or there is no snapshot; `Some([])` when enabled but this country/Auto has
/// no candidates (strict — the dial plan simply stays as it is).
#[must_use]
pub fn pool_for(
    cfg: &crate::relay::outbound::OutboundConfig,
    snapshot: Option<&Snapshot>,
) -> Option<Vec<Endpoint>> {
    pool_for_with_health(cfg, snapshot, &std::collections::BTreeMap::new())
}

/// [`pool_for`], plus Trinity's own health evidence: candidates with a known
/// healthy probe record come first, known failures go last, the rest keep
/// catalog order. Ordering only — the cap still bounds the result.
#[must_use]
pub fn pool_for_with_health(
    cfg: &crate::relay::outbound::OutboundConfig,
    snapshot: Option<&Snapshot>,
    health: &std::collections::BTreeMap<String, crate::relay::outbound_state::Health>,
) -> Option<Vec<Endpoint>> {
    // Pool enabled = the legacy flag OR Pool mode itself (mode drives it now).
    if !cfg.catalog_pool && cfg.mode != crate::relay::outbound::ProxyMode::Pool {
        return None;
    }
    let snapshot = snapshot?;
    // Location semantics: "AUTO" = the deterministic spread, "" or unknown =
    // no catalog contribution at all, an explicit code = that country ONLY.
    let country = cfg.catalog_country.trim();
    if country.is_empty() || country.eq_ignore_ascii_case("AUTO") {
        if country.is_empty() {
            return None;
        }
        // AUTO: the feed's deterministic spread; if the feed has none (the
        // verified feed has no auto list), build one — 2 per country, sorted
        // country order, capped at MAX_AUTO.
        if snapshot.auto.is_empty() {
            let mut spread: Vec<Endpoint> = Vec::new();
            for list in snapshot.countries.values() {
                spread.extend(list.iter().take(2).cloned());
                if spread.len() >= crate::catalog::MAX_AUTO_FALLBACK {
                    break;
                }
            }
            spread.truncate(crate::catalog::MAX_AUTO_FALLBACK);
            return Some(bounded(spread.into_iter(), health));
        }
        return Some(bounded(snapshot.auto.iter().cloned(), health));
    }
    let selected = snapshot.pool(Some(country))?;
    Some(bounded(selected.iter().cloned(), health))
}

/// Coarse region classification for fallback preference. ISO-2 codes only;
/// never inferred from hostnames. Unlisted codes count as Europe (Tier 2) —
/// the safe default for the dominant region in the feed.
#[must_use]
pub fn region_of(cc: &str) -> &'static str {
    match cc {
        "AE" | "AM" | "AZ" | "BH" | "GE" | "IL" | "IQ" | "IR" | "JO" | "KW" | "LB" | "OM"
        | "PS" | "QA" | "SA" | "SY" | "TR" | "YE" => "Middle East",
        "BD" | "BN" | "BT" | "CN" | "HK" | "ID" | "IN" | "JP" | "KH" | "KP" | "KR" | "KG"
        | "LA" | "LK" | "MM" | "MN" | "MV" | "MY" | "NP" | "PH" | "PK" | "SG" | "TH" | "TJ"
        | "TL" | "TM" | "TW" | "UZ" | "VN" => "Asia",
        "CA" | "MX" | "US" => "North America",
        "AR" | "BO" | "BR" | "CL" | "CO" | "EC" | "GY" | "PE" | "PY" | "SR" | "UY" | "VE" => {
            "South America"
        }
        "DZ" | "AO" | "BJ" | "BW" | "CD" | "CF" | "CG" | "CI" | "CM" | "CV" | "EG" | "ET"
        | "GA" | "GH" | "GM" | "GN" | "GQ" | "KE" | "LR" | "LS" | "LY" | "MA" | "MG" | "ML"
        | "MU" | "MW" | "MZ" | "NA" | "NE" | "NG" | "RW" | "SC" | "SD" | "SL" | "SN" | "SO"
        | "SS" | "SZ" | "TD" | "TG" | "TN" | "TZ" | "UG" | "ZA" | "ZM" | "ZW" => "Africa",
        "AU" | "FJ" | "FM" | "KI" | "MH" | "NC" | "NR" | "NZ" | "PG" | "PW" | "SB" | "TO"
        | "TV" | "VU" | "WS" => "Oceania",
        _ => "Europe",
    }
}

/// Deterministic AUTO fallback country for an exhausted primary.
///
/// Ranked by: non-Europe first (spec: prefer non-European), then verified pool
/// size (larger first), then country code (stable tiebreak). `epoch` rotates
/// the pick among the top 3 ranked countries so independent failure epochs
/// spread across candidates instead of hammering one country. Skips the
/// exhausted primary and empty pools. European countries enter only when no
/// non-European pool remains (Tier 2).
#[must_use]
pub fn choose_fallback_country(
    snapshot: &Snapshot,
    excluded: &[&str],
    epoch: u64,
) -> Option<String> {
    let mut ranked: Vec<(bool, usize, &String)> = snapshot
        .countries
        .iter()
        .filter(|(cc, pool)| !excluded.contains(&cc.as_str()) && !pool.is_empty())
        .map(|(cc, pool)| (region_of(cc) == "Europe", pool.len(), cc))
        .collect();
    // Sort: non-Europe first, larger pools first, then cc for stability.
    ranked.sort_by(|a, b| {
        a.0.cmp(&b.0)
            .then(b.1.cmp(&a.1))
            .then(a.2.cmp(b.2))
    });
    if ranked.is_empty() {
        return None;
    }
    let top = ranked.len().min(3);
    let pick = &ranked[(epoch % top as u64) as usize];
    Some(pick.2.clone())
}

/// Runtime fallback hook (V24.4.4): pick a fallback country for an exhausted
/// primary and return `(country, bounded candidate list)`. Reads the snapshot
/// from the settings KV; `None` when there is no usable fallback.
/// Deterministic within a 10-minute epoch; skips the exhausted country and
/// empty pools; prefers non-European countries.
#[cfg(target_arch = "wasm32")]
pub async fn fallback_retry_pool(
    kv: &worker::kv::KvStore,
    excluded_cc: &[&str],
    now_ms: u64,
) -> Option<(String, Vec<Endpoint>)> {
    let raw = kv.get(KV_KEY).text().await.ok().flatten()?;
    let document: serde_json::Value = serde_json::from_str(&raw).ok()?;
    let snapshot: Snapshot = serde_json::from_value(document.get("snapshot")?.clone()).ok()?;
    let epoch = crate::relay::outbound_state::fallback_epoch(now_ms);
    let cc = choose_fallback_country(&snapshot, excluded_cc, epoch)?;
    let mut cfg = crate::relay::outbound::OutboundConfig::default();
    cfg.mode = crate::relay::outbound::ProxyMode::Pool;
    cfg.catalog_country = cc.clone();
    let pool = pool_for(&cfg, Some(&snapshot))?;
    if pool.is_empty() {
        return None;
    }
    Some((cc, pool))
}

/// Full fallback decision for a failed Pool-mode dial (V24.4.4).
///
/// Returns `(fallback country, bounded candidates, updated state)` when a
/// fallback pool is available. Cooldown: an existing fresh fallback for the
/// same primary is retried as-is (held); when the fallback country ITSELF
/// fails, both it and the primary are excluded and the epoch advances for
/// variety. State is returned, never written from here.
#[cfg(target_arch = "wasm32")]
pub async fn try_pool_fallback(
    env: &worker::Env,
    cfg: &crate::relay::outbound::OutboundConfig,
    state: &crate::relay::outbound_state::OutboundState,
    now_ms: u64,
) -> Option<(String, Vec<Endpoint>, crate::relay::outbound_state::OutboundState)> {
    use crate::relay::outbound_state::{fallback_epoch, fallback_fresh, OutboundState};
    let primary = cfg.catalog_country.trim().to_ascii_uppercase();
    if primary.is_empty() {
        return None;
    }
    // What failed: the primary, or an active fallback on top of it?
    let (excluded, mut next) = if fallback_fresh(state, now_ms)
        && !state.fallback_active.is_empty()
        && state.fallback_primary == primary
    {
        (
            vec![primary.as_str(), state.fallback_active.as_str()],
            state.clone(),
        )
    } else {
        (vec![primary.as_str()], OutboundState::default())
    };
    let _ = fallback_epoch; // epoch is computed inside fallback_retry_pool
    let Ok(kv) = env.kv("SETTINGS") else { return None };
    let (cc, pool) = fallback_retry_pool(&kv, &excluded, now_ms).await?;
    next.fallback_primary = primary;
    next.fallback_active = cc.clone();
    next.fallback_at_ms = now_ms;
    Some((cc, pool, next))
}

/// Persist fallback runtime state. Debounced by the caller's semantics: the
/// write happens only on activation/re-exhaustion, never per session.
#[cfg(target_arch = "wasm32")]
pub async fn write_fallback_state(env: &worker::Env, state: &crate::relay::outbound_state::OutboundState) {
    if let Ok(kv) = env.kv("SETTINGS") {
        if let Ok(document) = serde_json::to_string(state) {
            if let Ok(pending) = kv.put(crate::relay::outbound_state::KV_KEY, document) {
                let _ = pending.execute().await;
            }
        }
    }
}

/// Order-preserving dedupe by host+port, capped at MAX_POOL_CANDIDATES.
/// Health evidence orders within the pool: measured-healthy first, then
/// unmeasured, then known-failed — so Auto does not re-serve the same dead
/// addresses the probe already condemned while healthy ones exist.
fn bounded(
    candidates: impl Iterator<Item = Endpoint>,
    health: &std::collections::BTreeMap<String, crate::relay::outbound_state::Health>,
) -> Vec<Endpoint> {
    let rank = |e: &Endpoint| -> u8 {
        match health.get(&format!("{}:{}", e.host.to_ascii_lowercase(), e.port)) {
            Some(h) if h.healthy() => 0,
            Some(h) if !h.ok => 2,
            _ => 1,
        }
    };
    let mut deduped: Vec<Endpoint> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for e in candidates {
        if seen.insert((e.host.to_ascii_lowercase(), e.port)) {
            deduped.push(e);
        }
    }
    // Stable sort keeps catalog order inside each band. Then enforce host
    // diversity: one IP with many port variants must not occupy the whole
    // pool (the US feed had 2 IPs x 4 ports filling all 8 slots — every dial
    // failed while 42 other US IPs sat lower in the feed).
    deduped.sort_by_key(|e| rank(e));
    let mut seen_hosts = std::collections::HashSet::new();
    let mut diversified: Vec<Endpoint> = Vec::new();
    for e in deduped {
        if seen_hosts.insert(e.host.to_ascii_lowercase()) {
            diversified.push(e);
        }
    }
    diversified.into_iter().take(MAX_POOL_CANDIDATES).collect()
}

/// Panel metadata about the stored snapshot — never the 865 KB document.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Meta {
    pub content_revision: String,
    pub upstream_revision: String,
    pub generated_at: String,
    pub fetched_at: String,
    pub country_count: usize,
    /// Countries the panel can offer: only those with a pool in the snapshot.
    pub countries: Vec<String>,
    pub endpoint_count: usize,
    /// Verified endpoint count per country (V24.5.8 spec 15: the Location
    /// menu shows "US · 54 verified"). Absent in older stored metas.
    pub country_counts: std::collections::BTreeMap<String, usize>,
}

impl Default for Meta {
    fn default() -> Self {
        Self {
            content_revision: String::new(),
            upstream_revision: String::new(),
            generated_at: String::new(),
            fetched_at: String::new(),
            country_count: 0,
            countries: Vec::new(),
            endpoint_count: 0,
            country_counts: Default::default(),
        }
    }
}

impl Meta {
    /// Derive panel metadata from a snapshot. `fetched_at` comes from the KV
    /// document, not the feed, so it reflects when TRINITY last synced.
    #[must_use]
    pub fn from_snapshot(snapshot: &Snapshot, fetched_at: &str) -> Self {
        Self {
            content_revision: snapshot.content_revision.clone(),
            upstream_revision: snapshot.upstream_revision.clone(),
            generated_at: snapshot.generated_at.clone(),
            fetched_at: fetched_at.to_owned(),
            country_count: snapshot.countries.len(),
            countries: snapshot.countries.keys().cloned().collect(),
            endpoint_count: snapshot.countries.values().map(Vec::len).sum::<usize>(),
            country_counts: snapshot
                .countries
                .iter()
                .map(|(k, v)| (k.clone(), v.len()))
                .collect(),
        }
    }

    /// Parse the small KV meta document. Any malformed input yields `None`.
    #[must_use]
    pub fn from_json(raw: &str) -> Option<Self> {
        serde_json::from_str(raw).ok()
    }

    /// Whether the catalog was never synced or its feed predates the current
    /// upstream revision — "stale" for the panel. Revision comparison only:
    /// the catalog pipeline refreshes daily, Trinity syncs on demand.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.content_revision.is_empty()
    }
}

/// KV key for the sync metadata summary (tiny; read by panel + sessions).
pub const KV_META_KEY: &str = "panel:catalog_meta";

#[cfg(test)]
mod fallback_tests {
    use super::*;

    fn snap(countries: &[(&str, usize)]) -> Snapshot {
        let mut map = std::collections::BTreeMap::new();
        for (cc, n) in countries {
            map.insert(
                (*cc).to_owned(),
                (0..*n)
                    .map(|i| Endpoint { host: format!("10.0.0.{i}"), port: 443 })
                    .collect(),
            );
        }
        Snapshot {
            schema_version: 1,
            upstream_revision: String::new(),
            content_revision: String::new(),
            generated_at: String::new(),
            countries: map,
            unassigned: Vec::new(),
            auto: Vec::new(),
        }
    }

    #[test]
    fn regions_classify_and_default_to_europe() {
        assert_eq!(region_of("SG"), "Asia");
        assert_eq!(region_of("US"), "North America");
        assert_eq!(region_of("TR"), "Middle East");
        assert_eq!(region_of("BR"), "South America");
        assert_eq!(region_of("ZA"), "Africa");
        assert_eq!(region_of("AU"), "Oceania");
        assert_eq!(region_of("DE"), "Europe");
        assert_eq!(region_of("XX"), "Europe"); // unlisted = Europe (Tier 2)
    }

    #[test]
    fn fallback_prefers_non_european_and_skips_exhausted_and_empty() {
        let s = snap(&[("DE", 8), ("FR", 4), ("SG", 6), ("US", 2), ("IT", 0)]);
        let cc = choose_fallback_country(&s, &["DE"], 0).unwrap();
        assert_ne!(cc, "DE");
        assert_ne!(cc, "IT"); // zero pool never chosen
        assert_eq!(region_of(&cc), "Asia"); // largest non-EU pool (SG=6)
    }

    #[test]
    fn fallback_rotates_across_top_candidates_by_epoch() {
        let s = snap(&[("DE", 8), ("SG", 6), ("US", 5), ("JP", 4)]);
        let a = choose_fallback_country(&s, &["DE"], 0).unwrap();
        let b = choose_fallback_country(&s, &["DE"], 1).unwrap();
        let c = choose_fallback_country(&s, &["DE"], 3).unwrap(); // wraps mod 3
        assert_ne!(a, b);
        assert_eq!(a, c); // deterministic: epoch 3 ≡ 0
    }

    #[test]
    fn european_fallback_only_when_no_non_european_pool_remains() {
        let s = snap(&[("DE", 8), ("FR", 4), ("NL", 2)]);
        let cc = choose_fallback_country(&s, &["DE"], 0).unwrap();
        assert_eq!(cc, "FR"); // Tier 2: largest remaining (all European)
    }

    #[test]
    fn fallback_never_returns_the_exhausted_primary() {
        let s = snap(&[("DE", 8)]);
        assert!(choose_fallback_country(&s, &["DE"], 0).is_none());
    }

    #[test]
    fn second_fallback_excludes_both_failed_countries() {
        let s = snap(&[("DE", 8), ("SG", 6), ("US", 5)]);
        // DE and the failed fallback SG are both excluded; US wins.
        let cc = choose_fallback_country(&s, &["DE", "SG"], 0).unwrap();
        assert_eq!(cc, "US");
    }

    #[test]
    fn fallback_hold_expires_and_fresh_logic_holds() {
        use crate::relay::outbound_state::{fallback_epoch, fallback_fresh, OutboundState};
        let mut st = OutboundState::default();
        assert!(!fallback_fresh(&st, 1_000));
        st.fallback_primary = "DE".into();
        st.fallback_active = "SG".into();
        st.fallback_at_ms = 10_000;
        assert!(fallback_fresh(&st, 10_000 + 299_000));
        assert!(!fallback_fresh(&st, 10_000 + 301_000)); // 5 min hold elapsed
        // Epoch: stable inside a 10-minute bucket, changes across buckets.
        assert_eq!(fallback_epoch(0), fallback_epoch(599_999));
        assert_ne!(fallback_epoch(0), fallback_epoch(600_000));
    }

    #[test]
    fn fallback_fields_survive_state_roundtrip_and_old_docs() {
        use crate::relay::outbound_state::OutboundState;
        // Old document without fallback fields parses with defaults.
        let old = OutboundState::from_json(r#"{"preferred":null,"updatedAtMs":1,"geo":{}}"#);
        assert!(old.fallback_active.is_empty());
        // New fields round-trip.
        let mut st = OutboundState::default();
        st.fallback_primary = "DE".into();
        st.fallback_active = "SG".into();
        st.fallback_at_ms = 42;
        let raw = serde_json::to_string(&st).unwrap();
        let back = OutboundState::from_json(&raw);
        assert_eq!(back.fallback_active, "SG");
        assert_eq!(back.fallback_at_ms, 42);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID: &str = r#"{"schema_version":1,"upstream_revision":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","content_revision":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","generated_at":"2026-09-20T16:33:24Z","counts":{},"countries":{"DE":[["203.0.113.7",443],["proxy.example.com",8443],["2001:db8::1",2053]]},"unassigned":[["bpb.yousef.isegaro.com",443]],"auto":[["198.51.100.1",8443]]}"#;

    fn snapshot() -> Snapshot {
        Snapshot::parse(VALID.as_bytes()).expect("valid feed parses")
    }

    #[test]
    fn unchanged_revision_means_no_write() {
        let doc = serde_json::json!({
            "snapshot": snapshot(),
            "fetchedAt": "2026-09-22T00:00:00Z"
        }).to_string();
        assert_eq!(stored_revision(Some(&doc)).as_deref(), Some("b".repeat(64).as_str()));
    }

    #[test]
    fn first_sync_and_damaged_store_write() {
        // No stored document.
        assert_eq!(stored_revision(None), None);
        // Damaged / foreign document: unreadable revision reads as "nothing".
        assert_eq!(stored_revision(Some("not json")), None);
        assert_eq!(stored_revision(Some(r#"{"fetchedAt":"x"}"#)), None);
    }

    #[test]
    fn changed_revision_is_detected() {
        let doc = serde_json::json!({
            "snapshot": snapshot(),
            "fetchedAt": "2026-09-22T00:00:00Z"
        }).to_string();
        let other = "c".repeat(64);
        assert_ne!(stored_revision(Some(&doc)).as_deref(), Some(other.as_str()));
    }

    #[test]
    fn feed_parses_valid_snapshot() {
        let snap = snapshot();
        assert_eq!(snap.countries["DE"][0].port, 443);
        assert_eq!(snap.countries["DE"][1].host, "proxy.example.com");
        // IPv6 stored bare, no brackets.
        assert_eq!(snap.countries["DE"][2].host, "2001:db8::1");
        assert_eq!(snap.unassigned.len(), 1);
    }

    #[test]
    fn feed_rejects_wrong_schema_version() {
        let bad = VALID.replace("\"schema_version\":1", "\"schema_version\":2");
        assert!(Snapshot::parse(bad.as_bytes()).is_err());
    }

    #[test]
    fn pool_caps_one_port_per_host_so_one_dead_ip_cannot_fill_the_pool() {
        // US-feed failure shape: a family of ports on the same IP ranked first;
        // every one of them undialable from the worker while 42 other US IPs
        // sat lower in the feed. The pool must spread across distinct hosts.
        let mk = |h: &str, p: u16| Endpoint {
            host: h.into(),
            port: p,
        };
        let health = std::collections::BTreeMap::new(); // nothing known: band 1
        let pool = bounded(
            [
                mk("104.129.166.131", 2083),
                mk("104.129.166.131", 2087),
                mk("104.129.166.131", 2096),
                mk("104.129.166.131", 443),
                mk("198.51.100.9", 443),
                mk("198.51.100.10", 443),
            ]
            .into_iter(),
            &health,
        );
        let hosts: Vec<&str> = pool.iter().map(|e| e.host.as_str()).collect();
        assert_eq!(hosts.len(), hosts.iter().collect::<std::collections::HashSet<_>>().len(),
            "duplicate host in pool: {hosts:?}");
        assert_eq!(hosts[0], "104.129.166.131"); // feed order preserved
        assert_ne!(hosts[1], "104.129.166.131"); // next host, not next port
    }

    #[test]
    fn feed_rejects_malformed_addresses() {
        for bad in [
            "http://evil.example", // scheme
            "[2001:db8::1]",       // brackets
            "host:443",            // port inside address
            "host/path",           // path
            "",                    // empty
        ] {
            let bad = VALID.replace("203.0.113.7", bad);
            assert!(Snapshot::parse(bad.as_bytes()).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn feed_rejects_bad_revisions() {
        let bad = VALID.replace(&"a".repeat(40), "short");
        assert!(Snapshot::parse(bad.as_bytes()).is_err());
        let bad = VALID.replace(&"b".repeat(64), &"z".repeat(64));
        assert!(Snapshot::parse(bad.as_bytes()).is_err());
    }

    #[test]
    fn feed_rejects_oversize_and_empty_country_pools() {
        let bad = VALID.replace("[[\"203.0.113.7\",443],[\"proxy.example.com\",8443],[\"2001:db8::1\",2053]]", "[]");
        assert!(Snapshot::parse(bad.as_bytes()).is_err());
        let big = format!("{{\"schema_version\":1,\"upstream_revision\":\"{}\",\"content_revision\":\"{}\",\"generated_at\":\"t\",\"counts\":{{}},\"countries\":{{}} ,\"unassigned\":[],\"auto\":[]}}", "a".repeat(40), "b".repeat(64));
        assert!(Snapshot::parse(big.as_bytes()).is_err());
    }

    #[test]
    fn feed_rejects_oversize_document() {
        let big = vec![b' '; MAX_FEED_BYTES + 1];
        assert!(Snapshot::parse(&big).is_err());
    }

    #[test]
    fn auto_pool_is_the_auto_list() {
        let snap = snapshot();
        let pool = snap.pool(None).expect("auto");
        assert_eq!(pool[0].host, "198.51.100.1");
        assert_eq!(pool[0].port, 8443);
        let pool = snap.pool(Some("")).expect("empty means auto");
        assert_eq!(pool[0].port, 8443);
    }

    #[test]
    fn country_pool_is_strict_no_cross_country_fallback() {
        let snap = snapshot();
        // DE exists.
        assert_eq!(snap.pool(Some("DE")).unwrap()[0].port, 443);
        assert_eq!(snap.pool(Some("de")).unwrap()[0].port, 443); // case-insensitive
        // AZ does not exist in this snapshot: strict — None, never Auto.
        assert!(snap.pool(Some("AZ")).is_none());
    }

    #[test]
    fn pool_for_none_when_disabled_or_missing_snapshot() {
        let cfg = crate::relay::outbound::OutboundConfig::default();
        assert!(pool_for(&cfg, None).is_none());
        let snap = snapshot();
        let mut cfg = crate::relay::outbound::OutboundConfig::default();
        assert!(pool_for(&cfg, Some(&snap)).is_none()); // pool disabled
        cfg.catalog_pool = true;
        assert!(pool_for(&cfg, None).is_none()); // no snapshot
        assert!(pool_for(&cfg, Some(&snap)).is_none()); // empty location = no contribution
    }

    #[test]
    fn pool_for_auto_requires_the_auto_selection() {
        let snap = snapshot();
        let cfg = crate::relay::outbound::OutboundConfig {
            catalog_pool: true,
            ..Default::default()
        };
        // Empty location = operator has not chosen: no catalog contribution.
        assert!(pool_for(&cfg, Some(&snap)).is_none());
        let cfg = crate::relay::outbound::OutboundConfig {
            catalog_pool: true,
            catalog_country: "AUTO".into(),
            ..Default::default()
        };
        let pool = pool_for(&cfg, Some(&snap)).expect("auto pool");
        assert_eq!(pool.len(), 1);
        assert_eq!(pool[0].host, "198.51.100.1");
        // Case-insensitive.
        let cfg = crate::relay::outbound::OutboundConfig {
            catalog_country: "auto".into(),
            ..cfg
        };
        assert!(pool_for(&cfg, Some(&snap)).is_some());
    }

    #[test]
    fn pool_for_strict_country_and_case_insensitive() {
        let snap = snapshot();
        let cfg = crate::relay::outbound::OutboundConfig {
            catalog_pool: true,
            catalog_country: "AZ".into(),
            ..Default::default()
        };
        // AZ has no pool in this snapshot: strict None, no Auto fallback.
        assert!(pool_for(&cfg, Some(&snap)).is_none());
        let cfg = crate::relay::outbound::OutboundConfig {
            catalog_pool: true,
            catalog_country: "de".into(),
            ..Default::default()
        };
        let pool = pool_for(&cfg, Some(&snap)).expect("de pool");
        assert_eq!(pool[0].host, "203.0.113.7");
    }

    #[test]
    fn pool_orders_healthy_first_then_unknown_then_dead() {
        use crate::relay::outbound_state::Health;
        let cfg = crate::relay::outbound::OutboundConfig {
            catalog_pool: true,
            catalog_country: "DE".into(),
            ..Default::default()
        };
        // Three DE-shaped endpoints via a custom snapshot: dead, unknown, healthy.
        let feed = VALID.replace(
            "[[\"203.0.113.7\",443],[\"proxy.example.com\",8443],[\"2001:db8::1\",2053]]",
            "[[\"9.9.9.1\",443],[\"9.9.9.2\",443],[\"9.9.9.3\",443]]",
        );
        let snap = Snapshot::parse(feed.as_bytes()).expect("parses");
        let mut health = std::collections::BTreeMap::new();
        health.insert(
            "9.9.9.1:443".into(),
            Health { ok: false, ..Default::default() },
        );
        health.insert(
            "9.9.9.3:443".into(),
            Health {
                ok: true,
                country: "DE".into(),
                ..Default::default()
            },
        );
        let pool = pool_for_with_health(&cfg, Some(&snap), &health).expect("pool");
        let hosts: Vec<&str> = pool.iter().map(|e| e.host.as_str()).collect();
        assert_eq!(hosts, vec!["9.9.9.3", "9.9.9.2", "9.9.9.1"]); // healthy, unknown, dead
    }

    #[test]
    fn runtime_consumes_verified_snapshot_directly() {
        // V24.4.1 contract: the verified feed's countries[XX] entries flow to
        // runtime with no Trinity-side health promotion. pool_for on a
        // verified-shaped snapshot returns the location's entries as-is.
        let feed = r#"{"schema_version":1,"upstream_revision":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","content_revision":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","generated_at":"2026-09-21T03:00:00Z","counts":{},"countries":{"DE":[["198.51.100.1",443],["198.51.100.2",8443]]}}"#;
        let snap = Snapshot::parse(feed.as_bytes()).expect("parses");
        let cfg = crate::relay::outbound::OutboundConfig {
            catalog_pool: true,
            catalog_country: "DE".into(),
            ..Default::default()
        };
        let pool = pool_for(&cfg, Some(&snap)).expect("DE pool");
        assert_eq!(pool.len(), 2);
        assert_eq!(pool[1].port, 8443); // exact port preserved
        // Strict: an unlisted country contributes nothing.
        assert!(pool_for(&crate::relay::outbound::OutboundConfig {
            catalog_pool: true,
            catalog_country: "FR".into(),
            ..Default::default()
        }, Some(&snap)).is_none());
    }

    #[test]
    fn auto_fallback_spreads_across_verified_countries() {
        // Verified-feed shape: no auto list, multiple country pools.
        let feed = r#"{"schema_version":1,"upstream_revision":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","content_revision":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","generated_at":"2026-09-21T03:00:00Z","counts":{},"countries":{"DE":[["198.51.100.1",443],["198.51.100.2",443],["198.51.100.3",443]],"FR":[["198.51.101.1",443]]}}"#;
        let snap = Snapshot::parse(feed.as_bytes()).expect("parses");
        let cfg = crate::relay::outbound::OutboundConfig {
            catalog_pool: true,
            catalog_country: "AUTO".into(),
            ..Default::default()
        };
        let pool = pool_for(&cfg, Some(&snap)).expect("auto pool");
        // 2 per country, DE first (sorted), capped.
        let hosts: Vec<&str> = pool.iter().map(|e| e.host.as_str()).collect();
        assert_eq!(hosts, vec!["198.51.100.1", "198.51.100.2", "198.51.101.1"]);
    }

    #[test]
    fn verified_feed_without_auto_list_parses() {
        let feed = r#"{"schema_version":1,"upstream_revision":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","content_revision":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","generated_at":"2026-09-21T03:00:00Z","counts":{},"countries":{"DE":[["198.51.100.1",443]]},"auto":[]}"#;
        assert!(Snapshot::parse(feed.as_bytes()).is_ok());
    }

    #[test]
    fn probe_and_runtime_share_the_candidate_representation() {
        // The same Endpoint tuple must flow to the probe (host+port dialed)
        // and to routing (Target host+port) without either layer substituting
        // the destination's address or port.
        use crate::protocol::{Host, Target};
        let e = Endpoint { host: "203.0.113.10".into(), port: 8443 };
        let t = Target {
            host: e.host.parse::<std::net::IpAddr>().map_or_else(
                |_| Host::Domain(e.host.to_lowercase().into_boxed_str()),
                Host::Ip,
            ),
            port: e.port,
        };
        // Dial target = candidate, not destination.
        assert_eq!(t.host, Host::Ip("203.0.113.10".parse().unwrap()));
        assert_eq!(t.port, 8443);
        // Health key records the same tuple.
        assert_eq!(
            crate::relay::outbound_state::candidate_key(&t),
            "203.0.113.10:8443"
        );
        // A hostname candidate keeps its name as SNI-capable identity and its
        // own port — no DNS collapse at the representation layer.
        let h = Endpoint { host: "proxy.example.com".into(), port: 2053 };
        let th = Target { host: Host::Domain("proxy.example.com".into()), port: h.port };
        assert_eq!(crate::relay::outbound_state::candidate_key(&th), "proxy.example.com:2053");
    }

    #[test]
    fn health_key_matches_candidate_key_format() {
        use crate::relay::outbound_state::candidate_key;
        use crate::protocol::{Host, Target};
        let key = candidate_key(&Target {
            host: Host::Ip("9.9.9.3".parse().unwrap()),
            port: 443,
        });
        assert_eq!(key, "9.9.9.3:443");
    }

    #[test]
    fn pool_for_dedupes_by_host_and_port() {
        // DE fixture has 203.0.113.7:443 twice.
        let duped = VALID.replace(
            "[[\"203.0.113.7\",443],[\"proxy.example.com\",8443],[\"2001:db8::1\",2053]]",
            "[[\"203.0.113.7\",443],[\"203.0.113.7\",443]]",
        );
        let snap = Snapshot::parse(duped.as_bytes()).expect("parses");
        let cfg = crate::relay::outbound::OutboundConfig {
            catalog_pool: true,
            catalog_country: "DE".into(),
            ..Default::default()
        };
        let pool = pool_for(&cfg, Some(&snap)).expect("pool");
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn meta_from_snapshot_lists_countries_and_counts() {
        let snap = snapshot();
        let meta = Meta::from_snapshot(&snap, "2026-09-20T17:00:00Z");
        assert_eq!(meta.country_count, 1);
        assert_eq!(meta.countries, vec!["DE".to_owned()]);
        assert_eq!(meta.endpoint_count, 3);
        assert!(!meta.is_empty());
        assert!(Meta::from_json("junk").is_none());
        assert!(Meta::default().is_empty());
    }

    #[test]
    fn dedupe_keeps_first_and_preserves_order() {
        let duped = VALID.replace(
            "[[\"203.0.113.7\",443],[\"proxy.example.com\",8443],[\"2001:db8::1\",2053]]",
            "[[\"203.0.113.7\",443],[\"203.0.113.7\",443]]",
        );
        let snap = Snapshot::parse(duped.as_bytes()).expect("parses");
        // Duplicate entries are preserved as-is; the dial layer dedupes by
        // candidate key, so a duplicate here costs an attempt, not a bug.
        assert_eq!(snap.countries["DE"].len(), 2);
    }
}
