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

/// Verdict hysteresis (paste 21-36 §5/§12): the discovery feed churns between
/// scanner runs (measured: 928–1592 endpoints), so a country can drop from
/// `passthrough: 2` to `passthrough: 0` on the next pull with ZERO Trinity-
/// vantage failure evidence — the observed FULL → LIMITED flip roughly two
/// hours after selection. While the last ACTIVATED revision that counted
/// passthrough for a country is younger than this window, a census flip is
/// held one cycle: the previous snapshot keeps serving and the held feed is
/// re-decided on the next pull. Recovery is instant (any positive census
/// activates). Trinity's own quarantine-grade worker-vantage evidence is a
/// different half of the verdict and is never held.
pub(crate) const CENSUS_GRACE_MS: u64 = 12 * 60 * 60 * 1000;

/// One remembered census observation per country: did the last activated
/// revision count passthrough endpoints for it, and how long the gate may
/// still be held.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct CensusNote {
    pub pt_seen: bool,
    pub grace_until_ms: u64,
}

/// The sync-side hold predicate (pure for host testing): would activating
/// `incoming` strip the last passthrough census from a country whose grace
/// window is still open?
pub(crate) fn census_hold_check(
    census: &std::collections::BTreeMap<String, CensusNote>,
    incoming: &Snapshot,
    now_ms: u64,
) -> bool {
    for (cc, note) in census {
        if !note.pt_seen || now_ms >= note.grace_until_ms {
            continue;
        }
        let pt = incoming
            .capability_counts
            .get(cc)
            .and_then(|c| c.get("passthrough"))
            .copied()
            .unwrap_or(0);
        if pt == 0 {
            return true;
        }
    }
    false
}

/// Update the census memory for one country from a snapshot being activated.
pub(crate) fn note_census(
    prior: Option<&CensusNote>,
    snapshot: &Snapshot,
    cc: &str,
    now_ms: u64,
) -> CensusNote {
    let pt_seen = snapshot
        .capability_counts
        .get(cc)
        .and_then(|c| c.get("passthrough"))
        .copied()
        .unwrap_or(0)
        > 0;
    CensusNote {
        pt_seen,
        // A positive census re-arms the window; a negative one keeps whatever
        // memory existed (it never extends past the last positive revision).
        grace_until_ms: if pt_seen {
            now_ms + CENSUS_GRACE_MS
        } else {
            prior.map(|p| p.grace_until_ms).unwrap_or(0)
        },
    }
}

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
    /// Per-country Stage-C relay-capability census from the feed
    /// (`country_metadata[cc].capability_counts`), when the feed carries it.
    /// Older feeds without it default to empty and the panel degrades to the
    /// feed-level `capability` note.
    #[serde(default)]
    pub capability_counts:
        std::collections::BTreeMap<String, std::collections::BTreeMap<String, u32>>,
    /// Per-endpoint Stage-C class from the feed (`ip:port` → class). Absent
    /// key = unclassified; `passthrough` ranks above every other class for
    /// pool ordering because a true passthrough carries every SNI the
    /// cf-relay class can, and more.
    #[serde(default)]
    pub capability_by_endpoint: std::collections::BTreeMap<String, String>,
    /// v1.9.6: per-endpoint quality verdict from the feed (`ip:port` →
    /// `risk/type/confidence/source`). Absent key = unmeasured; unknown is
    /// never bad. Older feeds without it default to empty.
    #[serde(default)]
    pub quality_by_endpoint: std::collections::BTreeMap<String, String>,
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
        // Stage-C census rides inside `country_metadata[cc].capability_counts`
        // (nested, optional; older feeds and the raw feed omit it). Lift it to
        // the snapshot field the panel reads; absence stays an empty map.
        let mut snapshot = snapshot;
        if let Ok(document) = serde_json::from_slice::<serde_json::Value>(bytes) {
            if let Some(metadata) = document.get("country_metadata").and_then(|m| m.as_object()) {
                for (cc, body) in metadata {
                    if let Some(counts) = body.get("capability_counts").and_then(|c| c.as_object())
                    {
                        let mapped: std::collections::BTreeMap<String, u32> = counts
                            .iter()
                            .filter_map(|(k, v)| v.as_u64().map(|n| (k.clone(), n as u32)))
                            .collect();
                        snapshot.capability_counts.insert(cc.clone(), mapped);
                    }
                }
            }
        }
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


/// Spec §8 (V24.8 decoupling): tamper-evidence. The feed's own
/// `content_revision` is a SHA-256 over its countries map, canonicalized by
/// the scanner (Python `json.dumps(..., sort_keys=True)` over `[addr, port]`
/// pairs). Rebuild that exact canonical string and compare — proves the
/// artifact survived transport intact without inventing cryptography, adding
/// feed fields, or writing anything. Integrity ≠ authenticity: raw HTTPS to
/// the pinned repo is the authenticity story for now. Pure fn — host tests
/// exercise it against the real scanner recipe.
fn verify_integrity(bytes: &[u8], declared: &str) -> Result<(), String> {
    use sha2::Digest as _;
    let document: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|e| format!("feed is not valid JSON: {e}"))?;
    let countries = document
        .get("countries")
        .and_then(|v| v.as_object())
        .ok_or("feed has no countries map")?;
    let mut keys: Vec<&String> = countries.keys().collect();
    keys.sort();
    let mut body = String::with_capacity(bytes.len() / 2);
    body.push('{');
    for (i, cc) in keys.iter().enumerate() {
        if i > 0 {
            body.push_str(", ");
        }
        body.push_str(&format!("{}: [", serde_json::json!(cc.as_str())));
        let list = countries[*cc]
            .as_array()
            .ok_or("countries entry is not a list")?;
        for (j, e) in list.iter().enumerate() {
            if j > 0 {
                body.push_str(", ");
            }
            // Feed entries are pairs: ["addr", port].
            let pair = e
                .as_array()
                .filter(|p| p.len() == 2)
                .ok_or("countries entry is not an [address, port] pair")?;
            let addr = pair[0].as_str().ok_or("address is not a string")?;
            let port = pair[1].as_u64().ok_or("port is not a number")?;
            body.push_str(&format!("[{}, {port}]", serde_json::json!(addr)));
        }
        body.push(']');
    }
    body.push('}');
    let hex: String = sha2::Sha256::digest(body.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    if hex != declared {
        return Err("content_revision does not match the feed body (integrity check failed)".into());
    }
    Ok(())
}

/// Fetch + parse + persist the catalog snapshot. NEVER called per session:
/// the only caller is the operator-triggered `api/catalog-sync` panel route.
///
/// Fail-closed: on any fetch/parse/put failure the previous snapshot in KV
/// stays exactly as it was and the error is reported.
#[cfg(target_arch = "wasm32")]
pub async fn sync(env: &worker::Env) -> SyncReport {
    let (status, report, reason, active) = sync_inner(env).await;
    // §21: exactly one line per pull — HTTP status, both revisions, validation
    // and activation outcome, last success/failure, rejection reason.
    worker::console_log!("{}", sync_log(status, &report, &reason, &active));
    report
}

/// The pull itself. Returns `(http_status, report, validation_reason,
/// active_revision)` so the caller logs one line without re-reading KV.
#[cfg(target_arch = "wasm32")]
async fn sync_inner(env: &worker::Env) -> (Option<u16>, SyncReport, String, String) {
    let fetched_at = worker::Date::now().as_millis();
    let (bytes, status, mut error) = match fetch_feed(env).await {
        Ok((b, s)) => (b, Some(s), None),
        Err(e) => (Vec::new(), None, Some(e)),
    };
    // The stored document is read before validation so the §21 line can report
    // the still-active revision on every outcome, a rejected feed included.
    let kv = env.kv("SETTINGS").ok();
    let previous: Option<String> = match kv.as_ref() {
        Some(kv) => kv.get(KV_KEY).text().await.ok().flatten(),
        None => None,
    };
    let active = stored_revision(previous.as_deref()).unwrap_or_default();
    if error.is_none() {
        // Surface the real validation reason to the operator.
        if let Err(failure) = Snapshot::parse(&bytes) {
            error = Some(format!("feed rejected: {failure}; previous snapshot kept"));
        }
    }
    if error.is_none() {
        // Integrity gate (spec §8): revision must match the body. Fail closed
        // — the previous snapshot in KV stays active on any mismatch.
        let declared = Snapshot::parse(&bytes)
            .map(|s| s.content_revision)
            .unwrap_or_default();
        if let Err(failure) = verify_integrity(&bytes, &declared) {
            error = Some(format!("feed rejected: {failure}; previous snapshot kept"));
        }
    }
    let parsed = if error.is_none() { Snapshot::parse(&bytes).ok() } else { None };
    let Some(snapshot) = parsed else {
        let reason = error.clone().unwrap_or_else(|| "unparsable feed".into());
        return (status, SyncReport {
            ok: false,
            changed: false,
            content_revision: String::new(),
            upstream_revision: String::new(),
            generated_at: String::new(),
            fetched_at: now_iso(fetched_at),
            country_count: 0,
            endpoint_count: 0,
            error,
        }, reason, active);
    };
    // Content identity, not document identity: `fetchedAt` changes on every
    // run, so comparing whole documents made every sync a KV write even when
    // the feed was byte-identical (V24.6.10 A). The feed's own
    // `content_revision` — the strongest identity the scanner already
    // publishes — decides. Unchanged revision: zero KV writes, previous
    // `fetchedAt` kept (it dates the stored content, not this probe).
    let incoming_rev = snapshot.content_revision.as_str();
    // §6: one decision covers the no-op (equal revision → zero writes) and
    // the rollback guard (older generated_at → reject, keep previous).
    let decision = revision_decision(
        incoming_rev,
        snapshot.generated_at.as_str(),
        stored_revision(previous.as_deref()).as_deref(),
        stored_generated_at(previous.as_deref()).as_deref(),
    );
    let (changed, mut error): (bool, Option<String>) = match decision {
        Ok(true) => (true, None),
        Ok(false) => (false, None),
        Err(rejection) => (
            false,
            Some(format!("feed rejected: {rejection}; previous snapshot kept")),
        ),
    };
    // Verdict hysteresis (paste 21-36): hold a feed whose activation would
    // strip the last passthrough census from a country inside its grace
    // window. The previous snapshot keeps serving; the held feed is re-decided
    // on the next pull. Trinity-vantage quarantine evidence is NOT part of
    // this gate and never held.
    let previous_snapshot: Option<Snapshot> = previous
        .as_deref()
        .and_then(|raw| serde_json::from_str::<serde_json::Value>(raw).ok())
        .and_then(|v| serde_json::from_value(v.get("snapshot")?.clone()).ok());
    let prior_census: std::collections::BTreeMap<String, CensusNote> = previous
        .as_deref()
        .and_then(|raw| serde_json::from_str::<serde_json::Value>(raw).ok())
        .and_then(|v| serde_json::from_value(v.get("census")?.clone()).ok())
        .unwrap_or_default();
    if changed && census_hold_check(&prior_census, &snapshot, fetched_at) {
        return (status, SyncReport {
            ok: true,
            changed: false,
            content_revision: snapshot.content_revision,
            upstream_revision: snapshot.upstream_revision,
            generated_at: snapshot.generated_at,
            fetched_at: now_iso(fetched_at),
            country_count: previous_snapshot.as_ref().map_or(0, |s| s.countries.len()),
            endpoint_count: previous_snapshot
                .as_ref()
                .map(|s| s.countries.values().map(Vec::len).sum::<usize>())
                .unwrap_or(0),
            error: Some(
                "held: census flip inside grace window; previous snapshot serving".into(),
            ),
        }, "census hold active; previous snapshot kept".to_string(), active);
    }
    if changed {
        let notes: std::collections::BTreeMap<String, CensusNote> = snapshot
            .capability_counts
            .keys()
            .chain(prior_census.keys())
            .cloned()
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .map(|cc| (cc.clone(), note_census(prior_census.get(&cc), &snapshot, &cc, fetched_at)))
            .collect();
        let document = serde_json::json!({
            "snapshot": snapshot,
            "census": notes,
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
        let reason = error.clone().unwrap_or_else(|| "write failed".into());
        return (status, SyncReport {
            ok: false,
            changed: false,
            content_revision: snapshot.content_revision,
            upstream_revision: snapshot.upstream_revision,
            generated_at: snapshot.generated_at,
            fetched_at: now_iso(fetched_at),
            country_count: snapshot.countries.len(),
            endpoint_count: snapshot.countries.values().map(Vec::len).sum::<usize>(),
            error,
        }, reason, active);
    }
    let reason = if changed { "new revision activated" } else { "revision unchanged; zero writes" };
    (status, SyncReport {
        ok: true,
        changed,
        content_revision: snapshot.content_revision,
        upstream_revision: snapshot.upstream_revision,
        generated_at: snapshot.generated_at,
        fetched_at: now_iso(fetched_at),
        country_count: snapshot.countries.len(),
        endpoint_count: snapshot.countries.values().map(Vec::len).sum::<usize>(),
        error: None,
    }, reason.to_owned(), active)
}

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

/// The `generated_at` of the snapshot stored in a `panel:catalog` document,
/// if any. Sibling of `stored_revision`; feeds the §6 rollback guard.
#[must_use]
fn stored_generated_at(previous: Option<&str>) -> Option<String> {
    let document: serde_json::Value = serde_json::from_str(previous?).ok()?;
    document
        .get("snapshot")?
        .get("generated_at")?
        .as_str()
        .map(str::to_owned)
}

/// Decoupling §6: revision-aware decision, made before any write.
///
/// - equal `content_revision`  → no-op (`Ok(false)`): zero KV writes.
/// - `generated_at` older than the stored one → reject (`Err`): never roll
///   backward, the previous snapshot stays active. Both timestamps are
///   scanner-generated RFC 3339 UTC (`…Z`), so lexicographic order is
///   chronological order.
/// - anything else (newer revision, or no stored document) → activate
///   (`Ok(true)`); a missing/unreadable stored timestamp fails safe toward
///   freshness, matching `stored_revision`.
#[must_use]
fn revision_decision(
    incoming_rev: &str,
    incoming_at: &str,
    stored_rev: Option<&str>,
    stored_at: Option<&str>,
) -> Result<bool, String> {
    if stored_rev == Some(incoming_rev) {
        return Ok(false);
    }
    if let Some(prev) = stored_at {
        if prev > incoming_at {
            return Err(format!(
                "older feed rejected (stored generated_at {prev}, incoming {incoming_at}); never roll backward"
            ));
        }
    }
    Ok(true)
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
async fn fetch_feed(env: &worker::Env) -> Result<(Vec<u8>, u16), String> {
    // CATALOG_URL (decoupling §4): the feed source is configurable per
    // deployment via a plain-text binding; the pinned public repo is the
    // default so a deployment that sets nothing still works.
    let base = catalog_url(env);
    // Cache-bust: raw.githubusercontent.com serves stale copies for minutes
    // after a push, and a sync that runs right after publishing must see the
    // revision it was invoked for (the idempotency check compares hashes).
    let url = format!("{base}?t={}", worker::Date::now().as_millis());
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
    let status = response.status_code();
    let bytes = response.bytes().await.map_err(|e| e.to_string())?;
    if bytes.len() > MAX_FEED_BYTES {
        return Err(format!("feed exceeds {MAX_FEED_BYTES} bytes"));
    }
    Ok((bytes, status))
}

/// §4: the feed source, CATALOG_URL binding first, pinned default second.
#[cfg(target_arch = "wasm32")]
fn catalog_url(env: &worker::Env) -> String {
    env.var("CATALOG_URL")
        .map(|v| v.to_string())
        .unwrap_or_else(|_| FEED_URL.to_owned())
}

/// §21 observability: one compact line per pull, built here as a pure fn so
/// the host tests pin the shape. Never includes the URL's query, headers or
/// any binding value — no secrets in logs.
#[must_use]
fn sync_log(
    status: Option<u16>,
    report: &SyncReport,
    reason: &str,
    active_revision: &str,
) -> String {
    format!(
        "catalog pull: http={} fetched_revision={} active_revision={} validation={} activation={} countries={} endpoints={} last_success={} last_failure={} reason={}",
        status.map_or_else(|| "none".to_owned(), |s| s.to_string()),
        short(&report.content_revision),
        short(active_revision),
        if report.error.is_none() { "ok" } else { "rejected" },
        if report.changed { "activated" } else { "kept" },
        report.country_count,
        report.endpoint_count,
        report.fetched_at,
        report.error.as_deref().unwrap_or("none"),
        reason,
    )
}

/// First 12 hex chars of a revision, or `none` — logs stay one line.
#[must_use]
fn short(revision: &str) -> String {
    if revision.is_empty() {
        "none".to_owned()
    } else {
        revision.chars().take(12).collect()
    }
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
            return Some(bounded(
                spread.into_iter(),
                health,
                &snapshot.capability_by_endpoint,
                &snapshot.quality_by_endpoint,
                false,
            ));
        }
        return Some(bounded(
            snapshot.auto.iter().cloned(),
            health,
            &snapshot.capability_by_endpoint,
            &snapshot.quality_by_endpoint,
            false,
        ));
    }
    let selected = snapshot.pool(Some(country))?;
    Some(bounded(
        selected.iter().cloned(),
        health,
        &snapshot.capability_by_endpoint,
        &snapshot.quality_by_endpoint,
        cfg.enforces_location(),
    ))
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
///
/// Capability gates the ranking: a country with verified passthrough
/// candidates outranks every zero-passthrough country (a 100-candidate
/// cf-relay-only pool cannot carry generic internet; a smaller pool with
/// passthrough can). Region and size rank inside each capability band.
#[must_use]
pub fn choose_fallback_country(
    snapshot: &Snapshot,
    excluded: &[&str],
    epoch: u64,
) -> Option<String> {
    let has_pt = |cc: &str| -> u8 {
        u8::from(
            snapshot
                .capability_counts
                .get(cc)
                .and_then(|c| c.get("passthrough"))
                .copied()
                .unwrap_or(0)
                > 0,
        )
    };
    let mut ranked: Vec<(u8, bool, usize, &String)> = snapshot
        .countries
        .iter()
        .filter(|(cc, pool)| !excluded.contains(&cc.as_str()) && !pool.is_empty())
        .map(|(cc, pool)| (has_pt(cc), region_of(cc) == "Europe", pool.len(), cc))
        .collect();
    // Sort: passthrough-capable first, non-Europe first, larger pools first,
    // then cc for stability.
    ranked.sort_by(|a, b| {
        b.0.cmp(&a.0)
            .then(a.1.cmp(&b.1))
            .then(b.2.cmp(&a.2))
            .then(a.3.cmp(b.3))
    });
    if ranked.is_empty() {
        return None;
    }
    let top = ranked.len().min(3);
    let pick = &ranked[(epoch % top as u64) as usize];
    Some(pick.3.clone())
}

/// Per-country capability state and deterministic quality score, derived ONLY
/// from verified data: the feed's Stage-C census (`capability_counts`) and
/// Trinity's own worker-vantage health records. No geography, ASN, or
/// name-based inference.
///
/// States (spec v1.9.5 country quality; 09-28 hardening: UNMEASURED ≠ BAD):
/// - `full`: verified passthrough candidates with no failure evidence —
///   either at least one currently healthy candidate, or the census is
///   verified and nothing has been measured failing. Missing liveness
///   measurements never demote (the 2-h scanner fills them progressively).
/// - `degraded`: passthrough exists AND concrete repeated/hard probe
///   failures (the dial path's quarantine predicate) — measurable
///   degradation, never "metadata missing".
/// - `limited`: zero passthrough (cf-relay-only census) — reachable maybe,
///   but generic destinations fail by design.
/// - `unavailable`: no candidates, or every candidate measured and none
///   healthy (all quarantined/dead).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CountryQuality {
    /// `full` | `degraded` | `limited` | `unavailable`.
    pub state: String,
    /// 0–100. Orders countries inside a state; the state orders between.
    /// `None` when nothing was measured: quality unknown, never a fake 0.
    pub quality: Option<u32>,
    pub passthrough: u32,
    pub cf_relay: u32,
    pub sni_terminate: u32,
    pub healthy: u32,
    pub discovered: u32,
    /// Mean worker-vantage success rate over measured candidates, percent.
    pub success_rate_pct: u32,
}

/// Freshness window for health records feeding the score (spec §9).
const FRESH_MS: u64 = 24 * 60 * 60 * 1000;

#[must_use]
pub fn country_quality(
    snapshot: &Snapshot,
    health: &std::collections::BTreeMap<String, crate::relay::outbound_state::Health>,
    now_ms: u64,
) -> std::collections::BTreeMap<String, CountryQuality> {
    let mut out = std::collections::BTreeMap::new();
    for (cc, list) in &snapshot.countries {
        let census = snapshot.capability_counts.get(cc);
        let pt = census
            .and_then(|c| c.get("passthrough"))
            .copied()
            .unwrap_or(0);
        let cf = census
            .and_then(|c| c.get("cf-relay"))
            .copied()
            .unwrap_or(0);
        let sni = census
            .and_then(|c| c.get("sni-terminate"))
            .copied()
            .unwrap_or(0);
        let discovered = list.len() as u32;
        // Worker-vantage evidence for this country's candidates.
        let mut measured = 0u32;
        let mut healthy = 0u32;
        let mut fresh = 0u32;
        // 09-28 hardening: concrete degradation evidence — repeated/hard probe
        // failures, the same predicate the dial path quarantines on. Counted
        // inside this loop so the freshness TTL above applies too: an old
        // failure can no more pin a country DEGRADED forever than an old
        // success can keep it FULL.
        let mut quarantined_fresh = 0u32;
        let mut success_sum = 0.0f64;
        let mut healthy_hosts = std::collections::HashSet::new();
        for e in list {
            let key = format!("{}:{}", e.host.to_ascii_lowercase(), e.port);
            if let Some(h) = health.get(&key) {
                // Stale evidence is not current proof (spec: freshness TTL).
                // A record older than 2x the freshness window decays to
                // unmeasured — it can neither keep a country FULL nor pin
                // it to a past failure. The 24h freshness share already
                // decays the score; this TTL also removes the liveness.
                if now_ms.saturating_sub(h.updated_at_ms) >= 2 * FRESH_MS {
                    continue;
                }
                // Platform runtime errors (e.g. the free-plan subrequest cap)
                // say nothing about the candidate — no measurement, no
                // evidence (Bug #4); poisoned records become inert here.
                if h.is_runtime_error() {
                    continue;
                }
                measured += 1;
                success_sum += h.success_rate();
                if h.quarantined() {
                    quarantined_fresh += 1;
                }
                // Same liveness predicate the health overlay's
                // `trinityReachable` uses: the last probe succeeded. The
                // stricter `healthy()` (which also demands a known exit
                // country) would miscount TCP-verified candidates whose
                // trace lookup never captured a country.
                if h.ok && !h.quarantined() {
                    healthy += 1;
                    healthy_hosts.insert(e.host.to_ascii_lowercase());
                }
                if now_ms.saturating_sub(h.updated_at_ms) < FRESH_MS {
                    fresh += 1;
                }
            }
        }
        // UNMEASURED ≠ BAD (paste 09-28): absence of measurements is not
        // evidence of degradation. A verified passthrough country with no
        // failure evidence is FULL — healthy now, or simply not yet probed
        // (the 2-h scanner fills that gap). Only concrete repeated/hard
        // failures demote it to DEGRADED; JSON shape unchanged for the UI.
        let state = if pt > 0 && (healthy > 0 || quarantined_fresh == 0) {
            "full"
        } else if pt > 0 {
            // Passthrough exists, nothing healthy, real failed probes on
            // record — measurable current degradation.
            "degraded"
        } else if discovered == 0 || (healthy == 0 && measured > 0) {
            "unavailable"
        } else {
            "limited"
        };
        // Deterministic score per spec weights: 35% passthrough availability,
        // 25% recent success rate, 15% reachable share, 15% freshness,
        // 10% host diversity of healthy candidates. Zero passthrough therefore
        // caps at 65; candidate count never enters directly.
        let pt_share = f64::from(pt) / f64::from(discovered.max(1));
        let success = if measured > 0 { success_sum / f64::from(measured) } else { 0.0 };
        let reach_share = f64::from(healthy) / f64::from(discovered.max(1));
        let fresh_share = f64::from(fresh) / f64::from(measured.max(1));
        let diversity = f64::from(healthy_hosts.len() as u32) / f64::from(healthy.max(1));
        let quality = (35.0 * pt_share
            + 25.0 * success
            + 15.0 * reach_share
            + 15.0 * fresh_share
            + 10.0 * diversity)
            .round() as u32;
        // UNMEASURED ≠ BAD (paste 09-28): with zero measurements the score is
        // unknown, not zero — emit null ("Quality: —"), never a fake 0.
        let quality = (measured > 0).then(|| quality.min(100));
        out.insert(
            cc.clone(),
            CountryQuality {
                state: state.to_owned(),
                quality,
                passthrough: pt,
                cf_relay: cf,
                sni_terminate: sni,
                healthy,
                discovered,
                success_rate_pct: (success * 100.0).round() as u32,
            },
        );
    }
    out
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
        // Read + merge (Bug Hunter 2): a probe pass or LKG write landing while
        // this session ran must survive — a wholesale put would clobber their
        // fresher per-candidate verdicts. Then two quota guards: a 60 s floor
        // (reconnect storms must not put a KV write on every session; the
        // hold clock drifts at most one floor, rotation stays epoch-granular)
        // and a no-op skip when the merged document equals what is stored.
        let stored = match kv.get(crate::relay::outbound_state::KV_KEY).text().await {
            Ok(Some(raw)) => crate::relay::outbound_state::OutboundState::from_json(&raw),
            _ => crate::relay::outbound_state::OutboundState::default(),
        };
        if !crate::relay::outbound_state::fallback_write_needed(&stored, state) {
            return;
        }
        let merged = crate::relay::outbound_state::merged_with_stored(state.clone(), stored.clone());
        if merged == stored {
            return;
        }
        if let Ok(document) = serde_json::to_string(&merged) {
            if let Ok(pending) = kv.put(crate::relay::outbound_state::KV_KEY, document) {
                let _ = pending.execute().await;
            }
        }
    }
}

/// Order-preserving dedupe by host+port, capped at MAX_POOL_CANDIDATES.
/// Health evidence orders within the pool: measured-healthy first, then
/// unmeasured, then known-failed — so Auto does not re-serve the same dead
/// addresses the probe already condemned while healthy ones exist. Feed
/// reputation (`quality_by_endpoint`, "risk/type/confidence/source") only
/// re-ranks: a `high`-risk verdict sinks within its health/capability band
/// but never disqualifies — absent or unparseable = unmeasured, never bad.
fn bounded(
    candidates: impl Iterator<Item = Endpoint>,
    health: &std::collections::BTreeMap<String, crate::relay::outbound_state::Health>,
    capability: &std::collections::BTreeMap<String, String>,
    quality: &std::collections::BTreeMap<String, String>,
    capability_first: bool,
) -> Vec<Endpoint> {
    // Capability band: a Stage-C `passthrough` is strictly more capable than
    // cf-relay (it forwards any SNI, including a CF edge's), so it outranks
    // everything; unclassified and cf-relay share a band; sni-terminate (it
    // terminates the destination TLS with its own certificate) sinks.
    let cap_rank = |e: &Endpoint| -> u8 {
        match capability
            .get(&format!("{}:{}", e.host.to_ascii_lowercase(), e.port))
            .map(String::as_str)
        {
            Some("passthrough") => 0,
            Some("sni-terminate") => 2,
            _ => 1,
        }
    };
    // capability_first (enforced pools, Bug #2): a full-capability candidate
    // must not be crowded out of the pool slot cap by measured-healthy
    // cf-only boxes — a cf-relay cannot serve the plain-HTTP/:8080 traffic
    // class the operator selected that country for. The 8x weight puts the
    // capability band above the whole health*risk range below it; quarantines
    // still win because they drop candidates entirely (eligibility, not rank).
    let rank = |e: &Endpoint| -> u8 {
        let health_part = (match health.get(&format!("{}:{}", e.host.to_ascii_lowercase(), e.port)) {
            Some(h) if h.healthy() => 0u8,
            Some(h) if !h.ok => 2,
            _ => 1,
        }) * 3
            + u8::from(
                quality
                    .get(&format!("{}:{}", e.host.to_ascii_lowercase(), e.port))
                    .and_then(|v| v.split('/').next())
                    .map(str::trim)
                    .is_some_and(|risk| risk.eq_ignore_ascii_case("high")),
            ) * 9;
        if capability_first {
            cap_rank(e) * 8 + health_part.min(7)
        } else {
            health_part + cap_rank(e)
        }
    };
    let mut deduped: Vec<Endpoint> = Vec::new();
    for e in candidates {
        // Trinity-vantage quarantine (see `Health::quarantined`): a candidate
        // the worker itself could not reach — or that failed repeatedly —
        // never enters a pool. This is the eligibility half of the health
        // model; ordering below is the ranking half. Absent record = no
        // verdict yet, stays eligible.
        let key = format!("{}:{}", e.host.to_ascii_lowercase(), e.port);
        if health.get(&key).is_some_and(|h| h.quarantined()) {
            continue;
        }
        if !deduped.iter().any(|d| d.host.eq_ignore_ascii_case(&e.host) && d.port == e.port) {
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

/// Deterministic worker-vantage verification order over every catalog
/// candidate (all countries + auto + unassigned), for the 2-hour
/// `verify-catalog` pass. Ordering: the configured country first (the pool
/// in use gets fresh evidence first), never-probed entries before measured
/// ones, longest-stale measurement first, then the health key for a stable
/// tie-break. Same inputs always produce the same list, so a stateless
/// `cursor` can slice it across bounded invocations.
#[must_use]
pub fn verify_order(
    snapshot: &Snapshot,
    health: &std::collections::BTreeMap<String, crate::relay::outbound_state::Health>,
    configured_country: &str,
) -> Vec<Endpoint> {
    let wanted = configured_country.trim().to_ascii_uppercase();
    let mut all: Vec<Endpoint> = Vec::new();
    for (country, list) in &snapshot.countries {
        let _ = country;
        all.extend(list.iter().cloned());
    }
    all.extend(snapshot.auto.iter().cloned());
    all.extend(snapshot.unassigned.iter().cloned());
    // Dedupe by health key, keep first occurrence.
    let mut seen = std::collections::HashSet::new();
    all.retain(|e| seen.insert(format!("{}:{}", e.host.to_ascii_lowercase(), e.port)));
    all.sort_by(|a, b| {
        let key = |e: &Endpoint| format!("{}:{}", e.host.to_ascii_lowercase(), e.port);
        let band = |e: &Endpoint| -> (u8, u8, u64) {
            let in_country = snapshot
                .countries
                .get(&wanted)
                .is_some_and(|list| list.iter().any(|c| c.host.eq_ignore_ascii_case(&e.host) && c.port == e.port));
            match health.get(&key(e)) {
                Some(h) => (u8::from(!in_country), 1, h.updated_at_ms),
                None => (u8::from(!in_country), 0, 0),
            }
        };
        band(a).cmp(&band(b)).then_with(|| key(a).cmp(&key(b)))
    });
    all
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
    /// The public feed URL this panel pulls from (V24.8 decoupling §4/§30):
    /// shown in the panel so the source is visible, not secret. Absent in
    /// older stored metas.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_url: Option<String>,
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
            source_url: None,
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
            source_url: Some(FEED_URL.to_owned()),
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
            capability_counts: std::collections::BTreeMap::new(),
            capability_by_endpoint: std::collections::BTreeMap::new(),
            quality_by_endpoint: std::collections::BTreeMap::new(),
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

    // ---- v1.9.5 country capability & quality (spec §13) ----

    use std::collections::BTreeMap;

    use crate::relay::outbound_state::Health;

    fn snap_with_capabilities(
        countries: &[(&str, usize, &[(&str, u32)])],
    ) -> Snapshot {
        let mut map = std::collections::BTreeMap::new();
        let mut caps = std::collections::BTreeMap::new();
        for (cc, n, c) in countries {
            map.insert(
                (*cc).to_owned(),
                (0..*n)
                    .map(|i| Endpoint { host: format!("10.{cc}.{i}.1").to_ascii_lowercase(), port: 443 })
                    .collect(),
            );
            let mut m = std::collections::BTreeMap::new();
            for (k, v) in *c {
                m.insert((*k).to_owned(), *v);
            }
            caps.insert((*cc).to_owned(), m);
        }
        Snapshot {
            schema_version: 1,
            upstream_revision: String::new(),
            content_revision: String::new(),
            generated_at: String::new(),
            countries: map,
            unassigned: Vec::new(),
            auto: Vec::new(),
            capability_counts: caps,
            capability_by_endpoint: std::collections::BTreeMap::new(),
            quality_by_endpoint: std::collections::BTreeMap::new(),
        }
    }

    fn healthy(cc: &str, at_ms: u64) -> (String, Health) {
        (
            format!("10.{cc}.0.1:443").to_ascii_lowercase(),
            Health {
                country: cc.to_owned(),
                ok: true,
                ok_count: 3,
                updated_at_ms: at_ms,
                ..Health::default()
            },
        )
    }

    #[test]
    fn full_country_has_passthrough_and_a_healthy_candidate() {
        let s = snap_with_capabilities(&[("JO", 4, &[("passthrough", 4)])]);
        let health = BTreeMap::from([healthy("JO", 1_000)]);
        let q = country_quality(&s, &health, 2_000);
        assert_eq!(q["JO"].state, "full");
        assert!(q["JO"].quality.unwrap_or(0) >= 35, "passthrough share must contribute");
    }

    #[test]
    fn limited_is_a_zero_passthrough_reachable_country() {
        // The Finland shape: 64 verified cf-relays, zero passthrough, alive.
        let s = snap_with_capabilities(&[
            ("FI", 64, &[("cf-relay", 64)]),
            ("JO", 4, &[("passthrough", 4)]),
        ]);
        let health = BTreeMap::from([healthy("FI", 1_000), healthy("JO", 1_000)]);
        let q = country_quality(&s, &health, 2_000);
        assert_eq!(q["FI"].state, "limited");
        // Spec §6: a cf-relay-only country must not rank alongside FULL ones —
        // even a fully healthy cf-relay pool scores below a passthrough pool.
        assert!(q["FI"].quality < q["JO"].quality);
    }

    #[test]
    fn single_soft_failure_does_not_degrade() {
        // 09-28 hardening (paste #11): ONE failed probe is not repeated
        // evidence — the dial path's quarantine predicate (fail_count >= 2
        // or a hard TCP connect error) is the degradation bar.
        let s = snap_with_capabilities(&[("US", 4, &[("passthrough", 2), ("cf-relay", 2)])]);
        let health = BTreeMap::from([(
            "10.us.0.1:443".to_owned(),
            Health { ok: false, fail_count: 1, updated_at_ms: 1_000, ..Health::default() },
        )]);
        let q = country_quality(&s, &health, 2_000);
        assert_eq!(q["US"].state, "full");
    }

    #[test]
    fn unmeasured_passthrough_country_is_full_not_degraded() {
        // 09-28 hardening (paste #1/#2/#9): a fresh catalog with verified
        // passthrough and ZERO health evidence is healthy-and-unmeasured,
        // never DEGRADED. Missing liveness data is not failure data.
        let s = snap_with_capabilities(&[("GB", 8, &[("passthrough", 8)])]);
        let q = country_quality(&s, &BTreeMap::new(), 1_000);
        assert_eq!(q["GB"].state, "full");
    }

    #[test]
    fn recovered_candidate_returns_country_to_full() {
        // 09-28 hardening (paste #12): quarantine evidence demotes; a later
        // successful probe clears it — transitions stay dynamic, no label
        // sticks.
        let s = snap_with_capabilities(&[("JO", 2, &[("passthrough", 2)])]);
        let dead = BTreeMap::from([(
            "10.jo.0.1:443".to_owned(),
            Health { ok: false, fail_count: 2, updated_at_ms: 1_000, ..Health::default() },
        )]);
        assert_eq!(country_quality(&s, &dead, 2_000)["JO"].state, "degraded");
        let mut healed = dead;
        healed.get_mut("10.jo.0.1:443").unwrap().ok = true;
        assert_eq!(country_quality(&s, &healed, 3_000)["JO"].state, "full");
    }

    #[test]
    fn runtime_error_records_are_not_candidate_evidence() {
        // Bug #4 (09-28): the verify pass tripping Cloudflare's per-invocation
        // subrequest cap recorded "Too many subrequests" as candidate
        // failures, quarantining whole countries. A platform budget error is
        // not evidence: state stays full, quality stays unmeasured (null).
        let s = snap_with_capabilities(&[("JO", 2, &[("passthrough", 2)])]);
        let poisoned = BTreeMap::from([(
            "10.jo.0.1:443".to_owned(),
            Health {
                ok: false,
                fail_count: 2,
                error: "Error: Too many subrequests by single Worker invocation.".to_owned(),
                updated_at_ms: 1_000,
                ..Health::default()
            },
        )]);
        let q = country_quality(&s, &poisoned, 2_000);
        assert_eq!(q["JO"].state, "full");
        assert_eq!(q["JO"].quality, None);
    }

    #[test]
    fn quarantined_ignores_runtime_errors() {
        let poisoned = Health {
            ok: false,
            fail_count: 2,
            error: "Error: Too many subrequests by single Worker invocation.".to_owned(),
            ..Health::default()
        };
        assert!(!poisoned.quarantined());
        assert!(poisoned.is_runtime_error());
        // Real probe failures still quarantine.
        let real = Health {
            ok: false,
            fail_count: 2,
            error: "tcp connect: refused".to_owned(),
            ..Health::default()
        };
        assert!(real.quarantined());
        assert!(!real.is_runtime_error());
    }

    #[test]
    fn census_hold_ignores_unseen_and_expired_windows() {
        let incoming = snap_with_capabilities(&[("US", 2, &[("cf-relay", 2)])]);
        // No positive observation on record: no hold.
        let empty = std::collections::BTreeMap::new();
        assert!(!census_hold_check(&empty, &incoming, 1_000));
        // Positive observation but window expired: no hold.
        let expired = BTreeMap::from([(
            "US".to_owned(),
            CensusNote { pt_seen: true, grace_until_ms: 500 },
        )]);
        assert!(!census_hold_check(&expired, &incoming, 1_000));
    }

    #[test]
    fn census_hold_triggers_on_pt_loss_inside_window() {
        let incoming = snap_with_capabilities(&[("US", 2, &[("cf-relay", 2)])]);
        let held = BTreeMap::from([(
            "US".to_owned(),
            CensusNote { pt_seen: true, grace_until_ms: 2_000 },
        )]);
        assert!(census_hold_check(&held, &incoming, 1_000));
        // A country VANISHING from the feed is the most destructive census
        // flip of all (pool emptied): it must hold too.
        let vanished = BTreeMap::from([(
            "DE".to_owned(),
            CensusNote { pt_seen: true, grace_until_ms: 2_000 },
        )]);
        assert!(census_hold_check(&vanished, &incoming, 1_000));
        // No observation recorded for any country: no hold.
        assert!(!census_hold_check(&std::collections::BTreeMap::new(), &incoming, 1_000));
    }

    #[test]
    fn census_recovery_is_instant_and_notes_rearm() {
        let with_pt = snap_with_capabilities(&[
            ("US", 2, &[("passthrough", 1), ("cf-relay", 1)]),
            ("DE", 1, &[("cf-relay", 1)]),
        ]);
        // Incoming still has passthrough: no hold (recovery path).
        let held = BTreeMap::from([(
            "US".to_owned(),
            CensusNote { pt_seen: true, grace_until_ms: 2_000 },
        )]);
        assert!(!census_hold_check(&held, &with_pt, 1_000));
        // Note from a positive census: pt_seen true, window re-armed.
        let note = note_census(None, &with_pt, "US", 1_000);
        assert!(note.pt_seen && note.grace_until_ms == 1_000 + CENSUS_GRACE_MS);
        // Note from a negative census keeps the prior window, never extends.
        let prior = CensusNote { pt_seen: true, grace_until_ms: 5_000 };
        let note = note_census(Some(&prior), &snap_with_capabilities(&[("US", 2, &[("cf-relay", 2)])]), "US", 6_000);
        assert!(!note.pt_seen && note.grace_until_ms == 5_000);
        // Negative census with no prior memory: zero window.
        let note = note_census(None, &snap_with_capabilities(&[("US", 2, &[("cf-relay", 2)])]), "US", 1_000);
        assert!(!note.pt_seen && note.grace_until_ms == 0);
    }

    #[test]
    fn ancient_failure_evidence_does_not_pin_degraded() {
        // 09-28 hardening: the degradation signal obeys the same 2x freshness
        // TTL as liveness. A stale quarantine record decays to unmeasured —
        // otherwise a country would stay DEGRADED forever with no current
        // evidence, which is the same lie in the other direction.
        let s = snap_with_capabilities(&[("JO", 2, &[("passthrough", 2)])]);
        let stale_dead = BTreeMap::from([(
            "10.jo.0.1:443".to_owned(),
            Health { ok: false, fail_count: 2, updated_at_ms: 0, ..Health::default() },
        )]);
        assert_eq!(country_quality(&s, &stale_dead, 3 * FRESH_MS)["JO"].state, "full");
    }

    #[test]
    fn unavailable_when_everything_measured_is_unhealthy() {
        let s = snap_with_capabilities(&[("AD", 1, &[("cf-relay", 1)])]);
        let health = BTreeMap::from([(
            "10.ad.0.1:443".to_owned(),
            Health { ok: false, fail_count: 2, updated_at_ms: 1_000, ..Health::default() },
        )]);
        let q = country_quality(&s, &health, 2_000);
        assert_eq!(q["AD"].state, "unavailable");
    }

    #[test]
    fn stale_health_downgrades_full_to_degraded() {
        // Spec §9: an old success must not keep a country FULL forever. The
        // healthy record is 25h old — outside the freshness window the score
        // decays; liveness itself is the state signal here: still "full"
        // (nothing measured-failed) but the freshness share contributes 0.
        let s = snap_with_capabilities(&[("JO", 2, &[("passthrough", 2)])]);
        let health = BTreeMap::from([healthy("JO", 0)]);
        let q = country_quality(&s, &health, 25 * 60 * 60 * 1000);
        assert_eq!(q["JO"].state, "full");
        assert!(q["JO"].quality.unwrap_or(100) < 90, "stale evidence must not score like fresh");
    }

    #[test]
    fn unmeasured_candidates_do_not_make_a_country_unavailable() {
        // A fresh catalog with zero health evidence: census says limited (no
        // passthrough) but NOT unavailable — nothing was measured yet.
        let s = snap_with_capabilities(&[("FI", 8, &[("cf-relay", 8)])]);
        let q = country_quality(&s, &BTreeMap::new(), 1_000);
        assert_eq!(q["FI"].state, "limited");
    }

    #[test]
    fn mixed_passthrough_beats_cf_relay_only_at_equal_health() {
        let s = snap_with_capabilities(&[
            ("JO", 4, &[("passthrough", 4)]),
            ("FI", 64, &[("cf-relay", 64)]),
        ]);
        let health = BTreeMap::from([healthy("JO", 1_000), healthy("FI", 1_000)]);
        let q = country_quality(&s, &health, 2_000);
        assert!(q["JO"].quality > q["FI"].quality);
    }

    #[test]
    fn quality_orders_countries_inside_the_same_state() {
        let s = snap_with_capabilities(&[
            ("GB", 8, &[("passthrough", 8)]),
            ("US", 8, &[("passthrough", 2), ("cf-relay", 6)]),
        ]);
        let health = BTreeMap::from([healthy("GB", 1_000), healthy("US", 1_000)]);
        let q = country_quality(&s, &health, 2_000);
        assert!(q["GB"].quality > q["US"].quality, "higher passthrough share wins");
    }

    #[test]
    fn fallback_prefers_a_passthrough_country_over_a_bigger_cf_relay_pool() {
        // Spec §7: 100 cf-relay candidates must not outrank a smaller pool
        // with passthrough. JO (non-EU, 8, all passthrough) beats SG
        // (non-EU, 64, all cf-relay).
        let s = snap_with_capabilities(&[
            ("DE", 8, &[("cf-relay", 8)]),
            ("SG", 64, &[("cf-relay", 64)]),
            ("JO", 8, &[("passthrough", 8)]),
        ]);
        let cc = choose_fallback_country(&s, &["DE"], 0).unwrap();
        assert_eq!(cc, "JO");
    }

    #[test]
    fn fallback_still_prefers_non_european_within_a_capability_band() {
        let s = snap_with_capabilities(&[
            ("DE", 8, &[("cf-relay", 8)]),
            ("FR", 4, &[("cf-relay", 4)]),
            ("JO", 8, &[("passthrough", 8)]),
        ]);
        // JO is excluded (exhausted): remaining band has no passthrough, so
        // region + size rank as before → DE (non... DE is Europe) → DE vs FR:
        // both Europe; DE larger. With no non-EU candidate left, DE wins.
        let cc = choose_fallback_country(&s, &["JO"], 0).unwrap();
        assert_eq!(cc, "DE");
    }

    #[test]
    fn country_enforcement_unchanged_by_quality_ranking() {
        // A LIMITED country selected explicitly still uses ONLY its own
        // candidates (spec §12/§14: ranking never weakens enforcement).
        let s = snap_with_capabilities(&[
            ("JO", 8, &[("passthrough", 8)]),
            ("FI", 64, &[("cf-relay", 64)]),
        ]);
        let cfg = crate::relay::outbound::OutboundConfig {
            mode: crate::relay::outbound::ProxyMode::Pool,
            catalog_pool: true,
            catalog_country: "FI".to_owned(),
            ..crate::relay::outbound::OutboundConfig::default()
        };
        let pool = pool_for(&cfg, Some(&s)).expect("FI pool");
        assert!(!pool.is_empty());
        assert!(pool.iter().all(|e| e.host.starts_with("10.fi.")));
    }

    // ---- v1.9.5 dynamic re-evaluation (spec: classification is never frozen) ----

    #[test]
    fn limited_becomes_full_when_new_passthrough_candidates_arrive() {
        // Scan N: FI cf-relay-only → limited. Scan N+1: the feed now carries
        // passthrough candidates and they are healthy → full. Same country,
        // no persisted label.
        let scan_n = snap_with_capabilities(&[("FI", 8, &[("cf-relay", 8)])]);
        let q_n = country_quality(&scan_n, &BTreeMap::new(), 1_000);
        assert_eq!(q_n["FI"].state, "limited");
        let scan_n1 = snap_with_capabilities(&[("FI", 5, &[("passthrough", 5)])]);
        let health = BTreeMap::from([healthy("FI", 1_000)]);
        let q_n1 = country_quality(&scan_n1, &health, 2_000);
        assert_eq!(q_n1["FI"].state, "full");
    }

    #[test]
    fn full_becomes_limited_when_the_feed_loses_passthrough() {
        // Reverse transition: a country that WAS full re-classifies from the
        // new snapshot alone — nothing cached the old verdict.
        let old = snap_with_capabilities(&[("TR", 4, &[("passthrough", 4)])]);
        let health = BTreeMap::from([healthy("TR", 1_000)]);
        let q_old = country_quality(&old, &health, 2_000);
        assert_eq!(q_old["TR"].state, "full");
        let new = snap_with_capabilities(&[("TR", 4, &[("cf-relay", 4)])]);
        let q_new = country_quality(&new, &health, 2_000);
        assert_eq!(q_new["TR"].state, "limited");
    }

    #[test]
    fn full_drops_to_degraded_when_its_passthrough_candidates_die() {
        let s = snap_with_capabilities(&[("JO", 4, &[("passthrough", 4)])]);
        let alive = BTreeMap::from([healthy("JO", 1_000)]);
        assert_eq!(country_quality(&s, &alive, 2_000)["JO"].state, "full");
        // Same feed, same candidates — but the latest measurements all failed
        // (two consecutive failures → quarantined). Nothing stale involved.
        let dead = BTreeMap::from([(
            "10.jo.0.1:443".to_owned(),
            Health { ok: false, fail_count: 2, updated_at_ms: 2_000, ..Health::default() },
        )]);
        let q = country_quality(&s, &dead, 3_000);
        assert_eq!(q["JO"].state, "degraded");
    }

    #[test]
    fn ancient_evidence_is_not_current_proof_in_either_direction() {
        let s = snap_with_capabilities(&[("FI", 8, &[("cf-relay", 8)])]);
        // A 3-day-old HEALTHY record must not make the country look alive…
        let old_ok = BTreeMap::from([healthy("FI", 0)]);
        let q = country_quality(&s, &old_ok, 72 * 60 * 60 * 1000);
        assert_eq!(q["FI"].healthy, 0, "stale success is not liveness");
        // …and a 3-day-old FAILED record must not brand it broken.
        let old_dead = BTreeMap::from([(
            "10.fi.0.1:443".to_owned(),
            Health { ok: false, fail_count: 2, updated_at_ms: 0, ..Health::default() },
        )]);
        let q2 = country_quality(&s, &old_dead, 72 * 60 * 60 * 1000);
        assert_eq!(q2["FI"].state, "limited", "stale failure is not unavailability");
    }

    #[test]
    fn every_catalog_country_is_reclassified_on_each_call() {
        // No hardcoded exceptions: the map covers exactly the snapshot's
        // countries, whatever they are, and a changed snapshot changes the map.
        let a = snap_with_capabilities(&[
            ("JO", 2, &[("passthrough", 2)]),
            ("XX", 2, &[("cf-relay", 2)]),
        ]);
        let qa = country_quality(&a, &BTreeMap::new(), 1_000);
        assert_eq!(qa.len(), 2);
        assert!(qa.contains_key("JO") && qa.contains_key("XX"));
        let b = snap_with_capabilities(&[("ZZ", 1, &[("passthrough", 1)])]);
        let qb = country_quality(&b, &BTreeMap::new(), 1_000);
        assert_eq!(qb.len(), 1);
        assert!(qb.contains_key("ZZ") && !qb.contains_key("JO"));
    }

    #[test]
    fn ordering_follows_current_quality_not_history() {
        // The spec's example: quality moves, and so must the order. Deriving
        // (state, quality) fresh, the sort key flips when the evidence flips.
        let s = snap_with_capabilities(&[
            ("JO", 8, &[("passthrough", 8)]),
            ("TR", 8, &[("passthrough", 2), ("cf-relay", 6)]),
        ]);
        let health = BTreeMap::from([healthy("JO", 1_000), healthy("TR", 1_000)]);
        let q = country_quality(&s, &health, 2_000);
        let rank = |v: &CountryQuality| (match v.state.as_str() {
            "full" => 0, "degraded" => 1, "limited" => 2, _ => 3
        }, 100 - v.quality.unwrap_or(0));
        let mut keys: Vec<_> = q.values().map(rank).collect();
        keys.sort();
        assert_eq!(keys[0], rank(&q["JO"]), "higher passthrough share leads");
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

    // §6 revision-aware fetch: decision table.
    #[test]
    fn same_revision_is_a_noop_even_with_a_newer_timestamp() {
        let s = snapshot();
        // Equal content_revision wins over any generated_at: zero writes.
        assert_eq!(
            revision_decision(&s.content_revision, "2026-09-25T00:00:00Z", Some(&s.content_revision), Some("2026-09-20T16:33:24Z")),
            Ok(false)
        );
    }

    #[test]
    fn newer_revision_activates() {
        let doc = serde_json::json!({ "snapshot": snapshot(), "fetchedAt": "x" }).to_string();
        assert_eq!(
            revision_decision(
                &"c".repeat(64),
                "2026-09-21T00:00:00Z", // later than stored 2026-09-20T16:33:24Z
                stored_revision(Some(&doc)).as_deref(),
                stored_generated_at(Some(&doc)).as_deref(),
            ),
            Ok(true)
        );
    }

    #[test]
    fn older_generated_at_is_rejected() {
        let doc = serde_json::json!({ "snapshot": snapshot(), "fetchedAt": "x" }).to_string();
        let decision = revision_decision(
            &"c".repeat(64),
            "2026-09-19T00:00:00Z", // older than stored 2026-09-20T16:33:24Z
            stored_revision(Some(&doc)).as_deref(),
            stored_generated_at(Some(&doc)).as_deref(),
        );
        assert!(decision.is_err(), "older feed must be rejected, not activated");
    }

    #[test]
    fn equal_timestamp_with_new_revision_still_activates() {
        // Republish within the same second must not wedge the pipeline.
        assert_eq!(
            revision_decision(&"c".repeat(64), "2026-09-20T16:33:24Z", Some(&"b".repeat(64)), Some("2026-09-20T16:33:24Z")),
            Ok(true)
        );
    }

    #[test]
    fn first_sync_activates_without_stored_document() {
        assert_eq!(
            revision_decision(&"c".repeat(64), "2026-09-21T00:00:00Z", None, None),
            Ok(true)
        );
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

    // §29 failure safety: an upstream that dies, hangs, or starts serving
    // garbage must leave the previous catalog active. sync() represents every
    // such outcome as a SyncReport with ok=false, changed=false — the write
    // block is gated on `changed`, so no KV mutation can happen. These tests
    // pin that decision table end-to-end at the pure layer (the wasm fetch/KV
    // halves are exercised live in §29's deploy proof).
    #[test]
    fn old_catalog_survives_upstream_fetch_failure() {
        // Fetch failure: status none, empty report fields, no activation.
        let r = SyncReport {
            ok: false,
            changed: false,
            content_revision: String::new(),
            upstream_revision: String::new(),
            generated_at: String::new(),
            fetched_at: "now".into(),
            country_count: 0,
            endpoint_count: 0,
            error: Some("catalog fetch timed out".into()),
        };
        let line = sync_log(None, &r, "fetch failed", "82fa9022b9f8");
        // The active revision is reported as still-active; nothing "activated".
        assert!(line.contains("active_revision=82fa9022b9f8"));
        assert!(line.contains("activation=kept"));
        assert!(line.contains("validation=rejected"));
        assert!(line.contains("http=none"));
        assert!(!r.changed);
    }

    #[test]
    fn old_catalog_survives_upstream_garbage() {
        // Garbage body: parse failure path — previous snapshot kept, changed=false.
        assert!(Snapshot::parse(b"not a feed").is_err());
        let doc = serde_json::json!({ "snapshot": snapshot(), "fetchedAt": "x" }).to_string();
        // And even a parseable feed that is BOTH older and differently
        // revisioned is rejected by the §6 guard (a replayed stale feed).
        let older = VALID
            .replace("2026-09-20T16:33:24Z", "2026-09-19T00:00:00Z")
            .replace("bbbbbbbbbbbb", "cccccccccccc");
        let snap = Snapshot::parse(older.as_bytes()).expect("older feed parses");
        let decision = revision_decision(
            snap.content_revision.as_str(),
            snap.generated_at.as_str(),
            stored_revision(Some(&doc)).as_deref(),
            stored_generated_at(Some(&doc)).as_deref(),
        );
        assert!(decision.is_err(), "rollback must be rejected; old catalog stays active");
    }

    #[test]
    fn sync_log_shape_pins_the_operability_fields() {
        // §21: the one line per pull carries every operability field and no
        // secrets — no URL, no query, no binding values.
        let r = SyncReport {
            ok: true,
            changed: true,
            content_revision: "96781ded18f9fc12ffffffffffffffffffffffffffffffffffffffffffff".into(),
            upstream_revision: "e6107b3ffa0b93d2".into(),
            generated_at: "2026-09-28T00:23:00Z".into(),
            fetched_at: "2026-09-28T00:23:05Z".into(),
            country_count: 79,
            endpoint_count: 1945,
            error: None,
        };
        let line = sync_log(Some(200), &r, "new revision activated", "82fa9022b9f8");
        for needle in [
            "http=200",
            "fetched_revision=96781ded18f9",
            "active_revision=82fa9022b9f8",
            "validation=ok",
            "activation=activated",
            "countries=79",
            "endpoints=1945",
            "last_success=2026-09-28T00:23:05Z",
            "last_failure=none",
            "reason=new revision activated",
        ] {
            assert!(line.contains(needle), "missing `{needle}` in: {line}");
        }
        assert!(!line.contains("https://"), "no URL in the log line");
        assert_eq!(line.matches('\n').count(), 0, "one line");
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
    fn quarantined_candidates_never_enter_the_pool() {
        // The vantage model's eligibility half: a candidate the worker
        // itself could not TCP-connect (the 44-IP US failure) or that failed
        // repeatedly must not enter ANY pool — while a single soft failure
        // only demotes, and no record keeps the candidate eligible.
        let mk = |h: &str| Endpoint { host: h.into(), port: 443 };
        let mut health = std::collections::BTreeMap::new();
        health.insert(
            "hard-dead.example:443".into(),
            crate::relay::outbound_state::Health {
                ok: false,
                fail_count: 1,
                error: "tcp connect: cannot connect to the specified address".into(),
                ..Default::default()
            },
        );
        health.insert(
            "soft-twice.example:443".into(),
            crate::relay::outbound_state::Health {
                ok: false,
                fail_count: 2,
                error: "tls handshake failed".into(),
                ..Default::default()
            },
        );
        health.insert(
            "soft-once.example:443".into(),
            crate::relay::outbound_state::Health {
                ok: false,
                fail_count: 1,
                error: "tls handshake failed".into(),
                ..Default::default()
            },
        );
        health.insert(
            "fine.example:443".into(),
            crate::relay::outbound_state::Health {
                country: "US".into(),
                ok: true,
                ok_count: 3,
                ..Default::default()
            },
        );
        let pool = bounded(
            [
                mk("hard-dead.example"),
                mk("soft-twice.example"),
                mk("soft-once.example"),
                mk("fine.example"),
                mk("unprobed.example"),
            ]
            .into_iter(),
            &health,
            &std::collections::BTreeMap::new(),
            &std::collections::BTreeMap::new(),
            false,
        );
        let hosts: Vec<&str> = pool.iter().map(|e| e.host.as_str()).collect();
        assert!(
            !hosts.contains(&"hard-dead.example") && !hosts.contains(&"soft-twice.example"),
            "quarantined candidate in pool: {hosts:?}"
        );
        assert_eq!(hosts[0], "fine.example", "healthy first: {hosts:?}");
        assert!(hosts.contains(&"soft-once.example"), "single soft failure demotes only: {hosts:?}");
        assert!(hosts.contains(&"unprobed.example"), "no verdict = eligible: {hosts:?}");
        assert_eq!(
            hosts.last(),
            Some(&"soft-once.example"),
            "single soft failure ranks last: {hosts:?}"
        );
    }

    #[test]
    fn passthrough_outranks_cf_relay_at_equal_health() {
        // Capability-aware ranking (spec PHASE 5): with identical health
        // bands, a Stage-C passthrough candidate sorts before cf-relay and
        // sni-terminate sinks below both. All unmeasured here (band 1).
        let mk = |h: &str| Endpoint { host: h.into(), port: 443 };
        let mut capability = std::collections::BTreeMap::new();
        capability.insert("relay.example:443".to_string(), "cf-relay".to_string());
        capability.insert("pass.example:443".to_string(), "passthrough".to_string());
        capability.insert("terminating.example:443".to_string(), "sni-terminate".to_string());
        let pool = bounded(
            [mk("relay.example"), mk("pass.example"), mk("terminating.example")].into_iter(),
            &std::collections::BTreeMap::new(),
            &capability,
            &std::collections::BTreeMap::new(),
            false,
        );
        let hosts: Vec<&str> = pool.iter().map(|e| e.host.as_str()).collect();
        assert_eq!(hosts, vec!["pass.example", "relay.example", "terminating.example"]);
    }

    #[test]
    fn bounded_high_risk_sinks_within_band_unknown_never_demoted() {
        let mk = |h: &str, p: u16| Endpoint {
            host: h.to_string(),
            port: p,
        };
        // All healthy-band, same capability: feed risk must only reorder, not evict.
        let mut quality = std::collections::BTreeMap::new();
        quality.insert("risky.example:443".to_string(), "high/datacenter/0.9/ip-api".to_string());
        quality.insert("fine.example:443".to_string(), "low/residential/0.9/ip-api".to_string());
        // unknown.example: deliberately absent — unmeasured must NOT rank after healthy-low.
        let pool = bounded(
            [mk("unknown.example", 443), mk("risky.example", 443), mk("fine.example", 443)]
                .into_iter(),
            &std::collections::BTreeMap::new(),
            &std::collections::BTreeMap::new(),
            &quality,
            false,
        );
        let hosts: Vec<&str> = pool.iter().map(|e| e.host.as_str()).collect();
        // Measured-low beats high; ties (low vs unmeasured) keep catalog order —
        // absent evidence is never treated as worse evidence.
        assert_eq!(hosts, vec!["unknown.example", "fine.example", "risky.example"]);
        // All three remain eligible — high risk re-ranks, never disqualifies.
        assert_eq!(pool.len(), 3);
    }

    #[test]
    fn verify_order_is_deterministic_and_country_first_stale_first() {
        use crate::relay::outbound_state::Health;
        let snap = snapshot();
        let mut health = std::collections::BTreeMap::new();
        // One DE candidate measured recently, one measured long ago, rest
        // unmeasured.
        health.insert(
            "203.0.113.7:443".into(),
            Health { country: "DE".into(), ok: true, updated_at_ms: 1_000, ..Default::default() },
        );
        health.insert(
            "proxy.example.com:8443".into(),
            Health { country: "DE".into(), ok: true, updated_at_ms: 500, ..Default::default() },
        );
        let order = verify_order(&snap, &health, "DE");
        let keys: Vec<String> = order
            .iter()
            .map(|e| format!("{}:{}", e.host.to_ascii_lowercase(), e.port))
            .collect();
        // Deterministic: same inputs, same list, every time.
        assert_eq!(keys, {
            let again: Vec<String> = verify_order(&snap, &health, "DE")
                .iter()
                .map(|e| format!("{}:{}", e.host.to_ascii_lowercase(), e.port))
                .collect();
            again
        });
        // The country in use first; within it unmeasured entries before
        // measured ones, and stale measurements before fresh ones (they need
        // re-verification most).
        assert_eq!(keys[0], "2001:db8::1:2053", "unmeasured DE first: {keys:?}");
        assert_eq!(keys[1], "proxy.example.com:8443", "stale-before-fresh: {keys:?}");
        assert_eq!(keys[2], "203.0.113.7:443", "freshest DE last: {keys:?}");
        assert!(keys[3..].iter().all(|k| k.starts_with("198.51.100.1") || k.starts_with("bpb")),
            "DE must finish before the rest: {keys:?}");
        // No duplicated entries: country lists, auto and unassigned dedupe by key.
        let unique: std::collections::HashSet<&String> = keys.iter().collect();
        assert_eq!(unique.len(), keys.len(), "duplicate candidate in verify order");
    }

    #[test]
    fn enforced_pool_spends_slots_on_capability_not_only_measured_health() {
        // Bug #2: `pool_for_with_health` bounded the slot cap before any
        // capability-aware ranking ran, so a country whose only
        // full-capability (passthrough) boxes were unmeasured got a runtime
        // pool of measured cf-relay candidates — and a cf-relay cannot serve
        // the plain-HTTP traffic class the operator picked that country for.
        // In an enforced pool a passthrough must outrank a healthy cf-relay.
        let mk = |host: &str, port: u16| Endpoint { host: host.into(), port };
        let mut capability = std::collections::BTreeMap::new();
        capability.insert("relay.example:2053".to_string(), "cf-relay".to_string());
        capability.insert("pass.example:2053".to_string(), "passthrough".to_string());
        let mut health = std::collections::BTreeMap::new();
        health.insert(
            "relay.example:2053".to_string(),
            crate::relay::outbound_state::Health {
                country: "TR".into(),
                latency_ms: 40,
                ok: true,
                ..Default::default()
            },
        );
        let quality = std::collections::BTreeMap::new();
        let enforced = bounded(
            [mk("relay.example", 2053), mk("pass.example", 2053)].into_iter(),
            &health, &capability, &quality, true,
        );
        assert_eq!(enforced[0].host, "pass.example",
            "enforced pool must not let a healthy cf-relay crowd out passthrough");
        // Auto (non-enforced) selection keeps the legacy health-first ordering.
        let auto = bounded(
            [mk("relay.example", 2053), mk("pass.example", 2053)].into_iter(),
            &health, &capability, &quality, false,
        );
        assert_eq!(auto[0].host, "relay.example");

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
            &std::collections::BTreeMap::new(),
            &std::collections::BTreeMap::new(),
            false,
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
    /// V24.8 §8: the integrity gate accepts a body whose content_revision is
    /// the scanner-recipe hash over its countries map.
    fn integrity_accepts_real_recipe_body() {
        let countries = r#"{"FI": [["1.2.3.4", 443], ["5.6.7.8", 8443]], "US": [["9.9.9.9", 80]]}"#;
        // Python: json.dumps(json.loads(countries), sort_keys=True)
        let canonical = "{\"FI\": [[\"1.2.3.4\", 443], [\"5.6.7.8\", 8443]], \"US\": [[\"9.9.9.9\", 80]]}";
        use sha2::Digest as _;
        let hex: String = sha2::Sha256::digest(canonical.as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let feed = format!(
            r#"{{"schema_version":1,"upstream_revision":"{}","content_revision":"{}","generated_at":"t","countries":{countries}}}"#,
            "a".repeat(64),
            hex
        );
        assert!(verify_integrity(feed.as_bytes(), &hex).is_ok());
    }

    #[test]
    /// A tampered body (one port flipped) must fail the gate.
    fn integrity_rejects_tampered_body() {
        let declared = "0".repeat(64);
        let feed = format!(
            r#"{{"schema_version":1,"content_revision":"{declared}","countries":{{"FI":[["1.2.3.4",443]]}}}}"#
        );
        assert!(verify_integrity(feed.as_bytes(), &declared).is_err());
    }

    #[test]
    /// Malformed JSON and missing countries never pass the gate.
    fn integrity_rejects_structural_garbage() {
        let declared = "0".repeat(64);
        assert!(verify_integrity(b"not json", &declared).is_err());
        assert!(verify_integrity(br#"{"schema_version":1}"#, &declared).is_err());
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
