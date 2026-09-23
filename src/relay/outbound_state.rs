//! Last-known-good Proxy IP preference, shared across sessions.
//!
//! Every session currently rediscovers which outbound route works by trying
//! candidates in a fixed order, paying full setup latency on dead candidates
//! each time. This module remembers the last candidate that actually carried a
//! session so the next session can try it first — while keeping every other
//! candidate available as fallback, because a preference that was right an
//! hour ago can be wrong now.
//!
//! # The two invariants that make reordering safe
//!
//! [`order_plan`] may only *move* a candidate to the front; it never drops,
//! duplicates, or rewrites one, and it never touches [`DialPlan::logical`].
//! A stale, absent, or foreign preference degrades to "no reorder", so the
//! worst case is exactly today's behaviour.
//!
//! # Why direct wins are not recorded
//!
//! In Proxy IP mode the first candidate *is* the logical destination, so a
//! direct win would record a per-session host (e.g. one website's domain) as
//! the "preferred" route. That string could never help a different session
//! and would churn the stored state for no benefit, so the caller records a
//! preference only when the winner was a genuine proxy candidate.

use crate::protocol::{Host, Target};
use crate::relay::outbound::DialPlan;

/// Where this document lives in the panel's SETTINGS namespace.
///
/// A separate key rather than a field inside `panel:settings`: sessions write
/// it autonomously at teardown, and a relay writing the operator's settings
/// document would need read-modify-write races against the panel UI.
pub const KV_KEY: &str = "panel:outbound_state";

/// How long a recorded preference stays fresh enough to act on.
pub const HEALTH_TTL_SECS: u64 = 3600;

/// Minimum spacing between writes for one winner change.
///
/// Sessions end constantly; without a floor, an oscillating route would put a
/// KV write on every session teardown.
pub const WRITE_DEBOUNCE_SECS: u64 = 300;

/// What a session learned about the outbound route, persisted between runs.
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct OutboundState {
    /// Canonical key ([`candidate_key`]) of the candidate that last worked,
    /// or `None` until a proxy candidate has won at least once.
    pub preferred: Option<String>,
    /// When the preference was written (session teardown time).
    pub updated_at_ms: u64,
    /// Last measured health per candidate host, keyed by [`host_key`].
    /// Written only by the operator-initiated panel probe, never the hot path.
    /// Session teardown must preserve this map (see [`with_preference`]).
    ///
    /// Deserialised leniently: an earlier deployment stored this as
    /// `{host: "DE"}`, and a whole-document parse failure would drop
    /// `preferred` with it and cost every session its known-good route.
    #[serde(default, deserialize_with = "de_geo")]
    pub geo: std::collections::BTreeMap<String, Health>,
    /// Country of the pool the current fallback was activated FOR (the
    /// configured primary at activation time). Empty when no fallback ran.
    #[serde(default)]
    pub fallback_primary: String,
    /// Country whose pool is currently dialed on top of the primary.
    /// Empty when no fallback is active.
    #[serde(default)]
    pub fallback_active: String,
    /// When the fallback was (re)activated. Drives the 5-minute hold in
    /// [`fallback_fresh`].
    #[serde(default)]
    pub fallback_at_ms: u64,
}

/// Accept both the current record shape and the older country-string shape.
///
/// A bare country carries no measurement, so it loads as country-only with no
/// success count: it can satisfy a preference filter but never ranks as
/// measured-healthy until a probe confirms it.
fn de_geo<'de, D>(d: D) -> core::result::Result<std::collections::BTreeMap<String, Health>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::Deserialize;

    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Entry {
        Record(Health),
        Country(String),
    }

    let raw = std::collections::BTreeMap::<String, Entry>::deserialize(d)?;
    Ok(raw
        .into_iter()
        .map(|(host, entry)| {
            let health = match entry {
                Entry::Record(h) => h,
                Entry::Country(country) => Health { country, ..Default::default() },
            };
            (host, health)
        })
        .collect())
}

/// What the panel probe last measured for one candidate.
///
/// One record per candidate host, stored on this document because it is read
/// on the dial path and a second KV key would be a second read per session.
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Health {
    /// Exit country (ISO 3166-1 alpha-2), empty when the probe could not read
    /// one. Only a non-empty value can satisfy a country preference.
    pub country: String,
    /// Cloudflare colo the egress landed in, for the operator's eyes.
    pub colo: String,
    /// Exit IP as the trace reported it. A candidate whose exit IP changes
    /// between probes is not a stable identity, which is what
    /// [`Health::stable`] reports.
    pub exit_ip: String,
    /// Round trip of the last successful probe, milliseconds.
    pub latency_ms: u32,
    /// Whether the last probe succeeded.
    pub ok: bool,
    /// Successful probes since this record was created.
    pub ok_count: u32,
    /// Failed probes since this record was created.
    pub fail_count: u32,
    /// Set when a probe saw a different exit IP than the one already stored:
    /// the egress is rotating, so it cannot offer a consistent identity.
    pub rotating: bool,
    /// When this record was last written (probe time).
    pub updated_at_ms: u64,
    /// Last probe error, when the last probe failed.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub error: String,
}

impl Health {
    /// Success rate over observed probes, 0.0 when nothing is known.
    #[must_use]
    pub fn success_rate(&self) -> f64 {
        let total = self.ok_count.saturating_add(self.fail_count);
        if total == 0 {
            return 0.0;
        }
        f64::from(self.ok_count) / f64::from(total)
    }

    /// Whether this candidate is currently usable as a preferred exit.
    #[must_use]
    pub fn healthy(&self) -> bool {
        self.ok && !self.country.is_empty()
    }

    /// Whether the exit identity has held still across probes.
    #[must_use]
    pub fn stable(&self) -> bool {
        !self.rotating
    }

    /// Ranking score, higher is better. Ordering only — the absolute value
    /// carries no meaning outside a comparison between candidates.
    ///
    /// Success rate dominates (a candidate that fails is worthless however
    /// fast it is), then a stable exit identity, then latency. `wanted` adds
    /// a country match bonus so a matching candidate outranks a marginally
    /// faster one in the wrong country.
    #[must_use]
    pub fn score(&self, wanted: &str) -> f64 {
        if !self.ok {
            return f64::from(self.success_rate() as f32) * 10.0;
        }
        let mut score = self.success_rate() * 100.0;
        if self.stable() {
            score += 25.0;
        }
        let wanted = wanted.trim();
        if !wanted.is_empty() && self.country.eq_ignore_ascii_case(wanted) {
            score += 40.0;
        }
        // Latency: a full 20 points at 0 ms decaying to 0 at 400 ms, so it
        // breaks ties without ever outweighing reliability.
        let latency_penalty = f64::from(self.latency_ms.min(400)) / 400.0;
        score += 20.0 * (1.0 - latency_penalty);
        score
    }

    /// Fold a fresh successful probe into this record.
    #[must_use]
    pub fn observed_ok(
        mut self,
        country: String,
        colo: String,
        exit_ip: String,
        latency_ms: u32,
        now_ms: u64,
    ) -> Self {
        // A changed exit IP is the rotation signal. First observation is not
        // rotation: there is nothing to have changed from.
        if !self.exit_ip.is_empty() && !exit_ip.is_empty() && self.exit_ip != exit_ip {
            self.rotating = true;
        }
        // Same for country: an exit that moves between countries cannot serve
        // a country preference consistently, even if the IP is unchanged.
        if !self.country.is_empty() && !country.is_empty() && !self.country.eq_ignore_ascii_case(&country) {
            self.rotating = true;
        }
        Self {
            country,
            colo,
            exit_ip,
            latency_ms,
            ok: true,
            ok_count: self.ok_count.saturating_add(1),
            updated_at_ms: now_ms,
            error: String::new(),
            ..self
        }
    }

    /// Fold a fresh failed probe into this record, keeping what was learned
    /// before: a candidate that fails one probe has not lost its country.
    #[must_use]
    pub fn observed_fail(mut self, error: String, now_ms: u64) -> Self {
        self.ok = false;
        self.fail_count = self.fail_count.saturating_add(1);
        self.updated_at_ms = now_ms;
        self.error = error;
        self
    }
}

impl OutboundState {
    /// Parse a stored document, falling back to "nothing known" on any
    /// malformed input. A corrupted blob must never cost a session its
    /// default routing behaviour.
    #[must_use]
    pub fn from_json(raw: &str) -> Self {
        serde_json::from_str(raw).unwrap_or_default()
    }

    /// The preferred candidate's key, when present and still fresh.
    fn preferred_fresh(&self, now_ms: u64) -> Option<&str> {
        let pref = self.preferred.as_deref()?.trim();
        if pref.is_empty() || self.updated_at_ms == 0 {
            return None;
        }
        if now_ms.saturating_sub(self.updated_at_ms) > HEALTH_TTL_SECS.saturating_mul(1000) {
            return None;
        }
        Some(pref)
    }
}

/// Empty or a two-letter ISO 3166-1 alpha-2 code. Anything else is refused
/// at save rather than silently ignored.
#[must_use]
pub fn valid_country(s: &str) -> bool {
    let s = s.trim();
    s.is_empty()
        || (s.len() == 2 && s.bytes().all(|b| b.is_ascii_alphabetic()))
}

impl OutboundState {
    /// Same document with a new LKG preference, geo map kept as-is.
    #[must_use]
    pub fn with_preference(self, preferred: Option<String>, updated_at_ms: u64) -> Self {
        Self {
            preferred,
            updated_at_ms,
            geo: self.geo,
            fallback_primary: self.fallback_primary,
            fallback_active: self.fallback_active,
            fallback_at_ms: self.fallback_at_ms,
        }
    }

    /// Empty preference, geo map kept. Used when a session demotes LKG.
    #[must_use]
    pub fn cleared_preference(self) -> Self {
        Self {
            preferred: None,
            updated_at_ms: 0,
            geo: self.geo,
            fallback_primary: self.fallback_primary,
            fallback_active: self.fallback_active,
            fallback_at_ms: self.fallback_at_ms,
        }
    }
}

/// Is a recorded fallback still inside its hold window?
///
/// A fallback stays "fresh" for [`FALLBACK_HOLD_SECS`] from activation, and
/// only while it is actually active AND for the same primary it was activated
/// for — an operator who changes the configured location invalidates the
/// hold immediately, so the next failure re-derives a fallback for the NEW
/// primary instead of layering onto a stale one.
#[must_use]
pub fn fallback_fresh(state: &OutboundState, now_ms: u64) -> bool {
    if state.fallback_active.is_empty() || state.fallback_at_ms == 0 {
        return false;
    }
    now_ms.saturating_sub(state.fallback_at_ms) < FALLBACK_HOLD_SECS.saturating_mul(1000)
}

/// Rotation epoch for fallback selection: the index of the 10-minute
/// `now_ms` bucket. Stable within a bucket, different across buckets, so
/// consecutive failures in the same bucket rotate deterministically through
/// [`crate::catalog::choose_fallback_country`]'s ranked candidates instead
/// of always picking the first.
#[must_use]
pub fn fallback_epoch(now_ms: u64) -> u64 {
    now_ms / FALLBACK_EPOCH_BUCKET_MS
}

/// How long an activated geographic fallback is honoured before expiring.
pub const FALLBACK_HOLD_SECS: u64 = 300;

/// Width of the fallback rotation bucket (10 minutes).
pub const FALLBACK_EPOCH_BUCKET_MS: u64 = 600_000;

/// The canonical comparison key for a candidate: host and PORT.
///
/// Domains compare case-insensitively (KV stores what the panel saved, xray
/// dials whatever case it resolved), IPs through their canonical rendering.
/// The port is part of the key on purpose: a proxy host that carried TLS
/// traffic says nothing about whether it forwards plain port-80 dials, and a
/// port-blind preference was measured adding a full 5 s handshake timeout to
/// every mismatched-port dial before the fallback succeeded.
#[must_use]
pub fn candidate_key(target: &Target) -> String {
    let host = match &target.host {
        Host::Domain(d) => d.trim().to_ascii_lowercase(),
        Host::Ip(ip) => ip.to_string(),
    };
    format!("{host}:{}", target.port)
}

/// Move the fresh preferred candidate forward in the plan — behind the direct
/// candidate, ahead of every other proxy — if it is one of the candidates at all.
///
/// # Why the logical destination keeps index 0
///
/// In Proxy IP mode the first candidate is the destination itself, dialled
/// over the runtime's own network — the only candidate that never leaves
/// Cloudflare's edge. Measured live: reordering the preferred proxy ahead of
/// it sent Google-family, Netflix and Spotify SNIs through the third-party
/// proxy pool, whose nodes answered those SNIs with TLS handshake alerts and,
/// on one node, a forged certificate, while the same destinations over
/// Cloudflare's own egress completed with the real certificate byte for byte.
/// The preference therefore goes immediately *behind* the direct candidate:
/// it still skips every other proxy, and it can never take traffic off the
/// clean path.
///
/// Pure: returns a new plan rather than mutating the input's `logical`, and
/// preserves the candidate list exactly (same members, same length).
#[must_use]
pub fn order_plan(plan: DialPlan, state: &OutboundState, now_ms: u64) -> DialPlan {
    order_plan_pref(plan, state, now_ms, "")
}

/// [`order_plan`], plus an operator country preference (ISO 3166-1 alpha-2).
///
/// Equivalent to [`order_plan_ranked`] with no manual pin.
#[must_use]
pub fn order_plan_pref(
    plan: DialPlan,
    state: &OutboundState,
    now_ms: u64,
    country: &str,
) -> DialPlan {
    order_plan_ranked(plan, state, now_ms, country, "")
}

/// Order the proxy candidates: manual pin, then LKG, then measured quality.
///
/// Precedence is deliberate and narrow-to-broad. An explicit pin is the
/// operator overriding the system, so it wins. LKG is next: it is the only
/// signal produced by a real session rather than a probe. Quality ranking
/// orders whatever is left.
///
/// Every rule here only *reorders*. No candidate is ever dropped, so a stale
/// measurement, an unreachable pin or an unmet country preference costs
/// attempt order and never connectivity — a bad selection cannot strand the
/// operator. Slot 0 (the direct destination in Proxy IP mode) is never moved,
/// so direct-first survives all of it.
#[must_use]
pub fn order_plan_ranked(
    mut plan: DialPlan,
    state: &OutboundState,
    now_ms: u64,
    country: &str,
    pin: &str,
) -> DialPlan {
    let at = usize::from(plan.candidates.first() == Some(&plan.logical));
    rank_by_quality(&mut plan, state, at, country);
    if let Some(pref) = state.preferred_fresh(now_ms) {
        if let Some(idx) = plan.candidates.iter().position(|c| candidate_key(c) == pref) {
            if idx > at {
                let candidate = plan.candidates.remove(idx);
                plan.candidates.insert(at, candidate);
            }
        }
    }
    apply_pin(&mut plan, at, pin);
    plan
}

/// Sort proxy candidates by measured quality, best first.
///
/// Ordering only: every candidate stays in the plan, so a wrong or stale
/// measurement costs attempt order and never reachability. Unmeasured
/// candidates keep their configured order behind measured healthy ones —
/// "unknown" must not outrank "known good", and must not be dropped either.
fn rank_by_quality(plan: &mut DialPlan, state: &OutboundState, at: usize, country: &str) {
    if plan.candidates.len().saturating_sub(at) < 2 {
        return;
    }
    let mut tail: Vec<Target> = plan.candidates.split_off(at);
    // Stable sort on the negated score: equal-scoring candidates (including
    // every unmeasured one, all scoring 0) keep the operator's own order.
    tail.sort_by(|a, b| {
        let sa = state.geo.get(&host_key(a)).map_or(0.0, |h| h.score(country));
        let sb = state.geo.get(&host_key(b)).map_or(0.0, |h| h.score(country));
        sb.partial_cmp(&sa).unwrap_or(core::cmp::Ordering::Equal)
    });
    plan.candidates.extend(tail);
}

/// Move a manually pinned candidate to the front of the proxy candidates.
///
/// A pin the plan does not contain is ignored rather than enforced: the
/// operator pinning a candidate they then removed must not cost the session
/// its route.
fn apply_pin(plan: &mut DialPlan, at: usize, pin: &str) {
    let pin = pin.trim().to_ascii_lowercase();
    if pin.is_empty() {
        return;
    }
    if let Some(idx) = plan
        .candidates
        .iter()
        .skip(at)
        .position(|c| host_key(c) == pin || candidate_key(c) == pin)
    {
        let candidate = plan.candidates.remove(at + idx);
        plan.candidates.insert(at, candidate);
    }
}

/// The host part of a candidate key, without the port: geo is a property of
/// the egress address, not of the port dialled.
fn host_key(target: &Target) -> String {
    match &target.host {
        Host::Domain(d) => d.trim().to_ascii_lowercase(),
        Host::Ip(ip) => ip.to_string(),
    }
}

/// Whether a session that ended on `winner` should update the stored state.
///
/// Two gates, both required: the winner differs from what is already stored,
/// and the last write is older than [`WRITE_DEBOUNCE_SECS`]. A brand-new
/// state (timestamp zero) debounces trivially — the epoch is always in the
/// past — so the first observation records immediately.
#[must_use]
pub fn should_record(winner: &Target, state: &OutboundState, now_ms: u64) -> bool {
    should_record_key(
        &candidate_key(winner),
        state.preferred.as_deref(),
        state.updated_at_ms,
        now_ms,
    )
}

fn should_record_key(winner_key: &str, preferred: Option<&str>, updated_at_ms: u64, now_ms: u64) -> bool {
    if preferred.is_some_and(|p| p.trim().to_ascii_lowercase() == winner_key) {
        return false;
    }
    now_ms.saturating_sub(updated_at_ms) >= WRITE_DEBOUNCE_SECS.saturating_mul(1000)
}

/// What teardown should do with the stored preference after one session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LkgAction {
    /// Leave the stored document untouched.
    Keep,
    /// Remove the preference entirely (it steered this session wrong).
    Clear,
    /// Store this candidate as the new preference.
    Record(String),
}

/// How the outbound dial phase ended for one session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DialVerdict<'a> {
    /// A candidate connected and carried the session.
    Won {
        /// Key of the winning candidate ([`candidate_key`]).
        winner: &'a str,
        /// True when the winner was the logical destination itself (direct).
        is_direct: bool,
        /// Key of the first candidate that failed en route to the win.
        first_failed: Option<&'a str>,
    },
    /// Every candidate failed; no socket exists.
    Failed,
}

/// Decide the teardown action for the stored preference.
///
/// Rules, in order:
/// - a total dial failure clears any existing preference — it was probably
///   what steered every attempt wrong, and keeping it would steer the next
///   session identically;
/// - a proxy win follows the ordinary record rules (changed AND debounced),
///   and recording supersedes clearing because the fresh winner replaces the
///   stale preference outright;
/// - a direct win keeps nothing by convention, EXCEPT when the recorded
///   preference is exactly the candidate that failed first this session —
///   then it is demoted immediately rather than steering sessions onto a
///   degraded proxy until its TTL expires (measured live: a stale cross-port
///   preference cost every dial a full handshake timeout);
/// - a proxy win by the preferred candidate itself demotes it when
///   `bytes_dropped` is set: the egress connected but the session relayed
///   almost nothing, the signature of a destination TLS that never completes
///   behind a dirty IP. Reachable is not usable, so the preference is cleared
///   and the next session falls through to the remaining candidates.
#[must_use]
pub fn lkg_on_session_result(
    preferred: Option<&str>,
    updated_at_ms: u64,
    verdict: DialVerdict<'_>,
    now_ms: u64,
    bytes_dropped: bool,
) -> LkgAction {
    let pref_failed = |first_failed: Option<&str>| -> bool {
        preferred.is_some_and(|p| {
            p.trim().to_ascii_lowercase() == first_failed.unwrap_or_default()
        })
    };
    match verdict {
        DialVerdict::Failed => {
            if preferred.is_some() {
                LkgAction::Clear
            } else {
                LkgAction::Keep
            }
        }
        DialVerdict::Won { winner, is_direct, first_failed } => {
            if !is_direct
                && should_record_key(winner, preferred, updated_at_ms, now_ms)
            {
                return LkgAction::Record(winner.to_owned());
            }
            if pref_failed(first_failed) {
                LkgAction::Clear
            } else if preferred.is_some_and(|p| p.eq_ignore_ascii_case(winner)) && bytes_dropped {
                // The preferred egress carried this session but the relay died
                // with almost nothing exchanged: a destination TLS that never
                // completes (blocked/dirty egress) looks exactly like this —
                // connect succeeds, few or zero useful bytes flow, teardown.
                // Demote so the next session tries the next candidate instead
                // of re-pinning a connected-but-unusable IP for the TTL.
                LkgAction::Clear
            } else {
                LkgAction::Keep
            }
        }
    }
}

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

    fn plan(cands: &[&str], port: u16) -> DialPlan {
        let logical = t(cands[0], port);
        DialPlan {
            logical: logical.clone(),
            candidates: std::iter::once(logical.clone())
                .chain(cands.iter().skip(1).map(|c| t(c, port)))
                .collect(),
        }
    }

    fn state(pref: Option<&str>, at_ms: u64) -> OutboundState {
        OutboundState {
            preferred: pref.map(str::to_owned),
            updated_at_ms: at_ms,
            ..Default::default()
        }
    }

    const NOW: u64 = 1_800_000_000_000;

    #[test]
    fn fresh_preferred_moves_behind_the_direct_candidate() {
        let p = plan(&["dest.example", "di.nscl.ir", "nima.nscl.ir"], 443);
        let ordered = order_plan(p, &state(Some("di.nscl.ir:443"), NOW - 1_000), NOW);
        // The preference jumps the other proxies; direct keeps slot 0.
        assert_eq!(ordered.candidates[0], t("dest.example", 443));
        assert_eq!(ordered.candidates[1], t("di.nscl.ir", 443));
        assert_eq!(ordered.candidates.len(), 3);
        assert_eq!(ordered.logical, t("dest.example", 443));
    }

    #[test]
    fn a_preferred_proxy_never_displaces_the_direct_candidate() {
        // Measured live (2026-09-09): with a fresh `di.nscl.ir:443` preference
        // the plan became [di, dest, nima], so Google-family, Netflix and
        // Spotify SNIs were served by the third-party proxy pool — which
        // answers some of them with a TLS handshake alert and, on one node, a
        // forged certificate — instead of Cloudflare's own egress, which
        // completes those same handshakes with the real certificate.
        for pref in ["di.nscl.ir:443", "nima.nscl.ir:443"] {
            let p = plan(&["dest.example", "di.nscl.ir", "nima.nscl.ir"], 443);
            let out = order_plan(p, &state(Some(pref), NOW), NOW);
            let host = pref.split(':').next().unwrap();
            assert_eq!(out.candidates[0], t("dest.example", 443), "{pref}");
            assert_eq!(out.candidates[1], t(host, 443), "{pref}");
        }
    }

    #[test]
    fn a_preference_learned_on_one_port_never_reorders_another_port() {
        // Regression for the measured live failure: a proxy that won on 443
        // was reordered ahead of direct for port-80 dials too, where it
        // blackholed and burned the whole handshake budget every time.
        let p = plan(&["dest.example", "di.nscl.ir", "nima.nscl.ir"], 80);
        let ordered = order_plan(p, &state(Some("di.nscl.ir:443"), NOW - 1_000), NOW);
        assert_eq!(ordered.candidates[0], t("dest.example", 80));
        // And the mirror image: an 80-win means nothing to a 443 dial.
        let p443 = plan(&["dest.example", "di.nscl.ir"], 443);
        let ordered443 =
            order_plan(p443, &state(Some("di.nscl.ir:80"), NOW - 1_000), NOW);
        assert_eq!(ordered443.candidates[0], t("dest.example", 443));
    }

    #[test]
    fn legacy_host_only_preferences_match_nothing_rather_than_guessing() {
        // Documents written before the port was part of the key degrade to
        // no-reorder instead of applying a possibly wrong guess.
        let p = plan(&["dest.example", "di.nscl.ir"], 443);
        let ordered = order_plan(p, &state(Some("di.nscl.ir"), NOW - 1_000), NOW);
        assert_eq!(ordered.candidates[0], t("dest.example", 443));
    }

    #[test]
    fn matching_is_case_insensitive_and_trimmed() {
        let p = plan(&["dest.example", "DI.NSCL.IR"], 443);
        let ordered = order_plan(p, &state(Some("  di.nscl.ir:443 "), NOW - 1_000), NOW);
        assert_eq!(ordered.candidates[0], t("dest.example", 443));
        assert_eq!(ordered.candidates[1], t("DI.NSCL.IR", 443));
    }

    #[test]
    fn stale_preference_reorders_nothing() {
        let ttl_ms = HEALTH_TTL_SECS * 1000;
        // Exactly one TTL old is still fresh enough to act on.
        let at_boundary = order_plan(
            plan(&["dest.example", "di.nscl.ir"], 443),
            &state(Some("di.nscl.ir:443"), NOW - ttl_ms),
            NOW,
        );
        assert_eq!(at_boundary.candidates[0], t("dest.example", 443));
        assert_eq!(at_boundary.candidates[1], t("di.nscl.ir", 443));
        // One millisecond past it is stale and reorders nothing.
        let past_ttl =
            order_plan(plan(&["dest.example", "di.nscl.ir"], 443), &state(Some("di.nscl.ir:443"), NOW - ttl_ms - 1), NOW);
        assert_eq!(past_ttl.candidates[0], t("dest.example", 443));
        assert_eq!(past_ttl.candidates[1], t("di.nscl.ir", 443));
    }

    #[test]
    fn absent_or_empty_preference_reorders_nothing() {
        for s in [state(None, NOW), state(Some(""), NOW), state(Some("   "), NOW)] {
            let p = plan(&["dest.example", "di.nscl.ir"], 443);
            let out = order_plan(p, &s, NOW);
            assert_eq!(out.candidates[0], t("dest.example", 443));
        }
    }

    #[test]
    fn preference_not_in_the_plan_is_ignored() {
        let p = plan(&["dest.example", "di.nscl.ir"], 443);
        let out = order_plan(p, &state(Some("pyip.ygkkk.dpdns.org:443"), NOW - 1_000), NOW);
        assert_eq!(
            out.candidates,
            vec![t("dest.example", 443), t("di.nscl.ir", 443)]
        );
    }

    #[test]
    fn already_first_is_a_no_op_not_a_churn() {
        let p = plan(&["dest.example", "di.nscl.ir"], 443);
        let out = order_plan(p, &state(Some("dest.example:443"), NOW - 1_000), NOW);
        assert_eq!(out.candidates[0], t("dest.example", 443));
        assert_eq!(out.candidates.len(), 2);
    }

    #[test]
    fn ordering_never_drops_or_duplicates_a_candidate() {
        // Property fuzz in the house style: no input shape may lose, clone,
        // or rewrite a candidate, and `logical` is untouchable.
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        let pool = [
            "dest.example",
            "di.nscl.ir",
            "nima.nscl.ir",
            "93.184.216.34",
            "proxyip.cmliussss.net",
        ];
        for _ in 0..2000 {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            let n = 1 + (seed % 4) as usize;
            let mut cands = Vec::new();
            for i in 0..n {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                cands.push(pool[((seed >> (i % 32)) as usize) % pool.len()]);
            }
            let built = plan(&cands, 443);
            seed ^= seed << 13;
            let age = (seed % 5_000_000) as u64;
            seed ^= seed << 17;
            let pick = pool[(seed as usize) % pool.len()];
            let st = state(Some(&format!("{pick}:443")), NOW.saturating_sub(age));

            let out = order_plan(built.clone(), &st, NOW);

            let key = |mut v: Vec<Target>| {
                v.sort_by(|a, b| candidate_key(a).cmp(&candidate_key(b)));
                v
            };
            assert_eq!(key(out.candidates.clone()), key(built.candidates.clone()));
            assert_eq!(out.candidates.len(), built.candidates.len());
            assert_eq!(out.logical, built.logical);
        }
    }

    #[test]
    fn changed_winner_inside_debounce_window_is_not_recorded() {
        let s = state(Some("di.nscl.ir:443"), NOW - (WRITE_DEBOUNCE_SECS * 1000 - 1));
        assert!(!should_record(&t("nima.nscl.ir", 443), &s, NOW));
    }

    #[test]
    fn changed_winner_at_the_debounce_boundary_is_recorded() {
        let s = state(Some("di.nscl.ir"), NOW - WRITE_DEBOUNCE_SECS * 1000);
        assert!(should_record(&t("nima.nscl.ir", 443), &s, NOW));
    }

    #[test]
    fn unchanged_winner_is_never_recorded_even_when_due() {
        let s = state(Some("di.nscl.ir:443"), NOW - WRITE_DEBOUNCE_SECS * 1000 * 100);
        assert!(!should_record(&t("DI.NSCL.IR", 443), &s, NOW));
    }


    #[test]
    fn preferred_winner_with_dropped_bytes_is_demoted() {
        let stale = NOW - (WRITE_DEBOUNCE_SECS * 1000 * 100);
        // Preferred egress carried the session but relayed almost nothing:
        // connected-but-dirty signature -> clear instead of keep.
        assert_eq!(
            lkg_on_session_result(
                Some("di.nscl.ir:443"),
                stale,
                DialVerdict::Won {
                    winner: "di.nscl.ir:443",
                    is_direct: false,
                    first_failed: None,
                },
                NOW,
                true,
            ),
            LkgAction::Clear
        );
        // Same session shape with real bytes exchanged keeps the preference.
        assert_eq!(
            lkg_on_session_result(
                Some("di.nscl.ir:443"),
                stale,
                DialVerdict::Won {
                    winner: "di.nscl.ir:443",
                    is_direct: false,
                    first_failed: None,
                },
                NOW,
                false,
            ),
            LkgAction::Keep
        );
    }

    #[test]
    fn first_observation_records_immediately() {
        let s = OutboundState::default();
        assert!(should_record(&t("di.nscl.ir", 443), &s, NOW));
    }

    #[test]
    fn serde_round_trip_preserves_the_document() {
        let original = state(Some("Di.Nscl.ir:443"), 1_756_000_000_123);
        let json = serde_json::to_string(&original).unwrap();
        assert_eq!(OutboundState::from_json(&json), original);
        // camelCase on the wire, as everywhere else in this project.
        assert!(json.contains("\"preferred\""));
        assert!(json.contains("\"updatedAtMs\""));
    }

    #[test]
    fn corrupted_json_degrades_to_default() {
        for raw in ["", "{", "null", "{\"preferred\":42}", "[1,2,3]"] {
            assert_eq!(OutboundState::from_json(raw), OutboundState::default());
        }
    }

    #[test]
    fn resolve_then_order_keeps_every_candidate_across_modes() {        use crate::relay::outbound::OutboundConfig;

        let cfg = OutboundConfig {
            mode: crate::relay::outbound::ProxyMode::ProxyIp,
            proxy_candidates: vec![
                "di.nscl.ir".into(),
                "nima.nscl.ir".into(),
                "bpb.yousef.isegaro.com".into(),
            ],
            nat64_prefixes: vec![],
            max_proxy_attempts: 8,
            ..Default::default()
        };
        let target = t("www.gstatic.com", 443);
        let resolved = cfg.resolve(&target);
        let ordered = order_plan(resolved.clone(), &state(Some("nima.nscl.ir:443"), NOW - 1), NOW);
        assert_eq!(ordered.candidates.len(), resolved.candidates.len());
        assert_eq!(candidate_key(&ordered.candidates[0]), "www.gstatic.com:443");
        assert_eq!(candidate_key(&ordered.candidates[1]), "nima.nscl.ir:443");
        assert_eq!(ordered.logical, target);
    }

    mod lkg_decisions {
        use super::*;

        const PREF: Option<&str> = Some("di.nscl.ir:443");
        const AT: u64 = NOW - 1_000;

        #[test]
        fn total_failure_clears_an_existing_preference() {
            assert_eq!(
                lkg_on_session_result(PREF, AT, DialVerdict::Failed, NOW, false),
                LkgAction::Clear
            );
        }

        #[test]
        fn total_failure_without_preference_keeps() {
            assert_eq!(
                lkg_on_session_result(None, 0, DialVerdict::Failed, NOW, false),
                LkgAction::Keep
            );
        }

        #[test]
        fn proxy_win_records_when_changed_and_debounced() {
            let at = NOW - WRITE_DEBOUNCE_SECS * 1000;
            assert_eq!(
                lkg_on_session_result(
                    PREF,
                    at,
                    DialVerdict::Won {
                        winner: "nima.nscl.ir:443",
                        is_direct: false,
                        first_failed: None
                    },
                    NOW,
                    false,
                ),
                LkgAction::Record("nima.nscl.ir:443".into())
            );
            // Inside the debounce window a changed winner is NOT recorded.
            assert_eq!(
                lkg_on_session_result(
                    PREF,
                    NOW - 1_000,
                    DialVerdict::Won {
                        winner: "nima.nscl.ir:443",
                        is_direct: false,
                        first_failed: None
                    },
                    NOW,
                    false,
                ),
                LkgAction::Keep
            );
        }

        #[test]
        fn direct_win_demotes_a_preference_that_failed_first() {
            assert_eq!(
                lkg_on_session_result(
                    PREF,
                    AT,
                    DialVerdict::Won {
                        winner: "dest.example:443",
                        is_direct: true,
                        first_failed: Some("di.nscl.ir:443")
                    },
                    NOW,
                    false,
                ),
                LkgAction::Clear
            );
        }

        #[test]
        fn direct_win_keeps_an_unrelated_preference() {
            assert_eq!(
                lkg_on_session_result(
                    PREF,
                    AT,
                    DialVerdict::Won {
                        winner: "dest.example:443",
                        is_direct: true,
                        first_failed: Some("nima.nscl.ir:443")
                    },
                    NOW,
                    false,
                ),
                LkgAction::Keep
            );
        }

        #[test]
        fn proxy_win_supersedes_demotion_when_it_replaces_the_failure() {
            // Preferred failed first but another proxy carried the session:
            // recording the fresh winner is strictly better than clearing.
            let at = NOW - WRITE_DEBOUNCE_SECS * 1000;
            assert_eq!(
                lkg_on_session_result(
                    PREF,
                    at,
                    DialVerdict::Won {
                        winner: "nima.nscl.ir:443",
                        is_direct: false,
                        first_failed: Some("di.nscl.ir:443")
                    },
                    NOW,
                    false,
                ),
                LkgAction::Record("nima.nscl.ir:443".into())
            );
        }

        #[test]
        fn unchanged_proxy_win_inside_debounce_keeps_and_still_demotes_failure() {
            // Same preferred candidate won again after failing first once:
            // nothing to record, but the failure demotion must still fire.
            let at = NOW - (WRITE_DEBOUNCE_SECS * 1000 - 1);
            assert_eq!(
                lkg_on_session_result(
                    PREF,
                    at,
                    DialVerdict::Won {
                        winner: "di.nscl.ir:443",
                        is_direct: false,
                        first_failed: Some("di.nscl.ir:443")
                    },
                    NOW,
                    false,
                ),
                LkgAction::Clear
            );
        }
    }

    /// A healthy measured candidate in `country`.
    fn healthy(country: &str, latency_ms: u32) -> Health {
        Health {
            country: country.into(),
            latency_ms,
            ok: true,
            ok_count: 4,
            ..Default::default()
        }
    }

    #[test]
    fn country_preference_puts_matching_proxies_first_without_dropping_any() {
        let p = plan(&["dest.example", "nima.nscl.ir", "di.nscl.ir"], 443);
        let mut s = state(None, NOW);
        s.geo.insert("di.nscl.ir".into(), healthy("DE", 40));
        s.geo.insert("nima.nscl.ir".into(), healthy("NL", 40));
        let out = order_plan_pref(p, &s, NOW, "DE");
        // Matching candidate leads; the non-matching one is still reachable.
        assert_eq!(
            out.candidates,
            vec![t("dest.example", 443), t("di.nscl.ir", 443), t("nima.nscl.ir", 443)]
        );
        assert_eq!(out.logical, t("dest.example", 443));
    }

    #[test]
    fn an_unsatisfiable_country_never_drops_the_working_route() {
        let p = plan(&["dest.example", "di.nscl.ir", "nima.nscl.ir"], 443);
        let mut s = state(None, NOW);
        s.geo.insert("di.nscl.ir".into(), healthy("DE", 40));
        // Nothing is in US: every candidate must survive, direct still first.
        let out = order_plan_pref(p.clone(), &s, NOW, "US");
        assert_eq!(out.candidates.len(), p.candidates.len());
        assert_eq!(out.candidates[0], t("dest.example", 443));
        for c in &p.candidates {
            assert!(out.candidates.contains(c), "{c:?} was dropped");
        }
    }

    #[test]
    fn a_measured_healthy_candidate_outranks_an_unmeasured_one() {
        let p = plan(&["dest.example", "unknown.example", "di.nscl.ir"], 443);
        let mut s = state(None, NOW);
        s.geo.insert("di.nscl.ir".into(), healthy("DE", 30));
        let out = order_plan_pref(p, &s, NOW, "");
        assert_eq!(
            out.candidates,
            vec![t("dest.example", 443), t("di.nscl.ir", 443), t("unknown.example", 443)]
        );
    }

    #[test]
    fn a_rotating_candidate_ranks_below_a_stable_one() {
        let p = plan(&["dest.example", "rotating.example", "stable.example"], 443);
        let mut s = state(None, NOW);
        let mut churn = healthy("DE", 30);
        churn.rotating = true;
        s.geo.insert("rotating.example".into(), churn);
        s.geo.insert("stable.example".into(), healthy("DE", 30));
        let out = order_plan_pref(p, &s, NOW, "DE");
        assert_eq!(out.candidates[1], t("stable.example", 443));
    }

    #[test]
    fn a_failing_candidate_ranks_below_everything_but_stays_in_the_plan() {
        let p = plan(&["dest.example", "dead.example", "live.example"], 443);
        let mut s = state(None, NOW);
        let dead = Health { fail_count: 3, ..Default::default() };
        s.geo.insert("dead.example".into(), dead);
        s.geo.insert("live.example".into(), healthy("DE", 50));
        let out = order_plan_pref(p, &s, NOW, "");
        assert_eq!(out.candidates[1], t("live.example", 443));
        assert!(out.candidates.contains(&t("dead.example", 443)));
    }

    #[test]
    fn a_pin_beats_the_ranking_and_an_unknown_pin_is_ignored() {
        let p = plan(&["dest.example", "fast.example", "slow.example"], 443);
        let mut s = state(None, NOW);
        s.geo.insert("fast.example".into(), healthy("DE", 10));
        s.geo.insert("slow.example".into(), healthy("DE", 300));
        // Pin loses nothing: the better-scoring candidate is still behind it.
        let pinned = order_plan_ranked(p.clone(), &s, NOW, "", "slow.example");
        assert_eq!(pinned.candidates[0], t("dest.example", 443));
        assert_eq!(pinned.candidates[1], t("slow.example", 443));
        assert_eq!(pinned.candidates.len(), 3);
        // A pin that is not a candidate cannot cost the session its route.
        let bogus = order_plan_ranked(p.clone(), &s, NOW, "", "gone.example");
        assert_eq!(bogus.candidates, order_plan_pref(p, &s, NOW, "").candidates);
    }

    #[test]
    fn lkg_still_wins_over_the_score_and_an_empty_country_is_a_noop() {
        let p = plan(&["dest.example", "fast.example", "lkg.example"], 443);
        let mut s = state(Some("lkg.example:443"), NOW);
        s.geo.insert("fast.example".into(), healthy("DE", 10));
        s.geo.insert("lkg.example".into(), healthy("DE", 200));
        let out = order_plan_pref(p, &s, NOW, "");
        assert_eq!(out.candidates[1], t("lkg.example", 443));
    }

    #[test]
    fn a_changed_exit_ip_or_country_marks_the_candidate_rotating() {
        let first = Health::default().observed_ok("DE".into(), "FRA".into(), "1.1.1.1".into(), 40, 1);
        assert!(first.stable(), "first observation cannot be rotation");
        assert!(first.healthy());
        let same = first.clone().observed_ok("DE".into(), "FRA".into(), "1.1.1.1".into(), 42, 2);
        assert!(same.stable());
        let moved = same.clone().observed_ok("DE".into(), "FRA".into(), "2.2.2.2".into(), 40, 3);
        assert!(moved.rotating, "changed exit IP is rotation");
        let country_moved =
            same.observed_ok("NL".into(), "AMS".into(), "1.1.1.1".into(), 40, 4);
        assert!(country_moved.rotating, "changed country is rotation");
    }

    #[test]
    fn a_failed_probe_keeps_what_was_measured_before() {
        let ok = Health::default().observed_ok("DE".into(), "FRA".into(), "1.1.1.1".into(), 40, 1);
        let failed = ok.observed_fail("tls reset".into(), 2);
        assert!(!failed.ok);
        assert!(!failed.healthy());
        assert_eq!(failed.country, "DE", "a failed probe must not erase the country");
        assert_eq!(failed.error, "tls reset");
        assert!((failed.success_rate() - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn a_stored_document_from_the_previous_geo_format_still_loads_its_lkg() {
        // V24 wrote `geo` as {host: "DE"}; this shape upgraded it to a record.
        // A whole-document parse failure would silently drop `preferred` too
        // and cost every session its last-known-good route, so the old shape
        // must degrade to "country only" rather than to "nothing".
        let old = r#"{"preferred":"di.nscl.ir:443","updatedAtMs":1789555828007,
                     "geo":{"di.nscl.ir":"DE","nima.nscl.ir":"NL"}}"#;
        let s = OutboundState::from_json(old);
        assert_eq!(s.preferred.as_deref(), Some("di.nscl.ir:443"), "LKG must survive the format change");
        assert_eq!(s.updated_at_ms, 1_789_555_828_007);
        assert_eq!(s.geo.get("di.nscl.ir").map(|h| h.country.as_str()), Some("DE"));
        assert_eq!(s.geo.get("nima.nscl.ir").map(|h| h.country.as_str()), Some("NL"));
        // Carried-over countries are not treated as measured health: nothing
        // was measured about reachability, so they must not rank as healthy.
        assert!(!s.geo["di.nscl.ir"].healthy());
    }

    #[test]
    fn valid_country_accepts_empty_and_alpha2() {
        assert!(valid_country(""));
        assert!(valid_country("DE"));
        assert!(valid_country("nl"));
        assert!(!valid_country("DEU"));
        assert!(!valid_country("D"));
        assert!(!valid_country("12"));
    }
}