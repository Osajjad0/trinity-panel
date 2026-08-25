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

/// The canonical comparison key for a candidate.
///
/// Domains compare case-insensitively (KV stores what the panel saved, xray
/// dials whatever case it resolved), IPs through their canonical rendering.
#[must_use]
pub fn candidate_key(target: &Target) -> String {
    match &target.host {
        Host::Domain(d) => d.trim().to_ascii_lowercase(),
        Host::Ip(ip) => ip.to_string(),
    }
}

/// Move the fresh preferred candidate to the front of the plan, if it is one
/// of the candidates at all.
///
/// Pure: returns a new plan rather than mutating the input's `logical`, and
/// preserves the candidate list exactly (same members, same length).
#[must_use]
pub fn order_plan(mut plan: DialPlan, state: &OutboundState, now_ms: u64) -> DialPlan {
    let Some(pref) = state.preferred_fresh(now_ms) else {
        return plan;
    };
    // Already first: leave the vector untouched rather than remove-and-insert
    // an identical element, so callers comparing plans see no spurious change.
    if let Some(idx) = plan.candidates.iter().position(|c| candidate_key(c) == pref) {
        if idx > 0 {
            let candidate = plan.candidates.remove(idx);
            plan.candidates.insert(0, candidate);
        }
    }
    plan
}

/// Whether a session that ended on `winner` should update the stored state.
///
/// Two gates, both required: the winner differs from what is already stored,
/// and the last write is older than [`WRITE_DEBOUNCE_SECS`]. A brand-new
/// state (timestamp zero) debounces trivially — the epoch is always in the
/// past — so the first observation records immediately.
#[must_use]
pub fn should_record(winner: &Target, state: &OutboundState, now_ms: u64) -> bool {
    if state.preferred.as_deref().is_some_and(|p| {
        p.trim().to_ascii_lowercase() == candidate_key(winner)
    }) {
        return false;
    }
    now_ms.saturating_sub(state.updated_at_ms) >= WRITE_DEBOUNCE_SECS.saturating_mul(1000)
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
        OutboundState { preferred: pref.map(str::to_owned), updated_at_ms: at_ms }
    }

    const NOW: u64 = 1_800_000_000_000;

    #[test]
    fn fresh_preferred_moves_to_the_front() {
        let p = plan(&["dest.example", "di.nscl.ir", "nima.nscl.ir"], 443);
        let ordered = order_plan(p, &state(Some("di.nscl.ir"), NOW - 1_000), NOW);
        assert_eq!(ordered.candidates[0], t("di.nscl.ir", 443));
        assert_eq!(ordered.candidates.len(), 3);
        assert_eq!(ordered.logical, t("dest.example", 443));
    }

    #[test]
    fn matching_is_case_insensitive_and_trimmed() {
        let p = plan(&["dest.example", "DI.NSCL.IR"], 443);
        let ordered = order_plan(p, &state(Some("  di.nscl.ir "), NOW - 1_000), NOW);
        assert_eq!(ordered.candidates[0], t("DI.NSCL.IR", 443));
    }

    #[test]
    fn stale_preference_reorders_nothing() {
        let ttl_ms = HEALTH_TTL_SECS * 1000;
        // Exactly one TTL old is still fresh enough to act on.
        let at_boundary = order_plan(
            plan(&["dest.example", "di.nscl.ir"], 443),
            &state(Some("di.nscl.ir"), NOW - ttl_ms),
            NOW,
        );
        assert_eq!(at_boundary.candidates[0], t("di.nscl.ir", 443));
        // One millisecond past it is stale and reorders nothing.
        let past_ttl =
            order_plan(plan(&["dest.example", "di.nscl.ir"], 443), &state(Some("di.nscl.ir"), NOW - ttl_ms - 1), NOW);
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
        let out = order_plan(p, &state(Some("pyip.ygkkk.dpdns.org"), NOW - 1_000), NOW);
        assert_eq!(
            out.candidates,
            vec![t("dest.example", 443), t("di.nscl.ir", 443)]
        );
    }

    #[test]
    fn already_first_is_a_no_op_not_a_churn() {
        let p = plan(&["dest.example", "di.nscl.ir"], 443);
        let out = order_plan(p, &state(Some("DEST.EXAMPLE"), NOW - 1_000), NOW);
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
            let st = state(Some(pick), NOW.saturating_sub(age));

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
        let s = state(Some("di.nscl.ir"), NOW - (WRITE_DEBOUNCE_SECS * 1000 - 1));
        assert!(!should_record(&t("nima.nscl.ir", 443), &s, NOW));
    }

    #[test]
    fn changed_winner_at_the_debounce_boundary_is_recorded() {
        let s = state(Some("di.nscl.ir"), NOW - WRITE_DEBOUNCE_SECS * 1000);
        assert!(should_record(&t("nima.nscl.ir", 443), &s, NOW));
    }

    #[test]
    fn unchanged_winner_is_never_recorded_even_when_due() {
        let s = state(Some("di.nscl.ir"), NOW - WRITE_DEBOUNCE_SECS * 1000 * 100);
        assert!(!should_record(&t("DI.NSCL.IR", 443), &s, NOW));
    }

    #[test]
    fn first_observation_records_immediately() {
        let s = OutboundState::default();
        assert!(should_record(&t("di.nscl.ir", 443), &s, NOW));
    }

    #[test]
    fn serde_round_trip_preserves_the_document() {
        let original = state(Some("Di.Nscl.ir"), 1_756_000_000_123);
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
    fn resolve_then_order_keeps_every_candidate_across_modes() {
        use crate::relay::outbound::OutboundConfig;

        let cfg = OutboundConfig {
            mode: crate::relay::outbound::ProxyMode::ProxyIp,
            proxy_candidates: vec![
                "di.nscl.ir".into(),
                "nima.nscl.ir".into(),
                "bpb.yousef.isegaro.com".into(),
            ],
            nat64_prefixes: vec![],
            max_proxy_attempts: 8,
        };
        let target = t("www.gstatic.com", 443);
        let resolved = cfg.resolve(&target);
        let ordered = order_plan(resolved.clone(), &state(Some("nima.nscl.ir"), NOW - 1), NOW);
        assert_eq!(ordered.candidates.len(), resolved.candidates.len());
        assert_eq!(candidate_key(&ordered.candidates[0]), "nima.nscl.ir");
        assert_eq!(ordered.logical, target);
    }
}
