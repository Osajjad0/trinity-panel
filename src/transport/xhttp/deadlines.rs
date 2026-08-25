//! Deadlines for the pre-socket header phase.
//!
//! The phase that assembles a session's protocol header used to give every
//! chunk the same flat ten-second timer. That shape leaks: a client that
//! delivers one byte every nine seconds holds an isolate — and on this tier,
//! real duration quota — indefinitely while never completing a header. Two
//! bounds fix it without touching legitimate traffic:
//!
//! - the *first* chunk gets [`FIRST_CHUNK_SECS`] (a real client sends it in
//!   well under a second; ten covers a bad mobile link);
//! - *subsequent* chunks get only [`NEXT_CHUNK_SECS`], because once bytes are
//!   flowing, silence is far more suspicious than slowness;
//! - and the whole phase ends at [`TOTAL_BUDGET_SECS`] regardless: receiving
//!   chunks resets the per-chunk timer, **never** the total budget.
//!
//! Pure functions over elapsed time only — no worker types, fully host-tested.

use core::time::Duration;

/// Wait allowed for the very first header chunk.
pub const FIRST_CHUNK_SECS: u64 = 10;

/// Wait allowed for each chunk after the first.
pub const NEXT_CHUNK_SECS: u64 = 4;

/// Total wall-clock budget for assembling one complete header.
pub const TOTAL_BUDGET_SECS: u64 = 15;

/// How long to wait for the next header chunk.
///
/// `header_budget_elapsed` is how long the phase has run so far. The result
/// is the per-chunk bound clamped so the phase can never outlive its total
/// budget; zero means the budget is spent and the phase must end now.
#[must_use]
pub fn header_deadline(is_first_chunk: bool, header_budget_elapsed: Duration) -> Duration {
    let remaining_secs =
        TOTAL_BUDGET_SECS.saturating_sub(header_budget_elapsed.as_secs());
    if remaining_secs == 0 {
        return Duration::ZERO;
    }
    let per_chunk = if is_first_chunk { FIRST_CHUNK_SECS } else { NEXT_CHUNK_SECS };
    Duration::from_secs(per_chunk.min(remaining_secs))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_chunk_gets_the_long_bound() {
        assert_eq!(header_deadline(true, Duration::ZERO), Duration::from_secs(10));
        assert_eq!(header_deadline(false, Duration::ZERO), Duration::from_secs(4));
    }

    #[test]
    fn later_chunks_get_the_short_bound() {
        // A first chunk landed at 9.9s (elapsed rounds to 9 whole seconds):
        // the next wait is the short one, still inside the budget.
        assert_eq!(header_deadline(false, Duration::from_millis(9_900)), Duration::from_secs(4));
    }

    #[test]
    fn the_never_exceeds_total_budget() {
        assert_eq!(header_deadline(true, Duration::from_secs(12)), Duration::from_secs(3));
        assert_eq!(header_deadline(false, Duration::from_secs(13)), Duration::from_secs(2));
        assert_eq!(header_deadline(true, Duration::from_secs(14)), Duration::from_secs(1));
    }

    #[test]
    fn budget_expiry_ends_the_phase_immediately() {
        assert_eq!(header_deadline(true, Duration::from_secs(15)), Duration::ZERO);
        assert_eq!(header_deadline(false, Duration::from_secs(16)), Duration::ZERO);
        assert_eq!(
            header_deadline(false, Duration::from_millis(15_500)),
            Duration::ZERO
        );
    }

    #[test]
    fn incomplete_continuation_stays_inside_the_budget() {
        // Chunk at 4.9s was Incomplete; the next wait is short-bound, not a
        // fresh long one.
        let next = header_deadline(false, Duration::from_millis(4_900));
        assert_eq!(next, Duration::from_secs(4));
    }

    #[test]
    fn absurd_elapsed_times_do_not_panic_or_wrap() {
        assert_eq!(header_deadline(true, Duration::from_secs(u64::MAX)), Duration::ZERO);
    }
}
