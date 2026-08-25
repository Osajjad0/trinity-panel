//! Supervised session teardown: the pure decision core.
//!
//! Before this module the socket owner raced one `join` against an idle
//! timer, so *how* a session ended was invisible to the code that ended it:
//! a client whose downlink GET vanished looked identical to one still
//! uploading, and both were dropped mid-flight by the same timer. This module
//! turns teardown into an explicit transition table over named events, which
//! buys three behaviours the old shape could not express:
//!
//! - a gone downlink receiver ends the session immediately (nothing can be
//!   served any more, so continuing only burns DO duration);
//! - a destination EOF or read error closes the upstream write side — telling
//!   the destination we are done — and lets whatever remains finish naturally
//!   instead of killing the whole session mid-await;
//! - true idleness still ends the session after [`IDLE_TIMEOUT_SECS`], with
//!   the counter reset by any successful transfer in either direction.
//!
//! Everything here is synchronous and free of worker types, so the whole
//! table is exercised on the host, including a fuzz that asserts bytes in
//! flight can never be terminated.

use super::diag::DownExit;

/// Seconds of complete silence (no successful transfer either direction)
/// before the supervisor gives up on the session. Unchanged from the value
/// the idle-select used before supervision existed.
const IDLE_TIMEOUT_SECS: u32 = 60;

/// Something observable happening to the session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    /// A chunk was written to the destination successfully.
    UpBytes,
    /// A chunk reached the client's downlink body successfully.
    DownBytes,
    /// The upstream pump finished (client stopped, or was cancelled).
    UpDone,
    /// The downlink pump finished, with the reason it stopped.
    DownDone(DownExit),
    /// The session state is unrecoverable while the owner still runs
    /// (corrupt stream data mid-session).
    Poisoned,
    /// One second elapsed with no decision from the pumps themselves.
    TimerTick,
}

/// What the owner task should do next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Nothing; keep running.
    Continue,
    /// Shut the destination's write side down (`writer.shutdown()`), tell the
    /// upstream pump to exit, and let the rest finish naturally.
    CloseUpstream,
    /// Tear the whole session down now.
    EndSession,
}

/// The teardown state for one session.
#[derive(Debug)]
pub struct Supervisor {
    up_done: bool,
    down_done: bool,
    /// Set by any successful transfer; consumed by each [`Event::TimerTick`].
    active: bool,
    idle_secs: u32,
}

impl Default for Supervisor {
    fn default() -> Self {
        Self::new()
    }
}

impl Supervisor {
    #[must_use]
    pub fn new() -> Self {
        Self { up_done: false, down_done: false, active: false, idle_secs: 0 }
    }

    /// Fold one event into the machine.
    pub fn on(&mut self, event: Event) -> Decision {
        match event {
            Event::UpBytes | Event::DownBytes => {
                self.active = true;
                self.idle_secs = 0;
                Decision::Continue
            }
            Event::TimerTick => {
                if self.active {
                    self.active = false;
                    self.idle_secs = 0;
                    return Decision::Continue;
                }
                self.idle_secs += 1;
                if self.idle_secs >= IDLE_TIMEOUT_SECS {
                    Decision::EndSession
                } else {
                    Decision::Continue
                }
            }
            Event::UpDone => {
                self.up_done = true;
                if self.down_done {
                    Decision::EndSession
                } else {
                    // The upstream tail shuts the write half down either way;
                    // what remains is the natural drain of whichever pump
                    // still runs.
                    Decision::Continue
                }
            }
            Event::DownDone(DownExit::ReceiverGone) => {
                // The GET response is gone: nothing reaches the client any
                // more, so serving further bytes serves nothing.
                self.down_done = true;
                Decision::EndSession
            }
            Event::DownDone(DownExit::Eof | DownExit::ReadError | DownExit::EncodeFailed) => {
                // The destination finished (or broke). Tell it we are done on
                // our side and let the remaining direction wind down rather
                // than truncating a client that is still legitimately talking.
                self.down_done = true;
                if self.up_done {
                    Decision::EndSession
                } else {
                    Decision::CloseUpstream
                }
            }
            Event::Poisoned => Decision::EndSession,
        }
    }

    /// Whether both pumps have reported completion.
    #[must_use]
    pub fn both_done(&self) -> bool {
        self.up_done && self.down_done
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn receiver_gone_ends_the_session_immediately() {
        let mut s = Supervisor::new();
        assert_eq!(s.on(Event::UpBytes), Decision::Continue);
        assert_eq!(
            s.on(Event::DownDone(DownExit::ReceiverGone)),
            Decision::EndSession
        );
    }

    #[test]
    fn destination_eof_closes_upstream_and_waits_for_it() {
        let mut s = Supervisor::new();
        assert_eq!(s.on(Event::DownBytes), Decision::Continue);
        assert_eq!(s.on(Event::DownDone(DownExit::Eof)), Decision::CloseUpstream);
        // The upstream side is still alive and may still report activity or
        // completion; neither may be lost.
        assert_eq!(s.on(Event::UpBytes), Decision::Continue);
        assert_eq!(s.on(Event::UpDone), Decision::EndSession);
    }

    #[test]
    fn destination_read_error_follows_the_same_path_as_eof() {
        let mut s = Supervisor::new();
        assert_eq!(
            s.on(Event::DownDone(DownExit::ReadError)),
            Decision::CloseUpstream
        );
        assert_eq!(s.on(Event::UpDone), Decision::EndSession);
    }

    #[test]
    fn encode_failure_is_a_destination_side_end_too() {
        // Not named by the contract table; grouped with the natural
        // destination endings because the codec, like the socket, cannot
        // carry anything further.
        let mut s = Supervisor::new();
        assert_eq!(
            s.on(Event::DownDone(DownExit::EncodeFailed)),
            Decision::CloseUpstream
        );
    }

    #[test]
    fn upstream_finishing_first_leaves_the_downlink_draining() {
        let mut s = Supervisor::new();
        assert_eq!(s.on(Event::UpDone), Decision::Continue);
        // Destination then closes cleanly: everything has now finished.
        assert_eq!(s.on(Event::DownDone(DownExit::Eof)), Decision::EndSession);
    }

    #[test]
    fn poisoned_ends_even_with_traffic_flying() {
        let mut s = Supervisor::new();
        assert_eq!(s.on(Event::UpBytes), Decision::Continue);
        assert_eq!(s.on(Event::DownBytes), Decision::Continue);
        assert_eq!(s.on(Event::Poisoned), Decision::EndSession);
    }

    #[test]
    fn quiet_session_dies_on_the_sixtieth_tick_and_not_before() {
        let mut s = Supervisor::new();
        for _ in 0..59 {
            assert_eq!(s.on(Event::TimerTick), Decision::Continue);
        }
        assert_eq!(s.on(Event::TimerTick), Decision::EndSession);
    }

    #[test]
    fn any_transfer_resets_the_idle_clock() {
        let mut s = Supervisor::new();
        for _ in 0..3 {
            for _ in 0..59 {
                assert_eq!(s.on(Event::TimerTick), Decision::Continue);
            }
            // One byte either direction keeps a live session alive forever.
            assert_eq!(s.on(Event::UpBytes), Decision::Continue);
        }
        assert_eq!(s.on(Event::DownBytes), Decision::Continue);
        assert_eq!(s.on(Event::TimerTick), Decision::Continue);
    }

    #[test]
    fn activity_between_ticks_counts_even_a_single_byte() {
        // Byte arrives between every pair of ticks: the counter must never
        // reach two consecutive quiet seconds, let alone sixty.
        let mut s = Supervisor::new();
        for i in 0..600 {
            let d = s.on(Event::TimerTick);
            assert_eq!(d, Decision::Continue, "tick {i}");
            let d = s.on(if i % 2 == 0 { Event::UpBytes } else { Event::DownBytes });
            assert_eq!(d, Decision::Continue);
        }
    }

    #[test]
    fn both_pumps_done_without_terminal_events_is_still_reachable() {
        let mut s = Supervisor::new();
        assert_eq!(s.on(Event::UpDone), Decision::Continue);
        assert!(s.both_done() == false);
        let _ = s.on(Event::DownDone(DownExit::Eof));
        assert!(s.both_done());
    }

    #[test]
    fn bytes_in_flight_are_never_terminated() {
        // Fuzz in the house style: random interleavings where at least one
        // byte moves within every idle window must never produce EndSession.
        let mut seed = 0x243f_6a88_85a3_08d3u64;
        for round in 0..2000 {
            let mut s = Supervisor::new();
            for step in 0..500u32 {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                let quiet_run = (seed % 55) as u32; // strictly under 60
                for _ in 0..quiet_run {
                    if s.on(Event::TimerTick) == Decision::EndSession {
                        panic!("idle kill during traffic: round {round} step {step}");
                    }
                }
                seed ^= seed << 13;
                seed ^= seed >> 7;
                let d = s.on(if seed % 2 == 0 { Event::UpBytes } else { Event::DownBytes });
                assert_eq!(d, Decision::Continue, "round {round} step {step}");
            }
        }
    }
}
