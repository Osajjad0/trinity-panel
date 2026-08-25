//! Per-session byte accounting and exit-reason capture for the socket owner.
//!
//! The relay's exit paths are deliberately silent toward the peer: a prober
//! must not learn why a session ended. Silence is correct for the wire, but it
//! also leaves an operator unable to answer "why was that download cut short"
//! — the exact question a truncated transfer poses. This module answers it on
//! deployments that ask for it.
//!
//! Counters are collected unconditionally (a few adds per chunk, nothing
//! observable on the wire). *Publication* is opt-in per deployment: only when
//! the `SESSION_DIAG` env binding is present does session teardown serialize
//! the counters to KV (`diag:<unix_ms>-<sid>`) and to the console. Production,
//! which never sets that binding, runs bit-identical: no logs, no KV writes.
//!
//! Everything here compiles and tests on the host; only [`publish`] touches
//! worker APIs, and it is compiled solely for the wasm target because that is
//! the only place a `worker::Env` exists.

use std::cell::{Cell, RefCell};

/// Why the downlink pump stopped reading its destination socket.
///
/// One match arm in the relay collapses these into a single silent break;
/// separating them is the entire point of the instrumentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DownExit {
    /// Destination closed cleanly (`read == 0`). Normal termination.
    Eof,
    /// `read_buf` returned an I/O error.
    ReadError,
    /// The body codec failed to frame a chunk just read.
    EncodeFailed,
    /// The downlink channel rejected a send: the GET response was gone.
    ReceiverGone,
}

impl DownExit {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            DownExit::Eof => "eof",
            DownExit::ReadError => "read_error",
            DownExit::EncodeFailed => "encode_failed",
            DownExit::ReceiverGone => "receiver_gone",
        }
    }
}

/// Why the session task as a whole ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionEnd {
    /// Both relay directions finished on their own.
    RelaysDone,
    /// The idle timer won the race and dropped both relays mid-await.
    IdleTimerFired,
    /// The client's downlink GET vanished; nothing could be served any more.
    /// (Supervised teardown — additive, older readers simply never see it.)
    ReceiverGone,
    /// Session state became unrecoverable while the owner still ran.
    Poisoned,
}

impl SessionEnd {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            SessionEnd::RelaysDone => "relays_done",
            SessionEnd::IdleTimerFired => "idle_timer",
            SessionEnd::ReceiverGone => "receiver_gone",
            SessionEnd::Poisoned => "poisoned",
        }
    }
}

/// One session's byte flow, counted where it happens.
///
/// `Cell`s rather than atomics: the owner task is a single future on a single
/// thread, so there is no concurrent writer — the shared handle across the two
/// relay closures is about ownership, not synchronization.
#[derive(Debug, Default)]
pub struct SessionDiag {
    pub upstream_read: Cell<u64>,
    pub downstream_sent: Cell<u64>,
    pub reads: Cell<u64>,
    pub sends: Cell<u64>,
    pub max_read: Cell<u64>,
    pub max_send: Cell<u64>,
    pub down_exit: Cell<Option<DownExit>>,
    pub session_end: Cell<Option<SessionEnd>>,
    /// Longest observed gap between successive successful sends, ms.
    pub max_send_gap_ms: Cell<u64>,
    /// Wall-clock ms from owner-task start to socket connected.
    pub setup_ms: Cell<u64>,
    /// Wall-clock ms from socket connected to pump exit.
    pub pump_ms: Cell<u64>,
    /// I/O error text when [`DownExit::ReadError`] (short, no destination echo).
    /// `RefCell` because `Cell` needs `Copy` and error text is an owned string.
    pub read_error: RefCell<Option<String>>,
}

impl SessionDiag {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_read(&self, n: usize) {
        self.upstream_read.set(self.upstream_read.get() + n as u64);
        self.reads.set(self.reads.get() + 1);
        if n as u64 > self.max_read.get() {
            self.max_read.set(n as u64);
        }
    }

    pub fn record_send(&self, n: usize) {
        self.downstream_sent.set(self.downstream_sent.get() + n as u64);
        self.sends.set(self.sends.get() + 1);
        if n as u64 > self.max_send.get() {
            self.max_send.set(n as u64);
        }
    }

    /// Compact single-line JSON. Hand-rolled because every field is known-good
    /// (numbers, fixed strings, one escaped error text) and pulling in a
    /// serializer for eleven fields is weight the isolate does not need.
    #[must_use]
    pub fn to_json(&self, sid: &str) -> String {
        let esc = |s: &str| s.replace('\\', "\\\\").replace('"', "\\\"");
        let err = match self.read_error.borrow().as_deref() {
            Some(e) => format!("\"{}\"", esc(e)),
            None => "null".to_owned(),
        };
        let exit = match self.down_exit.get() {
            Some(x) => x.as_str(),
            None => "none",
        };
        let end = match self.session_end.get() {
            Some(x) => x.as_str(),
            None => "running",
        };
        format!(
            "{{\"sid\":\"{}\",\"end\":\"{}\",\"down_exit\":\"{}\",\"err\":{},\
             \"read\":{},\"sent\":{},\"reads\":{},\"sends\":{},\
             \"max_read\":{},\"max_send\":{},\"max_gap_ms\":{},\
             \"setup_ms\":{},\"pump_ms\":{}}}",
            esc(sid),
            end,
            exit,
            err,
            self.upstream_read.get(),
            self.downstream_sent.get(),
            self.reads.get(),
            self.sends.get(),
            self.max_read.get(),
            self.max_send.get(),
            self.max_send_gap_ms.get(),
            self.setup_ms.get(),
            self.pump_ms.get(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_diag_serializes_with_defaults() {
        let d = SessionDiag::new();
        let j = d.to_json("sess01");
        assert!(j.contains("\"sid\":\"sess01\""));
        assert!(j.contains("\"end\":\"running\""));
        assert!(j.contains("\"down_exit\":\"none\""));
        assert!(j.contains("\"err\":null"));
        assert!(j.contains("\"read\":0"));
    }

    #[test]
    fn counters_accumulate_and_track_maxima() {
        let d = SessionDiag::new();
        d.record_read(100);
        d.record_read(50);
        d.record_send(100);
        assert_eq!(d.upstream_read.get(), 150);
        assert_eq!(d.reads.get(), 2);
        assert_eq!(d.max_read.get(), 100);
        assert_eq!(d.downstream_sent.get(), 100);
        assert_eq!(d.sends.get(), 1);
        assert_eq!(d.max_send.get(), 100);
    }

    #[test]
    fn exit_reasons_round_trip_through_json() {
        let d = SessionDiag::new();
        d.record_read(10);
        d.down_exit.set(Some(DownExit::ReadError));
        *d.read_error.borrow_mut() = Some("Other".to_owned());
        d.session_end.set(Some(SessionEnd::IdleTimerFired));
        let j = d.to_json("s");
        assert!(j.contains("\"down_exit\":\"read_error\""));
        assert!(j.contains("\"end\":\"idle_timer\""));
        assert!(j.contains("\"err\":\"Other\""));

        let e = SessionDiag::new();
        e.down_exit.set(Some(DownExit::ReceiverGone));
        assert!(e.to_json("s").contains("\"receiver_gone\""));

        let f = SessionDiag::new();
        f.down_exit.set(Some(DownExit::EncodeFailed));
        assert!(f.to_json("s").contains("\"encode_failed\""));

        let g = SessionDiag::new();
        g.down_exit.set(Some(DownExit::Eof));
        g.session_end.set(Some(SessionEnd::RelaysDone));
        let jg = g.to_json("s");
        assert!(jg.contains("\"down_exit\":\"eof\""));
        assert!(jg.contains("\"end\":\"relays_done\""));

        let supervised = [
            (SessionEnd::ReceiverGone, "\"end\":\"receiver_gone\""),
            (SessionEnd::Poisoned, "\"end\":\"poisoned\""),
        ];
        for (end, needle) in supervised {
            let d = SessionDiag::new();
            d.session_end.set(Some(end));
            assert!(d.to_json("s").contains(needle));
        }
    }

    #[test]
    fn quotes_in_error_text_are_escaped() {
        let d = SessionDiag::new();
        *d.read_error.borrow_mut() = Some(String::from("bad \"stuff\" \\ here"));
        let j = d.to_json("s");
        // Must remain valid enough JSON: no raw quote inside the value.
        assert!(j.contains("\\\"stuff\\\""));
    }
}
