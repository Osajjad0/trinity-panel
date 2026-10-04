//! Uplink reordering for XHTTP `packet-up`.
//!
//! In `packet-up` the client sends each uplink chunk as its own HTTP POST,
//! numbered from zero. Those POSTs are independent requests: they can be
//! retried, they can overtake each other in flight, and there is no ordering
//! guarantee anywhere between the client and us. The byte stream we hand to
//! the outbound socket must nevertheless be exactly the stream the client
//! wrote, in order, once each.
//!
//! That makes this small module the correctness-critical part of the whole
//! transport. A duplicate that gets forwarded corrupts the tunnelled protocol;
//! a gap that gets skipped does the same; an unbounded buffer is a memory
//! exhaustion vector reachable by any peer that has authenticated once.
//!
//! Pure logic, no I/O, so all of that is testable on the host.

use std::collections::BTreeMap;

use bytes::Bytes;

/// Why a chunk could not be accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueueError {
    /// Too many chunks are waiting on a missing predecessor. Either the
    /// network is reordering beyond anything reasonable, or the client is
    /// deliberately withholding a sequence number to make us buffer.
    TooManyBuffered,
    /// Buffered chunks exceed the byte budget. Tracked separately from the
    /// count because 30 chunks of 1 MB is 30 MB, and the isolate has 128 MB
    /// shared across every connection it is serving.
    BufferBytesExceeded,
    /// Sequence number is implausibly far ahead of what we are waiting for.
    /// Without this, one POST with a huge sequence number would pin an entry
    /// in the map forever while every subsequent chunk piles up behind it.
    SeqTooFarAhead,
}

/// Outcome of accepting a chunk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Accepted {
    /// Chunks that are now contiguous and ready to write, in order. Empty when
    /// the chunk filled a gap that is still incomplete.
    pub ready: Vec<Bytes>,
    /// True when the chunk was a duplicate or a retransmit of data already
    /// delivered. Not an error — a client retrying a POST it never saw
    /// acknowledged is correct behaviour, and must be answered `200`.
    pub duplicate: bool,
}

/// Reassembles numbered uplink chunks into an ordered byte stream.
#[derive(Debug)]
pub struct UploadQueue {
    /// Sequence number we are waiting for next.
    next_seq: u64,
    pending: BTreeMap<u64, Bytes>,
    pending_bytes: usize,
    max_buffered: usize,
    max_buffer_bytes: usize,
    max_lookahead: u64,
    /// Monotonic ms stamped by the last chunk that advanced the stream.
    last_progress_ms: u64,
    /// A chunk has been delivered, so a frozen expectation is a real stall
    /// rather than a session that never uploaded.
    started: bool,
}

impl UploadQueue {
    /// `max_buffered` mirrors Xray's `scMaxBufferedPosts` (default 30).
    #[must_use]
    pub fn new(max_buffered: usize, max_buffer_bytes: usize) -> Self {
        Self {
            next_seq: 0,
            pending: BTreeMap::new(),
            pending_bytes: 0,
            max_buffered,
            max_buffer_bytes,
            // A chunk more than this far ahead cannot be legitimate: the
            // client would have had to send that many POSTs we never saw.
            max_lookahead: max_buffered as u64 * 4,
            // Both seeded by the first accepted chunk in `push`.
            last_progress_ms: 0,
            started: false,
        }
    }

    /// Sequence number the queue is waiting for.
    #[must_use]
    pub const fn next_seq(&self) -> u64 {
        self.next_seq
    }

    /// Milliseconds since the last chunk that advanced the stream.
    #[must_use]
    pub fn stalled_ms(&self, now_ms: u64) -> u64 {
        now_ms.saturating_sub(self.last_progress_ms)
    }

    /// True when this session has delivered uplink bytes but the expected
    /// sequence number has not advanced inside one gap window.
    ///
    /// Without this a chunk lost in flight -- an HTTP/2 GOAWAY on any client
    /// older than xray #6632 (which added `Request.GetBody` so the body can
    /// be replayed), or a reset between the client and here -- leaves every
    /// later chunk buffered behind a gap the server can never fill. The
    /// session then holds a live socket and a live download GET while
    /// forwarding no uplink at all, until the buffer budget eventually
    /// rejects it. Xray leaves the wait unbounded too (issue #4846 asks for
    /// exactly this guard).
    ///
    /// Monotonic elapsed time only, and gated on having delivered bytes, so
    /// it cannot fire on an idle-but-healthy session or on a wall-clock jump.
    #[must_use]
    pub fn is_stalled(&self, now_ms: u64, limit_ms: u64) -> bool {
        self.started && self.stalled_ms(now_ms) > limit_ms
    }

    /// Chunks currently held awaiting a predecessor.
    #[must_use]
    pub fn buffered(&self) -> usize {
        self.pending.len()
    }

    /// Accept one uplink chunk. `now_ms` is monotonic and stamps progress.
    ///
    /// # Errors
    /// [`QueueError`] when the chunk cannot be buffered. The caller should
    /// answer `400` and tear the session down — every variant means the peer
    /// is either broken or hostile, and continuing costs memory.
    pub fn push(
        &mut self,
        seq: u64,
        data: Bytes,
        now_ms: u64,
    ) -> Result<Accepted, QueueError> {
        // Already delivered. A retry of an acknowledged POST, or the client
        // resending after a timeout it did not need. Drop it silently: this is
        // the case that corrupts the stream if forwarded twice.
        if seq < self.next_seq {
            return Ok(Accepted { ready: Vec::new(), duplicate: true });
        }
        if self.pending.contains_key(&seq) {
            return Ok(Accepted { ready: Vec::new(), duplicate: true });
        }
        if seq.saturating_sub(self.next_seq) > self.max_lookahead {
            return Err(QueueError::SeqTooFarAhead);
        }

        // Fast path: exactly the chunk we wanted. Hand it straight through and
        // then drain whatever it unblocked, without ever inserting into the
        // map. The common case allocates nothing but the output vector.
        if seq == self.next_seq {
            let mut ready = Vec::with_capacity(1 + self.pending.len().min(4));
            ready.push(data);
            self.next_seq += 1;
            while let Some(chunk) = self.pending.remove(&self.next_seq) {
                self.pending_bytes -= chunk.len();
                ready.push(chunk);
                self.next_seq += 1;
            }
            // Only real progress stamps the clock: a late out-of-order POST
            // must not keep a genuinely lost gap alive.
            self.last_progress_ms = now_ms;
            self.started = true;
            return Ok(Accepted { ready, duplicate: false });
        }

        // Out of order. Buffer it, subject to both budgets.
        if self.pending.len() >= self.max_buffered {
            return Err(QueueError::TooManyBuffered);
        }
        let new_bytes = self.pending_bytes.saturating_add(data.len());
        if new_bytes > self.max_buffer_bytes {
            return Err(QueueError::BufferBytesExceeded);
        }
        self.pending_bytes = new_bytes;
        self.pending.insert(seq, data);
        Ok(Accepted { ready: Vec::new(), duplicate: false })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Monotonic stand-in for the runtime clock `push` now stamps. Tests
    /// that exercise the stall guard advance it explicitly.
    const T: u64 = 1_000;

    const MAX_N: usize = 30;
    const MAX_B: usize = 4 * 1024 * 1024;

    fn q() -> UploadQueue {
        UploadQueue::new(MAX_N, MAX_B)
    }

    fn b(s: &str) -> Bytes {
        Bytes::copy_from_slice(s.as_bytes())
    }

    fn joined(chunks: &[Bytes]) -> String {
        chunks.iter().flat_map(|c| c.iter().copied()).map(|c| c as char).collect()
    }

    #[test]
    fn in_order_chunks_pass_straight_through() {
        let mut q = q();
        for (i, s) in ["a", "b", "c"].iter().enumerate() {
            let acc = q.push(i as u64,  b(s), T).expect("accepted");
            assert_eq!(joined(&acc.ready), *s);
            assert!(!acc.duplicate);
        }
        assert_eq!(q.buffered(), 0, "in-order traffic must never buffer");
    }

    #[test]
    fn out_of_order_chunks_are_reassembled_in_order() {
        let mut q = q();
        assert!(q.push(2, b("c"), T).expect("accepted").ready.is_empty());
        assert!(q.push(1, b("b"), T).expect("accepted").ready.is_empty());
        assert_eq!(q.buffered(), 2);

        // Arrival of 0 releases 0, 1 and 2 as one contiguous run.
        let acc = q.push(0, b("a"), T).expect("accepted");
        assert_eq!(joined(&acc.ready), "abc");
        assert_eq!(q.buffered(), 0);
        assert_eq!(q.next_seq(), 3);
    }

    #[test]
    fn severe_reordering_still_reassembles_exactly() {
        let mut q = q();
        let order = [7u64, 3, 0, 6, 1, 5, 2, 4];
        let mut out = String::new();
        for seq in order {
            let acc = q.push(seq,  b(&((b'a' + seq as u8) as char).to_string()), T).expect("accepted");
            out.push_str(&joined(&acc.ready));
        }
        assert_eq!(out, "abcdefgh", "delivered stream must be in sequence order");
        assert_eq!(q.buffered(), 0);
    }

    #[test]
    fn duplicates_are_reported_not_forwarded() {
        let mut q = q();
        q.push(0, b("a"), T).expect("accepted");

        // Retransmit of an already-delivered chunk. Forwarding this would
        // corrupt the tunnelled protocol.
        let again = q.push(0, b("a"), T).expect("accepted");
        assert!(again.duplicate);
        assert!(again.ready.is_empty());

        // Retransmit of a buffered-but-undelivered chunk.
        q.push(2, b("c"), T).expect("accepted");
        let dup = q.push(2, b("c"), T).expect("accepted");
        assert!(dup.duplicate);
        assert_eq!(q.buffered(), 1, "duplicate must not double-count the buffer");
    }

    #[test]
    fn refuses_to_buffer_more_chunks_than_configured() {
        let mut q = UploadQueue::new(3, MAX_B);
        // Withhold seq 0 and flood the queue with successors.
        for seq in 1..=3u64 {
            q.push(seq,  b("x"), T).expect("accepted");
        }
        assert_eq!(q.push(4, b("x"), T), Err(QueueError::TooManyBuffered));
    }

    #[test]
    fn refuses_to_exceed_the_byte_budget() {
        // Count budget is generous; the byte budget must bind first.
        let mut q = UploadQueue::new(100, 1000);
        let chunk = Bytes::from(vec![0u8; 400]);
        q.push(1, chunk.clone(), T).expect("accepted");
        q.push(2, chunk.clone(), T).expect("accepted");
        assert_eq!(q.push(3, chunk, T), Err(QueueError::BufferBytesExceeded));
    }

    #[test]
    fn byte_budget_is_released_as_chunks_drain() {
        let mut q = UploadQueue::new(100, 1000);
        let chunk = Bytes::from(vec![0u8; 400]);
        q.push(1, chunk.clone(), T).expect("accepted");
        q.push(2, chunk.clone(), T).expect("accepted");
        // Releasing 0 drains 0,1,2 and frees their bytes.
        q.push(0, Bytes::from_static(b""), T).expect("accepted");
        assert_eq!(q.buffered(), 0);
        // The budget is available again.
        q.push(4, chunk.clone(), T).expect("accepted");
        q.push(5, chunk, T).expect("accepted");
    }

    #[test]
    fn rejects_sequence_numbers_implausibly_far_ahead() {
        let mut q = q();
        assert_eq!(q.push(u64::MAX,  b("x"), T), Err(QueueError::SeqTooFarAhead));
        assert_eq!(q.push(1000, b("x"), T), Err(QueueError::SeqTooFarAhead));
        // Just inside the window is fine.
        assert!(q.push(MAX_N as u64 * 4,  b("x"), T).is_ok());
    }

    #[test]
    fn empty_chunks_advance_the_sequence() {
        // A zero-length POST is legal and must not stall the stream.
        let mut q = q();
        let acc = q.push(0, Bytes::from_static(b""), T).expect("accepted");
        assert_eq!(acc.ready.len(), 1);
        assert_eq!(q.next_seq(), 1);
    }

    #[test]
    fn never_panics_under_adversarial_sequences() {
        let mut seed = 0xdead_beef_cafe_1234u64;
        for _ in 0..300 {
            let mut q = UploadQueue::new(8, 64 * 1024);
            for _ in 0..80 {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                // Mix plausible sequence numbers with wild ones.
                let seq = if seed % 4 == 0 { seed } else { seed % 24 };
                let len = (seed % 300) as usize;
                let _ = q.push(seq,  Bytes::from(vec![0u8; len]), T);
            }
        }
    }


    // ---- stall guard (missing-sequence timeout) ----
    //
    // A chunk lost in flight -- an HTTP/2 GOAWAY on any client older than
    // xray #6632, or a reset between client and server -- leaves later chunks
    // buffered behind a gap that can never be filled. Before the guard the
    // session relayed downloads forever while forwarding no uplink; these
    // pin the bounded behaviour that lets a client reconnect instead.

    const GAP_MS: u64 = 12_000;

    /// Mirrors what the request handler sets: a chunk that did not advance the
    /// expectation leaves the gap open, one that did closes it.
    fn gap_flag(q: &UploadQueue) -> bool {
        q.buffered() > 0
    }

    #[test]
    fn sequential_upload_never_trips_the_guard() {
        let mut q = UploadQueue::new(30, 4 << 20);
        for seq in 0..50 {
            q.push(seq, b("x"), seq * 10).expect("in order");
            assert!(
                !q.is_stalled(seq * 10, GAP_MS),
                "a stream advancing one chunk per 10ms must never look stalled"
            );
        }
        assert_eq!(q.next_seq(), 50);
    }

    #[test]
    fn a_repaired_gap_never_trips_the_guard() {
        let mut q = UploadQueue::new(30, 4 << 20);
        q.push(0, b("a"), 0).expect("first");
        // 2 arrives, 1 is missing: buffered, nothing delivered, gap open.
        assert!(q.push(2, b("c"), 100).expect("buffered").ready.is_empty());
        assert!(gap_flag(&q));
        // Still fine well inside the window.
        assert!(!q.is_stalled(100, GAP_MS));
        // 1 fills the gap and drains 2 with it.
        let acc = q.push(1, b("b"), GAP_MS - 1).expect("gap filled");
        assert_eq!(joined(&acc.ready), "bc", "the fill and its successor flush together");
        assert_eq!(q.next_seq(), 3);
        // Progress restarted the clock.
        assert!(!q.is_stalled(GAP_MS - 1, GAP_MS));
        assert_eq!(q.stalled_ms(GAP_MS - 1), 0);
    }

    #[test]
    fn an_unrepaired_gap_trips_the_guard_once_the_window_passes() {
        let mut q = UploadQueue::new(30, 4 << 20);
        q.push(0, b("a"), 0).expect("first");
        q.push(2, b("c"), 10).expect("buffered");
        assert!(!q.is_stalled(GAP_MS, GAP_MS), "the boundary itself is not a stall");
        assert!(q.is_stalled(GAP_MS + 1, GAP_MS), "one ms past the window is");
        // Late arrival before the window closes still saves the session.
        let mut q2 = UploadQueue::new(30, 4 << 20);
        q2.push(0, b("a"), 0).expect("first");
        q2.push(2, b("c"), 10).expect("buffered");
        let acc = q2.push(1, b("b"), GAP_MS - 1).expect("late fill");
        assert_eq!(joined(&acc.ready), "bc");
        assert!(!q2.is_stalled(GAP_MS + 1, GAP_MS), "a repaired gap is not a stall");
    }

    #[test]
    fn a_session_that_never_uploaded_is_not_stalled() {
        // Idle-but-healthy: download GET open, no uplink yet. Firing here
        // would kill healthy one-way sessions.
        let q = UploadQueue::new(30, 4 << 20);
        assert!(!q.is_stalled(u64::MAX / 2, GAP_MS));
        assert_eq!(q.stalled_ms(10_000), 10_000, "reports elapsed, never fires");
    }

    #[test]
    fn duplicates_and_late_chunks_cannot_mask_a_lost_one() {
        // The guard must measure real progress only: a client retrying
        // buffered or already-delivered chunks must not keep a genuinely lost
        // gap alive forever.
        let mut q = UploadQueue::new(30, 4 << 20);
        q.push(0, b("a"), 0).expect("first");
        q.push(2, b("c"), 10).expect("buffered");
        let now = GAP_MS - 1;
        assert!(q.push(2, b("c"), now).expect("duplicate").duplicate);
        assert!(q.push(0, b("a"), now).expect("already delivered").duplicate);
        assert!(!q.is_stalled(now + 1, GAP_MS), "progress still missing");
        assert!(q.is_stalled(now + 2, GAP_MS));
    }

    #[test]
    fn a_wall_clock_jump_cannot_trip_the_guard() {
        // `is_stalled` saturates, so a clock that goes backwards reads as
        // zero elapsed rather than as a huge one.
        let mut q = UploadQueue::new(30, 4 << 20);
        q.push(0, b("a"), 1_000).expect("first");
        assert!(!q.is_stalled(900, GAP_MS));
        assert_eq!(q.stalled_ms(900), 0);
    }

    #[test]
    fn the_stall_guard_does_not_disturb_the_queue() {
        // Purely observational: reading the guard must not drain, drop, or
        // reorder anything the session is holding.
        let mut q = UploadQueue::new(30, 4 << 20);
        q.push(0, b("a"), 0).expect("first");
        q.push(2, b("c"), 0).expect("buffered");
        q.push(4, b("e"), 0).expect("buffered");
        let before = (q.next_seq(), q.buffered(), q.stalled_ms(0));
        for t in 0..GAP_MS * 2 {
            let _ = q.is_stalled(t, GAP_MS);
            let _ = q.stalled_ms(t);
        }
        assert_eq!((q.next_seq(), q.buffered(), q.stalled_ms(0)), before);
        assert!(q.is_stalled(GAP_MS + 1, GAP_MS));
        assert_eq!(q.next_seq(), 1, "and the fill still works afterwards");
        // Filling 1 flushes it together with the buffered 2, and stops there:
        // 3 is still missing, so the buffered 4 stays put. The long stall read
        // drained and reordered nothing.
        assert_eq!(joined(&q.push(1, b("b"), 0).expect("fill").ready), "bc");
        assert_eq!(q.next_seq(), 3);
        assert_eq!(joined(&q.push(3, b("d"), 0).expect("fill").ready), "de");
    }

    #[test]
    fn delivered_stream_matches_input_under_random_shuffles() {
        // The property that actually matters: whatever order chunks arrive in,
        // the bytes handed onward are the original stream exactly once.
        let mut seed = 0x5eed_1234_5678_9abcu64;
        for _ in 0..200 {
            let n = 16usize;
            let expected: String = (0..n).map(|i| (b'a' + i as u8) as char).collect();
            let mut order: Vec<u64> = (0..n as u64).collect();
            // Fisher-Yates with the xorshift stream.
            for i in (1..n).rev() {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                order.swap(i, (seed % (i as u64 + 1)) as usize);
            }
            let mut q = UploadQueue::new(n, MAX_B);
            let mut out = String::new();
            for seq in order {
                let payload = b(&((b'a' + seq as u8) as char).to_string());
                let acc = q
                    .push(seq, payload, T)
                    .expect("buffer is large enough to hold any permutation");
                out.push_str(&joined(&acc.ready));
            }
            assert_eq!(out, expected);
        }
    }
}
