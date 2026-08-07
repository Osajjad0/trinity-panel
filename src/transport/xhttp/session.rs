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
        }
    }

    /// Sequence number the queue is waiting for.
    #[must_use]
    pub const fn next_seq(&self) -> u64 {
        self.next_seq
    }

    /// Chunks currently held awaiting a predecessor.
    #[must_use]
    pub fn buffered(&self) -> usize {
        self.pending.len()
    }

    /// Accept one uplink chunk.
    ///
    /// # Errors
    /// [`QueueError`] when the chunk cannot be buffered. The caller should
    /// answer `400` and tear the session down — every variant means the peer
    /// is either broken or hostile, and continuing costs memory.
    pub fn push(&mut self, seq: u64, data: Bytes) -> Result<Accepted, QueueError> {
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
            let acc = q.push(i as u64, b(s)).expect("accepted");
            assert_eq!(joined(&acc.ready), *s);
            assert!(!acc.duplicate);
        }
        assert_eq!(q.buffered(), 0, "in-order traffic must never buffer");
    }

    #[test]
    fn out_of_order_chunks_are_reassembled_in_order() {
        let mut q = q();
        assert!(q.push(2, b("c")).expect("accepted").ready.is_empty());
        assert!(q.push(1, b("b")).expect("accepted").ready.is_empty());
        assert_eq!(q.buffered(), 2);

        // Arrival of 0 releases 0, 1 and 2 as one contiguous run.
        let acc = q.push(0, b("a")).expect("accepted");
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
            let acc = q.push(seq, b(&((b'a' + seq as u8) as char).to_string())).expect("accepted");
            out.push_str(&joined(&acc.ready));
        }
        assert_eq!(out, "abcdefgh", "delivered stream must be in sequence order");
        assert_eq!(q.buffered(), 0);
    }

    #[test]
    fn duplicates_are_reported_not_forwarded() {
        let mut q = q();
        q.push(0, b("a")).expect("accepted");

        // Retransmit of an already-delivered chunk. Forwarding this would
        // corrupt the tunnelled protocol.
        let again = q.push(0, b("a")).expect("accepted");
        assert!(again.duplicate);
        assert!(again.ready.is_empty());

        // Retransmit of a buffered-but-undelivered chunk.
        q.push(2, b("c")).expect("accepted");
        let dup = q.push(2, b("c")).expect("accepted");
        assert!(dup.duplicate);
        assert_eq!(q.buffered(), 1, "duplicate must not double-count the buffer");
    }

    #[test]
    fn refuses_to_buffer_more_chunks_than_configured() {
        let mut q = UploadQueue::new(3, MAX_B);
        // Withhold seq 0 and flood the queue with successors.
        for seq in 1..=3u64 {
            q.push(seq, b("x")).expect("accepted");
        }
        assert_eq!(q.push(4, b("x")), Err(QueueError::TooManyBuffered));
    }

    #[test]
    fn refuses_to_exceed_the_byte_budget() {
        // Count budget is generous; the byte budget must bind first.
        let mut q = UploadQueue::new(100, 1000);
        let chunk = Bytes::from(vec![0u8; 400]);
        q.push(1, chunk.clone()).expect("accepted");
        q.push(2, chunk.clone()).expect("accepted");
        assert_eq!(q.push(3, chunk), Err(QueueError::BufferBytesExceeded));
    }

    #[test]
    fn byte_budget_is_released_as_chunks_drain() {
        let mut q = UploadQueue::new(100, 1000);
        let chunk = Bytes::from(vec![0u8; 400]);
        q.push(1, chunk.clone()).expect("accepted");
        q.push(2, chunk.clone()).expect("accepted");
        // Releasing 0 drains 0,1,2 and frees their bytes.
        q.push(0, Bytes::from_static(b"")).expect("accepted");
        assert_eq!(q.buffered(), 0);
        // The budget is available again.
        q.push(4, chunk.clone()).expect("accepted");
        q.push(5, chunk).expect("accepted");
    }

    #[test]
    fn rejects_sequence_numbers_implausibly_far_ahead() {
        let mut q = q();
        assert_eq!(q.push(u64::MAX, b("x")), Err(QueueError::SeqTooFarAhead));
        assert_eq!(q.push(1000, b("x")), Err(QueueError::SeqTooFarAhead));
        // Just inside the window is fine.
        assert!(q.push(MAX_N as u64 * 4, b("x")).is_ok());
    }

    #[test]
    fn empty_chunks_advance_the_sequence() {
        // A zero-length POST is legal and must not stall the stream.
        let mut q = q();
        let acc = q.push(0, Bytes::from_static(b"")).expect("accepted");
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
                let _ = q.push(seq, Bytes::from(vec![0u8; len]));
            }
        }
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
                let acc = q.push(seq, b(&((b'a' + seq as u8) as char).to_string()))
                    .expect("buffer is large enough to hold any permutation");
                out.push_str(&joined(&acc.ready));
            }
            assert_eq!(out, expected);
        }
    }
}
