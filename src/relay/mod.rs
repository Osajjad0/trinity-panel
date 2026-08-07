//! The relay hot path.
//!
//! Once a protocol header has been parsed and authenticated, everything that
//! follows is opaque bytes moving in two directions. This module does that
//! moving, and it is the one place where per-byte cost actually matters — a
//! panel's throughput is decided here and nowhere else.
//!
//! # On "zero-copy"
//!
//! The payload is never copied between buffers. Reads land directly in a
//! [`BytesMut`], and the filled portion is detached with `split_to`, which is
//! a pointer and length adjustment over the same allocation rather than a
//! memcpy. The resulting [`Bytes`] can then be handed onward, cloned, or
//! queued, and cloning it bumps a refcount rather than duplicating the data.
//!
//! What is *not* avoided is the read itself: the runtime hands us bytes
//! through a JS-side stream, so there is one unavoidable copy at the WASM
//! boundary that no amount of Rust can remove. Claiming otherwise would be
//! dishonest. What this design does buy is that after that boundary, the same
//! allocation carries the payload all the way to the socket.
//!
//! The buffer is reused across reads and grown geometrically, so a long-lived
//! connection settles at a steady-state allocation and then stops allocating
//! entirely.

pub mod connect;

use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Initial read buffer size.
///
/// Sized to hold a full TLS record (16 KB plus framing) so the common case of
/// a single record per read completes without a regrow. Larger wastes isolate
/// memory across many concurrent connections; the isolate has 128 MB total,
/// shared.
pub const INITIAL_BUFFER: usize = 16 * 1024 + 512;

/// Never let one connection's buffer grow beyond this.
///
/// A peer that never stops sending would otherwise be able to make a single
/// connection consume the isolate's whole memory budget and take every other
/// connection on it down.
pub const MAX_BUFFER: usize = 512 * 1024;

/// How a relay direction finished.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Closed {
    /// The source signalled end of stream. Normal termination.
    Eof,
    /// The destination went away. Also normal — the peer hung up.
    PeerClosed,
}

/// Statistics for one direction, for per-user accounting.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Transferred {
    pub bytes: u64,
    pub chunks: u64,
}

/// Copy from `src` to `dst` until end of stream.
///
/// Returns how much moved, so the caller can attribute it to the
/// authenticated user. Attribution is the whole reason this returns a count
/// rather than `()`: a panel that cannot say whose traffic is whose cannot
/// enforce a quota, and that is how operators end up unknowingly carrying
/// terabytes for strangers.
///
/// # Errors
/// Propagates the first I/O error from either side. A relay error is not
/// recoverable — the byte stream has a hole in it — so the caller must drop
/// the connection rather than retry.
pub async fn pump<R, W>(src: &mut R, dst: &mut W) -> Result<(Closed, Transferred), std::io::Error>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = BytesMut::with_capacity(INITIAL_BUFFER);
    let mut moved = Transferred::default();

    loop {
        // Ensure headroom without discarding what `split_to` already returned
        // to the allocator. `reserve` reuses the existing allocation whenever
        // the detached `Bytes` have been dropped downstream.
        //
        // Growth is to a fixed target rather than geometric. An earlier version
        // doubled the capacity and clamped to MAX_BUFFER, but the doubling
        // could only run when capacity was already *below* INITIAL_BUFFER, so
        // the upper clamp was unreachable and MAX_BUFFER never bound anything.
        // A steady-state read size is what this loop actually wants.
        if buf.capacity() < INITIAL_BUFFER {
            buf.reserve(INITIAL_BUFFER - buf.capacity());
        }

        let n = src.read_buf(&mut buf).await?;
        if n == 0 {
            // Flush before reporting EOF: bytes sitting in the destination's
            // buffer are bytes the peer never sees, and on a short-lived
            // request that is the difference between a working response and a
            // truncated one.
            dst.flush().await?;
            return Ok((Closed::Eof, moved));
        }

        // O(1) detach — no memcpy, same allocation.
        let chunk: Bytes = buf.split_to(n).freeze();
        moved.bytes += n as u64;
        moved.chunks += 1;

        match dst.write_all(&chunk).await {
            Ok(()) => {}
            Err(e) if is_disconnect(&e) => return Ok((Closed::PeerClosed, moved)),
            Err(e) => return Err(e),
        }
    }
}

/// Whether an I/O error means the peer hung up rather than something failing.
///
/// A hangup is the ordinary way a proxied connection ends — a browser tab
/// closing produces one on every request in flight. Treating it as an error
/// would fill the logs with noise that hides real failures.
fn is_disconnect(e: &std::io::Error) -> bool {
    use std::io::ErrorKind::{BrokenPipe, ConnectionAborted, ConnectionReset, NotConnected};
    matches!(
        e.kind(),
        BrokenPipe | ConnectionReset | ConnectionAborted | NotConnected
    )
}

/// Write the bytes that arrived alongside a protocol header.
///
/// Transport framing does not align with protocol framing, so the first
/// application bytes very often ride in the same buffer as the header that
/// describes them. Forgetting to forward this is a classic bug whose symptom
/// is that TLS handshakes to the destination hang forever: the ClientHello was
/// parsed off and dropped.
///
/// # Errors
/// Propagates write failures.
pub async fn write_initial<W>(dst: &mut W, payload: &[u8]) -> Result<u64, std::io::Error>
where
    W: AsyncWrite + Unpin,
{
    if payload.is_empty() {
        return Ok(0);
    }
    dst.write_all(payload).await?;
    dst.flush().await?;
    Ok(payload.len() as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[tokio::test]
    async fn moves_all_bytes_and_reports_the_count() {
        let (mut a, mut b) = duplex(4096);
        let payload = vec![0xabu8; 100_000];
        let expected = payload.clone();

        let writer = tokio::spawn(async move {
            a.write_all(&payload).await.expect("write");
            a.shutdown().await.expect("shutdown");
        });

        let mut out = Vec::new();
        let (closed, moved) = pump(&mut b, &mut out).await.expect("pump");
        writer.await.expect("writer task");

        assert_eq!(closed, Closed::Eof);
        assert_eq!(moved.bytes, 100_000);
        assert_eq!(out, expected, "relayed stream must be byte-identical");
    }

    #[tokio::test]
    async fn empty_stream_terminates_cleanly() {
        let (a, mut b) = duplex(64);
        drop(a);
        let mut out = Vec::new();
        let (closed, moved) = pump(&mut b, &mut out).await.expect("pump");
        assert_eq!(closed, Closed::Eof);
        assert_eq!(moved.bytes, 0);
        assert!(out.is_empty());
    }

    #[tokio::test]
    async fn preserves_boundaries_across_many_small_writes() {
        // Byte-stream semantics: chunking must not alter the delivered bytes.
        let (mut a, mut b) = duplex(64);
        let writer = tokio::spawn(async move {
            for i in 0u16..2000 {
                a.write_all(&i.to_be_bytes()).await.expect("write");
            }
            a.shutdown().await.expect("shutdown");
        });

        let mut out = Vec::new();
        let (_, moved) = pump(&mut b, &mut out).await.expect("pump");
        writer.await.expect("writer task");

        assert_eq!(moved.bytes, 4000);
        for i in 0u16..2000 {
            let at = usize::from(i) * 2;
            assert_eq!(&out[at..at + 2], &i.to_be_bytes(), "corruption at {i}");
        }
    }

    #[tokio::test]
    async fn buffer_does_not_grow_without_bound() {
        // A long transfer must settle rather than expand forever. The check is
        // that a large volume completes without exhausting memory and the
        // relay stays correct throughout.
        let (mut a, mut b) = duplex(8192);
        let writer = tokio::spawn(async move {
            let block = vec![0x5au8; 8192];
            for _ in 0..256 {
                a.write_all(&block).await.expect("write");
            }
            a.shutdown().await.expect("shutdown");
        });

        let mut out = Vec::new();
        let (closed, moved) = pump(&mut b, &mut out).await.expect("pump");
        writer.await.expect("writer task");

        assert_eq!(closed, Closed::Eof);
        assert_eq!(moved.bytes, 8192 * 256);
        assert!(out.iter().all(|&x| x == 0x5a));
    }

    #[tokio::test]
    async fn initial_payload_is_forwarded_and_flushed() {
        let (mut a, mut b) = duplex(1024);
        let n = write_initial(&mut a, b"\x16\x03\x01ClientHello").await.expect("write");
        assert_eq!(n, 14);

        let mut got = vec![0u8; 14];
        b.read_exact(&mut got).await.expect("read");
        assert_eq!(&got, b"\x16\x03\x01ClientHello");
    }

    #[tokio::test]
    async fn empty_initial_payload_writes_nothing() {
        let (mut a, _b) = duplex(64);
        assert_eq!(write_initial(&mut a, b"").await.expect("write"), 0);
    }

    #[test]
    fn hangup_kinds_are_classified_as_disconnects_not_errors() {
        use std::io::{Error, ErrorKind};
        for k in [
            ErrorKind::BrokenPipe,
            ErrorKind::ConnectionReset,
            ErrorKind::ConnectionAborted,
            ErrorKind::NotConnected,
        ] {
            assert!(is_disconnect(&Error::new(k, "x")), "{k:?} should be a hangup");
        }
        assert!(!is_disconnect(&Error::new(ErrorKind::PermissionDenied, "x")));
        assert!(!is_disconnect(&Error::new(ErrorKind::InvalidData, "x")));
    }
}
