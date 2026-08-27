#!/usr/bin/env python3
"""Trinity Relay PoC — external stateful TCP relay for XHTTP packet-up.

Replaces Cloudflare Durable Objects for socket ownership. The Worker forwards
XHTTP uplink/downlink requests here; this process owns the upstream TCP sockets.

Protocol (all endpoints require Authorization: Bearer <RELAY_SECRET>):
  POST /connect?sid=X&dst=host:port[&proxy_ip=addr]  — dial upstream
  POST /up?sid=X                                      — write body to upstream
  GET  /down?sid=X                                    — stream upstream reads
  DELETE /close?sid=X                                  — tear down session

No WebSocket. Pure HTTP/1.1 chunked streaming.
"""

import asyncio
import os
import sys
import time
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Lock
from urllib.parse import parse_qs, urlparse

# --- Configuration -----------------------------------------------------------

RELAY_SECRET = os.environ.get("RELAY_SECRET", "dev-secret-change-me")
LISTEN_PORT = int(os.environ.get("RELAY_PORT", "8900"))
MAX_SESSIONS = 1000
IDLE_TIMEOUT_S = int(os.environ.get("RELAY_IDLE_TIMEOUT", "300"))  # 5 min default
CONNECT_TIMEOUT_S = 30
MAX_UPLINK_BYTES = 1 * 1024 * 1024  # 1 MB per chunk
DOWN_READ_SIZE = 64 * 1024  # 64 KB read buffer


# --- Session table -----------------------------------------------------------

class Session:
    __slots__ = ("reader", "writer", "last_active", "bytes_in", "bytes_out")

    def __init__(self, reader, writer):
        self.reader = reader
        self.writer = writer
        self.last_active = time.monotonic()
        self.bytes_in = 0
        self.bytes_out = 0


_sessions = {}
_lock = Lock()


def _get_session(sid):
    with _lock:
        s = _sessions.get(sid)
        if s:
            s.last_active = time.monotonic()
        return s


def _add_session(sid, sess):
    with _lock:
        if len(_sessions) >= MAX_SESSIONS:
            return False
        _sessions[sid] = sess
        return True


def _remove_session(sid):
    with _lock:
        return _sessions.pop(sid, None)


def _session_count():
    with _lock:
        return len(_sessions)


# --- Idle sweeper ------------------------------------------------------------

async def _idle_sweeper():
    while True:
        await asyncio.sleep(10)
        try:
            now = time.monotonic()
            stale = []
            with _lock:
                for sid, s in _sessions.items():
                    if now - s.last_active > IDLE_TIMEOUT_S:
                        stale.append(sid)
            for sid in stale:
                s = _remove_session(sid)
                if s:
                    try:
                        s.writer.close()
                        await s.writer.wait_closed()
                    except Exception:
                        pass
                    print(f"[sweep] closed idle session {sid[:8]}", flush=True)
        except asyncio.CancelledError:
            raise
        except Exception as e:
            # sweeper must never die: log and keep looping
            print(f"[sweep] error: {e!r}", flush=True)


# --- Async connect -----------------------------------------------------------

async def _dial(dst_host, dst_port, proxy_ip=None):
    connect_host = proxy_ip if proxy_ip else dst_host
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(connect_host, dst_port),
        timeout=CONNECT_TIMEOUT_S,
    )
    return reader, writer


# --- HTTP handler ------------------------------------------------------------

_loop = None


class RelayHandler(BaseHTTPRequestHandler):
    # HTTP/1.1 keep-alive: without it every /up chunk opens a fresh TCP
    # connection and sustained traffic exhausts the local ephemeral port pool.
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass

    def _reply(self, code: int, body: bytes = b"ok"):
        self.send_response(code)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _check_auth(self):
        auth = self.headers.get("Authorization", "")
        if auth != f"Bearer {RELAY_SECRET}":
            self._reply(401, b"unauthorized")
            return False
        return True

    def _parse(self):
        parsed = urlparse(self.path)
        return parsed.path, parse_qs(parsed.query)

    def do_POST(self):
        if not self._check_auth():
            return
        path, qs = self._parse()
        if path == "/connect":
            self._handle_connect(qs)
        elif path == "/up":
            self._handle_up(qs)
        else:
            self._reply(404, b"not found")

    def _handle_connect(self, qs):
        sid = qs.get("sid", [None])[0]
        dst = qs.get("dst", [None])[0]
        proxy_ip = qs.get("proxy_ip", [None])[0]

        if not sid or not dst:
            self._reply(400, b"missing sid or dst")
            return

        if ":" in dst:
            host, port_s = dst.rsplit(":", 1)
            try:
                port = int(port_s)
            except ValueError:
                self._reply(400, b"invalid dst port")
                return
        else:
            host, port = dst, 443

        if _session_count() >= MAX_SESSIONS:
            self._reply(503, b"max sessions reached")
            return

        try:
            fut = asyncio.run_coroutine_threadsafe(
                _dial(host, port, proxy_ip), _loop
            )
            reader, writer = fut.result(timeout=CONNECT_TIMEOUT_S + 5)
        except Exception as e:
            self._reply(502, f"connect failed: {e}".encode())
            return

        sess = Session(reader, writer)
        if not _add_session(sid, sess):
            writer.close()
            self._reply(503, b"max sessions reached")
            return

        self._reply(200, b"connected")
        print(f"[connect] sid={sid[:8]} dst={dst} proxy={proxy_ip}", flush=True)

    def _handle_up(self, qs):
        sid = qs.get("sid", [None])[0]
        if not sid:
            self._reply(400, b"missing sid")
            return

        sess = _get_session(sid)
        if not sess:
            self._reply(404, b"no such session")
            return

        cl = int(self.headers.get("Content-Length", 0))
        if cl > MAX_UPLINK_BYTES:
            self._reply(413, b"uplink too large")
            return

        body = self.rfile.read(cl) if cl > 0 else b""

        try:
            fut = asyncio.run_coroutine_threadsafe(
                _async_write(sess, body), _loop
            )
            written = fut.result(timeout=30)
        except Exception as e:
            self._reply(502, f"write failed: {e}".encode())
            return

        self._reply(200, str(written).encode())

    def do_GET(self):
        path, qs = self._parse()

        if path == "/health":
            self._reply(200, f"sessions={_session_count()}".encode())
            return

        if not self._check_auth():
            return

        if path == "/down":
            self._handle_down(qs)
        else:
            self._reply(404, b"not found")

    def _handle_down(self, qs):
        sid = qs.get("sid", [None])[0]
        if not sid:
            self._reply(400, b"missing sid")
            return

        sess = _get_session(sid)
        if not sess:
            self._reply(404, b"no such session")
            return

        # Chunked streaming response; Connection: close so the client treats
        # EOF as end-of-downlink (the terminator alone is ambiguous mid-session).
        self.send_response(200)
        self.send_header("Transfer-Encoding", "chunked")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.close_connection = True
        self.end_headers()

        try:
            fut = asyncio.run_coroutine_threadsafe(
                _async_stream_down(sess, self.wfile), _loop
            )
            fut.result(timeout=IDLE_TIMEOUT_S + 30)
        except Exception:
            pass
        finally:
            try:
                self.wfile.write(b"0\r\n\r\n")
                self.wfile.flush()
            except Exception:
                pass

    def do_DELETE(self):
        if not self._check_auth():
            return
        path, qs = self._parse()
        if path != "/close":
            self._reply(404, b"not found")
            return

        sid = qs.get("sid", [None])[0]
        if not sid:
            self._reply(400, b"missing sid")
            return

        sess = _remove_session(sid)
        if sess:
            try:
                sess.writer.close()
            except Exception:
                pass
            print(f"[close] sid={sid[:8]} in={sess.bytes_in} out={sess.bytes_out}", flush=True)

        self._reply(200, b"closed")


async def _async_write(sess, data):
    sess.writer.write(data)
    await sess.writer.drain()
    sess.bytes_in += len(data)
    return len(data)


async def _async_stream_down(sess, wfile):
    try:
        while True:
            data = await asyncio.wait_for(
                sess.reader.read(DOWN_READ_SIZE),
                timeout=IDLE_TIMEOUT_S,
            )
            if not data:
                break
            sess.bytes_out += len(data)
            chunk = f"{len(data):x}\r\n".encode() + data + b"\r\n"
            wfile.write(chunk)
            wfile.flush()
    except asyncio.TimeoutError:
        pass
    except ConnectionResetError:
        pass


# --- Main --------------------------------------------------------------------

def _loop_supervisor():
    """Run the asyncio loop; restart it if it crashes. Sessions owned by a dead
    loop cannot survive, so they are closed and dropped — no zombies."""
    global _loop
    while True:
        # Selector loop: the Windows IOCP proactor has a CPython bug where
        # aborted overlapped ops raise InvalidStateError inside _poll and take
        # down run_forever. The selector policy avoids that entirely.
        try:
            from asyncio import SelectorEventLoop
            _loop = SelectorEventLoop()
        except Exception:
            _loop = asyncio.new_event_loop()
        asyncio.set_event_loop(_loop)
        asyncio.ensure_future(_idle_sweeper(), loop=_loop)
        try:
            _loop.run_forever()
        except Exception as e:
            print(f"[loop] crashed: {e!r}; restarting", flush=True)
        finally:
            with _lock:
                stale = list(_sessions.values())
                _sessions.clear()
            for s in stale:
                try:
                    s.writer.close()
                except Exception:
                    pass
            if stale:
                print(f"[loop] dropped {len(stale)} session(s) with dead loop", flush=True)
            try:
                _loop.close()
            except Exception:
                pass
        time.sleep(0.2)


def main():
    server = ThreadingHTTPServer(("0.0.0.0", LISTEN_PORT), RelayHandler)
    server.daemon_threads = True
    print(f"[relay] listening on :{LISTEN_PORT}", flush=True)
    secret_status = "set" if RELAY_SECRET != "dev-secret-change-me" else "DEFAULT"
    print(f"[relay] secret={secret_status}", flush=True)

    loop_thread = threading.Thread(target=_loop_supervisor, daemon=True)
    loop_thread.start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()
        print("\n[relay] stopped", flush=True)


if __name__ == "__main__":
    main()
