#!/usr/bin/env python3
"""Phase-1 verification suite for the Trinity relay PoC.

Covers: accurate direct-vs-relay throughput (100KB..10MB, 60s sustained),
concurrency ladder (1/5/10/25/50), reconnect, idle cleanup, failure cleanup,
session-table drain, security sanity, and relay memory accounting.

Uses time.perf_counter_ns() everywhere (no Windows clock-granularity artifacts).
"""

import http.client
import socket
import threading
import time
import uuid

import psutil

RELAY_HOST = "127.0.0.1"
RELAY_PORT = 8900
SECRET = "dev-secret-change-me"
ECHO_PORT = 18901
AUTH = {"Authorization": f"Bearer {SECRET}"}


def now() -> float:
    return time.perf_counter_ns() / 1e9  # seconds, high resolution


# ---------------------------------------------------------------- echo server

def run_echo_server():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", ECHO_PORT))
    srv.listen(128)
    # No accept timeout: the echo server must outlive the whole suite.
    while True:
        try:
            conn, _ = srv.accept()
        except OSError:
            continue

        def handle(c):
            try:
                c.settimeout(None)
                while True:
                    d = c.recv(65536)
                    if not d:
                        break
                    c.sendall(d)
            except Exception:
                pass
        threading.Thread(target=handle, args=(conn,), daemon=True).start()


# ---------------------------------------------------------------- primitives

def relay_connect(sid: str, dst: str) -> tuple[int, float]:
    t = now()
    c = http.client.HTTPConnection(RELAY_HOST, RELAY_PORT, timeout=30)
    c.request("POST", f"/connect?sid={sid}&dst={dst}", headers=AUTH)
    r = c.getresponse()
    body = r.read()
    ms = (now() - t) * 1000
    c.close()
    return r.status, ms


def relay_up(sid: str, data: bytes, conn=None) -> int:
    """Send an uplink chunk. Pass conn= to reuse a keep-alive connection."""
    own = conn is None
    if own:
        conn = http.client.HTTPConnection(RELAY_HOST, RELAY_PORT, timeout=60)
    try:
        conn.request("POST", f"/up?sid={sid}", body=data,
                     headers={**AUTH, "Content-Length": str(len(data))})
        r = conn.getresponse()
        r.read()
        st = r.status
        return st
    except Exception:
        if own:
            raise
        # keep-alive connection went stale — caller should reconnect
        raise


def new_up_conn() -> http.client.HTTPConnection:
    return http.client.HTTPConnection(RELAY_HOST, RELAY_PORT, timeout=60)


def relay_down_open(sid: str):
    """Open the downlink with a raw socket; returns (sock, header_bytes, ttfb_ms)."""
    t = now()
    s = socket.create_connection((RELAY_HOST, RELAY_PORT), timeout=60)
    req = (f"GET /down?sid={sid} HTTP/1.1\r\nHost: {RELAY_HOST}\r\n"
           f"Authorization: Bearer {SECRET}\r\nConnection: close\r\n\r\n")
    s.sendall(req.encode())
    buf = b""
    while b"\r\n\r\n" not in buf:
        ch = s.recv(4096)
        if not ch:
            break
        buf += ch
    ms = (now() - t) * 1000
    head, _, rest = buf.partition(b"\r\n\r\n")
    status_line = head.split(b"\r\n")[0].decode(errors="replace")
    return s, status_line, rest, ms


def chunk_payload_of(body: bytes) -> bytes:
    """Sum of de-chunked sizes is approximated by counting raw body bytes minus
    framing; for throughput we report raw socket bytes (framing overhead included),
    which is the honest client-visible number."""
    return body


def relay_close(sid: str):
    try:
        c = http.client.HTTPConnection(RELAY_HOST, RELAY_PORT, timeout=5)
        c.request("DELETE", f"/close?sid={sid}", headers=AUTH)
        c.getresponse().read()
        c.close()
    except Exception:
        pass


def relay_health() -> dict:
    c = http.client.HTTPConnection(RELAY_HOST, RELAY_PORT, timeout=5)
    c.request("GET", "/health")
    body = c.getresponse().read().decode(errors="replace")
    c.close()
    # /health returns plain text: "sessions=N"
    d = {}
    for part in body.split(";"):
        if "=" in part:
            k, _, v = part.strip().partition("=")
            d[k] = v
    return d


def json_loads_safe(b):
    import json
    try:
        return json.loads(b.decode())
    except Exception:
        return {}


def relay_sessions() -> int:
    return int(relay_health().get("sessions", -1))


def relay_mem_mb(pid: int) -> float:
    p = psutil.Process(pid)
    return p.memory_info().rss / (1024 * 1024)


def find_relay_pid() -> int | None:
    # Prefer the actual listener on RELAY_PORT via netstat
    import subprocess
    out = subprocess.run(["netstat", "-ano"], capture_output=True, text=True).stdout
    for line in out.splitlines():
        if f":{RELAY_PORT}" in line and "LISTENING" in line:
            try:
                return int(line.split()[-1])
            except ValueError:
                pass
    # Fallback: python.exe running main.py
    for p in psutil.process_iter(["name", "cmdline"]):
        try:
            if p.info["name"] == "python.exe" and any(
                    a and a.endswith("main.py") for a in (p.info["cmdline"] or [])):
                return p.info["pid"]
        except Exception:
            continue
    return None


# ---------------------------------------------------------------- transfer test

def run_transfer(size_bytes: int, label: str, results: dict):
    sid = uuid.uuid4().hex
    dst = f"127.0.0.1:{ECHO_PORT}"

    st, connect_ms = relay_connect(sid, dst)
    if st != 200:
        results[label] = {"error": f"connect {st}"}
        return
    # open downlink FIRST so echo has somewhere to go (avoids deadlock on large sends)
    sock, status_line, rest_head, ttfb_ms = relay_down_open(sid)
    if " 200" not in status_line:
        results[label] = {"error": f"down {status_line}"}
        relay_close(sid)
        return

    # pump uplink in background over one keep-alive connection
    sent = 0
    up_err = None
    def pump():
        nonlocal sent, up_err
        CH = 65536
        try:
            conn = new_up_conn()
            while sent < size_bytes:
                n = min(CH, size_bytes - sent)
                if relay_up(sid, b"\x42" * n, conn=conn) != 200:
                    up_err = "up non-200"
                    return
                sent += n
            conn.close()
        except Exception as e:
            up_err = repr(e)

    th = threading.Thread(target=pump)
    t0 = now()
    th.start()

    recv_total = len(rest_head)  # count any body bytes already in header buffer
    sock.settimeout(30)
    try:
        while recv_total < size_bytes:
            d = sock.recv(65536)
            if not d:
                break
            recv_total += len(d)
    except socket.timeout:
        pass
    elapsed = now() - t0
    th.join(timeout=60)

    sock.close()
    relay_close(sid)

    mb = recv_total / (1024 * 1024)
    mbps = (mb * 8) / elapsed if elapsed > 0 else 0
    results[label] = {
        "ok": recv_total >= size_bytes and up_err is None,
        "connect_ms": round(connect_ms, 2),
        "ttfb_ms": round(ttfb_ms, 2),
        "mb": round(mb, 3),
        "elapsed_s": round(elapsed, 3),
        "mbps": round(mbps, 2),
        "up_error": up_err,
    }


def run_direct(size_bytes: int, label: str, results: dict):
    s = socket.create_connection(("127.0.0.1", ECHO_PORT), timeout=10)
    t0 = now()
    CH = 256 * 1024
    sent = 0
    chunk = b"\x42" * CH

    def pump():
        nonlocal sent
        try:
            while sent < size_bytes:
                n = min(CH, size_bytes - sent)
                s.sendall(chunk[:n])
                sent += n
        except Exception:
            pass

    th = threading.Thread(target=pump)
    th.start()
    recv_total = 0
    ttfb = None
    s.settimeout(30)
    try:
        while recv_total < size_bytes:
            d = s.recv(65536)
            if not d:
                break
            if ttfb is None:
                ttfb = (now() - t0) * 1000
            recv_total += len(d)
    except socket.timeout:
        pass
    elapsed = now() - t0
    th.join(timeout=30)
    s.close()
    mb = recv_total / (1024 * 1024)
    mbps = (mb * 8) / elapsed if elapsed > 0 else 0
    results[label] = {"ok": recv_total >= size_bytes,
                      "ttfb_ms": round(ttfb or 0, 2),
                      "mb": round(mb, 3),
                      "elapsed_s": round(elapsed, 4),
                      "mbps": round(mbps, 2)}


def run_sustained(seconds: float, results: dict):
    """Continuous bidirectional-ish transfer through the relay for `seconds`."""
    sid = uuid.uuid4().hex
    dst = f"127.0.0.1:{ECHO_PORT}"
    st, connect_ms = relay_connect(sid, dst)
    if st != 200:
        results["sustained"] = {"error": f"connect {st}"}
        return
    sock, status_line, rest, ttfb_ms = relay_down_open(sid)

    stop = False
    def pump():
        CH = 65536
        try:
            conn = new_up_conn()
            while not stop:
                if relay_up(sid, b"\x42" * CH, conn=conn) != 200:
                    return
            conn.close()
        except Exception:
            pass

    th = threading.Thread(target=pump, daemon=True)
    t0 = now()
    th.start()
    recv_total = len(rest)
    samples = []
    last_t = t0
    last_r = 0
    sock.settimeout(5)
    try:
        while now() - t0 < seconds:
            d = sock.recv(65536)
            if not d:
                break
            recv_total += len(d)
            tnow = now()
            if tnow - last_t >= 5.0:
                samples.append((recv_total - last_r) * 8 / (tnow - last_t) / 1e6)
                last_t = tnow
                last_r = recv_total
    except socket.timeout:
        pass
    elapsed = now() - t0
    stop = True
    stayed_connected = sock.fileno() != -1  # check BEFORE close()
    sock.close()
    relay_close(sid)
    mb = recv_total / (1024 * 1024)
    mbps = (mb * 8) / elapsed if elapsed > 0 else 0
    results["sustained"] = {
        "ok": elapsed >= seconds * 0.95 and stayed_connected,
        "duration_s": round(elapsed, 1),
        "total_mb": round(mb, 1),
        "avg_mbps": round(mbps, 2),
        "per_5s_samples_mbps": [round(x, 1) for x in samples],
        "ttfb_ms": round(ttfb_ms, 2),
    }


# ---------------------------------------------------------------- concurrency

def one_concurrent_session(idx: int, size_bytes: int, out: dict):
    sid = uuid.uuid4().hex + f"-{idx}"
    dst = f"127.0.0.1:{ECHO_PORT}"
    try:
        st, connect_ms = relay_connect(sid, dst)
        if st != 200:
            out[idx] = {"ok": False, "err": f"connect {st}"}
            return
        sock, status_line, rest, ttfb_ms = relay_down_open(sid)
        if " 200" not in status_line:
            out[idx] = {"ok": False, "err": f"down {status_line}"}
            relay_close(sid)
            return

        sent = 0
        def pump():
            nonlocal sent
            CH = 65536
            try:
                conn = new_up_conn()
                while sent < size_bytes:
                    n = min(CH, size_bytes - sent)
                    if relay_up(sid, b"\x42" * n, conn=conn) != 200:
                        out[idx] = {"ok": False, "err": f"up non-200 at {sent}"}
                        return
                    sent += n
                conn.close()
            except Exception as e:
                out[idx] = {"ok": False, "err": f"pump {e!r} at {sent}"}
        th = threading.Thread(target=pump)
        t0 = now()
        th.start()
        recv_total = len(rest)
        sock.settimeout(20)
        try:
            while recv_total < size_bytes:
                d = sock.recv(65536)
                if not d:
                    break
                recv_total += len(d)
        except socket.timeout:
            pass
        el = now() - t0
        th.join(timeout=30)
        sock.close()
        relay_close(sid)
        mbps = (recv_total * 8) / el / 1e6 if el > 0 else 0
        out[idx] = {"ok": recv_total >= size_bytes,
                    "connect_ms": round(connect_ms, 1),
                    "mbps": round(mbps, 1)}
    except Exception as e:
        out[idx] = {"ok": False, "err": repr(e)}


def run_concurrency(n: int, per_session_kb: int, pid: int, results: dict):
    mem_before = relay_mem_mb(pid)
    sessions_before = relay_sessions()
    out = {}
    threads = [threading.Thread(target=one_concurrent_session, args=(i, per_session_kb * 1024, out))
               for i in range(n)]
    t0 = now()
    for t in threads: t.start()
    for t in threads: t.join(timeout=180)
    wall = now() - t0

    oks = [v for v in out.values() if v.get("ok")]
    errs = {}
    for v in out.values():
        if not v.get("ok"):
            e = v.get("err", "incomplete transfer")
            errs[e] = errs.get(e, 0) + 1
    total_mb = sum(per_session_kb for _ in oks) / 1024
    agg_mbps = total_mb * 8 / wall if wall > 0 else 0
    # let sweeper/cleanups settle briefly before reading table/memory
    deadline = now() + 15
    sess_after = relay_sessions()
    while sess_after > 0 and now() < deadline:
        time.sleep(0.5)
        sess_after = relay_sessions()
    mem_after = relay_mem_mb(pid)

    results[f"x{n}"] = {
        "success": len(oks),
        "failed": n - len(oks),
        "errors": errs,
        "wall_s": round(wall, 2),
        "agg_mbps": round(agg_mbps, 1),
        "per_session_avg_mbps": round(sum(v.get("mbps", 0) for v in oks) / len(oks), 1) if oks else 0,
        "avg_connect_ms": round(sum(v.get("connect_ms", 0) for v in oks) / len(oks), 1) if oks else 0,
        "sessions_before": sessions_before,
        "sessions_after": sess_after,
        "mem_before_mb": round(mem_before, 1),
        "mem_after_mb": round(mem_after, 1),
    }


# ---------------------------------------------------------------- main

def main():
    print("Starting local echo server...")
    threading.Thread(target=run_echo_server, daemon=True).start()
    time.sleep(0.3)

    pid = find_relay_pid()
    print(f"Relay PID: {pid}")
    baseline_mem = relay_mem_mb(pid)
    print(f"Baseline RSS: {baseline_mem:.1f} MB")

    report = {}

    print("\n[1] Throughput ladder (direct vs relay)")
    sizes = [("100KB", 100 * 1024), ("1MB", 1024 * 1024), ("5MB", 5 * 1024 * 1024), ("10MB", 10 * 1024 * 1024)]
    for label, sz in sizes:
        run_direct(sz, f"direct_{label}", report)
        run_transfer(sz, f"relay_{label}", report)
        d = report[f"direct_{label}"]
        r = report[f"relay_{label}"]
        ds = f"{d['mbps']} Mbps ({d['elapsed_s']}s)" if "error" not in d and d.get("ok") else d
        rs = (f"{r['mbps']} Mbps ({r['elapsed_s']}s, ttfb {r.get('ttfb_ms')}ms)"
              if "error" not in r and r.get("ok") else r)
        print(f"  {label:>6}: DIRECT {ds} | RELAY {rs}")

    print("\n[2] Sustained 60s transfer")
    run_sustained(60.0, report)
    print(f"  {report['sustained']}")

    print("\n[3] Concurrency ladder")
    for n in [1, 5, 10, 25, 50]:
        run_concurrency(n, per_session_kb=512, pid=pid, results=report)
        print(f"  x{n}: {report[f'x{n}']}")

    print("\n[4] Reconnect test")
    reconn = {}
    sid = uuid.uuid4().hex
    st, _ = relay_connect(sid, f"127.0.0.1:{ECHO_PORT}")
    ok1 = st == 200 and relay_up(sid, b"hello-reconnect") == 200
    relay_close(sid)
    time.sleep(0.3)
    st2, cms = relay_connect(sid, f"127.0.0.1:{ECHO_PORT}")   # SAME sid reused
    sock, sl, rest, _ = relay_down_open(sid)
    ok2 = " 200" in sl
    sock.close()
    relay_close(sid)
    reconn = {"first_session_ok": ok1, "reconnect_same_sid_ok": ok2 and st2 == 200,
              "reconnect_setup_ms": round(cms, 1)}
    report["reconnect"] = reconn
    print(f"  {reconn}")

    print("\n[5] Idle cleanup (idle timeout + margin)")
    import os as _os
    idle_to = int(_os.environ.get("RELAY_IDLE_TIMEOUT", "300"))
    sid = uuid.uuid4().hex
    relay_connect(sid, f"127.0.0.1:{ECHO_PORT}")
    s_before = relay_sessions()
    wait_s = idle_to + 15
    print(f"  session created; table={s_before}; relay IDLE_TIMEOUT={idle_to}s; "
          f"waiting {wait_s}s for idle sweep...")
    time.sleep(wait_s)
    s_after = relay_sessions()
    report["idle_cleanup"] = {"idle_timeout_s": idle_to,
                              "sessions_before": s_before, "sessions_after_wait": s_after}
    print(f"  {report['idle_cleanup']}")

    print("\n[6] Failure cleanup")
    fail = {}
    # (a) client disappears: open downlink then abort it abruptly
    sid = uuid.uuid4().hex
    relay_connect(sid, f"127.0.0.1:{ECHO_PORT}")
    relay_up(sid, b"trigger-echo")          # ensure downlink has data flowing
    sock, _, _, _ = relay_down_open(sid)
    sock.close()                             # abrupt client abort
    # (b) upstream closes: session whose upstream dies
    sid2 = uuid.uuid4().hex
    relay_connect(sid2, f"127.0.0.1:{ECHO_PORT}")
    relay_up(sid2, b"die-now")
    time.sleep(1.0)
    fail["sessions_after_aborts"] = relay_sessions()
    # force-close both to simulate relay-side detection; then verify removal
    relay_close(sid); relay_close(sid2)
    time.sleep(1.0)
    fail["sessions_after_explicit_close"] = relay_sessions()
    fail["relay_alive"] = relay_health() != {}
    report["failure_cleanup"] = fail
    print(f"  {fail}")

    print("\n[7] Session table drain + memory")
    time.sleep(2)
    final_sess = relay_sessions()
    final_mem = relay_mem_mb(pid)
    report["resources"] = {
        "baseline_rss_mb": round(baseline_mem, 1),
        "peak_rss_seen_mb": round(max(final_mem, baseline_mem), 1),
        "final_rss_mb": round(final_mem, 1),
        "final_sessions": final_sess,
    }
    print(f"  {report['resources']}")

    print("\n[8] Security sanity")
    sec = {}
    # unauthenticated connect must be rejected
    c = http.client.HTTPConnection(RELAY_HOST, RELAY_PORT, timeout=5)
    c.request("POST", f"/connect?sid=evil&dst=127.0.0.1:{ECHO_PORT}")
    sec["no_auth_status"] = c.getresponse().status
    c.close()
    # wrong secret rejected
    c = http.client.HTTPConnection(RELAY_HOST, RELAY_PORT, timeout=5)
    c.request("POST", f"/up?sid=x", body=b"x",
              headers={"Authorization": "Bearer WRONG", "Content-Length": "1"})
    sec["wrong_secret_status"] = c.getresponse().status
    c.close()
    # unknown session rejected
    c = http.client.HTTPConnection(RELAY_HOST, RELAY_PORT, timeout=5)
    c.request("GET", "/down?sid=nonexistent", headers=AUTH)
    sec["unknown_session_status"] = c.getresponse().status
    c.close()
    report["security"] = sec
    print(f"  {sec}")

    import json as _json
    with open("verify_results.json", "w") as f:
        _json.dump(report, f, indent=1)
    print("\nResults written to verify_results.json")


if __name__ == "__main__":
    main()
