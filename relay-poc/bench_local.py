#!/usr/bin/env python3
"""Local benchmark: direct TCP vs relay throughput using a local echo server."""

import http.client
import socket
import threading
import time
import uuid

RELAY_HOST = "127.0.0.1"
RELAY_PORT = 8900
SECRET = "dev-secret-change-me"
ECHO_PORT = 18901


def run_echo_server():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", ECHO_PORT))
    srv.listen(5)
    srv.settimeout(120)
    while True:
        try:
            conn, _ = srv.accept()
        except socket.timeout:
            break
        def handle(c):
            try:
                while True:
                    d = c.recv(65536)
                    if not d:
                        break
                    c.sendall(d)
            except Exception:
                pass
            finally:
                c.close()
        threading.Thread(target=handle, args=(conn,), daemon=True).start()


def bench_direct(size_bytes):
    t0 = time.monotonic()
    s = socket.create_connection(("127.0.0.1", ECHO_PORT), timeout=10)
    connect_ms = (time.monotonic() - t0) * 1000
    chunk = b"\x42" * 65536
    sent = 0
    while sent < size_bytes:
        n = min(len(chunk), size_bytes - sent)
        s.sendall(chunk[:n])
        sent += n
    recv_total = 0
    ttfb = None
    s.settimeout(10)
    while recv_total < size_bytes:
        d = s.recv(65536)
        if not d:
            break
        if ttfb is None:
            ttfb = (time.monotonic() - t0) * 1000
        recv_total += len(d)
    elapsed = time.monotonic() - t0
    s.close()
    mb = recv_total / (1024 * 1024)
    mbps = (mb * 8) / elapsed if elapsed > 0 else 0
    return {"connect_ms": connect_ms, "ttfb_ms": ttfb or 0,
            "mb": mb, "mbps": mbps, "elapsed_s": elapsed}


def bench_relay(size_bytes):
    sid = uuid.uuid4().hex
    auth = f"Bearer {SECRET}"
    t0 = time.monotonic()
    c = http.client.HTTPConnection(RELAY_HOST, RELAY_PORT, timeout=30)
    c.request("POST", f"/connect?sid={sid}&dst=127.0.0.1:{ECHO_PORT}",
              headers={"Authorization": auth})
    r = c.getresponse()
    r.read()
    connect_ms = (time.monotonic() - t0) * 1000
    if r.status != 200:
        return {"error": f"connect failed: {r.status}", "connect_ms": connect_ms,
                "ttfb_ms": 0, "mb": 0, "mbps": 0, "elapsed_s": 0}
    c.close()
    chunk = b"\x42" * 65536
    sent = 0
    while sent < size_bytes:
        n = min(len(chunk), size_bytes - sent)
        c = http.client.HTTPConnection(RELAY_HOST, RELAY_PORT, timeout=30)
        c.request("POST", f"/up?sid={sid}", body=chunk[:n],
                  headers={"Authorization": auth, "Content-Length": str(n)})
        r = c.getresponse()
        r.read()
        c.close()
        sent += n
    # Download via raw socket (avoids http.client chunked-encoding issues)
    t_down = time.monotonic()
    s = socket.create_connection((RELAY_HOST, RELAY_PORT), timeout=60)
    req = f"GET /down?sid={sid} HTTP/1.1\r\nHost: {RELAY_HOST}\r\nAuthorization: {auth}\r\nConnection: close\r\n\r\n"
    s.sendall(req.encode())
    buf = b""
    while b"\r\n\r\n" not in buf:
        ch = s.recv(4096)
        if not ch:
            break
        buf += ch
    ttfb = (time.monotonic() - t_down) * 1000
    recv_total = len(buf.split(b"\r\n\r\n", 1)[1]) if b"\r\n\r\n" in buf else 0
    s.settimeout(10)
    while recv_total < size_bytes:
        try:
            d = s.recv(65536)
        except socket.timeout:
            break
        if not d:
            break
        recv_total += len(d)
    elapsed = time.monotonic() - t0
    s.close()
    c = http.client.HTTPConnection(RELAY_HOST, RELAY_PORT, timeout=5)
    c.request("DELETE", f"/close?sid={sid}", headers={"Authorization": auth})
    r = c.getresponse()
    r.read()
    c.close()
    mb = recv_total / (1024 * 1024)
    mbps = (mb * 8) / elapsed if elapsed > 0 else 0
    return {"connect_ms": connect_ms, "ttfb_ms": ttfb,
            "mb": mb, "mbps": mbps, "elapsed_s": elapsed}


def main():
    print("Starting local echo server...")
    threading.Thread(target=run_echo_server, daemon=True).start()
    time.sleep(0.5)
    sizes = [("100 KB", 100 * 1024), ("1 MB", 1024 * 1024), ("5 MB", 5 * 1024 * 1024)]
    runs = 3
    for label, size in sizes:
        print(f"\n{'='*60}")
        print(f"Size: {label} ({size // 1024} KB)")
        print(f"{'='*60}")
        print("\n--- DIRECT TCP ---")
        direct_results = []
        for i in range(runs):
            m = bench_direct(size)
            direct_results.append(m)
            print(f"  Run {i+1}: connect={m['connect_ms']:.1f}ms  "
                  f"ttfb={m['ttfb_ms']:.1f}ms  "
                  f"{m['mb']:.3f} MB in {m['elapsed_s']:.3f}s  "
                  f"{m['mbps']:.1f} Mbps")
        print("\n--- VIA RELAY ---")
        relay_results = []
        for i in range(runs):
            m = bench_relay(size)
            relay_results.append(m)
            if "error" in m:
                print(f"  Run {i+1}: ERROR {m['error']}")
            else:
                print(f"  Run {i+1}: connect={m['connect_ms']:.1f}ms  "
                      f"ttfb={m['ttfb_ms']:.1f}ms  "
                      f"{m['mb']:.3f} MB in {m['elapsed_s']:.3f}s  "
                      f"{m['mbps']:.1f} Mbps")
        vd = [r for r in direct_results if r["mbps"] > 0]
        vr = [r for r in relay_results if r.get("mbps", 0) > 0]
        if vd and vr:
            ad = sum(r["mbps"] for r in vd) / len(vd)
            ar = sum(r["mbps"] for r in vr) / len(vr)
            ratio = ar / ad * 100 if ad > 0 else 0
            print(f"\n  Avg direct: {ad:.1f} Mbps | Avg relay: {ar:.1f} Mbps | "
                  f"Relay/Direct: {ratio:.0f}%")


if __name__ == "__main__":
    main()