#!/usr/bin/env python3
"""Benchmark: direct TCP vs relay throughput.

Usage:
  python bench.py                     # defaults: example.com:80, secret=dev-secret-change-me
  python bench.py --host speed.cloudflare.com --port 443 --secret mysecret
"""

import argparse
import http.client
import socket
import ssl
import time
import uuid


def bench_direct(host: str, port: int, size_mb: float, use_ssl: bool) -> dict:
    """Download size_mb from host:port directly via HTTP(S), return metrics."""
    t0 = time.monotonic()
    if use_ssl:
        conn = http.client.HTTPSConnection(host, port, timeout=30)
    else:
        conn = http.client.HTTPConnection(host, port, timeout=30)

    path = "/cdn-cgi/trace" if host == "speed.cloudflare.com" else "/"
    conn.request("GET", path, headers={"Connection": "close"})
    resp = conn.getresponse()
    connect_ms = (time.monotonic() - t0) * 1000
    ttfb = connect_ms  # response headers arrived

    total = 0
    target = int(size_mb * 1024 * 1024)
    while total < target:
        chunk = resp.read(65536)
        if not chunk:
            break
        total += len(chunk)

    elapsed = time.monotonic() - t0
    conn.close()

    mb = total / (1024 * 1024)
    mbps = (mb * 8) / elapsed if elapsed > 0 else 0
    return {"connect_ms": connect_ms, "ttfb_ms": ttfb, "mb": mb, "mbps": mbps, "elapsed_s": elapsed}


def bench_relay(relay_host: str, relay_port: int, dst_host: str, dst_port: int,
                size_mb: float, secret: str, use_ssl: bool) -> dict:
    """Download size_mb through the relay, return metrics."""
    sid = uuid.uuid4().hex
    auth = f"Bearer {secret}"

    # Connect
    t0 = time.monotonic()
    conn = http.client.HTTPConnection(relay_host, relay_port, timeout=30)
    dst = f"{dst_host}:{dst_port}"
    conn.request("POST", f"/connect?sid={sid}&dst={dst}", headers={"Authorization": auth})
    r = conn.getresponse()
    r.read()
    connect_ms = (time.monotonic() - t0) * 1000
    if r.status != 200:
        return {"error": f"connect failed: {r.status}", "connect_ms": connect_ms, "ttfb_ms": 0, "mb": 0, "mbps": 0, "elapsed_s": 0}

    # Downlink
    t1 = time.monotonic()
    conn2 = http.client.HTTPConnection(relay_host, relay_port, timeout=300)
    conn2.request("GET", f"/down?sid={sid}", headers={"Authorization": auth})
    r2 = conn2.getresponse()

    total = 0
    ttfb = None
    while total < size_mb * 1024 * 1024:
        chunk = r2.read(65536)
        if not chunk:
            break
        if ttfb is None:
            ttfb = (time.monotonic() - t1) * 1000
        total += len(chunk)

    elapsed = time.monotonic() - t1
    r2.close()
    conn2.close()

    # Cleanup
    conn3 = http.client.HTTPConnection(relay_host, relay_port, timeout=5)
    conn3.request("DELETE", f"/close?sid={sid}", headers={"Authorization": auth})
    r3 = conn3.getresponse()
    r3.read()
    conn3.close()

    mb = total / (1024 * 1024)
    mbps = (mb * 8) / elapsed if elapsed > 0 else 0
    return {"connect_ms": connect_ms, "ttfb_ms": ttfb or 0, "mb": mb, "mbps": mbps, "elapsed_s": elapsed}


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="speed.cloudflare.com")
    p.add_argument("--port", type=int, default=443)
    p.add_argument("--relay", default="127.0.0.1")
    p.add_argument("--relay-port", type=int, default=8900)
    p.add_argument("--secret", default="dev-secret-change-me")
    p.add_argument("--size-mb", type=float, default=1.0)
    p.add_argument("--no-ssl", action="store_true")
    p.add_argument("--runs", type=int, default=3)
    args = p.parse_args()

    use_ssl = not args.no_ssl

    print(f"Target: {args.host}:{args.port} | Size: {args.size_mb} MB | Runs: {args.runs}")
    print(f"SSL: {use_ssl}")
    print()

    # Direct baseline
    print("=== DIRECT ===")
    for i in range(args.runs):
        m = bench_direct(args.host, args.port, args.size_mb, use_ssl)
        print(f"  Run {i+1}: connect={m['connect_ms']:.0f}ms  ttfb={m['ttfb_ms']:.0f}ms  "
              f"{m['mb']:.2f} MB in {m['elapsed_s']:.2f}s  {m['mbps']:.1f} Mbps")

    print()

    # Relay
    print("=== RELAY ===")
    for i in range(args.runs):
        m = bench_relay(args.relay, args.relay_port, args.host, args.port,
                        args.size_mb, args.secret, use_ssl)
        if "error" in m:
            print(f"  Run {i+1}: ERROR {m['error']}")
        else:
            print(f"  Run {i+1}: connect={m['connect_ms']:.0f}ms  ttfb={m['ttfb_ms']:.0f}ms  "
                  f"{m['mb']:.2f} MB in {m['elapsed_s']:.2f}s  {m['mbps']:.1f} Mbps")


if __name__ == "__main__":
    main()
