#!/usr/bin/env python3
"""Phase2 download benchmark harness (window-aware).

Waits for the tunnel+destination to come good, then runs the entire size
matrix back-to-back inside the good window. Saves results to JSON.
Usage: python bench_dl.py <label> [dest]
"""
from __future__ import annotations

import json
import os
import statistics
import subprocess
import sys
import time

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

SOCKS = ["--socks5-hostname", "127.0.0.1:10832"]
OUT = "/tmp/bench_dl.bin"
PROBE = "https://proof.ovh.net/files/1Mb.dat"

# dest -> size -> url. Sizes not offered natively fall back to nearest file;
# truncation checks accept the fallback size.
OVH = {
    1024 * 1024: ("https://proof.ovh.net/files/1Mb.dat", 1024 * 1024),
    5 * 1024 * 1024: ("https://proof.ovh.net/files/5Mb.dat", 5 * 1024 * 1024),
    10 * 1024 * 1024: ("https://proof.ovh.net/files/10Mb.dat", 10 * 1024 * 1024),
}


def curl(url, max_time):
    t0 = time.perf_counter()
    r = subprocess.run(
        ["curl", "-sS", *SOCKS, "-o", OUT,
         "-w", "%{http_code} %{time_starttransfer} %{time_total}",
         "--max-time", str(max_time), url],
        capture_output=True, text=True, timeout=max_time + 30)
    wall = time.perf_counter() - t0
    size = os.path.getsize(OUT) if os.path.exists(OUT) else 0
    parts = r.stdout.split()
    return {
        "code": parts[0] if parts else "000",
        "ttfb": float(parts[1]) if len(parts) > 1 else 0.0,
        "total": float(parts[2]) if len(parts) > 2 else 0.0,
        "size": size, "wall": round(wall, 3),
        "mbps": round(size * 8 / 1e6 / total, 1) if (total := float(parts[2]) if len(parts) > 2 else 0) > 0 else 0.0,
        "err": r.stderr.strip()[:100],
    }


def wait_for_window(max_wait_s=1800):
    waited = 0
    while waited < max_wait_s:
        r = curl(PROBE, 40)
        if r["code"] == "200" and r["size"] == 1024 * 1024:
            print(f"  window open after {waited}s")
            return True
        time.sleep(60)
        waited += 60
        print(f"  waiting... ({r['code']} {r['size']}B)")
    return False


def main():
    label = sys.argv[1] if len(sys.argv) > 1 else "run"
    plan = [
        (1024 * 1024, 5),
        (5 * 1024 * 1024, 3),
        (10 * 1024 * 1024, 5),
    ]
    print(f"== {label}: waiting for good window ==")
    if not wait_for_window():
        print("no window within budget; aborting without results")
        return
    results = {}
    for n, runs in plan:
        rows = []
        url, expect = OVH[n]
        for i in range(runs):
            r = curl(url, 300)
            ok = r["code"] == "200" and r["size"] == expect
            rows.append(r)
            print(f"  {n//(1024*1024)}MB run{i+1}: code={r['code']} ttfb={r['ttfb']:.2f} "
                  f"total={r['total']:.2f}s {r['size']}B {'OK' if ok else 'FAIL'} "
                  f"{r['mbps']} Mbps {r['err']}")
            time.sleep(2)
        good = [r for r in rows if r["code"] == "200" and r["size"] == expect]
        speeds = [r["mbps"] for r in good]
        tt = [r["total"] for r in good]
        tb = [r["ttfb"] for r in good]
        results[str(n)] = {
            "runs": len(rows), "ok": len(good),
            "fail": len(rows) - len(good),
            "median_mbps": statistics.median(speeds) if speeds else 0,
            "min_mbps": min(speeds) if speeds else 0,
            "max_mbps": max(speeds) if speeds else 0,
            "p95_mbps": sorted(speeds)[min(len(speeds)-1, int(len(speeds)*0.95))] if speeds else 0,
            "median_total_s": round(statistics.median(tt), 2) if tt else 0,
            "median_ttfb_s": round(statistics.median(tb), 2) if tb else 0,
        }
        print("   ->", json.dumps(results[str(n)]))
        time.sleep(3)
    with open(f"bench_dl_{label}.json", "w", encoding="utf-8") as fh:
        json.dump({"label": label, "results": results}, fh, indent=2)
    print("saved bench_dl_" + label + ".json")


if __name__ == "__main__":
    main()
