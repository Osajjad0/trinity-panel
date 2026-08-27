#!/usr/bin/env python3
"""Download benchmark: N runs per candidate, TTFB + throughput, 1MB and 10MB.

Usage: python bench_download.py <label>
Writes bench_<label>.json. Assumes xray is already running on PORT with the
right client config, and KV holds the candidate set being measured.
"""
import json, os, subprocess, sys, tempfile, time, statistics

PORT = 10820
RUNS = 5
# speed.cloudflare.com is TLS-blocked by the local network even without any
# proxy; cachefly (global CDN) serves ranges reliably from this link.
SIZES = [("1MB", "https://cachefly.cachefly.net/10mb.test", ["-r", "0-1048575"]),
         ("10MB", "https://cachefly.cachefly.net/10mb.test", ["-r", "0-10485759"])]

def one(url, extra=(), timeout=90):
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".bin")
    tmp.close()
    try:
        r = subprocess.run(
            ["curl", "-sS", "--socks5-hostname", f"127.0.0.1:{PORT}",
             *extra,
             "-o", tmp.name, "-w", "%{http_code} %{time_starttransfer} %{time_total} %{size_download}",
             "--max-time", str(timeout), url],
            capture_output=True, text=True, timeout=timeout + 15)
        size = os.path.getsize(tmp.name) if os.path.exists(tmp.name) else 0
        parts = r.stdout.strip().split()
        if len(parts) >= 4 and size > 0:
            code, ttfb, total = int(parts[0]), float(parts[1]), float(parts[2])
            return {"code": code, "ttfb": ttfb, "total": total, "size": size,
                    "mbps": (size * 8) / (total * 1e6) if total > 0 else 0}
    except Exception:
        pass
    finally:
        try:
            os.unlink(tmp.name)
        except OSError:
            pass
    return None

def main():
    label = sys.argv[1] if len(sys.argv) > 1 else "run"
    out = {"label": label, "started": time.strftime("%Y-%m-%dT%H:%M:%S"), "runs": {}}
    for size_name, url, extra in SIZES:
        results = []
        for i in range(RUNS):
            r = one(url, extra)
            results.append(r)
            mbps = f"{r['mbps']:.2f}" if r else "FAIL"
            ttfb = f"{r['ttfb']:.3f}s" if r else "-"
            print(f"  {size_name} run{i+1}/{RUNS}: {mbps} Mbps ttfb={ttfb}", flush=True)
            time.sleep(1)
        ok = [r for r in results if r]
        if ok:
            out["runs"][size_name] = {
                "n": len(ok), "fail": RUNS - len(ok),
                "median_mbps": statistics.median(r["mbps"] for r in ok),
                "max_mbps": max(r["mbps"] for r in ok),
                "median_ttfb": statistics.median(r["ttfb"] for r in ok),
                "raw": results,
            }
        else:
            out["runs"][size_name] = {"n": 0, "fail": RUNS, "raw": results}
    fname = f"bench_{label}.json"
    json.dump(out, open(fname, "w"), indent=1)
    print("saved", fname)
    for size_name, s in out["runs"].items():
        if s.get("n"):
            print(f"  {size_name}: median {s['median_mbps']:.2f} Mbps, "
                  f"max {s['max_mbps']:.2f}, ttfb {s['median_ttfb']:.3f}s, "
                  f"fail {s['fail']}/{RUNS}")

if __name__ == "__main__":
    main()
