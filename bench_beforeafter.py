#!/usr/bin/env python3
"""Before/after benchmark for the write-chunking fix.

Same Worker, same Proxy IP (di.nscl.ir), same client, same destinations as the
Aug 21 baseline (bench_results.json: 26.17 Mbps 10MB median via di.nscl.ir).
Measures download (1MB / 10MB / 60s sustained), TTFB, reconnect, EOF/error
rate, plus a 5MB upload POST through the tunnel (the direction workerd#7074
actually threatens).

Usage: python bench_beforeafter.py <label>
Writes bench_<label>.json.
"""
import json, os, statistics, subprocess, sys, tempfile, time, urllib.request

import os as _os
PORT = int(_os.environ.get("BENCH_PORT", "10820"))
WORKER = _os.environ.get("BENCH_WORKER", "trinity-cleanacct.koxis91079.workers.dev")
XHTTP_PATH = _os.environ.get("BENCH_XPATH", "/d94169f65c7f81bb")
UUID = _os.environ.get("BENCH_UUID", "3ee2b139-b6b2-44b2-ac91-3d4079d85dfd")
KV_NS = _os.environ.get("BENCH_KV_NS", "bd6f705c23944f8cae9011f8d2a587c6")
XRAY = "./xray.exe"

# Same destinations as the Aug 21 baseline (bench_rigorous.py). The local
# network blocks speed.cloudflare.com for DIRECT fetches only; through the
# tunnel the Worker egress fetches, so it is reachable — and it is the exact
# destination the 26.17 Mbps baseline was measured against.
URL_1M = ("https://speed.cloudflare.com/__down?bytes=1048576", [])
URL_10M = ("https://speed.cloudflare.com/__down?bytes=10485760", [])
URL_SUSTAINED = "https://proof.ovh.net/files/100Mb.dat"
GEN = "https://www.gstatic.com/generate_204"


def kv_get():
    url = (f"https://api.cloudflare.com/client/v4/accounts/{os.environ['CLOUDFLARE_ACCOUNT_ID']}"
           f"/storage/kv/namespaces/{KV_NS}/values/panel%3Asettings")
    req = urllib.request.Request(url, headers={
        "Authorization": f"Bearer {os.environ['CLOUDFLARE_API_TOKEN']}"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.load(r)
    except Exception:
        return None


def kv_put(settings):
    raise RuntimeError(
        "BLOCKED: benchmark KV writes are forbidden (roadmap Step 0 / fresh-account "
        "run). This harness must never PUT panel:settings; configure outbound "
        "mode through the panel API instead.")


def make_xray_config():
    return {"log": {"loglevel": "warning"},
            "inbounds": [{"port": PORT, "protocol": "socks", "settings": {"udp": True}}],
            "outbounds": [
                {"protocol": "vless",
                 "settings": {"vnext": [{"address": WORKER, "port": 443,
                                         "users": [{"id": UUID, "encryption": "none"}]}]},
                 "streamSettings": {"network": "xhttp", "security": "tls",
                                    "tlsSettings": {"serverName": WORKER},
                                    "xhttpSettings": {"path": XHTTP_PATH,
                                                      "mode": "packet-up"}}},
                {"protocol": "freedom", "tag": "direct"}],
            "routing": {"rules": [{"type": "field", "ip": ["geoip:private"],
                                   "outboundTag": "direct"}]}}


def curl_get(url, extra=(), timeout=90):
    """GET through the tunnel; returns metrics dict or None on failure."""
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".bin")
    tmp.close()
    try:
        r = subprocess.run(
            ["curl", "-sS", "--socks5-hostname", f"127.0.0.1:{PORT}", *extra,
             "-o", tmp.name, "-w", "%{http_code} %{time_starttransfer} %{time_total}",
             "--max-time", str(timeout), url],
            capture_output=True, text=True, timeout=timeout + 15)
        size = os.path.getsize(tmp.name) if os.path.exists(tmp.name) else 0
        parts = r.stdout.strip().split()
        if len(parts) >= 3 and (size > 0 or parts[0] == "204"):
            return {"code": int(parts[0]), "ttfb": float(parts[1]),
                    "total": float(parts[2]), "size": size,
                    "mbps": (size * 8) / (float(parts[2]) * 1e6)}
    except Exception:
        pass
    finally:
        try:
            os.unlink(tmp.name)
        except OSError:
            pass
    return None


def summarize(results, expected_size=None):
    ok = [r for r in results if r]
    out = {"n": len(ok),
           "fail": len(results) - len(ok),
           "median_mbps": round(statistics.median(r["mbps"] for r in ok), 2) if ok else None,
           "max_mbps": round(max(r["mbps"] for r in ok), 2) if ok else None,
           "median_ttfb": round(statistics.median(r["ttfb"] for r in ok), 3) if ok else None}
    # A short body is an error even with HTTP 200 — count truncated transfers.
    if expected_size:
        out["short"] = sum(1 for r in ok if r["size"] < expected_size)
        out["fail"] += out["short"]
    return out


def main():
    label = sys.argv[1] if len(sys.argv) > 1 else "after"
    print(f"Before/after benchmark — label={label}, worker={WORKER}, proxyip=di.nscl.ir")
    started = time.strftime("%Y-%m-%dT%H:%M:%S")

    # Outbound mode is whatever the deployment's panel:settings already says.
    # This harness no longer writes KV at all (roadmap Step 0): configure the
    # outbound through the panel API before running, then measure read-only.
    settings = kv_get()
    if settings is None:
        print("FATAL: could not READ panel:settings; aborting before any measurement")
        sys.exit(1)
    print(f"outbound mode observed: {(settings.get('outbound') or {}).get('mode')} "
          f"(nodes={len(settings.get('nodes') or [])}) — read-only, nothing written")

    json.dump(make_xray_config(), open("test-xhttp.json", "w"), indent=1)
    subprocess.run(["taskkill", "//F", "//IM", "xray.exe"], capture_output=True)
    time.sleep(1)
    xray = subprocess.Popen([XRAY, "run", "-config", "test-xhttp.json"],
                            stdout=open("xray-bench.log", "w"),
                            stderr=subprocess.STDOUT)
    time.sleep(4)

    out = {"label": label, "started": started, "worker": WORKER}

    # --- setup latency (tunnel establishment, non-CF target) ---
    setup = []
    for _ in range(3):
        r = curl_get(GEN, timeout=30)
        if r and r["code"] == 204:
            setup.append(r["total"])
        time.sleep(0.5)
    out["setup_s_median"] = round(statistics.median(setup), 3) if setup else None

    # --- 1MB ---
    runs = [curl_get(URL_1M[0], URL_1M[1], timeout=60) for _ in range(5)]
    out["1MB"] = summarize(runs, expected_size=1048576)
    for i, r in enumerate(runs):
        print(f"  1MB run{i+1}: " + (f"{r['mbps']:.2f} Mbps ttfb={r['ttfb']:.3f}s size={r['size']}" if r else "FAIL"), flush=True)

    # --- 10MB ---
    runs = [curl_get(URL_10M[0], URL_10M[1], timeout=120) for _ in range(5)]
    out["10MB"] = summarize(runs, expected_size=10485760)
    for i, r in enumerate(runs):
        print(f"  10MB run{i+1}: " + (f"{r['mbps']:.2f} Mbps ttfb={r['ttfb']:.3f}s size={r['size']}" if r else "FAIL"), flush=True)

    # --- 60s sustained download ---
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".bin"); tmp.close()
    try:
        t0 = time.time()
        subprocess.run(
            ["curl", "-sS", "--socks5-hostname", f"127.0.0.1:{PORT}",
             "-o", tmp.name, "--max-time", "61", URL_SUSTAINED],
            capture_output=True, timeout=75)
        elapsed = time.time() - t0
        size = os.path.getsize(tmp.name)
        out["sustained60s"] = {"bytes": size, "seconds": round(elapsed, 1),
                               "avg_mbps": round((size * 8) / (elapsed * 1e6), 2)}
        print(f"  sustained: {size} bytes in {elapsed:.1f}s = {out['sustained60s']['avg_mbps']} Mbps avg")
    finally:
        try:
            os.unlink(tmp.name)
        except OSError:
            pass

    # --- reconnect: three sequential fresh tunnels (gstatic each time) ---
    rec = []
    for _ in range(3):
        t0 = time.time()
        r = curl_get(GEN, timeout=30)
        if r and r["code"] == 204:
            rec.append(time.time() - t0)
    out["reconnect_s_median"] = round(statistics.median(rec), 3) if rec else None

    # --- 5MB upload POST through the tunnel ---
    # httpbin echoes the body; success requires a complete 5MB uplink, which
    # is exactly what oversized single writes were destroying pre-fix.
    up_ok, up_total, up_secs = 0, 3, []
    payload = os.urandom(5 * 1024 * 1024)
    for i in range(up_total):
        open(f"/tmp/up{i}.bin", "wb").write(payload)
        try:
            t0 = time.time()
            r = subprocess.run(
                ["curl", "-sS", "--socks5-hostname", f"127.0.0.1:{PORT}",
                 "-o", f"/tmp/upresp{i}.json", "-w", "%{http_code}",
                 "--max-time", "120", "-X", "POST",
                 "-H", "Content-Type: application/octet-stream",
                 "--data-binary", f"@/tmp/up{i}.bin",
                 "https://httpbin.org/post"],
                capture_output=True, text=True, timeout=135)
            took = time.time() - t0
            resp = open(f"/tmp/upresp{i}.json", encoding="utf-8", errors="replace").read() \
                if os.path.exists(f"/tmp/upresp{i}.json") else ""
            echoed = str(len(payload)) in resp
            if r.stdout.strip() == "200" and echoed:
                up_ok += 1
                up_secs.append(took)
                print(f"  upload run{i+1}: OK {took:.1f}s ({(len(payload)*8)/(took*1e6):.2f} Mbps)")
            else:
                print(f"  upload run{i+1}: FAIL code={r.stdout.strip()} echoed={echoed}")
        except Exception as e:
            print(f"  upload run{i+1}: EXC {e}")
        finally:
            for p in (f"/tmp/up{i}.bin", f"/tmp/upresp{i}.json"):
                try:
                    os.unlink(p)
                except OSError:
                    pass
    out["upload5MB"] = {"ok": up_ok, "total": up_total,
                        "median_mbps": round(statistics.median(
                            (len(payload) * 8) / (s * 1e6) for s in up_secs), 2) if up_secs else None}

    xray.terminate()
    try:
        xray.wait(timeout=5)
    except Exception:
        subprocess.run(["taskkill", "//F", "//IM", "xray.exe"], capture_output=True)

    fname = f"bench_{label}.json"
    json.dump(out, open(fname, "w"), indent=1)
    print("saved", fname)


if __name__ == "__main__":
    main()
