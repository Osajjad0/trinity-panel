"""ONE sustained-download measurement through a single VLESS+XHTTP packet-up session.

Spawns curl once (25 MiB Range GET from ash-speed.hetzner.com through the
local xray SOCKS inbound) and samples the output file size to build a
throughput timeline. Read-only with respect to production: no KV writes,
no config changes, no concurrency.
"""
import json
import os
import subprocess
import sys
import time

URL = "https://ash-speed.hetzner.com/100MB.bin"
RANGE = "0-26214399"          # 25 MiB
PROXY = "socks5h://127.0.0.1:10832"
OUT = "sustained_out.bin"
W = "%{http_code} %{size_download} %{time_starttransfer} %{time_total} %{speed_download}"
TARGET = 26214400
MIB = 1048576

if os.path.exists(OUT):
    os.remove(OUT)

t0 = time.monotonic()
proc = subprocess.Popen(
    ["curl", "-s", "-x", PROXY, "--range", RANGE, "-o", OUT,
     "--connect-timeout", "30", "--max-time", "600", "-w", W, URL],
    stdout=subprocess.PIPE, text=True)

samples = []
while True:
    rc = proc.poll()
    try:
        sz = os.path.getsize(OUT)
    except OSError:
        sz = 0
    samples.append((round(time.monotonic() - t0, 3), sz))
    if rc is not None:
        break
    time.sleep(0.2)

rc = proc.wait()
wline = (proc.stdout.read() or "").strip()
elapsed = round(time.monotonic() - t0, 3)


def cross(mark):
    """Time at which `mark` bytes had arrived (interpolated between samples)."""
    prev_t, prev_s = samples[0]
    for t, s in samples[1:]:
        if s >= mark > prev_s:
            frac = (mark - prev_s) / max(1, (s - prev_s))
            return prev_t + frac * (t - prev_t)
        if s >= mark:
            return t
        prev_t, prev_s = t, s
    return None


# Longest mid-transfer stall (no byte growth between consecutive samples,
# ignoring the initial wait before the first byte).
stall_max = 0.0
started = False
for i in range(1, len(samples)):
    pt, ps = samples[i - 1]
    t, s = samples[i]
    if ps > 0:
        started = True
    if started and s == ps and s < TARGET:
        stall_max = max(stall_max, t - pt)

t_first = next((t for t, s in samples if s > 0), None)
t_1m, t_5m, t_10m = cross(MIB), cross(5 * MIB), cross(10 * MIB)
final = samples[-1][1]

res = {
    "curl_rc": rc,
    "curl_w": wline.split(),
    "wall_elapsed_s": elapsed,
    "bytes_downloaded": final,
    "ttfb_to_first_byte_s": t_first,
    "first_1mb": {
        "t_from_launch_s": t_1m,
        "rate_kbps_incl_setup": round(MIB / t_1m / 1024, 1) if t_1m else None,
        "rate_kbps_post_ttfb": round(MIB / (t_1m - t_first) / 1024, 1)
        if t_1m and t_first else None,
    },
    "cumulative_10mb_rate_kbps_from_launch": round(10 * MIB / t_10m / 1024, 1)
    if t_10m else None,
    "steady_state_after_5mb_kbps": round((final - 5 * MIB) / (elapsed - t_5m) / 1024, 1)
    if t_5m and elapsed > t_5m else None,
    "overall_kbps": round(final / elapsed / 1024, 1),
    "max_midtransfer_stall_s": round(stall_max, 2),
    # 1-second-granularity timeline: [t_s, MB_so_far]
    "timeline_1s": [[t, round(s / MIB, 2)] for t, s in samples
                    if s != dict(samples).get(int(t) and next(x for x in samples if x[0] <= t)[-1])],
}
# Simpler 1s timeline: keep the last sample seen at each integer second.
seen = {}
for t, s in samples:
    seen[int(t)] = (t, s)
res["timeline_1s"] = [[t, round(s / MIB, 2)] for t, (tt, s) in sorted(seen.items())]

print(json.dumps(res, indent=1))
with open("bench_sustained_result.json", "w") as fh:
    json.dump({"result": res, "raw_samples_tail": samples[-200:]}, fh, indent=1)
