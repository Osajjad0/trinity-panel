#!/usr/bin/env python3
"""Deploy trinity-fresh3b with FULL identity (fresh3_deploy.py constants + kv-id from deploy_checks.py).
Never prints secrets: output filtered to non-secret lines only."""
import os, re, subprocess, sys, tempfile

ROOT = r"C:/Users/alma/Desktop/panel 2"
src = open(os.path.join(ROOT, "fresh3_deploy.py")).read()
env = {"CLOUDFLARE_API_TOKEN": None, "CLOUDFLARE_ACCOUNT_ID": None}
for line in open(os.path.join(ROOT, ".env.fresh")):
    if line.startswith("TRINITY_NEW_TOKEN="):
        env["CLOUDFLARE_API_TOKEN"] = line.split("=", 1)[1].strip()
if not env["CLOUDFLARE_API_TOKEN"]:
    sys.exit("no token in .env.fresh")
# account id appears in deploy_checks.py URL
m = re.search(r"accounts/([0-9a-f]{32})", open(os.path.join(ROOT, "deploy_checks.py")).read())
env["CLOUDFLARE_ACCOUNT_ID"] = m.group(1)

def grab(name):
    m = re.search(rf'^{name}\s*=\s*"([^"]+)"', src, re.M)
    return m.group(1)

KV_ID = "75973b6b001f46638d8565d14ec039f6"
cmd = [sys.executable, os.path.join(ROOT, "scripts", "deploy.py"),
       "--name", "trinity-fresh3b",
       "--build-dir", os.path.join(ROOT, "build", "worker"),
       "--kv-id", KV_ID,
       # No --no-do: deploy.py registers the DO class only when Cloudflare
       # says it is missing (400/10061 on a fresh worker) and sends NO
       # migration on redeploys — a second declaration of the class is
       # REJECTED (412/10079), so "the migration is idempotent" is false.
       # --no-do on a fresh worker skips registration entirely, ships a
       # binding to an unregistered class, and every request then throws
       # (Cloudflare 1101) with the code unchanged.
       "--ws",
       "--uuid", grab("UUID"), "--vmess-uuid", grab("UUID"),
       "--xhttp-path", grab("XHTTP_PATH"),
       "--panel-path", grab("PANEL_PATH"),
       "--sub-path", grab("SUB_PATH"),
       "--panel-password", grab("PANEL_PW"),
       "--trojan-password", grab("TROJAN_PW"),
       "--ss-users", grab("SS_USERS"),
       "--cron", "23 */6 * * *"]
# Pass args via a temp file? deploy.py takes argv directly; keep env clean otherwise.
filter_keys = ("Deployed", "Host", "XHTTP path", "Panel path", "Subscription",
               "rejected", "Error", "error", "Checking", "Uploading", "KV", "Durable",
               "wasm", "sha256", "Identity")
out_path = os.path.join(tempfile.gettempdir(), "fresh3b_deploy_out.txt")
with open(out_path, "w") as outf:
    code = subprocess.call(cmd, stdout=outf, stderr=subprocess.STDOUT,
                           env={**os.environ, **{k: v for k, v in env.items() if v}})
text = open(out_path).read()
os.remove(out_path)
for line in text.splitlines():
    if any(k in line for k in filter_keys):
        print(line[:200])
print("exit:", code)
