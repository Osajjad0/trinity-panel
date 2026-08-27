#!/usr/bin/env python3
"""Count live Durable Object instances in the account's XhttpSession namespace(s)."""
import json, os, urllib.request

tok = os.environ["CLOUDFLARE_API_TOKEN"]
acct = os.environ["CLOUDFLARE_ACCOUNT_ID"]

def get(url):
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {tok}"})
    return json.load(urllib.request.urlopen(req, timeout=30))

namespaces = get(
    f"https://api.cloudflare.com/client/v4/accounts/{acct}/workers/durable_objects/namespaces"
).get("result", [])
targets = [n["id"] for n in namespaces if n["name"].endswith("_XhttpSession")]
if not targets:
    raise SystemExit("no *_XhttpSession DO namespace found")

for ns in targets:
    cursor = ""
    total = 0
    while True:
        url = (f"https://api.cloudflare.com/client/v4/accounts/{acct}/workers/durable_objects"
               f"/namespaces/{ns}/objects?limit=100&cursor={cursor}")
        d = get(url)
        total += len(d.get("result") or [])
        cursor = (d.get("result_info") or {}).get("cursor") or ""
        if not cursor:
            break
    print(f"{ns}: total live DO instances: {total}")
