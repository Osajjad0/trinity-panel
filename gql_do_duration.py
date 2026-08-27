#!/usr/bin/env python3
"""Read-only GraphQL snapshot of recent Durable Object duration/invocations.

Introspects the available DO datasets first so a schema change degrades into a
clear message instead of a hard failure.
"""
import datetime
import json
import os
import sys
import urllib.request

ACCT = os.environ["CLOUDFLARE_ACCOUNT_ID"]
TOK = os.environ["CLOUDFLARE_API_TOKEN"]
hours = int(sys.argv[1]) if len(sys.argv) > 1 else 24

end = datetime.datetime.utcnow()
start = end - datetime.timedelta(hours=hours)


def gql(query, variables=None):
    body = json.dumps({"query": query, "variables": variables or {}}).encode()
    req = urllib.request.Request("https://api.cloudflare.com/client/v4/graphql",
        data=body, headers={"Authorization": f"Bearer {TOK}",
                            "Content-Type": "application/json"})
    return json.load(urllib.request.urlopen(req, timeout=30))


def type_fields(name):
    r = gql('query($t:String!){__type(name:$t){fields{name}}}', {"t": name})
    if r.get("errors") or not r.get("data", {}).get("__type"):
        return None
    return sorted(f["name"] for f in r["data"]["__type"]["fields"])

out = {}
for ds in ["durableObjectsDurationAdaptiveGroups",
           "durableObjectsInvocationsAdaptiveGroups"]:
    out[ds] = type_fields(ds)
    print(ds, "->", out[ds])

window = {"acct": ACCT, "start": start.isoformat() + "Z", "end": end.isoformat() + "Z"}

if out.get("durableObjectsDurationAdaptiveGroups"):
    q = """
    query ($acct: String!, $start: Time!, $end: Time!) {
      viewer {
        accounts(filter: {accountTag: $acct}) {
          durableObjectsDurationAdaptiveGroups(limit: 10000,
            filter: {datetimeHour_geq: $start, datetimeHour_leq: $end},
            orderBy: [datetimeHour_ASC]) {
            dimensions { datetimeHour }
            quantiles { durationP50 durationP99 }
            sum { requests }
          }
        }
      }
    }"""
    r = gql(q, window)
    if r.get("errors"):
        print("duration query errors:", json.dumps(r["errors"])[:800])
    else:
        rows = r["data"]["viewer"]["accounts"][0]["durableObjectsDurationAdaptiveGroups"]
        print(f"\nDO duration by hour ({hours}h):")
        for row in rows:
            d = row["dimensions"]["datetimeHour"]
            q50 = row["quantiles"].get("durationP50")
            q99 = row["quantiles"].get("durationP99")
            n = row["sum"]["requests"]
            print(f"  {d}  n={n:>7}  p50={q50}  p99={q99}")

q2 = """
query ($acct: String!, $start: Time!, $end: Time!) {
  viewer {
    accounts(filter: {accountTag: $acct}) {
      durableObjectsInvocationsAdaptiveGroups(limit: 10000,
        filter: {datetimeHour_geq: $start, datetimeHour_leq: $end},
        orderBy: [datetimeHour_ASC]) {
        dimensions { datetimeHour }
        sum { requests errors }
      }
    }
  }
}"""
r = gql(q2, window)
if not r.get("errors"):
    rows = r["data"]["viewer"]["accounts"][0]["durableObjectsInvocationsAdaptiveGroups"]
    print("\nDO invocations by hour:")
    tot = 0
    for row in rows:
        s = row["sum"]
        tot += s["requests"]
        print(f"  {row['dimensions']['datetimeHour']}  req={s['requests']:>7} err={s['errors']}")
    print("total DO invocations:", tot)
else:
    print("invocation query errors:", json.dumps(r["errors"])[:400])
