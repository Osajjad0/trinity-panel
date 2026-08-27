#!/usr/bin/env python3
"""GraphQL analytics: hourly requests + DO duration for trinity, last N hours."""
import json, os, urllib.request, sys, datetime

ACCT = os.environ["CLOUDFLARE_ACCOUNT_ID"]
TOK = os.environ["CLOUDFLARE_API_TOKEN"]

hours = int(sys.argv[1]) if len(sys.argv) > 1 else 36
end = datetime.datetime.utcnow()
start = end - datetime.timedelta(hours=hours)

q = """
query ($acct: String!, $start: Time!, $end: Time!) {
  viewer {
    accounts(filter: {accountTag: $acct}) {
      workersInvocationsAdaptive(limit: 10000,
        filter: {datetime_geq: $start, datetime_leq: $end, scriptName: "trinity-cleanacct"},
        orderBy: [datetimeHour_ASC]) {
        dimensions { datetimeHour }
        sum { requests errors }
      }
      durableObjectsInvocationsAdaptiveGroups(limit: 10000,
        filter: {datetimeHour_geq: $start, datetimeHour_leq: $end},
        orderBy: [datetimeHour_ASC]) {
        dimensions { datetimeHour }
        sum { requests }
      }
    }
  }
}"""

body = json.dumps({"query": q, "variables": {
    "acct": ACCT, "start": start.isoformat() + "Z", "end": end.isoformat() + "Z"}}).encode()
req = urllib.request.Request(
    f"https://api.cloudflare.com/client/v4/graphql",
    data=body,
    headers={"Authorization": f"Bearer {TOK}", "Content-Type": "application/json"})
try:
    r = json.load(urllib.request.urlopen(req, timeout=30))
except Exception as e:
    print("API error:", e)
    sys.exit(1)
if r.get("errors"):
    print("GraphQL errors:", json.dumps(r["errors"])[:500])
acct_data = r["data"]["viewer"]["accounts"][0]
print(f"window: {start.isoformat()}Z .. {end.isoformat()}Z")
print("\nWorker invocations/hour:")
for row in acct_data.get("workersInvocationsAdaptive", []):
    d = row["dimensions"]["datetimeHour"]
    s = row["sum"]
    print(f"  {d}  req={s['requests']:>7} err={s['errors']}")
print("\nDO invocations/hour:")
for row in acct_data.get("durableObjectsInvocationsAdaptiveGroups", []):
    d = row["dimensions"]["datetimeHour"]
    print(f"  {d}  do_req={row['sum']['requests']:>7}")
