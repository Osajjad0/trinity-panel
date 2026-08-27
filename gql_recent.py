#!/usr/bin/env python3
"""Read-only: recent DO + Worker activity, minute-level where available."""
import datetime
import json
import os
import urllib.request

ACCT = os.environ["CLOUDFLARE_ACCOUNT_ID"]
TOK = os.environ["CLOUDFLARE_API_TOKEN"]

end = datetime.datetime.now(datetime.UTC).replace(tzinfo=None)
start = end - datetime.timedelta(hours=3)


def gql(query, variables):
    body = json.dumps({"query": query, "variables": variables}).encode()
    req = urllib.request.Request("https://api.cloudflare.com/client/v4/graphql",
        data=body, headers={"Authorization": f"Bearer {TOK}",
                            "Content-Type": "application/json"})
    return json.load(urllib.request.urlopen(req, timeout=30))


vars_ = {"acct": ACCT, "start": start.isoformat() + "Z", "end": end.isoformat() + "Z"}

q_min = """
query ($acct: String!, $start: Time!, $end: Time!) {
  viewer {
    accounts(filter: {accountTag: $acct}) {
      durableObjectsInvocationsAdaptiveGroups(limit: 10000,
        filter: {datetimeHour_geq: $start, datetimeHour_leq: $end},
        orderBy: [datetimeHour_ASC]) {
        dimensions { datetimeHour }
        sum { requests errors }
      }
      workersInvocationsAdaptive(limit: 10000,
        filter: {datetime_geq: $start, datetime_leq: $end},
        orderBy: [datetimeHour_ASC]) {
        dimensions { datetimeHour }
        sum { requests errors }
      }
    }
  }
}"""
r = gql(q_min, vars_)
if r.get("errors"):
    print("graphql errors:", json.dumps(r["errors"])[:600])
data = (r.get("data") or {}).get("viewer", {}).get("accounts", [{}])[0]
for row in data.get("durableObjectsInvocationsAdaptiveGroups", []):
    print("DO  ", row["dimensions"]["datetimeHour"], row["sum"])
for row in data.get("workersInvocationsAdaptive", []):
    print("WRK ", row["dimensions"]["datetimeHour"], row["sum"])
