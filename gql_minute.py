#!/usr/bin/env python3
"""Read-only: minute-level DO invocations around today's hard stop."""
import datetime
import json
import os
import urllib.request

ACCT = os.environ["CLOUDFLARE_ACCOUNT_ID"]
TOK = os.environ["CLOUDFLARE_API_TOKEN"]

end = datetime.datetime.now(datetime.UTC).replace(tzinfo=None)
start = end - datetime.timedelta(hours=6)


def gql(query, variables):
    body = json.dumps({"query": query, "variables": variables}).encode()
    req = urllib.request.Request("https://api.cloudflare.com/client/v4/graphql",
        data=body, headers={"Authorization": f"Bearer {TOK}",
                            "Content-Type": "application/json"})
    return json.load(urllib.request.urlopen(req, timeout=30))


vars_ = {"acct": ACCT, "start": start.isoformat() + "Z", "end": end.isoformat() + "Z"}
q = """
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
r = gql(q, vars_)
if r.get("errors"):
    print("errors:", json.dumps(r["errors"])[:800])
rows = ((r.get("data") or {}).get("viewer", {}).get("accounts") or [{}])[0].get(
    "durableObjectsInvocationsAdaptiveGroups", [])
for row in rows:
    print(row["dimensions"]["datetimeHour"], row["sum"])
