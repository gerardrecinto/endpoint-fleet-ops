"""Jamf Pro API: token auth, computer inventory, and a stale check-in report."""
import base64
from datetime import datetime, timedelta

from fleetops.http import call


def token(base, user, password):
    basic = base64.b64encode(f"{user}:{password}".encode()).decode()
    return call("POST", f"{base}/api/v1/auth/token", basic=basic)["token"]


def computers(base, tok, size=100):
    out, page = [], 0
    while True:
        r = call("GET", f"{base}/api/v1/computers-inventory?section=GENERAL&section=HARDWARE&page={page}&page-size={size}", tok)
        out += r["results"]
        if len(out) >= r["totalCount"] or not r["results"]:
            return out
        page += 1


def stale(comps, now: datetime, days=7):
    cutoff = now - timedelta(days=days)
    return [
        (c["hardware"]["serialNumber"], c["general"]["name"])
        for c in comps
        if datetime.fromisoformat(c["general"]["lastContactTime"].replace("Z", "+00:00")) < cutoff
    ]
