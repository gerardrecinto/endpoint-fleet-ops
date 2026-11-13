"""Intune managed devices through Microsoft Graph."""
from datetime import datetime, timedelta, timezone

from fleetops.http import call

GRAPH = "https://graph.microsoft.com/v1.0"


def devices(token, base=GRAPH):
    url = (f"{base}/deviceManagement/managedDevices"
           "?$select=id,deviceName,serialNumber,operatingSystem,complianceState,lastSyncDateTime")
    out = []
    while url:
        r = call("GET", url, token)
        out += r["value"]
        url = r.get("@odata.nextLink")
    return out


def problems(devs, now, stale_days=7):
    """Noncompliant devices, and devices that have not synced recently."""
    cutoff = now - timedelta(days=stale_days)
    out = []
    for d in devs:
        if d["complianceState"] != "compliant":
            out.append((d["serialNumber"], f"compliance state {d['complianceState']}"))
        elif datetime.fromisoformat(d["lastSyncDateTime"].replace("Z", "+00:00")) < cutoff:
            out.append((d["serialNumber"], f"no sync in {stale_days} days"))
    return out
