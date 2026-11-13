"""FleetDM REST API: list hosts and sync policies from YAML (create new, update changed, leave the rest)."""
from fleetops.http import call


def hosts(base, token, per_page=100):
    out, page = [], 0
    while True:
        r = call("GET", f"{base}/api/v1/fleet/hosts?per_page={per_page}&page={page}", token)
        out += r["hosts"]
        if len(r["hosts"]) < per_page:
            return out
        page += 1


def sync_policies(base, token, wanted):
    """wanted: [{name, query, platform, description, resolution}]. Returns (created, updated) names."""
    have = {p["name"]: p for p in call("GET", f"{base}/api/v1/fleet/global/policies", token)["policies"]}
    created, updated = [], []
    for w in wanted:
        cur = have.get(w["name"])
        if cur is None:
            call("POST", f"{base}/api/v1/fleet/global/policies", token, w)
            created.append(w["name"])
        elif any(cur.get(k) != w.get(k) for k in ("query", "platform", "description", "resolution")):
            call("PATCH", f"{base}/api/v1/fleet/global/policies/{cur['id']}", token, w)
            updated.append(w["name"])
    return created, updated
