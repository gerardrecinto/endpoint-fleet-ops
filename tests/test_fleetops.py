import json
import sqlite3
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import yaml

from fleetops import fleet, intune, jamf

ROOT = Path(__file__).parent.parent
NOW = datetime(2026, 11, 13, tzinfo=timezone.utc)


def serve(routes, log=None):
    """routes: {(method, path-prefix): response-dict or callable(handler)->dict}"""
    class H(BaseHTTPRequestHandler):
        def handle_any(self):
            body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
            if log is not None:
                log.append((self.command, self.path, json.loads(body) if body else None, self.headers.get("Authorization")))
            for (m, prefix), resp in routes.items():
                if m == self.command and self.path.startswith(prefix):
                    out = resp(self) if callable(resp) else resp
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(json.dumps(out).encode())
                    return
            self.send_response(404)
            self.end_headers()

        do_GET = do_POST = do_PATCH = handle_any

        def log_message(self, *a):
            pass

    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_port}"


# ---- Fleet ----
def test_fleet_hosts_pages_until_a_short_page():
    pages = {"0": [1, 2], "1": [3]}
    srv, base = serve({("GET", "/api/v1/fleet/hosts"): lambda h: {"hosts": pages[h.path.split("&page=")[1]]}})
    assert fleet.hosts(base, "t", per_page=2) == [1, 2, 3]
    srv.shutdown()


def test_policy_sync_creates_updates_and_skips():
    same = {"name": "a", "query": "q1", "platform": "darwin", "description": "d", "resolution": "r"}
    log = []
    srv, base = serve({
        ("GET", "/api/v1/fleet/global/policies"): {"policies": [dict(same, id=1), dict(same, id=2, name="b", query="old")]},
        ("POST", "/api/v1/fleet/global/policies"): {},
        ("PATCH", "/api/v1/fleet/global/policies/2"): {},
    }, log)
    wanted = [same, dict(same, name="b", query="new"), dict(same, name="c")]
    assert fleet.sync_policies(base, "t", wanted) == (["c"], ["b"])
    srv.shutdown()
    assert [m for m, *_ in log] == ["GET", "PATCH", "POST"]


def test_shipped_policy_file_has_what_fleet_needs():
    for p in yaml.safe_load((ROOT / "policies/fleet-policies.yml").read_text()):
        assert {"name", "query", "platform", "description", "resolution"} <= set(p)


# ---- Intune, Jamf ----
def test_intune_flags_noncompliant_and_stale():
    devs = [{"serialNumber": "A", "complianceState": "noncompliant", "lastSyncDateTime": "2026-11-12T00:00:00Z"},
            {"serialNumber": "B", "complianceState": "compliant", "lastSyncDateTime": "2026-10-01T00:00:00Z"},
            {"serialNumber": "C", "complianceState": "compliant", "lastSyncDateTime": "2026-11-12T00:00:00Z"}]
    assert intune.problems(devs, NOW) == [("A", "compliance state noncompliant"), ("B", "no sync in 7 days")]


def test_jamf_token_then_stale_list():
    comps = [{"general": {"name": "mac1", "lastContactTime": "2026-11-12T10:00:00Z"}, "hardware": {"serialNumber": "S1"}},
             {"general": {"name": "mac2", "lastContactTime": "2026-10-01T10:00:00Z"}, "hardware": {"serialNumber": "S2"}}]
    log = []
    srv, base = serve({("POST", "/api/v1/auth/token"): {"token": "jt"},
                       ("GET", "/api/v1/computers-inventory"): {"totalCount": 2, "results": comps}}, log)
    tok = jamf.token(base, "u", "p")
    got = jamf.computers(base, tok)
    srv.shutdown()
    assert log[0][3].startswith("Basic ") and log[1][3] == "Bearer jt"
    assert jamf.stale(got, NOW) == [("S2", "mac2")]


# ---- SQL gaps and osquery queries, run on SQLite with the same column names ----
def gaps(name):
    c = sqlite3.connect(":memory:")
    for t in ("fleet", "intune", "jamf"):
        c.execute(f"CREATE TABLE {t} (serial)")
    c.executemany("INSERT INTO fleet VALUES (?)", [("A",), ("B",), ("D",)])
    c.executemany("INSERT INTO intune VALUES (?)", [("A",), ("C",), ("E",)])
    c.executemany("INSERT INTO jamf VALUES (?)", [("B",), ("E",)])
    import re
    text = (ROOT / "sql/gaps.sql").read_text()
    q = dict(re.findall(r"-- name: (\w+)\n(?:--[^\n]*\n)*(.*?;)", text, re.S))[name]
    return sorted(r[0] for r in c.execute(q))


def test_inventory_gaps():
    assert gaps("missing_agent") == ["C", "E"]
    assert gaps("missing_mdm") == ["D"]
    assert gaps("double_managed") == ["E"]


def osq(query, setup):
    c = sqlite3.connect(":memory:")
    c.executescript(setup)
    return c.execute(query).fetchall()


MAC = """CREATE TABLE disk_encryption(name, encrypted); CREATE TABLE mounts(device, path);
         CREATE TABLE gatekeeper(assessments_enabled); CREATE TABLE alf(global_state);
         CREATE TABLE os_version(name, version, major, build, platform);
         INSERT INTO mounts VALUES ('/dev/disk3s5', '/System/Volumes/Data'), ('/dev/disk3s1', '/');"""


def pack(name):
    return json.loads((ROOT / "osquery/compliance.json").read_text())["queries"][name]["query"]


def test_filevault_finding_fires_only_when_the_data_volume_is_unencrypted():
    assert osq(pack("macos_filevault_off"), MAC + "INSERT INTO disk_encryption VALUES ('/dev/disk3s5', 0);") == [("filevault_off",)]
    assert osq(pack("macos_filevault_off"), MAC + "INSERT INTO disk_encryption VALUES ('/dev/disk3s5', 1), ('/dev/disk3s1', 0);") == []


def test_other_findings_and_old_os():
    assert osq(pack("macos_gatekeeper_off"), MAC + "INSERT INTO gatekeeper VALUES (0);") == [("gatekeeper_off",)]
    assert osq(pack("macos_firewall_off"), MAC + "INSERT INTO alf VALUES (1);") == []
    old = MAC + "INSERT INTO os_version VALUES ('macOS','13.6',13,'x','darwin'),('Windows','10','10','19044','windows'),('Windows','10','10','19045','windows');"
    assert len(osq(pack("old_os"), old)) == 2


def test_every_pack_and_policy_query_parses_as_sql():
    c = sqlite3.connect(":memory:")
    c.executescript(MAC + "CREATE TABLE windows_security_center(firewall, antivirus);")
    queries = [q["query"] for q in json.loads((ROOT / "osquery/compliance.json").read_text())["queries"].values()]
    queries += [p["query"] for p in yaml.safe_load((ROOT / "policies/fleet-policies.yml").read_text())]
    for q in queries:
        c.execute(q).fetchall()
