# endpoint-fleet-ops

Check Windows and macOS laptops from four angles and find the gaps between them: osquery for state, Fleet for policies, Intune and Jamf for enrollment and compliance.

| Piece | Files |
|---|---|
| osquery and SQL | `osquery/compliance.json`: scheduled queries for FileVault, Gatekeeper, firewall, Windows Security Center, and old OS versions |
| FleetDM | `policies/fleet-policies.yml` (pass when a row returns), `fleetops/fleet.py`: page through hosts and sync policies by API, creating new ones and updating changed ones |
| Intune | `fleetops/intune.py`: Graph managed devices, flags noncompliant and stale |
| Jamf | `fleetops/jamf.py`: token auth, paged computer inventory, stale check-ins |
| SQL across systems | `sql/gaps.sql`: devices missing the agent, missing MDM, or enrolled in both MDMs |
| macOS | `scripts/macos-posture.sh`: FileVault, Gatekeeper, SIP, firewall |
| Windows, PowerShell | `scripts/windows-posture.ps1`: BitLocker, Defender, firewall, pending reboot, osqueryd |

```bash
pip install -r requirements.txt
python -m pytest -q tests
scripts/macos-posture.sh
```

## Verified
- 9 pytest tests pass. The osquery and policy queries run on SQLite with the same table and column names, so syntax and logic are checked. The API clients and policy sync run against local stub servers. The gap SQL runs on sample data.
- `scripts/macos-posture.sh` ran on a real Mac (all four checks passed). `shellcheck` is clean.

## Not verified
- Nothing ran against a real Fleet, Intune, or Jamf instance. The endpoints and field names come from their API docs.
- The queries were not run in osquery itself. Table and column names (`disk_encryption`, `gatekeeper`, `alf`, `windows_security_center`, `mounts`) are from the osquery schema, and a few columns differ by version.
- `windows-posture.ps1` was not run (no Windows or PowerShell here).
- Serial numbers are assumed to match across systems. Real fleets have blanks, case differences, and virtual machines.
