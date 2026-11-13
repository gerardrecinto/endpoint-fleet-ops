#!/usr/bin/env bash
# Read-only macOS posture check. Exit 1 if any control is off.
set -u
fail=0
check() { if eval "$2" >/dev/null 2>&1; then echo "ok   $1"; else echo "FAIL $1"; fail=1; fi; }

check "FileVault on"        "fdesetup status | grep -q 'FileVault is On'"
check "Gatekeeper on"       "spctl --status | grep -q 'assessments enabled'"
check "SIP on"              "csrutil status | grep -q 'enabled'"
check "Firewall on"         "/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate | grep -q 'enabled'"
exit "$fail"
