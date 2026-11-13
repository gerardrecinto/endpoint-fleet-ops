# Read-only Windows posture check. Exit code 1 if any control is off.
$ErrorActionPreference = "Stop"
$findings = @()

$bl = Get-BitLockerVolume -MountPoint $env:SystemDrive
if ($bl.ProtectionStatus -ne "On") { $findings += "BitLocker off on $env:SystemDrive" }

$mp = Get-MpComputerStatus
if (-not $mp.RealTimeProtectionEnabled) { $findings += "Defender real-time protection off" }
if ($mp.AntivirusSignatureAge -gt 3) { $findings += "Defender signatures $($mp.AntivirusSignatureAge) days old" }

Get-NetFirewallProfile | Where-Object { -not $_.Enabled } | ForEach-Object { $findings += "Firewall off: $($_.Name)" }

$pending = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"
if ($pending) { $findings += "Reboot pending after updates" }

if (-not (Get-Service osqueryd -ErrorAction SilentlyContinue)) { $findings += "osqueryd service missing" }

$findings | ForEach-Object { Write-Output "FAIL $_" }
if ($findings) { exit 1 } else { Write-Output "ok" }
