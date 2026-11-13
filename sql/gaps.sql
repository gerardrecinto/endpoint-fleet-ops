-- Tables: fleet(serial, os), intune(serial), jamf(serial). One row per device per system.

-- name: missing_agent
-- Managed by MDM but not reporting to Fleet/osquery.
SELECT serial FROM (
  SELECT serial FROM intune UNION SELECT serial FROM jamf
) WHERE serial NOT IN (SELECT serial FROM fleet);

-- name: missing_mdm
-- Reporting to Fleet but enrolled in neither Intune nor Jamf.
SELECT serial FROM fleet
WHERE serial NOT IN (SELECT serial FROM intune) AND serial NOT IN (SELECT serial FROM jamf);

-- name: double_managed
-- Enrolled in both MDMs: the two will fight over settings.
SELECT serial FROM intune WHERE serial IN (SELECT serial FROM jamf);
