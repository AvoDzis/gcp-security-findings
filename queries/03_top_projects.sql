-- The 20 projects with the most open CRITICAL and HIGH findings, with their folders.
-- Same latest-state logic and 30-day window as 01.
WITH latest AS (
  SELECT *
  FROM scc_findings.findings
  WHERE publish_time >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 30 DAY)
  QUALIFY ROW_NUMBER() OVER (PARTITION BY finding_name ORDER BY event_time DESC, publish_time DESC) = 1
)
SELECT
  project_display_name AS project,
  ARRAY_TO_STRING(folders, ', ') AS folder_names,
  COUNTIF(severity = 'CRITICAL') AS critical,
  COUNTIF(severity = 'HIGH') AS high,
  COUNTIF(severity = 'MEDIUM') AS medium,
  COUNT(*) AS open_total
FROM latest
WHERE state = 'ACTIVE'
  AND IFNULL(mute, '') != 'MUTED'
GROUP BY project, folder_names
ORDER BY critical DESC, high DESC, open_total DESC
LIMIT 20
