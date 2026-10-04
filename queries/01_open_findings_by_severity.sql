-- Open findings by severity and category.
-- Takes the latest notification of every finding seen in the last 30 days and keeps the ones that
-- are still ACTIVE and not muted. A finding with no notification in the window is not counted:
-- widen the interval if your findings change rarely.
WITH latest AS (
  SELECT *
  FROM scc_findings.findings
  WHERE publish_time >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 30 DAY)
  QUALIFY ROW_NUMBER() OVER (PARTITION BY finding_name ORDER BY event_time DESC, publish_time DESC) = 1
)
SELECT
  severity,
  category,
  COUNT(*) AS open_findings,
  COUNT(DISTINCT project_display_name) AS projects
FROM latest
WHERE state = 'ACTIVE'
  AND IFNULL(mute, '') != 'MUTED'
GROUP BY severity, category
ORDER BY
  CASE severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 4 ELSE 5 END,
  open_findings DESC
