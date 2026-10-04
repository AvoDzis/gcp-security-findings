-- New CRITICAL and HIGH findings: first created in the last 7 days, newest first.
-- One row per finding (its latest notification), with where it is and what to do about it.
SELECT
  create_time,
  severity,
  category,
  state,
  project_display_name AS project,
  resource_display_name,
  resource_name,
  source_display_name AS detector,
  next_steps,
  external_uri
FROM scc_findings.findings
WHERE publish_time >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 7 DAY)
  AND create_time >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 7 DAY)
  AND severity IN ('CRITICAL', 'HIGH')
QUALIFY ROW_NUMBER() OVER (PARTITION BY finding_name ORDER BY event_time DESC, publish_time DESC) = 1
ORDER BY create_time DESC
