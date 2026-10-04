-- SCC's view of the risks quick-audit checks: SSH/RDP open to the internet and user-managed
-- service account keys (Security Health Analytics categories). Open findings only.
-- SERVICE_ACCOUNT_KEY_NOT_ROTATED needs the Premium tier or higher.
WITH latest AS (
  SELECT *
  FROM scc_findings.findings
  WHERE publish_time >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 30 DAY)
    AND category IN ('OPEN_SSH_PORT', 'OPEN_RDP_PORT', 'USER_MANAGED_SERVICE_ACCOUNT_KEY', 'SERVICE_ACCOUNT_KEY_NOT_ROTATED')
  QUALIFY ROW_NUMBER() OVER (PARTITION BY finding_name ORDER BY event_time DESC, publish_time DESC) = 1
)
SELECT
  category,
  severity,
  project_display_name AS project,
  resource_display_name,
  resource_name,
  create_time AS first_seen,
  event_time AS last_seen
FROM latest
WHERE state = 'ACTIVE'
  AND IFNULL(mute, '') != 'MUTED'
ORDER BY category, project, resource_display_name
