-- Cross-check quick-audit against SCC for public SSH/RDP firewall rules.
-- Load the quick-audit CSV as scc_findings.quick_audit first (see queries/README.md).
-- Matches on project ID + firewall rule name: SCC's resource_name can carry the rule's numeric ID,
-- while quick-audit names the rule. Rows marked "only ..." are worth a look: a rule SCC does not
-- flag (detector not enabled, rule changed since the scan) or a finding the audit missed.
WITH audit AS (
  SELECT
    project,
    REGEXP_EXTRACT(resource, r'/firewalls/([^/]+)$') AS rule_name,
    STRING_AGG(`check`, ', ' ORDER BY `check`) AS audit_checks
  FROM scc_findings.quick_audit
  WHERE `check` IN ('PUBLIC_SSH', 'PUBLIC_RDP')
  GROUP BY project, rule_name
),
scc AS (
  SELECT
    project_display_name AS project,
    resource_display_name AS rule_name,
    STRING_AGG(category, ', ' ORDER BY category) AS scc_categories
  FROM (
    SELECT *
    FROM scc_findings.findings
    WHERE publish_time >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 30 DAY)
      AND category IN ('OPEN_SSH_PORT', 'OPEN_RDP_PORT')
    QUALIFY ROW_NUMBER() OVER (PARTITION BY finding_name ORDER BY event_time DESC, publish_time DESC) = 1
  )
  WHERE state = 'ACTIVE'
    AND IFNULL(mute, '') != 'MUTED'
  GROUP BY project, rule_name
)
SELECT
  COALESCE(audit.project, scc.project) AS project,
  COALESCE(audit.rule_name, scc.rule_name) AS rule_name,
  audit.audit_checks,
  scc.scc_categories,
  CASE
    WHEN scc.rule_name IS NULL THEN 'only quick-audit'
    WHEN audit.rule_name IS NULL THEN 'only SCC'
    ELSE 'both'
  END AS seen_by
FROM audit
FULL OUTER JOIN scc
  ON audit.project = scc.project
  AND audit.rule_name = scc.rule_name
ORDER BY seen_by, project, rule_name
