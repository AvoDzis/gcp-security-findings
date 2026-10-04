-- How long findings stay open, by severity.
-- For findings with an INACTIVE notification in the last 90 days: time from creation to the first
-- INACTIVE event. A finding that was reactivated and resolved again counts once, at its first fix.
WITH resolved AS (
  SELECT
    finding_name,
    ANY_VALUE(severity) AS severity,
    MIN(create_time) AS created_at,
    MIN(IF(state = 'INACTIVE', event_time, NULL)) AS resolved_at
  FROM scc_findings.findings
  WHERE publish_time >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 90 DAY)
  GROUP BY finding_name
  HAVING resolved_at IS NOT NULL
)
SELECT
  severity,
  COUNT(*) AS resolved_findings,
  ROUND(AVG(TIMESTAMP_DIFF(resolved_at, created_at, HOUR)) / 24, 1) AS mean_days_open,
  ROUND(APPROX_QUANTILES(TIMESTAMP_DIFF(resolved_at, created_at, HOUR), 100)[OFFSET(50)] / 24, 1) AS median_days_open,
  ROUND(APPROX_QUANTILES(TIMESTAMP_DIFF(resolved_at, created_at, HOUR), 100)[OFFSET(90)] / 24, 1) AS p90_days_open
FROM resolved
GROUP BY severity
ORDER BY
  CASE severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 4 ELSE 5 END
