-- Is the pipeline flowing? Notifications per day for the last 14 days, read from the raw table.
-- Days with no notifications do not appear. Pub/Sub delivers at least once, so `notifications`
-- can exceed `distinct_messages`; the gap is redelivered duplicates.
-- Also check the backlog of the <prefix>-dlq-inspect subscription: anything there was rejected.
SELECT
  DATE(publish_time) AS day,
  COUNT(*) AS notifications,
  COUNT(DISTINCT message_id) AS distinct_messages,
  MAX(publish_time) AS newest
FROM scc_findings.notifications_raw
WHERE publish_time >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 14 DAY)
GROUP BY day
ORDER BY day DESC
