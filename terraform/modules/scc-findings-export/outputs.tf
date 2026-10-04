output "topic_id" {
  description = "Pub/Sub topic SCC publishes to. Other consumers (chat alerts, SOAR) can add their own subscriptions."
  value       = google_pubsub_topic.findings.id
}

output "subscription_id" {
  description = "BigQuery subscription that writes notifications to the raw table."
  value       = google_pubsub_subscription.to_bigquery.id
}

output "dead_letter_topic_id" {
  description = "Topic that receives messages BigQuery rejected."
  value       = google_pubsub_topic.dead_letter.id
}

output "dead_letter_subscription_id" {
  description = "Pull subscription for inspecting dead-lettered messages."
  value       = google_pubsub_subscription.dead_letter_inspect.id
}

output "raw_table" {
  description = "Raw notifications table as project.dataset.table."
  value       = local.raw_table_ref
}

output "findings_view" {
  description = "Typed findings view as project.dataset.table."
  value       = "${var.project_id}.${google_bigquery_dataset.findings.dataset_id}.${google_bigquery_table.findings_view.table_id}"
}

output "notification_config_name" {
  description = "Full resource name of the SCC notification config."
  value       = local.notification_config_name
}

output "scc_service_account" {
  description = "Service account SCC publishes notifications as."
  value       = local.scc_service_account
}
