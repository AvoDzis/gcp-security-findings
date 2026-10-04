# Pub/Sub -> BigQuery wiring, table layout and IAM. Independent of the SCC scope.

mock_provider "google" {
  source = "./tests/mocks"
}

variables {
  project_id = "acme-prod-secops-5e1d"
  scc_parent = "organizations/100000000001"
  labels = {
    env           = "prod"
    service       = "secops"
    owner         = "platform"
    "cost-center" = "security"
  }
}

run "raw_table_layout" {
  command = apply

  assert {
    condition     = google_bigquery_table.raw.time_partitioning[0].type == "DAY" && google_bigquery_table.raw.time_partitioning[0].field == "publish_time"
    error_message = "Raw table must be partitioned by day on publish_time."
  }

  assert {
    condition     = google_bigquery_table.raw.time_partitioning[0].expiration_ms == 365 * 86400000
    error_message = "Default partition expiration must be 365 days."
  }

  assert {
    condition     = google_bigquery_table.raw.require_partition_filter == true
    error_message = "Queries on the raw table must be forced to filter on the partition column."
  }

  assert {
    condition = toset([for c in jsondecode(google_bigquery_table.raw.schema) : "${c.name}:${c.type}"]) == toset([
      "subscription_name:STRING",
      "message_id:STRING",
      "publish_time:TIMESTAMP",
      "attributes:JSON",
      "data:JSON",
    ])
    error_message = "Raw schema must be the Pub/Sub write_metadata columns plus data as JSON."
  }

  assert {
    condition     = google_bigquery_dataset.findings.location == "europe-west1" && google_bigquery_dataset.findings.dataset_id == "scc_findings"
    error_message = "Dataset must default to scc_findings in europe-west1."
  }

  assert {
    condition     = google_bigquery_table.raw.deletion_protection == true && google_bigquery_table.findings_view.deletion_protection == true
    error_message = "Table and view must be deletion-protected by default."
  }
}

run "bigquery_subscription" {
  command = apply

  assert {
    condition     = google_pubsub_subscription.to_bigquery.topic == google_pubsub_topic.findings.id
    error_message = "BigQuery subscription must read the findings topic."
  }

  assert {
    condition     = google_pubsub_subscription.to_bigquery.bigquery_config[0].table == "acme-prod-secops-5e1d.scc_findings.notifications_raw"
    error_message = "BigQuery subscription must write to project.dataset.notifications_raw."
  }

  assert {
    condition     = google_pubsub_subscription.to_bigquery.bigquery_config[0].write_metadata == true
    error_message = "write_metadata must be on so publish_time (the partition column) is written."
  }

  assert {
    condition     = !coalesce(google_pubsub_subscription.to_bigquery.bigquery_config[0].use_table_schema, false) && !coalesce(google_pubsub_subscription.to_bigquery.bigquery_config[0].use_topic_schema, false)
    error_message = "Messages must land whole in the data column (no topic or table schema mapping)."
  }

  assert {
    condition     = google_pubsub_subscription.to_bigquery.dead_letter_policy[0].dead_letter_topic == google_pubsub_topic.dead_letter.id
    error_message = "Rejected messages must go to the dead-letter topic."
  }

  assert {
    condition     = google_pubsub_subscription.to_bigquery.dead_letter_policy[0].max_delivery_attempts == 5
    error_message = "Default max_delivery_attempts must be 5."
  }

  assert {
    condition     = google_pubsub_subscription.to_bigquery.expiration_policy[0].ttl == "" && google_pubsub_subscription.dead_letter_inspect.expiration_policy[0].ttl == ""
    error_message = "Subscriptions must never expire from inactivity."
  }

  assert {
    condition     = google_pubsub_subscription.dead_letter_inspect.topic == google_pubsub_topic.dead_letter.id
    error_message = "Inspection subscription must read the dead-letter topic."
  }

  assert {
    condition     = google_pubsub_topic.findings.message_storage_policy[0].allowed_persistence_regions == toset(["europe-west1"])
    error_message = "Messages must be stored only in the configured region."
  }
}

run "service_agent_iam" {
  command = apply

  assert {
    condition     = google_bigquery_table_iam_member.pubsub_writes_raw.member == "serviceAccount:service-300000000199@gcp-sa-pubsub.iam.gserviceaccount.com"
    error_message = "The host project's Pub/Sub service agent must be the table writer."
  }

  assert {
    condition     = google_bigquery_table_iam_member.pubsub_writes_raw.role == "roles/bigquery.dataEditor" && google_bigquery_table_iam_member.pubsub_writes_raw.table_id == "notifications_raw"
    error_message = "Pub/Sub needs BigQuery Data Editor on the raw table only."
  }

  assert {
    condition     = google_pubsub_topic_iam_member.pubsub_publishes_dead_letter.topic == google_pubsub_topic.dead_letter.name && google_pubsub_topic_iam_member.pubsub_publishes_dead_letter.role == "roles/pubsub.publisher"
    error_message = "Pub/Sub must be able to publish to the dead-letter topic."
  }

  assert {
    condition     = google_pubsub_subscription_iam_member.pubsub_acks_source.subscription == google_pubsub_subscription.to_bigquery.name && google_pubsub_subscription_iam_member.pubsub_acks_source.role == "roles/pubsub.subscriber"
    error_message = "Pub/Sub must be able to ack dead-lettered messages on the source subscription."
  }
}

run "findings_view" {
  command = apply

  assert {
    condition     = strcontains(google_bigquery_table.findings_view.view[0].query, "FROM `acme-prod-secops-5e1d.scc_findings.notifications_raw`")
    error_message = "View must read the fully qualified raw table."
  }

  assert {
    condition     = google_bigquery_table.findings_view.view[0].use_legacy_sql == false
    error_message = "View must use GoogleSQL."
  }

  assert {
    condition     = output.findings_view == "acme-prod-secops-5e1d.scc_findings.findings"
    error_message = "findings_view output must be project.dataset.findings."
  }
}

run "custom_retention_and_labels" {
  command = apply

  variables {
    retention_days        = 90
    max_delivery_attempts = 10
    deletion_protection   = false
  }

  assert {
    condition     = google_bigquery_table.raw.time_partitioning[0].expiration_ms == 90 * 86400000
    error_message = "retention_days must set partition expiration."
  }

  assert {
    condition     = google_pubsub_subscription.to_bigquery.dead_letter_policy[0].max_delivery_attempts == 10
    error_message = "max_delivery_attempts must be passed through."
  }

  assert {
    condition     = google_bigquery_table.raw.deletion_protection == false
    error_message = "deletion_protection must be passed through."
  }

  assert {
    condition     = google_pubsub_topic.findings.labels["cost-center"] == "security" && google_bigquery_dataset.findings.labels["env"] == "prod"
    error_message = "Shared labels must be applied."
  }
}
