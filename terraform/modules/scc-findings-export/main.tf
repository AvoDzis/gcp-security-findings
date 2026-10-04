# SCC notification config -> Pub/Sub topic -> BigQuery subscription -> partitioned raw table -> typed view.
#
# The raw table stores each notification as JSON (schema-on-read): SCC adds finding fields often, and
# a fixed column mapping would push every new field to the dead-letter topic. The `findings` view
# pulls out the fields that queries need.

locals {
  parent_type = split("/", var.scc_parent)[0]
  parent_id   = split("/", var.scc_parent)[1]

  pubsub_service_agent = "serviceAccount:service-${data.google_project.host.number}@gcp-sa-pubsub.iam.gserviceaccount.com"

  raw_table_ref = "${var.project_id}.${google_bigquery_dataset.findings.dataset_id}.${google_bigquery_table.raw.table_id}"

  # Exactly one of the three notification configs exists; this is the identity SCC publishes as.
  scc_service_account = one(concat(
    google_scc_v2_organization_notification_config.this[*].service_account,
    google_scc_v2_folder_notification_config.this[*].service_account,
    google_scc_v2_project_notification_config.this[*].service_account,
  ))

  notification_config_name = one(concat(
    google_scc_v2_organization_notification_config.this[*].name,
    google_scc_v2_folder_notification_config.this[*].name,
    google_scc_v2_project_notification_config.this[*].name,
  ))
}

data "google_project" "host" {
  project_id = var.project_id
}

# --- Pub/Sub ---------------------------------------------------------------------------------------

resource "google_pubsub_topic" "findings" {
  project = var.project_id
  name    = var.name_prefix
  labels  = var.labels

  message_storage_policy {
    allowed_persistence_regions = [var.region]
  }
}

resource "google_pubsub_topic" "dead_letter" {
  project = var.project_id
  name    = "${var.name_prefix}-dlq"
  labels  = var.labels

  message_storage_policy {
    allowed_persistence_regions = [var.region]
  }
}

resource "google_pubsub_subscription" "to_bigquery" {
  project = var.project_id
  name    = "${var.name_prefix}-to-bq"
  topic   = google_pubsub_topic.findings.id
  labels  = var.labels

  bigquery_config {
    table = local.raw_table_ref
    # No topic or table schema: the whole message lands in the `data` column, and
    # subscription_name, message_id, publish_time and attributes are written too.
    write_metadata = true
  }

  dead_letter_policy {
    dead_letter_topic     = google_pubsub_topic.dead_letter.id
    max_delivery_attempts = var.max_delivery_attempts
  }

  retry_policy {
    minimum_backoff = "10s"
    maximum_backoff = "600s"
  }

  # Never expire: a quiet organisation can go weeks without a matching finding.
  expiration_policy {
    ttl = ""
  }

  depends_on = [google_bigquery_table_iam_member.pubsub_writes_raw]
}

# Holds whatever BigQuery rejected, for inspection and replay.
resource "google_pubsub_subscription" "dead_letter_inspect" {
  project                    = var.project_id
  name                       = "${var.name_prefix}-dlq-inspect"
  topic                      = google_pubsub_topic.dead_letter.id
  labels                     = var.labels
  message_retention_duration = "604800s"

  expiration_policy {
    ttl = ""
  }
}

# The Pub/Sub service agent forwards undeliverable messages: it must publish to the
# dead-letter topic and acknowledge on the source subscription.
resource "google_pubsub_topic_iam_member" "pubsub_publishes_dead_letter" {
  project = var.project_id
  topic   = google_pubsub_topic.dead_letter.name
  role    = "roles/pubsub.publisher"
  member  = local.pubsub_service_agent
}

resource "google_pubsub_subscription_iam_member" "pubsub_acks_source" {
  project      = var.project_id
  subscription = google_pubsub_subscription.to_bigquery.name
  role         = "roles/pubsub.subscriber"
  member       = local.pubsub_service_agent
}

# SCC also grants itself access on the topic when the config is created; this keeps the
# grant visible in code and restores it if an authoritative IAM change removes it.
resource "google_pubsub_topic_iam_member" "scc_publishes_findings" {
  project = var.project_id
  topic   = google_pubsub_topic.findings.name
  role    = "roles/pubsub.publisher"
  member  = "serviceAccount:${local.scc_service_account}"
}

# --- BigQuery --------------------------------------------------------------------------------------

resource "google_bigquery_dataset" "findings" {
  project     = var.project_id
  dataset_id  = var.dataset_id
  location    = var.region
  description = "Security Command Center findings streamed from ${var.scc_parent}."
  labels      = var.labels
}

resource "google_bigquery_table" "raw" {
  project             = var.project_id
  dataset_id          = google_bigquery_dataset.findings.dataset_id
  table_id            = "notifications_raw"
  description         = "One row per SCC notification as delivered by the Pub/Sub BigQuery subscription."
  labels              = var.labels
  schema              = file("${path.module}/schema/notifications_raw.json")
  deletion_protection = var.deletion_protection

  time_partitioning {
    type          = "DAY"
    field         = "publish_time"
    expiration_ms = var.retention_days * 86400000
  }

  # Every query must say which days it reads.
  require_partition_filter = true
}

resource "google_bigquery_table_iam_member" "pubsub_writes_raw" {
  project    = var.project_id
  dataset_id = google_bigquery_dataset.findings.dataset_id
  table_id   = google_bigquery_table.raw.table_id
  role       = "roles/bigquery.dataEditor"
  member     = local.pubsub_service_agent
}

resource "google_bigquery_table" "findings_view" {
  project             = var.project_id
  dataset_id          = google_bigquery_dataset.findings.dataset_id
  table_id            = "findings"
  description         = "Typed view over notifications_raw: one row per notification. Filter on publish_time."
  labels              = var.labels
  deletion_protection = var.deletion_protection

  view {
    query          = templatefile("${path.module}/sql/findings_view.sql.tftpl", { raw_table = local.raw_table_ref })
    use_legacy_sql = false
  }
}

# --- SCC notification config (one of three, by scc_parent) -------------------------------------------

resource "google_scc_v2_organization_notification_config" "this" {
  count = local.parent_type == "organizations" ? 1 : 0

  organization = local.parent_id
  location     = var.scc_location
  config_id    = var.config_id
  description  = "Stream SCC findings to BigQuery (${var.dataset_id})."
  pubsub_topic = google_pubsub_topic.findings.id

  streaming_config {
    filter = var.findings_filter
  }
}

resource "google_scc_v2_folder_notification_config" "this" {
  count = local.parent_type == "folders" ? 1 : 0

  folder       = local.parent_id
  location     = var.scc_location
  config_id    = var.config_id
  description  = "Stream SCC findings to BigQuery (${var.dataset_id})."
  pubsub_topic = google_pubsub_topic.findings.id

  streaming_config {
    filter = var.findings_filter
  }
}

resource "google_scc_v2_project_notification_config" "this" {
  count = local.parent_type == "projects" ? 1 : 0

  project      = local.parent_id
  location     = var.scc_location
  config_id    = var.config_id
  description  = "Stream SCC findings to BigQuery (${var.dataset_id})."
  pubsub_topic = google_pubsub_topic.findings.id

  streaming_config {
    filter = var.findings_filter
  }
}
