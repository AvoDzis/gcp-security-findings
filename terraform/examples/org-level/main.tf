# Organization-wide findings export for the fictional acme.example org.
# Validated offline only (`terraform validate`); not applied.
# Add a remote backend (e.g. a GCS bucket) before using this for real.

terraform {
  required_version = ">= 1.7.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 6.0, < 9.0"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = "europe-west1"
}

variable "project_id" {
  description = "Security tooling project that hosts Pub/Sub and BigQuery."
  type        = string
}

variable "organization_id" {
  description = "Numeric organization ID."
  type        = string
}

module "scc_findings" {
  source = "../../modules/scc-findings-export"

  project_id = var.project_id
  scc_parent = "organizations/${var.organization_id}"

  labels = {
    env           = "prod"
    service       = "secops"
    owner         = "platform"
    "cost-center" = "security"
  }
}

output "findings_view" {
  description = "Query this view; see queries/ for examples."
  value       = module.scc_findings.findings_view
}

output "topic_id" {
  description = "Topic SCC publishes to."
  value       = module.scc_findings.topic_id
}
