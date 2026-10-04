variable "project_id" {
  description = "Project that hosts the Pub/Sub topic, subscriptions and BigQuery dataset (a security tooling project, not the projects being scanned)."
  type        = string

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{4,28}[a-z0-9]$", var.project_id))
    error_message = "project_id must be a valid project ID (6-30 chars, lowercase letters, digits, hyphens)."
  }
}

variable "scc_parent" {
  description = "Where the SCC notification config lives, in API form: organizations/<number>, folders/<number> or projects/<id-or-number>. Findings for everything under it are streamed."
  type        = string

  validation {
    condition     = can(regex("^(organizations/[0-9]+|folders/[0-9]+|projects/([a-z][a-z0-9-]{4,28}[a-z0-9]|[0-9]+))$", var.scc_parent))
    error_message = "scc_parent must look like organizations/123456789012, folders/123456789012 or projects/<project-id>."
  }
}

variable "scc_location" {
  description = "SCC v2 location for the notification config. \"global\" unless data residency is enabled (then eu, sa or us)."
  type        = string
  default     = "global"

  validation {
    condition     = contains(["global", "eu", "sa", "us"], var.scc_location)
    error_message = "scc_location must be one of global, eu, sa, us."
  }
}

variable "config_id" {
  description = "ID of the SCC notification config."
  type        = string
  default     = "scc-findings-to-bigquery"

  validation {
    condition     = can(regex("^[A-Za-z0-9_-]{1,128}$", var.config_id))
    error_message = "config_id must be 1-128 characters: letters, digits, underscores or hyphens."
  }
}

variable "findings_filter" {
  description = "SCC streaming filter. The default drops LOW findings but keeps every state change (ACTIVE and INACTIVE) so resolution can be tracked."
  type        = string
  default     = "severity = \"CRITICAL\" OR severity = \"HIGH\" OR severity = \"MEDIUM\""
}

variable "name_prefix" {
  description = "Prefix for the Pub/Sub topic and subscription names."
  type        = string
  default     = "scc-findings"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,40}$", var.name_prefix))
    error_message = "name_prefix must start with a letter and use 3-41 lowercase letters, digits or hyphens."
  }
}

variable "dataset_id" {
  description = "BigQuery dataset for the findings tables and view."
  type        = string
  default     = "scc_findings"

  validation {
    condition     = can(regex("^[A-Za-z_][A-Za-z0-9_]*$", var.dataset_id)) && length(var.dataset_id) <= 1024
    error_message = "dataset_id may contain only letters, digits and underscores (max 1024 characters)."
  }
}

variable "region" {
  description = "Region for the BigQuery dataset and for Pub/Sub message storage."
  type        = string
  default     = "europe-west1"
}

variable "retention_days" {
  description = "Partition expiration for the raw notifications table, in days."
  type        = number
  default     = 365

  validation {
    condition     = var.retention_days >= 1 && floor(var.retention_days) == var.retention_days
    error_message = "retention_days must be a whole number of days, at least 1."
  }
}

variable "max_delivery_attempts" {
  description = "Delivery attempts before a message that BigQuery rejects goes to the dead-letter topic (Pub/Sub allows 5-100)."
  type        = number
  default     = 5

  validation {
    condition     = var.max_delivery_attempts >= 5 && var.max_delivery_attempts <= 100
    error_message = "max_delivery_attempts must be between 5 and 100."
  }
}

variable "deletion_protection" {
  description = "Protect the BigQuery table and view from terraform destroy."
  type        = bool
  default     = true
}

variable "labels" {
  description = "Labels for every labelable resource. Must include the shared keys env, service, owner and cost-center."
  type        = map(string)

  validation {
    condition     = alltrue([for k in ["env", "service", "owner", "cost-center"] : contains(keys(var.labels), k)])
    error_message = "labels must include env, service, owner and cost-center."
  }
}
