# One notification config per scope: organization, folder or project.

mock_provider "google" {
  source = "./tests/mocks"
}

variables {
  project_id = "acme-prod-secops-5e1d"
  labels = {
    env           = "prod"
    service       = "secops"
    owner         = "platform"
    "cost-center" = "security"
  }
}

run "organization_scope" {
  command = apply

  variables {
    scc_parent = "organizations/100000000001"
  }

  assert {
    condition     = length(google_scc_v2_organization_notification_config.this) == 1
    error_message = "organizations/ parent must create one organization notification config."
  }

  assert {
    condition     = length(google_scc_v2_folder_notification_config.this) + length(google_scc_v2_project_notification_config.this) == 0
    error_message = "organizations/ parent must not create folder or project configs."
  }

  assert {
    condition     = google_scc_v2_organization_notification_config.this[0].organization == "100000000001"
    error_message = "Organization ID must be the number after organizations/."
  }

  assert {
    condition     = google_scc_v2_organization_notification_config.this[0].pubsub_topic == google_pubsub_topic.findings.id
    error_message = "SCC must publish to the findings topic."
  }

  assert {
    condition     = google_scc_v2_organization_notification_config.this[0].location == "global"
    error_message = "Default SCC location must be global."
  }

  assert {
    condition     = google_scc_v2_organization_notification_config.this[0].streaming_config[0].filter == "severity = \"CRITICAL\" OR severity = \"HIGH\" OR severity = \"MEDIUM\""
    error_message = "Default filter must keep CRITICAL, HIGH and MEDIUM findings without filtering on state."
  }

  assert {
    condition     = output.notification_config_name == google_scc_v2_organization_notification_config.this[0].name
    error_message = "notification_config_name output must come from the organization config."
  }

  assert {
    condition     = google_pubsub_topic_iam_member.scc_publishes_findings.member == "serviceAccount:service-org-100000000001@gcp-sa-scc-notification.iam.gserviceaccount.com"
    error_message = "The SCC notification service account must be able to publish to the topic."
  }
}

run "folder_scope" {
  command = apply

  variables {
    scc_parent      = "folders/200000000020"
    config_id       = "prod-folder-findings"
    findings_filter = "category = \"OPEN_SSH_PORT\" OR category = \"OPEN_RDP_PORT\""
  }

  assert {
    condition     = length(google_scc_v2_folder_notification_config.this) == 1
    error_message = "folders/ parent must create one folder notification config."
  }

  assert {
    condition     = length(google_scc_v2_organization_notification_config.this) + length(google_scc_v2_project_notification_config.this) == 0
    error_message = "folders/ parent must not create organization or project configs."
  }

  assert {
    condition     = google_scc_v2_folder_notification_config.this[0].folder == "200000000020"
    error_message = "Folder ID must be the number after folders/."
  }

  assert {
    condition     = google_scc_v2_folder_notification_config.this[0].config_id == "prod-folder-findings"
    error_message = "config_id must be passed through."
  }

  assert {
    condition     = google_scc_v2_folder_notification_config.this[0].streaming_config[0].filter == "category = \"OPEN_SSH_PORT\" OR category = \"OPEN_RDP_PORT\""
    error_message = "A custom filter must be passed through unchanged."
  }

  assert {
    condition     = output.notification_config_name == google_scc_v2_folder_notification_config.this[0].name
    error_message = "notification_config_name output must come from the folder config."
  }
}

run "project_scope" {
  command = apply

  variables {
    scc_parent   = "projects/acme-prod-data-7a21"
    scc_location = "eu"
  }

  assert {
    condition     = length(google_scc_v2_project_notification_config.this) == 1
    error_message = "projects/ parent must create one project notification config."
  }

  assert {
    condition     = length(google_scc_v2_organization_notification_config.this) + length(google_scc_v2_folder_notification_config.this) == 0
    error_message = "projects/ parent must not create organization or folder configs."
  }

  assert {
    condition     = google_scc_v2_project_notification_config.this[0].project == "acme-prod-data-7a21"
    error_message = "Project must be the ID after projects/."
  }

  assert {
    condition     = google_scc_v2_project_notification_config.this[0].location == "eu"
    error_message = "scc_location must be passed through for data residency."
  }

  assert {
    condition     = google_scc_v2_project_notification_config.this[0].pubsub_topic == google_pubsub_topic.findings.id
    error_message = "SCC must publish to the findings topic."
  }
}
