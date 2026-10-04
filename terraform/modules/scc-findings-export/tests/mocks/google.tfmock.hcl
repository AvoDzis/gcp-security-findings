# Shared mock data for `terraform test`. No real API calls are made.

mock_data "google_project" {
  defaults = {
    number = "300000000199"
  }
}

mock_resource "google_scc_v2_organization_notification_config" {
  defaults = {
    name            = "organizations/100000000001/locations/global/notificationConfigs/scc-findings-to-bigquery"
    service_account = "service-org-100000000001@gcp-sa-scc-notification.iam.gserviceaccount.com"
  }
}

mock_resource "google_scc_v2_folder_notification_config" {
  defaults = {
    name            = "folders/200000000020/locations/global/notificationConfigs/scc-findings-to-bigquery"
    service_account = "service-org-100000000001@gcp-sa-scc-notification.iam.gserviceaccount.com"
  }
}

mock_resource "google_scc_v2_project_notification_config" {
  defaults = {
    name            = "projects/acme-prod-data-7a21/locations/global/notificationConfigs/scc-findings-to-bigquery"
    service_account = "service-org-100000000001@gcp-sa-scc-notification.iam.gserviceaccount.com"
  }
}
