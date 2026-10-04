# Bad input is rejected at plan time.

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

run "parent_with_unknown_type" {
  command = plan

  variables {
    scc_parent = "orgs/100000000001"
  }

  expect_failures = [var.scc_parent]
}

run "folder_parent_must_be_numeric" {
  command = plan

  variables {
    scc_parent = "folders/prod"
  }

  expect_failures = [var.scc_parent]
}

run "parent_without_id" {
  command = plan

  variables {
    scc_parent = "projects/"
  }

  expect_failures = [var.scc_parent]
}

run "unsupported_location" {
  command = plan

  variables {
    scc_location = "europe-west1"
  }

  expect_failures = [var.scc_location]
}

run "config_id_with_spaces" {
  command = plan

  variables {
    config_id = "all findings"
  }

  expect_failures = [var.config_id]
}

run "zero_retention" {
  command = plan

  variables {
    retention_days = 0
  }

  expect_failures = [var.retention_days]
}

run "too_few_delivery_attempts" {
  command = plan

  variables {
    max_delivery_attempts = 3
  }

  expect_failures = [var.max_delivery_attempts]
}

run "missing_shared_labels" {
  command = plan

  variables {
    labels = { env = "prod" }
  }

  expect_failures = [var.labels]
}
