from __future__ import annotations

import subprocess

import pytest

from quick_audit import sources
from quick_audit.sources import (
    SourceError,
    collect_cai,
    collect_gcloud,
    firewall_from_api,
    gcloud_runner,
    key_from_api,
    parse_cai_assets,
)

PROJECTS = ["acme-dev-web-3f9c", "acme-prod-data-7a21", "acme-sandbox-lab-b04e"]


def test_cai_export_is_parsed(cai_assets):
    rules, keys = parse_cai_assets(cai_assets)
    assert len(rules) == 10
    assert len(keys) == 4  # includes the SYSTEM_MANAGED key; the check skips it later

    by_name = {r.name: r for r in rules}
    bastion = by_name["allow-rdp-bastion"]
    assert bastion.project == "acme-prod-data-7a21"
    assert bastion.network == "prod-vpc"
    assert bastion.priority == 900
    assert bastion.target_tags == ("rdp-bastion",)
    assert bastion.resource == "//compute.googleapis.com/projects/acme-prod-data-7a21/global/firewalls/allow-rdp-bastion"
    assert by_name["legacy-ssh-disabled"].disabled is True
    assert by_name["allow-egress-all"].direction == "EGRESS"
    assert by_name["deny-ssh-world"].allowed == ()


def test_cai_key_names_use_the_service_account_email(cai_assets):
    _, keys = parse_cai_assets(cai_assets)
    ci = next(k for k in keys if k.key_id.endswith("1"))
    assert ci.service_account == "ci-deployer@acme-prod-data-7a21.iam.gserviceaccount.com"
    assert ci.project == "acme-prod-data-7a21"
    assert ci.valid_before.year == 9999


def test_cai_firewall_named_by_numeric_id_still_uses_rule_name():
    # CAI may name a firewall by its numeric ID; the audit identifies it by project + rule name.
    asset = {
        "name": "//compute.googleapis.com/projects/acme-dev-web-3f9c/global/firewalls/4000000000000000099",
        "assetType": "compute.googleapis.com/Firewall",
        "resource": {"data": {"name": "allow-ssh", "sourceRanges": ["0.0.0.0/0"], "allowed": [{"IPProtocol": "tcp"}]}},
    }
    [rule], _ = parse_cai_assets([asset])
    assert rule.resource == "//compute.googleapis.com/projects/acme-dev-web-3f9c/global/firewalls/allow-ssh"
    assert rule.direction == "INGRESS" and rule.priority == 1000  # API defaults


def test_other_asset_types_are_ignored():
    assert parse_cai_assets([{"name": "//storage.googleapis.com/b", "assetType": "storage.googleapis.com/Bucket"}]) == ([], [])


def test_lowercase_ip_protocol_is_accepted():
    rule = firewall_from_api({"name": "r", "allowed": [{"ipProtocol": "tcp", "ports": ["22"]}]}, "p")
    assert rule.allowed[0].protocol == "tcp"


def test_bad_key_name_is_reported():
    with pytest.raises(SourceError, match="unexpected service account key name"):
        key_from_api({"name": "keys/abc"})


def test_bad_timestamp_is_reported():
    with pytest.raises(SourceError, match="unexpected timestamp"):
        key_from_api({"name": "projects/p/serviceAccounts/sa/keys/k", "validAfterTime": "yesterday"})


def test_collect_cai_makes_one_call(fake_gcloud):
    rules, keys = collect_cai(fake_gcloud, "organization", "100000000001")
    assert fake_gcloud.calls == [
        [
            "asset",
            "list",
            "--organization=100000000001",
            "--asset-types=compute.googleapis.com/Firewall,iam.googleapis.com/ServiceAccountKey",
            "--content-type=resource",
            "--format=json",
        ]
    ]
    assert (len(rules), len(keys)) == (10, 4)


def test_collect_cai_rejects_unknown_scope(fake_gcloud):
    with pytest.raises(ValueError):
        collect_cai(fake_gcloud, "billingAccount", "x")


def test_collect_gcloud_walks_projects_and_service_accounts(fake_gcloud):
    rules, keys = collect_gcloud(fake_gcloud, PROJECTS)
    assert len(rules) == 10
    assert sorted(k.key_id[-1] for k in keys) == ["1", "3", "4"]  # user-managed only
    assert ["iam", "service-accounts", "keys", "list", "--iam-account=admin-vm@acme-prod-data-7a21.iam.gserviceaccount.com",
            "--project=acme-prod-data-7a21", "--managed-by=user", "--format=json"] in fake_gcloud.calls
    # 3 firewall lists + 3 service account lists + 5 key lists
    assert len(fake_gcloud.calls) == 11


def test_both_sources_produce_the_same_records(fake_gcloud, cai_assets):
    cai_rules, cai_keys = parse_cai_assets(cai_assets)
    gcloud_rules, gcloud_keys = collect_gcloud(fake_gcloud, PROJECTS)
    assert sorted(cai_rules, key=lambda r: r.resource) == sorted(gcloud_rules, key=lambda r: r.resource)
    user_keys = [k for k in cai_keys if k.key_type == "USER_MANAGED"]
    assert sorted(user_keys, key=lambda k: k.resource) == sorted(gcloud_keys, key=lambda k: k.resource)


def test_gcloud_output_that_is_not_a_list_is_reported():
    with pytest.raises(SourceError, match="expected a JSON list"):
        collect_gcloud(lambda args: '{"error": "nope"}', ["acme-dev-web-3f9c"])


def test_gcloud_runner_reports_failures(monkeypatch):
    def failing_run(cmd, **kwargs):
        raise subprocess.CalledProcessError(1, cmd, stderr="ERROR: (gcloud.asset.list) PERMISSION_DENIED\n")

    monkeypatch.setattr(sources.subprocess, "run", failing_run)
    with pytest.raises(SourceError, match="PERMISSION_DENIED"):
        gcloud_runner(["asset", "list", "--organization=1"])


def test_gcloud_runner_reports_missing_binary(monkeypatch):
    def missing(cmd, **kwargs):
        raise FileNotFoundError("gcloud")

    monkeypatch.setattr(sources.subprocess, "run", missing)
    with pytest.raises(SourceError, match="gcloud not found"):
        gcloud_runner(["version"])
