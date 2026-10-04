from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from quick_audit.checks import allows, check_firewall, check_key, is_whole_internet, run_checks
from quick_audit.models import Allowed, FirewallRule, ServiceAccountKey, Severity

from conftest import NOW


def rule(**overrides) -> FirewallRule:
    base = FirewallRule(
        project="acme-dev-web-3f9c",
        name="r",
        resource="//compute.googleapis.com/projects/acme-dev-web-3f9c/global/firewalls/r",
        network="default",
        direction="INGRESS",
        disabled=False,
        priority=1000,
        source_ranges=("0.0.0.0/0",),
        allowed=(Allowed("tcp", ("22",)),),
    )
    return replace(base, **overrides)


def key(**overrides) -> ServiceAccountKey:
    base = ServiceAccountKey(
        project="acme-prod-data-7a21",
        service_account="ci-deployer@acme-prod-data-7a21.iam.gserviceaccount.com",
        key_id="1000000000000000000000000000000000000009",
        resource="//iam.googleapis.com/projects/acme-prod-data-7a21/serviceAccounts/"
        "ci-deployer@acme-prod-data-7a21.iam.gserviceaccount.com/keys/1000000000000000000000000000000000000009",
        key_type="USER_MANAGED",
        key_origin="GOOGLE_PROVIDED",
        valid_after=NOW - timedelta(days=10),
        valid_before=datetime(9999, 12, 31, 23, 59, 59, tzinfo=UTC),
    )
    return replace(base, **overrides)


def checks_of(r: FirewallRule) -> list[str]:
    return [f.check for f in check_firewall(r)]


# --- source ranges ----------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("cidr", "expected"),
    [
        ("0.0.0.0/0", True),
        ("::/0", True),
        ("0.0.0.0", False),  # a single host, not the internet
        ("35.235.240.0/20", False),
        ("10.0.0.0/8", False),
        ("not-a-cidr", False),
    ],
)
def test_is_whole_internet(cidr, expected):
    assert is_whole_internet(cidr) is expected


# --- protocol / port matching -----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("entry", "protocol", "port", "expected"),
    [
        (Allowed("tcp", ("22",)), "tcp", 22, True),
        (Allowed("tcp", ("2222",)), "tcp", 22, False),
        (Allowed("tcp", ("20-30",)), "tcp", 22, True),
        (Allowed("tcp", ("23-30",)), "tcp", 22, False),
        (Allowed("tcp", ()), "tcp", 22, True),  # no ports = every port
        (Allowed("udp", ("22",)), "tcp", 22, False),
        (Allowed("all", ()), "tcp", 3389, True),
        (Allowed("6", ("22",)), "tcp", 22, True),  # IANA protocol number for TCP
        (Allowed("17", ("3389",)), "udp", 3389, True),  # IANA protocol number for UDP
        (Allowed("TCP", ("22",)), "tcp", 22, True),
        (Allowed("icmp", ()), "tcp", 22, False),
    ],
)
def test_allows(entry, protocol, port, expected):
    assert allows(entry, protocol, port) is expected


# --- firewall rules ---------------------------------------------------------------------------------


def test_public_ssh_is_high():
    [finding] = check_firewall(rule())
    assert finding.check == "PUBLIC_SSH"
    assert finding.severity is Severity.HIGH
    assert finding.resource == "//compute.googleapis.com/projects/acme-dev-web-3f9c/global/firewalls/r"
    assert "tcp:22 allowed from 0.0.0.0/0 on network default" in finding.detail
    assert "targets: all instances in the network" in finding.detail
    assert "gcloud compute firewall-rules update r --project=acme-dev-web-3f9c --disabled" in finding.remediation


def test_public_rdp_tcp_and_udp_in_one_finding():
    [finding] = check_firewall(rule(allowed=(Allowed("tcp", ("3389",)), Allowed("udp", ("3389",)))))
    assert finding.check == "PUBLIC_RDP"
    assert finding.detail.startswith("tcp:3389, udp:3389 allowed from 0.0.0.0/0")


def test_all_protocols_opens_ssh_and_rdp():
    assert checks_of(rule(allowed=(Allowed("all"),))) == ["PUBLIC_SSH", "PUBLIC_RDP"]


def test_ipv6_any_counts_as_public():
    assert checks_of(rule(source_ranges=("::/0",))) == ["PUBLIC_SSH"]


def test_public_range_listed_with_private_ranges():
    [finding] = check_firewall(rule(source_ranges=("10.0.0.0/8", "0.0.0.0/0")))
    assert "allowed from 0.0.0.0/0 on" in finding.detail


@pytest.mark.parametrize(
    "overrides",
    [
        {"source_ranges": ("35.235.240.0/20",)},  # IAP only
        {"source_ranges": ("10.0.0.0/8", "192.168.0.0/16")},
        {"disabled": True},
        {"direction": "EGRESS"},
        {"allowed": ()},  # deny rule: nothing allowed
        {"allowed": (Allowed("tcp", ("80", "443")),)},
    ],
    ids=["iap-only", "private", "disabled", "egress", "deny-rule", "other-ports"],
)
def test_no_finding(overrides):
    assert check_firewall(rule(**overrides)) == []


def test_targets_are_described():
    [tagged] = check_firewall(rule(target_tags=("rdp-bastion", "win")))
    assert "targets: tags rdp-bastion, win" in tagged.detail
    [by_sa] = check_firewall(rule(target_service_accounts=("vm@acme-dev-web-3f9c.iam.gserviceaccount.com",)))
    assert "targets: service accounts vm@acme-dev-web-3f9c.iam.gserviceaccount.com" in by_sa.detail


# --- service account keys ---------------------------------------------------------------------------


def test_recent_user_managed_key_is_medium():
    finding = check_key(key(), NOW)
    assert finding.check == "USER_MANAGED_SA_KEY"
    assert finding.severity is Severity.MEDIUM
    assert "(10 days ago)" in finding.detail
    assert "expires never" in finding.detail


def test_old_user_managed_key_is_high():
    assert check_key(key(valid_after=NOW - timedelta(days=91)), NOW).severity is Severity.HIGH


def test_key_exactly_at_max_age_is_not_high():
    assert check_key(key(valid_after=NOW - timedelta(days=90)), NOW).severity is Severity.MEDIUM


def test_max_age_is_configurable():
    assert check_key(key(valid_after=NOW - timedelta(days=31)), NOW, max_age_days=30).severity is Severity.HIGH


def test_disabled_key_is_low_whatever_its_age():
    finding = check_key(key(disabled=True, valid_after=NOW - timedelta(days=900)), NOW)
    assert finding.severity is Severity.LOW
    assert finding.detail.endswith("; disabled")
    assert finding.remediation.startswith("Delete the disabled key")


def test_expiry_date_is_shown():
    finding = check_key(key(valid_before=datetime(2026, 12, 30, 10, tzinfo=UTC)), NOW)
    assert "expires 2026-12-30" in finding.detail


def test_system_managed_key_is_skipped():
    assert check_key(key(key_type="SYSTEM_MANAGED"), NOW) is None


def test_remediation_names_the_key():
    finding = check_key(key(), NOW)
    assert (
        "gcloud iam service-accounts keys delete 1000000000000000000000000000000000000009 "
        "--iam-account=ci-deployer@acme-prod-data-7a21.iam.gserviceaccount.com"
    ) in finding.remediation


# --- ordering ---------------------------------------------------------------------------------------


def test_run_checks_orders_by_severity_then_check_project_resource():
    findings = run_checks(
        [rule(project="b-proj"), rule(project="a-proj", allowed=(Allowed("all"),))],
        [key(), key(disabled=True), key(valid_after=NOW - timedelta(days=400))],
        NOW,
    )
    assert [(f.severity.name, f.check, f.project) for f in findings] == [
        ("HIGH", "PUBLIC_RDP", "a-proj"),
        ("HIGH", "PUBLIC_SSH", "a-proj"),
        ("HIGH", "PUBLIC_SSH", "b-proj"),
        ("HIGH", "USER_MANAGED_SA_KEY", "acme-prod-data-7a21"),
        ("MEDIUM", "USER_MANAGED_SA_KEY", "acme-prod-data-7a21"),
        ("LOW", "USER_MANAGED_SA_KEY", "acme-prod-data-7a21"),
    ]
