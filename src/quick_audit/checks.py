"""The audit rules. Pure functions over normalized records: no I/O, no gcloud."""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable
from datetime import datetime

from quick_audit.models import Allowed, Finding, FirewallRule, ServiceAccountKey, Severity

# Ports that should never be reachable from the whole internet. RDP also runs over UDP.
WATCHED_PORTS: dict[str, tuple[tuple[str, int], ...]] = {
    "PUBLIC_SSH": (("tcp", 22),),
    "PUBLIC_RDP": (("tcp", 3389), ("udp", 3389)),
}

# The Compute API accepts IANA protocol numbers as well as names.
PROTOCOL_NUMBERS = {"6": "tcp", "17": "udp"}

# Source range Google uses for IAP TCP forwarding: the usual replacement for public SSH/RDP.
IAP_RANGE = "35.235.240.0/20"

DEFAULT_MAX_KEY_AGE_DAYS = 90


def is_whole_internet(cidr: str) -> bool:
    """True for 0.0.0.0/0, ::/0 and equivalents (any /0)."""
    try:
        return ipaddress.ip_network(cidr.strip(), strict=False).prefixlen == 0
    except ValueError:
        return False


def allows(entry: Allowed, protocol: str, port: int) -> bool:
    """Does one `allowed` entry open protocol/port? Missing ports means every port."""
    entry_protocol = entry.protocol.lower()
    entry_protocol = PROTOCOL_NUMBERS.get(entry_protocol, entry_protocol)
    if entry_protocol == "all":
        return True
    if entry_protocol != protocol:
        return False
    if not entry.ports:
        return True
    for spec in entry.ports:
        low, _, high = spec.partition("-")
        if int(low) <= port <= int(high or low):
            return True
    return False


def _targets(rule: FirewallRule) -> str:
    if rule.target_tags:
        return "tags " + ", ".join(rule.target_tags)
    if rule.target_service_accounts:
        return "service accounts " + ", ".join(rule.target_service_accounts)
    return "all instances in the network"


def check_firewall(rule: FirewallRule) -> list[Finding]:
    """PUBLIC_SSH / PUBLIC_RDP for an enabled ingress rule that allows the port from anywhere.

    This is a per-rule check: it does not evaluate priorities against deny rules,
    hierarchical firewall policies or network firewall policies.
    """
    if rule.direction.upper() != "INGRESS" or rule.disabled:
        return []
    world = [r for r in rule.source_ranges if is_whole_internet(r)]
    if not world:
        return []

    findings = []
    for check, watched in WATCHED_PORTS.items():
        opened = [f"{proto}:{port}" for proto, port in watched if any(allows(a, proto, port) for a in rule.allowed)]
        if not opened:
            continue
        findings.append(
            Finding(
                check=check,
                severity=Severity.HIGH,
                project=rule.project,
                resource=rule.resource,
                detail=(
                    f"{', '.join(opened)} allowed from {', '.join(world)} on network {rule.network}; "
                    f"priority {rule.priority}; targets: {_targets(rule)}"
                ),
                remediation=(
                    f"Restrict source ranges (IAP TCP forwarding uses {IAP_RANGE}) or disable the rule: "
                    f"gcloud compute firewall-rules update {rule.name} --project={rule.project} --disabled"
                ),
            )
        )
    return findings


def check_key(key: ServiceAccountKey, now: datetime, max_age_days: int = DEFAULT_MAX_KEY_AGE_DAYS) -> Finding | None:
    """USER_MANAGED_SA_KEY for every user-managed key.

    HIGH if enabled and older than max_age_days, MEDIUM if enabled, LOW if disabled.
    Google-managed (SYSTEM_MANAGED) keys are rotated by Google and skipped.
    """
    if key.key_type != "USER_MANAGED":
        return None

    age_days = (now - key.valid_after).days if key.valid_after else None
    if key.disabled:
        severity = Severity.LOW
    elif age_days is not None and age_days > max_age_days:
        severity = Severity.HIGH
    else:
        severity = Severity.MEDIUM

    created = f"{key.valid_after.date().isoformat()} ({age_days} days ago)" if key.valid_after else "unknown"
    if key.valid_before is None or key.valid_before.year >= 9999:
        expires = "never"
    else:
        expires = key.valid_before.date().isoformat()

    detail = f"user-managed key for {key.service_account}; created {created}; expires {expires}; origin {key.key_origin}"
    delete = f"gcloud iam service-accounts keys delete {key.key_id} --iam-account={key.service_account}"
    if key.disabled:
        detail += "; disabled"
        remediation = f"Delete the disabled key: {delete}"
    else:
        remediation = (
            "Move the workload to Workload Identity Federation or an attached service account, "
            f"then delete the key: {delete}"
        )

    return Finding(
        check="USER_MANAGED_SA_KEY",
        severity=severity,
        project=key.project,
        resource=key.resource,
        detail=detail,
        remediation=remediation,
    )


def run_checks(
    rules: Iterable[FirewallRule],
    keys: Iterable[ServiceAccountKey],
    now: datetime,
    max_key_age_days: int = DEFAULT_MAX_KEY_AGE_DAYS,
) -> list[Finding]:
    """All findings, most severe first, then by check, project and resource (stable output for diffs)."""
    findings = [f for rule in rules for f in check_firewall(rule)]
    findings += [f for key in keys if (f := check_key(key, now, max_key_age_days))]
    return sorted(findings, key=lambda f: (-f.severity, f.check, f.project, f.resource))
