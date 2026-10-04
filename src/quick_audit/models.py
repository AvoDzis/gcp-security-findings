"""Normalized records shared by the sources (CAI, gcloud) and the checks."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import IntEnum


class Severity(IntEnum):
    """Ordered so that a higher value is more severe."""

    LOW = 1
    MEDIUM = 2
    HIGH = 3


@dataclass(frozen=True)
class Allowed:
    """One entry of a firewall rule's `allowed` list. Empty ports means every port."""

    protocol: str
    ports: tuple[str, ...] = ()


@dataclass(frozen=True)
class FirewallRule:
    project: str
    name: str
    resource: str  # //compute.googleapis.com/projects/<project>/global/firewalls/<name>
    network: str  # short network name
    direction: str  # INGRESS or EGRESS
    disabled: bool
    priority: int
    source_ranges: tuple[str, ...]
    allowed: tuple[Allowed, ...]
    target_tags: tuple[str, ...] = ()
    target_service_accounts: tuple[str, ...] = ()


@dataclass(frozen=True)
class ServiceAccountKey:
    project: str
    service_account: str
    key_id: str
    resource: str  # //iam.googleapis.com/projects/<project>/serviceAccounts/<sa>/keys/<key_id>
    key_type: str  # USER_MANAGED or SYSTEM_MANAGED
    key_origin: str  # GOOGLE_PROVIDED or USER_PROVIDED
    valid_after: datetime | None
    valid_before: datetime | None
    disabled: bool = False


@dataclass(frozen=True)
class Finding:
    check: str
    severity: Severity
    project: str
    resource: str
    detail: str
    remediation: str


CSV_COLUMNS = ("check", "severity", "project", "resource", "detail", "remediation")
