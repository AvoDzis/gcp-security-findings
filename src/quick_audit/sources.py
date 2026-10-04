"""Read firewall rules and service account keys from Cloud Asset Inventory or per-project gcloud calls.

Every cloud call goes through a `Runner` (gcloud arguments in, stdout out), so tests swap in a
fake that serves fixture files and nothing ever reaches the network.
"""

from __future__ import annotations

import json
import re
import subprocess
from collections.abc import Callable, Iterable, Sequence
from datetime import UTC, datetime

from quick_audit.models import Allowed, FirewallRule, ServiceAccountKey

Runner = Callable[[Sequence[str]], str]

FIREWALL_ASSET_TYPE = "compute.googleapis.com/Firewall"
SA_KEY_ASSET_TYPE = "iam.googleapis.com/ServiceAccountKey"

_PROJECT_IN_ASSET_NAME = re.compile(r"^//[^/]+/projects/([^/]+)/")
_KEY_NAME = re.compile(r"^projects/(?P<project>[^/]+)/serviceAccounts/(?P<sa>[^/]+)/keys/(?P<key>[^/]+)$")


class SourceError(RuntimeError):
    """gcloud failed or returned something we cannot read."""


def gcloud_runner(args: Sequence[str]) -> str:
    """Run gcloud with the caller's credentials and return stdout."""
    try:
        proc = subprocess.run(["gcloud", *args], check=True, capture_output=True, text=True)
    except FileNotFoundError as exc:
        raise SourceError("gcloud not found on PATH") from exc
    except subprocess.CalledProcessError as exc:
        raise SourceError(f"gcloud {' '.join(args)} failed: {exc.stderr.strip()}") from exc
    return proc.stdout


def load_json_list(text: str, what: str) -> list[dict]:
    try:
        value = json.loads(text) if text.strip() else []
    except json.JSONDecodeError as exc:
        raise SourceError(f"{what}: not valid JSON ({exc})") from exc
    if not isinstance(value, list):
        raise SourceError(f"{what}: expected a JSON list")
    return value


def _timestamp(value: str | None) -> datetime | None:
    """RFC 3339 timestamp from the API; naive values are taken as UTC."""
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise SourceError(f"unexpected timestamp: {value!r}") from exc
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _short_name(url: str) -> str:
    return url.rstrip("/").rsplit("/", 1)[-1] if url else ""


def firewall_from_api(data: dict, project: str) -> FirewallRule:
    """Compute API Firewall resource (as in `gcloud compute firewall-rules list` or CAI resource.data)."""
    name = data["name"]
    allowed = tuple(
        Allowed(
            # The REST API spells it IPProtocol; accept the camelCase form too.
            protocol=str(entry.get("IPProtocol") or entry.get("ipProtocol") or ""),
            ports=tuple(str(p) for p in entry.get("ports", ())),
        )
        for entry in data.get("allowed", ())
    )
    return FirewallRule(
        project=project,
        name=name,
        resource=f"//compute.googleapis.com/projects/{project}/global/firewalls/{name}",
        network=_short_name(data.get("network", "")),
        direction=data.get("direction", "INGRESS"),
        disabled=bool(data.get("disabled", False)),
        priority=int(data.get("priority", 1000)),
        source_ranges=tuple(data.get("sourceRanges", ())),
        allowed=allowed,
        target_tags=tuple(data.get("targetTags", ())),
        target_service_accounts=tuple(data.get("targetServiceAccounts", ())),
    )


def key_from_api(data: dict) -> ServiceAccountKey:
    """IAM API ServiceAccountKey (as in `gcloud iam service-accounts keys list` or CAI resource.data)."""
    name = data.get("name", "")
    match = _KEY_NAME.match(name)
    if not match:
        raise SourceError(f"unexpected service account key name: {name!r}")
    return ServiceAccountKey(
        project=match["project"],
        service_account=match["sa"],
        key_id=match["key"],
        resource=f"//iam.googleapis.com/{name}",
        key_type=data.get("keyType", ""),
        key_origin=data.get("keyOrigin", ""),
        valid_after=_timestamp(data.get("validAfterTime")),
        valid_before=_timestamp(data.get("validBeforeTime")),
        disabled=bool(data.get("disabled", False)),
    )


def parse_cai_assets(assets: Iterable[dict]) -> tuple[list[FirewallRule], list[ServiceAccountKey]]:
    """Assets from `gcloud asset list --content-type=resource --format=json`. Other asset types are ignored."""
    rules: list[FirewallRule] = []
    keys: list[ServiceAccountKey] = []
    for asset in assets:
        asset_type = asset.get("assetType")
        data = (asset.get("resource") or {}).get("data") or {}
        if asset_type == FIREWALL_ASSET_TYPE:
            match = _PROJECT_IN_ASSET_NAME.match(asset.get("name", ""))
            if not match:
                raise SourceError(f"cannot find the project in asset name {asset.get('name')!r}")
            rules.append(firewall_from_api(data, match[1]))
        elif asset_type == SA_KEY_ASSET_TYPE:
            keys.append(key_from_api(data))
    return rules, keys


def collect_cai(runner: Runner, scope: str, scope_id: str) -> tuple[list[FirewallRule], list[ServiceAccountKey]]:
    """One Cloud Asset Inventory call for a whole organization, folder or project.

    Needs roles/cloudasset.viewer on the scope and the Cloud Asset API enabled in the billing project.
    """
    if scope not in ("organization", "folder", "project"):
        raise ValueError(f"scope must be organization, folder or project, not {scope!r}")
    out = runner(
        [
            "asset",
            "list",
            f"--{scope}={scope_id}",
            f"--asset-types={FIREWALL_ASSET_TYPE},{SA_KEY_ASSET_TYPE}",
            "--content-type=resource",
            "--format=json",
        ]
    )
    return parse_cai_assets(load_json_list(out, f"gcloud asset list --{scope}={scope_id}"))


def collect_gcloud(runner: Runner, projects: Iterable[str]) -> tuple[list[FirewallRule], list[ServiceAccountKey]]:
    """Per-project calls for when CAI is not available. One extra call per service account."""
    rules: list[FirewallRule] = []
    keys: list[ServiceAccountKey] = []
    for project in projects:
        firewalls = runner(["compute", "firewall-rules", "list", f"--project={project}", "--format=json"])
        rules += [firewall_from_api(d, project) for d in load_json_list(firewalls, f"firewall rules of {project}")]

        accounts = runner(["iam", "service-accounts", "list", f"--project={project}", "--format=json"])
        for account in load_json_list(accounts, f"service accounts of {project}"):
            email = account["email"]
            listed = runner(
                [
                    "iam",
                    "service-accounts",
                    "keys",
                    "list",
                    f"--iam-account={email}",
                    f"--project={project}",
                    "--managed-by=user",
                    "--format=json",
                ]
            )
            keys += [key_from_api(k) for k in load_json_list(listed, f"keys of {email}")]
    return rules, keys
