"""quick-audit command line.

Exit codes: 0 = audit ran, 1 = findings at or above --fail-on, 2 = usage or gcloud error.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

from quick_audit.checks import DEFAULT_MAX_KEY_AGE_DAYS, run_checks
from quick_audit.models import Severity
from quick_audit.report import summary, write_csv
from quick_audit.sources import (
    Runner,
    SourceError,
    collect_cai,
    collect_gcloud,
    gcloud_runner,
    load_json_list,
    parse_cai_assets,
)


def _utc(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--out", default="-", help="CSV file to write (default: stdout)")
    common.add_argument(
        "--max-key-age-days",
        type=int,
        default=DEFAULT_MAX_KEY_AGE_DAYS,
        help=f"user-managed keys older than this are HIGH (default: {DEFAULT_MAX_KEY_AGE_DAYS})",
    )
    common.add_argument("--now", type=_utc, help="reference time for key age, ISO 8601 (default: current UTC time)")
    common.add_argument(
        "--fail-on",
        choices=[s.name for s in Severity],
        help="exit 1 if any finding is at or above this severity (for CI)",
    )

    parser = argparse.ArgumentParser(
        prog="quick-audit",
        description="Find public SSH/RDP firewall rules and user-managed service account keys; write CSV.",
    )
    sources = parser.add_subparsers(dest="source", required=True)

    cai = sources.add_parser(
        "cai",
        parents=[common],
        help="Cloud Asset Inventory: one call for an organization, folder or project",
    )
    scope = cai.add_mutually_exclusive_group(required=True)
    scope.add_argument("--organization", metavar="ORG_ID")
    scope.add_argument("--folder", metavar="FOLDER_ID")
    scope.add_argument("--project", metavar="PROJECT_ID")
    scope.add_argument(
        "--input",
        type=Path,
        metavar="ASSETS_JSON",
        help="audit a saved `gcloud asset list ... --content-type=resource --format=json` export offline",
    )

    per_project = sources.add_parser("gcloud", parents=[common], help="per-project gcloud calls (no CAI needed)")
    per_project.add_argument("--project", dest="projects", action="append", required=True, metavar="PROJECT_ID")

    return parser


def main(argv: Sequence[str] | None = None, runner: Runner | None = None) -> int:
    args = build_parser().parse_args(argv)
    runner = runner or gcloud_runner
    now = args.now or datetime.now(UTC)

    try:
        if args.source == "gcloud":
            rules, keys = collect_gcloud(runner, args.projects)
        elif args.input:
            rules, keys = parse_cai_assets(load_json_list(args.input.read_text(), str(args.input)))
        else:
            scope = next(s for s in ("organization", "folder", "project") if getattr(args, s))
            rules, keys = collect_cai(runner, scope, getattr(args, scope))
    except (SourceError, OSError) as exc:
        print(f"quick-audit: {exc}", file=sys.stderr)
        return 2

    findings = run_checks(rules, keys, now, args.max_key_age_days)

    if args.out == "-":
        write_csv(findings, sys.stdout)
    else:
        with open(args.out, "w", newline="", encoding="utf-8") as stream:
            write_csv(findings, stream)

    target = "stdout" if args.out == "-" else args.out
    print(
        f"quick-audit: {len(rules)} firewall rules, {len(keys)} keys checked; {summary(findings)} -> {target}",
        file=sys.stderr,
    )

    if args.fail_on and any(f.severity >= Severity[args.fail_on] for f in findings):
        return 1
    return 0
