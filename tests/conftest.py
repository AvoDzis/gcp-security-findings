from __future__ import annotations

import json
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"
REPO = Path(__file__).parent.parent

# Fixed reference time so key ages in the golden CSV never drift.
NOW = datetime(2026, 10, 4, tzinfo=UTC)


class FakeGcloud:
    """Serves fixture files for the exact gcloud commands quick-audit is expected to run."""

    def __init__(self, root: Path = FIXTURES / "gcloud"):
        self.root = root
        self.calls: list[list[str]] = []

    def __call__(self, args: Sequence[str]) -> str:
        args = list(args)
        self.calls.append(args)
        flags = dict(a.removeprefix("--").split("=", 1) for a in args if a.startswith("--") and "=" in a)
        assert flags.get("format") == "json", f"every call must ask for JSON: {args}"
        match args[:4]:
            case ["compute", "firewall-rules", "list", _]:
                path = self.root / flags["project"] / "firewall-rules.json"
            case ["iam", "service-accounts", "list", _]:
                path = self.root / flags["project"] / "service-accounts.json"
            case ["iam", "service-accounts", "keys", "list"]:
                assert flags.get("managed-by") == "user", f"keys must be listed with --managed-by=user: {args}"
                path = self.root / flags["project"] / "keys" / f"{flags['iam-account']}.json"
            case ["asset", "list", *_]:
                path = FIXTURES / "cai" / "assets.json"
            case _:
                raise AssertionError(f"unexpected gcloud call: {args}")
        return path.read_text()


@pytest.fixture
def fake_gcloud() -> FakeGcloud:
    return FakeGcloud()


@pytest.fixture
def cai_assets() -> list[dict]:
    return json.loads((FIXTURES / "cai" / "assets.json").read_text())
