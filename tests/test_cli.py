"""End to end on fixture data: every source must produce the reviewed golden CSV."""

from __future__ import annotations

import csv
import io

import pytest

from quick_audit.cli import main

from conftest import FIXTURES, REPO

GOLDEN = FIXTURES / "expected" / "findings.csv"
PINNED = ["--now", "2026-10-04"]


def test_cai_export_file_matches_golden_csv(tmp_path, capsys):
    out = tmp_path / "findings.csv"
    code = main(["cai", "--input", str(FIXTURES / "cai" / "assets.json"), "--out", str(out), *PINNED])
    assert code == 0
    assert out.read_text() == GOLDEN.read_text()
    assert "10 firewall rules, 4 keys checked; 9 findings (7 HIGH, 1 MEDIUM, 1 LOW)" in capsys.readouterr().err


def test_cai_live_call_matches_golden_csv(tmp_path, fake_gcloud):
    out = tmp_path / "findings.csv"
    assert main(["cai", "--organization", "100000000001", "--out", str(out), *PINNED], runner=fake_gcloud) == 0
    assert fake_gcloud.calls[0][:3] == ["asset", "list", "--organization=100000000001"]
    assert out.read_text() == GOLDEN.read_text()


def test_gcloud_per_project_matches_golden_csv(tmp_path, fake_gcloud):
    out = tmp_path / "findings.csv"
    projects = ["acme-dev-web-3f9c", "acme-prod-data-7a21", "acme-sandbox-lab-b04e"]
    argv = ["gcloud", *[a for p in projects for a in ("--project", p)], "--out", str(out), *PINNED]
    assert main(argv, runner=fake_gcloud) == 0
    assert out.read_text() == GOLDEN.read_text()


def test_csv_goes_to_stdout_by_default(capsys):
    assert main(["cai", "--input", str(FIXTURES / "cai" / "assets.json"), *PINNED]) == 0
    rows = list(csv.DictReader(io.StringIO(capsys.readouterr().out)))
    assert len(rows) == 9
    assert {r["check"] for r in rows} == {"PUBLIC_SSH", "PUBLIC_RDP", "USER_MANAGED_SA_KEY"}


def test_golden_csv_has_the_documented_columns():
    with GOLDEN.open() as stream:
        assert next(csv.reader(stream)) == ["check", "severity", "project", "resource", "detail", "remediation"]


def test_readme_example_is_real_output():
    readme = (REPO / "README.md").read_text()
    example = readme.split("```csv\n", 1)[1].split("```", 1)[0].splitlines()
    golden = GOLDEN.read_text().splitlines()
    assert example[0] == golden[0]
    assert len(example) > 1 and set(example[1:]) <= set(golden[1:])


@pytest.mark.parametrize(("threshold", "code"), [("HIGH", 1), ("MEDIUM", 1), ("LOW", 1)])
def test_fail_on_threshold_met(threshold, code):
    argv = ["cai", "--input", str(FIXTURES / "cai" / "assets.json"), "--fail-on", threshold, "--out", "/dev/null"]
    assert main([*argv, *PINNED]) == code


def test_fail_on_threshold_not_met(tmp_path):
    clean = tmp_path / "assets.json"
    clean.write_text("[]")
    assert main(["cai", "--input", str(clean), "--fail-on", "LOW", "--out", str(tmp_path / "f.csv")]) == 0
    assert (tmp_path / "f.csv").read_text() == "check,severity,project,resource,detail,remediation\n"


def test_max_key_age_changes_severity(capsys):
    argv = ["cai", "--input", str(FIXTURES / "cai" / "assets.json"), "--max-key-age-days", "30", *PINNED]
    assert main(argv) == 0
    rows = list(csv.DictReader(io.StringIO(capsys.readouterr().out)))
    app_key = next(r for r in rows if "app-runtime" in r["resource"])
    assert app_key["severity"] == "HIGH"  # 32 days old, limit 30


def test_gcloud_failure_exits_2(capsys):
    from quick_audit.sources import SourceError

    def denied(args):
        raise SourceError("gcloud asset list --organization=1 failed: PERMISSION_DENIED")

    assert main(["cai", "--organization", "1"], runner=denied) == 2
    assert "PERMISSION_DENIED" in capsys.readouterr().err


def test_missing_input_file_exits_2(tmp_path, capsys):
    assert main(["cai", "--input", str(tmp_path / "nope.json")]) == 2
    assert "nope.json" in capsys.readouterr().err


def test_scope_is_required():
    with pytest.raises(SystemExit) as exc:
        main(["cai"])
    assert exc.value.code == 2


def test_only_one_scope_at_a_time():
    with pytest.raises(SystemExit) as exc:
        main(["cai", "--organization", "1", "--folder", "2"])
    assert exc.value.code == 2
