"""Offline checks for the BigQuery view and the sample queries (no BigQuery needed)."""

from __future__ import annotations

import json
import re

import pytest

from conftest import FIXTURES, REPO

VIEW_SQL = (REPO / "terraform" / "modules" / "scc-findings-export" / "sql" / "findings_view.sql.tftpl").read_text()
QUERIES = sorted((REPO / "queries").glob("*.sql"))
VIEW_QUERIES = [q for q in QUERIES if "FROM scc_findings.findings" in q.read_text()]
NOTIFICATIONS = json.loads((FIXTURES / "scc" / "notifications.json").read_text())

# JSON_VALUE(data, '$.finding.category') and JSON_QUERY_ARRAY(data, '$.resource.folders')
DATA_PATHS = re.findall(r"JSON_(?:VALUE|QUERY_ARRAY)\(data, '\$\.([\w.]+)'\)", VIEW_SQL)
# JSON_VALUE(folder, '$.resourceFolderDisplayName'), evaluated on each element of resource.folders
FOLDER_PATHS = re.findall(r"JSON_VALUE\(folder, '\$\.([\w.]+)'\)", VIEW_SQL)


def lookup(document: dict, dotted: str):
    value = document
    for part in dotted.split("."):
        if not isinstance(value, dict) or part not in value:
            return None
        value = value[part]
    return value


def test_view_reads_the_expected_fields():
    assert len(DATA_PATHS) >= 20
    assert {"finding.name", "finding.category", "finding.severity", "finding.state", "finding.eventTime"} <= set(DATA_PATHS)
    assert FOLDER_PATHS == ["resourceFolderDisplayName"]


@pytest.mark.parametrize("path", DATA_PATHS)
def test_view_path_exists_in_sample_notifications(path):
    # SCC leaves out empty fields, so a path only has to appear in at least one sample message.
    assert any(lookup(message, path) is not None for message in NOTIFICATIONS), f"$.{path} is in no sample message"


def test_folder_paths_exist_in_folder_elements():
    folders = [f for message in NOTIFICATIONS for f in lookup(message, "resource.folders") or []]
    assert folders
    for path in FOLDER_PATHS:
        assert all(path in folder for folder in folders)


def test_view_reads_the_templated_raw_table():
    assert "FROM `${raw_table}`" in VIEW_SQL


def test_sample_notifications_cover_a_state_change():
    states = {(m["finding"]["name"], m["finding"]["state"]) for m in NOTIFICATIONS}
    names = {name for name, _ in states}
    assert any({(n, "ACTIVE"), (n, "INACTIVE")} <= states for n in names)


def test_there_are_queries():
    assert len(QUERIES) >= 5


@pytest.mark.parametrize("query", QUERIES, ids=lambda p: p.name)
def test_query_filters_every_table_read_on_publish_time(query):
    sql = query.read_text()
    reads = len(re.findall(r"FROM scc_findings\.(?:findings|notifications_raw)\b", sql))
    filters = len(re.findall(r"publish_time >= TIMESTAMP_SUB\(CURRENT_TIMESTAMP\(\), INTERVAL \d+ DAY\)", sql))
    assert reads >= 1, "query must read the findings view or the raw table"
    assert filters >= reads, "every read must filter on the partition column"


@pytest.mark.parametrize("query", QUERIES, ids=lambda p: p.name)
def test_query_starts_with_a_comment(query):
    assert query.read_text().startswith("-- ")


@pytest.mark.parametrize("query", QUERIES, ids=lambda p: p.name)
def test_query_is_documented(query):
    assert f"]({query.name})" in (REPO / "queries" / "README.md").read_text()


TABLE_NAMES = {"scc_findings", "notifications_raw", "quick_audit"}


@pytest.mark.parametrize("query", VIEW_QUERIES, ids=lambda p: p.name)
def test_query_columns_exist_in_the_view(query):
    """Every snake_case identifier a query uses must be a view column, its own alias or a table name.

    Functions and keywords are upper case and the view columns are lower snake_case, so this catches
    typos such as project_displayname.
    """
    view_columns = set(re.findall(r"\bAS (\w+)", VIEW_SQL)) | {"publish_time", "message_id"}
    sql = "\n".join(line.split("--", 1)[0] for line in query.read_text().splitlines())  # drop comments
    sql = re.sub(r"r?'[^']*'", "''", sql)  # drop string literals and regexes
    own_aliases = set(re.findall(r"\bAS (\w+)", sql))
    used = set(re.findall(r"\b([a-z]+(?:_[a-z0-9]+)+)\b", sql)) - own_aliases - TABLE_NAMES
    assert used <= view_columns, f"unknown view columns: {sorted(used - view_columns)}"
