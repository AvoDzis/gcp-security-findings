"""CSV output."""

from __future__ import annotations

import csv
from collections import Counter
from collections.abc import Iterable
from typing import TextIO

from quick_audit.models import CSV_COLUMNS, Finding, Severity


def write_csv(findings: Iterable[Finding], stream: TextIO) -> None:
    writer = csv.writer(stream, lineterminator="\n")
    writer.writerow(CSV_COLUMNS)
    for f in findings:
        writer.writerow([f.check, f.severity.name, f.project, f.resource, f.detail, f.remediation])


def summary(findings: list[Finding]) -> str:
    """e.g. '6 findings (4 HIGH, 1 MEDIUM, 1 LOW)'."""
    counts = Counter(f.severity for f in findings)
    parts = [f"{counts[s]} {s.name}" for s in sorted(Severity, reverse=True) if counts[s]]
    noun = "finding" if len(findings) == 1 else "findings"
    return f"{len(findings)} {noun}" + (f" ({', '.join(parts)})" if parts else "")
