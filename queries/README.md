# Sample queries

GoogleSQL for the dataset the Terraform module creates (default name `scc_findings`). They read the
`findings` view, except `06`, which reads the raw table. If you renamed the dataset, change the
`scc_findings.` prefix.

| File | Answers | Window |
|---|---|---|
| [01_open_findings_by_severity.sql](01_open_findings_by_severity.sql) | How many findings are open right now, by severity and category, and across how many projects? | 30 days |
| [02_new_high_findings_7d.sql](02_new_high_findings_7d.sql) | Which CRITICAL/HIGH findings appeared this week, where, and what are the next steps? | 7 days |
| [03_top_projects.sql](03_top_projects.sql) | Which 20 projects carry the most open CRITICAL/HIGH findings? | 30 days |
| [04_time_to_resolve.sql](04_time_to_resolve.sql) | How long do findings stay open before they go INACTIVE (mean, median, p90), by severity? | 90 days |
| [05_ssh_rdp_and_sa_keys.sql](05_ssh_rdp_and_sa_keys.sql) | What does SCC report for the risks quick-audit checks (open SSH/RDP, user-managed keys)? | 30 days |
| [06_ingestion_health.sql](06_ingestion_health.sql) | Is the pipeline delivering? Notifications and duplicates per day. | 14 days |
| [07_audit_vs_scc.sql](07_audit_vs_scc.sql) | Which public SSH/RDP rules does quick-audit flag that SCC does not, and the other way round? | 30 days |

## Running them

```sh
# Uses your gcloud default project; add --project_id=<project> to target another.
bq query --use_legacy_sql=false < queries/01_open_findings_by_severity.sql
```

Or paste a file into the BigQuery console.

## Things every query does

- **Filter on `publish_time`.** The raw table is partitioned by day on `publish_time` and has
  `require_partition_filter = true`, so a query without that filter fails rather than scanning the
  whole table. The filter goes through the view to the table.
- **Take the latest notification per finding.** SCC publishes a notification every time a matching
  finding is created or updated, so one finding has several rows. The queries keep the newest one:
  `QUALIFY ROW_NUMBER() OVER (PARTITION BY finding_name ORDER BY event_time DESC, publish_time DESC) = 1`.
  `WHERE` runs before `QUALIFY`, so the partition filter still prunes.
- **Skip muted findings** with `IFNULL(mute, '') != 'MUTED'`.

"Latest state" only covers findings that had at least one notification inside the window. A finding
that has not changed for longer than the window does not show up; widen the interval for those, or
materialize a state table with a scheduled query.

## Loading quick-audit output for 07

```sh
quick-audit cai --organization 100000000001 --out findings.csv
bq load --source_format=CSV --skip_leading_rows=1 --replace \
  scc_findings.quick_audit findings.csv \
  check:STRING,severity:STRING,project:STRING,resource:STRING,detail:STRING,remediation:STRING
bq query --use_legacy_sql=false < queries/07_audit_vs_scc.sql
```

`07` matches on project ID and firewall rule name, not on the full resource name: SCC can name a
firewall by its numeric ID while quick-audit uses the rule name.

## What is tested

`tests/test_queries.py` checks, offline, that every JSON path the view reads exists in the sample
SCC notifications under `tests/fixtures/scc/`, that every query here filters on `publish_time` and
starts with a comment saying what it answers, and that this page lists every `.sql` file. The SQL has
not been run against a live BigQuery dataset.
