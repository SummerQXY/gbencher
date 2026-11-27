# gbench

`gbench` is a read-only Go CLI for CIS baseline assessments of explicitly selected Google Cloud projects and their GKE clusters. Rules are embedded in the binary. The CLI emits a versioned JSON report that can be consumed by another service; it does not provide a web interface, scan history, or automatic remediation.

## Safety and coverage

- Scans collect data through read-only Google Cloud CLI, REST, and optional `kubectl` operations. They do not create, change, or delete cloud resources. Review the selected rules and planned commands before scanning.
- A dry run only prints the plan. It does not call `gcloud`, `kubectl`, or REST endpoints.
- No report is saved unless `--output` is supplied. Reports, standard output, and diagnostic output can contain account names, resource identifiers, and evidence. Store and share them accordingly.
- Rule verification levels describe available evidence: `none`, `static`, `fixture`, or `live`. In the current embedded catalog, 4 of 93 GCP rules and 15 of 54 GKE rules are at `fixture`; the other 128 rules are `none`. The public fixture corpus contains handwritten and schema-derived inputs only; captured and captured-plus-mutated inputs are not distributed. Fixture execution does not establish complete branch coverage or live correctness, and these figures do not mean either benchmark has passed its full acceptance gate.

## Requirements

- Go 1.25.6 to build from source.
- Google Cloud CLI (`gcloud`) on `PATH` for live scans, authenticated as an identity with the read permissions required by the selected rules.
- `kubectl` on `PATH` only when enabling the optional `kubectl` capability for cluster checks. Cluster access and credentials must be configured for the selected project.
- macOS or Linux.

## Build from source

```sh
git clone https://github.com/SummerQXY/gbencher.git
cd gbencher
go build -o gbench ./cmd/gbench
./gbench version
```

`--quota-project` is optional. If supplied, the scan identity needs `serviceusage.services.use` on that project. If omitted, `gcloud` uses its configured quota project or SDK default; the report records the explicit quota project as `null` when none was supplied. Use a quota project only when its use is authorized.

## Build and offline checks

```sh
go build -o gbench ./cmd/gbench
./gbench version

# Offline rule and fixture checks
./gbench rules lint
./gbench rules test
```

The public `make verify` target runs build, vet, and race-enabled tests:

```sh
make verify
```

The private-identifier scan used in the development repository is not included in this public copy because its local patterns are private. The target runs fully offline.

## Dry run and scan

The following dry run uses a synthetic project ID and makes no cloud calls:

```sh
./gbench scan --project=example-synthetic-123 --dry-run --format=json
```

For an actual read-only scan, replace the synthetic ID with a project you are authorized to assess. The sample writes the canonical JSON report to `./report.json`:

```sh
./gbench scan \
  --project=example-synthetic-123 \
  --format=json \
  --output=./report.json
```

The live-scan example is intentionally nonfunctional unless that synthetic ID happens to be a real project accessible to your identity. Use an authorized project ID before running it. To request cluster checks that need `kubectl`, add `--enable=kubectl` and ensure the corresponding access is configured. To select a separate quota project, add `--quota-project=example-quota-456` only when authorized.

`--output` writes the JSON report with owner-only permissions, refuses to replace an existing file by default, and requires `--force` to overwrite it. Without `--output`, use `--format=json` to print the report to standard output.

## Reading results

The report has top-level `scan`, `summary`, `rule_summaries`, `results`, and `collectors` fields. `results` contains per-rule assessments and evidence; `collectors` records collection attempts. Validate a report with the `schemas/report.schema.json` shipped with the same gbench version.

- `scan.status` is `completed` when every unit was evaluated or not applicable. `completed_with_gaps` means at least one unit was `SKIPPED` or `ERROR`; check `scan.coverage` and individual results.
- Assessment statuses are `PASS`, `FAIL`, `REVIEW`, `NOT_APPLICABLE`, `SKIPPED`, and `ERROR`. `REVIEW` needs human review. `SKIPPED` and `ERROR` are gaps, not evidence of a passing configuration.
- The default `--fail-on=fail,error` can return exit code 1 while still producing a report. Exit code 4 means the scan ran but no unit was successfully evaluated; it also produces a report. See [docs/integration.md](docs/integration.md) for the full exit-code and report contract.

## Security

Treat reports and command output as sensitive operational data. Keep credentials out of profiles and source control, restrict report access and retention, and review the requested project, rules, and optional quota project before a live scan. gbench reports findings and remediation guidance but never applies fixes.

## License and project status

This project is an independent implementation. It is not affiliated with, endorsed by, or an official product of the Center for Internet Security (CIS). The project's original code is provided under Apache-2.0. That license does not grant rights to CIS Benchmark text or other third-party materials. Benchmark names identify the assessment coverage only.

See [LICENSE](LICENSE) for the Apache-2.0 terms.
