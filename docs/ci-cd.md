# CI/CD Integration

PledgeRecon is designed to be CI-native — it returns appropriate exit codes, generates SARIF for GitHub code scanning, and provides templates for common CI platforms.

## Exit Codes

| Code | Meaning | When |
|---|---|---|
| `0` | Success | No actionable vulnerabilities found |
| `1` | Vulnerabilities found | Findings at or above severity threshold that are reachable and not false positives |
| `2` | Scan error | Internal error during scan (I/O, parsing, etc.) |
| `3` | Database error | Advisory database could not be fetched and no cache available |

### CI Gating Logic

A finding blocks CI if ALL of the following are true:
1. Severity ≥ configured `min_severity` threshold
2. Reachability is NOT `Unreachable` (unless `--fail-on-unreachable` is set)
3. Triage status is NOT `FalsePositive`

```bash
# Fail on high+ severity, don't block on unreachable findings
pledgerecon scan . --fail-on-findings --min-severity high

# Fail on medium+ severity, block even on unreachable findings
pledgerecon scan . --fail-on-findings --min-severity medium
```

## GitHub Actions

### Workflow Template

Generate with:
```bash
pledgerecon ci --platform github
```

```yaml
name: PledgeRecon Security Scan

on:
  push:
    branches: [main, master]
  pull_request:
    branches: [main, master]

jobs:
  pledgerecon:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install PledgeRecon
        run: |
          curl -L https://github.com/pledgeandgrow/pledgerecon/releases/latest/download/pledgerecon-linux-amd64 -o /usr/local/bin/pledgerecon
          chmod +x /usr/local/bin/pledgerecon

      - name: Run vulnerability scan
        run: pledgerecon scan . --fail-on-findings --min-severity high --format sarif --output pledgerecon.sarif

      - name: Upload SARIF results
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: pledgerecon.sarif

      - name: Generate SBOM
        run: pledgerecon sbom . --format cyclonedx --output sbom.json

      - uses: actions/upload-artifact@v4
        with:
          name: sbom
          path: sbom.json
```

### GitHub Step Summary

PledgeRecon can generate a GitHub Actions step summary:

```bash
pledgerecon scan . --format markdown >> $GITHUB_STEP_SUMMARY
```

### PR Comments

The `github_pr_comment()` function generates a compact markdown table suitable for PR comments:

```markdown
## 🔍 PledgeRecon Vulnerability Scan

⚠️ Found **3 actionable vulnerability(ies)** out of 5 total findings.

| Severity | Package | Advisory | Reachable | Fix |
|---|---|---|---|---|
| 🟠 High | `npm:lodash@4.17.11` | CVE-2021-23337 | 🔴 Yes | 4.17.21 |
| 🟡 Medium | `npm:express@4.17.0` | CVE-2022-24999 | 🔴 Yes | 4.17.3 |
| 🔵 Low | `npm:axios@0.21.0` | CVE-2021-3749 | ⚪ ? | 0.21.1 |

_Run `pledgerecon scan . --format markdown` for full details._
```

## GitLab CI

### Job Template

Generate with:
```bash
pledgerecon ci --platform gitlab
```

```yaml
pledgerecon:scan:
  stage: test
  image:
    name: ghcr.io/pledgeandgrow/pledgerecon:latest
    entrypoint: [""]
  script:
    - pledgerecon scan . --fail-on-findings --min-severity high --format json --output pledgerecon-report.json
    - pledgerecon sbom . --format cyclonedx --output sbom.json
  artifacts:
    reports:
      codequality: pledgerecon-report.json
    paths:
      - sbom.json
  allow_failure: false
```

### GitLab Code Quality

PledgeRecon can output GitLab Code Quality JSON format for integration with GitLab's vulnerability management:

```bash
pledgerecon scan . --format json --output pledgerecon-report.json
```

## Jenkins

```groovy
pipeline {
    agent any
    stages {
        stage('Security Scan') {
            steps {
                sh 'pledgerecon scan . --fail-on-findings --min-severity high --format json --output pledgerecon-report.json'
            }
            post {
                always {
                    archiveArtifacts artifacts: 'pledgerecon-report.json', fingerprint: true
                    publishHTML(target: [
                        reportDir: '.',
                        reportFiles: 'pledgerecon-report.json',
                        reportName: 'PledgeRecon Security Report'
                    ])
                }
            }
        }
    }
}
```

## Azure DevOps

```yaml
trigger:
  branches:
    include: [main, master]

pool:
  vmImage: 'ubuntu-latest'

steps:
  - script: |
      curl -L https://github.com/pledgeandgrow/pledgerecon/releases/latest/download/pledgerecon-linux-amd64 -o /usr/local/bin/pledgerecon
      chmod +x /usr/local/bin/pledgerecon
    displayName: 'Install PledgeRecon'

  - script: pledgerecon scan . --fail-on-findings --min-severity high --format sarif --output pledgerecon.sarif
    displayName: 'Run vulnerability scan'

  - task: PublishBuildArtifacts@1
    inputs:
      pathToPublish: 'pledgerecon.sarif'
      artifactName: 'SARIF Report'
```

## SARIF Output

PledgeRecon generates SARIF 2.1.0 output compatible with:
- GitHub code scanning
- Azure DevOps
- SonarQube
- Fortify

```bash
pledgerecon scan . --format sarif --output pledgerecon.sarif
```

The SARIF output includes:
- Tool information (name, version, information URI)
- Rules (one per advisory ID with description and tags)
- Results (one per finding with location, severity, properties)
- Reachability as `precision` (high=reachable, low=unreachable, medium=unknown)

## Best Practices

1. **Use `--fail-on-findings`** in CI to block merges on new vulnerabilities
2. **Set `--min-severity high`** to avoid noise from low-severity findings
3. **Use `--format sarif`** for GitHub integration
4. **Generate SBOM** on every build for compliance
5. **Use `--offline`** in CI with a pre-populated cache for reproducible scans
6. **Enable triage** for projects with many transitive dependencies
7. **Use ignore rules** with expiry dates for accepted risks
8. **Use `--incremental`** (Goal 76) for faster re-scans in PR pipelines
9. **Use `--monorepo`** (Goal 83) for multi-package repositories
10. **Use `--progress`** (Goal 82) for local development visibility
11. **Use `--timeout`** (Goal 81) to prevent hung scans in CI
12. **Use `--vex`** (Goal 91) to communicate exploitability to downstream consumers
13. **Configure webhooks** (Goal 99) for real-time vulnerability alerts

## Docker (Goal 84)

PledgeRecon provides an official Docker image for CI/CD pipelines:

```bash
# Pull and scan
docker run --rm -v $(pwd):/repo ghcr.io/pledgeandgrow/pledgerecon scan /repo

# With SBOM generation
docker run --rm -v $(pwd):/repo ghcr.io/pledgeandgrow/pledgerecon scan /repo --generate-sbom

# Offline scan with pre-populated cache
docker run --rm -v $(pwd):/repo -v pledgerecon-cache:/cache ghcr.io/pledgeandgrow/pledgerecon scan /repo --offline
```

The Dockerfile uses a multi-stage build (`rust:1.85-bookworm` builder → `debian:bookworm-slim` runtime) for minimal image size. The cache directory is exposed as a volume at `/cache`.

## Monorepo Support (Goal 83)

For monorepos with multiple sub-projects, PledgeRecon can discover and scan each independently:

```bash
# Auto-discover sub-projects and scan each
pledgerecon scan . --monorepo
```

PledgeRecon walks the directory tree (max depth 3) looking for manifest files (`Cargo.toml`, `package.json`, `go.mod`, `requirements.txt`, etc.) and treats each directory containing a manifest as a separate sub-project.

## Webhook Integration (Goal 99)

Configure webhooks to receive real-time notifications on scan events:

```toml
# pledgerecon.toml
[[webhook]]
url = "https://example.com/webhook"
events = ["scan.completed", "vulnerability.new", "vulnerability.critical"]
secret = "whsec-..."
```

Supported events:
- `scan.completed` — fired when a scan finishes
- `vulnerability.new` — fired for each new vulnerability found
- `vulnerability.critical` — fired for each critical-severity finding
