# CLI Reference

## `pledgerecon scan`

Scan a project for dependency vulnerabilities.

### Usage

```bash
pledgerecon scan [OPTIONS] [PATH]
```

### Arguments

| Argument | Default | Description |
|---|---|---|
| `PATH` | `.` | Project root directory to scan |

### Options

| Flag | Default | Description |
|---|---|---|
| `-f, --format <FORMAT>` | `text` | Output format: `text`, `json`, `sarif`, `markdown`, `html` |
| `-o, --output <PATH>` | stdout | Output file path |
| `--min-severity <SEV>` | `low` | Minimum severity: `low`, `medium`, `high`, `critical` |
| `--fail-on-findings` | false | Exit non-zero if actionable vulnerabilities found |
| `--no-reachability` | false | Disable AST-based reachability analysis |
| `--triage` | false | Enable LLM-powered triage |
| `--generate-sbom` | false | Generate SBOM alongside scan |
| `--sbom-format <FMT>` | `cyclonedx` | SBOM format: `spdx`, `cyclonedx` |
| `--sbom-path <PATH>` | `sbom.json` | SBOM output file path |
| `--wasm-rules` | false | Enable WASM custom rules |
| `--wasm-rule <PATH>` | — | Path to WASM rule file (repeatable) |
| `--offline` | false | Use cached advisory database only |
| `--github-token <TOKEN>` | — | GitHub API token for GHSA queries |
| `--incremental` | false | Only re-scan changed manifests (Goal 76) |
| `--monorepo` | false | Scan sub-projects independently (Goal 83) |
| `--progress` | false | Show progress bar (Goal 82) |
| `--timeout <SECS>` | 0 | Scan timeout in seconds, 0 = no timeout (Goal 81) |
| `--license-check` | false | Check dependency licenses against policy (Goal 87) |
| `--slsa-min-level <L>` | None | Minimum SLSA level: L1–L4 (Goal 88) |
| `--verify-signatures` | false | Verify sigstore/cosign signatures (Goal 89) |
| `--check-pinning` | false | Enforce dependency pinning (Goal 92) |
| `--air-gapped` | false | Air-gapped mode with pre-bundled advisories (Goal 94) |
| `--vex` | false | Generate VEX document alongside scan (Goal 91) |
| `-v, --verbose` | false | Enable debug logging |

### Examples

```bash
# Basic scan (text output to terminal)
pledgerecon scan .

# JSON output to file
pledgerecon scan . --format json --output report.json

# SARIF for GitHub code scanning
pledgerecon scan . --format sarif --output pledgerecon.sarif

# CI mode — fail on high+ severity
pledgerecon scan . --fail-on-findings --min-severity high

# Full pipeline — scan + triage + SBOM
pledgerecon scan . --triage --generate-sbom --sbom-format cyclonedx

# Offline scan with cached advisories
pledgerecon scan . --offline

# With WASM custom rules
pledgerecon scan . --wasm-rules --wasm-rule ./rules/banned.wasm

# Markdown for PR comment
pledgerecon scan . --format markdown --output pr-comment.md
```

---

## `pledgerecon sbom`

Generate an SBOM for a project.

### Usage

```bash
pledgerecon sbom [OPTIONS] [PATH]
```

### Arguments

| Argument | Default | Description |
|---|---|---|
| `PATH` | `.` | Project root directory |

### Options

| Flag | Default | Description |
|---|---|---|
| `-f, --format <FORMAT>` | `cyclonedx` | SBOM format: `spdx`, `cyclonedx` |
| `-o, --output <PATH>` | `sbom.json` | Output file path |

### Examples

```bash
# CycloneDX SBOM (default)
pledgerecon sbom . --output sbom.json

# SPDX SBOM
pledgerecon sbom . --format spdx --output sbom.spdx.json
```

---

## `pledgerecon init`

Initialize a `pledgerecon.toml` configuration file.

### Usage

```bash
pledgerecon init [PATH]
```

### Arguments

| Argument | Default | Description |
|---|---|---|
| `PATH` | `.` | Project root directory |

### Example

```bash
pledgerecon init .
# → Created pledgerecon.toml
```

---

## `pledgerecon list`

List all dependencies in a project without scanning for vulnerabilities.

### Usage

```bash
pledgerecon list [OPTIONS] [PATH]
```

### Arguments

| Argument | Default | Description |
|---|---|---|
| `PATH` | `.` | Project root directory |

### Options

| Flag | Default | Description |
|---|---|---|
| `-f, --format <FORMAT>` | `text` | Output format: `text`, `json` |

### Example

```bash
# Text output
pledgerecon list .
# Dependencies (15 total, 8 direct):
#   🦀 serde@1.0 (direct)
#   🦀 tokio@1.40 (direct)
#   📦 lodash@4.17.11 (direct)
#   ...

# JSON output
pledgerecon list . --format json
```

---

## `pledgerecon ci`

Generate CI/CD pipeline templates.

### Usage

```bash
pledgerecon ci [OPTIONS]
```

### Options

| Flag | Default | Description |
|---|---|---|
| `-p, --platform <PLATFORM>` | `github` | CI platform: `github`, `gitlab` |

### Examples

```bash
# GitHub Actions template
pledgerecon ci --platform github

# GitLab CI template
pledgerecon ci --platform gitlab
```

---

## `pledgerecon sbom-diff` (Goal 90)

Compare two SBOMs to show added/removed/changed components.

### Usage

```bash
pledgerecon sbom-diff <OLD_SBOM> <NEW_SBOM> [OPTIONS]
```

### Options

| Flag | Default | Description |
|---|---|---|
| `-o, --output <PATH>` | stdout | Output file path |
| `-f, --format <FORMAT>` | `text` | Output format: `text`, `json` |

### Example

```bash
# Compare two SBOMs
pledgerecon sbom-diff sbom-v1.json sbom-v2.json
```

---

## `pledgerecon vex` (Goal 91)

Generate a VEX (Vulnerability Exploitability eXchange) document from a scan report.

### Usage

```bash
pledgerecon vex <REPORT_JSON> [OPTIONS]
```

### Options

| Flag | Default | Description |
|---|---|---|
| `-o, --output <PATH>` | `vex.json` | Output file path |

### Example

```bash
# Generate VEX from a scan report
pledgerecon vex report.json --output vex.json
```

---

## `pledgerecon serve` (Goal 96)

Start a long-running REST API server for programmatic scan access.

### Usage

```bash
pledgerecon serve [OPTIONS]
```

### Options

| Flag | Default | Description |
|---|---|---|
| `--host <HOST>` | `127.0.0.1` | Bind address |
| `--port <PORT>` | `8080` | Listen port |
| `--auth-token <TOKEN>` | — | Bearer token for API authentication |

### Example

```bash
# Start API server on port 8080
pledgerecon serve --port 8080

# With authentication
pledgerecon serve --auth-token secret
```

---

## Global Options

| Flag | Description |
|---|---|
| `-v, --verbose` | Enable debug-level logging (applies to all commands) |
| `-h, --help` | Print help |
| `-V, --version` | Print version |

## Exit Codes

| Code | Meaning |
|---|---|
| 0 | Success — no actionable vulnerabilities |
| 1 | Vulnerabilities found at or above severity threshold |
| 2 | Scan error (I/O, parsing, etc.) |
| 3 | Advisory database unavailable (no network + no cache) |
