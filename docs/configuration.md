# Configuration Reference

PledgeRecon is configured via a `pledgerecon.toml` file in the project root. Command-line flags override config file values.

## Initialization

```bash
pledgerecon init
```

Creates a `pledgerecon.toml` with default values.

## Full Reference

```toml
# ─── Advisory Sources ──────────────────────────────────────
# Sources to query for vulnerability advisories.
# Default: OSV + GHSA

[[advisory_sources]]
# type = "osv"    # OSV.dev (Google)
# type = "ghsa"   # GitHub Security Advisories
# type = "nvd"    # NVD (planned)

# Local advisory database:
# [[advisory_sources]]
# type = "local"
# path = "./internal-advisories.json"

# ─── Scan Settings ─────────────────────────────────────────

# Minimum severity to report.
# Findings below this severity are filtered out.
# Options: "low", "medium", "high", "critical", "info"
# Default: "low"
min_severity = "low"

# Enable AST-based reachability analysis.
# When true, PledgeRecon builds a call graph and checks
# if vulnerable functions are reachable from entry points.
# Default: true
reachability = true

# ─── Triage ────────────────────────────────────────────────

# Enable LLM-powered false positive reduction.
# Default: false
triage = false

# LLM provider configuration.
[triage_config]
# Provider: "openai", "anthropic", "ollama", "llamacpp", "local", or custom
provider = "openai"

# API key (or set via environment variable).
# For Ollama/llama.cpp, no API key is needed.
api_key = "sk-..."

# Model name.
model = "gpt-4o-mini"

# Custom endpoint (for self-hosted models).
# endpoint = "http://localhost:11434/api/generate"

# Maximum tokens for triage response.
# Default: 1024
max_tokens = 1024

# Batch size — number of findings per LLM call (Goal 36).
# Default: 5
batch_size = 5

# Stream LLM responses via SSE (Goal 38).
# Default: false
# stream = false

# llama.cpp model path (Goal 39).
# llamacpp_model_path = "/path/to/ggml-model.bin"

# Fine-tuned model path (Goal 40).
# fine_tuned_model_path = "/path/to/fine-tuned-model"

# Custom prompt template with {placeholder} variables (Goal 41).
# prompt_template = "Analyze {advisory_id} for {package}@{version}"

# Confidence threshold for auto-suppressing false positives (Goal 42).
# Default: 0.8
# confidence_threshold = 0.8

# Consensus models — query multiple LLMs and majority vote (Goal 43).
# consensus_models = ["anthropic:claude-sonnet-4-20250514", "ollama:llama3"]

# Audit logging — log all LLM calls (Goal 44).
# audit_log = true
# audit_log_path = ".pledgerecon/audit.jsonl"

# Cost tracking — track token usage and cost (Goal 45).
# cost_tracking = true
# cost_per_input_token = 0.00001   # $0.01/1M tokens
# cost_per_output_token = 0.00003  # $0.03/1M tokens

# Response caching — avoid redundant LLM calls (Goal 37).
# enable_cache = true
# cache_dir = ".pledgerecon/triage-cache"

# ─── SBOM ──────────────────────────────────────────────────

# Generate an SBOM alongside the scan.
# Default: false
generate_sbom = false

# SBOM format: "spdx" or "cyclonedx".
# Default: "cyclonedx"
sbom_format = "cyclonedx"

# SBOM output file path.
# Default: "sbom.json"
sbom_path = "sbom.json"

# ─── Ignore Rules ──────────────────────────────────────────
# Suppress findings matching specific criteria.

[[ignore]]
# Ignore by package name (e.g. "npm:lodash").
package = "npm:lodash"
# Ignore by advisory ID (e.g. "CVE-2021-23337").
# advisory_id = "CVE-2021-23337"
# Reason for ignoring (for audit trail).
reason = "Reviewed and accepted — template() not called in production code"
# Expiry date (ISO 8601). After this date, the ignore is no longer applied.
# expires = "2025-12-31"

# ─── Output ────────────────────────────────────────────────

# Output format: "text", "json", "sarif", "markdown", "html".
# Default: "text"
output_format = "text"

# Output file path (stdout if not specified).
# output_path = "report.json"

# ─── CI/CD ─────────────────────────────────────────────────

# Fail with non-zero exit code if actionable vulnerabilities are found.
# Default: false
fail_on_findings = false

# ─── Notifications (Goals 63–65) ───────────────────────────

# Slack webhook URL for post-scan notifications (Goal 63).
# slack_webhook_url = "https://hooks.slack.com/services/T000/B000/XXX"

# Microsoft Teams webhook URL for post-scan notifications (Goal 64).
# teams_webhook_url = "https://outlook.office.com/webhook/..."

# SMTP host for email reports (Goal 65).
# smtp_host = "smtp.gmail.com"
# smtp_port = 587
# smtp_username = "alerts@example.com"
# smtp_password = "app-password"
# email_from = "pledgerecon@example.com"
# email_to = ["security@example.com", "devops@example.com"]

# ─── Baseline & Auto-Fix (Goals 72–73) ─────────────────────

# Path to baseline file for baseline comparison (Goal 73).
# When set, scan will fail only on new vulnerabilities not in baseline.
# baseline_path = "pledgerecon-baseline.json"

# Fail only on new vulnerabilities not in baseline (Goal 73).
# Default: false
# fail_on_new_only = false

# Generate auto-fix suggestions for fixable vulnerabilities (Goal 72).
# Default: false
# generate_autofix = false

# Path for trend history file (Goal 59).
# trend_path = "pledgerecon-trend.json"

# ─── WASM Rules ────────────────────────────────────────────

# Enable WASM custom rules.
# Default: false
wasm_rules = false

# Path(s) to WASM rule files.
# wasm_rule_paths = ["rules/unsafe_config.wasm"]

# WASM plugin configuration (Goals 46–55).
[wasm_plugin_config]
# Fuel limit for WASM execution (Goal 46). 0 = unlimited.
# Default: 1000000000 (1 billion instructions)
# fuel_limit = 1000000000

# Enable plugin signature verification (Goal 49).
# verify_signatures = false
# signature_public_key = "/path/to/public-key.pem"

# Plugin permissions (Goal 50).
# permissions = ["ReadManifests", "ReadSource"]

# Hot-reload plugins without restarting scan (Goal 51).
# hot_reload = false

# Run plugins in parallel (Goal 52).
# Default: true
# parallel = true

# Plugin registry URL for discovering and installing plugins (Goal 48).
# registry_url = "https://registry.pledgerecon.dev/plugins.json"

# ─── Network ───────────────────────────────────────────────

# GitHub API token for GHSA queries (increases rate limit).
# github_token = "ghp_..."

# Use cached advisory database only (no network requests).
# Default: true
offline = true

# ─── Performance ───────────────────────────────────────────

# Cache directory for advisory database.
# Default: ".pledgerecon-cache"
cache_dir = ".pledgerecon-cache"

# Maximum number of concurrent scans.
# Default: 8
concurrency = 8

# ─── Performance & Scale (Goals 76–85) ─────────────────────

# Enable incremental scanning — only re-scan changed manifests (Goal 76).
# Default: false
# incremental = false

# Parallel advisory fetching concurrency limit (Goal 77).
# Default: 8
# advisory_fetch_concurrency = 8

# Advisory store path — persistent on-disk advisory database (Goal 78).
# advisory_store_path = ".pledgerecon-cache/advisory-store.json"

# Memory-mapped file threshold in bytes (Goal 79).
# Files larger than this are read via memmap2.
# Default: 1048576 (1 MB)
# mmap_threshold = 1048576

# Glob-based source file filtering (Goal 80).
# [source_filter]
# include = ["src/**/*.rs", "src/**/*.ts"]
# exclude = ["node_modules/**", "target/**", "dist/**"]

# Scan timeout configuration in seconds (Goal 81).
# 0 = no timeout.
# [timeout]
# scan_timeout_secs = 0
# fetch_timeout_secs = 120
# reachability_timeout_secs = 300

# Enable progress reporting (Goal 82).
# Default: true in TTY, false otherwise
# progress = true

# Enable monorepo support — scan sub-projects independently (Goal 83).
# Default: false
# monorepo = false

# ─── Enterprise (Goals 87–99) ──────────────────────────────

# License compliance policy (Goal 87).
# [license_policy]
# allowed = ["MIT", "Apache-2.0", "BSD-3-Clause", "ISC"]
# denied = ["GPL-3.0", "AGPL-3.0"]
# warn = ["MPL-2.0", "LGPL-3.0"]

# SLSA provenance verification (Goal 88).
# Minimum SLSA level required for dependencies.
# slsa_min_level = "L3"  # Options: "None", "L1", "L2", "L3", "L4"

# Sigstore/cosign signature verification (Goal 89).
# [signature_verification]
# enabled = false
# cosign_path = "cosign"
# identity = "https://github.com/pledgeandgrow/.github/.github/workflows/release.yml@refs/heads/main"
# oidc_issuer = "https://token.actions.githubusercontent.com"

# Dependency pinning enforcement (Goal 92).
# [pinning]
# enforce = false
# deny_floating = true   # Flag ^ and ~ versions
# deny_wildcard = true   # Flag * versions
# deny_range = false     # Flag >=, >, < versions

# Registry mirroring (Goal 93).
# [registry_mirror]
# npm_registry = "https://artifactory.example.com/api/npm/npm-virtual"
# crates_registry = "https://artifactory.example.com/api/cargo/crates-virtual"
# pypi_index = "https://nexus.example.com/repository/pypi-proxy/simple"
# pypi_extra_index = "https://nexus.example.com/repository/pypi-internal/simple"

# Air-gapped mode (Goal 94).
# [air_gapped]
# enabled = false
# advisory_bundle_path = ".pledgerecon-cache/advisory-bundle.json"
# verify_bundle = true

# Multi-tenant scan profiles (Goal 95).
# [[scan_profile]]
# name = "frontend"
# path_pattern = "packages/frontend/**"
# min_severity = "medium"
# reachability = true
# [[scan_profile]]
# name = "backend"
# path_pattern = "packages/backend/**"
# min_severity = "high"
# reachability = true

# REST API server (Goal 96).
# [rest_api]
# enabled = false
# host = "127.0.0.1"
# port = 8080
# auth_token = "secret-token"

# GraphQL API (Goal 97).
# [graphql]
# enabled = false
# path = "/graphql"

# Web UI dashboard (Goal 98).
# [web_ui]
# enabled = false
# path = "/dashboard"

# Webhook integration (Goal 99).
# [[webhook]]
# url = "https://example.com/webhook"
# events = ["scan.completed", "vulnerability.new", "vulnerability.critical"]
# secret = "whsec-..."
```

## Environment Variables

| Variable | Description | Used By |
|---|---|---|
| `GITHUB_TOKEN` | GitHub API token for GHSA queries | Advisory fetching |
| `OPENAI_API_KEY` | OpenAI API key for triage | LLM triage |
| `ANTHROPIC_API_KEY` | Anthropic API key for triage | LLM triage |
| `SLACK_WEBHOOK_URL` | Slack webhook URL for notifications | Notifications (Goal 63) |
| `TEAMS_WEBHOOK_URL` | Teams webhook URL for notifications | Notifications (Goal 64) |
| `PLEDGERECON_CACHE_DIR` | Cache directory for advisory database | Advisory cache |
| `PLEDGERECON_ADVISORY_STORE` | Path to persistent advisory store | Advisory store (Goal 78) |
| `PLEDGERECON_AIR_GAPPED` | Enable air-gapped mode (1/0) | Air-gapped mode (Goal 94) |
| `PLEDGERECON_API_TOKEN` | REST API auth token | REST API (Goal 96) |
| `PLEDGERECON_COSIGN_PATH` | Path to cosign binary | Sigstore verification (Goal 89) |

## Ignore Rules

Ignore rules suppress findings to reduce noise. Each rule can match by:
- **Package name**: `npm:lodash`, `crates:serde`, `pypi:django`
- **Advisory ID**: `CVE-2021-23337`, `GHSA-35jh-r3h4-6jhm`
- **Both**: More specific — only ignores the specific advisory for the specific package

### Expiry

Ignore rules can have an expiry date. After the expiry, the rule is automatically ignored:

```toml
[[ignore]]
package = "npm:lodash"
advisory_id = "CVE-2021-23337"
reason = "Accepted risk — upgrading in Q1 2025"
expires = "2025-03-31"
```

### Audit Trail

The `reason` field is included in scan reports, providing an audit trail for compliance:

```
Finding: CVE-2021-23337 in npm:lodash@4.17.11
  Status: Ignored
  Reason: "Accepted risk — upgrading in Q1 2025"
  Expires: 2025-03-31
```

## Precedence

Configuration values are resolved in this order (highest priority first):

1. Command-line flags (`--min-severity high`)
2. `pledgerecon.toml` file values
3. Default values
