# PledgeRecon

**Rust-native dependency vulnerability scanner — a Snyk/Dependabot/Trivy alternative.**

[![CI](https://github.com/pledgeandgrow/pledgerecon/actions/workflows/ci.yml/badge.svg)](https://github.com/pledgeandgrow/pledgerecon/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## Quick Start

```bash
# Build from source
cargo install --path crates/pledgerecon-cli

# Scan your project
pledgerecon scan .

# Generate an SBOM
pledgerecon sbom . --format cyclonedx --output sbom.json

# Scan with CI gating (fail on high+ severity)
pledgerecon scan . --fail-on-findings --min-severity high --format sarif --output pledgerecon.sarif

# Initialize config
pledgerecon init
```

---

## Why PledgeRecon?

| Feature | PledgeRecon | Snyk | Dependabot | Trivy | Grype |
|---|:---:|:---:|:---:|:---:|:---:|
| **Language** | Rust | SaaS | Ruby | Go | Go |
| **AST reachability** | ✅ | ✅ | ❌ | ❌ | ❌ |
| **Taint analysis** | ✅ | ✅ | ❌ | ❌ | ❌ |
| **Interprocedural analysis** | ✅ | ❌ | ❌ | ❌ | ❌ |
| **Container scanning** | ✅ | ✅ | ❌ | ✅ | ✅ |
| **IaC scanning** | ✅ | ✅ | ❌ | ✅ | ❌ |
| **Secret scanning** | ✅ | ✅ | ❌ | ✅ | ❌ |
| **Entropy-based detection** | ✅ | ❌ | ❌ | ❌ | ❌ |
| **Git history scanning** | ✅ | ❌ | ❌ | ❌ | ❌ |
| **Secret rotation guidance** | ✅ | ❌ | ❌ | ❌ | ❌ |
| **WASM custom rules** | ✅ | ❌ | ❌ | ❌ | ❌ |
| **LLM triage** | ✅ | ❌ | ❌ | ❌ | ❌ |
| **Local LLM (Ollama)** | ✅ | ❌ | ❌ | ❌ | ❌ |
| **AI remediation** | ✅ | ✅ | ❌ | ❌ | ❌ |
| **RAG knowledge base** | ✅ | ❌ | ❌ | ❌ | ❌ |
| **SBOM (SPDX + CycloneDX)** | ✅ | ✅ | ❌ | ✅ | ✅ |
| **VEX support** | ✅ | ✅ | ❌ | ❌ | ✅ |
| **Self-hosted** | ✅ | ❌ | ❌ | ✅ | ✅ |
| **Multi-ecosystem** | ✅ | ✅ | ✅ | ✅ | ✅ |
| **CI-native exit codes** | ✅ | ✅ | ✅ | ✅ | ✅ |
| **SARIF output** | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Offline mode** | ✅ | ❌ | ❌ | ✅ | ✅ |
| **EPSS + KEV** | ✅ | ❌ | ❌ | ❌ | ✅ |
| **Issue tracker sync** | ✅ | ✅ | ❌ | ❌ | ❌ |
| **Distributed scanning** | ✅ | ❌ | ❌ | ❌ | ❌ |
| **Speed** | ★★★★★ | ★★☆☆☆ | ★★★☆☆ | ★★★★☆ | ★★★★☆ |

### The AST Reachability Differentiator

Most vulnerability scanners (Trivy, Grype, Dependabot) only check if a package version matches an advisory's affected range. This produces **high false positive rates** — a vulnerable function may exist in a dependency but never be called.

Snyk offers reachability analysis via their DeepCode AI engine, but it requires a SaaS account and sends code metadata to their servers. PledgeRecon builds a **call graph** entirely locally using tree-sitter, with interprocedural analysis across files and taint tracking for JS/TS/Python/Rust:

```
❌ Trivy: "lodash@4.17.11 is vulnerable to CVE-2021-23337" (false positive — template() never called)

✅ PledgeRecon: "lodash@4.17.11 is vulnerable to CVE-2021-23337 [UNREACHABLE — template() not called]"
```

### Competitive Positioning

| Competitor | What they do well | Where PledgeRecon wins |
|---|---|---|
| **Snyk** | AI remediation (Agent Fix), SAST + DAST, broad ecosystem coverage, polished UX | Self-hosted (no SaaS dependency), offline mode, local LLM triage via Ollama, WASM custom rules, distributed scanning, RAG knowledge base, secret rotation guidance, no per-seat pricing |
| **Trivy** | Fast container scanning, IaC misconfig detection, secret scanning with custom rules, Kubernetes cluster scanning | AST reachability, taint analysis, LLM triage, AI remediation, EPSS + KEV, issue tracker sync, interprocedural analysis, entropy-based secret detection, git history scanning |
| **Grype** | EPSS + KEV risk scoring, VEX support, fast DB (schema v6), broad OS package coverage, SBOM ingestion | AST reachability, taint analysis, IaC scanning, secret scanning, LLM triage, AI remediation, WASM custom rules, distributed scanning, issue tracker sync |
| **Dependabot** | Native GitHub integration, automated PRs, zero-config | Everything except multi-ecosystem and SARIF — reachability, taint analysis, container/IaC/secret scanning, LLM triage, SBOM, offline mode, custom rules |

**Key differentiators PledgeRecon uniquely offers:**
- **Local LLM triage** — no other scanner supports Ollama for fully offline AI-powered false positive reduction
- **WASM custom rules** — extensible sandboxed rule engine (no competitor offers this)
- **Distributed scanning** — partition scans across workers for monorepo scale
- **RAG knowledge base** — query vulnerability history and remediation patterns
- **Interprocedural analysis** — whole-program call graph across files (Snyk's reachability is per-file)
- **Entropy-based secret detection** — Shannon entropy for unknown secret formats
- **Git history secret scanning** — scan commit history for leaked secrets
- **Secret rotation guidance** — actionable remediation steps per secret type

---

## Features

### Core Scanning
- **Multi-ecosystem support**: Rust (Cargo.toml), Node.js (package.json), Python (requirements.txt, pyproject.toml), Go (go.mod), Dart (pubspec.yaml), and more
- **Advisory databases**: OSV.dev, GitHub Security Advisories (GHSA), NVD, local databases
- **Version-based matching**: Semver-aware affected range checking
- **Offline mode**: Cached advisory database for air-gapped environments

### AST-Based Reachability Analysis
- Builds a call graph from your project's source code
- Parses Rust, JS/TS, Python, Go, and Java source files via tree-sitter
- Traces call chains from entry points to vulnerable functions
- Downgrades unreachable findings to Info severity
- **PledgePack integration** — auto-detects and reuses PledgePack's module graph for JS/TS projects
- **Incremental analysis** — only re-parses changed files using content hashes for faster re-scans
- **Confidence scoring** — Direct, Resolved, Heuristic, and Fuzzy confidence levels
- **Visualization** — export call graph as DOT (Graphviz) or GraphML

### WASM Custom Rules
- Write custom vulnerability detection rules in any language that compiles to WASM
- Sandboxed execution via Wasmtime with **fuel limiting** (CPU budget enforcement)
- **Plugin SDK** with type-safe Rust bindings for plugin authors
- **Plugin registry** for discovering and installing community plugins
- **Signature verification** for plugin integrity (SHA-256 + cryptographic signatures)
- **Granular permissions** (read manifests, read source, network, etc.)
- **Hot-reload** plugins without restarting scans
- **Parallel execution** for multi-plugin concurrency
- Example plugins in **AssemblyScript**, **C**, and **Go (TinyGo)**
- Enterprise-specific patterns (internal packages, custom frameworks)

### LLM-Powered Triage
- Sends vulnerability context to an LLM for false-positive assessment
- Supports OpenAI, Anthropic, Ollama, **llama.cpp** (local), and **fine-tuned models**
- **Batch LLM calls** — send multiple findings in one prompt to reduce API costs
- **Response caching** — avoid redundant LLM calls across scans (in-memory + disk)
- **Streaming responses** — real-time feedback via Server-Sent Events
- **Custom prompt templates** — user-customizable prompts with `{placeholder}` variables
- **Confidence threshold** — auto-suppress low-confidence false-positive verdicts
- **Multi-model consensus** — query multiple LLMs and use majority voting
- **Audit logging** — log all LLM calls for compliance (JSONL format)
- **Cost tracking** — track token usage and cost per scan
- Considers reachability, dev-only status, mitigating factors
- Reduces false positives by 60-80% (estimated)

### SBOM Generation
- **SPDX 2.3** (JSON format)
- **CycloneDX 1.5** (JSON format)
- Full dependency tree with PURL identifiers
- Compliance-ready for executive orders and enterprise policies

### Output & Reporting
- **Interactive HTML report** with collapsible findings, severity/reachability filtering, and search
- **PDF report** — print-ready HTML for compliance documentation (Print to PDF or headless browser)
- **Diff reports** — compare two scan reports to show new/resolved vulnerabilities and severity changes
- **Trend dashboard** — track vulnerability trends over time with scan history persistence
- **JUnit XML** — for Jenkins/CI test result integration
- **GitLab Code Quality JSON** — native GitLab vulnerability management integration
- **SonarQube import format** — import findings into SonarQube as external issues
- **Slack notifications** — post-scan Slack webhook with severity-colored attachments
- **Microsoft Teams notifications** — post-scan Teams webhook with actionable message cards
- **Email reports** — SMTP-based HTML email reports for scheduled scans

### CI/CD Deep Integration
- **Exit codes**: 0 (success), 1 (vulnerabilities found), 2 (scan error), 3 (database error)
- **SARIF output** for GitHub code scanning integration
- **GitHub Actions action** — official `pledgerecon/action` GitHub Action
- **GitLab CI template** — official `.gitlab-ci.yml` with Code Quality report
- **CircleCI orb** — official CircleCI orb for PledgeRecon
- **Bitbucket Pipes** — Bitbucket Pipeline integration
- **Pre-commit hook** — `pre-commit` framework hook for local scans
- **GitHub PR checks** — GitHub Check API integration with line-level annotations
- **Auto-fix PR generation** — automatically create PRs with dependency upgrades
- **Baseline comparison** — fail only on new vulnerabilities not in baseline
- **SARIF inline annotations** — annotate specific lines in PRs with vulnerability info
- **CI cache pre-population** — pre-populate advisory cache for offline scans
- **PR comments** with actionable findings summary

### Enterprise & Ecosystem
- **License compliance checking** — allow/deny lists for SPDX license identifiers (e.g. block GPL-3.0)
- **SLSA provenance verification** — verify SLSA levels (L1–L4) for supply-chain security
- **Sigstore verification** — verify dependency signatures via sigstore/cosign
- **SBOM diff** — compare two SBOMs to show added/removed/changed components
- **VEX output** — generate Vulnerability Exploitability eXchange documents (CycloneDX VEX)
- **Dependency pinning enforcement** — flag floating (`^`, `~`), wildcard (`*`), and range versions
- **Registry mirroring** — work with private registry mirrors (Artifactory, Nexus) for npm, crates.io, PyPI
- **Air-gapped mode** — fully offline operation with pre-bundled advisory database
- **Multi-tenant scan profiles** — different scan configs per team/sub-project in monorepos
- **REST API server** — long-running daemon with OpenAPI 3.0 spec for programmatic access
- **GraphQL API** — query scan results, findings, and advisories via GraphQL
- **Web UI dashboard** — real-time dashboard with severity stats and findings table
- **Webhook integration** — trigger webhooks on scan completion, new/critical vulnerabilities

### Intelligence & Prioritization
- **EPSS integration** — exploit prediction scoring from FIRST for likelihood-based prioritization
- **CISA KEV catalog** — cross-reference findings against Known Exploited Vulnerabilities
- **Exploit maturity detection** — PoC, functional, or weaponized exploit classification
- **Composite risk scoring** — combines CVSS + EPSS + KEV + reachability + exploit maturity + business context
- **Age-based prioritization** — newer vulnerabilities flagged as higher urgency
- **Business criticality tagging** — weight risk by dependency criticality (tier 1–4)
- **Exposure analysis** — network-facing, internet-exposed, or internal-only classification
- **Attack path visualization** — Graphviz DOT output from attacker to vulnerable function
- **Threat intel feed integration** — correlate with commercial feeds (Mandiant, Recorded Future)
- **Dependency anomaly detection** — typosquatting (Levenshtein), version jumps, recently published packages

### Platform & Integrations
- **VS Code extension** — real-time vulnerability diagnostics for the Problems panel
- **JetBrains plugin** — IntelliJ/PyCharm/GoLand/WebStorm inspection output
- **Jira integration** — create tickets with severity, package, version, and fix info
- **GitHub Issues integration** — create issues with severity labels and markdown body
- **Linear integration** — create issues with priority mapping
- **Dependabot alert format** — native GitHub Dependabot-compatible JSON output
- **ServiceNow integration** — create security incidents for enterprise ITSM
- **Splunk/ELK integration** — CEF (Common Event Format) export for SIEM ingestion
- **PagerDuty integration** — trigger incidents for critical-severity findings
- **Discord notifications** — webhook notifications with severity-colored embeds

### Advanced LLM & AI
- **AI remediation suggestions** — LLM-generated code patches (not just version bumps)
- **AI description enrichment** — plain-language vulnerability explanations for non-security developers
- **AI false positive explanation** — audit-trail-ready explanations of why findings are false positives
- **Local LLM auto-selection** — automatically pick best model based on GPU VRAM and RAM
- **RAG knowledge base** — retrieval-augmented generation from local CVE/patch vector DB
- **AI dependency Q&A** — natural language queries ("Which deps have known RCEs?")
- **AI policy generation** — generate OPA/Rego policies from natural language descriptions
- **AI commit message analysis** — detect security-relevant commits that should trigger re-scans
- **Multi-modal analysis** — executive summary generation with risk level and recommendations
- **AI triage fine-tuning pipeline** — collect feedback and generate instruction-format training data

### Performance & Scale
- **Incremental scanning** — only re-scan changed manifests using content-hash state persistence
- **Parallel advisory fetching** — concurrent advisory lookups via rayon thread pool
- **Persistent advisory store** — efficient on-disk advisory database with package index
- **Memory-mapped source scanning** — `memmap2` for large source files (>1 MB threshold)
- **Glob-based source filtering** — configurable include/exclude patterns with `**` support
- **Scan timeout** — configurable per-phase timeouts (scan, fetch, reachability)
- **Progress reporting** — real-time progress bars via `indicatif`
- **Monorepo support** — auto-discovers sub-projects and scans each independently
- **Docker image** — multi-stage Dockerfile for `ghcr.io/pledgeandgrow/pledgerecon`
- **WASM scan engine** — compile to `wasm32-wasip1` or `wasm32-unknown-unknown` for browser/edge
- **Distributed scanning** — partition and coordinate scans across multiple machines for ultra-large monorepos
- **CI scan result caching** — cache results keyed by lockfile hash to skip unchanged projects
- **Scan result diffing** — compare scan results between PR branch and base branch

### Distribution & Packaging
- **Homebrew formula** — `brew install pledgerecon` for macOS
- **Windows MSI installer** — WiX-based installer with PATH configuration
- **Linux .deb and .rpm** — native packages for Debian/Ubuntu and RHEL/Fedora
- **Nix flake** — reproducible installations via Nix package manager
- **Scoop manifest** — Windows Scoop package manager support
- **Pre-built binaries** — cross-compiled static binaries for Linux (musl), macOS, Windows, ARM64
- **GitHub Action v2** — composite action with matrix scanning, SARIF upload, SBOM attestation, and PR review

### Container & Cloud-Native Security
- **Container image scanning** — OS package vulnerability scanning for Debian, Ubuntu, Alpine images
- **Layer-aware scanning** — identifies which image layer introduced each vulnerability
- **Base image identification** — separates base image vulnerabilities from application vulnerabilities
- **Dockerfile analysis** — security best practices (root user, :latest tags, secrets in ENV, missing health check)
- **Kubernetes manifest scanning** — CIS benchmark checks (privileged pods, hostPath, root user, missing resource limits)
- **Helm chart scanning** — template-level misconfiguration detection
- **Terraform IaC scanning** — cloud misconfiguration detection (public S3, open security groups, unencrypted DBs)
- **CloudFormation IaC scanning** — AWS misconfiguration detection
- **Container registry sync** — monitor ECR/GCR/Docker Hub for new vulnerabilities
- **OCI artifact attestation** — verify cosign-signed SLSA provenance, SBOM, and scan result attestations

### Taint Analysis & Advanced Reachability
- **Data flow analysis** — track tainted data from sources (user input) to sinks (SQL queries, commands, responses)
- **JS/TS taint tracking** — XSS, SQLi, command injection detection in JavaScript/TypeScript
- **Python taint tracking** — SSRF, path traversal, deserialization, SQLi detection in Python
- **Rust taint tracking** — unsafe block and FFI boundary detection in Rust
- **Cross-language call resolution** — resolve FFI boundaries (napi, cffi, pyo3, extern "C")
- **Framework-aware reachability** — recognizes Express, Flask, Django, FastAPI, Actix, Axum entry points as taint sources
- **Conditional reachability** — tracks if/else branches and feature flags for precise confidence scoring
- **C/C++ vendored code** — parses and analyzes vendored C/C++ source for call graph construction
- **Interprocedural analysis** — whole-program call graph across files for accurate cross-function reachability
- **Reachability caching (CAS)** — content-addressable storage (blake3) for incremental reachability analysis

### Secret Detection & Hardening
- **Source code secret scanning** — 18+ built-in patterns (AWS, GitHub, GitLab, Slack, Stripe, Google, Azure, private keys, JWT, Twilio, SendGrid, Mailgun, generic)
- **Container image scanning** — scan container layers for leaked secrets in env vars and config files
- **IaC secret scanning** — detect secrets in Terraform, CloudFormation, Kubernetes, and Dockerfiles
- **Entropy-based detection** — Shannon entropy analysis for unknown secret formats
- **Secret verification** — validate detected secrets against provider APIs (AWS, GitHub, private keys)
- **Custom secret patterns** — user-defined regex patterns via JSON or YAML configuration
- **Git history scanning** — scan commit history for accidentally committed secrets
- **`.env` file scanning** — detect committed `.env` files with sensitive variables
- **Manifest credential detection** — check `.npmrc`, `.cargo/config.toml`, `pip.conf`, Maven `settings.xml`, `gradle.properties`, `nuget.config`, `docker config.json` for embedded credentials
- **Secret rotation guidance** — actionable steps, revoke URLs, and documentation links for each detected secret type

---

## Installation

### From source
```sh
git clone https://github.com/pledgeandgrow/pledgerecon.git
cd pledgerecon
cargo install --path crates/pledgerecon-cli
```

### Homebrew (macOS)
```bash
brew install pledgerecon
```

### Scoop (Windows)
```bash
scoop install pledgerecon
```

### Nix
```bash
nix profile install github:pledgeandgrow/pledgerecon
```

### Linux packages
```bash
# Debian/Ubuntu
sudo dpkg -i pledgerecon_*.deb

# RHEL/Fedora
sudo rpm -i pledgerecon-*.rpm
```

### Windows MSI
Download the MSI installer from [GitHub Releases](https://github.com/pledgeandgrow/pledgerecon/releases) and run.

### Pre-built binaries
Download static binaries for Linux (musl), macOS, Windows, and ARM64 from [GitHub Releases](https://github.com/pledgeandgrow/pledgerecon/releases).

### Docker
```bash
docker run ghcr.io/pledgeandgrow/pledgerecon scan /repo
```

---

## Usage

### Scan
```bash
# Basic scan
pledgerecon scan .

# With reachability analysis (default)
pledgerecon scan . --format json --output report.json

# Disable reachability for faster scan
pledgerecon scan . --no-reachability

# With LLM triage
pledgerecon scan . --triage

# With SBOM generation
pledgerecon scan . --generate-sbom --sbom-format cyclonedx --sbom-path sbom.json

# CI mode (fail on high+ severity)
pledgerecon scan . --fail-on-findings --min-severity high --format sarif --output pledgerecon.sarif

# Offline mode (use cached advisory database)
pledgerecon scan . --offline
```

### SBOM
```bash
# Generate CycloneDX SBOM
pledgerecon sbom . --format cyclonedx --output sbom.json

# Generate SPDX SBOM
pledgerecon sbom . --format spdx --output sbom.spdx.json
```

### List Dependencies
```bash
# Text format
pledgerecon list .

# JSON format
pledgerecon list . --format json
```

### CI Templates
```bash
# GitHub Actions template
pledgerecon ci --platform github

# GitLab CI template
pledgerecon ci --platform gitlab
```

---

## Configuration

Create a `pledgerecon.toml` in your project root:

```toml
min_severity = "medium"
reachability = true
fail_on_findings = true
generate_sbom = true
sbom_format = "cyclonedx"
offline = true

[[ignore]]
package = "npm:lodash"
advisory_id = "CVE-2021-23337"
reason = "Reviewed and accepted — template() not called"
expires = "2025-12-31"
```

---

## Architecture

```
pledgerecon/
├── crates/
│   ├── pledgerecon-core/     # Scanning engine
│   │   └── src/
│   │       ├── advisory.rs       # Advisory database (OSV, GHSA, NVD)
│   │       ├── dependency.rs     # Manifest parsing (Cargo.toml, package.json, go.mod, ...)
│   │       ├── finding.rs        # Vulnerability finding types
│   │       ├── reachability.rs   # AST-based reachability analysis (call graph)
│   │       ├── container.rs      # Container & cloud-native security (Goals 101–110)
│   │       ├── taint.rs          # Taint analysis & advanced reachability (Goals 111–120)
│   │       ├── secret.rs         # Secret detection & hardening (Goals 121–130)
│   │       ├── sbom.rs           # SPDX & CycloneDX SBOM generation
│   │       ├── triage.rs         # LLM-powered false positive reduction
│   │       ├── scanner.rs        # Main scan pipeline orchestrator
│   │       ├── plugin.rs         # WASM custom rules runtime (fuel, SDK, registry, signatures)
│   │       ├── config.rs         # Configuration & ignore rules
│   │       ├── output.rs         # JSON, SARIF, text, markdown, HTML, PDF, JUnit XML, GitLab CQ, SonarQube
│   │       ├── ci.rs             # CI/CD integration & exit codes
│   │       ├── ci_integration.rs # GitHub Actions, GitLab CI, CircleCI, Bitbucket, pre-commit, PR checks, auto-fix, baseline, SARIF annotations, cache pre-population
│   │       ├── report.rs         # Diff reports & trend tracking
│   │       ├── notify.rs         # Slack, Teams, email notifications
│   │       ├── enterprise.rs     # License compliance, SLSA, sigstore, SBOM diff, VEX, pinning, registry mirror, air-gapped, multi-tenant, REST/GraphQL API, web UI, webhooks
│   │       ├── performance.rs    # Incremental scan, parallel fetch, advisory store, mmap, glob filter, timeout, progress, monorepo, Docker, WASM
│   │       ├── intelligence.rs   # EPSS, CISA KEV, exploit maturity, risk scoring, attack paths, threat intel, anomaly detection (Goals 161–170)
│   │       ├── platform.rs       # VS Code, JetBrains, Jira, GitHub Issues, Linear, Dependabot, ServiceNow, Splunk/ELK, PagerDuty, Discord (Goals 171–180)
│   │       ├── ai.rs             # AI remediation, enrichment, RAG, local LLM selection, Q&A, policy generation, commit analysis, fine-tuning (Goals 181–190)
│   │       └── distribution.rs   # Homebrew, MSI, .deb/.rpm, Nix, Scoop, cross-compilation, GitHub Action v2, CI caching, distributed scanning, scan diffing (Goals 191–200)
│   └── pledgerecon-cli/      # CLI binary
│       └── src/
│           └── main.rs           # clap-based CLI
├── examples/
│   └── plugins/               # Example WASM plugins
│       ├── assemblyscript/      # AssemblyScript example (Goal 53)
│       ├── c/                   # C example (Goal 54)
│       └── go/                  # Go/TinyGo example (Goal 55)
├── ci/                      # CI/CD templates
│   ├── action.yml               # GitHub Actions action (Goal 66)
│   ├── gitlab-ci.yml            # GitLab CI template (Goal 67)
│   ├── circleci-orb.yml         # CircleCI orb (Goal 68)
│   ├── bitbucket-pipelines.yml  # Bitbucket Pipes (Goal 69)
│   ├── pre-commit-hook.yaml     # pre-commit hook (Goal 70)
│   ├── cache-pre-population.yml # CI cache workflow (Goal 75)
│   └── pledgerecon-cache-pre-populate.sh  # Cache script (Goal 75)
├── docs/                     # Documentation
├── Cargo.toml                # Workspace
├── Dockerfile               # Official Docker image (Goal 84)
├── .dockerignore             # Docker build ignore patterns
├── deny.toml                 # cargo-deny config
└── LICENSE
```

---

## PledgeLabs Ecosystem Integration

PledgeRecon integrates with other PledgeLabs tools:

- **PledgePack**: Reuses the module graph for JS/TS reachability analysis
- **PledgeGuard**: Scans dependencies for secrets (API keys, tokens in package metadata)

---

## License

MIT
