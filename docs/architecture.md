# Architecture

## Overview

PledgeRecon is a Rust-native dependency vulnerability scanner built as a Cargo workspace with two crates:

```
pledgerecon/
├── crates/
│   ├── pledgerecon-core/     # Scanning engine (library)
│   └── pledgerecon-cli/      # CLI binary
├── docs/                     # This documentation
├── Cargo.toml                # Workspace root
├── deny.toml                 # cargo-deny config
├── LICENSE                   # MIT
└── README.md
```

## Scan Pipeline

The scanner orchestrates a 12-step pipeline:

```
┌─────────────────────────────────────────────────────────────┐
│                     Scanner::scan()                          │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  1. Load Configuration (pledgerecon.toml)                    │
│     ↓                                                        │
│  2. Discover & Parse Manifests                               │
│     ├── Cargo.toml (Rust)                                    │
│     ├── package.json (Node.js)                               │
│     ├── go.mod (Go)                                          │
│     ├── requirements.txt / pyproject.toml (Python)           │
│     └── pubspec.yaml (Dart)                                  │
│     ↓                                                        │
│  3. Build Dependency Graph                                   │
│     ↓                                                        │
│  4. Load/Fetch Advisory Database                             │
│     ├── Local cache (.pledgerecon-cache/)                    │
│     ├── OSV.dev API                                          │
│     ├── GitHub Security Advisories (GHSA)                    │
│     └── NVD (planned)                                        │
│     ↓                                                        │
│  5. Match Dependencies ↔ Advisories (parallel via Rayon)     │
│     ↓                                                        │
│  6. Run WASM Custom Rules (if enabled)                       │
│     ├── Fuel-limited Wasmtime sandbox                        │
│     ├── Parallel execution (rayon)                           │
│     ├── Signature verification & permissions                 │
│     └── Hot-reload support                                   │
│     ↓                                                        │
│  7. Build Call Graph from Source Code                        │
│     ├── Parse Rust (use statements, fn calls)                │
│     ├── Parse JS/TS (import/require, function calls)         │
│     ├── Parse Python (import, def calls)                     │
│     └── Parse Go (import, func calls)                        │
│     ↓                                                        │
│  8. AST-Based Reachability Analysis                          │
│     ├── BFS from entry points → vulnerable functions         │
│     └── Trace call chains                                    │
│     ↓                                                        │
│  9. LLM-Powered Triage (if enabled)                          │
│     ├── Batch calls (multiple findings per LLM call)         │
│     ├── Cache check (skip if cached)                         │
│     ├── Providers: OpenAI/Anthropic/Ollama/llama.cpp/local   │
│     ├── Multi-model consensus (majority vote)                │
│     ├── Streaming (SSE) or standard request                  │
│     ├── Confidence threshold → auto-suppress                 │
│     ├── Audit log + cost tracking                            │
│     └── Verdict: confirmed / false_positive / inconclusive   │
│     ↓                                                        │
│ 10. Apply Ignore Rules (from config)                         │
│     ↓                                                        │
│ 11. Generate SBOM (if enabled)                               │
│     ├── SPDX 2.3 JSON                                        │
│     └── CycloneDX 1.5 JSON                                   │
│     ↓                                                        │
│ 12. Output Report                                            │
│     ├── Text (terminal)                                      │
│     ├── JSON                                                 │
│     ├── SARIF 2.1.0 (GitHub code scanning)                   │
│     ├── Markdown (PR comments)                               │
│     ├── HTML (interactive, collapsible, filtering)           │
│     ├── PDF (print-ready compliance report)                  │
│     ├── JUnit XML (Jenkins/CI test results)                  │
│     ├── GitLab Code Quality JSON                             │
│     └── SonarQube import format                              │
│     ↓                                                        │
│ 13. Notifications (if configured)                            │
│     ├── Slack webhook                                        │
│     ├── Microsoft Teams webhook                              │
│     ├── SMTP email report                                    │
│     ├── Discord webhook (Goal 180)                           │
│     ├── PagerDuty incidents for criticals (Goal 179)         │
│     └── SIEM (CEF) export for Splunk/ELK (Goal 178)          │
│     ↓                                                        │
│ 14. Intelligence & Prioritization (if enabled)               │
│     ├── EPSS scoring (Goal 161)                              │
│     ├── CISA KEV cross-reference (Goal 162)                  │
│     ├── Exploit maturity detection (Goal 163)                │
│     ├── Composite risk scoring (Goal 164)                    │
│     ├── Age-based urgency (Goal 165)                         │
│     ├── Business criticality weighting (Goal 166)            │
│     ├── Exposure analysis (Goal 167)                         │
│     ├── Attack path visualization (Goal 168)                 │
│     ├── Threat intel correlation (Goal 169)                  │
│     └── Dependency anomaly detection (Goal 170)              │
│     ↓                                                        │
│ 15. AI Enrichment & Platform Integrations (if enabled)       │
│     ├── AI remediation suggestions (Goal 181)                │
│     ├── AI description enrichment (Goal 182)                 │
│     ├── AI false positive explanation (Goal 183)             │
│     ├── RAG knowledge base query (Goal 185)                  │
│     ├── Executive summary generation (Goal 189)              │
│     └── Issue tracker sync: Jira, GitHub Issues,             │
│         Linear, ServiceNow, Dependabot (Goals 173–177)       │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

## Module Reference

### `advisory.rs`
- **Types**: `Advisory`, `AdvisoryId`, `AdvisorySeverity`, `AdvisoryReference`, `VersionRange`, `AdvisoryDatabase`
- **Sources**: OSV.dev (POST query API), GHSA (GitHub REST API), local JSON files
- **Caching**: Binary serialization to `.pledgerecon-cache/advisories.json` for offline use
- **Matching**: `for_package()` and `for_package_version()` with semver-aware range checking

### `dependency.rs`
- **Types**: `Dependency`, `DependencyKind`, `DependencyGraph`, `ManifestParseError`
- **Parsers**: Cargo.toml, package.json, go.mod, requirements.txt, pyproject.toml, pubspec.yaml
- **Graph**: Direct vs transitive dependencies, dependency tree, qualified names (`npm:lodash`, `crates:serde`)

### `finding.rs`
- **Types**: `Finding`, `VulnerabilitySeverity`, `ReachabilityStatus`, `FindingStatus`
- **Severity**: Info < Low < Medium < High < Critical (Ord derived)
- **Status**: Pending → Confirmed / FalsePositive / Inconclusive (after triage)
- **CI Logic**: `is_ci_blocking()` considers severity threshold + reachability + triage status

### `reachability.rs`
- **Types**: `CallGraph`, `CallNode`, `ReachabilityAnalyzer`, `ReachabilityResult`, `ConfidenceLevel`
- **Call Graph**: Nodes = functions, edges = call relationships, reverse index for BFS
- **Parsers**: Tree-sitter-based parsing for Rust, JS/TS, Python, Go, Java
- **Analysis**: BFS from entry points to vulnerable functions, returns call chain
- **Confidence**: Direct call = High, heuristic = Medium/Low
- **Visualization**: Export as DOT (Graphviz) or GraphML
- **PledgePack Integration** (Goal 31): Import `SerializableModuleGraph` from `.pledgpack/graph.json` and convert to `CallGraph` via `import_pledgepack_graph()`
- **PledgePack Auto-Detection** (Goal 33): `detect_pledgepack()` checks for `.pledgpack` config; `build_call_graph_with_pledgepack()` auto-uses PledgePack graph or falls back to tree-sitter
- **Incremental Reachability** (Goal 32): `build_call_graph_incremental()` only re-parses files whose content hash changed, reusing nodes from the previous graph for unchanged files

### `sbom.rs`
- **Types**: `SbomGenerator`, `SbomFormat`, `SbomError`
- **SPDX 2.3**: JSON format with packages, relationships, creation info, external refs (PURLs)
- **CycloneDX 1.5**: JSON format with components, dependencies, metadata, tools, bom-ref

### `triage.rs`
- **Types**: `TriageEngine`, `TriageResult`, `TriageVerdict`, `TokenUsage`, `CostReport`, `AuditLogEntry`
- **Providers**: OpenAI (`gpt-4o-mini`), Anthropic, Ollama (local), llama.cpp (local), fine-tuned models, custom endpoints
- **Batching**: Multiple findings per LLM call (`batch_size` config, default 5)
- **Caching**: In-memory `HashMap` + disk cache keyed by finding hash
- **Streaming**: SSE streaming for OpenAI-compatible endpoints
- **Prompt**: Custom templates with `{placeholder}` variables, includes advisory ID, summary, description, severity, CVSS, package, version, fix info, reachability, call chain, CWEs
- **Response**: JSON with verdict, confidence (0.0-1.0), explanation, remediation
- **Consensus**: Multi-model majority voting
- **Confidence Threshold**: Auto-suppress false positives below threshold (default 0.8)
- **Audit Log**: JSONL format with timestamp, model, tokens, cost, verdict
- **Cost Tracking**: Per-token cost accumulation and reporting

### `scanner.rs`
- **Types**: `Scanner`, `ScanReport`, `ScanError`
- **Orchestration**: Full 12-step pipeline
- **Parallelism**: Rayon for dependency-advisory matching
- **Report**: `ScanReport` with scan ID, timestamp, duration, findings, counts

### `plugin.rs`
- **Types**: `WasmRule`, `WasmRuleInput`, `WasmRuleOutput`, `PluginError`, `PluginRegistry`, `PluginRegistryEntry`
- **Runtime**: Wasmtime v26 sandboxed execution with fuel limiting
- **Protocol**: WASM module exports `alloc(size)`, `check(ptr, len)`, `memory`
- **I/O**: JSON passed via WASM memory (alloc → write → call → read)
- **Fuel Limiting**: CPU budget enforcement via `store.set_fuel()`
- **SDK**: `plugin::sdk` module with `PluginInput`, `PluginOutput` for type-safe plugin authoring
- **Registry**: `PluginRegistry` for discovering, downloading, and installing community plugins
- **Signatures**: SHA-256 hash verification + optional cryptographic signature verification
- **Permissions**: `PluginPermission` enum (ReadManifests, ReadSource, ReadAdvisories, Network, WriteFile, Environment)
- **Hot-Reload**: mtime + content hash tracking, automatic reload on file change
- **Parallelism**: `run_plugins_parallel()` using rayon for concurrent plugin execution

### `config.rs`
- **Types**: `ScanConfig`, `AdvisorySource`, `IgnoreRule`, `TriageConfig`, `WasmPluginConfig`, `PluginPermission`
- **File**: `pledgerecon.toml` in project root
- **Ignore Rules**: By package name, advisory ID, with expiry dates
- **Triage Config**: Provider, model, batch size, caching, streaming, prompt templates, confidence threshold, consensus models, audit log, cost tracking
- **WASM Plugin Config**: Fuel limit, signature verification, permissions, hot-reload, parallelism, registry URL
- **Defaults**: OSV + GHSA sources, low min severity, reachability enabled, batch size 5, confidence threshold 0.8, fuel 1B instructions

### `output.rs`
- **Formats**: JSON, SARIF 2.1.0, Text, Markdown, HTML, PDF, JUnit XML, GitLab Code Quality JSON, SonarQube
- **HTML**: Interactive report with collapsible findings, severity/reachability filtering, and search (Goal 56)
- **PDF**: Print-ready HTML for compliance documentation, works with Print to PDF or headless browser (Goal 57)
- **JUnit XML**: Jenkins/CI test result integration with testcases and failures (Goal 60)
- **GitLab Code Quality**: Native GitLab vulnerability management JSON format (Goal 61)
- **SonarQube**: External issue import format with engineId, ruleId, severity, locations (Goal 62)
- **SARIF**: GitHub code scanning compatible with rules, results, locations
- **Text**: Human-readable terminal output with severity tags and call chains
- **Markdown**: Tables, emoji severity indicators, PR-comment friendly

### `report.rs`
- **Types**: `DiffReport`, `ReportSummary`, `SeverityChange`, `TrendTracker`, `TrendPoint`, `TrendDirection`
- **Diff Report**: Compare two scan reports to show new/resolved vulnerabilities and severity changes (Goal 58)
- **Trend Dashboard**: Track vulnerability trends over time with scan history persistence (Goal 59)
- **Persistence**: Trend history saved/loaded from JSON files
- **Output**: Text and HTML formats for diff and trend reports

### `notify.rs`
- **Types**: `SlackNotification`, `TeamsNotification`, `EmailReport`, `NotifyError`
- **Slack**: Webhook-based notification with severity-colored attachments and top findings (Goal 63)
- **Teams**: Webhook-based notification with MessageCard format and actionable buttons (Goal 64)
- **Email**: SMTP-based HTML email report with summary table and findings detail (Goal 65)

### `ci.rs`
- **Exit Codes**: 0 (success), 1 (vulns found), 2 (scan error), 3 (database error)
- **GitHub Actions**: Workflow template, step summary, PR comment
- **GitLab CI**: Job template, Code Quality JSON format
- **Logic**: Severity threshold + reachability + triage-aware blocking

### `ci_integration.rs`
- **Types**: `CheckOutput`, `CheckAnnotation`, `AutoFixSuggestion`, `BaselineComparison`, `CiIntegrationError`
- **GitHub Actions action** (Goal 66): Official `action.yml` with SARIF upload, SBOM, baseline support
- **GitLab CI template** (Goal 67): Official `.gitlab-ci.yml` with Code Quality report artifacts
- **CircleCI orb** (Goal 68): Official orb with `pledgerecon-scan` command and configurable parameters
- **Bitbucket Pipes** (Goal 69): Bitbucket Pipeline integration with artifact storage
- **Pre-commit hook** (Goal 70): `pre-commit` framework hook for local scans on manifest changes
- **GitHub PR check** (Goal 71): GitHub Check API integration with line-level annotations and severity-based conclusion
- **Auto-fix PR generation** (Goal 72): Generate dependency upgrade suggestions and PR body from fixable findings
- **Baseline comparison** (Goal 73): Compare against baseline file to fail only on new vulnerabilities
- **SARIF inline annotations** (Goal 74): Enhanced SARIF with line-level region annotations for PR inline display
- **CI cache pre-population** (Goal 75): Script and GitHub Actions workflow for pre-downloading advisory cache

### `enterprise.rs`
- **License compliance** (Goal 87): `LicensePolicy` with allow/deny lists, `check_license_compliance()` checks SPDX identifiers
- **SLSA provenance** (Goal 88): `SlsaLevel` (None/L1/L2/L3/L4), `verify_slsa_provenance()` checks attestations against minimum level
- **Sigstore verification** (Goal 89): `SignatureAttestation`, `verify_signatures()` checks cosign signatures
- **SBOM diff** (Goal 90): `diff_sboms()` compares two SBOMs (SPDX/CycloneDX), returns added/removed/changed components
- **VEX output** (Goal 91): `generate_vex()` creates CycloneDX VEX documents from scan findings with status/justification
- **Dependency pinning** (Goal 92): `check_dependency_pinning()` flags floating (`^`, `~`), wildcard (`*`), and range versions
- **Registry mirroring** (Goal 93): `RegistryMirrorConfig` generates `.npmrc`, Cargo config, pip config for private mirrors
- **Air-gapped mode** (Goal 94): `AirGappedConfig` with pre-bundled advisory database, `verify_air_gapped()` validates prerequisites
- **Multi-tenant profiles** (Goal 95): `MultiTenantConfig` with glob-based path matching per sub-project
- **REST API** (Goal 96): `RestApiConfig`, `api_endpoints()`, `generate_openapi_spec()` for OpenAPI 3.0
- **GraphQL API** (Goal 97): `graphql_schema()` returns type definitions for Query/Mutation resolvers
- **Web UI dashboard** (Goal 98): `dashboard_html()` returns self-contained HTML dashboard with live API fetch
- **Webhook integration** (Goal 99): `WebhookConfig`, `send_webhook()` with event types and HMAC secret support

### `performance.rs`
- **Incremental scanning** (Goal 76): `ScanState` persists manifest hashes, `detect_changed_manifests()` identifies changed files
- **Parallel advisory fetching** (Goal 77): `fetch_advisories_parallel()` uses rayon thread pool with configurable concurrency
- **Advisory store** (Goal 78): `AdvisoryStore` — persistent on-disk advisory database with package index and batch insert
- **Memory-mapped I/O** (Goal 79): `read_source_file()` uses `memmap2` for files >1 MB threshold
- **Glob source filtering** (Goal 80): `SourceFilter` with include/exclude patterns, `**` recursive matching
- **Scan timeout** (Goal 81): `TimeoutConfig` with per-phase timeouts, `check_timeout()`, `with_timeout()`
- **Progress reporting** (Goal 82): `ProgressReporter` wrapping `indicatif::ProgressBar`
- **Monorepo support** (Goal 83): `discover_subprojects()` walks directory tree, `scan_monorepo()` scans each sub-project
- **Docker image** (Goal 84): `dockerfile_content()` generates multi-stage Dockerfile, `dockerignore_content()` for build context
- **WASM scan engine** (Goal 85): `wasm_build_config()` for `wasm32-wasip1`/`wasm32-unknown-unknown`, `wasm_js_wrapper()` for browser

### `container.rs`
- **Container image scanning** (Goal 101): `scan_container_image()` extracts OS packages from Debian/Ubuntu (dpkg status) and Alpine (apk installed) filesystems
- **Layer-aware scanning** (Goal 102): `assign_vulnerabilities_to_layers()` maps vulnerabilities to the image layer that introduced them
- **Base image identification** (Goal 103): `identify_base_image()` parses Dockerfile `FROM` lines, detects distroless/scratch, official images, and digest references
- **Dockerfile analysis** (Goal 104): `analyze_dockerfile()` checks for root user, `:latest` tags, missing health checks, secrets in ENV, and more (DF001–DF009)
- **Kubernetes manifest scanning** (Goal 105): `scan_k8s_manifest()` checks CIS benchmark controls (privileged pods, hostPath, root user, missing resource limits, KSV codes)
- **Helm chart scanning** (Goal 106): `scan_helm_chart()` parses `Chart.yaml` and templates for misconfigurations
- **Terraform IaC scanning** (Goal 107): `scan_terraform()` detects public S3 buckets, open security groups, unencrypted databases, hardcoded secrets (TF001–TF005)
- **CloudFormation IaC scanning** (Goal 108): `scan_cloudformation()` detects AWS misconfigurations (public S3, open SGs, unencrypted RDS)
- **Container registry sync** (Goal 109): `discover_registry_images()` simulates registry API calls to ECR/GCR/Docker Hub for image inventory
- **OCI artifact attestation** (Goal 110): `verify_attestations()` parses and verifies cosign in-toto attestations (SLSA provenance, SBOM, scan results)

### `taint.rs`
- **Data flow analysis** (Goal 111): `TaintAnalyzer` tracks tainted data from sources to sinks, detects XSS, SQLi, command injection, SSRF, path traversal
- **JS/TS taint tracking** (Goal 112): `analyze_javascript()` with patterns for Express req.query, req.body, res.send, db.query, child_process.exec, eval
- **Python taint tracking** (Goal 113): `analyze_python()` with patterns for Flask/Django request.args, cursor.execute, subprocess.call, pickle.loads, requests.get
- **Rust taint tracking** (Goal 114): `analyze_rust()` with patterns for env::args, unsafe blocks, Command::new, FFI boundaries
- **Cross-language call resolution** (Goal 115): `detect_cross_language_calls()` identifies FFI boundaries (napi, cffi, pyo3, extern "C"), `resolve_cross_language()` matches bindings to target exports
- **Framework-aware reachability** (Goal 116): `framework_entry_points()` defines known entry points for Express, Fastify, Flask, FastAPI, Django, Spring, Actix, Axum; `detect_framework_entries()` finds them in source
- **Conditional reachability** (Goal 117): `analyze_conditional_reachability()` tracks if/else branches and feature flags, adjusts confidence based on conditional path complexity
- **C/C++ vendored code** (Goal 118): `parse_c_source()` extracts function definitions and calls from C/C++ source, `build_c_call_graph()` constructs a call graph from vendored C/C++ directories
- **Interprocedural analysis** (Goal 119): `build_interprocedural_graph()` constructs a whole-program call graph across files, `find_interprocedural_paths()` finds all paths from entry points to target functions via BFS
- **Reachability caching with CAS** (Goal 120): `ReachabilityCache` stores reachability results keyed by blake3 content hash, supports incremental analysis by skipping unchanged files

### `secret.rs`
- **Source code secret scanning** (Goal 121): `SecretPattern`, `builtin_patterns()` with 18+ patterns (AWS, GitHub, GitLab, Slack, Stripe, Google, Azure, private keys, JWT, Twilio, SendGrid, Mailgun, generic), `scan_source_code()` recursive directory scanning
- **Container image secret scanning** (Goal 122): `ContainerLayer`, `scan_container_secrets()` scans layer files for leaked secrets
- **IaC secret scanning** (Goal 123): `IaCKind` (Terraform, CloudFormation, Kubernetes, Dockerfile), `scan_iac_files()` for infrastructure-as-code files
- **Entropy-based detection** (Goal 124): `shannon_entropy()`, `detect_high_entropy()` for unknown secret formats using Shannon entropy
- **Secret verification** (Goal 125): `VerificationResult`, `verify_secrets()` validates format and checksums for AWS, GitHub, private keys
- **Custom secret patterns** (Goal 126): `load_custom_patterns()` (JSON), `load_custom_patterns_yaml()` (YAML) for organization-specific patterns
- **Git history scanning** (Goal 127): `GitCommitContent`, `scan_git_history()` for accidentally committed secrets
- **.env file scanning** (Goal 128): `scan_env_files()` detects sensitive variables and committed .env files
- **Manifest credential detection** (Goal 129): `ManifestKind` (Npmrc, CargoConfig, PipConf, MavenSettings, GradleProperties, NugetConfig, DockerConfig), `scan_manifests()` with manifest-specific patterns
- **Secret rotation guidance** (Goal 130): `RotationGuidance`, `rotation_guidance()`, `rotation_guidance_for_scan()` with service-specific steps, revoke URLs, and documentation links

### `intelligence.rs`
- **EPSS integration** (Goal 161): `EpssScore` with `fetch_scores()` for exploit prediction scoring, `for_cve()` lookup
- **CISA KEV catalog** (Goal 162): `KevCatalog` with `load_from_json()`, `is_known_exploited()` cross-referencing
- **Exploit maturity detection** (Goal 163): `ExploitMaturity` enum (ProofOfConcept, Functional, Weaponized), `detect()` from advisory references and descriptions
- **Risk-based prioritization** (Goal 164): `RiskScore` composite scoring combining CVSS, EPSS, KEV, reachability, exploit maturity; `calculate_risk_score()` and `prioritize_findings()`
- **Age-based prioritization** (Goal 165): `vulnerability_age_days()` and `age_urgency_multiplier()` factoring vulnerability recency
- **Business criticality tagging** (Goal 166): `BusinessCriticality` enum, `CriticalityTag`, `CriticalityRegistry` for weighted risk scoring
- **Exposure analysis** (Goal 167): `ExposureLevel` enum (InternetFacing, NetworkExposed, InternalOnly), `analyze_exposure()` via package and call chain heuristics
- **Attack path visualization** (Goal 168): `AttackPath`, `AttackPathNode`, `AttackPathEdge`, `build_attack_path()`, `attack_path_to_dot()` for Graphviz export
- **Threat intel feed integration** (Goal 169): `ThreatIntelFeed`, `ThreatIntelEntry`, `correlate_threat_intel()` for commercial feed correlation
- **Anomaly detection** (Goal 170): `DependencyAnomaly`, `AnomalyType`, `detect_typosquatting()` (Levenshtein distance), `detect_version_jump()`, `detect_recently_published()`

### `platform.rs`
- **VS Code extension** (Goal 171): `VsCodeDiagnostic`, `VsCodeSeverity`, `generate_vscode_diagnostics()` for VS Code Problems panel output
- **JetBrains plugin** (Goal 172): `JetBrainsInspection`, `generate_jetbrains_inspections()` with severity mapping and quick-fix suggestions
- **Jira integration** (Goal 173): `JiraIssue`, `create_jira_issues()` with project key, priority, labels, and formatted description
- **GitHub Issues integration** (Goal 174): `GitHubIssue`, `create_github_issues()` with severity labels and markdown body
- **Linear integration** (Goal 175): `LinearIssue`, `create_linear_issues()` with priority mapping (1–4) and team ID
- **Dependabot alert format** (Goal 176): `DependabotAlert`, `DependabotPackage`, `DependabotVulnerability`, `to_dependabot_alerts()` for native GitHub integration
- **ServiceNow integration** (Goal 177): `ServiceNowIncident`, `create_servicenow_incidents()` with urgency/impact/priority mapping
- **Splunk/ELK integration** (Goal 178): `CefEvent`, `to_cef_events()`, `cef_to_string()` for CEF (Common Event Format) SIEM ingestion
- **PagerDuty integration** (Goal 179): `PagerDutyEvent`, `PagerDutyPayload`, `create_pagerduty_events()` for critical-severity incident triggering
- **Discord notification** (Goal 180): `DiscordNotification`, `build_payload()` with embed color coding by severity

### `ai.rs`
- **AI remediation suggestions** (Goal 181): `AiRemediationSuggestion`, `CodePatch`, `generate_ai_remediation()` with code-level patches and confidence
- **AI description enrichment** (Goal 182): `EnrichedDescription`, `enrich_description()` with plain-language, impact, affected users, and analogy
- **AI false positive explanation** (Goal 183): `FpExplanation`, `explain_false_positive()` with reasoning, evidence, and confidence
- **Local LLM auto-selection** (Goal 184): `HardwareProfile`, `LocalModel` enum (Llama3-8b/70b, Mistral7b, Phi3Mini, Qwen2-7b), `select_local_model()` based on GPU VRAM and RAM
- **RAG knowledge base** (Goal 185): `KnowledgeBase`, `KnowledgeEntry`, cosine similarity search, `build_rag_prompt()` for retrieval-augmented generation
- **AI dependency Q&A** (Goal 186): `QaAnswer`, `answer_dependency_question()` for natural language queries (RCE, critical, reachable)
- **AI policy generation** (Goal 187): `GeneratedPolicy`, `generate_policy()` producing OPA/Rego from natural language descriptions
- **AI commit message analysis** (Goal 188): `CommitAnalysis`, `analyze_commit_message()` detecting security-relevant keywords and rescan triggers
- **Multi-modal analysis** (Goal 189): `ExecutiveSummary`, `generate_executive_summary()` with risk level, key findings, and recommendations
- **AI triage fine-tuning pipeline** (Goal 190): `FineTuningDataset`, `TriageFeedback`, accuracy tracking, JSONL export, instruction-format training data

### `distribution.rs`
- **Homebrew formula** (Goal 191): `homebrew_formula()` generating Ruby formula with version, SHA-256, and test block
- **Windows MSI installer** (Goal 192): `wix_config()` generating WiX XML with PATH configuration and per-machine install scope
- **Linux .deb and .rpm** (Goal 193): `debian_control()` generating Debian control file, `rpm_spec()` generating RPM spec file
- **Nix flake** (Goal 194): `nix_flake()` generating Nix flake.nix with buildRustPackage and devShell
- **Scoop manifest** (Goal 195): `scoop_manifest()` generating JSON manifest with autoupdate configuration
- **Pre-built binaries** (Goal 196): `CrossTarget` enum (x86_64/aarch64, Linux/macOS/Windows), `cross_compilation_matrix()` for GitHub Actions
- **GitHub Action v2** (Goal 197): `github_action_v2()` generating composite workflow with SARIF upload, SBOM, and PR review
- **Scan result caching in CI** (Goal 198): `ScanCache`, `compute_cache_key()` (SHA-256 lockfile hash), `save_scan_cache()`, `load_scan_cache()`, `is_cache_valid()`
- **Distributed scanning** (Goal 199): `ScanPartition`, `partition_scan()` with load-balanced manifest distribution, `merge_scan_results()` for combining partition results
- **Scan result diffing** (Goal 200): `ScanDiff`, `ScanDiffSummary`, `diff_scan_results()` showing new/resolved/unchanged findings, `diff_to_markdown()` for PR-friendly reports

## Data Flow

```
Manifest Files → DependencyGraph → AdvisoryDatabase → Vec<Finding>
                                                        ↓
Source Files → CallGraph → ReachabilityAnalysis → Enriched Findings
                                                        ↓
LLM Provider → TriageEngine → TriageResults → Triaged Findings
                                                        ↓
Ignore Rules → Filtered Findings → Output Format → Report
                                                        ↓
DependencyGraph → SbomGenerator → SBOM File (SPDX/CycloneDX)
```

## Design Principles

1. **Rust-native**: No Node.js, Python, or external runtime required
2. **Self-hosted**: No SaaS dependency — works fully offline with cached advisories
3. **CI-native**: Exit codes, SARIF, PR comments, GitHub Actions, GitLab CI, CircleCI, Bitbucket, pre-commit hooks
4. **Extensible**: WASM plugins for custom rules, TOML config for ignore rules
5. **Fast**: Rayon parallelism, memory-mapped I/O, tree-sitter parsing, parallel WASM plugins, incremental scanning
6. **Accurate**: AST reachability + LLM triage (batch, consensus, caching) to minimize false positives
7. **Reportable**: Interactive HTML, PDF, JUnit XML, GitLab CQ, SonarQube, diff reports, trend dashboards, VEX
8. **Notifiable**: Slack, Microsoft Teams, email, Discord, PagerDuty, and webhook notifications for post-scan alerts
9. **Enterprise-ready**: License compliance, SLSA provenance, sigstore verification, SBOM diff, dependency pinning
10. **Scalable**: Monorepo support, multi-tenant profiles, persistent advisory store, air-gapped mode, Docker, WASM, distributed scanning, CI result caching
11. **Cloud-native**: Container image scanning, Dockerfile/K8s/Helm/IaC analysis, OCI attestation verification, registry sync
12. **Code-aware**: Taint analysis (JS/TS/Python/Rust), cross-language FFI resolution, framework-aware reachability, interprocedural analysis, CAS-cached reachability
13. **Secret-aware**: Source code, container image, IaC, git history, .env, and manifest secret scanning with entropy detection, verification, and rotation guidance
14. **Intelligence-driven**: EPSS scoring, CISA KEV catalog, exploit maturity detection, composite risk scoring, attack path visualization, threat intel correlation, dependency anomaly detection
15. **Platform-integrated**: VS Code and JetBrains IDE diagnostics, Jira/GitHub Issues/Linear/ServiceNow issue creation, Dependabot alert format, Splunk/ELK CEF export
16. **AI-powered**: AI remediation suggestions, description enrichment, false positive explanations, local LLM auto-selection, RAG knowledge base, natural language Q&A, policy generation, commit message analysis, executive summaries, triage fine-tuning pipeline
17. **Distributable**: Homebrew formula, Windows MSI, Linux .deb/.rpm, Nix flake, Scoop manifest, cross-compiled binaries, GitHub Action v2, scan result diffing across branches
