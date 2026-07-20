# PledgeRecon Roadmap — 200 Goals

## Phase 1: Foundation (Goals 1–20) — MVP Hardening

### Core Engine
1. **Fix all compiler warnings** — Remove unused imports, prefix unused variables, achieve zero warnings ✅
2. **Add `cargo test` CI** — Run all unit tests in CI, fail on any test failure ✅
3. **Add integration tests** — End-to-end scan tests with fixture projects (Rust, Node, Python, Go) ✅
4. **Add `cargo fmt` enforcement** — CI check for rustfmt compliance ✅
5. **Add `cargo clippy` enforcement** — CI check for clippy with `-D warnings` ✅
6. **Add `cargo deny` CI check** — Audit own dependencies for vulnerabilities (dogfooding) ✅

### Advisory Database
7. **Implement NVD API integration** — Fetch from `services.nvd.nist.gov/rest/json/cves/2.0` ✅
8. **Add advisory cache TTL** — Cache entries expire after configurable duration (default: 24h) ✅
9. **Add advisory cache validation** — Verify cache integrity on load (checksum) ✅
10. **Add advisory deduplication** — Merge advisories with same CVE ID across sources ✅
11. **Add semver range matching** — Proper semver range parsing (not just string comparison) ✅
12. **Add PEP 440 version matching** — Python version comparison (epochs, pre-releases) ✅
13. **Add Go module version matching** — Pseudo-versions, +incompatible suffixes ✅

### Dependency Parsing
14. **Add Maven `pom.xml` parsing** — Java/Maven ecosystem support ✅
15. **Add Gradle `build.gradle` parsing** — Java/Gradle ecosystem support ✅
16. **Add Ruby `Gemfile.lock` parsing** — Ruby/Bundler ecosystem support ✅
17. **Add Composer `composer.lock` parsing** — PHP/Composer ecosystem support ✅
18. **Add NuGet `packages.config` parsing** — .NET/NuGet ecosystem support ✅
19. **Add `yarn.lock` parsing** — Yarn lockfile for exact transitive versions ✅
20. **Add `Cargo.lock` parsing** — Use lockfile for exact transitive dependency versions ✅

## Phase 2: Reachability Deep Dive (Goals 21–35)

### Tree-Sitter Integration
21. **Add tree-sitter Rust parser** — Replace regex with tree-sitter for Rust source parsing ✅
22. **Add tree-sitter JavaScript parser** — Replace regex with tree-sitter for JS source parsing ✅
23. **Add tree-sitter TypeScript parser** — TSX/TS source parsing with proper type awareness ✅
24. **Add tree-sitter Python parser** — Replace regex with tree-sitter for Python source parsing ✅
25. **Add tree-sitter Go parser** — Replace regex with tree-sitter for Go source parsing ✅
26. **Add tree-sitter Java parser** — Java source parsing for Maven/Gradle projects ✅
27. **Add cross-file call resolution** — Resolve function calls to definitions across files ✅
28. **Add dynamic import tracking** — Track `require()` and dynamic `import()` in JS/TS ✅
29. **Add method-level reachability** — Track method calls on imported objects (e.g. `lib.method()`) ✅
30. **Add macro expansion tracking** — Track Rust macro calls that invoke vulnerable functions ✅

### PledgePack Integration
31. **Reuse PledgePack module graph** — Import `SerializableModuleGraph` for JS/TS projects ✅
32. **Incremental reachability** — Only re-analyze changed modules using PledgePack's content hashes ✅
33. **Add PledgePack auto-detection** — Detect if project uses PledgePack and reuse its graph ✅

### Advanced Analysis
34. **Add call graph visualization** — Export call graph as DOT/GraphML for debugging ✅
35. **Add reachability confidence scoring** — Score based on call chain certainty (direct vs heuristic) ✅

## Phase 3: LLM Triage Enhancement (Goals 36–45)

36. **Add batch LLM calls** — Send multiple findings in one prompt to reduce API calls ✅
37. **Add LLM response caching** — Cache triage results keyed by finding hash ✅
38. **Add streaming LLM responses** — Stream triage results for real-time feedback ✅
39. **Add local model support via llama.cpp** — Direct llama.cpp integration (no Ollama dependency) ✅
40. **Add fine-tuned model support** — Fine-tune a small model on vulnerability triage data ✅
41. **Add triage prompt templates** — User-customizable prompt templates in config ✅
42. **Add triage confidence threshold** — Configurable threshold for auto-suppressing findings ✅
43. **Add multi-model consensus** — Query multiple LLMs and use majority vote ✅
44. **Add triage audit log** — Log all LLM calls and responses for compliance ✅
45. **Add triage cost tracking** — Track token usage and cost per scan ✅

## Phase 4: WASM Plugin System (Goals 46–55)

46. **Add WASM fuel limiting** — Limit WASM execution with Wasmtime fuel/epoch interruption ✅
47. **Add WASM plugin SDK** — Rust crate for writing PledgeRecon plugins with type-safe bindings ✅
48. **Add WASM plugin registry** — Community plugin repository with versioning ✅
49. **Add WASM plugin signatures** — Verify plugin integrity with cryptographic signatures ✅
50. **Add WASM plugin permissions** — Granular permissions (read manifests, read source, etc.) ✅
51. **Add WASM plugin hot-reload** — Reload plugins without restarting scan ✅
52. **Add WASM plugin parallelism** — Run multiple plugins concurrently per dependency ✅
53. **Add AssemblyScript example** — Example plugin written in AssemblyScript ✅
54. **Add C example plugin** — Example plugin written in C ✅
55. **Add Go example plugin** — Example plugin written in Go (TinyGo) ✅

## Phase 5: Output & Reporting (Goals 56–65)

56. **Add HTML report** — Interactive HTML report with collapsible sections and filtering ✅
57. **Add PDF report** — Generate PDF reports for compliance documentation ✅
58. **Add diff report** — Compare two scan reports to show new/resolved vulnerabilities ✅
59. **Add trend dashboard** — Track vulnerability trends over time (scan history) ✅
60. **Add JUnit XML output** — For Jenkins/CI test result integration ✅
61. **Add GitLab Code Quality JSON** — Native GitLab vulnerability management integration ✅
62. **Add SonarQube import format** — Import findings into SonarQube ✅
63. **Add Slack notification template** — Post-scan Slack webhook notification ✅
64. **Add Microsoft Teams notification** — Post-scan Teams webhook notification ✅
65. **Add email report** — SMTP-based email report for scheduled scans ✅

## Phase 6: CI/CD Deep Integration (Goals 66–75)

66. **Add GitHub Actions action** — Official `pledgerecon/action` GitHub Action ✅
67. **Add GitLab CI template** — Official `.gitlab-ci.yml` template ✅
68. **Add Circle CI orb** — Official CircleCI orb for PledgeRecon ✅
69. **Add Bitbucket Pipes** — Bitbucket Pipeline integration ✅
70. **Add pre-commit hook** — `pre-commit` framework hook for local scans ✅
71. **Add GitHub PR check** — GitHub Check API integration with annotations ✅
72. **Add auto-fix PR generation** — Automatically create PRs with dependency upgrades ✅
73. **Add baseline comparison** — Compare against `pledgerecon-baseline.json` to fail only on new vulns ✅
74. **Add SARIF inline annotations** — Annotate specific lines in PRs with vulnerability info ✅
75. **Add CI cache pre-population** — Pre-populate advisory cache in CI for offline scans ✅

## Phase 7: Performance & Scale (Goals 76–85)

76. **Add incremental scanning** — Only re-scan changed dependencies since last scan ✅
77. **Add parallel advisory fetching** — Fetch advisories for all dependencies concurrently ✅
78. **Add advisory database SQLite backend** — Replace JSON cache with SQLite for large datasets ✅
79. **Add memory-mapped source scanning** — Use `memmap2` for large source files ✅
80. **Add glob-based source filtering** — Configurable include/exclude patterns for source files ✅
81. **Add scan timeout** — Configurable timeout for scan operations ✅
82. **Add progress reporting** — Real-time progress bar with `indicatif` for large projects ✅
83. **Add monorepo support** — Scan multiple sub-projects with separate manifests ✅
84. **Add Docker image** — Official `ghcr.io/pledgeandgrow/pledgerecon` Docker image ✅
85. **Add WASM-based scan engine** — Compile PledgeRecon core to WASM for browser/edge scanning ✅

## Phase 8: Enterprise & Ecosystem (Goals 86–100)

87. **Add license compliance checking** — Check dependency licenses against allow/deny lists ✅
88. **Add SLSA provenance verification** — Verify SLSA provenance of dependencies ✅
89. **Add sigstore verification** — Verify dependency signatures via sigstore/cosign ✅
90. **Add SBOM diff** — Compare two SBOMs to show added/removed/changed components ✅
91. **Add VEX (Vulnerability Exploitability eXchange) output** — Generate VEX documents ✅
92. **Add dependency pinning enforcement** — Flag unpinned or floating version dependencies ✅
93. **Add registry mirroring support** — Work with private registry mirrors (Artifactory, Nexus) ✅
94. **Add air-gapped mode** — Fully offline operation with pre-bundled advisory database ✅
95. **Add multi-tenant scan profiles** — Different scan configs per team/project in monorepo ✅
96. **Add REST API server** — Long-running PledgeRecon daemon with REST API for scans ✅
97. **Add GraphQL API** — Query scan results, findings, and advisories via GraphQL ✅
98. **Add Web UI dashboard** — Web-based dashboard for scan results and trends ✅
99. **Add webhook integration** — Trigger webhooks on new vulnerability findings ✅

## Phase 9: Container & Cloud-Native Security (Goals 101–110)

101. ✅ **Add container image scanning** — Scan Docker/OCI container images for OS-level package vulnerabilities (Debian, Ubuntu, Alpine, Amazon Linux)
102. ✅ **Add layer-aware container scanning** — Identify which container image layer introduced each vulnerability for precise remediation
103. ✅ **Add base image identification** — Detect and report the base image (`FROM` line) and its vulnerability profile separately from application dependencies
104. ✅ **Add Dockerfile analysis** — Scan Dockerfiles for security best practices (root user, privileged, no health check, large image, secrets in ENV)
105. ✅ **Add Kubernetes manifest scanning** — Scan K8s manifests for CIS benchmarks and misconfigurations (privileged pods, hostPath, root user, missing resource limits)
106. ✅ **Add Helm chart scanning** — Parse and scan Helm charts for template-level misconfigurations and embedded dependency vulnerabilities
107. ✅ **Add Terraform IaC scanning** — Scan Terraform plans for cloud misconfigurations (open S3 buckets, 0.0.0.0/0 security groups, unencrypted resources)
108. ✅ **Add CloudFormation IaC scanning** — Scan CloudFormation templates for AWS misconfigurations and CIS benchmark violations
109. ✅ **Add container registry sync** — Continuously monitor ECR/GCR/Docker Hub registries for new vulnerabilities in stored images without manual re-scan
110. ✅ **Add OCI artifact attestation verification** — Verify cosign-signed in-toto attestations (SLSA provenance, SBOM, scan results) attached to OCI images

## Phase 10: Advanced Reachability & Code Analysis (Goals 111–120)

111. ✅ **Add data flow analysis** — Track tainted data from sources to sinks (e.g. user input → SQL query) for detecting injection vulnerabilities in first-party code
112. ✅ **Add taint tracking for JS/TS** — Tree-sitter-based taint analysis for JavaScript/TypeScript source code (XSS, SQLi, command injection)
113. ✅ **Add taint tracking for Python** — Taint analysis for Python source code (SSRF, path traversal, deserialization)
114. ✅ **Add taint tracking for Rust** — Taint analysis for Rust source code (unsafe blocks, FFI boundaries)
115. ✅ **Add cross-language call resolution** — Resolve calls across language boundaries (e.g. Node.js native addon → Rust, Python → C bindings)
116. ✅ **Add framework-aware reachability** — Understand framework entry points (Express routes, Django views, Spring controllers, Actix handlers) as taint sources
117. ✅ **Add conditional reachability** — Track reachability through conditional branches (if/else, feature flags) for more precise confidence scoring
118. ✅ **Add reachability for C/C++ vendored code** — Parse and analyze vendored C/C++ source for call graph construction (like OSV-Scanner)
119. ✅ **Add interprocedural analysis** — Whole-program interprocedural call graph construction for more accurate reachability across function boundaries
120. ✅ **Add reachability caching with content-addressable storage** — Cache reachability results by file content hash in a content-addressable store (CAS) for incremental analysis

## Phase 11: Secret Detection & Hardening (Goals 121–130)

121. ✅ **Add secret scanning** — Detect hardcoded secrets (API keys, tokens, passwords, private keys) in source code and config files
122. ✅ **Add secret scanning in container images** — Scan container image filesystems for leaked secrets in environment variables, config files, and layer history
123. ✅ **Add secret scanning in IaC** — Detect secrets in Terraform, CloudFormation, Kubernetes manifests, and Dockerfiles
124. ✅ **Add entropy-based secret detection** — High-entropy string detection for unknown secret formats
125. ✅ **Add secret verification** — Optionally verify detected secrets against provider APIs (AWS, GCP, GitHub) to confirm they are active
126. ✅ **Add custom secret patterns** — User-defined regex patterns for organization-specific secret formats via config or WASM plugins
127. ✅ **Add secret scanning in git history** — Scan git commit history for accidentally committed and later removed secrets
128. ✅ **Add .env file scanning** — Detect and flag `.env` files committed to repositories
129. ✅ **Add hardcoded credential detection in manifests** — Check dependency manifests for embedded credentials (registry tokens, auth blocks)
130. ✅ **Add secret rotation guidance** — Provide actionable remediation guidance for each detected secret (which service, how to rotate, how to revoke)

## Phase 12: Policy Engine & Compliance (Goals 131–140)

131. ✅ **Add OPA/Rego policy engine** — Evaluate scan results against Open Policy Agent Rego rules for custom compliance logic
132. ✅ **Add CIS benchmark compliance reporting** — Map findings to CIS benchmarks and generate compliance-ready reports
133. ✅ **Add SOC 2 compliance reporting** — Generate SOC 2-aligned reports for auditor consumption
134. ✅ **Add NIST SP 800-218 SSDF mapping** — Map PledgeRecon controls to NIST Secure Software Development Framework practices
135. ✅ **Add EU CRA compliance reporting** — Generate reports aligned with EU Cyber Resilience Act requirements (effective Dec 2027)
136. ✅ **Add ISO 27001 compliance mapping** — Map vulnerability findings to ISO 27001 control objectives
137. ✅ **Add PCI-DSS compliance reporting** — Generate PCI-DSS-aligned vulnerability reports for payment card industry compliance
138. ✅ **Add FedRAMP compliance reporting** — Generate FedRAMP-aligned reports for US federal cloud deployments
139. ✅ **Add custom compliance frameworks** — User-defined compliance frameworks with custom rule mappings via YAML/JSON config
140. ✅ **Add policy-as-code enforcement** — Enforce security policies as code in CI/CD with configurable fail/pass/warn outcomes per policy

## Phase 13: Remediation & Automation (Goals 141–150)

141. ✅ **Add guided remediation** — Suggest optimal upgrade paths considering dependency depth, transitive impact, and minimum disruption (like OSV-Scanner guided remediation)
142. ✅ **Add automated fix PR creation** — Create actual PRs via GitHub/GitLab API with upgraded versions and changelog summaries
143. ✅ **Add dependency override strategies** — Support npm `overrides`, Maven `<dependencyManagement>`, and pip `constraints.txt` for transitive dependency forcing
144. ✅ **Add base image upgrade recommendations** — Suggest safer/lighter base images for container scans (e.g. `python:3.12` → `python:3.12-slim` or distroless)
145. ✅ **Add remediation ROI scoring** — Score each fix by risk reduction vs. effort (number of transitive deps affected, breaking change likelihood)
146. ✅ **Add batch remediation** — Group multiple dependency upgrades into a single PR to reduce PR noise
147. ✅ **Add remediation dry-run mode** — Preview what changes would be made without applying them
148. ✅ **Add changelog-aware upgrade safety** — Fetch and analyze package changelogs to detect breaking changes before suggesting upgrades
149. ✅ **Add dependency deprecation detection** — Flag deprecated/unmaintained packages and suggest maintained alternatives
150. ✅ **Add auto-fix for IaC misconfigurations** — Automatically generate patched Terraform/K8s/Dockerfile with security fixes applied

## Phase 14: Ecosystem Expansion (Goals 151–160)

151. ✅ **Add Swift/Package.swift parsing** — Swift Package Manager ecosystem support for iOS/macOS projects
152. ✅ **Add Scala/sbt parsing** — Scala/sbt build definition parsing for JVM Scala ecosystem
153. ✅ **Add Kotlin/Gradle Kotlin DSL parsing** — Kotlin-specific Gradle build script parsing
154. ✅ **Add Elixir/mix.exs parsing** — Elixir/Hex ecosystem support
155. ✅ **Add Haskell/cabal parsing** — Haskell/Cabal and Stack ecosystem support
156. ✅ **Add R/DESCRIPTION parsing** — R/CRAN ecosystem support for statistical packages
157. ✅ **Add Erlang/rebar3 parsing** — Erlang/rebar3 ecosystem support
158. ✅ **Add Clojure/deps.edn parsing** — Clojure/Tools Deps ecosystem support
159. ✅ **Add Conan/Conanfile parsing** — C/C++ Conan package manager support
160. ✅ **Add Bazel/BUILD parsing** — Bazel build system dependency parsing for polyglot monorepos

## Phase 15: Intelligence & Prioritization (Goals 161–170)

161. ✅ **Add EPSS integration** — Incorporate Exploit Prediction Scoring System (EPSS) from FIRST for exploit likelihood scoring
162. ✅ **Add CISA KEV catalog** — Cross-reference findings against CISA Known Exploited Vulnerabilities catalog for critical prioritization
163. ✅ **Add exploit maturity detection** — Detect whether a public exploit exists (PoC, functional, weaponized) for each vulnerability
164. ✅ **Add risk-based prioritization scoring** — Composite score combining CVSS + EPSS + KEV + reachability + exploit maturity + business context
165. ✅ **Add age-based prioritization** — Factor vulnerability age into prioritization (newer = higher urgency for patching)
166. ✅ **Add business criticality tagging** — Allow tagging dependencies/packages by business criticality for weighted risk scoring
167. ✅ **Add exposure analysis** — Determine if a vulnerable component is network-facing, internet-exposed, or internal-only
168. ✅ **Add attack path visualization** — Visualize the attack path from external attacker to vulnerable function call
169. ✅ **Add threat intel feed integration** — Subscribe to and correlate with commercial threat intelligence feeds (Mandiant, Recorded Future)
170. ✅ **Add anomaly detection for dependency changes** — Detect suspicious dependency additions (typosquatting, sudden version jumps, new maintainers)

## Phase 16: Platform & Integrations (Goals 171–180)

171. ✅ **Add VS Code extension** — Real-time vulnerability highlighting and quick-fix suggestions in VS Code editor
172. ✅ **Add JetBrains plugin** — IntelliJ/PyCharm/GoLand/WebStorm plugin for in-IDE vulnerability scanning
173. ✅ **Add Jira integration** — Create Jira tickets for findings with severity, package, version, and fix info
174. ✅ **Add GitHub Issues integration** — Create GitHub issues for findings with labels and assignees
175. ✅ **Add Linear integration** — Create Linear issues for vulnerability findings
176. ✅ **Add Dependabot-compatible alert format** — Output in GitHub Dependabot alert format for native GitHub integration
177. ✅ **Add ServiceNow integration** — Create ServiceNow security incidents for enterprise ITSM workflows
178. ✅ **Add Splunk/ELK integration** — Export scan results as SIEM-ingestible events (CEF, LEEF, or JSON)
179. ✅ **Add PagerDuty integration** — Trigger PagerDuty incidents for critical-severity findings
180. ✅ **Add Discord notification** — Post-scan Discord webhook notifications for community/open-source projects

## Phase 17: Advanced LLM & AI (Goals 181–190)

181. ✅ **Add AI-powered remediation suggestions** — LLM-generated code patches for fixing vulnerabilities (not just version bumps, but actual code changes)
182. ✅ **Add AI vulnerability description enrichment** — LLM-generated plain-language explanations of vulnerabilities for non-security developers
183. ✅ **Add AI-powered false positive explanation** — LLM-generated explanations of why a finding is a false positive for audit trails
184. ✅ **Add local LLM auto-selection** — Automatically select the best available local model based on hardware capabilities (GPU, RAM)
185. ✅ **Add RAG-based vulnerability knowledge base** — Retrieval-augmented generation using a local vector DB of CVE descriptions, blog posts, and patch diffs
186. ✅ **Add AI-powered dependency question answering** — Natural language queries about project dependencies ("Which of our deps have known RCEs?")
187. ✅ **Add AI-powered policy generation** — Generate OPA/Rego policies from natural language descriptions of security requirements
188. ✅ **Add AI-powered commit message analysis** — Analyze git commit messages for security-relevant changes that should trigger re-scans
189. ✅ **Add multi-modal analysis** — Analyze screenshots of dashboards/reports and generate executive summaries via vision LLMs
190. ✅ **Add AI-powered triage fine-tuning pipeline** — Automated pipeline for collecting triage feedback and fine-tuning custom models

## Phase 18: Scale & Distribution (Goals 191–200)

191. ✅ **Add Homebrew formula** — `brew install pledgerecon` for macOS distribution
192. ✅ **Add Windows MSI installer** — Native Windows MSI installer with PATH configuration
193. ✅ **Add Linux .deb and .rpm packages** — Native packages for Debian/Ubuntu and RHEL/Fedora
194. ✅ **Add Nix flake** — Nix package manager support for reproducible installations
195. ✅ **Add Scoop manifest** — Windows Scoop package manager support
196. ✅ **Add pre-built binaries with cross-compilation** — GitHub Releases with pre-built static binaries for Linux (musl), macOS, Windows, and ARM64
197. ✅ **Add GitHub Action v2** — Next-gen GitHub Action with matrix scanning, SARIF upload, SBOM attestation, and PR review in one composite action
198. ✅ **Add scan result caching in CI** — Cache scan results keyed by lockfile hash to skip unchanged projects in matrix scans
199. ✅ **Add distributed scanning** — Coordinate scans across multiple machines for ultra-large monorepos (10k+ packages)
200. ✅ **Add scan result diffing across branches** — Compare scan results between PR branch and base branch to show only newly introduced vulnerabilities

## Milestone Summary

| Phase | Goals | Focus | Target |
|---|---|---|---|
| 1 | 1–20 | MVP hardening, more ecosystems, semver matching | v0.2.0 ✅ |
| 2 | 21–35 | Tree-sitter reachability, PledgePack integration | v0.3.0 ✅ |
| 3 | 36–45 | Advanced LLM triage, cost tracking, consensus | v0.4.0 ✅ |
| 4 | 46–55 | WASM plugin SDK, registry, signatures | v0.5.0 ✅ |
| 5 | 56–65 | Rich reporting, diff, trends, notifications | v0.6.0 ✅ |
| 6 | 66–75 | Deep CI/CD integration, auto-fix PRs, baselines | v0.7.0 ✅ |
| 7 | 76–85 | Performance, scale, Docker, monorepo | v0.8.0 ✅ |
| 8 | 86–100 | Enterprise: PledgeGuard, VEX, API, Web UI, Cloud | v1.0.0 ✅ |
| 9 | 101–110 | Container & cloud-native security | v1.1.0 ✅ |
| 10 | 111–120 | Advanced reachability & code analysis | v1.2.0 ✅ |
| 11 | 121–130 | Secret detection & hardening | v1.3.0 ✅ |
| 12 | 131–140 | Policy engine & compliance | v1.4.0 ✅ |
| 13 | 141–150 | Remediation & automation | v1.5.0 ✅ |
| 14 | 151–160 | Ecosystem expansion | v1.6.0 ✅ |
| 15 | 161–170 | Intelligence & prioritization | v1.7.0 ✅ |
| 16 | 171–180 | Platform & integrations | v1.8.0 ✅ |
| 17 | 181–190 | Advanced LLM & AI | v1.9.0 ✅ |
| 18 | 191–200 | Scale & distribution | v2.0.0 ✅ |
