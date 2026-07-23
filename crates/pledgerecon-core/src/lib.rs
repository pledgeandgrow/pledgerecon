//! PledgeRecon — Rust-native dependency vulnerability scanner.
//!
//! `pledgerecon-core` provides the scanning engine: an [`advisory::Advisory`]
//! database fetched from OSV/NVD/GHSA, a [`dependency::DependencyGraph`] built
//! from project manifests (Cargo.toml, package.json, go.mod, etc.), an
//! AST-based [`reachability::ReachabilityAnalyzer`] that determines whether
//! vulnerable functions are actually called in the dependency graph, an
//! [`sbom::SbomGenerator`] for SPDX/CycloneDX output, an LLM-powered
//! [`triage::TriageEngine`] for false-positive reduction, and a [`scanner::Scanner`]
//! that orchestrates the full scan pipeline.
//!
//! # Example
//!
//! ```
//! use pledgerecon_core::{scanner::Scanner, config::ScanConfig};
//! use std::path::Path;
//!
//! let config = ScanConfig::default();
//! let scanner = Scanner::new(config);
//! let report = scanner.scan(Path::new(".")).unwrap();
//! println!("Found {} vulnerabilities", report.findings.len());
//! ```

pub mod advisory;
pub mod ai;
pub mod ci;
pub mod ci_integration;
pub mod config;
pub mod container;
pub mod dependency;
pub mod distribution;
pub mod enterprise;
pub mod finding;
pub mod intelligence;
pub mod notify;
pub mod output;
pub mod performance;
pub mod platform;
pub mod plugin;
pub mod policy;
pub mod reachability;
pub mod remediation;
pub mod report;
pub mod sbom;
pub mod scanner;
pub mod secret;
pub mod taint;
pub mod tree_sitter_parser;
pub mod triage;
pub mod version;

pub use advisory::{
    Advisory, AdvisoryDatabase, AdvisoryId, AdvisoryRange, AdvisoryReference, AdvisorySeverity,
    DatabaseError,
};
pub use ai::{
    AiError, AiRemediationSuggestion, CodePatch, CommitAnalysis, EnrichedDescription,
    ExecutiveSummary, FineTuningDataset, FpExplanation, GeneratedPolicy, HardwareProfile,
    KnowledgeBase, KnowledgeEntry, LocalModel, QaAnswer, TriageFeedback, analyze_commit_message,
    answer_dependency_question, build_rag_prompt, enrich_description, explain_false_positive,
    generate_ai_remediation, generate_executive_summary, generate_policy, select_local_model,
};
pub use ci_integration::{
    AutoFixSuggestion, BaselineComparison, CheckAnnotation, CheckOutput, CiIntegrationError,
    build_github_check, compare_with_baseline, generate_autofix_pr_body,
    generate_autofix_suggestions, save_baseline, to_sarif_with_annotations,
};
pub use config::TriageConfig;
pub use config::{ConfigError, ScanConfig, load_config};
pub use container::{
    AppDependency, Attestation, AttestationVerificationResult, BaseImageInfo, CloudFormationIssue,
    ContainerError, ContainerImage, ContainerScanResult, ContainerScanSummary,
    ContainerVulnerability, DiscoveredImage, DockerfileIssue, DockerfileIssueSeverity, HelmIssue,
    ImageLayer, K8sIssue, K8sIssueSeverity, LinuxDistro, OsPackage, RegistryConfig,
    RegistrySyncResult, RegistryType, TerraformIssue, TerraformIssueSeverity, analyze_dockerfile,
    assign_vulnerabilities_to_layers, discover_registry_images, identify_base_image,
    parse_dockerfile_layers, scan_cloudformation, scan_container_image, scan_helm_chart,
    scan_k8s_manifest, scan_terraform, separate_base_and_app_vulnerabilities, verify_attestations,
};
pub use dependency::{
    Dependency, DependencyGraph, DependencyKind, ManifestParseError, ManifestParser,
};
pub use distribution::{
    CrossTarget, DistributionError, ScanCache, ScanDiff, ScanDiffSummary, ScanPartition,
    compute_cache_key, cross_compilation_matrix, debian_control, diff_scan_results,
    diff_to_markdown, github_action_v2, homebrew_formula, is_cache_valid, load_scan_cache,
    merge_scan_results, nix_flake, partition_scan, rpm_spec, save_scan_cache, scoop_manifest,
    wix_config,
};
pub use enterprise::{
    AirGappedConfig, ApiEndpoint, EnterpriseError, LicenseFinding, LicensePolicy, LicenseStatus,
    MultiTenantConfig, PinningFinding, PinningViolation, ProvenanceResult, RegistryMirror,
    RegistryMirrorConfig, RestApiConfig, SbomComponent, SbomComponentChange, SbomDiff,
    SbomDiffSummary, ScanProfile, SignatureAttestation, SignatureResult, SlsaLevel, SlsaProvenance,
    VexDocument, VexStatement, VexStatus, WebhookConfig, WebhookEvent, api_endpoints,
    build_webhook_payload, check_dependency_pinning, check_license_compliance, dashboard_html,
    diff_sboms, generate_bundle_script, generate_openapi_spec, generate_vex, graphql_schema,
    sbom_diff_to_text, send_webhook, verify_air_gapped, verify_signatures, verify_slsa_provenance,
    vex_to_json,
};
pub use finding::{Finding, FindingStatus, ReachabilityStatus, VulnerabilitySeverity};
pub use intelligence::{
    AnomalyType, AttackPath, AttackPathEdge, AttackPathNode, AttackPathNodeType,
    BusinessCriticality, CriticalityRegistry, CriticalityTag, DependencyAnomaly, EpssScore,
    ExploitMaturity, ExposureLevel, IntelligenceError, KevCatalog, KevEntry, RiskScore,
    ThreatIntelCorrelation, ThreatIntelEntry, ThreatIntelFeed, age_urgency_multiplier,
    analyze_exposure, attack_path_to_dot, build_attack_path, calculate_risk_score,
    correlate_threat_intel, detect_recently_published, detect_typosquatting, detect_version_jump,
    prioritize_findings, vulnerability_age_days,
};
pub use notify::{EmailReport, NotifyError, SlackNotification, TeamsNotification};
pub use output::{
    OutputFormat, to_gitlab_code_quality, to_html, to_json, to_junit_xml, to_markdown, to_pdf,
    to_sarif, to_sonarqube, to_text,
};
pub use performance::{
    AdvisoryStore, DEFAULT_MMAP_THRESHOLD, IncrementalResult, MonorepoSubProject, PerformanceError,
    ProgressReporter, ScanState, SourceFilter, TimeoutConfig, check_timeout,
    detect_changed_manifests, discover_subprojects, dockerfile_content, dockerignore_content,
    fetch_advisories_parallel, load_scan_state, read_source_file, save_scan_state, scan_monorepo,
    wasm_build_config, wasm_js_wrapper, with_timeout,
};
pub use platform::{
    CefEvent, DependabotAlert, DependabotPackage, DependabotVulnerability, DiscordNotification,
    GitHubIssue, JetBrainsInspection, JiraIssue, LinearIssue, PagerDutyEvent, PagerDutyPayload,
    PlatformError, ServiceNowIncident, VsCodeDiagnostic, VsCodeSeverity, cef_to_string,
    create_github_issues, create_jira_issues, create_linear_issues, create_pagerduty_events,
    create_servicenow_incidents, generate_jetbrains_inspections, generate_vscode_diagnostics,
    to_cef_events, to_dependabot_alerts,
};
pub use plugin::{
    PluginError, PluginRegistry, PluginRegistryEntry, WasmRule, load_plugins,
    load_plugins_with_config, run_plugins_parallel,
};
pub use policy::{
    CisComplianceReport, CisControl, ComplianceStatus, CraReport, CraRequirement, CustomControl,
    CustomControlResult, CustomFramework, CustomFrameworkReport, EnforcementAction,
    EnforcementConfig, EnforcementResult, FedrampControl, FedrampReport, Iso27001Control,
    Iso27001Report, PciDssReport, PciDssRequirement, PolicyError, PolicyOutcome, PolicyResult,
    PolicyRule, PolicySet, Soc2Control, Soc2Report, SsdfPractice, SsdfReport, SsdfTask,
    enforce_policies, evaluate_custom_framework, evaluate_policies, generate_cis_report,
    generate_cra_report, generate_fedramp_report, generate_iso27001_report,
    generate_pci_dss_report, generate_soc2_report, generate_ssdf_report, load_custom_framework,
    load_policy_set,
};
pub use reachability::{
    CallGraph, ReachabilityAnalyzer, ReachabilityResult, ReachabilityStatus as ReachStatus,
};
pub use remediation::{
    BaseImageRecommendation, BatchRemediation, ChangelogAnalysis, DeprecationStatus,
    DisruptionLevel, DryRunChange, DryRunResult, FileChange, FixPRRequest, IacAutoFix, IacFinding,
    OverrideStrategy, RemediationError, RemediationPriority, RemediationRoi, RemediationSuggestion,
    UpgradeStep, analyze_changelog, auto_fix_iac, batch_remediation, check_all_deprecations,
    check_deprecation, create_fix_pr, dry_run_remediation, generate_override, guided_remediation,
    recommend_base_image, score_remediation_roi,
};
pub use report::{
    DiffReport, ReportError, ReportSummary, TrendDirection, TrendPoint, TrendTracker,
};
pub use sbom::{SbomError, SbomFormat, SbomGenerator};
pub use scanner::{ScanError, ScanReport, Scanner};
pub use secret::{
    ContainerLayer, GitCommitContent, IaCKind, ManifestKind, ManifestToScan, RotationGuidance,
    SecretError, SecretFinding, SecretLocation, SecretPattern, SecretScanResult, SecretSeverity,
    SecretType, VerificationResult, builtin_patterns, detect_high_entropy, load_custom_patterns,
    load_custom_patterns_yaml, rotation_guidance, rotation_guidance_for_scan,
    scan_container_secrets, scan_env_files, scan_git_history, scan_iac_files, scan_manifests,
    scan_source_code, secret_scan_report, shannon_entropy, verify_secrets,
};
pub use taint::{
    BranchPath, CFunction, ConditionalBranch, ConditionalReachabilityResult, CrossLanguageCall,
    FrameworkEntry, InterproceduralNode, JsTaintResult, PythonTaintResult, ReachabilityCache,
    RustTaintResult, Sanitizer, TaintAnalyzer, TaintError, TaintFlow, TaintSink, TaintSource,
    TaintStep, analyze_conditional_reachability, analyze_javascript, analyze_python, analyze_rust,
    build_c_call_graph, build_interprocedural_graph, detect_cross_language_calls,
    detect_framework_entries, find_interprocedural_paths, framework_entry_points, parse_c_source,
    resolve_cross_language,
};
pub use triage::{
    AuditLogEntry, CostReport, TokenUsage, TriageEngine, TriageResult, TriageVerdict,
};
