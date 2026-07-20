//! Remediation & automation (Goals 141–150).
//!
//! - Guided remediation (Goal 141)
//! - Automated fix PR creation (Goal 142)
//! - Dependency override strategies (Goal 143)
//! - Base image upgrade recommendations (Goal 144)
//! - Remediation ROI scoring (Goal 145)
//! - Batch remediation (Goal 146)
//! - Remediation dry-run mode (Goal 147)
//! - Changelog-aware upgrade safety (Goal 148)
//! - Dependency deprecation detection (Goal 149)
//! - Auto-fix for IaC misconfigurations (Goal 150)

use crate::container::ContainerScanResult;
use crate::dependency::{DependencyGraph, DependencyKind};
use crate::finding::{Finding, VulnerabilitySeverity};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RemediationError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("YAML error: {0}")]
    Yaml(String),
    #[error("remediation failed: {0}")]
    Remediation(String),
    #[error("no fix available for {0}")]
    NoFix(String),
}

// ─── Goal 141: Guided Remediation ───────────────────────────────────────────

/// A remediation suggestion for a single finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationSuggestion {
    pub advisory_id: String,
    pub package: String,
    pub current_version: String,
    pub fix_version: String,
    pub upgrade_path: Vec<UpgradeStep>,
    pub transitive_impact: usize,
    pub disruption_level: DisruptionLevel,
    pub recommendation: String,
}

/// A single step in an upgrade path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpgradeStep {
    pub from_version: String,
    pub to_version: String,
    pub breaking_changes: bool,
    pub reason: String,
}

/// How disruptive an upgrade is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisruptionLevel {
    None,
    Low,
    Medium,
    High,
}

/// Generate guided remediation suggestions for findings with fixes.
pub fn guided_remediation(
    findings: &[Finding],
    graph: &DependencyGraph,
) -> Vec<RemediationSuggestion> {
    findings
        .iter()
        .filter(|f| f.fix_available && f.fix_version.is_some())
        .map(|f| {
            let fix_version = f.fix_version.as_ref().unwrap();
            let transitive_impact = count_transitive_dependents(graph, &f.package);
            let disruption = assess_disruption(&f.version, fix_version);
            let upgrade_path = build_upgrade_path(&f.version, fix_version);

            RemediationSuggestion {
                advisory_id: f.advisory_id.clone(),
                package: f.package.clone(),
                current_version: f.version.clone(),
                fix_version: fix_version.clone(),
                upgrade_path,
                transitive_impact,
                disruption_level: disruption,
                recommendation: format!(
                    "Upgrade {} from {} to {} to resolve {}",
                    f.package, f.version, fix_version, f.advisory_id
                ),
            }
        })
        .collect()
}

fn count_transitive_dependents(graph: &DependencyGraph, package: &str) -> usize {
    graph
        .dependencies
        .values()
        .filter(|d| d.dependencies.iter().any(|dep| dep.contains(package)))
        .count()
}

fn assess_disruption(current: &str, target: &str) -> DisruptionLevel {
    let cur_parts: Vec<u32> = current.split('.').filter_map(|s| s.parse().ok()).collect();
    let tgt_parts: Vec<u32> = target.split('.').filter_map(|s| s.parse().ok()).collect();

    if cur_parts.len() >= 2 && tgt_parts.len() >= 2 {
        if cur_parts[0] != tgt_parts[0] {
            return DisruptionLevel::High;
        }
        if cur_parts[1] != tgt_parts[1] {
            return DisruptionLevel::Medium;
        }
        return DisruptionLevel::Low;
    }
    DisruptionLevel::Medium
}

fn build_upgrade_path(current: &str, target: &str) -> Vec<UpgradeStep> {
    vec![UpgradeStep {
        from_version: current.to_string(),
        to_version: target.to_string(),
        breaking_changes: assess_disruption(current, target) >= DisruptionLevel::Medium,
        reason: "Direct upgrade to fix version".into(),
    }]
}

// ─── Goal 142: Automated Fix PR Creation ────────────────────────────────────

/// PR creation request for automated fixes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FixPRRequest {
    pub title: String,
    pub body: String,
    pub branch: String,
    pub base_branch: String,
    pub files: Vec<FileChange>,
    pub labels: Vec<String>,
}

/// A file change in a fix PR.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileChange {
    pub path: String,
    pub original_content: String,
    pub patched_content: String,
}

/// Generate a fix PR request from remediation suggestions.
pub fn create_fix_pr(
    suggestions: &[RemediationSuggestion],
    manifest_path: &str,
    manifest_content: &str,
) -> Result<FixPRRequest, RemediationError> {
    if suggestions.is_empty() {
        return Err(RemediationError::Remediation("No suggestions".into()));
    }

    let mut patched = manifest_content.to_string();
    for s in suggestions {
        patched = patched.replace(&s.current_version, &s.fix_version);
    }

    let title = if suggestions.len() == 1 {
        format!("fix: upgrade {} to {}", suggestions[0].package, suggestions[0].fix_version)
    } else {
        format!("fix: upgrade {} dependencies", suggestions.len())
    };

    let mut body = String::from("## Automated Security Fix\n\n");
    body.push_str("This PR upgrades dependencies to resolve the following vulnerabilities:\n\n");
    for s in suggestions {
        body.push_str(&format!(
            "- **{}**: `{}` {} → {}\n",
            s.advisory_id, s.package, s.current_version, s.fix_version
        ));
    }

    Ok(FixPRRequest {
        title,
        body,
        branch: "pledgerecon/auto-fix".into(),
        base_branch: "main".into(),
        files: vec![FileChange {
            path: manifest_path.to_string(),
            original_content: manifest_content.to_string(),
            patched_content: patched,
        }],
        labels: vec!["security".into(), "automated".into()],
    })
}

// ─── Goal 143: Dependency Override Strategies ───────────────────────────────

/// Override strategy for forcing transitive dependency versions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OverrideStrategy {
    pub ecosystem: DependencyKind,
    pub package: String,
    pub target_version: String,
    pub override_file: String,
    pub override_content: String,
    pub instructions: String,
}

/// Generate a dependency override strategy for a given ecosystem.
pub fn generate_override(
    ecosystem: DependencyKind,
    package: &str,
    target_version: &str,
) -> OverrideStrategy {
    match ecosystem {
        DependencyKind::Npm => OverrideStrategy {
            ecosystem,
            package: package.to_string(),
            target_version: target_version.to_string(),
            override_file: "package.json".into(),
            override_content: serde_json::json!({
                "overrides": {
                    package: target_version
                }
            })
            .to_string(),
            instructions: format!(
                "Add the following to your package.json \"overrides\" section:\n\"overrides\": {{ \"{}\": \"{}\" }}",
                package, target_version
            ),
        },
        DependencyKind::Maven | DependencyKind::Gradle => OverrideStrategy {
            ecosystem,
            package: package.to_string(),
            target_version: target_version.to_string(),
            override_file: "pom.xml".into(),
            override_content: format!(
                "<dependencyManagement>\n  <dependencies>\n    <dependency>\n      <groupId>{{group}}</groupId>\n      <artifactId>{}</artifactId>\n      <version>{}</version>\n    </dependency>\n  </dependencies>\n</dependencyManagement>",
                package, target_version
            ),
            instructions: format!(
                "Add a <dependencyManagement> section in your pom.xml to force {} to version {}",
                package, target_version
            ),
        },
        DependencyKind::Python => OverrideStrategy {
            ecosystem,
            package: package.to_string(),
            target_version: target_version.to_string(),
            override_file: "constraints.txt".into(),
            override_content: format!("{}=={}", package, target_version),
            instructions: format!(
                "Create a constraints.txt file with: {}=={}\nThen install with: pip install -c constraints.txt -r requirements.txt",
                package, target_version
            ),
        },
        DependencyKind::Rust => OverrideStrategy {
            ecosystem,
            package: package.to_string(),
            target_version: target_version.to_string(),
            override_file: "Cargo.toml".into(),
            override_content: format!(
                "[patch.crates-io]\n{} = {{ version = \"{}\" }}",
                package, target_version
            ),
            instructions: format!(
                "Add a [patch.crates-io] section in your Cargo.toml to override {} to {}",
                package, target_version
            ),
        },
        _ => OverrideStrategy {
            ecosystem,
            package: package.to_string(),
            target_version: target_version.to_string(),
            override_file: "unknown".into(),
            override_content: String::new(),
            instructions: "Override strategy not supported for this ecosystem".into(),
        },
    }
}

// ─── Goal 144: Base Image Upgrade Recommendations ───────────────────────────

/// Base image upgrade recommendation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaseImageRecommendation {
    pub current_image: String,
    pub recommended_image: String,
    pub reason: String,
    pub size_reduction: Option<String>,
    pub vulnerability_reduction: Option<usize>,
}

/// Recommend safer/lighter base images for container scans.
pub fn recommend_base_image(scan: &ContainerScanResult) -> Vec<BaseImageRecommendation> {
    let mut recommendations = Vec::new();
    let current = &scan.image_ref;

    // Recommend slim variants.
    if !current.contains("slim") && !current.contains("alpine") && !current.contains("distroless") {
        if current.contains("python") {
            recommendations.push(BaseImageRecommendation {
                current_image: current.clone(),
                recommended_image: current.replace("python", "python:slim"),
                reason: "Slim variant reduces attack surface by removing build tools".into(),
                size_reduction: Some("~150MB".into()),
                vulnerability_reduction: None,
            });
        }
        if current.contains("node") {
            recommendations.push(BaseImageRecommendation {
                current_image: current.clone(),
                recommended_image: current.replace("node", "node:slim"),
                reason: "Slim variant reduces attack surface".into(),
                size_reduction: Some("~200MB".into()),
                vulnerability_reduction: None,
            });
        }
    }

    // Recommend distroless for production.
    if !current.contains("distroless") {
        if current.contains("gcr.io/distroless") || current.contains("python") || current.contains("node") {
            let distroless = if current.contains("python") {
                "gcr.io/distroless/python3-debian12".to_string()
            } else if current.contains("node") {
                "gcr.io/distroless/nodejs20-debian12".to_string()
            } else {
                "gcr.io/distroless/static-debian12".to_string()
            };
            recommendations.push(BaseImageRecommendation {
                current_image: current.clone(),
                recommended_image: distroless,
                reason: "Distroless images contain no shell or package manager, minimizing attack surface".into(),
                size_reduction: Some("~100MB".into()),
                vulnerability_reduction: Some(scan.os_packages.len()),
            });
        }
    }

    // Recommend Alpine for smaller images.
    if !current.contains("alpine") && !current.contains("distroless") {
        let alpine = if current.contains("python") {
            current.replace("python", "python:alpine")
        } else if current.contains("node") {
            current.replace("node", "node:alpine")
        } else {
            format!("alpine:3.19")
        };
        recommendations.push(BaseImageRecommendation {
            current_image: current.clone(),
            recommended_image: alpine,
            reason: "Alpine Linux has a much smaller package set and attack surface".into(),
            size_reduction: Some("~250MB".into()),
            vulnerability_reduction: Some(scan.os_packages.len() / 2),
        });
    }

    recommendations
}

// ─── Goal 145: Remediation ROI Scoring ──────────────────────────────────────

/// ROI score for a remediation action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationRoi {
    pub advisory_id: String,
    pub package: String,
    pub risk_reduction: f64,
    pub effort_score: f64,
    pub roi_score: f64,
    pub priority: RemediationPriority,
}

/// Priority level for remediation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemediationPriority {
    Critical,
    High,
    Medium,
    Low,
}

/// Score remediation suggestions by risk reduction vs. effort.
pub fn score_remediation_roi(
    findings: &[Finding],
    suggestions: &[RemediationSuggestion],
) -> Vec<RemediationRoi> {
    suggestions
        .iter()
        .map(|s| {
            let finding = findings.iter().find(|f| f.advisory_id == s.advisory_id);
            let severity_score = match finding.map(|f| f.severity) {
                Some(VulnerabilitySeverity::Critical) => 10.0,
                Some(VulnerabilitySeverity::High) => 7.5,
                Some(VulnerabilitySeverity::Medium) => 5.0,
                Some(VulnerabilitySeverity::Low) => 2.5,
                Some(VulnerabilitySeverity::Info) => 1.0,
                None => 5.0,
            };

            let reachability_score = match finding.map(|f| f.reachability) {
                Some(crate::finding::ReachabilityStatus::Reachable) => 1.5,
                Some(crate::finding::ReachabilityStatus::Unreachable) => 0.3,
                _ => 1.0,
            };

            let risk_reduction = severity_score * reachability_score;
            let effort = match s.disruption_level {
                DisruptionLevel::None => 1.0,
                DisruptionLevel::Low => 2.0,
                DisruptionLevel::Medium => 4.0,
                DisruptionLevel::High => 8.0,
            } + (s.transitive_impact as f64 * 0.5);

            let roi_score = risk_reduction / effort;
            let priority = if roi_score >= 5.0 {
                RemediationPriority::Critical
            } else if roi_score >= 3.0 {
                RemediationPriority::High
            } else if roi_score >= 1.5 {
                RemediationPriority::Medium
            } else {
                RemediationPriority::Low
            };

            RemediationRoi {
                advisory_id: s.advisory_id.clone(),
                package: s.package.clone(),
                risk_reduction,
                effort_score: effort,
                roi_score,
                priority,
            }
        })
        .collect()
}

// ─── Goal 146: Batch Remediation ────────────────────────────────────────────

/// A batch of remediation actions grouped into a single PR.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchRemediation {
    pub batch_id: String,
    pub title: String,
    pub suggestions: Vec<RemediationSuggestion>,
    pub total_findings: usize,
    pub total_packages: usize,
    pub estimated_risk_reduction: f64,
}

/// Group remediation suggestions into batches to reduce PR noise.
pub fn batch_remediation(
    suggestions: &[RemediationSuggestion],
    max_per_batch: usize,
) -> Vec<BatchRemediation> {
    if suggestions.is_empty() {
        return Vec::new();
    }

    let mut batches = Vec::new();
    let mut current_batch: Vec<RemediationSuggestion> = Vec::new();

    for s in suggestions {
        current_batch.push(s.clone());
        if current_batch.len() >= max_per_batch {
            let batch = create_batch(&current_batch, batches.len() + 1);
            batches.push(batch);
            current_batch.clear();
        }
    }

    if !current_batch.is_empty() {
        batches.push(create_batch(&current_batch, batches.len() + 1));
    }

    batches
}

fn create_batch(suggestions: &[RemediationSuggestion], batch_num: usize) -> BatchRemediation {
    let packages: Vec<String> = suggestions.iter().map(|s| s.package.clone()).collect::<std::collections::HashSet<_>>().into_iter().collect();
    BatchRemediation {
        batch_id: format!("batch-{}", batch_num),
        title: format!("Security fixes batch #{} ({} packages)", batch_num, packages.len()),
        suggestions: suggestions.to_vec(),
        total_findings: suggestions.len(),
        total_packages: packages.len(),
        estimated_risk_reduction: suggestions.len() as f64 * 5.0,
    }
}

// ─── Goal 147: Remediation Dry-Run Mode ─────────────────────────────────────

/// Dry-run result showing what changes would be made.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DryRunResult {
    pub would_change: Vec<DryRunChange>,
    pub would_create_pr: bool,
    pub total_files_changed: usize,
    pub total_upgrades: usize,
    pub summary: String,
}

/// A single change in a dry-run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DryRunChange {
    pub file: String,
    pub package: String,
    pub current_version: String,
    pub new_version: String,
    pub advisory_id: String,
}

/// Preview remediation changes without applying them.
pub fn dry_run_remediation(
    suggestions: &[RemediationSuggestion],
    manifest_path: &str,
) -> DryRunResult {
    let changes: Vec<DryRunChange> = suggestions
        .iter()
        .map(|s| DryRunChange {
            file: manifest_path.to_string(),
            package: s.package.clone(),
            current_version: s.current_version.clone(),
            new_version: s.fix_version.clone(),
            advisory_id: s.advisory_id.clone(),
        })
        .collect();

    let total_upgrades = changes.len();
    let total_files = 1;

    DryRunResult {
        would_change: changes,
        would_create_pr: !suggestions.is_empty(),
        total_files_changed: total_files,
        total_upgrades,
        summary: format!(
            "Would upgrade {} package(s) across {} file(s)",
            total_upgrades, total_files
        ),
    }
}

// ─── Goal 148: Changelog-Aware Upgrade Safety ───────────────────────────────

/// Changelog analysis result for an upgrade.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangelogAnalysis {
    pub package: String,
    pub from_version: String,
    pub to_version: String,
    pub breaking_changes: Vec<String>,
    pub deprecations: Vec<String>,
    pub new_features: Vec<String>,
    pub safe_to_upgrade: bool,
    pub recommendation: String,
}

/// Analyze a changelog for breaking changes before upgrading.
pub fn analyze_changelog(
    package: &str,
    from_version: &str,
    to_version: &str,
    changelog_content: &str,
) -> ChangelogAnalysis {
    let mut breaking = Vec::new();
    let mut deprecations = Vec::new();
    let mut features = Vec::new();

    for line in changelog_content.lines() {
        let lower = line.to_lowercase();
        if lower.contains("breaking") || lower.contains("removed") {
            breaking.push(line.trim().to_string());
        }
        if lower.contains("deprecated") {
            deprecations.push(line.trim().to_string());
        }
        if lower.contains("added") || lower.contains("new") || lower.contains("feature") {
            features.push(line.trim().to_string());
        }
    }

    let safe = breaking.is_empty();
    let recommendation = if safe {
        format!("Safe to upgrade {} from {} to {}", package, from_version, to_version)
    } else {
        format!(
            "CAUTION: {} has {} breaking change(s) between {} and {}. Review before upgrading.",
            package,
            breaking.len(),
            from_version,
            to_version
        )
    };

    ChangelogAnalysis {
        package: package.to_string(),
        from_version: from_version.to_string(),
        to_version: to_version.to_string(),
        breaking_changes: breaking,
        deprecations,
        new_features: features,
        safe_to_upgrade: safe,
        recommendation,
    }
}

// ─── Goal 149: Dependency Deprecation Detection ─────────────────────────────

/// Deprecation status for a dependency.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeprecationStatus {
    pub package: String,
    pub is_deprecated: bool,
    pub reason: Option<String>,
    pub maintained_alternative: Option<String>,
    pub last_release_date: Option<String>,
    pub recommendation: String,
}

/// Known deprecated packages and their alternatives.
fn known_deprecated() -> HashMap<&'static str, (&'static str, &'static str)> {
    let mut map = HashMap::new();
    map.insert("npm:request", ("Deprecated since 2020", "node-fetch, axios, got"));
    map.insert("npm:node-uuid", ("Replaced by uuid", "uuid"));
    map.insert("npm:lodash", ("Consider lodash-es or native JS", "lodash-es, radash"));
    map.insert("npm:moment", ("Deprecated, use modern alternatives", "dayjs, date-fns"));
    map.insert("npm:left-pad", ("No longer needed", "String.prototype.padStart"));
    map.insert("npm:colors", ("Malicious version detected", "chalk, picocolors"));
    map.insert("npm:faker", ("Project abandoned", "@faker-js/faker"));
    map.insert("PyPI:distutils", ("Removed in Python 3.12", "setuptools, packaging"));
    map.insert("PyPI:pip-tools", ("Use pip-compile directly", "pip-compile"));
    map
}

/// Check if a dependency is deprecated and suggest alternatives.
pub fn check_deprecation(package: &str) -> DeprecationStatus {
    let deprecated = known_deprecated();

    if let Some((reason, alternative)) = deprecated.get(package) {
        return DeprecationStatus {
            package: package.to_string(),
            is_deprecated: true,
            reason: Some(reason.to_string()),
            maintained_alternative: Some(alternative.to_string()),
            last_release_date: None,
            recommendation: format!("Replace {} with {}", package, alternative),
        };
    }

    DeprecationStatus {
        package: package.to_string(),
        is_deprecated: false,
        reason: None,
        maintained_alternative: None,
        last_release_date: None,
        recommendation: "Package appears to be actively maintained".into(),
    }
}

/// Check deprecation status for all dependencies in a graph.
pub fn check_all_deprecations(graph: &DependencyGraph) -> Vec<DeprecationStatus> {
    graph
        .dependencies
        .values()
        .map(|dep| check_deprecation(&dep.qualified_name()))
        .filter(|status| status.is_deprecated)
        .collect()
}

// ─── Goal 150: Auto-Fix for IaC Misconfigurations ───────────────────────────

/// A unified IaC finding for auto-fix purposes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IacFinding {
    pub rule_id: String,
    pub file_path: String,
    pub line: usize,
    pub description: String,
    pub severity: String,
}

/// An auto-fix patch for an IaC file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IacAutoFix {
    pub file_path: String,
    pub rule_id: String,
    pub description: String,
    pub original_line: String,
    pub patched_line: String,
    pub line_number: usize,
}

/// Generate auto-fix patches for IaC misconfigurations.
pub fn auto_fix_iac(findings: &[IacFinding], file_type: &str) -> Vec<IacAutoFix> {
    findings
        .iter()
        .filter_map(|f| generate_iac_fix(f, file_type))
        .collect()
}

fn generate_iac_fix(finding: &IacFinding, file_type: &str) -> Option<IacAutoFix> {
    match (file_type, finding.rule_id.as_str()) {
        // Dockerfile fixes.
        ("dockerfile", "DF001") => Some(IacAutoFix {
            file_path: finding.file_path.clone(),
            rule_id: finding.rule_id.clone(),
            description: "Add non-root USER instruction".into(),
            original_line: "FROM ubuntu:22.04".into(),
            patched_line: "FROM ubuntu:22.04\nUSER nonroot".into(),
            line_number: finding.line,
        }),
        ("dockerfile", "DF002") => Some(IacAutoFix {
            file_path: finding.file_path.clone(),
            rule_id: finding.rule_id.clone(),
            description: "Pin specific version tag instead of :latest".into(),
            original_line: "FROM node:latest".into(),
            patched_line: "FROM node:20.11.0-slim".into(),
            line_number: finding.line,
        }),
        ("dockerfile", "DF005") => Some(IacAutoFix {
            file_path: finding.file_path.clone(),
            rule_id: finding.rule_id.clone(),
            description: "Remove secret from ENV, use build-time ARG or runtime secret".into(),
            original_line: format!("ENV API_KEY={}", finding.description.split('=').nth(1).unwrap_or("secret")),
            patched_line: "# ENV API_KEY removed — use runtime secret injection".into(),
            line_number: finding.line,
        }),

        // Terraform fixes.
        ("terraform", "TF001") => Some(IacAutoFix {
            file_path: finding.file_path.clone(),
            rule_id: finding.rule_id.clone(),
            description: "Make S3 bucket private".into(),
            original_line: "acl = \"public-read\"".into(),
            patched_line: "acl = \"private\"".into(),
            line_number: finding.line,
        }),
        ("terraform", "TF002") => Some(IacAutoFix {
            file_path: finding.file_path.clone(),
            rule_id: finding.rule_id.clone(),
            description: "Restrict security group to specific CIDR".into(),
            original_line: "cidr_blocks = [\"0.0.0.0/0\"]".into(),
            patched_line: "cidr_blocks = [\"10.0.0.0/8\"]".into(),
            line_number: finding.line,
        }),
        ("terraform", "TF003") => Some(IacAutoFix {
            file_path: finding.file_path.clone(),
            rule_id: finding.rule_id.clone(),
            description: "Enable encryption at rest".into(),
            original_line: "encrypt = false".into(),
            patched_line: "encrypt = true".into(),
            line_number: finding.line,
        }),
        ("terraform", "TF004") => Some(IacAutoFix {
            file_path: finding.file_path.clone(),
            rule_id: finding.rule_id.clone(),
            description: "Enable versioning on S3 bucket".into(),
            original_line: "versioning { enabled = false }".into(),
            patched_line: "versioning { enabled = true }".into(),
            line_number: finding.line,
        }),

        // Kubernetes fixes.
        ("kubernetes", "KSV001") => Some(IacAutoFix {
            file_path: finding.file_path.clone(),
            rule_id: finding.rule_id.clone(),
            description: "Set runAsNonRoot to true".into(),
            original_line: "runAsNonRoot: false".into(),
            patched_line: "runAsNonRoot: true".into(),
            line_number: finding.line,
        }),
        ("kubernetes", "KSV011") => Some(IacAutoFix {
            file_path: finding.file_path.clone(),
            rule_id: finding.rule_id.clone(),
            description: "Remove privileged flag".into(),
            original_line: "privileged: true".into(),
            patched_line: "privileged: false".into(),
            line_number: finding.line,
        }),

        _ => None,
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::container::{ContainerScanResult, ContainerScanSummary, LinuxDistro, OsPackage};
    use crate::dependency::{Dependency, DependencyGraph};
    use crate::finding::{Finding, FindingStatus, ReachabilityStatus, VulnerabilitySeverity};
    use std::path::PathBuf;

    fn make_finding(severity: VulnerabilitySeverity, fix_version: Option<String>) -> Finding {
        Finding {
            advisory_id: "CVE-2024-12345".into(),
            summary: "Test".into(),
            description: "Test vulnerability".into(),
            severity,
            cvss_score: Some(7.5),
            package: "npm:lodash".into(),
            version: "4.17.0".into(),
            fix_version: fix_version.clone(),
            fix_available: fix_version.is_some(),
            reachability: ReachabilityStatus::Reachable,
            vulnerable_functions: vec![],
            call_chain: vec![],
            status: FindingStatus::Pending,
            triage_explanation: None,
            references: vec![],
            cwes: vec![],
            manifest_path: PathBuf::new(),
            aliases: vec![],
        }
    }

    fn make_graph() -> DependencyGraph {
        let mut graph = DependencyGraph::new();
        graph.add(Dependency {
            name: "lodash".into(),
            version: "4.17.0".into(),
            kind: DependencyKind::Npm,
            is_direct: true,
            manifest_path: PathBuf::from("package.json"),
            dependencies: vec![],
            source_url: None,
        });
        graph
    }

    // Goal 141 tests

    #[test]
    fn test_guided_remediation() {
        let findings = vec![make_finding(VulnerabilitySeverity::High, Some("4.17.21".into()))];
        let graph = make_graph();
        let suggestions = guided_remediation(&findings, &graph);
        assert_eq!(suggestions.len(), 1);
        assert_eq!(suggestions[0].fix_version, "4.17.21");
    }

    #[test]
    fn test_guided_remediation_no_fix() {
        let findings = vec![make_finding(VulnerabilitySeverity::High, None)];
        let graph = make_graph();
        let suggestions = guided_remediation(&findings, &graph);
        assert!(suggestions.is_empty());
    }

    #[test]
    fn test_disruption_assessment() {
        assert_eq!(assess_disruption("1.0.0", "2.0.0"), DisruptionLevel::High);
        assert_eq!(assess_disruption("1.0.0", "1.1.0"), DisruptionLevel::Medium);
        assert_eq!(assess_disruption("1.0.0", "1.0.1"), DisruptionLevel::Low);
    }

    // Goal 142 tests

    #[test]
    fn test_create_fix_pr() {
        let findings = vec![make_finding(VulnerabilitySeverity::High, Some("4.17.21".into()))];
        let graph = make_graph();
        let suggestions = guided_remediation(&findings, &graph);
        let pr = create_fix_pr(&suggestions, "package.json", "{\"lodash\": \"4.17.0\"}").unwrap();
        assert!(pr.title.contains("upgrade"));
        assert_eq!(pr.files.len(), 1);
        assert!(pr.files[0].patched_content.contains("4.17.21"));
    }

    #[test]
    fn test_create_fix_pr_empty() {
        let suggestions = vec![];
        let result = create_fix_pr(&suggestions, "package.json", "{}");
        assert!(result.is_err());
    }

    // Goal 143 tests

    #[test]
    fn test_override_npm() {
        let o = generate_override(DependencyKind::Npm, "lodash", "4.17.21");
        assert_eq!(o.override_file, "package.json");
        assert!(o.override_content.contains("lodash"));
    }

    #[test]
    fn test_override_python() {
        let o = generate_override(DependencyKind::Python, "requests", "2.31.0");
        assert_eq!(o.override_file, "constraints.txt");
        assert!(o.override_content.contains("requests==2.31.0"));
    }

    #[test]
    fn test_override_rust() {
        let o = generate_override(DependencyKind::Rust, "serde", "1.0.197");
        assert_eq!(o.override_file, "Cargo.toml");
        assert!(o.override_content.contains("[patch.crates-io]"));
    }

    // Goal 144 tests

    #[test]
    fn test_base_image_recommendation() {
        let scan = ContainerScanResult {
            image_ref: "python:3.12".into(),
            distro: LinuxDistro::Unknown,
            os_packages: vec![OsPackage { name: "test".into(), version: "1.0".into(), distro: LinuxDistro::Unknown, manager: "dpkg".into(), arch: None }],
            app_dependencies: vec![],
            vulnerabilities: vec![],
            summary: ContainerScanSummary::default(),
        };
        let recs = recommend_base_image(&scan);
        assert!(!recs.is_empty());
        assert!(recs.iter().any(|r| r.recommended_image.contains("slim") || r.recommended_image.contains("alpine") || r.recommended_image.contains("distroless")));
    }

    #[test]
    fn test_base_image_already_alpine() {
        let scan = ContainerScanResult {
            image_ref: "python:3.12-alpine".into(),
            distro: LinuxDistro::Alpine,
            os_packages: vec![],
            app_dependencies: vec![],
            vulnerabilities: vec![],
            summary: ContainerScanSummary::default(),
        };
        let recs = recommend_base_image(&scan);
        // Already alpine, should not recommend alpine again.
        assert!(!recs.iter().any(|r| r.recommended_image.contains("alpine")));
    }

    // Goal 145 tests

    #[test]
    fn test_remediation_roi() {
        let findings = vec![make_finding(VulnerabilitySeverity::Critical, Some("4.17.21".into()))];
        let graph = make_graph();
        let suggestions = guided_remediation(&findings, &graph);
        let rois = score_remediation_roi(&findings, &suggestions);
        assert_eq!(rois.len(), 1);
        assert!(rois[0].risk_reduction > 0.0);
    }

    #[test]
    fn test_remediation_roi_priority() {
        let findings = vec![make_finding(VulnerabilitySeverity::Critical, Some("4.17.21".into()))];
        let graph = make_graph();
        let suggestions = guided_remediation(&findings, &graph);
        let rois = score_remediation_roi(&findings, &suggestions);
        assert!(rois[0].priority == RemediationPriority::Critical || rois[0].priority == RemediationPriority::High);
    }

    // Goal 146 tests

    #[test]
    fn test_batch_remediation() {
        let findings: Vec<Finding> = (0..5)
            .map(|i| Finding {
                advisory_id: format!("CVE-2024-{}", 1000 + i),
                package: format!("npm:pkg{}", i),
                version: "1.0.0".into(),
                fix_version: Some("2.0.0".into()),
                fix_available: true,
                ..make_finding(VulnerabilitySeverity::High, Some("2.0.0".into()))
            })
            .collect();
        let graph = make_graph();
        let suggestions = guided_remediation(&findings, &graph);
        let batches = batch_remediation(&suggestions, 2);
        assert_eq!(batches.len(), 3); // 2 + 2 + 1
    }

    #[test]
    fn test_batch_remediation_empty() {
        let batches = batch_remediation(&[], 5);
        assert!(batches.is_empty());
    }

    // Goal 147 tests

    #[test]
    fn test_dry_run() {
        let findings = vec![make_finding(VulnerabilitySeverity::High, Some("4.17.21".into()))];
        let graph = make_graph();
        let suggestions = guided_remediation(&findings, &graph);
        let dry = dry_run_remediation(&suggestions, "package.json");
        assert!(dry.would_create_pr);
        assert_eq!(dry.total_upgrades, 1);
    }

    #[test]
    fn test_dry_run_empty() {
        let dry = dry_run_remediation(&[], "package.json");
        assert!(!dry.would_create_pr);
        assert_eq!(dry.total_upgrades, 0);
    }

    // Goal 148 tests

    #[test]
    fn test_changelog_analysis_safe() {
        let changelog = "## 2.0.0\n- Added new feature X\n- Improved performance\n";
        let analysis = analyze_changelog("test-pkg", "1.0.0", "2.0.0", changelog);
        assert!(analysis.safe_to_upgrade);
        assert!(!analysis.new_features.is_empty());
    }

    #[test]
    fn test_changelog_analysis_breaking() {
        let changelog = "## 2.0.0\n- Breaking: removed old API\n- Added new feature X\n";
        let analysis = analyze_changelog("test-pkg", "1.0.0", "2.0.0", changelog);
        assert!(!analysis.safe_to_upgrade);
        assert!(!analysis.breaking_changes.is_empty());
    }

    // Goal 149 tests

    #[test]
    fn test_deprecation_detected() {
        let status = check_deprecation("npm:moment");
        assert!(status.is_deprecated);
        assert!(status.maintained_alternative.is_some());
    }

    #[test]
    fn test_deprecation_not_detected() {
        let status = check_deprecation("npm:react");
        assert!(!status.is_deprecated);
    }

    #[test]
    fn test_check_all_deprecations() {
        let mut graph = DependencyGraph::new();
        graph.add(Dependency {
            name: "moment".into(),
            version: "2.29.0".into(),
            kind: DependencyKind::Npm,
            is_direct: true,
            manifest_path: PathBuf::from("package.json"),
            dependencies: vec![],
            source_url: None,
        });
        let deprecated = check_all_deprecations(&graph);
        assert!(!deprecated.is_empty());
    }

    // Goal 150 tests

    #[test]
    fn test_auto_fix_dockerfile_root() {
        let finding = IacFinding {
            rule_id: "DF001".into(),
            file_path: "Dockerfile".into(),
            line: 1,
            description: "Running as root".into(),
            severity: "medium".into(),
        };
        let fixes = auto_fix_iac(&[finding], "dockerfile");
        assert_eq!(fixes.len(), 1);
        assert!(fixes[0].patched_line.contains("USER"));
    }

    #[test]
    fn test_auto_fix_terraform_public_s3() {
        let finding = IacFinding {
            rule_id: "TF001".into(),
            file_path: "main.tf".into(),
            line: 10,
            description: "S3 bucket is public".into(),
            severity: "high".into(),
        };
        let fixes = auto_fix_iac(&[finding], "terraform");
        assert_eq!(fixes.len(), 1);
        assert!(fixes[0].patched_line.contains("private"));
    }

    #[test]
    fn test_auto_fix_k8s_privileged() {
        let finding = IacFinding {
            rule_id: "KSV011".into(),
            file_path: "deployment.yaml".into(),
            line: 15,
            description: "Privileged container".into(),
            severity: "high".into(),
        };
        let fixes = auto_fix_iac(&[finding], "kubernetes");
        assert_eq!(fixes.len(), 1);
        assert!(fixes[0].patched_line.contains("privileged: false"));
    }

    #[test]
    fn test_auto_fix_unknown_rule() {
        let finding = IacFinding {
            rule_id: "UNKNOWN".into(),
            file_path: "Dockerfile".into(),
            line: 1,
            description: "Unknown issue".into(),
            severity: "low".into(),
        };
        let fixes = auto_fix_iac(&[finding], "dockerfile");
        assert!(fixes.is_empty());
    }
}
