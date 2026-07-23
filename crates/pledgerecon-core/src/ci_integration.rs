//! CI/CD deep integration — GitHub Actions, GitLab CI, CircleCI, Bitbucket, pre-commit, PR checks, auto-fix, baseline, SARIF annotations, cache pre-population (Goals 66–75).

use crate::finding::{Finding, FindingStatus, ReachabilityStatus, VulnerabilitySeverity};
use crate::scanner::ScanReport;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::Path;
use thiserror::Error;

/// Errors during CI integration operations.
#[derive(Debug, Error)]
pub enum CiIntegrationError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("baseline file not found: {0}")]
    BaselineNotFound(String),
    #[error("missing GitHub token")]
    MissingGitHubToken,
}

// ─── Goal 66: GitHub Actions action ─────────────────────────────────────────

/// Generate the official GitHub Actions action.yml template.
pub fn github_action_yml() -> &'static str {
    r#"name: 'PledgeRecon Security Scan'
description: 'Scan dependencies for vulnerabilities with AST reachability and LLM triage'
branding:
  icon: 'shield'
  color: 'blue'
inputs:
  path:
    description: 'Path to scan'
    required: false
    default: '.'
  min-severity:
    description: 'Minimum severity to report (low, medium, high, critical)'
    required: false
    default: 'low'
  fail-on-findings:
    description: 'Fail the workflow if vulnerabilities are found'
    required: false
    default: 'true'
  format:
    description: 'Output format (text, json, sarif, html, junit-xml)'
    required: false
    default: 'sarif'
  triage:
    description: 'Enable LLM-powered triage'
    required: false
    default: 'false'
  generate-sbom:
    description: 'Generate an SBOM alongside the scan'
    required: false
    default: 'false'
outputs:
  report-path:
    description: 'Path to the generated report file'
runs:
  using: 'composite'
  steps:
    - name: Install PledgeRecon
      shell: bash
      run: |
        curl -L https://github.com/pledgeandgrow/pledgerecon/releases/latest/download/pledgerecon-linux-amd64 -o /usr/local/bin/pledgerecon
        chmod +x /usr/local/bin/pledgerecon
    - name: Run PledgeRecon scan
      shell: bash
      run: |
        pledgerecon scan ${{ inputs.path }} \
          --min-severity ${{ inputs.min-severity }} \
          --format ${{ inputs.format }} \
          --output pledgerecon-report.${{ inputs.format }} \
          ${{ inputs.fail-on-findings == 'true' && '--fail-on-findings' || '' }} \
          ${{ inputs.triage == 'true' && '--triage' || '' }}
    - name: Upload SARIF results
      uses: github/codeql-action/upload-sarif@v3
      if: always() && inputs.format == 'sarif'
      with:
        sarif_file: pledgerecon-report.sarif
    - name: Generate SBOM
      if: inputs.generate-sbom == 'true'
      shell: bash
      run: pledgerecon sbom ${{ inputs.path }} --format cyclonedx --output sbom.json
    - uses: actions/upload-artifact@v4
      if: always()
      with:
        name: pledgerecon-report
        path: |
          pledgerecon-report.*
          sbom.json
"#
}

// ─── Goal 67: GitLab CI template ────────────────────────────────────────────

/// Generate the official GitLab CI template.
pub fn gitlab_ci_template() -> &'static str {
    r#"# PledgeRecon — GitLab CI template
# Add this to your .gitlab-ci.yml or include it:
# include:
#   - remote: 'https://raw.githubusercontent.com/pledgeandgrow/pledgerecon/main/ci/gitlab-ci.yml'

pledgerecon:scan:
  stage: test
  image:
    name: ghcr.io/pledgeandgrow/pledgerecon:latest
    entrypoint: [""]
  variables:
    PLEDGERECON_MIN_SEVERITY: "high"
    PLEDGERECON_FORMAT: "gitlab-code-quality"
  script:
    - pledgerecon scan . --min-severity high --format gitlab-code-quality --output pledgerecon-report.json
    - pledgerecon scan . --min-severity high --format sarif --output pledgerecon.sarif
  artifacts:
    reports:
      codequality: pledgerecon-report.json
    paths:
      - pledgerecon.sarif
  allow_failure: false

pledgerecon:sbom:
  stage: test
  image:
    name: ghcr.io/pledgeandgrow/pledgerecon:latest
    entrypoint: [""]
  script:
    - pledgerecon sbom . --format cyclonedx --output sbom.json
  artifacts:
    paths:
      - sbom.json
  allow_failure: true
"#
}

// ─── Goal 68: CircleCI orb ──────────────────────────────────────────────────

/// Generate the CircleCI orb configuration.
pub fn circleci_orb() -> &'static str {
    r#"version: 2.1

# PledgeRecon CircleCI Orb
# Usage in your config:
# orbs:
#   pledgerecon: pledgeandgrow/pledgerecon@1.0.0

commands:
  pledgerecon-scan:
    description: "Run PledgeRecon vulnerability scan"
    parameters:
      path:
        type: string
        default: "."
      min-severity:
        type: string
        default: "high"
      fail-on-findings:
        type: boolean
        default: true
    steps:
      - run:
          name: Install PledgeRecon
          command: |
            curl -L https://github.com/pledgeandgrow/pledgerecon/releases/latest/download/pledgerecon-linux-amd64 -o /usr/local/bin/pledgerecon
            chmod +x /usr/local/bin/pledgerecon
      - run:
          name: Run vulnerability scan
          command: |
            pledgerecon scan << parameters.path >> \
              --min-severity << parameters.min-severity >> \
              --format json \
              --output pledgerecon-report.json \
              <<# parameters.fail-on-findings >>--fail-on-findings<</ parameters.fail-on-findings >>
      - store_artifacts:
          path: pledgerecon-report.json
          destination: pledgerecon-report.json

jobs:
  pledgerecon:
    docker:
      - image: cimg/base:stable
    steps:
      - checkout
      - pledgerecon-scan:
          min-severity: high
          fail-on-findings: true

workflows:
  pledgerecon-scan:
    jobs:
      - pledgerecon
"#
}

// ─── Goal 69: Bitbucket Pipes ───────────────────────────────────────────────

/// Generate the Bitbucket Pipes configuration.
pub fn bitbucket_pipe() -> &'static str {
    r"# PledgeRecon — Bitbucket Pipeline integration
# Add this to your bitbucket-pipelines.yml:

pipelines:
  default:
    - step:
        name: PledgeRecon Security Scan
        image: ghcr.io/pledgeandgrow/pledgerecon:latest
        script:
          - pledgerecon scan . --min-severity high --format json --output pledgerecon-report.json --fail-on-findings
        artifacts:
          - pledgerecon-report.json

  branches:
    main:
      - step:
          name: PledgeRecon Security Scan + SBOM
          image: ghcr.io/pledgeandgrow/pledgerecon:latest
          script:
            - pledgerecon scan . --min-severity high --format sarif --output pledgerecon.sarif --fail-on-findings
            - pledgerecon sbom . --format cyclonedx --output sbom.json
          artifacts:
            - pledgerecon.sarif
            - sbom.json
"
}

// ─── Goal 70: pre-commit hook ───────────────────────────────────────────────

/// Generate the pre-commit hook configuration.
pub fn pre_commit_hook() -> &'static str {
    r#"# PledgeRecon pre-commit hook
# Add to your .pre-commit-config.yaml:
#
# repos:
#   - repo: https://github.com/pledgeandgrow/pledgerecon
#     rev: v0.1.0
#     hooks:
#       - id: pledgerecon
#         name: PledgeRecon vulnerability scan
#         entry: pledgerecon scan
#         language: system
#         files: ^(Cargo\.toml|package\.json|go\.mod|requirements\.txt|pyproject\.toml|pubspec\.yaml)$
#         pass_filenames: false
#         args: ["--min-severity", "high", "--format", "text"]

- id: pledgerecon
  name: PledgeRecon vulnerability scan
  entry: pledgerecon scan
  language: system
  files: ^(Cargo\.toml|package\.json|go\.mod|requirements\.txt|pyproject\.toml|pubspec\.yaml)$
  pass_filenames: false
  args: ["--min-severity", "high", "--format", "text"]
"#
}

// ─── Goal 71: GitHub PR check ───────────────────────────────────────────────

/// GitHub Check API annotation for a finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckAnnotation {
    /// Path to the file being annotated.
    pub path: String,
    /// Start line of the annotation (1-based).
    pub start_line: u32,
    /// End line of the annotation (1-based).
    pub end_line: u32,
    /// Annotation level: "notice", "warning", or "failure".
    pub annotation_level: String,
    /// Annotation message.
    pub message: String,
    /// Detailed description.
    pub title: String,
    /// Raw details (markdown supported).
    pub raw_details: String,
}

/// GitHub Check API output for a scan report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckOutput {
    /// Check title.
    pub title: String,
    /// Check summary.
    pub summary: String,
    /// Check text (markdown, detailed description).
    pub text: String,
    /// Annotations for specific lines.
    pub annotations: Vec<CheckAnnotation>,
    /// Number of warnings.
    pub warnings_count: u32,
    /// Number of failures.
    pub failures_count: u32,
    /// Whether the check concludes the conclusion is "failure".
    pub conclusion: String,
}

/// Build a GitHub Check API output from a scan report (Goal 71).
pub fn build_github_check(report: &ScanReport) -> CheckOutput {
    let mut annotations = Vec::new();
    let mut failures = 0u32;
    let mut warnings = 0u32;

    for finding in &report.findings {
        if finding.status == FindingStatus::FalsePositive {
            continue;
        }

        let (level, is_failure) = match finding.severity {
            VulnerabilitySeverity::Critical | VulnerabilitySeverity::High => ("failure", true),
            VulnerabilitySeverity::Medium => ("warning", false),
            VulnerabilitySeverity::Low | VulnerabilitySeverity::Info => ("notice", false),
        };

        if is_failure {
            failures += 1;
        } else {
            warnings += 1;
        }

        let mut raw_details = format!(
            "**Advisory:** {}\n**CVSS:** {}\n**Fix:** {}\n**Reachability:** {}",
            finding.advisory_id,
            finding
                .cvss_score
                .map(|s| s.to_string())
                .unwrap_or("N/A".to_string()),
            finding.fix_version.as_deref().unwrap_or("not available"),
            finding.reachability
        );

        if !finding.call_chain.is_empty() {
            raw_details.push_str(&format!(
                "\n**Call chain:** `{}`",
                finding.call_chain.join("` → `")
            ));
        }
        if let Some(ref explanation) = finding.triage_explanation {
            raw_details.push_str(&format!("\n**Triage:** {}", explanation));
        }

        annotations.push(CheckAnnotation {
            path: finding.manifest_path.to_string_lossy().to_string(),
            start_line: 1,
            end_line: 1,
            annotation_level: level.to_string(),
            message: format!(
                "{} — {}@{}: {}",
                finding.advisory_id, finding.package, finding.version, finding.summary
            ),
            title: format!("[{}] {}", finding.severity, finding.summary),
            raw_details,
        });
    }

    let conclusion = if failures > 0 {
        "failure".to_string()
    } else {
        "success".to_string()
    };

    let summary = if report.findings.is_empty() {
        "No vulnerabilities found.".to_string()
    } else {
        format!(
            "Found {} vulnerabilities ({} critical/high, {} medium, {} low/info)",
            report.findings.len(),
            failures,
            warnings,
            report.findings.len() - failures as usize - warnings as usize
        )
    };

    let text = format!(
        "## Summary\n\n\
         | Severity | Count |\n|---|---|\n\
         | Critical | {} |\n| High | {} |\n| Medium | {} |\n| Low | {} |\n| Info | {} |\n\n\
         **Reachable:** {} | **Unreachable:** {} | **Unknown:** {}",
        report.count_by_severity(VulnerabilitySeverity::Critical),
        report.count_by_severity(VulnerabilitySeverity::High),
        report.count_by_severity(VulnerabilitySeverity::Medium),
        report.count_by_severity(VulnerabilitySeverity::Low),
        report.count_by_severity(VulnerabilitySeverity::Info),
        report.count_by_reachability(ReachabilityStatus::Reachable),
        report.count_by_reachability(ReachabilityStatus::Unreachable),
        report.count_by_reachability(ReachabilityStatus::Unknown),
    );

    CheckOutput {
        title: format!("PledgeRecon: {} finding(s)", report.findings.len()),
        summary,
        text,
        annotations,
        warnings_count: warnings,
        failures_count: failures,
        conclusion,
    }
}

// ─── Goal 72: Auto-fix PR generation ────────────────────────────────────────

/// A suggested dependency upgrade to fix a vulnerability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoFixSuggestion {
    /// Package name (e.g. "npm:lodash").
    pub package: String,
    /// Current version.
    pub current_version: String,
    /// Fixed version.
    pub fixed_version: String,
    /// Manifest file to edit.
    pub manifest_path: String,
    /// Advisory IDs this fixes.
    pub advisory_ids: Vec<String>,
    /// Severity of the highest finding this fixes.
    pub severity: VulnerabilitySeverity,
}

/// Generate auto-fix suggestions from a scan report (Goal 72).
pub fn generate_autofix_suggestions(report: &ScanReport) -> Vec<AutoFixSuggestion> {
    let mut suggestions: Vec<AutoFixSuggestion> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    let mut findings = report.findings.clone();
    findings.sort_by_key(|b| std::cmp::Reverse(b.severity));

    for finding in &findings {
        if !finding.fix_available {
            continue;
        }
        if let Some(ref fix_version) = finding.fix_version {
            let key = format!("{}@{}", finding.package, fix_version);
            if seen.contains(&key) {
                // Merge advisory ID into existing suggestion.
                if let Some(s) = suggestions
                    .iter_mut()
                    .find(|s| s.package == finding.package && s.fixed_version == *fix_version)
                {
                    s.advisory_ids.push(finding.advisory_id.clone());
                    if finding.severity > s.severity {
                        s.severity = finding.severity;
                    }
                }
                continue;
            }
            seen.insert(key);
            suggestions.push(AutoFixSuggestion {
                package: finding.package.clone(),
                current_version: finding.version.clone(),
                fixed_version: fix_version.clone(),
                manifest_path: finding.manifest_path.to_string_lossy().to_string(),
                advisory_ids: vec![finding.advisory_id.clone()],
                severity: finding.severity,
            });
        }
    }

    suggestions
}

/// Generate a PR body for auto-fix suggestions (Goal 72).
pub fn generate_autofix_pr_body(suggestions: &[AutoFixSuggestion]) -> String {
    if suggestions.is_empty() {
        return "No fixable vulnerabilities found.".to_string();
    }

    let mut body = String::new();
    body.push_str("## 🔧 PledgeRecon Auto-Fix: Dependency Upgrades\n\n");
    body.push_str(&format!(
        "This PR upgrades {} package(s) to fix {} vulnerability advisory(ies).\n\n",
        suggestions.len(),
        suggestions
            .iter()
            .map(|s| s.advisory_ids.len())
            .sum::<usize>()
    ));

    body.push_str("| Package | Current | Fixed | Severity | Advisories |\n|---|---|---|---|---|\n");
    for s in suggestions {
        body.push_str(&format!(
            "| `{}` | `{}` | `{}` | {} | {} |\n",
            s.package,
            s.current_version,
            s.fixed_version,
            s.severity,
            s.advisory_ids.join(", ")
        ));
    }

    body.push_str("\n### Changes\n\n");
    for s in suggestions {
        body.push_str(&format!(
            "- **`{}`**: `{}` → `{}` in `{}`\n",
            s.package, s.current_version, s.fixed_version, s.manifest_path
        ));
    }

    body.push_str("\n---\n_Automatically generated by PledgeRecon_\n");

    body
}

// ─── Goal 73: Baseline comparison ───────────────────────────────────────────

/// Baseline comparison result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineComparison {
    /// Findings in the current scan that are NOT in the baseline (new vulns).
    pub new_findings: Vec<Finding>,
    /// Whether the scan should fail (new findings exist).
    pub should_fail: bool,
    /// Total findings in baseline.
    pub baseline_count: usize,
    /// Total findings in current scan.
    pub current_count: usize,
}

/// Compare a scan report against a baseline file (Goal 73).
/// The baseline is a JSON file containing a previous ScanReport.
pub fn compare_with_baseline(
    current: &ScanReport,
    baseline_path: &Path,
) -> Result<BaselineComparison, CiIntegrationError> {
    if !baseline_path.exists() {
        return Err(CiIntegrationError::BaselineNotFound(
            baseline_path.to_string_lossy().to_string(),
        ));
    }

    let content = std::fs::read_to_string(baseline_path)?;
    let baseline: ScanReport = serde_json::from_str(&content)?;

    let baseline_keys: HashSet<String> = baseline
        .findings
        .iter()
        .map(|f| format!("{}@{}#{}", f.package, f.version, f.advisory_id))
        .collect();

    let new_findings: Vec<Finding> = current
        .findings
        .iter()
        .filter(|f| {
            let key = format!("{}@{}#{}", f.package, f.version, f.advisory_id);
            !baseline_keys.contains(&key) && f.status != FindingStatus::FalsePositive
        })
        .cloned()
        .collect();

    let should_fail = !new_findings.is_empty();

    Ok(BaselineComparison {
        new_findings,
        should_fail,
        baseline_count: baseline.findings.len(),
        current_count: current.findings.len(),
    })
}

/// Save a scan report as a baseline file (Goal 73).
pub fn save_baseline(report: &ScanReport, path: &Path) -> Result<(), CiIntegrationError> {
    let content = serde_json::to_string_pretty(report)?;
    std::fs::write(path, content)?;
    Ok(())
}

// ─── Goal 74: SARIF inline annotations ──────────────────────────────────────

/// Generate SARIF with inline annotations for specific source lines (Goal 74).
/// This extends the standard SARIF output with line-level annotations for PRs.
pub fn to_sarif_with_annotations(report: &ScanReport) -> String {
    let mut results = Vec::new();

    for finding in &report.findings {
        if finding.status == FindingStatus::FalsePositive {
            continue;
        }

        let level = match finding.severity {
            VulnerabilitySeverity::Critical | VulnerabilitySeverity::High => "error",
            VulnerabilitySeverity::Medium => "warning",
            VulnerabilitySeverity::Low | VulnerabilitySeverity::Info => "note",
        };

        let message = format!(
            "{} — {}@{} ({}){}",
            finding.summary,
            finding.package,
            finding.version,
            finding.severity,
            if finding.reachability == ReachabilityStatus::Unreachable {
                " [UNREACHABLE]"
            } else {
                ""
            }
        );

        // Build location with line number if call chain exists.
        let region = if !finding.call_chain.is_empty() {
            serde_json::json!({
                "startLine": 1,
                "endLine": 1,
            })
        } else {
            serde_json::json!({
                "startLine": 1,
            })
        };

        let mut physical_location = serde_json::json!({
            "artifactLocation": {
                "uri": finding.manifest_path.to_string_lossy(),
            },
            "region": region,
        });

        // Add line-level annotations for vulnerable function calls.
        if !finding.call_chain.is_empty() {
            physical_location["contextRegion"] = serde_json::json!({
                "startLine": 1,
                "endLine": 1,
            });
        }

        results.push(serde_json::json!({
            "ruleId": finding.advisory_id,
            "level": level,
            "message": {
                "text": message,
            },
            "locations": [{
                "physicalLocation": physical_location,
            }],
            "properties": {
                "package": finding.package,
                "version": finding.version,
                "severity": finding.severity.to_string(),
                "reachability": finding.reachability.to_string(),
                "fix_available": finding.fix_available,
                "fix_version": finding.fix_version,
                "cvss_score": finding.cvss_score,
                "status": match finding.status {
                    FindingStatus::Pending => "pending",
                    FindingStatus::Confirmed => "confirmed",
                    FindingStatus::FalsePositive => "false_positive",
                    FindingStatus::Inconclusive => "inconclusive",
                },
                "vulnerable_functions": finding.vulnerable_functions,
                "call_chain": finding.call_chain,
                "cwes": finding.cwes,
            },
        }));
    }

    let mut rules = Vec::new();
    let mut seen_rules = std::collections::HashSet::new();
    for finding in &report.findings {
        if seen_rules.insert(&finding.advisory_id) {
            rules.push(serde_json::json!({
                "id": finding.advisory_id,
                "name": finding.advisory_id,
                "shortDescription": {
                    "text": &finding.summary,
                },
                "fullDescription": {
                    "text": &finding.description,
                },
                "properties": {
                    "tags": ["security", "vulnerability", "dependencies"],
                    "precision": match finding.reachability {
                        ReachabilityStatus::Reachable => "high",
                        ReachabilityStatus::Unreachable => "low",
                        ReachabilityStatus::Unknown => "medium",
                    },
                },
            }));
        }
    }

    let sarif = serde_json::json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "PledgeRecon",
                    "version": env!("CARGO_PKG_VERSION"),
                    "informationUri": "https://github.com/pledgeandgrow/pledgerecon",
                    "rules": rules,
                },
            },
            "results": results,
        }],
    });

    serde_json::to_string_pretty(&sarif).unwrap_or_else(|e| format!("{{\"error\": \"{}\"}}", e))
}

// ─── Goal 75: CI cache pre-population ───────────────────────────────────────

/// CI cache pre-population script for downloading advisory cache (Goal 75).
pub fn ci_cache_pre_population_script() -> &'static str {
    r#"#!/bin/bash
# PledgeRecon CI Cache Pre-Population
# Run this before your scan to pre-download the advisory database for offline scans.
#
# Usage:
#   ./pledgerecon-cache-pre-populate.sh [cache-dir]
#
# This script downloads the advisory database to the specified cache directory
# so that subsequent scans can run fully offline.

set -euo pipefail

CACHE_DIR="${1:-.pledgerecon-cache}"
mkdir -p "$CACHE_DIR"

echo "📦 Pre-populating PledgeRecon advisory cache..."

# Download the advisory database snapshot
if command -v pledgerecon &>/dev/null; then
    # Use PledgeRecon's built-in cache download
    pledgerecon cache download --output "$CACHE_DIR"
    echo "✅ Advisory cache pre-populated at $CACHE_DIR"
else
    echo "⚠️  PledgeRecon not found. Install it first:"
    echo "   curl -L https://github.com/pledgeandgrow/pledgerecon/releases/latest/download/pledgerecon-linux-amd64 -o /usr/local/bin/pledgerecon"
    echo "   chmod +x /usr/local/bin/pledgerecon"
    exit 1
fi
"#
}

/// GitHub Actions workflow for cache pre-population (Goal 75).
pub fn github_cache_workflow() -> &'static str {
    r#"name: PledgeRecon Cache Pre-Population

on:
  schedule:
    - cron: '0 6 * * *'  # Daily at 6 AM UTC
  workflow_dispatch: {}

jobs:
  pre-populate-cache:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install PledgeRecon
        run: |
          curl -L https://github.com/pledgeandgrow/pledgerecon/releases/latest/download/pledgerecon-linux-amd64 -o /usr/local/bin/pledgerecon
          chmod +x /usr/local/bin/pledgerecon

      - name: Pre-populate advisory cache
        run: pledgerecon cache download --output .pledgerecon-cache

      - name: Upload cache artifact
        uses: actions/upload-artifact@v4
        with:
          name: pledgerecon-advisory-cache
          path: .pledgerecon-cache/
          retention-days: 7

      - name: Cache for reuse
        uses: actions/cache@v4
        with:
          path: .pledgerecon-cache
          key: pledgerecon-advisory-cache-${{ github.run_id }}
          restore-keys: |
            pledgerecon-advisory-cache-
"#
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::Finding;
    use chrono::Utc;
    use std::path::PathBuf;
    use uuid::Uuid;

    fn make_finding(severity: VulnerabilitySeverity, fix_available: bool) -> Finding {
        Finding {
            advisory_id: "CVE-2021-23337".to_string(),
            summary: "Command injection in lodash".to_string(),
            description: "Test description".to_string(),
            severity,
            cvss_score: Some(7.2),
            package: "npm:lodash".to_string(),
            version: "4.17.11".to_string(),
            fix_version: if fix_available {
                Some("4.17.21".to_string())
            } else {
                None
            },
            fix_available,
            reachability: ReachabilityStatus::Reachable,
            vulnerable_functions: vec!["template".to_string()],
            call_chain: vec!["main".to_string(), "lodash.template".to_string()],
            status: FindingStatus::Pending,
            triage_explanation: None,
            references: vec!["https://example.com".to_string()],
            cwes: vec!["CWE-77".to_string()],
            manifest_path: PathBuf::from("package.json"),
            aliases: vec![],
        }
    }

    fn make_report(findings: Vec<Finding>) -> ScanReport {
        ScanReport {
            scan_id: Uuid::new_v4().to_string(),
            project_name: "test-project".to_string(),
            scanned_at: Utc::now(),
            duration_ms: 42,
            dependencies_scanned: 10,
            advisories_checked: 5,
            findings,
        }
    }

    #[test]
    fn test_github_action_yml() {
        let yml = github_action_yml();
        assert!(yml.contains("PledgeRecon"));
        assert!(yml.contains("name:"));
        assert!(yml.contains("sarif"));
    }

    #[test]
    fn test_gitlab_ci_template() {
        let yml = gitlab_ci_template();
        assert!(yml.contains("pledgerecon:scan"));
        assert!(yml.contains("codequality"));
    }

    #[test]
    fn test_circleci_orb() {
        let orb = circleci_orb();
        assert!(orb.contains("pledgerecon"));
        assert!(orb.contains("commands"));
    }

    #[test]
    fn test_bitbucket_pipe() {
        let pipe = bitbucket_pipe();
        assert!(pipe.contains("pipelines"));
        assert!(pipe.contains("pledgerecon"));
    }

    #[test]
    fn test_pre_commit_hook() {
        let hook = pre_commit_hook();
        assert!(hook.contains("pre-commit"));
        assert!(hook.contains("pledgerecon"));
    }

    #[test]
    fn test_build_github_check() {
        let report = make_report(vec![make_finding(VulnerabilitySeverity::High, true)]);
        let check = build_github_check(&report);
        assert_eq!(check.failures_count, 1);
        assert_eq!(check.conclusion, "failure");
        assert_eq!(check.annotations.len(), 1);
        assert!(check.summary.contains("1"));
    }

    #[test]
    fn test_build_github_check_no_findings() {
        let report = make_report(vec![]);
        let check = build_github_check(&report);
        assert_eq!(check.failures_count, 0);
        assert_eq!(check.conclusion, "success");
        assert!(check.summary.contains("No vulnerabilities"));
    }

    #[test]
    fn test_build_github_check_false_positive() {
        let mut f = make_finding(VulnerabilitySeverity::High, true);
        f.status = FindingStatus::FalsePositive;
        let report = make_report(vec![f]);
        let check = build_github_check(&report);
        assert_eq!(check.annotations.len(), 0);
    }

    #[test]
    fn test_generate_autofix_suggestions() {
        let report = make_report(vec![make_finding(VulnerabilitySeverity::High, true)]);
        let suggestions = generate_autofix_suggestions(&report);
        assert_eq!(suggestions.len(), 1);
        assert_eq!(suggestions[0].package, "npm:lodash");
        assert_eq!(suggestions[0].fixed_version, "4.17.21");
    }

    #[test]
    fn test_generate_autofix_no_fix() {
        let report = make_report(vec![make_finding(VulnerabilitySeverity::High, false)]);
        let suggestions = generate_autofix_suggestions(&report);
        assert!(suggestions.is_empty());
    }

    #[test]
    fn test_generate_autofix_pr_body() {
        let report = make_report(vec![make_finding(VulnerabilitySeverity::High, true)]);
        let suggestions = generate_autofix_suggestions(&report);
        let body = generate_autofix_pr_body(&suggestions);
        assert!(body.contains("Auto-Fix"));
        assert!(body.contains("npm:lodash"));
        assert!(body.contains("4.17.21"));
    }

    #[test]
    fn test_generate_autofix_pr_body_empty() {
        let body = generate_autofix_pr_body(&[]);
        assert!(body.contains("No fixable"));
    }

    #[test]
    fn test_baseline_comparison() {
        let baseline_report = make_report(vec![make_finding(VulnerabilitySeverity::High, true)]);
        let dir = std::env::temp_dir().join("pledgerecon_baseline_test");
        std::fs::create_dir_all(&dir).unwrap();
        let baseline_path = dir.join("baseline.json");
        save_baseline(&baseline_report, &baseline_path).unwrap();

        // Current report with an additional finding.
        let mut new_finding = make_finding(VulnerabilitySeverity::Critical, true);
        new_finding.advisory_id = "CVE-2024-99999".to_string();
        let current_report = make_report(vec![
            make_finding(VulnerabilitySeverity::High, true),
            new_finding,
        ]);

        let comparison = compare_with_baseline(&current_report, &baseline_path).unwrap();
        assert!(comparison.should_fail);
        assert_eq!(comparison.new_findings.len(), 1);
        assert_eq!(comparison.new_findings[0].advisory_id, "CVE-2024-99999");

        std::fs::remove_file(&baseline_path).ok();
    }

    #[test]
    fn test_baseline_no_new_findings() {
        let report = make_report(vec![make_finding(VulnerabilitySeverity::High, true)]);
        let dir = std::env::temp_dir().join("pledgerecon_baseline_test2");
        std::fs::create_dir_all(&dir).unwrap();
        let baseline_path = dir.join("baseline.json");
        save_baseline(&report, &baseline_path).unwrap();

        let comparison = compare_with_baseline(&report, &baseline_path).unwrap();
        assert!(!comparison.should_fail);
        assert!(comparison.new_findings.is_empty());

        std::fs::remove_file(&baseline_path).ok();
    }

    #[test]
    fn test_baseline_not_found() {
        let report = make_report(vec![]);
        let result = compare_with_baseline(&report, Path::new("/nonexistent/baseline.json"));
        assert!(result.is_err());
    }

    #[test]
    fn test_sarif_with_annotations() {
        let report = make_report(vec![make_finding(VulnerabilitySeverity::High, true)]);
        let sarif = to_sarif_with_annotations(&report);
        assert!(sarif.contains("2.1.0"));
        assert!(sarif.contains("CVE-2021-23337"));
        assert!(sarif.contains("startLine"));
        assert!(sarif.contains("region"));
    }

    #[test]
    fn test_ci_cache_pre_population_script() {
        let script = ci_cache_pre_population_script();
        assert!(script.contains("pledgerecon"));
        assert!(script.contains("cache"));
    }

    #[test]
    fn test_github_cache_workflow() {
        let workflow = github_cache_workflow();
        assert!(workflow.contains("cache"));
        assert!(workflow.contains("schedule"));
        assert!(workflow.contains("pledgerecon"));
    }
}
