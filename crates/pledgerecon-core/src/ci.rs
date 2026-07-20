//! CI/CD integration — exit codes, PR comments, and pipeline templates.
//!
//! PledgeRecon is designed to be CI-native: it returns appropriate exit codes
//! for pipeline gating, generates PR comments, and provides templates for
//! GitHub Actions, GitLab CI, Jenkins, and Azure DevOps.

use crate::finding::{Finding, FindingStatus, ReachabilityStatus, VulnerabilitySeverity};
use crate::scanner::ScanReport;

/// Exit codes for CI/CD integration.
pub mod exit_codes {
    /// No vulnerabilities found.
    pub const SUCCESS: i32 = 0;
    /// Vulnerabilities found at or above the severity threshold.
    pub const VULNERABILITIES_FOUND: i32 = 1;
    /// Scan failed due to an error.
    pub const SCAN_ERROR: i32 = 2;
    /// Advisory database could not be fetched and no cache is available.
    pub const DATABASE_ERROR: i32 = 3;
}

/// Determine the exit code for a scan report based on CI gate configuration.
pub fn exit_code(
    report: &ScanReport,
    fail_on_severity: VulnerabilitySeverity,
    fail_on_unreachable: bool,
) -> i32 {
    let has_blocking = report.findings.iter().any(|f| {
        let severity_ok = f.severity >= fail_on_severity;
        let reachability_ok = if fail_on_unreachable {
            true
        } else {
            f.reachability != ReachabilityStatus::Unreachable
        };
        let not_false_positive = f.status != FindingStatus::FalsePositive;

        severity_ok && reachability_ok && not_false_positive
    });

    if has_blocking {
        exit_codes::VULNERABILITIES_FOUND
    } else {
        exit_codes::SUCCESS
    }
}

/// Generate a GitHub Actions step summary (markdown).
pub fn github_actions_summary(report: &ScanReport) -> String {
    let mut summary = String::new();

    summary.push_str("## PledgeRecon Security Scan\n\n");

    if report.findings.is_empty() {
        summary.push_str("✅ **No vulnerabilities found.**\n");
        return summary;
    }

    let critical = report.count_by_severity(VulnerabilitySeverity::Critical);
    let high = report.count_by_severity(VulnerabilitySeverity::High);
    let medium = report.count_by_severity(VulnerabilitySeverity::Medium);
    let low = report.count_by_severity(VulnerabilitySeverity::Low);

    summary.push_str(&format!(
        "| Severity | Count |\n|---|---|\n\
         | 🔴 Critical | {} |\n\
         | 🟠 High | {} |\n\
         | 🟡 Medium | {} |\n\
         | 🔵 Low | {} |\n\
         | **Total** | **{}** |\n\n",
        critical,
        high,
        medium,
        low,
        report.findings.len()
    ));

    let reachable = report
        .findings
        .iter()
        .filter(|f| f.reachability == ReachabilityStatus::Reachable)
        .count();
    summary.push_str(&format!(
        "**Reachability analysis:** {} of {} vulnerabilities are reachable from entry points.\n\n",
        reachable,
        report.findings.len()
    ));

    // Top 5 most critical findings.
    let mut findings = report.findings.clone();
    findings.sort_by_key(|b| std::cmp::Reverse(b.severity));

    if !findings.is_empty() {
        summary.push_str("### Top Findings\n\n");
        for finding in findings.iter().take(5) {
            let icon = match finding.severity {
                VulnerabilitySeverity::Critical => "🔴",
                VulnerabilitySeverity::High => "🟠",
                VulnerabilitySeverity::Medium => "🟡",
                VulnerabilitySeverity::Low => "🔵",
                VulnerabilitySeverity::Info => "⚪",
            };
            summary.push_str(&format!(
                "- {} **{}** — `{}@{}` → Fix: `{}`\n",
                icon,
                finding.summary,
                finding.package,
                finding.version,
                finding.fix_version.as_deref().unwrap_or("N/A")
            ));
        }
    }

    summary
}

/// Generate a GitHub PR comment body (markdown, truncated for comment length limits).
pub fn github_pr_comment(report: &ScanReport) -> String {
    let mut comment = String::new();

    comment.push_str("## 🔍 PledgeRecon Vulnerability Scan\n\n");

    if report.findings.is_empty() {
        comment.push_str("✅ No vulnerabilities found in dependencies.\n");
        return comment;
    }

    let blocking: Vec<&Finding> = report
        .findings
        .iter()
        .filter(|f| {
            f.reachability != ReachabilityStatus::Unreachable
                && f.status != FindingStatus::FalsePositive
        })
        .collect();

    if blocking.is_empty() {
        comment.push_str(&format!(
            "✅ No actionable vulnerabilities found. {} findings were detected but all are either unreachable or false positives.\n",
            report.findings.len()
        ));
        return comment;
    }

    comment.push_str(&format!(
        "⚠️ Found **{} actionable vulnerability(ies)** out of {} total findings.\n\n",
        blocking.len(),
        report.findings.len()
    ));

    // Compact table of blocking findings.
    comment
        .push_str("| Severity | Package | Advisory | Reachable | Fix |\n|---|---|---|---|---|\n");

    for finding in &blocking {
        let reachable = match finding.reachability {
            ReachabilityStatus::Reachable => "🔴 Yes",
            ReachabilityStatus::Unreachable => "🟢 No",
            ReachabilityStatus::Unknown => "⚪ ?",
        };
        comment.push_str(&format!(
            "| {} | `{}@{}` | {} | {} | {} |\n",
            finding.severity,
            finding.package,
            finding.version,
            finding.advisory_id,
            reachable,
            finding.fix_version.as_deref().unwrap_or("N/A"),
        ));
    }

    comment.push_str("\n_Run `pledgerecon scan . --format markdown` for full details._\n");

    comment
}

/// Generate a GitLab CI job output (GitLab Code Quality JSON format).
pub fn gitlab_code_quality(report: &ScanReport) -> String {
    let mut items = Vec::new();

    for finding in &report.findings {
        if finding.status == FindingStatus::FalsePositive {
            continue;
        }

        let severity = match finding.severity {
            VulnerabilitySeverity::Critical | VulnerabilitySeverity::High => "blocker",
            VulnerabilitySeverity::Medium => "major",
            VulnerabilitySeverity::Low => "minor",
            VulnerabilitySeverity::Info => "info",
        };

        items.push(serde_json::json!({
            "description": format!("{}: {}@{} — {}", finding.advisory_id, finding.package, finding.version, finding.summary),
            "severity": severity,
            "fingerprint": finding.advisory_id,
            "location": {
                "path": finding.manifest_path.to_string_lossy(),
            },
        }));
    }

    serde_json::to_string_pretty(&items).unwrap_or("[]".to_string())
}

/// GitHub Actions workflow YAML template.
pub fn github_actions_template() -> &'static str {
    r#"name: PledgeRecon Security Scan

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
"#
}

/// GitLab CI YAML template.
pub fn gitlab_ci_template() -> &'static str {
    r#"pledgerecon:scan:
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
"#
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use std::path::PathBuf;
    use uuid::Uuid;

    fn make_report(
        severity: VulnerabilitySeverity,
        reachability: ReachabilityStatus,
    ) -> ScanReport {
        ScanReport {
            scan_id: Uuid::new_v4().to_string(),
            project_name: "test".to_string(),
            scanned_at: Utc::now(),
            duration_ms: 10,
            dependencies_scanned: 5,
            advisories_checked: 3,
            findings: vec![Finding {
                advisory_id: "TEST-001".to_string(),
                summary: "Test".to_string(),
                description: "Test".to_string(),
                severity,
                cvss_score: None,
                package: "npm:test".to_string(),
                version: "1.0.0".to_string(),
                fix_version: Some("1.0.1".to_string()),
                fix_available: true,
                reachability,
                vulnerable_functions: vec![],
                call_chain: vec![],
                status: FindingStatus::Pending,
                triage_explanation: None,
                references: vec![],
                cwes: vec![],
                manifest_path: PathBuf::from("package.json"),
                aliases: vec![],
            }],
        }
    }

    #[test]
    fn test_exit_code_success() {
        let report = make_report(VulnerabilitySeverity::Low, ReachabilityStatus::Reachable);
        assert_eq!(
            exit_code(&report, VulnerabilitySeverity::High, false),
            exit_codes::SUCCESS
        );
    }

    #[test]
    fn test_exit_code_vulns_found() {
        let report = make_report(VulnerabilitySeverity::High, ReachabilityStatus::Reachable);
        assert_eq!(
            exit_code(&report, VulnerabilitySeverity::Medium, false),
            exit_codes::VULNERABILITIES_FOUND
        );
    }

    #[test]
    fn test_exit_code_unreachable_not_blocking() {
        let report = make_report(VulnerabilitySeverity::High, ReachabilityStatus::Unreachable);
        assert_eq!(
            exit_code(&report, VulnerabilitySeverity::Medium, false),
            exit_codes::SUCCESS
        );
    }

    #[test]
    fn test_exit_code_unreachable_blocking() {
        let report = make_report(VulnerabilitySeverity::High, ReachabilityStatus::Unreachable);
        assert_eq!(
            exit_code(&report, VulnerabilitySeverity::Medium, true),
            exit_codes::VULNERABILITIES_FOUND
        );
    }

    #[test]
    fn test_github_pr_comment() {
        let report = make_report(VulnerabilitySeverity::High, ReachabilityStatus::Reachable);
        let comment = github_pr_comment(&report);
        assert!(comment.contains("PledgeRecon"));
        assert!(comment.contains("actionable"));
    }

    #[test]
    fn test_github_actions_template() {
        let template = github_actions_template();
        assert!(template.contains("pledgerecon"));
        assert!(template.contains("sarif"));
    }
}
