//! Platform & Integrations — IDE plugins, issue trackers, SIEM, and
//! notification integrations (Goals 171–180).

use crate::finding::{FindingStatus, VulnerabilitySeverity};
use crate::scanner::ScanReport;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PlatformError {
    #[error("HTTP error: {0}")]
    Http(String),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("missing configuration: {0}")]
    MissingConfig(String),
    #[error("API error: {0}")]
    Api(String),
}

// ─── Goal 171: VS Code Extension Output ──────────────────────────────────────

/// A diagnostic entry for VS Code Problems panel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VsCodeDiagnostic {
    pub file: String,
    pub line: u32,
    pub column: u32,
    pub severity: VsCodeSeverity,
    pub source: String,
    pub message: String,
    pub code: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VsCodeSeverity { Error, Warning, Information, Hint }

/// Generate VS Code diagnostics from scan findings.
pub fn generate_vscode_diagnostics(report: &ScanReport) -> Vec<VsCodeDiagnostic> {
    report
        .findings
        .iter()
        .filter(|f| f.status != FindingStatus::FalsePositive)
        .map(|f| {
            let severity = match f.severity {
                VulnerabilitySeverity::Critical | VulnerabilitySeverity::High => VsCodeSeverity::Error,
                VulnerabilitySeverity::Medium => VsCodeSeverity::Warning,
                VulnerabilitySeverity::Low => VsCodeSeverity::Information,
                VulnerabilitySeverity::Info => VsCodeSeverity::Hint,
            };
            VsCodeDiagnostic {
                file: f.manifest_path.display().to_string(),
                line: 1,
                column: 1,
                severity,
                source: "pledgerecon".to_string(),
                message: format!("{}: {} in {}@{}", f.advisory_id, f.summary, f.package, f.version),
                code: f.advisory_id.clone(),
            }
        })
        .collect()
}

// ─── Goal 172: JetBrains Plugin Output ───────────────────────────────────────

/// An inspection result for JetBrains IDEs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JetBrainsInspection {
    pub file: String,
    pub line: u32,
    pub severity: String,
    pub message: String,
    pub highlight_type: String,
    pub quick_fix: Option<String>,
}

/// Generate JetBrains inspection results from scan findings.
pub fn generate_jetbrains_inspections(report: &ScanReport) -> Vec<JetBrainsInspection> {
    report
        .findings
        .iter()
        .filter(|f| f.status != FindingStatus::FalsePositive)
        .map(|f| {
            let (severity, highlight) = match f.severity {
                VulnerabilitySeverity::Critical => ("ERROR", "ERROR"),
                VulnerabilitySeverity::High => ("ERROR", "ERROR"),
                VulnerabilitySeverity::Medium => ("WARNING", "WARNING"),
                VulnerabilitySeverity::Low => ("WEAK WARNING", "WEAK_WARNING"),
                VulnerabilitySeverity::Info => ("INFORMATION", "INFORMATION"),
            };
            JetBrainsInspection {
                file: f.manifest_path.display().to_string(),
                line: 1,
                severity: severity.to_string(),
                message: format!("{}: {} in {}@{}", f.advisory_id, f.summary, f.package, f.version),
                highlight_type: highlight.to_string(),
                quick_fix: f.fix_version.as_ref().map(|v| format!("Upgrade to {}", v)),
            }
        })
        .collect()
}

// ─── Goal 173: Jira Integration ──────────────────────────────────────────────

/// A Jira issue created from a vulnerability finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JiraIssue {
    pub project_key: String,
    pub summary: String,
    pub description: String,
    pub issue_type: String,
    pub priority: String,
    pub labels: Vec<String>,
    pub components: Vec<String>,
}

/// Create Jira issues from scan findings.
pub fn create_jira_issues(report: &ScanReport, project_key: &str) -> Vec<JiraIssue> {
    report
        .findings
        .iter()
        .filter(|f| f.status != FindingStatus::FalsePositive && f.severity >= VulnerabilitySeverity::Medium)
        .map(|f| {
            let priority = match f.severity {
                VulnerabilitySeverity::Critical => "Highest",
                VulnerabilitySeverity::High => "High",
                VulnerabilitySeverity::Medium => "Medium",
                _ => "Low",
            };
            let description = format!(
                "h2. {advisory}\n\n*Package:* {pkg}@{ver}\n*Severity:* {sev}\n*Reachability:* {reach}\n*Fix:* {fix}\n\nh3. Description\n{desc}\n\nh3. References\n{refs}",
                advisory = f.advisory_id,
                pkg = f.package,
                ver = f.version,
                sev = f.severity,
                reach = f.reachability,
                fix = f.fix_version.as_deref().unwrap_or("No fix available"),
                desc = f.description,
                refs = f.references.iter().map(|r| format!("- {}", r)).collect::<Vec<_>>().join("\n"),
            );
            JiraIssue {
                project_key: project_key.to_string(),
                summary: format!("[{}] {} in {}@{}", f.advisory_id, f.summary, f.package, f.version),
                description,
                issue_type: "Bug".to_string(),
                priority: priority.to_string(),
                labels: vec!["security".to_string(), "vulnerability".to_string(), f.advisory_id.clone()],
                components: vec![],
            }
        })
        .collect()
}

// ─── Goal 174: GitHub Issues Integration ─────────────────────────────────────

/// A GitHub issue created from a vulnerability finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitHubIssue {
    pub title: String,
    pub body: String,
    pub labels: Vec<String>,
    pub assignees: Vec<String>,
}

/// Create GitHub issues from scan findings.
pub fn create_github_issues(report: &ScanReport) -> Vec<GitHubIssue> {
    report
        .findings
        .iter()
        .filter(|f| f.status != FindingStatus::FalsePositive && f.severity >= VulnerabilitySeverity::Medium)
        .map(|f| {
            let body = format!(
                "## {advisory}\n\n**Package:** `{pkg}@{ver}`\n**Severity:** {sev}\n**Reachability:** {reach}\n**Fix:** {fix}\n\n### Description\n{desc}\n\n### References\n{refs}",
                advisory = f.advisory_id,
                pkg = f.package,
                ver = f.version,
                sev = f.severity,
                reach = f.reachability,
                fix = f.fix_version.as_deref().map(|v| format!("`{}`", v)).unwrap_or("No fix available".to_string()),
                desc = f.description,
                refs = f.references.iter().map(|r| format!("- {}", r)).collect::<Vec<_>>().join("\n"),
            );
            let label_sev = match f.severity {
                VulnerabilitySeverity::Critical => "severity/critical",
                VulnerabilitySeverity::High => "severity/high",
                VulnerabilitySeverity::Medium => "severity/medium",
                VulnerabilitySeverity::Low => "severity/low",
                VulnerabilitySeverity::Info => "severity/info",
            };
            GitHubIssue {
                title: format!("[{}] {} in {}@{}", f.advisory_id, f.summary, f.package, f.version),
                body,
                labels: vec!["security".to_string(), "vulnerability".to_string(), label_sev.to_string()],
                assignees: vec![],
            }
        })
        .collect()
}

// ─── Goal 175: Linear Integration ────────────────────────────────────────────

/// A Linear issue created from a vulnerability finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinearIssue {
    pub title: String,
    pub description: String,
    pub priority: u8,
    pub labels: Vec<String>,
    pub team_id: String,
}

/// Create Linear issues from scan findings.
pub fn create_linear_issues(report: &ScanReport, team_id: &str) -> Vec<LinearIssue> {
    report
        .findings
        .iter()
        .filter(|f| f.status != FindingStatus::FalsePositive && f.severity >= VulnerabilitySeverity::Medium)
        .map(|f| {
            let priority = match f.severity {
                VulnerabilitySeverity::Critical => 1, // Urgent
                VulnerabilitySeverity::High => 2,    // High
                VulnerabilitySeverity::Medium => 3,  // Medium
                _ => 4,                               // Low
            };
            LinearIssue {
                title: format!("[{}] {} in {}@{}", f.advisory_id, f.summary, f.package, f.version),
                description: format!("{}\n\nPackage: {}@{}\nFix: {}", f.description, f.package, f.version, f.fix_version.as_deref().unwrap_or("N/A")),
                priority,
                labels: vec!["Security".to_string(), "Vulnerability".to_string()],
                team_id: team_id.to_string(),
            }
        })
        .collect()
}

// ─── Goal 176: Dependabot-Compatible Alert Format ────────────────────────────

/// A Dependabot-compatible alert.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependabotAlert {
    pub rule_id: String,
    pub rule_severity: String,
    pub rule_description: String,
    pub rule_name: String,
    pub package: DependabotPackage,
    pub vulnerability: DependabotVulnerability,
    pub url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependabotPackage {
    pub ecosystem: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependabotVulnerability {
    pub advisory_ghsa_id: String,
    pub advisory_cve_id: Option<String>,
    pub advisory_summary: String,
    pub advisory_description: String,
    pub vulnerable_version_range: String,
    pub first_patched_version: Option<String>,
}

/// Convert scan findings to Dependabot alert format.
pub fn to_dependabot_alerts(report: &ScanReport) -> Vec<DependabotAlert> {
    report
        .findings
        .iter()
        .filter(|f| f.status != FindingStatus::FalsePositive)
        .map(|f| {
            let ecosystem = f.package.split(':').next().unwrap_or("unknown").to_string();
            let name = f.package.split(':').nth(1).unwrap_or(&f.package).to_string();
            let severity = match f.severity {
                VulnerabilitySeverity::Critical => "critical",
                VulnerabilitySeverity::High => "high",
                VulnerabilitySeverity::Medium => "medium",
                VulnerabilitySeverity::Low => "low",
                VulnerabilitySeverity::Info => "info",
            };
            DependabotAlert {
                rule_id: f.advisory_id.clone(),
                rule_severity: severity.to_string(),
                rule_description: f.summary.clone(),
                rule_name: f.advisory_id.clone(),
                package: DependabotPackage { ecosystem, name },
                vulnerability: DependabotVulnerability {
                    advisory_ghsa_id: f.advisory_id.clone(),
                    advisory_cve_id: f.aliases.iter().find(|a| a.starts_with("CVE-")).cloned(),
                    advisory_summary: f.summary.clone(),
                    advisory_description: f.description.clone(),
                    vulnerable_version_range: f.version.clone(),
                    first_patched_version: f.fix_version.clone(),
                },
                url: f.references.first().cloned().unwrap_or_default(),
            }
        })
        .collect()
}

// ─── Goal 177: ServiceNow Integration ────────────────────────────────────────

/// A ServiceNow security incident.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceNowIncident {
    pub short_description: String,
    pub description: String,
    pub urgency: String,
    pub impact: String,
    pub priority: String,
    pub category: String,
    pub subcategory: String,
    pub cmdb_ci: String,
}

/// Create ServiceNow incidents from scan findings.
pub fn create_servicenow_incidents(report: &ScanReport) -> Vec<ServiceNowIncident> {
    report
        .findings
        .iter()
        .filter(|f| f.status != FindingStatus::FalsePositive && f.severity >= VulnerabilitySeverity::High)
        .map(|f| {
            let (urgency, impact, priority) = match f.severity {
                VulnerabilitySeverity::Critical => ("1", "1", "1"),
                VulnerabilitySeverity::High => ("2", "2", "2"),
                _ => ("3", "3", "3"),
            };
            ServiceNowIncident {
                short_description: format!("[{}] {} in {}", f.advisory_id, f.summary, f.package),
                description: format!("{}\n\nPackage: {}@{}\nFix: {}", f.description, f.package, f.version, f.fix_version.as_deref().unwrap_or("N/A")),
                urgency: urgency.to_string(),
                impact: impact.to_string(),
                priority: priority.to_string(),
                category: "Security".to_string(),
                subcategory: "Vulnerability".to_string(),
                cmdb_ci: f.package.clone(),
            }
        })
        .collect()
}

// ─── Goal 178: Splunk/ELK Integration (SIEM) ─────────────────────────────────

/// SIEM event format (CEF - Common Event Format).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CefEvent {
    pub version: String,
    pub vendor: String,
    pub product: String,
    pub product_version: String,
    pub signature_id: String,
    pub name: String,
    pub severity: String,
    pub extension: String,
}

/// Convert scan findings to CEF events for Splunk/ELK.
pub fn to_cef_events(report: &ScanReport) -> Vec<CefEvent> {
    report
        .findings
        .iter()
        .filter(|f| f.status != FindingStatus::FalsePositive)
        .map(|f| {
            let severity = match f.severity {
                VulnerabilitySeverity::Critical => "10",
                VulnerabilitySeverity::High => "8",
                VulnerabilitySeverity::Medium => "6",
                VulnerabilitySeverity::Low => "4",
                VulnerabilitySeverity::Info => "2",
            };
            CefEvent {
                version: "0".to_string(),
                vendor: "PledgeLabs".to_string(),
                product: "PledgeRecon".to_string(),
                product_version: "1.0".to_string(),
                signature_id: f.advisory_id.clone(),
                name: f.summary.clone(),
                severity: severity.to_string(),
                extension: format!(
                    "pkg={} ver={} fix={} reach={}",
                    f.package, f.version,
                    f.fix_version.as_deref().unwrap_or("N/A"),
                    f.reachability
                ),
            }
        })
        .collect()
}

/// Render a CEF event as a CEF-formatted string.
pub fn cef_to_string(event: &CefEvent) -> String {
    format!(
        "CEF:{}|{}|{}|{}|{}|{}|{}|{}",
        event.version, event.vendor, event.product, event.product_version,
        event.signature_id, event.name, event.severity, event.extension
    )
}

// ─── Goal 179: PagerDuty Integration ─────────────────────────────────────────

/// A PagerDuty event for triggering incidents.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PagerDutyEvent {
    pub routing_key: String,
    pub event_action: String,
    pub dedup_key: String,
    pub payload: PagerDutyPayload,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PagerDutyPayload {
    pub summary: String,
    pub severity: String,
    pub source: String,
    pub component: String,
    pub custom_details: serde_json::Value,
}

/// Create PagerDuty events for critical findings.
pub fn create_pagerduty_events(report: &ScanReport, routing_key: &str) -> Vec<PagerDutyEvent> {
    report
        .findings
        .iter()
        .filter(|f| f.status != FindingStatus::FalsePositive && f.severity >= VulnerabilitySeverity::Critical)
        .map(|f| {
            let severity = match f.severity {
                VulnerabilitySeverity::Critical => "critical",
                _ => "error",
            };
            PagerDutyEvent {
                routing_key: routing_key.to_string(),
                event_action: "trigger".to_string(),
                dedup_key: format!("pledgerecon-{}", f.advisory_id),
                payload: PagerDutyPayload {
                    summary: format!("[{}] {} in {}@{}", f.advisory_id, f.summary, f.package, f.version),
                    severity: severity.to_string(),
                    source: "PledgeRecon".to_string(),
                    component: f.package.clone(),
                    custom_details: serde_json::json!({
                        "advisory_id": f.advisory_id,
                        "package": f.package,
                        "version": f.version,
                        "fix_version": f.fix_version,
                        "reachability": f.reachability.to_string(),
                    }),
                },
            }
        })
        .collect()
}

// ─── Goal 180: Discord Notification ──────────────────────────────────────────

/// Discord webhook notification configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscordNotification {
    pub webhook_url: String,
    pub username: Option<String>,
    pub avatar_url: Option<String>,
}

impl DiscordNotification {
    pub fn new(webhook_url: &str) -> Self {
        Self { webhook_url: webhook_url.to_string(), username: Some("PledgeRecon".to_string()), avatar_url: None }
    }

    /// Build a Discord embed payload from a scan report.
    pub fn build_payload(&self, report: &ScanReport) -> serde_json::Value {
        let critical = report.count_by_severity(VulnerabilitySeverity::Critical);
        let high = report.count_by_severity(VulnerabilitySeverity::High);
        let medium = report.count_by_severity(VulnerabilitySeverity::Medium);
        let low = report.count_by_severity(VulnerabilitySeverity::Low);
        let color = if critical > 0 { 0xFF0000 } else if high > 0 { 0xFF6600 } else if medium > 0 { 0xFFCC00 } else { 0x00FF00 };
        let title = if report.findings.is_empty() { "No vulnerabilities found".to_string() } else { format!("Found {} vulnerabilities", report.findings.len()) };
        serde_json::json!({
            "username": self.username,
            "embeds": [{
                "title": title,
                "color": color,
                "fields": [
                    { "name": "Critical", "value": critical.to_string(), "inline": true },
                    { "name": "High", "value": high.to_string(), "inline": true },
                    { "name": "Medium", "value": medium.to_string(), "inline": true },
                    { "name": "Low", "value": low.to_string(), "inline": true },
                ],
                "footer": { "text": "PledgeRecon Security Scanner" },
            }]
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::ScanReport;
    use crate::finding::{Finding, FindingStatus, ReachabilityStatus, VulnerabilitySeverity};
    use std::path::PathBuf;

    fn make_finding(sev: VulnerabilitySeverity) -> Finding {
        Finding {
            advisory_id: "CVE-2024-12345".into(), summary: "Test vuln".into(), description: "A test".into(),
            severity: sev, cvss_score: Some(7.5), package: "npm:lodash".into(), version: "4.17.0".into(),
            fix_version: Some("4.17.21".into()), fix_available: true,
            reachability: ReachabilityStatus::Reachable, vulnerable_functions: vec![], call_chain: vec![],
            status: FindingStatus::Pending, triage_explanation: None,
            references: vec!["https://example.com/ref".into()], cwes: vec!["CWE-79".into()],
            manifest_path: PathBuf::from("package.json"), aliases: vec!["GHSA-test".into()],
        }
    }

    fn make_report(findings: Vec<Finding>) -> ScanReport {
        ScanReport { scan_id: "test".into(), project_name: "test".into(), scanned_at: chrono::Utc::now(), duration_ms: 100, dependencies_scanned: 10, advisories_checked: 5, findings }
    }

    #[test]
    fn test_vscode_diagnostics() {
        let report = make_report(vec![make_finding(VulnerabilitySeverity::High)]);
        let diags = generate_vscode_diagnostics(&report);
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].severity, VsCodeSeverity::Error);
        assert_eq!(diags[0].source, "pledgerecon");
    }

    #[test]
    fn test_vscode_diagnostics_filters_fp() {
        let mut f = make_finding(VulnerabilitySeverity::High);
        f.status = FindingStatus::FalsePositive;
        let report = make_report(vec![f]);
        let diags = generate_vscode_diagnostics(&report);
        assert_eq!(diags.len(), 0);
    }

    #[test]
    fn test_jetbrains_inspections() {
        let report = make_report(vec![make_finding(VulnerabilitySeverity::Medium)]);
        let insp = generate_jetbrains_inspections(&report);
        assert_eq!(insp.len(), 1);
        assert_eq!(insp[0].severity, "WARNING");
        assert!(insp[0].quick_fix.is_some());
    }

    #[test]
    fn test_jira_issues() {
        let report = make_report(vec![make_finding(VulnerabilitySeverity::Critical)]);
        let issues = create_jira_issues(&report, "SEC");
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].project_key, "SEC");
        assert_eq!(issues[0].priority, "Highest");
        assert!(issues[0].description.contains("CVE-2024-12345"));
    }

    #[test]
    fn test_jira_filters_low() {
        let report = make_report(vec![make_finding(VulnerabilitySeverity::Low)]);
        let issues = create_jira_issues(&report, "SEC");
        assert_eq!(issues.len(), 0);
    }

    #[test]
    fn test_github_issues() {
        let report = make_report(vec![make_finding(VulnerabilitySeverity::High)]);
        let issues = create_github_issues(&report);
        assert_eq!(issues.len(), 1);
        assert!(issues[0].labels.contains(&"severity/high".to_string()));
        assert!(issues[0].body.contains("CVE-2024-12345"));
    }

    #[test]
    fn test_linear_issues() {
        let report = make_report(vec![make_finding(VulnerabilitySeverity::High)]);
        let issues = create_linear_issues(&report, "team-123");
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].priority, 2);
        assert_eq!(issues[0].team_id, "team-123");
    }

    #[test]
    fn test_dependabot_alerts() {
        let report = make_report(vec![make_finding(VulnerabilitySeverity::High)]);
        let alerts = to_dependabot_alerts(&report);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].package.ecosystem, "npm");
        assert_eq!(alerts[0].package.name, "lodash");
        assert_eq!(alerts[0].vulnerability.advisory_ghsa_id, "CVE-2024-12345");
    }

    #[test]
    fn test_servicenow_incidents() {
        let report = make_report(vec![make_finding(VulnerabilitySeverity::Critical)]);
        let incs = create_servicenow_incidents(&report);
        assert_eq!(incs.len(), 1);
        assert_eq!(incs[0].priority, "1");
        assert_eq!(incs[0].category, "Security");
    }

    #[test]
    fn test_servicenow_filters_medium() {
        let report = make_report(vec![make_finding(VulnerabilitySeverity::Medium)]);
        let incs = create_servicenow_incidents(&report);
        assert_eq!(incs.len(), 0);
    }

    #[test]
    fn test_cef_events() {
        let report = make_report(vec![make_finding(VulnerabilitySeverity::High)]);
        let events = to_cef_events(&report);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].severity, "8");
        let cef_str = cef_to_string(&events[0]);
        assert!(cef_str.starts_with("CEF:0|PledgeLabs|PledgeRecon"));
    }

    #[test]
    fn test_pagerduty_events() {
        let report = make_report(vec![make_finding(VulnerabilitySeverity::Critical)]);
        let events = create_pagerduty_events(&report, "routing-key-123");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].routing_key, "routing-key-123");
        assert_eq!(events[0].payload.severity, "critical");
    }

    #[test]
    fn test_pagerduty_filters_non_critical() {
        let report = make_report(vec![make_finding(VulnerabilitySeverity::High)]);
        let events = create_pagerduty_events(&report, "key");
        assert_eq!(events.len(), 0);
    }

    #[test]
    fn test_discord_notification() {
        let discord = DiscordNotification::new("https://discord.com/api/webhooks/123");
        let report = make_report(vec![make_finding(VulnerabilitySeverity::Critical)]);
        let payload = discord.build_payload(&report);
        let embeds = payload["embeds"].as_array().unwrap();
        assert_eq!(embeds.len(), 1);
        assert_eq!(embeds[0]["color"], 0xFF0000);
        let fields = embeds[0]["fields"].as_array().unwrap();
        assert_eq!(fields[0]["value"], "1"); // 1 critical
    }

    #[test]
    fn test_discord_no_findings() {
        let discord = DiscordNotification::new("https://discord.com/api/webhooks/123");
        let report = make_report(vec![]);
        let payload = discord.build_payload(&report);
        let embeds = payload["embeds"].as_array().unwrap();
        assert_eq!(embeds[0]["color"], 0x00FF00);
    }
}
