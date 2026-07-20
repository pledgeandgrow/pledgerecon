//! Notifications — Slack, Microsoft Teams, and email (Goals 63–65).
//!
//! Post-scan notifications for integrating PledgeRecon into team workflows.

use crate::finding::{ReachabilityStatus, VulnerabilitySeverity};
use crate::scanner::ScanReport;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Errors during notification operations.
#[derive(Debug, Error)]
pub enum NotifyError {
    #[error("HTTP error: {0}")]
    Http(String),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("missing webhook URL")]
    MissingWebhookUrl,
    #[error("missing SMTP configuration")]
    MissingSmtpConfig,
}

/// Slack notification configuration (Goal 63).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlackNotification {
    /// Slack webhook URL (incoming webhook).
    pub webhook_url: String,
    /// Optional channel override (e.g. "#security-alerts").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel: Option<String>,
    /// Optional emoji icon.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icon_emoji: Option<String>,
}

impl SlackNotification {
    /// Create a new Slack notification config with a webhook URL.
    pub fn new(webhook_url: &str) -> Self {
        Self {
            webhook_url: webhook_url.to_string(),
            channel: None,
            icon_emoji: Some(":shield:".to_string()),
        }
    }

    /// Build the Slack message payload as JSON.
    pub fn build_payload(&self, report: &ScanReport) -> serde_json::Value {
        let critical = report.count_by_severity(VulnerabilitySeverity::Critical);
        let high = report.count_by_severity(VulnerabilitySeverity::High);
        let medium = report.count_by_severity(VulnerabilitySeverity::Medium);
        let low = report.count_by_severity(VulnerabilitySeverity::Low);
        let reachable = report.count_by_reachability(ReachabilityStatus::Reachable);

        let color = if critical > 0 {
            "#dc2626"
        } else if high > 0 {
            "#ea580c"
        } else if medium > 0 {
            "#ca8a04"
        } else {
            "#22c55e"
        };

        let title = if report.findings.is_empty() {
            "✅ PledgeRecon: No vulnerabilities found".to_string()
        } else {
            format!(
                "🚨 PledgeRecon: {} finding(s) — {} critical, {} high, {} medium, {} low",
                report.findings.len(),
                critical,
                high,
                medium,
                low
            )
        };

        let mut fields = vec![
            serde_json::json!({
                "title": "Project",
                "value": &report.project_name,
                "short": true,
            }),
            serde_json::json!({
                "title": "Dependencies Scanned",
                "value": report.dependencies_scanned.to_string(),
                "short": true,
            }),
            serde_json::json!({
                "title": "Reachable",
                "value": format!("{} of {}", reachable, report.findings.len()),
                "short": true,
            }),
            serde_json::json!({
                "title": "Duration",
                "value": format!("{}ms", report.duration_ms),
                "short": true,
            }),
        ];

        // Top 5 critical/high findings.
        let mut sorted_findings = report.findings.clone();
        sorted_findings.sort_by_key(|b| std::cmp::Reverse(b.severity));
        let top_findings: Vec<&crate::finding::Finding> = sorted_findings.iter().take(5).collect();

        if !top_findings.is_empty() {
            let detail_text = top_findings
                .iter()
                .map(|f| {
                    format!(
                        "• {} `{}` — `{}@{}` [{}]",
                        f.severity,
                        f.advisory_id,
                        f.package,
                        f.version,
                        f.summary
                    )
                })
                .collect::<Vec<_>>()
                .join("\n");

            fields.push(serde_json::json!({
                "title": "Top Findings",
                "value": detail_text,
                "short": false,
            }));
        }

        let mut payload = serde_json::json!({
            "attachments": [{
                "color": color,
                "title": title,
                "fields": fields,
                "footer": format!("PledgeRecon v{}", env!("CARGO_PKG_VERSION")),
                "ts": report.scanned_at.timestamp(),
            }],
        });

        if let Some(ref ch) = self.channel {
            payload["channel"] = serde_json::json!(ch);
        }
        if let Some(ref icon) = self.icon_emoji {
            payload["icon_emoji"] = serde_json::json!(icon);
        }

        payload
    }

    /// Send the notification to Slack via webhook.
    pub fn send(&self, report: &ScanReport) -> Result<(), NotifyError> {
        let payload = self.build_payload(report);
        let body = serde_json::to_string(&payload)?;

        let response = ureq::post(&self.webhook_url)
            .set("Content-Type", "application/json")
            .send_string(&body)
            .map_err(|e| NotifyError::Http(e.to_string()))?;

        if response.status() >= 400 {
            return Err(NotifyError::Http(format!(
                "Slack webhook returned {}",
                response.status()
            )));
        }

        Ok(())
    }
}

/// Microsoft Teams notification configuration (Goal 64).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeamsNotification {
    /// Teams incoming webhook URL.
    pub webhook_url: String,
}

impl TeamsNotification {
    /// Create a new Teams notification config with a webhook URL.
    pub fn new(webhook_url: &str) -> Self {
        Self {
            webhook_url: webhook_url.to_string(),
        }
    }

    /// Build the Teams message card payload as JSON.
    pub fn build_payload(&self, report: &ScanReport) -> serde_json::Value {
        let critical = report.count_by_severity(VulnerabilitySeverity::Critical);
        let high = report.count_by_severity(VulnerabilitySeverity::High);
        let medium = report.count_by_severity(VulnerabilitySeverity::Medium);
        let low = report.count_by_severity(VulnerabilitySeverity::Low);
        let reachable = report.count_by_reachability(ReachabilityStatus::Reachable);

        let theme_color = if critical > 0 {
            "FF0000"
        } else if high > 0 {
            "EA580C"
        } else if medium > 0 {
            "CA8A04"
        } else {
            "22C55E"
        };

        let summary = if report.findings.is_empty() {
            "No vulnerabilities found".to_string()
        } else {
            format!(
                "{} findings — {} critical, {} high, {} medium, {} low ({} reachable)",
                report.findings.len(),
                critical,
                high,
                medium,
                low,
                reachable
            )
        };

        let mut facts = vec![
            serde_json::json!({ "name": "Project", "value": &report.project_name }),
            serde_json::json!({ "name": "Dependencies", "value": report.dependencies_scanned.to_string() }),
            serde_json::json!({ "name": "Duration", "value": format!("{}ms", report.duration_ms) }),
            serde_json::json!({ "name": "Scan ID", "value": &report.scan_id }),
        ];

        // Top 3 findings.
        let mut sorted_findings = report.findings.clone();
        sorted_findings.sort_by_key(|b| std::cmp::Reverse(b.severity));
        let top_findings: Vec<&crate::finding::Finding> = sorted_findings.iter().take(3).collect();

        for f in &top_findings {
            facts.push(serde_json::json!({
                "name": format!("[{}] {}", f.severity, f.advisory_id),
                "value": format!("{}@{} — {}", f.package, f.version, f.summary),
            }));
        }

        serde_json::json!({
            "@type": "MessageCard",
            "@context": "https://schema.org/extensions",
            "themeColor": theme_color,
            "summary": &summary,
            "sections": [{
                "activityTitle": "PledgeRecon Security Scan",
                "activitySubtitle": report.scanned_at.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
                "facts": facts,
                "text": if report.findings.is_empty() {
                    "✅ **No vulnerabilities found.**"
                } else {
                    &summary
                },
                "markdown": true,
            }],
            "potentialAction": [{
                "@type": "OpenUri",
                "name": "View Report",
                "targets": [{
                    "os": "default",
                    "uri": format!("https://github.com/pledgeandgrow/pledgerecon"),
                }],
            }],
        })
    }

    /// Send the notification to Teams via webhook.
    pub fn send(&self, report: &ScanReport) -> Result<(), NotifyError> {
        let payload = self.build_payload(report);
        let body = serde_json::to_string(&payload)?;

        let response = ureq::post(&self.webhook_url)
            .set("Content-Type", "application/json")
            .send_string(&body)
            .map_err(|e| NotifyError::Http(e.to_string()))?;

        if response.status() >= 400 {
            return Err(NotifyError::Http(format!(
                "Teams webhook returned {}",
                response.status()
            )));
        }

        Ok(())
    }
}

/// Email notification configuration (Goal 65).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailReport {
    /// SMTP server hostname.
    pub smtp_host: String,
    /// SMTP server port (e.g. 587 for TLS, 465 for SSL).
    pub smtp_port: u16,
    /// SMTP username for authentication.
    pub smtp_username: String,
    /// SMTP password for authentication.
    pub smtp_password: String,
    /// From email address.
    pub from_address: String,
    /// Recipient email addresses.
    pub to_addresses: Vec<String>,
    /// Whether to use TLS.
    #[serde(default = "default_true")]
    pub use_tls: bool,
}

fn default_true() -> bool {
    true
}

impl EmailReport {
    /// Create a new email report config.
    pub fn new(
        smtp_host: &str,
        smtp_port: u16,
        username: &str,
        password: &str,
        from: &str,
        to: Vec<String>,
    ) -> Self {
        Self {
            smtp_host: smtp_host.to_string(),
            smtp_port,
            smtp_username: username.to_string(),
            smtp_password: password.to_string(),
            from_address: from.to_string(),
            to_addresses: to,
            use_tls: true,
        }
    }

    /// Build the email subject for a scan report.
    pub fn build_subject(&self, report: &ScanReport) -> String {
        if report.findings.is_empty() {
            format!("[PledgeRecon] {} — No vulnerabilities found", report.project_name)
        } else {
            let critical = report.count_by_severity(VulnerabilitySeverity::Critical);
            let high = report.count_by_severity(VulnerabilitySeverity::High);
            format!(
                "[PledgeRecon] {} — {} findings ({} critical, {} high)",
                report.project_name,
                report.findings.len(),
                critical,
                high
            )
        }
    }

    /// Build the email body (HTML) for a scan report.
    pub fn build_body_html(&self, report: &ScanReport) -> String {
        let critical = report.count_by_severity(VulnerabilitySeverity::Critical);
        let high = report.count_by_severity(VulnerabilitySeverity::High);
        let medium = report.count_by_severity(VulnerabilitySeverity::Medium);
        let low = report.count_by_severity(VulnerabilitySeverity::Low);

        let mut html = String::new();
        html.push_str("<html><body style=\"font-family: sans-serif;\">\n");
        html.push_str(&format!(
            "<h2>PledgeRecon Security Scan Report</h2>\n"
        ));
        html.push_str(&format!(
            "<p><strong>Project:</strong> {}<br>\n\
             <strong>Scan ID:</strong> {}<br>\n\
             <strong>Scanned at:</strong> {}<br>\n\
             <strong>Duration:</strong> {}ms</p>\n",
            report.project_name,
            report.scan_id,
            report.scanned_at.format("%Y-%m-%d %H:%M:%S UTC"),
            report.duration_ms
        ));

        if report.findings.is_empty() {
            html.push_str("<p style=\"color: green; font-size: 1.2em;\">✅ No vulnerabilities found.</p>\n");
        } else {
            html.push_str(&format!(
                "<h3>Summary: {} findings</h3>\n\
                 <table border=\"1\" cellpadding=\"6\" style=\"border-collapse: collapse;\">\n\
                 <tr><th>Severity</th><th>Count</th></tr>\n\
                 <tr><td>Critical</td><td>{}</td></tr>\n\
                 <tr><td>High</td><td>{}</td></tr>\n\
                 <tr><td>Medium</td><td>{}</td></tr>\n\
                 <tr><td>Low</td><td>{}</td></tr>\n\
                 </table>\n",
                report.findings.len(),
                critical,
                high,
                medium,
                low
            ));

            html.push_str("<h3>Findings</h3>\n<table border=\"1\" cellpadding=\"6\" style=\"border-collapse: collapse; width: 100%;\">\n");
            html.push_str("<tr><th>Severity</th><th>Advisory</th><th>Package</th><th>Summary</th><th>Fix</th></tr>\n");

            let mut findings = report.findings.clone();
            findings.sort_by_key(|b| std::cmp::Reverse(b.severity));

            for f in &findings {
                let color = match f.severity {
                    VulnerabilitySeverity::Critical => "#dc2626",
                    VulnerabilitySeverity::High => "#ea580c",
                    VulnerabilitySeverity::Medium => "#ca8a04",
                    VulnerabilitySeverity::Low => "#3b82f6",
                    VulnerabilitySeverity::Info => "#6b7280",
                };
                html.push_str(&format!(
                    "<tr style=\"color: {};\"><td><strong>{}</strong></td><td>{}</td><td>{}@{}</td><td>{}</td><td>{}</td></tr>\n",
                    color,
                    f.severity,
                    f.advisory_id,
                    f.package,
                    f.version,
                    f.summary,
                    f.fix_version.as_deref().unwrap_or("N/A"),
                ));
            }
            html.push_str("</table>\n");
        }

        html.push_str(&format!(
            "<hr><p style=\"color: #999; font-size: 0.85em;\">Generated by PledgeRecon v{}</p>\n",
            env!("CARGO_PKG_VERSION")
        ));
        html.push_str("</body></html>\n");

        html
    }

    /// Build the raw SMTP message (headers + body).
    pub fn build_smtp_message(&self, report: &ScanReport) -> String {
        let subject = self.build_subject(report);
        let body = self.build_body_html(report);
        let to = self.to_addresses.join(", ");

        format!(
            "From: {}\r\n\
             To: {}\r\n\
             Subject: {}\r\n\
             MIME-Version: 1.0\r\n\
             Content-Type: text/html; charset=UTF-8\r\n\
             \r\n\
             {}",
            self.from_address, to, subject, body
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::{Finding, FindingStatus};
    use chrono::Utc;
    use std::path::PathBuf;
    use uuid::Uuid;

    fn make_report() -> ScanReport {
        let finding = Finding {
            advisory_id: "CVE-2021-23337".to_string(),
            summary: "Command injection in lodash".to_string(),
            description: "Test".to_string(),
            severity: VulnerabilitySeverity::High,
            cvss_score: Some(7.2),
            package: "npm:lodash".to_string(),
            version: "4.17.11".to_string(),
            fix_version: Some("4.17.21".to_string()),
            fix_available: true,
            reachability: ReachabilityStatus::Reachable,
            vulnerable_functions: vec![],
            call_chain: vec![],
            status: FindingStatus::Pending,
            triage_explanation: None,
            references: vec![],
            cwes: vec![],
            manifest_path: PathBuf::from("package.json"),
            aliases: vec![],
        };

        ScanReport {
            scan_id: Uuid::new_v4().to_string(),
            project_name: "test-project".to_string(),
            scanned_at: Utc::now(),
            duration_ms: 42,
            dependencies_scanned: 10,
            advisories_checked: 5,
            findings: vec![finding],
        }
    }

    fn make_empty_report() -> ScanReport {
        ScanReport {
            scan_id: Uuid::new_v4().to_string(),
            project_name: "clean-project".to_string(),
            scanned_at: Utc::now(),
            duration_ms: 10,
            dependencies_scanned: 5,
            advisories_checked: 3,
            findings: vec![],
        }
    }

    #[test]
    fn test_slack_payload_with_findings() {
        let slack = SlackNotification::new("https://hooks.slack.com/test");
        let report = make_report();
        let payload = slack.build_payload(&report);
        let attachments = payload["attachments"].as_array().unwrap();
        assert_eq!(attachments.len(), 1);
        assert!(attachments[0]["title"].as_str().unwrap().contains("finding"));
    }

    #[test]
    fn test_slack_payload_no_findings() {
        let slack = SlackNotification::new("https://hooks.slack.com/test");
        let report = make_empty_report();
        let payload = slack.build_payload(&report);
        let attachments = payload["attachments"].as_array().unwrap();
        let title = attachments[0]["title"].as_str().unwrap();
        assert!(title.contains("No vulnerabilities"));
    }

    #[test]
    fn test_teams_payload_with_findings() {
        let teams = TeamsNotification::new("https://outlook.office.com/webhook/test");
        let report = make_report();
        let payload = teams.build_payload(&report);
        assert_eq!(payload["@type"].as_str().unwrap(), "MessageCard");
        assert!(payload["summary"].as_str().unwrap().contains("findings"));
    }

    #[test]
    fn test_teams_payload_no_findings() {
        let teams = TeamsNotification::new("https://outlook.office.com/webhook/test");
        let report = make_empty_report();
        let payload = teams.build_payload(&report);
        assert!(payload["summary"].as_str().unwrap().contains("No vulnerabilities"));
    }

    #[test]
    fn test_email_subject_with_findings() {
        let email = EmailReport::new(
            "smtp.gmail.com",
            587,
            "user",
            "pass",
            "from@test.com",
            vec!["to@test.com".to_string()],
        );
        let report = make_report();
        let subject = email.build_subject(&report);
        assert!(subject.contains("test-project"));
        assert!(subject.contains("findings"));
    }

    #[test]
    fn test_email_subject_no_findings() {
        let email = EmailReport::new(
            "smtp.gmail.com",
            587,
            "user",
            "pass",
            "from@test.com",
            vec!["to@test.com".to_string()],
        );
        let report = make_empty_report();
        let subject = email.build_subject(&report);
        assert!(subject.contains("No vulnerabilities"));
    }

    #[test]
    fn test_email_body_html() {
        let email = EmailReport::new(
            "smtp.gmail.com",
            587,
            "user",
            "pass",
            "from@test.com",
            vec!["to@test.com".to_string()],
        );
        let report = make_report();
        let html = email.build_body_html(&report);
        assert!(html.contains("PledgeRecon"));
        assert!(html.contains("CVE-2021-23337"));
        assert!(html.contains("lodash"));
    }

    #[test]
    fn test_email_smtp_message() {
        let email = EmailReport::new(
            "smtp.gmail.com",
            587,
            "user",
            "pass",
            "from@test.com",
            vec!["to@test.com".to_string()],
        );
        let report = make_report();
        let msg = email.build_smtp_message(&report);
        assert!(msg.contains("From: from@test.com"));
        assert!(msg.contains("To: to@test.com"));
        assert!(msg.contains("Subject:"));
        assert!(msg.contains("MIME-Version: 1.0"));
        assert!(msg.contains("Content-Type: text/html"));
    }
}
