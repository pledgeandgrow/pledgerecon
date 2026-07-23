//! Report comparison and trend tracking (Goals 58–59).
//!
//! Diff reports compare two scan reports to show new and resolved vulnerabilities.
//! Trend tracking stores scan history for vulnerability trend analysis over time.

use crate::finding::{Finding, FindingStatus, ReachabilityStatus, VulnerabilitySeverity};
use crate::scanner::ScanReport;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use thiserror::Error;

/// Errors during report operations.
#[derive(Debug, Error)]
pub enum ReportError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("report file not found: {0}")]
    NotFound(String),
}

/// A finding key used for comparison — uniquely identifies a finding.
fn finding_key(f: &Finding) -> String {
    format!("{}@{}#{}", f.package, f.version, f.advisory_id)
}

/// The result of comparing two scan reports.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffReport {
    /// The previous (baseline) scan.
    pub previous: ReportSummary,
    /// The current scan.
    pub current: ReportSummary,
    /// Findings that are new in the current scan (not in the previous).
    pub new_findings: Vec<Finding>,
    /// Findings that were in the previous scan but are resolved in the current.
    pub resolved_findings: Vec<Finding>,
    /// Findings present in both scans (unchanged).
    pub unchanged_findings: Vec<Finding>,
    /// Findings where the severity changed.
    pub severity_changes: Vec<SeverityChange>,
}

/// A summary of a scan report for diff/trend purposes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportSummary {
    pub scan_id: String,
    pub project_name: String,
    pub scanned_at: DateTime<Utc>,
    pub total_findings: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
}

/// A severity change between two scans for the same finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeverityChange {
    pub advisory_id: String,
    pub package: String,
    pub version: String,
    pub previous_severity: VulnerabilitySeverity,
    pub current_severity: VulnerabilitySeverity,
}

impl DiffReport {
    /// Compare two scan reports.
    pub fn from_reports(previous: &ScanReport, current: &ScanReport) -> Self {
        let prev_keys: HashMap<String, &Finding> = previous
            .findings
            .iter()
            .map(|f| (finding_key(f), f))
            .collect();
        let curr_keys: HashMap<String, &Finding> = current
            .findings
            .iter()
            .map(|f| (finding_key(f), f))
            .collect();

        let prev_set: HashSet<&String> = prev_keys.keys().collect();
        let curr_set: HashSet<&String> = curr_keys.keys().collect();

        let new_findings: Vec<Finding> = curr_set
            .difference(&prev_set)
            .filter_map(|k| curr_keys.get(*k).map(|f| (*f).clone()))
            .collect();

        let resolved_findings: Vec<Finding> = prev_set
            .difference(&curr_set)
            .filter_map(|k| prev_keys.get(*k).map(|f| (*f).clone()))
            .collect();

        let unchanged_findings: Vec<Finding> = curr_set
            .intersection(&prev_set)
            .filter_map(|k| {
                let f = curr_keys.get(*k)?;
                if f.severity == prev_keys[*k].severity {
                    Some((*f).clone())
                } else {
                    None
                }
            })
            .collect();

        let severity_changes: Vec<SeverityChange> = curr_set
            .intersection(&prev_set)
            .filter_map(|k| {
                let curr_f = curr_keys.get(*k)?;
                let prev_f = prev_keys.get(*k)?;
                if curr_f.severity != prev_f.severity {
                    Some(SeverityChange {
                        advisory_id: curr_f.advisory_id.clone(),
                        package: curr_f.package.clone(),
                        version: curr_f.version.clone(),
                        previous_severity: prev_f.severity,
                        current_severity: curr_f.severity,
                    })
                } else {
                    None
                }
            })
            .collect();

        Self {
            previous: ReportSummary::from_report(previous),
            current: ReportSummary::from_report(current),
            new_findings,
            resolved_findings,
            unchanged_findings,
            severity_changes,
        }
    }

    /// Whether the diff has any changes.
    pub fn has_changes(&self) -> bool {
        !self.new_findings.is_empty() || !self.resolved_findings.is_empty()
    }

    /// Whether new findings were introduced.
    pub fn has_new_findings(&self) -> bool {
        !self.new_findings.is_empty()
    }

    /// Render the diff report as text.
    pub fn to_text(&self) -> String {
        let mut out = String::new();
        out.push_str("PledgeRecon Diff Report\n");
        out.push_str("=======================\n\n");
        out.push_str(&format!(
            "Previous: {} ({} findings, {} critical, {} high)\n",
            self.previous.scanned_at.format("%Y-%m-%d %H:%M:%S UTC"),
            self.previous.total_findings,
            self.previous.critical,
            self.previous.high
        ));
        out.push_str(&format!(
            "Current:  {} ({} findings, {} critical, {} high)\n\n",
            self.current.scanned_at.format("%Y-%m-%d %H:%M:%S UTC"),
            self.current.total_findings,
            self.current.critical,
            self.current.high
        ));

        if self.new_findings.is_empty() && self.resolved_findings.is_empty() {
            out.push_str("No changes detected.\n");
            return out;
        }

        if !self.new_findings.is_empty() {
            out.push_str(&format!("New Findings ({}):\n", self.new_findings.len()));
            for f in &self.new_findings {
                out.push_str(&format!(
                    "  + [{}] {} — {}@{} ({})\n",
                    f.severity, f.advisory_id, f.package, f.version, f.summary
                ));
            }
            out.push('\n');
        }

        if !self.resolved_findings.is_empty() {
            out.push_str(&format!(
                "Resolved Findings ({}):\n",
                self.resolved_findings.len()
            ));
            for f in &self.resolved_findings {
                out.push_str(&format!(
                    "  - [{}] {} — {}@{} ({})\n",
                    f.severity, f.advisory_id, f.package, f.version, f.summary
                ));
            }
            out.push('\n');
        }

        if !self.severity_changes.is_empty() {
            out.push_str(&format!(
                "Severity Changes ({}):\n",
                self.severity_changes.len()
            ));
            for c in &self.severity_changes {
                out.push_str(&format!(
                    "  ~ {} — {}@{}: {} → {}\n",
                    c.advisory_id, c.package, c.version, c.previous_severity, c.current_severity
                ));
            }
        }

        out
    }

    /// Render the diff report as markdown.
    pub fn to_markdown(&self) -> String {
        let mut md = String::new();
        md.push_str("# PledgeRecon Diff Report\n\n");
        md.push_str(&format!(
            "| | Previous | Current |\n|---|---|---|\n\
             | Date | {} | {} |\n\
             | Total | {} | {} |\n\
             | Critical | {} | {} |\n\
             | High | {} | {} |\n\
             | Medium | {} | {} |\n\
             | Low | {} | {} |\n\n",
            self.previous.scanned_at.format("%Y-%m-%d"),
            self.current.scanned_at.format("%Y-%m-%d"),
            self.previous.total_findings,
            self.current.total_findings,
            self.previous.critical,
            self.current.critical,
            self.previous.high,
            self.current.high,
            self.previous.medium,
            self.current.medium,
            self.previous.low,
            self.current.low,
        ));

        if self.new_findings.is_empty() && self.resolved_findings.is_empty() {
            md.push_str("✅ **No changes detected.**\n");
            return md;
        }

        if !self.new_findings.is_empty() {
            md.push_str(&format!(
                "## 🆕 New Findings ({})\n\n| Severity | Advisory | Package | Summary |\n|---|---|---|---|\n",
                self.new_findings.len()
            ));
            for f in &self.new_findings {
                md.push_str(&format!(
                    "| {} | {} | `{}@{}` | {} |\n",
                    f.severity, f.advisory_id, f.package, f.version, f.summary
                ));
            }
            md.push('\n');
        }

        if !self.resolved_findings.is_empty() {
            md.push_str(&format!(
                "## ✅ Resolved Findings ({})\n\n| Severity | Advisory | Package | Summary |\n|---|---|---|---|\n",
                self.resolved_findings.len()
            ));
            for f in &self.resolved_findings {
                md.push_str(&format!(
                    "| {} | {} | `{}@{}` | {} |\n",
                    f.severity, f.advisory_id, f.package, f.version, f.summary
                ));
            }
            md.push('\n');
        }

        if !self.severity_changes.is_empty() {
            md.push_str(&format!(
                "## 🔄 Severity Changes ({})\n\n| Advisory | Package | Previous | Current |\n|---|---|---|---|\n",
                self.severity_changes.len()
            ));
            for c in &self.severity_changes {
                md.push_str(&format!(
                    "| {} | `{}@{}` | {} | {} |\n",
                    c.advisory_id, c.package, c.version, c.previous_severity, c.current_severity
                ));
            }
        }

        md
    }
}

impl ReportSummary {
    fn from_report(report: &ScanReport) -> Self {
        Self {
            scan_id: report.scan_id.clone(),
            project_name: report.project_name.clone(),
            scanned_at: report.scanned_at,
            total_findings: report.findings.len(),
            critical: report.count_by_severity(VulnerabilitySeverity::Critical),
            high: report.count_by_severity(VulnerabilitySeverity::High),
            medium: report.count_by_severity(VulnerabilitySeverity::Medium),
            low: report.count_by_severity(VulnerabilitySeverity::Low),
            info: report.count_by_severity(VulnerabilitySeverity::Info),
        }
    }
}

// ─── Trend Tracking (Goal 59) ──────────────────────────────────────────────

/// A single data point in the trend history.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrendPoint {
    pub scan_id: String,
    pub scanned_at: DateTime<Utc>,
    pub total_findings: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
    pub reachable: usize,
    pub unreachable: usize,
    pub false_positives: usize,
}

impl TrendPoint {
    fn from_report(report: &ScanReport) -> Self {
        Self {
            scan_id: report.scan_id.clone(),
            scanned_at: report.scanned_at,
            total_findings: report.findings.len(),
            critical: report.count_by_severity(VulnerabilitySeverity::Critical),
            high: report.count_by_severity(VulnerabilitySeverity::High),
            medium: report.count_by_severity(VulnerabilitySeverity::Medium),
            low: report.count_by_severity(VulnerabilitySeverity::Low),
            info: report.count_by_severity(VulnerabilitySeverity::Info),
            reachable: report.count_by_reachability(ReachabilityStatus::Reachable),
            unreachable: report.count_by_reachability(ReachabilityStatus::Unreachable),
            false_positives: report
                .findings
                .iter()
                .filter(|f| f.status == FindingStatus::FalsePositive)
                .count(),
        }
    }
}

/// Tracks vulnerability trends over time by storing scan history.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrendTracker {
    /// Project name.
    pub project_name: String,
    /// All historical scan data points.
    pub points: Vec<TrendPoint>,
}

impl TrendTracker {
    /// Create a new trend tracker for a project.
    pub fn new(project_name: &str) -> Self {
        Self {
            project_name: project_name.to_string(),
            points: Vec::new(),
        }
    }

    /// Load trend history from a file.
    pub fn load(path: &Path) -> Result<Self, ReportError> {
        if !path.exists() {
            return Err(ReportError::NotFound(path.to_string_lossy().to_string()));
        }
        let content = std::fs::read_to_string(path)?;
        let tracker: TrendTracker = serde_json::from_str(&content)?;
        Ok(tracker)
    }

    /// Save trend history to a file.
    pub fn save(&self, path: &Path) -> Result<(), ReportError> {
        let content = serde_json::to_string_pretty(self)?;
        std::fs::write(path, content)?;
        Ok(())
    }

    /// Add a scan report to the trend history.
    pub fn add_report(&mut self, report: &ScanReport) {
        self.points.push(TrendPoint::from_report(report));
        // Keep points sorted by time.
        self.points.sort_by_key(|p| p.scanned_at);
    }

    /// Get the trend over the last N scans.
    pub fn recent(&self, n: usize) -> &[TrendPoint] {
        let start = self.points.len().saturating_sub(n);
        &self.points[start..]
    }

    /// Calculate the trend direction for total findings.
    pub fn trend_direction(&self) -> TrendDirection {
        if self.points.len() < 2 {
            return TrendDirection::Stable;
        }
        let last = self.points.last().unwrap().total_findings;
        let prev = self.points[self.points.len() - 2].total_findings;
        if last < prev {
            TrendDirection::Improving
        } else if last > prev {
            TrendDirection::Worsening
        } else {
            TrendDirection::Stable
        }
    }

    /// Render the trend as a text summary.
    pub fn to_text(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "PledgeRecon Trend Report — {}\n",
            self.project_name
        ));
        out.push_str(&format!("{} scans recorded\n\n", self.points.len()));

        if self.points.is_empty() {
            out.push_str("No scan history available.\n");
            return out;
        }

        out.push_str("Scan History:\n");
        out.push_str(&format!(
            "{:<25} {:>8} {:>8} {:>8} {:>8} {:>8} {:>10}\n",
            "Date", "Total", "Crit", "High", "Med", "Low", "Reachable"
        ));
        out.push_str(&"-".repeat(85));
        out.push('\n');

        for p in &self.points {
            out.push_str(&format!(
                "{:<25} {:>8} {:>8} {:>8} {:>8} {:>8} {:>10}\n",
                p.scanned_at.format("%Y-%m-%d %H:%M"),
                p.total_findings,
                p.critical,
                p.high,
                p.medium,
                p.low,
                p.reachable
            ));
        }

        out.push_str(&format!("\nTrend: {}\n", self.trend_direction()));

        out
    }

    /// Render the trend as an HTML dashboard with a chart.
    pub fn to_html(&self) -> String {
        let points_json = serde_json::to_string(
            &self
                .points
                .iter()
                .map(|p| {
                    serde_json::json!({
                        "date": p.scanned_at.format("%Y-%m-%d").to_string(),
                        "total": p.total_findings,
                        "critical": p.critical,
                        "high": p.high,
                        "medium": p.medium,
                        "low": p.low,
                        "reachable": p.reachable,
                    })
                })
                .collect::<Vec<_>>(),
        )
        .unwrap_or_else(|_| "[]".to_string());

        format!(
            r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>PledgeRecon Trend Dashboard — {project}</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 2rem; background: #f8f9fa; }}
  h1 {{ color: #1a1a2e; }}
  .summary {{ display: flex; gap: 1rem; margin: 1rem 0 2rem; }}
  .card {{ background: white; padding: 1rem 1.5rem; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
  .card h3 {{ margin: 0 0 0.5rem; font-size: 0.85rem; color: #666; text-transform: uppercase; }}
  .card .value {{ font-size: 1.8rem; font-weight: 700; }}
  .trend-improving {{ color: #22c55e; }}
  .trend-worsening {{ color: #ef4444; }}
  .trend-stable {{ color: #6b7280; }}
  table {{ width: 100%; border-collapse: collapse; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
  th, td {{ padding: 0.6rem 1rem; text-align: left; border-bottom: 1px solid #e5e7eb; }}
  th {{ background: #f1f5f9; font-size: 0.85rem; text-transform: uppercase; color: #64748b; }}
  td {{ font-size: 0.9rem; }}
  .chart-placeholder {{ background: white; padding: 2rem; border-radius: 8px; text-align: center; color: #999; margin: 1rem 0; }}
</style>
</head>
<body>
<h1>📊 PledgeRecon Trend Dashboard</h1>
<p>Project: <strong>{project}</strong> — {count} scans recorded</p>

<div class="summary">
  <div class="card"><h3>Trend</h3><div class="value {trend_class}">{trend}</div></div>
  <div class="card"><h3>Latest Total</h3><div class="value">{latest_total}</div></div>
  <div class="card"><h3>Latest Critical</h3><div class="value">{latest_crit}</div></div>
  <div class="card"><h3>Latest Reachable</h3><div class="value">{latest_reach}</div></div>
</div>

<div class="chart-placeholder">
  📈 Trend data available — use a JS charting library (e.g. Chart.js) to visualize {count} data points.
  <br><small>Data: <code>{data}</code></small>
</div>

<h2>Scan History</h2>
<table>
<thead><tr><th>Date</th><th>Total</th><th>Critical</th><th>High</th><th>Medium</th><th>Low</th><th>Reachable</th><th>False Positives</th></tr></thead>
<tbody>
{rows}
</tbody>
</table>
</body>
</html>"#,
            project = self.project_name,
            count = self.points.len(),
            trend = self.trend_direction(),
            trend_class = match self.trend_direction() {
                TrendDirection::Improving => "trend-improving",
                TrendDirection::Worsening => "trend-worsening",
                TrendDirection::Stable => "trend-stable",
            },
            latest_total = self.points.last().map(|p| p.total_findings).unwrap_or(0),
            latest_crit = self.points.last().map(|p| p.critical).unwrap_or(0),
            latest_reach = self.points.last().map(|p| p.reachable).unwrap_or(0),
            data = points_json,
            rows = self
                .points
                .iter()
                .rev()
                .map(|p| format!(
                    "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                    p.scanned_at.format("%Y-%m-%d %H:%M"),
                    p.total_findings, p.critical, p.high, p.medium, p.low, p.reachable, p.false_positives
                ))
                .collect::<Vec<_>>()
                .join("\n"),
        )
    }
}

/// The direction of a vulnerability trend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrendDirection {
    /// Findings are decreasing.
    Improving,
    /// Findings are increasing.
    Worsening,
    /// Findings are unchanged.
    Stable,
}

impl std::fmt::Display for TrendDirection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TrendDirection::Improving => write!(f, "improving"),
            TrendDirection::Worsening => write!(f, "worsening"),
            TrendDirection::Stable => write!(f, "stable"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::Finding;
    use chrono::Utc;
    use std::path::PathBuf;
    use uuid::Uuid;

    fn make_finding(advisory_id: &str, severity: VulnerabilitySeverity) -> Finding {
        Finding {
            advisory_id: advisory_id.to_string(),
            summary: "Test".to_string(),
            description: "Test".to_string(),
            severity,
            cvss_score: None,
            package: "npm:test".to_string(),
            version: "1.0.0".to_string(),
            fix_version: Some("1.0.1".to_string()),
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
        }
    }

    fn make_report(findings: Vec<Finding>) -> ScanReport {
        ScanReport {
            scan_id: Uuid::new_v4().to_string(),
            project_name: "test".to_string(),
            scanned_at: Utc::now(),
            duration_ms: 10,
            dependencies_scanned: 5,
            advisories_checked: 3,
            findings,
        }
    }

    #[test]
    fn test_diff_new_findings() {
        let prev = make_report(vec![make_finding("CVE-001", VulnerabilitySeverity::High)]);
        let curr = make_report(vec![
            make_finding("CVE-001", VulnerabilitySeverity::High),
            make_finding("CVE-002", VulnerabilitySeverity::Medium),
        ]);
        let diff = DiffReport::from_reports(&prev, &curr);
        assert_eq!(diff.new_findings.len(), 1);
        assert_eq!(diff.resolved_findings.len(), 0);
        assert!(diff.has_new_findings());
    }

    #[test]
    fn test_diff_resolved_findings() {
        let prev = make_report(vec![
            make_finding("CVE-001", VulnerabilitySeverity::High),
            make_finding("CVE-002", VulnerabilitySeverity::Medium),
        ]);
        let curr = make_report(vec![make_finding("CVE-001", VulnerabilitySeverity::High)]);
        let diff = DiffReport::from_reports(&prev, &curr);
        assert_eq!(diff.new_findings.len(), 0);
        assert_eq!(diff.resolved_findings.len(), 1);
        assert!(diff.has_changes());
    }

    #[test]
    fn test_diff_severity_change() {
        let prev = make_report(vec![make_finding("CVE-001", VulnerabilitySeverity::Medium)]);
        let curr = make_report(vec![make_finding("CVE-001", VulnerabilitySeverity::High)]);
        let diff = DiffReport::from_reports(&prev, &curr);
        assert_eq!(diff.severity_changes.len(), 1);
        assert_eq!(
            diff.severity_changes[0].previous_severity,
            VulnerabilitySeverity::Medium
        );
        assert_eq!(
            diff.severity_changes[0].current_severity,
            VulnerabilitySeverity::High
        );
    }

    #[test]
    fn test_diff_no_changes() {
        let prev = make_report(vec![make_finding("CVE-001", VulnerabilitySeverity::High)]);
        let curr = make_report(vec![make_finding("CVE-001", VulnerabilitySeverity::High)]);
        let diff = DiffReport::from_reports(&prev, &curr);
        assert!(!diff.has_changes());
        assert_eq!(diff.unchanged_findings.len(), 1);
    }

    #[test]
    fn test_diff_to_text() {
        let prev = make_report(vec![make_finding("CVE-001", VulnerabilitySeverity::High)]);
        let curr = make_report(vec![
            make_finding("CVE-001", VulnerabilitySeverity::High),
            make_finding("CVE-002", VulnerabilitySeverity::Critical),
        ]);
        let diff = DiffReport::from_reports(&prev, &curr);
        let text = diff.to_text();
        assert!(text.contains("New Findings"));
        assert!(text.contains("CVE-002"));
    }

    #[test]
    fn test_diff_to_markdown() {
        let prev = make_report(vec![make_finding("CVE-001", VulnerabilitySeverity::High)]);
        let curr = make_report(vec![
            make_finding("CVE-001", VulnerabilitySeverity::High),
            make_finding("CVE-002", VulnerabilitySeverity::Critical),
        ]);
        let diff = DiffReport::from_reports(&prev, &curr);
        let md = diff.to_markdown();
        assert!(md.contains("New Findings"));
        assert!(md.contains("CVE-002"));
    }

    #[test]
    fn test_trend_tracker() {
        let mut tracker = TrendTracker::new("test-project");
        assert_eq!(tracker.points.len(), 0);

        tracker.add_report(&make_report(vec![
            make_finding("CVE-001", VulnerabilitySeverity::High),
            make_finding("CVE-002", VulnerabilitySeverity::Medium),
        ]));
        assert_eq!(tracker.points.len(), 1);
        assert_eq!(tracker.points[0].total_findings, 2);

        tracker.add_report(&make_report(vec![make_finding(
            "CVE-001",
            VulnerabilitySeverity::High,
        )]));
        assert_eq!(tracker.points.len(), 2);
        assert_eq!(tracker.trend_direction(), TrendDirection::Improving);
    }

    #[test]
    fn test_trend_to_text() {
        let mut tracker = TrendTracker::new("test-project");
        tracker.add_report(&make_report(vec![make_finding(
            "CVE-001",
            VulnerabilitySeverity::High,
        )]));
        let text = tracker.to_text();
        assert!(text.contains("Trend Report"));
        assert!(text.contains("test-project"));
    }

    #[test]
    fn test_trend_to_html() {
        let mut tracker = TrendTracker::new("test-project");
        tracker.add_report(&make_report(vec![make_finding(
            "CVE-001",
            VulnerabilitySeverity::High,
        )]));
        let html = tracker.to_html();
        assert!(html.contains("Trend Dashboard"));
        assert!(html.contains("test-project"));
    }

    #[test]
    fn test_trend_save_load() {
        let dir = std::env::temp_dir().join("pledgerecon_trend_test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("trend.json");

        let mut tracker = TrendTracker::new("test-project");
        tracker.add_report(&make_report(vec![make_finding(
            "CVE-001",
            VulnerabilitySeverity::High,
        )]));
        tracker.save(&path).unwrap();

        let loaded = TrendTracker::load(&path).unwrap();
        assert_eq!(loaded.project_name, "test-project");
        assert_eq!(loaded.points.len(), 1);

        std::fs::remove_file(&path).ok();
    }
}
