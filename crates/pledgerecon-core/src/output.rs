//! Output formats — JSON, SARIF, text, and markdown report generation.
//!
//! PledgeRecon supports multiple output formats for integration with
//! CI/CD systems, security dashboards, and developer workflows.

use crate::finding::{FindingStatus, ReachabilityStatus, VulnerabilitySeverity};
use crate::scanner::ScanReport;

/// The output format for scan results.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Json,
    Sarif,
    Text,
    Markdown,
    Html,
    Pdf,
    JunitXml,
    GitlabCodeQuality,
    SonarQube,
}

impl std::fmt::Display for OutputFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OutputFormat::Json => write!(f, "json"),
            OutputFormat::Sarif => write!(f, "sarif"),
            OutputFormat::Text => write!(f, "text"),
            OutputFormat::Markdown => write!(f, "markdown"),
            OutputFormat::Html => write!(f, "html"),
            OutputFormat::Pdf => write!(f, "pdf"),
            OutputFormat::JunitXml => write!(f, "junit-xml"),
            OutputFormat::GitlabCodeQuality => write!(f, "gitlab-code-quality"),
            OutputFormat::SonarQube => write!(f, "sonarqube"),
        }
    }
}

impl std::str::FromStr for OutputFormat {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "json" => Ok(OutputFormat::Json),
            "sarif" => Ok(OutputFormat::Sarif),
            "text" => Ok(OutputFormat::Text),
            "markdown" | "md" => Ok(OutputFormat::Markdown),
            "html" => Ok(OutputFormat::Html),
            "pdf" => Ok(OutputFormat::Pdf),
            "junit-xml" | "junit" => Ok(OutputFormat::JunitXml),
            "gitlab-code-quality" | "gitlab" => Ok(OutputFormat::GitlabCodeQuality),
            "sonarqube" | "sonar" => Ok(OutputFormat::SonarQube),
            _ => Err(format!("unknown output format: {}", s)),
        }
    }
}

/// Render a scan report as JSON.
pub fn to_json(report: &ScanReport) -> String {
    serde_json::to_string_pretty(report).unwrap_or_else(|e| format!("{{\"error\": \"{}\"}}", e))
}

/// Render a scan report as SARIF 2.1.0 (for GitHub code scanning integration).
pub fn to_sarif(report: &ScanReport) -> String {
    let mut results = Vec::new();

    for finding in &report.findings {
        let rule_id = finding.advisory_id.clone();
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

        results.push(serde_json::json!({
            "ruleId": rule_id,
            "level": level,
            "message": {
                "text": message,
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": finding.manifest_path.to_string_lossy(),
                    },
                },
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

/// Render a scan report as human-readable text (for terminal output).
pub fn to_text(report: &ScanReport) -> String {
    let mut out = String::new();

    out.push_str(&format!(
        "PledgeRecon Vulnerability Scan Report\n\
         =====================================\n\
         Project: {}\n\
         Scan ID: {}\n\
         Scanned at: {}\n\
         Duration: {}ms\n\n",
        report.project_name,
        report.scan_id,
        report.scanned_at.format("%Y-%m-%d %H:%M:%S UTC"),
        report.duration_ms
    ));

    out.push_str(&format!(
        "Summary: {} findings ({} critical, {} high, {} medium, {} low, {} info)\n",
        report.findings.len(),
        report.count_by_severity(VulnerabilitySeverity::Critical),
        report.count_by_severity(VulnerabilitySeverity::High),
        report.count_by_severity(VulnerabilitySeverity::Medium),
        report.count_by_severity(VulnerabilitySeverity::Low),
        report.count_by_severity(VulnerabilitySeverity::Info),
    ));

    let reachable = report
        .findings
        .iter()
        .filter(|f| f.reachability == ReachabilityStatus::Reachable)
        .count();
    let unreachable = report
        .findings
        .iter()
        .filter(|f| f.reachability == ReachabilityStatus::Unreachable)
        .count();
    out.push_str(&format!(
        "Reachability: {} reachable, {} unreachable, {} unknown\n\n",
        reachable,
        unreachable,
        report.findings.len() - reachable - unreachable
    ));

    if report.findings.is_empty() {
        out.push_str("✓ No vulnerabilities found.\n");
        return out;
    }

    // Sort findings by severity (descending).
    let mut findings = report.findings.clone();
    findings.sort_by_key(|b| std::cmp::Reverse(b.severity));

    for (i, finding) in findings.iter().enumerate() {
        let reachability_tag = match finding.reachability {
            ReachabilityStatus::Reachable => " [REACHABLE]",
            ReachabilityStatus::Unreachable => " [UNREACHABLE]",
            ReachabilityStatus::Unknown => "",
        };

        let triage_tag = match finding.status {
            FindingStatus::Confirmed => " [CONFIRMED]",
            FindingStatus::FalsePositive => " [FALSE POSITIVE]",
            FindingStatus::Inconclusive => " [INCONCLUSIVE]",
            FindingStatus::Pending => "",
        };

        out.push_str(&format!(
            "{}/{} [{}] {}{}\n\
             \x20   Package: {}@{}\n\
             \x20   Advisory: {}{}\n\
             \x20   CVSS: {}\n\
             \x20   Fix: {}\n",
            i + 1,
            findings.len(),
            format!("{}", finding.severity).to_uppercase(),
            finding.summary,
            reachability_tag,
            finding.package,
            finding.version,
            finding.advisory_id,
            triage_tag,
            finding
                .cvss_score
                .map(|s| s.to_string())
                .unwrap_or("N/A".to_string()),
            if finding.fix_available {
                finding.fix_version.as_deref().unwrap_or("available")
            } else {
                "not available"
            },
        ));

        if !finding.vulnerable_functions.is_empty() {
            out.push_str(&format!(
                "    Vulnerable functions: {}\n",
                finding.vulnerable_functions.join(", ")
            ));
        }

        if !finding.call_chain.is_empty() {
            out.push_str(&format!(
                "    Call chain: {}\n",
                finding.call_chain.join(" → ")
            ));
        }

        if let Some(ref explanation) = finding.triage_explanation {
            out.push_str(&format!("    Triage: {}\n", explanation));
        }

        if !finding.references.is_empty() {
            out.push_str("    References:\n");
            for ref_url in &finding.references {
                out.push_str(&format!("      - {}\n", ref_url));
            }
        }

        out.push('\n');
    }

    out
}

/// Render a scan report as Markdown (for PR comments, wikis, etc.).
pub fn to_markdown(report: &ScanReport) -> String {
    let mut md = String::new();

    md.push_str("# PledgeRecon Vulnerability Scan Report\n\n");
    md.push_str(&format!(
        "| Field | Value |\n|---|---|\n\
         | Project | {} |\n\
         | Scan ID | {} |\n\
         | Scanned at | {} |\n\
         | Duration | {}ms |\n\
         | Dependencies scanned | {} |\n\
         | Total findings | {} |\n\n",
        report.project_name,
        report.scan_id,
        report.scanned_at.format("%Y-%m-%d %H:%M:%S UTC"),
        report.duration_ms,
        report.dependencies_scanned,
        report.findings.len()
    ));

    // Summary table.
    md.push_str("## Summary\n\n");
    md.push_str("| Severity | Count | Reachable | Unreachable |\n|---|---|---|---|\n");
    for severity in &[
        VulnerabilitySeverity::Critical,
        VulnerabilitySeverity::High,
        VulnerabilitySeverity::Medium,
        VulnerabilitySeverity::Low,
        VulnerabilitySeverity::Info,
    ] {
        let count = report.count_by_severity(*severity);
        let reachable = report
            .findings
            .iter()
            .filter(|f| f.severity == *severity && f.reachability == ReachabilityStatus::Reachable)
            .count();
        let unreachable = report
            .findings
            .iter()
            .filter(|f| {
                f.severity == *severity && f.reachability == ReachabilityStatus::Unreachable
            })
            .count();
        md.push_str(&format!(
            "| {} | {} | {} | {} |\n",
            severity, count, reachable, unreachable
        ));
    }
    md.push('\n');

    if report.findings.is_empty() {
        md.push_str("✅ **No vulnerabilities found.**\n");
        return md;
    }

    // Findings detail.
    md.push_str("## Findings\n\n");

    let mut findings = report.findings.clone();
    findings.sort_by_key(|b| std::cmp::Reverse(b.severity));

    for (i, finding) in findings.iter().enumerate() {
        let reachability_emoji = match finding.reachability {
            ReachabilityStatus::Reachable => "🔴",
            ReachabilityStatus::Unreachable => "🟢",
            ReachabilityStatus::Unknown => "⚪",
        };

        md.push_str(&format!(
            "### {i}. {reachability_emoji} [{severity}] {summary}\n\n\
             - **Advisory:** `{advisory_id}`\n\
             - **Package:** `{package}@{version}`\n\
             - **CVSS:** {cvss}\n\
             - **Fix:** {fix}\n\
             - **Reachability:** {reachability}\n",
            i = i + 1,
            reachability_emoji = reachability_emoji,
            severity = finding.severity,
            summary = finding.summary,
            advisory_id = finding.advisory_id,
            package = finding.package,
            version = finding.version,
            cvss = finding
                .cvss_score
                .map(|s| s.to_string())
                .unwrap_or("N/A".to_string()),
            fix = if finding.fix_available {
                format!(
                    "`{}`",
                    finding.fix_version.as_deref().unwrap_or("available")
                )
            } else {
                "Not available".to_string()
            },
            reachability = finding.reachability,
        ));

        if !finding.vulnerable_functions.is_empty() {
            md.push_str(&format!(
                "- **Vulnerable functions:** {}\n",
                finding
                    .vulnerable_functions
                    .iter()
                    .map(|f| format!("`{}`", f))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }

        if !finding.call_chain.is_empty() {
            md.push_str(&format!(
                "- **Call chain:** `{}`\n",
                finding.call_chain.join("` → `")
            ));
        }

        if let Some(ref explanation) = finding.triage_explanation {
            md.push_str(&format!("- **Triage:** {}\n", explanation));
        }

        if !finding.references.is_empty() {
            md.push_str("- **References:**\n");
            for ref_url in &finding.references {
                md.push_str(&format!("  - [{}]({})\n", ref_url, ref_url));
            }
        }

        md.push('\n');
    }

    md
}

/// Render a scan report as an interactive HTML report with collapsible sections and filtering (Goal 56).
pub fn to_html(report: &ScanReport) -> String {
    let critical = report.count_by_severity(VulnerabilitySeverity::Critical);
    let high = report.count_by_severity(VulnerabilitySeverity::High);
    let medium = report.count_by_severity(VulnerabilitySeverity::Medium);
    let low = report.count_by_severity(VulnerabilitySeverity::Low);
    let info = report.count_by_severity(VulnerabilitySeverity::Info);
    let reachable = report.count_by_reachability(ReachabilityStatus::Reachable);
    let unreachable = report.count_by_reachability(ReachabilityStatus::Unreachable);

    let findings_json = serde_json::to_string(
        &report
            .findings
            .iter()
            .map(|f| {
                serde_json::json!({
                    "advisory_id": f.advisory_id,
                    "summary": f.summary,
                    "description": f.description,
                    "severity": f.severity.to_string(),
                    "cvss_score": f.cvss_score,
                    "package": f.package,
                    "version": f.version,
                    "fix_version": f.fix_version,
                    "fix_available": f.fix_available,
                    "reachability": f.reachability.to_string(),
                    "status": match f.status {
                        FindingStatus::Pending => "pending",
                        FindingStatus::Confirmed => "confirmed",
                        FindingStatus::FalsePositive => "false_positive",
                        FindingStatus::Inconclusive => "inconclusive",
                    },
                    "vulnerable_functions": f.vulnerable_functions,
                    "call_chain": f.call_chain,
                    "triage_explanation": f.triage_explanation,
                    "references": f.references,
                    "cwes": f.cwes,
                    "manifest_path": f.manifest_path.to_string_lossy(),
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
<title>PledgeRecon Report — {project}</title>
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f0f2f5; color: #1a1a2e; padding: 1rem; }}
  .header {{ background: linear-gradient(135deg, #1a1a2e, #16213e); color: white; padding: 2rem; border-radius: 12px; margin-bottom: 1rem; }}
  .header h1 {{ font-size: 1.5rem; margin-bottom: 0.5rem; }}
  .header .meta {{ font-size: 0.9rem; opacity: 0.85; }}
  .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 0.75rem; margin-bottom: 1rem; }}
  .card {{ background: white; padding: 1rem 1.5rem; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); text-align: center; }}
  .card .label {{ font-size: 0.75rem; text-transform: uppercase; color: #666; margin-bottom: 0.25rem; }}
  .card .value {{ font-size: 1.6rem; font-weight: 700; }}
  .card.critical .value {{ color: #dc2626; }}
  .card.high .value {{ color: #ea580c; }}
  .card.medium .value {{ color: #ca8a04; }}
  .card.low .value {{ color: #3b82f6; }}
  .card.info .value {{ color: #6b7280; }}
  .filters {{ background: white; padding: 1rem; border-radius: 8px; margin-bottom: 1rem; display: flex; gap: 1rem; flex-wrap: wrap; align-items: center; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
  .filters label {{ font-size: 0.85rem; font-weight: 600; }}
  .filters select, .filters input {{ padding: 0.4rem 0.6rem; border: 1px solid #d1d5db; border-radius: 4px; font-size: 0.85rem; }}
  .findings {{ background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
  .finding {{ border-bottom: 1px solid #e5e7eb; padding: 1rem 1.5rem; cursor: pointer; }}
  .finding:hover {{ background: #f9fafb; }}
  .finding-header {{ display: flex; align-items: center; gap: 0.75rem; }}
  .badge {{ padding: 0.15rem 0.5rem; border-radius: 4px; font-size: 0.75rem; font-weight: 700; text-transform: uppercase; }}
  .badge.critical {{ background: #fee2e2; color: #dc2626; }}
  .badge.high {{ background: #ffedd5; color: #ea580c; }}
  .badge.medium {{ background: #fef9c3; color: #ca8a04; }}
  .badge.low {{ background: #dbeafe; color: #3b82f6; }}
  .badge.info {{ background: #f3f4f6; color: #6b7280; }}
  .badge.reachable {{ background: #fee2e2; color: #dc2626; }}
  .badge.unreachable {{ background: #d1fae5; color: #16a34a; }}
  .finding-title {{ font-weight: 600; flex: 1; }}
  .finding-package {{ font-family: monospace; font-size: 0.85rem; color: #666; }}
  .finding-detail {{ display: none; margin-top: 0.75rem; padding-top: 0.75rem; border-top: 1px solid #e5e7eb; font-size: 0.9rem; line-height: 1.6; }}
  .finding.open .finding-detail {{ display: block; }}
  .finding-detail dt {{ font-weight: 600; margin-top: 0.5rem; }}
  .finding-detail dd {{ margin-left: 1rem; }}
  .finding-detail a {{ color: #3b82f6; text-decoration: none; }}
  .no-findings {{ text-align: center; padding: 3rem; color: #22c55e; font-size: 1.2rem; }}
  .footer {{ text-align: center; padding: 1rem; color: #999; font-size: 0.8rem; }}
</style>
</head>
<body>
<div class="header">
  <h1>🔍 PledgeRecon Vulnerability Scan Report</h1>
  <div class="meta">
    <strong>Project:</strong> {project} &nbsp;|&nbsp;
    <strong>Scan ID:</strong> {scan_id} &nbsp;|&nbsp;
    <strong>Date:</strong> {date} &nbsp;|&nbsp;
    <strong>Duration:</strong> {duration}ms &nbsp;|&nbsp;
    <strong>Dependencies:</strong> {deps}
  </div>
</div>

<div class="summary">
  <div class="card critical"><div class="label">Critical</div><div class="value">{critical}</div></div>
  <div class="card high"><div class="label">High</div><div class="value">{high}</div></div>
  <div class="card medium"><div class="label">Medium</div><div class="value">{medium}</div></div>
  <div class="card low"><div class="label">Low</div><div class="value">{low}</div></div>
  <div class="card info"><div class="label">Info</div><div class="value">{info}</div></div>
  <div class="card"><div class="label">Reachable</div><div class="value">{reachable}</div></div>
  <div class="card"><div class="label">Unreachable</div><div class="value">{unreachable}</div></div>
  <div class="card"><div class="label">Total</div><div class="value">{total}</div></div>
</div>

<div class="filters">
  <label>Filter:</label>
  <select id="severity-filter" onchange="applyFilters()">
    <option value="">All Severities</option>
    <option value="critical">Critical</option>
    <option value="high">High</option>
    <option value="medium">Medium</option>
    <option value="low">Low</option>
    <option value="info">Info</option>
  </select>
  <select id="reachability-filter" onchange="applyFilters()">
    <option value="">All Reachability</option>
    <option value="reachable">Reachable</option>
    <option value="unreachable">Unreachable</option>
    <option value="unknown">Unknown</option>
  </select>
  <input type="text" id="search-filter" placeholder="Search advisory, package..." oninput="applyFilters()" style="flex: 1; min-width: 200px;">
</div>

<div class="findings" id="findings-container">
  <div class="no-findings" id="no-findings" style="display: none;">✅ No vulnerabilities found.</div>
</div>

<div class="footer">Generated by PledgeRecon v{version}</div>

<script>
const findings = {findings_json};

function renderFindings(filtered) {{
  const container = document.getElementById('findings-container');
  const noFindings = document.getElementById('no-findings');
  container.innerHTML = '';
  if (filtered.length === 0) {{
    noFindings.style.display = 'block';
    return;
  }}
  noFindings.style.display = 'none';
  filtered.forEach((f, i) => {{
    const div = document.createElement('div');
    div.className = 'finding';
    div.onclick = (e) => {{ if (e.target.tagName !== 'A') div.classList.toggle('open'); }};
    const sevClass = f.severity;
    const reachClass = f.reachability;
    const reachBadge = f.reachability !== 'unknown' ? `<span class="badge ${{reachClass}}">${{f.reachability}}</span>` : '';
    let detail = `<div class="finding-detail"><dl>`;
    detail += `<dt>Advisory ID</dt><dd>${{f.advisory_id}}</dd>`;
    detail += `<dt>Description</dt><dd>${{f.description}}</dd>`;
    detail += `<dt>CVSS Score</dt><dd>${{f.cvss_score !== null ? f.cvss_score : 'N/A'}}</dd>`;
    detail += `<dt>Package</dt><dd><code>${{f.package}}@${{f.version}}</code></dd>`;
    detail += `<dt>Fix</dt><dd>${{f.fix_available ? '<code>' + (f.fix_version || 'available') + '</code>' : 'Not available'}}</dd>`;
    if (f.vulnerable_functions.length > 0) detail += `<dt>Vulnerable Functions</dt><dd>${{f.vulnerable_functions.join(', ')}}</dd>`;
    if (f.call_chain.length > 0) detail += `<dt>Call Chain</dt><dd><code>${{f.call_chain.join(' → ')}}</code></dd>`;
    if (f.triage_explanation) detail += `<dt>Triage</dt><dd>${{f.triage_explanation}}</dd>`;
    if (f.references.length > 0) detail += `<dt>References</dt><dd>${{f.references.map(r => '<a href="' + r + '">' + r + '</a>').join('<br>')}}</dd>`;
    if (f.cwes.length > 0) detail += `<dt>CWEs</dt><dd>${{f.cwes.join(', ')}}</dd>`;
    detail += `<dt>Manifest</dt><dd><code>${{f.manifest_path}}</code></dd>`;
    detail += `</dl></div>`;
    div.innerHTML = `<div class="finding-header"><span class="badge ${{sevClass}}">${{f.severity}}</span>${{reachBadge}}<span class="finding-title">${{f.summary}}</span><span class="finding-package">${{f.package}}@${{f.version}}</span></div>${{detail}}`;
    container.appendChild(div);
  }});
}}

function applyFilters() {{
  const sev = document.getElementById('severity-filter').value;
  const reach = document.getElementById('reachability-filter').value;
  const search = document.getElementById('search-filter').value.toLowerCase();
  const filtered = findings.filter(f => {{
    if (sev && f.severity !== sev) return false;
    if (reach && f.reachability !== reach) return false;
    if (search) {{
      const text = (f.advisory_id + ' ' + f.package + ' ' + f.summary + ' ' + f.description).toLowerCase();
      if (!text.includes(search)) return false;
    }}
    return true;
  }});
  renderFindings(filtered);
}}

applyFilters();
</script>
</body>
</html>"#,
        project = report.project_name,
        scan_id = report.scan_id,
        date = report.scanned_at.format("%Y-%m-%d %H:%M:%S UTC"),
        duration = report.duration_ms,
        deps = report.dependencies_scanned,
        critical = critical,
        high = high,
        medium = medium,
        low = low,
        info = info,
        reachable = reachable,
        unreachable = unreachable,
        total = report.findings.len(),
        version = env!("CARGO_PKG_VERSION"),
        findings_json = findings_json,
    )
}

/// Render a scan report as a print-ready HTML for PDF conversion (Goal 57).
/// Open in a browser and use "Print to PDF" or use a headless browser to convert.
pub fn to_pdf(report: &ScanReport) -> String {
    let critical = report.count_by_severity(VulnerabilitySeverity::Critical);
    let high = report.count_by_severity(VulnerabilitySeverity::High);
    let medium = report.count_by_severity(VulnerabilitySeverity::Medium);
    let low = report.count_by_severity(VulnerabilitySeverity::Low);

    let mut findings_html = String::new();
    if report.findings.is_empty() {
        findings_html.push_str(
            "<p style=\"color: #22c55e; font-size: 1.2em;\">No vulnerabilities found.</p>\n",
        );
    } else {
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
            findings_html.push_str(&format!(
                "<div class=\"finding\">\n\
                 <h3 style=\"color: {color};\">[{sev}] {summary}</h3>\n\
                 <table class=\"detail\">\n\
                 <tr><th>Advisory ID</th><td>{adv}</td></tr>\n\
                 <tr><th>Package</th><td><code>{pkg}@{ver}</code></td></tr>\n\
                 <tr><th>CVSS</th><td>{cvss}</td></tr>\n\
                 <tr><th>Fix</th><td>{fix}</td></tr>\n\
                 <tr><th>Reachability</th><td>{reach}</td></tr>\n\
                 <tr><th>Manifest</th><td><code>{manifest}</code></td></tr>\n\
                 </table>\n",
                color = color,
                sev = f.severity,
                summary = f.summary,
                adv = f.advisory_id,
                pkg = f.package,
                ver = f.version,
                cvss = f
                    .cvss_score
                    .map(|s| s.to_string())
                    .unwrap_or("N/A".to_string()),
                fix = if f.fix_available {
                    f.fix_version.as_deref().unwrap_or("available")
                } else {
                    "not available"
                },
                reach = f.reachability,
                manifest = f.manifest_path.to_string_lossy(),
            ));

            if !f.vulnerable_functions.is_empty() {
                findings_html.push_str(&format!(
                    "<p><strong>Vulnerable functions:</strong> {}</p>\n",
                    f.vulnerable_functions.join(", ")
                ));
            }
            if !f.call_chain.is_empty() {
                findings_html.push_str(&format!(
                    "<p><strong>Call chain:</strong> <code>{}</code></p>\n",
                    f.call_chain.join(" → ")
                ));
            }
            if let Some(ref explanation) = f.triage_explanation {
                findings_html.push_str(&format!(
                    "<p><strong>Triage:</strong> {}</p>\n",
                    explanation
                ));
            }
            if !f.references.is_empty() {
                findings_html.push_str("<p><strong>References:</strong><br>\n");
                for r in &f.references {
                    findings_html.push_str(&format!("- {}<br>\n", r));
                }
                findings_html.push_str("</p>\n");
            }
            findings_html.push_str("</div>\n");
        }
    }

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>PledgeRecon Compliance Report — {project}</title>
<style>
  @page {{ margin: 2cm; }}
  body {{ font-family: 'Times New Roman', serif; font-size: 12pt; line-height: 1.5; color: #1a1a2e; }}
  h1 {{ font-size: 20pt; border-bottom: 2px solid #1a1a2e; padding-bottom: 0.5rem; margin-bottom: 1rem; }}
  h2 {{ font-size: 16pt; margin-top: 1.5rem; }}
  h3 {{ font-size: 13pt; margin-top: 1rem; }}
  .header {{ margin-bottom: 1.5rem; }}
  .header p {{ margin: 0.2rem 0; font-size: 11pt; }}
  .summary-table {{ width: 100%; border-collapse: collapse; margin: 1rem 0; }}
  .summary-table th, .summary-table td {{ border: 1px solid #ccc; padding: 0.4rem 0.8rem; text-align: left; }}
  .summary-table th {{ background: #f1f5f9; font-weight: bold; }}
  .finding {{ page-break-inside: avoid; margin-bottom: 1.5rem; padding: 0.5rem 0; border-top: 1px solid #e5e7eb; }}
  .detail {{ width: 100%; border-collapse: collapse; margin: 0.5rem 0; }}
  .detail th {{ width: 150px; text-align: right; font-size: 10pt; color: #666; padding: 0.2rem 0.5rem; }}
  .detail td {{ font-size: 11pt; padding: 0.2rem 0.5rem; }}
  .footer {{ margin-top: 2rem; padding-top: 0.5rem; border-top: 1px solid #ccc; font-size: 9pt; color: #999; text-align: center; }}
  .compliance-stamp {{ border: 2px solid #1a1a2e; padding: 0.5rem 1rem; display: inline-block; margin: 1rem 0; font-weight: bold; }}
</style>
</head>
<body>
<div class="header">
  <h1>PledgeRecon Compliance Report</h1>
  <p><strong>Project:</strong> {project}</p>
  <p><strong>Scan ID:</strong> {scan_id}</p>
  <p><strong>Date:</strong> {date}</p>
  <p><strong>Duration:</strong> {duration}ms</p>
  <p><strong>Dependencies scanned:</strong> {deps}</p>
  <p><strong>Advisories checked:</strong> {advs}</p>
</div>

<div class="compliance-stamp">Compliance Documentation — Generated {date}</div>

<h2>Summary</h2>
<table class="summary-table">
<tr><th>Severity</th><th>Count</th></tr>
<tr><td>Critical</td><td>{critical}</td></tr>
<tr><td>High</td><td>{high}</td></tr>
<tr><td>Medium</td><td>{medium}</td></tr>
<tr><td>Low</td><td>{low}</td></tr>
<tr><td><strong>Total</strong></td><td><strong>{total}</strong></td></tr>
</table>

<h2>Findings</h2>
{findings_html}

<div class="footer">
  Generated by PledgeRecon v{version} — {date}
</div>
</body>
</html>"#,
        project = report.project_name,
        scan_id = report.scan_id,
        date = report.scanned_at.format("%Y-%m-%d %H:%M:%S UTC"),
        duration = report.duration_ms,
        deps = report.dependencies_scanned,
        advs = report.advisories_checked,
        critical = critical,
        high = high,
        medium = medium,
        low = low,
        total = report.findings.len(),
        findings_html = findings_html,
        version = env!("CARGO_PKG_VERSION"),
    )
}

/// Render a scan report as JUnit XML for Jenkins/CI test result integration (Goal 60).
pub fn to_junit_xml(report: &ScanReport) -> String {
    let total = report.findings.len();
    let failures = report
        .findings
        .iter()
        .filter(|f| f.severity >= VulnerabilitySeverity::Medium)
        .count();

    let mut xml = String::new();
    xml.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    xml.push_str(&format!(
        "<testsuites name=\"pledgerecon\" tests=\"{}\" failures=\"{}\" time=\"{}\">\n",
        total,
        failures,
        report.duration_ms as f64 / 1000.0
    ));
    xml.push_str(&format!(
        "  <testsuite name=\"{}\" tests=\"{}\" failures=\"{}\" time=\"{}\">\n",
        report.project_name,
        total,
        failures,
        report.duration_ms as f64 / 1000.0
    ));

    for f in &report.findings {
        let classname = f.package.replace(':', ".");
        let name = format!("{}_{}", f.advisory_id, f.package.replace(':', "_"));

        let is_failure = f.severity >= VulnerabilitySeverity::Medium;

        if is_failure {
            xml.push_str(&format!(
                "    <testcase classname=\"{}\" name=\"{}\">\n",
                classname, name
            ));
            xml.push_str(&format!(
                "      <failure type=\"{}\" message=\"{} — {}@{}\">\n",
                f.severity, f.summary, f.package, f.version
            ));
            xml.push_str(&format!(
                "        Advisory: {}\n        CVSS: {}\n        Fix: {}\n        Reachability: {}\n",
                f.advisory_id,
                f.cvss_score.map(|s| s.to_string()).unwrap_or("N/A".to_string()),
                f.fix_version.as_deref().unwrap_or("N/A"),
                f.reachability
            ));
            if !f.call_chain.is_empty() {
                xml.push_str(&format!(
                    "        Call chain: {}\n",
                    f.call_chain.join(" -> ")
                ));
            }
            xml.push_str("      </failure>\n");
            xml.push_str("    </testcase>\n");
        } else {
            xml.push_str(&format!(
                "    <testcase classname=\"{}\" name=\"{}\"/>\n",
                classname, name
            ));
        }
    }

    xml.push_str("  </testsuite>\n");
    xml.push_str("</testsuites>\n");

    xml
}

/// Render a scan report as GitLab Code Quality JSON (Goal 61).
/// This is the native GitLab vulnerability management integration format.
pub fn to_gitlab_code_quality(report: &ScanReport) -> String {
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

/// Render a scan report in SonarQube import format (Goal 62).
/// This generates a JSON file compatible with SonarQube's external issue importer.
pub fn to_sonarqube(report: &ScanReport) -> String {
    let mut issues = Vec::new();

    for finding in &report.findings {
        if finding.status == FindingStatus::FalsePositive {
            continue;
        }

        let severity = match finding.severity {
            VulnerabilitySeverity::Critical => "BLOCKER",
            VulnerabilitySeverity::High => "CRITICAL",
            VulnerabilitySeverity::Medium => "MAJOR",
            VulnerabilitySeverity::Low => "MINOR",
            VulnerabilitySeverity::Info => "INFO",
        };

        let rule_key = finding.advisory_id.replace('-', "_");

        issues.push(serde_json::json!({
            "engineId": "PledgeRecon",
            "ruleId": finding.advisory_id,
            "severity": severity,
            "type": "VULNERABILITY",
            "primaryLocation": {
                "message": format!("{} — {}@{}: {}", finding.summary, finding.package, finding.version, finding.description),
                "filePath": finding.manifest_path.to_string_lossy(),
            },
            "effortMin": if finding.fix_available { "15min" } else { "1h" },
        }));

        // SonarQube issues can have remediation effort.
        let _ = rule_key; // rule_key used for potential future rule registry.
    }

    serde_json::json!({
        "issues": issues,
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::Finding;
    use crate::scanner::ScanReport;
    use chrono::Utc;
    use std::path::PathBuf;
    use uuid::Uuid;

    fn make_test_report() -> ScanReport {
        let finding = Finding {
            advisory_id: "CVE-2021-23337".to_string(),
            summary: "Command injection in lodash.template".to_string(),
            description: "Test description".to_string(),
            severity: VulnerabilitySeverity::High,
            cvss_score: Some(7.2),
            package: "npm:lodash".to_string(),
            version: "4.17.11".to_string(),
            fix_version: Some("4.17.21".to_string()),
            fix_available: true,
            reachability: ReachabilityStatus::Reachable,
            vulnerable_functions: vec!["template".to_string()],
            call_chain: vec!["main".to_string(), "lodash.template".to_string()],
            status: FindingStatus::Pending,
            triage_explanation: None,
            references: vec!["https://example.com/advisory".to_string()],
            cwes: vec!["CWE-77".to_string()],
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

    #[test]
    fn test_to_json() {
        let report = make_test_report();
        let json = to_json(&report);
        assert!(json.contains("CVE-2021-23337"));
        assert!(json.contains("lodash"));
    }

    #[test]
    fn test_to_sarif() {
        let report = make_test_report();
        let sarif = to_sarif(&report);
        assert!(sarif.contains("2.1.0"));
        assert!(sarif.contains("PledgeRecon"));
        assert!(sarif.contains("CVE-2021-23337"));
    }

    #[test]
    fn test_to_text() {
        let report = make_test_report();
        let text = to_text(&report);
        assert!(text.contains("PledgeRecon"));
        assert!(text.contains("HIGH"));
        assert!(text.contains("REACHABLE"));
        assert!(text.contains("lodash"));
    }

    #[test]
    fn test_to_markdown() {
        let report = make_test_report();
        let md = to_markdown(&report);
        assert!(md.contains("# PledgeRecon"));
        assert!(md.contains("CVE-2021-23337"));
        assert!(md.contains("lodash"));
    }

    #[test]
    fn test_to_html() {
        let report = make_test_report();
        let html = to_html(&report);
        assert!(html.contains("PledgeRecon"));
        assert!(html.contains("CVE-2021-23337"));
        assert!(html.contains("lodash"));
        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains("applyFilters"));
    }

    #[test]
    fn test_to_pdf() {
        let report = make_test_report();
        let pdf = to_pdf(&report);
        assert!(pdf.contains("Compliance Report"));
        assert!(pdf.contains("CVE-2021-23337"));
        assert!(pdf.contains("@page"));
    }

    #[test]
    fn test_to_junit_xml() {
        let report = make_test_report();
        let xml = to_junit_xml(&report);
        assert!(xml.contains("<?xml"));
        assert!(xml.contains("testsuites"));
        assert!(xml.contains("CVE-2021-23337"));
        assert!(xml.contains("<failure"));
    }

    #[test]
    fn test_to_gitlab_code_quality() {
        let report = make_test_report();
        let json = to_gitlab_code_quality(&report);
        assert!(json.contains("severity"));
        assert!(json.contains("blocker"));
        assert!(json.contains("CVE-2021-23337"));
    }

    #[test]
    fn test_to_sonarqube() {
        let report = make_test_report();
        let json = to_sonarqube(&report);
        assert!(json.contains("issues"));
        assert!(json.contains("PledgeRecon"));
        assert!(json.contains("VULNERABILITY"));
        assert!(json.contains("CVE-2021-23337"));
    }

    #[test]
    fn test_output_format_from_str() {
        assert_eq!("json".parse::<OutputFormat>().unwrap(), OutputFormat::Json);
        assert_eq!(
            "sarif".parse::<OutputFormat>().unwrap(),
            OutputFormat::Sarif
        );
        assert_eq!("text".parse::<OutputFormat>().unwrap(), OutputFormat::Text);
        assert_eq!(
            "markdown".parse::<OutputFormat>().unwrap(),
            OutputFormat::Markdown
        );
        assert_eq!(
            "md".parse::<OutputFormat>().unwrap(),
            OutputFormat::Markdown
        );
        assert_eq!("html".parse::<OutputFormat>().unwrap(), OutputFormat::Html);
        assert_eq!("pdf".parse::<OutputFormat>().unwrap(), OutputFormat::Pdf);
        assert_eq!(
            "junit-xml".parse::<OutputFormat>().unwrap(),
            OutputFormat::JunitXml
        );
        assert_eq!(
            "junit".parse::<OutputFormat>().unwrap(),
            OutputFormat::JunitXml
        );
        assert_eq!(
            "gitlab-code-quality".parse::<OutputFormat>().unwrap(),
            OutputFormat::GitlabCodeQuality
        );
        assert_eq!(
            "sonarqube".parse::<OutputFormat>().unwrap(),
            OutputFormat::SonarQube
        );
        assert!("invalid".parse::<OutputFormat>().is_err());
    }
}
