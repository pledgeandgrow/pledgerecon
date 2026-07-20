//! Vulnerability finding types — the output of a scan.
//!
//! A [`Finding`] represents a single vulnerability detected in a project
//! dependency, enriched with reachability status and LLM triage verdict.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Severity of a vulnerability finding, aligned with CVSS.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VulnerabilitySeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for VulnerabilitySeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VulnerabilitySeverity::Info => write!(f, "info"),
            VulnerabilitySeverity::Low => write!(f, "low"),
            VulnerabilitySeverity::Medium => write!(f, "medium"),
            VulnerabilitySeverity::High => write!(f, "high"),
            VulnerabilitySeverity::Critical => write!(f, "critical"),
        }
    }
}

impl std::str::FromStr for VulnerabilitySeverity {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "info" | "none" => Ok(VulnerabilitySeverity::Info),
            "low" => Ok(VulnerabilitySeverity::Low),
            "medium" => Ok(VulnerabilitySeverity::Medium),
            "high" => Ok(VulnerabilitySeverity::High),
            "critical" => Ok(VulnerabilitySeverity::Critical),
            _ => Err(format!("unknown severity: {}", s)),
        }
    }
}

/// Whether the vulnerable code is actually reachable from the project's entry points.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReachabilityStatus {
    /// The vulnerable function is called in the dependency graph.
    Reachable,
    /// The vulnerable function is not called — the vulnerability is present but not exploitable.
    Unreachable,
    /// Reachability analysis was not performed (no vulnerable function data or AST unavailable).
    Unknown,
}

impl std::fmt::Display for ReachabilityStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReachabilityStatus::Reachable => write!(f, "reachable"),
            ReachabilityStatus::Unreachable => write!(f, "unreachable"),
            ReachabilityStatus::Unknown => write!(f, "unknown"),
        }
    }
}

/// Whether the finding has been triaged by the LLM.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingStatus {
    /// Not yet triaged.
    Pending,
    /// Confirmed as a true positive by LLM triage.
    Confirmed,
    /// Classified as a false positive by LLM triage.
    FalsePositive,
    /// LLM triage was inconclusive.
    Inconclusive,
}

/// A single vulnerability finding from a scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Advisory ID (e.g. "CVE-2024-12345", "GHSA-xxxx-xxxx-xxxx").
    pub advisory_id: String,
    /// Advisory summary.
    pub summary: String,
    /// Description of the vulnerability.
    pub description: String,
    /// Severity of the vulnerability.
    pub severity: VulnerabilitySeverity,
    /// CVSS score, if available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cvss_score: Option<f64>,
    /// The vulnerable package name (ecosystem-prefixed, e.g. "npm:lodash").
    pub package: String,
    /// The installed version of the package.
    pub version: String,
    /// The fixed version, if available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fix_version: Option<String>,
    /// Whether a fix is available.
    pub fix_available: bool,
    /// Reachability status from AST analysis.
    pub reachability: ReachabilityStatus,
    /// Vulnerable function names (if known from advisory data).
    #[serde(default)]
    pub vulnerable_functions: Vec<String>,
    /// Call chain from entry point to vulnerable function (if reachable).
    #[serde(default)]
    pub call_chain: Vec<String>,
    /// Finding status after LLM triage.
    pub status: FindingStatus,
    /// LLM triage explanation (if triaged).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub triage_explanation: Option<String>,
    /// Reference URLs.
    #[serde(default)]
    pub references: Vec<String>,
    /// CWE IDs.
    #[serde(default)]
    pub cwes: Vec<String>,
    /// Path to the manifest file where this dependency was declared.
    pub manifest_path: PathBuf,
    /// Aliases (e.g. CVE IDs).
    #[serde(default)]
    pub aliases: Vec<String>,
}

impl Finding {
    /// Whether this finding should fail a CI gate.
    pub fn is_ci_blocking(&self, min_severity: VulnerabilitySeverity) -> bool {
        self.severity >= min_severity
            && self.reachability != ReachabilityStatus::Unreachable
            && self.status != FindingStatus::FalsePositive
    }

    /// Effective severity after reachability adjustment.
    /// Unreachable findings are downgraded to Info.
    pub fn effective_severity(&self) -> VulnerabilitySeverity {
        if self.reachability == ReachabilityStatus::Unreachable {
            return VulnerabilitySeverity::Info;
        }
        self.severity
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_finding(severity: VulnerabilitySeverity, reachability: ReachabilityStatus) -> Finding {
        Finding {
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
        }
    }

    #[test]
    fn test_ci_blocking() {
        let f = make_finding(VulnerabilitySeverity::High, ReachabilityStatus::Reachable);
        assert!(f.is_ci_blocking(VulnerabilitySeverity::Medium));

        let f = make_finding(VulnerabilitySeverity::High, ReachabilityStatus::Unreachable);
        assert!(!f.is_ci_blocking(VulnerabilitySeverity::Medium));

        let f = make_finding(VulnerabilitySeverity::Low, ReachabilityStatus::Reachable);
        assert!(!f.is_ci_blocking(VulnerabilitySeverity::Medium));
    }

    #[test]
    fn test_effective_severity() {
        let f = make_finding(VulnerabilitySeverity::High, ReachabilityStatus::Unreachable);
        assert_eq!(f.effective_severity(), VulnerabilitySeverity::Info);

        let f = make_finding(VulnerabilitySeverity::High, ReachabilityStatus::Reachable);
        assert_eq!(f.effective_severity(), VulnerabilitySeverity::High);
    }
}
